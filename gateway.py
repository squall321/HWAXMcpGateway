# 3개 백엔드 MCP를 집계해 단일 streamable-http 엔드포인트로 재노출하는 게이트웨이
import hashlib
import json
import logging
import os
import re
import time
from collections import Counter, OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import anyio
import httpx
import uvicorn
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("hwax-mcp-gateway")

CONFIG_PATH = os.environ.get("GATEWAY_CONFIG", str(Path(__file__).with_name("gateway_config.json")))


def _load_config():
    if not os.path.exists(CONFIG_PATH):
        # traceback 크래시-루프 대신 명확한 프로비저닝 안내 후 종료 (fresh 서버에서 가장 흔한 실수)
        log.error("설정 파일 없음: %s", CONFIG_PATH)
        log.error("이 파일은 시크릿이라 git 에 없습니다. 같은 디렉토리의 gateway_config.example.json 을")
        log.error("복사한 뒤 실토큰(GW_TOKEN·백엔드 Authorization·rest.inject)을 채우세요:")
        log.error("  cp %s %s && chmod 600 %s",
                  str(Path(CONFIG_PATH).with_name("gateway_config.example.json")), CONFIG_PATH, CONFIG_PATH)
        raise SystemExit(1)
    with open(CONFIG_PATH, "r") as f:
        cfg = json.load(f)
    gw = cfg.pop("_gateway")
    rest = cfg.pop("rest", {})       # REST 프록시 백엔드(site -> base+inject) — MCP 백엔드 아님
    portal = cfg.pop("portal", {})   # 포털 JWKS/폐기목록/aud allowlist (PAT 검증용)
    heax = cfg.pop("heax_registry", {})  # heax-hub MCP 앱 자동탐지(없으면 비활성) — {servers_url, base, token, poll_s}
    backends = {k: v for k, v in cfg.items() if isinstance(v, dict) and "url" in v}
    return gw, backends, rest, portal, heax


GW, BACKENDS, REST, PORTAL, HEAX = _load_config()
GW_TOKEN = GW["token"]
HOST = GW.get("host", "127.0.0.1")
# GATEWAY_PORT 로 config 를 덮어쓸 수 있다 — 임시/재현 실행이 운영 포트(9110)를 뺏지 않도록
# "임시 실행은 다른 포트" 규약을 코드로 지원한다(start.sh 의 포트 가드와 짝).
PORT = int(os.environ.get("GATEWAY_PORT") or GW.get("port", 9110))
# /mcp 를 GW_TOKEN(내부 에이전트) 외에 포털 PAT(개인 Claude 등)로도 열 때 요구하는 audience.
MCP_AUDIENCE = PORTAL.get("mcp_audience", "mcp-gateway")
AUDIT_PATH = os.environ.get("GATEWAY_AUDIT", str(Path(__file__).with_name("audit.jsonl")))
# 백엔드 도구 호출 타임아웃(초) — 행 걸린 백엔드가 챗 SSE 를 무기한 붙잡지 않게.
CALL_TIMEOUT_S = int(os.environ.get("GATEWAY_CALL_TIMEOUT", "120"))
# 죽은 백엔드 재활 주기(초) — 부팅 때 없던 백엔드가 나중에 떠도 재시작 없이 합류.
REVIVE_INTERVAL_S = int(os.environ.get("GATEWAY_REVIVE_INTERVAL", "60"))
# 연결 상태 백엔드의 list_tools 확인 타임아웃 — 행 걸린 백엔드가 revive 루프를 막지 않게.
LIVENESS_TIMEOUT_S = float(os.environ.get("GATEWAY_LIVENESS_TIMEOUT", "10"))
# 호출 경로에서 재연결이 일어났음을 revive 루프에 알리는 플래그(카탈로그 재집계 예약).
_REAGG: dict[str, bool] = {}

# 그룹 기반 도구 인가: Agent Server가 사용자 groups를 X-HWAX-Groups(콤마구분)로 실어 보낸다.
# 백엔드별 allowed_groups가 비었거나 없으면 전체 공개, 있으면 caller groups와 교집합이 있어야 노출/호출.
from urllib.parse import quote, unquote  # 비ASCII 그룹명 헤더 인/디코드

GROUPS_HEADER = "x-hwax-groups"
POLICY: dict[str, list[str]] = {k: list(v.get("allowed_groups", [])) for k, v in BACKENDS.items()}

# 호출자 신원(이메일). groups 가 '무엇을 볼 수 있는 부류인가'라면 이쪽은 '누구인가'다.
# 백엔드가 사용자별 데이터를 스코프할 때 필요하다 — 게이트웨이는 백엔드마다 서비스 계정
# 자격증명 하나로 접속하므로, 이 헤더가 없으면 백엔드 눈에는 모든 호출이 '게이트웨이'다.
# 실제로 DynaForge 가 그랬다: 세션 12·K파일 25건이 있는데 심의는 0건을 봤다(2026-08-17).
# groups 와 같은 규칙으로 퍼센트 인코딩한다(헤더는 latin-1 만 담는다).
USER_HEADER = "x-hwax-user"
# 백엔드별 사용자 위임 설정 — {app_id: {sso_url, secret, client, base?}}.
# 값이 있는 백엔드만 사용자별 자격증명으로 호출한다(나머지는 종전대로 서비스 계정).
PER_USER_SSO: dict[str, dict] = {k: v for k, v in (HEAX.get("per_user_sso") or {}).items()
                                 if isinstance(v, dict) and v.get("sso_url") and v.get("secret")}
# 사용자 PAT 캐시 수명(초). PAT 자체는 장수명이라 만료 때문이 아니라 '권한 회수 반영'을 위한 값이다.
# 짧게 잡으면 재발급이 잦아 백엔드에 폐기 토큰 행이 쌓인다(발급이 직전 것을 회수하는 구조).
USER_PAT_TTL_S = int(os.environ.get("GATEWAY_USER_PAT_TTL", "43200"))

# ── 포털 등록 연결 토큰으로 위임하는 백엔드(사용자 발안 2026-09-03) ──────────────
# 사용자가 해당 서비스(RA)에서 직접 발급받은 PAT 를 포털 API 토큰 페이지에 등록하면,
# 게이트웨이가 호출 시 포털 /internal/connections 에서 그 토큰을 읽어 그 사람 명의로
# 부른다. 미등록 사용자는 종전대로 서비스 계정(폴백 유지 — 등록은 점진 전환).
# {backend_key: 포털 service 이름}. 인증은 GW_TOKEN 공유 시크릿(포털 쪽 동일 값 필요).
PORTAL_CONN_BACKENDS: dict[str, str] = {"reportarchive": "reportarchive"}
PORTAL_CONN_TTL_S = int(os.environ.get("GATEWAY_CONN_TTL", "300"))
# {(service,email): (conn|None, 만료 monotonic)} — None 은 '등록 없음' 부정 캐시.
_CONN_CACHE: dict[tuple[str, str], tuple[dict | None, float]] = {}


async def _portal_connection(service: str, email: str) -> dict | None:
    """포털에 등록된 사용자 연결 토큰 {token, workspace} — 없거나 실패면 None(서비스 계정 폴백)."""
    key = (service, email)
    hit = _CONN_CACHE.get(key)
    if hit and hit[1] > time.monotonic():
        return hit[0]
    base = (PORTAL.get("api_base") or "").rstrip("/")
    conn: dict | None = None
    if base:
        try:
            async with httpx.AsyncClient(timeout=8) as cli:
                resp = await cli.get(f"{base}/internal/connections/{service}",
                                     params={"email": email},
                                     headers={"Authorization": f"Bearer {GW_TOKEN}"})
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict) and data.get("token"):
                    conn = {"token": data["token"], "workspace": data.get("workspace") or ""}
            elif resp.status_code not in (404,):
                log.warning("portal connection lookup %s/%s → HTTP %s", service, email,
                            resp.status_code)
        except Exception as exc:  # noqa: BLE001 — 조회 실패는 서비스 계정 폴백(가용성 우선)
            log.warning("portal connection lookup failed (%r) — 서비스 계정 폴백", exc)
            # 실패는 짧게만 캐시해 포털 복구가 빨리 반영되게 한다.
            _CONN_CACHE[key] = (None, time.monotonic() + 30)
            return None
    # '등록 없음'(404)도 30초만 — 방금 등록한 사용자가 5분을 기다리게 하지 않는다.
    ttl = PORTAL_CONN_TTL_S if conn else 30
    _CONN_CACHE[key] = (conn, time.monotonic() + ttl)
    return conn

# ── 읽기 전용 응답 캐시 ───────────────────────────────────────────────────────
# 심의는 좌석 수만큼 **같은 조회를 반복한다.** 실측(2026-09-02 솔더볼 심의): hwax 도구
# 728회 중 124회(17%)가 (도구,인자) 완전 동일이었고 `get_model_info {}` 하나가 29회,
# 같은 좌석의 `get_context_bundle` 이 6회였다. 좌석마다 같은 것을 묻는 건 정상 동작이라
# 프롬프트로 막을 일이 아니라 캐시할 일이다.
#
# 왜 게이트웨이인가 — 에이전트끼리 공유되려면 **모든 호출이 지나는 유일한 지점**이어야 한다.
# 워크플로는 자식 에이전트의 도구 호출을 가로챌 수 없고, 심의 엔진(deliberation.py)은
# agent-server 경로만 덮는다. MCP 워크플로 경로는 그쪽을 안 지난다.
#
# 부수 효과 하나 더 — 권한 auto-mode 가 호출마다 안전성을 판정하는데 그 판정 모델이
# rate-limit 에 걸려 같은 실측에서 호출의 33%가 거부됐다. 중복을 없애면 판정 부하도 준다.
CACHE_TTL_S = float(os.environ.get("GATEWAY_CACHE_TTL", "300"))
CACHE_MAX = int(os.environ.get("GATEWAY_CACHE_MAX", "512"))
# 캐시해도 되는 도구 — 접두사 화이트리스트로만 연다(deny-by-default). 심의 엔진의
# _FREE_ALLOW 와 같은 자세다. 여기 없으면 캐시하지 않고, 쓰기로 보이면 아래에서 무효화한다.
_CACHEABLE = ("list_", "get_", "search_", "find_", "query_", "describe_", "hybrid_",
              "semantic_", "fts_", "material_", "property_", "database_", "catalog_",
              "coverage_", "top_", "agent_search", "recommend_agents", "instrument_summary",
              "section_contact_usage", "report_", "inspect_", "project_tree", "part_",
              "compare_", "ashby_", "measurement_gaps", "how_to_measure")
# ⚠ 접두사가 여는 것 중 **쓰기**가 섞여 있다 — report_ingest·report_fragmentize 는 report_ 에
#   걸리지만 원장에 쓴다. 쓰기가 캐시되면 TTL 안 재호출이 백엔드에 도달하지 않고 무음 드롭되고,
#   flush 경로(캐시 비대상=쓰기 가정)도 안 탄다(감사 비판자 1-B 실증). 이름 명시로 막는다.
_CACHE_DENY = ("report_ingest", "report_fragmentize", "get_agent_session")
# {(backend, tool, args, identity): (result, expiry)} — 삽입 순서 = LRU 근사(오래된 것부터 버린다)
_RESP_CACHE: "OrderedDict[tuple, tuple]" = OrderedDict()
_CACHE_STAT = {"hit": 0, "miss": 0, "flush": 0}


# 백엔드별 도구 지문 — {이름: 설명·스키마 해시}. 이름 집합만 보면 설명·스키마 변경을 못 잡는다.
_FP: dict[str, dict] = {}


def _tools_fp(tools) -> dict:
    """도구 목록의 지문. 이름 → (설명 + 입력스키마) 해시."""
    out = {}
    for t in tools:
        try:
            sch = json.dumps(getattr(t, "inputSchema", None) or {}, sort_keys=True, default=str)
        except Exception:  # noqa: BLE001
            sch = ""
        raw = (getattr(t, "description", "") or "") + "\x00" + sch
        out[t.name] = hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]
    return out


def _cache_key(backend_key: str, tool: str, arguments) -> tuple | None:
    """캐시 키. 캐시 불가면 None.

    ⚠ 키에 **호출자 신원**을 넣는다. PER_USER_SSO 백엔드는 사용자별 시야로 답하므로,
      신원을 빼면 A 가 부른 결과를 B 가 받는다 — 권한 우회다.
    """
    if CACHE_TTL_S <= 0 or tool in _CACHE_DENY or not tool.startswith(_CACHEABLE):
        return None
    try:
        args = json.dumps(arguments or {}, sort_keys=True, ensure_ascii=False)
    except Exception:  # noqa: BLE001 — 직렬화 안 되는 인자는 캐시하지 않는다
        return None
    return (backend_key, tool, args, _request_user(), tuple(sorted(_request_groups())))


def _cache_get(key):
    if key is None:
        return None
    hit = _RESP_CACHE.get(key)
    if hit is None:
        return None
    res, exp = hit
    if time.monotonic() >= exp:
        _RESP_CACHE.pop(key, None)
        return None
    _RESP_CACHE.move_to_end(key)
    _CACHE_STAT["hit"] += 1
    return res


def _cache_put(key, res):
    """성공 결과만 담는다 — 오류를 캐시하면 일시적 실패가 TTL 동안 굳는다."""
    if key is None or getattr(res, "isError", False):
        return res
    _RESP_CACHE[key] = (res, time.monotonic() + CACHE_TTL_S)
    _RESP_CACHE.move_to_end(key)
    while len(_RESP_CACHE) > CACHE_MAX:
        _RESP_CACHE.popitem(last=False)
    _CACHE_STAT["miss"] += 1
    return res


def _cache_flush_backend(backend_key: str):
    """그 백엔드의 캐시를 버린다. 쓰기 호출 직후에 부른다 — 안 그러면 방금 만든 것이
    TTL 동안 목록에 안 보인다(create_project 뒤 list_projects 가 옛 목록을 준다)."""
    doomed = [k for k in _RESP_CACHE if k[0] == backend_key]
    for k in doomed:
        _RESP_CACHE.pop(k, None)
    if doomed:
        _CACHE_STAT["flush"] += len(doomed)


def _audit(tool, backend, ok, err, ms, caller=None):
    """호출 1건을 JSONL 감사 로그에 append (감사 실패가 호출을 막지 않게). caller=REST PAT 주체."""
    try:
        rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "tool": tool, "backend": backend, "ok": ok, "ms": ms}
        if caller:
            rec["caller"] = caller
        if err:
            rec["error"] = err[:200]
        with open(AUDIT_PATH, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001
        pass


class _Backend:
    """백엔드 1개에 대한 영속 ClientSession을 anyio 태스크로 들고 있는 핸들."""

    def __init__(self, key, url, headers):
        self.key = key
        self.url = url
        self.headers = headers or {}
        self.session: ClientSession | None = None
        self._ready = anyio.Event()
        self._stop = anyio.Event()
        self._failed: Exception | None = None
        # 재연결 직렬화 + 세대 번호. 아래 reconnect 주석 참고.
        self._recon_lock = anyio.Lock()
        self._gen = 0

    async def run(self, task_status=anyio.TASK_STATUS_IGNORED):
        """streamablehttp_client + ClientSession을 열고 stop 이벤트까지 park."""
        try:
            async with streamablehttp_client(self.url, headers=self.headers) as (read, write, _get_sid):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    self.session = session
                    self._failed = None
                    self._ready.set()
                    task_status.started()
                    await self._stop.wait()
        except Exception as e:  # noqa: BLE001
            self._failed = e
            self.session = None
            if not self._ready.is_set():
                self._ready.set()
                task_status.started()
            log.warning("backend %s session ended: %r", self.key, e)

    async def reconnect(self, tg, seen_gen: int | None = None):
        """call 시 세션이 죽었으면 새 태스크로 1회 재연결.

        ⚠ 락이 없으면 안 된다. 이 함수는 앞 5줄이 동기라 거기서는 안 끼어들지만
        `await tg.start(self.run)` 에서 양보한다. 그 창에 들어온 두 번째 호출이 _stop/_ready
        를 또 갈아 끼워, 백엔드 하나에 영속 세션이 여러 개 살아남고 self.session 은 핸드셰이크를
        마지막에 끝낸 쪽으로 비결정적으로 정해진다(재현: 동시 3건 → 세션 3개 생존).

        seen_gen 은 "내가 죽었다고 본 그 세션" 의 세대다. 호출 실패는 한 백엔드에 대해 동시에
        여러 건이 겪는다 — 세대를 안 보면 첫 호출이 새로 만든 멀쩡한 세션을 두 번째 호출이
        곧바로 다시 부수고, 그 사이 다른 모든 동시 호출이 read timeout 까지 조용히 매달린다.
        이미 누가 갈아 끼웠으면 그냥 그 세션을 쓴다. (liveness 로 부르는 _revive_loop 는
        세대를 넘기지 않는다 — 거기서는 무조건 갈아 끼우는 것이 의도다.)
        """
        async with self._recon_lock:
            if seen_gen is not None and seen_gen != self._gen:
                return                       # 다른 호출이 이미 새 세션을 세웠다
            self._stop.set()
            self.session = None
            self._ready = anyio.Event()
            self._stop = anyio.Event()
            self._failed = None
            self._gen += 1
            await tg.start(self.run)


# 백엔드 핸들 + 노출 도구/라우트 (lifespan에서 채움)
backends: dict[str, _Backend] = {}
exposed_tools: list[types.Tool] = []
route: dict[str, tuple[str, str]] = {}  # exposed_name -> (backend_key, original_name)
_task_group_holder: dict[str, object] = {}


async def _aggregate():
    """모든 백엔드에서 list_tools 수집, 충돌 도구만 프리픽스, exposed_tools/route 구축."""
    collected: list[tuple[str, types.Tool]] = []  # (backend_key, tool)
    for key, b in backends.items():
        await b._ready.wait()
        if b.session is None:
            log.error("backend %s NOT available at aggregate time: %r", key, b._failed)
            continue
        res = await b.session.list_tools()
        for t in res.tools:
            collected.append((key, t))
        log.info("backend %s -> %d tools", key, len(res.tools))

    name_counts = Counter(t.name for _, t in collected)
    exposed_tools.clear()
    route.clear()
    for key, t in collected:
        if name_counts[t.name] > 1:
            prefix = key.replace("-", "")  # mx-white-paper -> mxwhitepaper
            exposed_name = f"{prefix}_{t.name}"
        else:
            exposed_name = t.name
        exposed_tools.append(
            types.Tool(
                name=exposed_name,
                description=t.description,
                inputSchema=t.inputSchema,
                **({"outputSchema": t.outputSchema} if getattr(t, "outputSchema", None) else {}),
                **({"annotations": t.annotations} if getattr(t, "annotations", None) else {}),
                **({"title": t.title} if getattr(t, "title", None) else {}),
            )
        )
        route[exposed_name] = (key, t.name)
    log.info("AGGREGATED %d exposed tools (unique names: %d)", len(exposed_tools), len(set(route)))


HEAX_PREFIX = "heax-"  # 자동탐지된 heax-hub MCP 앱 백엔드 키 프리픽스


async def _discover_heax() -> dict[str, dict] | None:
    """heax registry(servers_url) 폴링 → {backend_key: spec(url, headers)}.

    ⚠ 반환값 계약: **폴링 실패는 None, '등록된 앱이 없음'은 {}** 로 구분한다. 예전에는 둘 다
    {} 였고 revive 루프가 "discovered 에 없으면 제거"를 그대로 적용해, HEAX Hub 가 재시작하는
    60초 동안 heax MCP 앱 40개가 통째로 게이트웨이에서 사라졌다(운영에서 하루 3회, 166→126).
    사용자에겐 "열충격 도구 있어?" → "그런 도구 없습니다"로 보인다. 일시적 불통이 카탈로그를
    지우면 안 된다.
    반환 URL = base(게이트웨이 config 의 heax Caddy 오리진) + 각 앱의 상대경로(path).
    heax 서비스 PAT 를 Authorization 으로 주입해 forward_auth(/authz) 게이트를 통과한다.
    """
    servers_url = HEAX.get("servers_url")
    if not servers_url:
        return {}
    base = (HEAX.get("base") or "").rstrip("/")
    token = HEAX.get("token")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    # 자체 인증을 쓰는 앱의 토큰 예외표 {app_id: token}. heax 서비스 PAT 는 Caddy 의
    # forward_auth 를 통과시키는 용도라, 앱이 Authorization 을 자기 백엔드로 넘겨 다시
    # 검증하면 종류가 안 맞아 전량 실패한다. kooremapper_mcp 가 그랬다 — 도구 22개가
    # 목록에는 뜨는데 호출은 100% "토큰이 유효하지 않거나 만료되었습니다"였고,
    # 노출된 2026-08-01 이후 감사로그 성공 0건이었다(발견 2026-08-12).
    app_tokens = HEAX.get("app_tokens") or {}
    try:
        async with httpx.AsyncClient(timeout=10) as cli:
            resp = await cli.get(servers_url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:  # noqa: BLE001 — 다음 주기에 재시도
        log.warning("heax registry 폴링 실패(%s): %r — 기존 heax 앱 유지", servers_url, exc)
        return None
    out: dict[str, dict] = {}
    for s in data.get("servers", []):
        sid, path = s.get("id"), s.get("path")
        if not sid or not path:
            continue
        # registry 가 주는 표시 정보(name·description)를 버리지 않는다 — 앱 단위 선택 UI 는
        # 라벨이 곧 사용자가 보는 전부라, 버리면 클라이언트가 앱 키에서 이름을 추측하게 되고
        # 실제로 틀린 이름이 노출된다(heax-kooremapper_mcp → 'Kooremapper' vs 등록명 'DynaForge MCP').
        hdrs = headers
        if app_tokens.get(sid):
            hdrs = {**headers, "Authorization": f"Bearer {app_tokens[sid]}"}
        out[f"{HEAX_PREFIX}{sid}"] = {"url": f"{base}{path}", "headers": hdrs,
                                      "allowed_groups": list(s.get("allowed_groups") or []),
                                      "label": (s.get("name") or "").strip()[:80],
                                      "description": (s.get("description") or "").strip()[:300]}
    return out


# heax registry 연속 폴링 실패 횟수 — 일시적 불통과 '정말 사라짐'을 구분하기 위한 상태.
_HEAX_FAILS = {"n": 0}


async def _revive_once(tg) -> bool:
    """재활 1회 — 죽은 백엔드 재연결 + heax 앱 재탐지 + 도구 구성 변경 감지 후 재집계.

    주기 루프(_revive_loop)와 수동 트리거(POST /refresh)가 **같은 코드**를 쓴다. 수동
    트리거가 필요한 이유는 배포 자동화 때문이다 — 외부 MCP 를 재배포한 직후 update-all 이
    카탈로그를 검증하는데, 주기가 60초라 그때까지 옛 도구 목록으로 판정하게 된다.
    변화가 있었으면 True."""
    revived = False
    # heax registry 재폴링 — 신규 MCP 앱 합류 / 레지스트리에서 사라진 앱 제거
    if HEAX.get("servers_url"):
        discovered = await _discover_heax()
        if discovered is None:
            # 폴링 실패 — 마지막 정상 상태를 그대로 유지한다(제거 금지).
            _HEAX_FAILS["n"] += 1
            log.warning("heax registry 연속 실패 %d회 — 기존 앱 %d개 유지",
                        _HEAX_FAILS["n"],
                        sum(1 for k in backends if k.startswith(HEAX_PREFIX)))
            discovered = {}
            _allow_removal = False
        else:
            _HEAX_FAILS["n"] = 0
            _allow_removal = True
        for key, spec in discovered.items():
            # 표시 정보는 백엔드 합류 여부와 무관하게 항상 갱신한다 — 이미 붙어 있는 앱도
            # registry 에서 이름이 바뀔 수 있고, 라벨은 세션 생존과 별개다.
            DISCOVERED_META[key] = {"label": spec.get("label") or "",
                                    "description": spec.get("description") or ""}
            if key in backends:
                continue
            b = _Backend(key, spec["url"], spec.get("headers"))
            backends[key] = b
            POLICY[key] = spec.get("allowed_groups") or []   # heax 앱의 그룹 필터 반영
            await tg.start(b.run)
            await b._ready.wait()
            if b.session is not None:
                log.info("heax MCP %s 합류 (%s)", key, spec["url"])
                revived = True
        for key in ([k for k in list(backends)
                     if k.startswith(HEAX_PREFIX) and k not in discovered]
                    if _allow_removal else []):
            backends.pop(key)._stop.set()
            POLICY.pop(key, None)
            log.info("heax MCP %s 제거 (레지스트리에서 사라짐)", key)
            revived = True
    # ── 연결된 백엔드의 도구 목록 재확인(G3) ──────────────────────────────
    # 앱 인스턴스가 교체돼도(SIF 재빌드·재기동) run() 은 _stop 대기로 park 중이라 예외가
    # 나지 않아 session 객체가 살아 있는 것처럼 남는다. 그러면 아래 재연결 루프가
    # 건너뛰고 카탈로그는 옛 도구로 굳는다 — 새 도구가 게이트웨이 재기동 전까지 안 보였다.
    # 주기적으로 list_tools 를 다시 받아 (a) 죽은 세션을 감지해 재연결 대상으로 돌리고
    # (b) 도구 구성이 바뀌었으면 재집계한다. 백엔드당 60초에 1회라 비용은 무시할 수준.
    for key, b in list(backends.items()):
        if b.session is None:
            continue
        try:
            with anyio.fail_after(LIVENESS_TIMEOUT_S):
                res = await b.session.list_tools()
            # ⚠ **이름만 비교하면 안 된다.** 설명·입력 스키마가 바뀌어도 이름은 그대로라
            #   재집계가 안 걸리고, 카탈로그가 옛 설명으로 굳는다 — 게이트웨이를 재기동해야만
            #   반영됐다(실측 2026-09-02: 도구 설명 2건을 고치고 앱을 재기동했는데
            #   /refresh 가 changed:false 를 냈다). 지문으로 비교한다.
            now = _tools_fp(res.tools)
            prev = _FP.get(key)
            if prev != now:
                _FP[key] = now
                if prev is not None:
                    log.info("backend %s 도구 구성·메타 변경 (%d→%d) — 재집계",
                             key, len(prev), len(now))
                    revived = True
        except Exception as exc:  # noqa: BLE001 — 죽은 세션 → 아래 재연결 루프가 처리
            log.warning("backend %s liveness 실패 (%r) — 재연결 예약", key, exc)
            b.session = None

    for key, b in backends.items():
        if b.session is not None:
            continue
        try:
            # LIVENESS_TIMEOUT_S 는 위 list_tools 한 곳에만 걸려 있었고 재연결 경로엔
            # 아무 데드라인이 없었다. 여기서 멈추면 '예외'가 아니라 '행'이라 except 도
            # 안 걸리고, MCP 클라이언트 기본 read timeout(300s)이 만료될 때까지 revive
            # 루프 전체가 얼어붙는다 — 그동안 로그도 완전 무음이다.
            # anyio 는 start() 대기가 취소되면 방금 띄운 자식 태스크도 함께 취소한다.
            with anyio.move_on_after(LIVENESS_TIMEOUT_S) as _sc:
                await b.reconnect(tg)
                await b._ready.wait()
            if _sc.cancel_called:
                log.warning("backend %s 재연결 타임아웃(%.0fs) — 다음 주기에 재시도",
                            key, LIVENESS_TIMEOUT_S)
            elif b.session is not None:
                log.info("backend %s revived — re-aggregating tools", key)
                revived = True
        except Exception as exc:  # noqa: BLE001 — 다음 주기에 재시도
            log.debug("revive %s failed: %r", key, exc)
    # 호출 경로(_call_tool)에서 재연결이 일어났으면 그쪽은 카탈로그를 못 고치므로 여기서 갱신.
    if _REAGG.pop("pending", False):
        revived = True
    if revived:
        try:
            await _aggregate()
        except Exception as exc:  # noqa: BLE001
            log.warning("re-aggregate after revive failed: %r", exc)
    return revived


async def _revive_loop(tg):
    """_revive_once 를 REVIVE_INTERVAL_S 마다 돌린다."""
    while True:
        await anyio.sleep(REVIVE_INTERVAL_S)
        try:
            await _revive_once(tg)
        except Exception as exc:  # noqa: BLE001 — 한 주기 실패가 루프를 죽이면 안 된다
            log.warning("revive 주기 실패: %r", exc)


@asynccontextmanager
async def _backends_lifespan():
    """백엔드 영속 세션 + 도구 집계. streamable_http_app 의 세션매니저 lifespan 과 함께 돈다."""
    async with anyio.create_task_group() as tg:
        _task_group_holder["tg"] = tg
        for key, spec in BACKENDS.items():
            b = _Backend(key, spec["url"], spec.get("headers"))
            backends[key] = b
            await tg.start(b.run)
        # heax-hub MCP 앱 자동탐지 → heax-<id> 백엔드로 합류 (heax_registry 있을 때만)
        # _discover_heax 는 '폴링 실패=None, 앱 없음={}' 계약이다(docstring). revive 루프는
        # `if discovered is None:` 으로 지키는데 부팅 경로만 곧바로 .items() 를 불렀다 —
        # 게이트웨이가 뜨는 순간 heax-hub(:4040)가 마침 불통이면 AttributeError 로 lifespan 이
        # 죽어 게이트웨이 자체가 못 뜬다. 선택 기능 하나가 전체 기동을 막으면 안 된다.
        # 폴링이 실패하면 heax 앱 없이 뜨고, 60초 뒤 _revive_loop 가 알아서 합류시킨다.
        _boot_heax = await _discover_heax()
        if _boot_heax is None:
            log.warning("부팅 시 heax registry 폴링 실패 — heax 앱 없이 기동한다"
                        "(%ds 후 revive 루프가 합류시킨다)", REVIVE_INTERVAL_S)
            _boot_heax = {}
        for key, spec in _boot_heax.items():
            DISCOVERED_META[key] = {"label": spec.get("label") or "",
                                    "description": spec.get("description") or ""}
            b = _Backend(key, spec["url"], spec.get("headers"))
            backends[key] = b
            POLICY[key] = spec.get("allowed_groups") or []   # heax 앱의 그룹 필터 반영
            await tg.start(b.run)
        await _aggregate()
        tg.start_soon(_revive_loop, tg)
        try:
            yield
        finally:
            for b in backends.values():
                b._stop.set()
            tg.cancel_scope.cancel()


fm = FastMCP("hwax-mcp-gateway")
# nginx 리버스프록시(/mcp-gw/) 뒤 + 개인 Claude(다양한 도메인 Host)로 접근되므로 MCP SDK 의
# DNS-rebinding Host 검증을 끈다 — 안 끄면 프록시가 넘긴 Host(localhost·도메인)를 거부해 421.
# 인가는 Bearer GW_TOKEN/포털 PAT 로 별도 수행하므로 Host 화이트리스트는 불필요.
fm.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
_low = fm._mcp_server


def _parse_groups(raw: str | None) -> list[str]:
    """콤마 구분 헤더 → 그룹 리스트(공백·빈값 제거).

    HTTP 헤더는 latin-1 만 담으므로 '연구소' 같은 비ASCII 그룹명은 클라이언트가 퍼센트
    인코딩해 보낸다(에이전트 서버 _with_groups). 여기서 되돌린다 — 순수 ASCII 값은
    unquote 해도 그대로라 기존 클라이언트와 하위호환된다.
    """
    out = []
    for g in (raw or "").split(","):
        g = g.strip()
        if not g:
            continue
        if "%" in g:
            try:
                g = unquote(g)
            except Exception:  # noqa: BLE001 — 잘못된 인코딩이면 원문 유지
                pass
        out.append(g)
    return out


def _backend_allowed(backend_key: str, groups: list[str]) -> bool:
    """백엔드 공개 여부: allowed_groups 비었으면 전체 공개, 아니면 caller groups와 교집합 필요."""
    allowed = POLICY.get(backend_key, [])
    return (not allowed) or bool(set(groups) & set(allowed))


# ── 게이트웨이 로컬 도구: save_conversation ─────────────────────────────────
# Claude(MCP) 심의의 대화 전개를 포털 서버 대화 저장소에 남긴다(웹 챗에서 이어보기).
# 신원 귀속: 호출자의 Authorization(포털 PAT)을 그대로 포털 REST 에 포워딩 → 포털이
# 자체 검증해 owner_sub = PAT sub. 게이트웨이는 신원 매핑을 하지 않는다(위조 불가).
# GW_TOKEN 경로(내부 에이전트)는 포털이 401 → CONV_UNAVAILABLE 반환(비치명적 폴백).
SAVE_CONV_TOOL = types.Tool(
    name="save_conversation",
    description=(
        "심의/대화 로그를 포털 서버 대화 저장소에 저장한다(웹 챗에서 이어보기·GLM 이어가기용). "
        "messages: [{role: user|assistant|system|persona, content, persona?, round?}] 순서대로. "
        "성공 시 conversation_id 반환, 포털 미가용/인증 불가면 CONV_UNAVAILABLE."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "title": {"type": "string", "description": "대화 제목(심의 주제 등)"},
            "kind": {"type": "string", "enum": ["chat", "deliberation"], "default": "deliberation"},
            "source": {"type": "string", "enum": ["web", "mcp"], "default": "mcp"},
            "messages": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "role": {"type": "string", "enum": ["user", "assistant", "system", "persona"]},
                        "content": {"type": "string"},
                        "persona": {"type": "string"},
                        "round": {"type": "integer"},
                    },
                    "required": ["role", "content"],
                },
            },
        },
        "required": ["title", "messages"],
    },
)


def _portal_api_base() -> str | None:
    """포털 REST base — portal.api_base 우선, 없으면 jwks_url 의 origin 에서 유도."""
    base = PORTAL.get("api_base")
    if base:
        return str(base).rstrip("/")
    jwks = PORTAL.get("jwks_url") or ""
    m = re.match(r"^(https?://[^/]+)", jwks)
    return m.group(1) if m else None


async def _save_conversation(arguments: dict) -> types.CallToolResult:
    """로컬 도구 실행: 호출자 PAT 를 포워딩해 포털 /agent/conversations 에 일괄 생성."""
    t0 = time.monotonic()

    def _fail(reason: str) -> types.CallToolResult:
        _audit("save_conversation", "portal", False, reason,
               round((time.monotonic() - t0) * 1000))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"CONV_UNAVAILABLE: {reason}")],
            isError=True,
        )

    base = _portal_api_base()
    if not base:
        return _fail("portal api base not configured")
    try:
        req = _low.request_context.request
        auth = req.headers.get("authorization") if req is not None else None
    except LookupError:
        auth = None
    if not auth:
        return _fail("no caller authorization to forward")
    # 포털 검증 상한(persona 120·content 20000·messages 200)에 맞춰 사전 정규화 — 항목 하나가
    # 길면 포털이 배치 전체를 422 로 거부해 심의 대화가 통째로 유실된다(전기박리 심의 사고).
    def _msg(m: dict) -> dict:
        role = m.get("role")
        out = {"role": role if role in ("user", "assistant", "system", "persona") else "assistant",
               "content": str(m.get("content") or "")[:20000]}
        if m.get("persona") is not None:
            out["persona"] = str(m["persona"])[:120]
        if m.get("round") is not None:
            try:
                out["round"] = int(m["round"])
            except (TypeError, ValueError):
                pass
        return out

    raw_msgs = arguments.get("messages") or []
    # kind/source 도 정규화한다. 포털 스키마가 Literal 이라 값 하나가 어긋나면 422 로
    # 배치 전체가 거부돼 심의 전문이 통째로 유실된다 — 길이 상한만 맞춰 두고 여기를
    # 비워 두면 같은 사고가 다른 필드로 재현될 뿐이다.
    _kind = str(arguments.get("kind") or "deliberation")
    _source = str(arguments.get("source") or "mcp")
    body = {
        "title": str(arguments.get("title") or "심의")[:200],
        "kind": _kind if _kind in ("chat", "deliberation") else "deliberation",
        "source": _source if _source in ("web", "mcp") else "mcp",
        # ⚠ 머리 200 을 남기면 잘리는 쪽이 꼬리 = 결정문 분할(워크플로 msgs 는 결정문이 맨 뒤다).
        #   첫 항목(user 질문) + 꼬리 199 를 지킨다 — 발언 일부를 버려도 결정문은 산다(감사 C48).
        "messages": (lambda ms: ms if len(ms) <= 200 else [ms[0]] + ms[-199:])(
            [_msg(m) for m in raw_msgs if isinstance(m, dict)]),
    }
    try:
        async with httpx.AsyncClient(timeout=15.0) as cli:
            r = await cli.post(f"{base}/agent/conversations", json=body,
                               headers={"Authorization": auth})
        if r.status_code != 200:
            return _fail(f"portal {r.status_code}")
        cid = r.json().get("id")
        _audit("save_conversation", "portal", True, None,
               round((time.monotonic() - t0) * 1000))
        return types.CallToolResult(
            content=[types.TextContent(type="text",
                     text=json.dumps({"ok": True, "conversation_id": cid}))],
        )
    except Exception as e:  # noqa: BLE001 — 포털 미가용은 비치명적(폴백 계약)
        return _fail(repr(e))


# ── 게이트웨이 로컬 도구: search_conversations ──────────────────────────────
# "예전에 이거 얘기했었는데" 를 찾아 준다. 키워드가 아니라 의미로 찾는다 — 사용자가 기억하는
# 것은 표현이 아니라 내용이기 때문이다. 신원 귀속은 save_conversation 과 같다: 호출자 PAT 를
# 포털에 그대로 넘겨 포털이 owner_sub 를 판정한다. 게이트웨이는 "누구인지"를 말하지 않는다
# — 여기서 신원을 만들어 내면 남의 대화를 읽는 경로가 생긴다.
SEARCH_CONV_TOOL = types.Tool(
    name="search_conversations",
    description=(
        "내 지난 대화(심의·웹 챗)를 의미로 검색한다. 키워드가 아니라 뜻으로 찾으므로 "
        "'그때 배터리 스웰링 논의에서 뭘 결정했더라' 같은 질문에 쓴다. 호출자 본인의 대화만 "
        "검색된다. 결과에는 대화 제목·발화자·본문 조각·유사도가 들어 있고, 전문이 필요하면 "
        "conversation_id 로 포털에서 이어보면 된다. 포털 미가용/인증 불가면 CONV_UNAVAILABLE."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "찾고 싶은 내용(문장으로 쓸수록 좋다)"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 30, "default": 8},
        },
        "required": ["query"],
    },
)


async def _search_conversations(arguments: dict) -> types.CallToolResult:
    """로컬 도구 실행: 호출자 PAT 를 포워딩해 포털 /agent/conversations/search 를 부른다."""
    t0 = time.monotonic()

    def _fail(reason: str) -> types.CallToolResult:
        _audit("search_conversations", "portal", False, reason,
               round((time.monotonic() - t0) * 1000))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"CONV_UNAVAILABLE: {reason}")],
            isError=True,
        )

    base = _portal_api_base()
    if not base:
        return _fail("portal api base not configured")
    try:
        req = _low.request_context.request
        auth = req.headers.get("authorization") if req is not None else None
    except LookupError:
        auth = None
    if not auth:
        return _fail("no caller authorization to forward")
    q = str(arguments.get("query") or "").strip()
    if len(q) < 2:
        return _fail("query 가 너무 짧습니다")
    try:
        limit = max(1, min(30, int(arguments.get("limit") or 8)))
    except (TypeError, ValueError):
        limit = 8
    try:
        # 임베딩 + 색인이 걸릴 수 있어 save 보다 넉넉히 준다(첫 검색은 전량 색인).
        async with httpx.AsyncClient(timeout=120.0) as cli:
            r = await cli.post(f"{base}/agent/conversations/search",
                               json={"query": q, "limit": limit},
                               headers={"Authorization": auth})
        if r.status_code != 200:
            return _fail(f"portal {r.status_code}")
        _audit("search_conversations", "portal", True, None,
               round((time.monotonic() - t0) * 1000))
        return types.CallToolResult(
            content=[types.TextContent(type="text",
                     text=json.dumps(r.json(), ensure_ascii=False))],
        )
    except Exception as e:  # noqa: BLE001 — 포털 미가용은 비치명적(폴백 계약)
        return _fail(repr(e))


# ── 게이트웨이 로컬 도구: list_tool_apps ────────────────────────────────────
# 167개 도구가 평평하게 보이면 "무엇을 할 수 있는지" 파악이 불가능하다. 도구를 소유 앱(도메인)
# 단위로 묶어 보여주고, 각 앱의 접근 가능 여부(그룹 인가 + 백엔드 생존)까지 함께 알려준다.
# 앱 표시 정보 — 앱 단위 선택 UI 는 라벨·설명이 곧 사용자가 보는 전부다.
# heax 앱은 registry 가 name·description 을 주므로 자동이고, 정적 백엔드는 출처가 아예 없어
# (config 에 url/headers 뿐, MCP initialize 의 serverInfo 도 'mxwp-rag' 수준) 여기 손으로 둔다.
# 신규 앱이 붙어도 이름은 registry 를 따라가므로 이 표는 정적 5개만 유지하면 된다.
# registry 발굴로 채워지는 표시 정보 — heax 앱은 여기, 정적 백엔드는 아래 APP_META.
# backends 는 _Backend 객체라 라벨을 담지 못하고 BACKENDS 는 정적 config 사본이라 heax 앱이 없다.
DISCOVERED_META: dict[str, dict] = {}

APP_META: dict[str, dict] = {
    "reportarchive": {"label": "리포트 아카이브",
                      "description": "보고서 작성·검색·온톨로지 — 템플릿으로 보고서를 만들고 과거 보고 이력과 객체 그래프를 조회한다."},
    "signalforge": {"label": "SignalForge VOC",
                    "description": "글로벌 커뮤니티 VOC 인텔리전스 — 제품·이슈별 불만을 수집·분류하고 급상승 이슈를 알린다."},
    "mx-white-paper": {"label": "MX 백서",
                       "description": "사내 업무 백서 검색 — 축적된 업무 지식·노하우 문서를 의미 검색으로 찾는다."},
    "ai-data-hub": {"label": "AI 데이터 허브",
                    "description": "사내 데이터 계층화·온톨로지·API 프록시 — 흩어진 사내 데이터와 시스템 API 를 한 곳에서 조회한다."},
    "smart-twin-cluster": {"label": "시뮬레이션 클러스터",
                           "description": "Slurm 해석 잡 조회 — 실행 중·완료 해석 잡과 결과 파일 상태를 읽는다(읽기 전용)."},
    "_gateway": {"label": "게이트웨이 공통",
                 "description": "앱·도구 카탈로그와 대화 저장 등 게이트웨이 자체 기능."},
}


def _app_meta(key: str) -> dict:
    """앱 표시 정보 — registry(heax) > 큐레이션 표(정적) > 키에서 유도 순."""
    spec = DISCOVERED_META.get(key) or BACKENDS.get(key) or {}
    label = (spec.get("label") or "").strip()
    desc = (spec.get("description") or "").strip()
    curated = APP_META.get(key, {})
    if not label:
        label = curated.get("label") or ""
    if not desc:
        desc = curated.get("description") or ""
    if not label:
        # 마지막 폴백 — heax- 접두사와 _mcp 접미사를 떼고 사람이 읽을 형태로.
        base = key.removeprefix(HEAX_PREFIX).removesuffix("_mcp").removesuffix("-mcp")
        label = " ".join(w.capitalize() for w in base.replace("_", " ").replace("-", " ").split()) or key
    return {"label": label, "description": desc}


LIST_APPS_TOOL = types.Tool(
    name="list_tool_apps",
    description=(
        "이 게이트웨이에 연결된 MCP 앱(도메인) 목록과 각 앱의 도구를 계층적으로 반환한다. "
        "'무슨 앱/도구가 있냐', '어떤 기능이 되냐' 같은 질문에 전체 도구를 나열하는 대신 이걸 호출하라. "
        "각 앱마다 accessible(내 권한으로 사용 가능한지)·reachable(백엔드 생존)·tool_count·tools 를 준다. "
        "app 인자를 주면 그 앱의 도구만 상세(이름+설명)로 반환한다."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "app": {"type": "string", "description": "특정 앱 키(예: heax-thermal_shock_mcp). 생략 시 전체 앱 요약."},
            "include_tools": {"type": "boolean", "description": "전체 목록에도 도구 이름을 포함(기본 true)."},
        },
    },
)


INVOKE_TOOL = types.Tool(
    name="invoke_tool",
    description=(
        "게이트웨이의 아무 도구나 **이름으로 즉시 호출**한다 — search_tools 로 찾은 도구가 "
        "현재 목록에 바인딩돼 있지 않아도 이걸로 바로 쓸 수 있다(웹 챗의 '찾은 즉시 호출' 경로). "
        "arguments 는 그 도구의 스키마를 따라야 한다 — search_tools 결과의 args 를 참고하고, "
        "모르면 추측하지 말고 search_tools/list_tool_apps 로 먼저 확인하라. "
        "안전장치: 파괴·제어성 도구(delete_/remove_/cancel_/purge_/…_control/…_set_state)는 "
        "여기로 못 부른다 — 그런 작업은 직접 바인딩된 도구로만 한다."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "호출할 도구 이름(search_tools 결과의 tool)"},
            "arguments": {"type": "object", "description": "그 도구에 넘길 인자 객체"},
        },
        "required": ["name"],
    },
)
# 범용 실행기로는 못 부르는 것 — 한 번의 환각이 곧 파괴가 되는 도구들. 직접 바인딩 전용.
_INVOKE_DENY_PREFIX = ("delete_", "remove_", "cancel_", "purge_", "destroy_")
_INVOKE_DENY_SUFFIX = ("_control", "_set_state")


SEARCH_TOOLS_TOOL = types.Tool(
    name="search_tools",
    description=(
        "하고 싶은 일을 한 문장으로 주면 맞는 도구를 이름·설명에서 찾아 추천한다(전 앱 대상). "
        "맞는 도구가 안 보이거나 앱이 많아 고르기 어려울 때 **먼저** 이걸 호출하라 — "
        "기본 노출에서 숨겨진 도구도 여기서는 전부 찾아진다. 결과의 도구는 이름으로 바로 호출 "
        "가능하다. 결과가 비면 list_tool_apps 로 앱 목록을 훑어라."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "하고 싶은 일(한국어/영어, 예: '과거 보고서 요약', 'mesh quality check')"},
            "limit": {"type": "integer", "description": "최대 결과 수(기본 8)"},
        },
        "required": ["query"],
    },
)


async def _search_tools(arguments: dict) -> types.CallToolResult:
    """도구 검색 안내대 — 351개 평면 노출의 선택 비용을 줄이는 입구(실측: 상위 40개가
    호출의 79%, 30%는 한 번도 안 불림 — 롱테일은 검색으로 찾게 한다). 임베딩 없이
    부분문자열 매칭(한국어는 조사 탓에 토큰 경계가 흐려 substring 이 더 잘 맞는다)."""
    q = str((arguments or {}).get("query") or "").strip().lower()
    limit = max(1, min(20, int((arguments or {}).get("limit") or 8)))
    if len(q) < 2:
        return types.CallToolResult(content=[types.TextContent(
            type="text", text='{"error": "query 를 2자 이상 주세요"}')], isError=True)
    terms = [w for w in re.split(r"[\s,;·/()\[\]{}\"']+", q) if len(w) >= 2]
    # 도구 이름이 전부 영어라 한국어 질의가 이름을 못 맞힌다 — 도메인 동의어로 넓힌다.
    # (조사가 붙어도 substring 이라 '보고서를'→'보고서' 매칭은 된다.)
    _SYN = {
        "보고서": ("report",), "리포트": ("report",), "요약": ("digest", "summary"),
        "검색": ("search",), "조회": ("get", "list", "search"), "목록": ("list",),
        "물성": ("material", "property"), "재료": ("material",), "곡선": ("curve",),
        "잡": ("job",), "작업": ("job",), "상태": ("status", "health"),
        "슬럼": ("slurm",), "슬럼잡": ("slurm",), "클러스터": ("cluster",),
        "메쉬": ("mesh",), "메시": ("mesh",), "형상": ("geometry", "shape"),
        "시험": ("test",), "측정": ("measure",), "업로드": ("upload",),
        "그래프": ("plot", "chart"), "차트": ("chart", "plot"), "그림": ("plot", "render"),
        "템플릿": ("template",), "초안": ("draft",), "전문가": ("agent", "expert"),
        "부품": ("part",), "적층": ("laminate",), "대화": ("conversation",),
    }
    expand = {w: (w,) + tuple(s for k, ss in _SYN.items() if k in w for s in ss) for w in terms}
    groups = _request_groups()
    rows = []
    for t in _visible_tools(groups):
        name = t.name.lower()
        desc = (t.description or "").lower()
        app = route.get(t.name, ("_gateway",))[0]
        meta = _app_meta(app) if app != "_gateway" else {"label": "gateway", "description": ""}
        hay_app = (str(meta.get("label") or "") + " " + str(meta.get("description") or "")).lower()
        score, covered = 0, 0
        for w, variants in expand.items():
            name_hit = any(v in name for v in variants)
            desc_freq = max(min(desc.count(v), 3) for v in variants)
            app_hit = any(v in hay_app for v in variants)
            if name_hit or desc_freq or app_hit:
                covered += 1
                score += 4 * name_hit + desc_freq + app_hit
        if score > 0:
            # 커버리지 승수 — 질의어를 더 많이 맞힌 도구가 개별 단어 빈도보다 앞선다.
            rows.append((score * (1 + covered / max(1, len(terms))),
                         t.name, app, (t.description or "").strip()[:220], t))
    rows.sort(key=lambda r: (-r[0], r[1]))

    def _args_summary(t) -> dict:
        """invoke_tool 로 바로 부를 수 있게 인자 요약을 붙인다 — 이게 없으면 모델이
        스키마를 추측해 넣는다(범용 실행기의 최대 실패 모드)."""
        sch = getattr(t, "inputSchema", None) or {}
        props = sch.get("properties") or {}
        return {
            "required": sch.get("required") or [],
            "properties": {k: str((v or {}).get("type") or "any")
                           for k, v in list(props.items())[:12]},
        }
    payload = {
        "query": q,
        "matches": [{"tool": n, "app": a, "description": d, "args": _args_summary(t)}
                    for _, n, a, d, t in rows[:limit]],
        "match_count": len(rows),
        "note": "여기 나온 도구는 현재 목록에 없어도 invoke_tool(name, arguments) 로 즉시 "
                "호출할 수 있다(args 의 required 를 채워라). 원하는 게 없으면 질문을 바꿔 "
                "다시 검색하거나 list_tool_apps(app='<키>') 로 앱 상세를 보라.",
    }
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(payload, ensure_ascii=False, indent=2))]
    )


async def _list_tool_apps(arguments: dict) -> types.CallToolResult:
    groups = _request_groups()
    want_app = str((arguments or {}).get("app") or "").strip()
    include = (arguments or {}).get("include_tools")
    include = True if include is None else bool(include)

    by_app: dict[str, list[types.Tool]] = {}
    for t in exposed_tools:
        by_app.setdefault(route[t.name][0], []).append(t)
    by_app.setdefault("_gateway", []).extend([SAVE_CONV_TOOL, SEARCH_CONV_TOOL, LIST_APPS_TOOL, SEARCH_TOOLS_TOOL, INVOKE_TOOL])
    # 연결이 끊긴 백엔드는 도구가 집계되지 않아 목록에서 통째로 사라진다 — 접근성 점검이
    # 목적이므로 '앱은 있는데 지금 불통'을 보이게 빈 항목으로 채운다.
    for _k in backends:
        by_app.setdefault(_k, [])

    apps = []
    for key in sorted(by_app, key=lambda k: -len(by_app[k])):
        tools = by_app[key]
        local = key == "_gateway"
        # 접근성: 그룹 인가(로컬 도구는 전 그룹) + 백엔드 세션 생존.
        accessible = True if local else _backend_allowed(key, groups)
        reachable = True if local else (key in backends and backends[key].session is not None)
        if want_app and key != want_app:
            continue
        meta = _app_meta(key)
        entry = {
            "app": key,
            "label": meta["label"],
            "description": meta["description"],
            "tool_count": len(tools),
            "accessible": accessible,
            "reachable": reachable,
            "status": "ok" if (accessible and reachable) else
                      ("no_access" if not accessible else "backend_down"),
        }
        if want_app:
            entry["tools"] = [{"name": t.name, "description": (t.description or "")[:300]} for t in tools]
        elif include:
            entry["tools"] = sorted(t.name for t in tools)
        apps.append(entry)

    payload = {
        "apps": apps,
        "app_count": len(apps),
        "total_tools": sum(a["tool_count"] for a in apps),
        "note": "accessible=내 권한으로 호출 가능, reachable=백엔드 연결 정상. "
                "특정 앱의 도구 설명은 list_tool_apps(app='<키>') 로 조회.",
    }
    if want_app and not apps:
        payload["error"] = f"unknown app: {want_app}"
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(payload, ensure_ascii=False, indent=2))]
    )


def _visible_tools(groups: list[str]) -> list[types.Tool]:
    # 로컬 도구는 전 그룹 노출 — 실제 게이트는 포털 인증(PAT 포워딩)이 담당.
    return [t for t in exposed_tools if _backend_allowed(route[t.name][0], groups)] + [SAVE_CONV_TOOL, SEARCH_CONV_TOOL, LIST_APPS_TOOL, SEARCH_TOOLS_TOOL, INVOKE_TOOL]


def _request_groups() -> list[str]:
    """현재 요청 헤더(X-HWAX-Groups)에서 caller groups 추출.
    요청 컨텍스트·헤더가 없으면 [](=제한 백엔드는 숨김 → fail-closed)."""
    try:
        req = _low.request_context.request
    except LookupError:
        return []
    raw = req.headers.get(GROUPS_HEADER) if req is not None else None
    return _parse_groups(raw)


def _request_user() -> str:
    """현재 요청 헤더(X-HWAX-User)의 호출자 이메일. 없으면 ''(=위임 없음)."""
    try:
        req = _low.request_context.request
    except LookupError:
        return ""
    raw = req.headers.get(USER_HEADER) if req is not None else None
    if not raw:
        return ""
    try:
        return unquote(raw).strip().lower()
    except Exception:  # noqa: BLE001 — 헤더가 깨져도 호출을 막지 않는다(위임 없음으로 강등)
        return ""


# ── 사용자별 백엔드 자격증명 ────────────────────────────────────────────────
# {(app_id, email): (token, 만료 monotonic)}. 발급이 '같은 이름의 직전 토큰'을 회수하므로
# 같은 사용자에 대한 동시 발급은 서로를 무효화한다 — 사용자 단위 락으로 직렬화한다.
_USER_PATS: dict[tuple[str, str], tuple[str, float]] = {}
_USER_PAT_LOCKS: dict[tuple[str, str], anyio.Lock] = {}


async def _mint_user_pat(conf: dict, email: str) -> str:
    """백엔드의 게이트웨이 SSO 로 이 사용자의 PAT 를 발급받는다. 실패 시 예외."""
    async with httpx.AsyncClient(timeout=15) as cli:
        resp = await cli.post(conf["sso_url"], headers={
            "X-Heax-Gateway-Secret": conf["secret"],
            "X-Heax-User-Email": email,
            # 클라이언트를 구분해야 이 발급이 사용자의 웹 세션 토큰을 회수하지 않는다.
            "X-Heax-Client": conf.get("client") or "deliberation",
        })
    if resp.status_code != 200:
        raise RuntimeError(f"SSO {resp.status_code}: {resp.text[:200]}")
    data = resp.json()

    def _find(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in ("access_token", "token") and isinstance(v, str):
                    return v
                got = _find(v)
                if got:
                    return got
        return None

    tok = _find(data)
    if not tok:
        raise RuntimeError(f"SSO 응답에 토큰 없음: {json.dumps(data, ensure_ascii=False)[:200]}")
    return tok


async def _user_pat(app_id: str, email: str, *, force: bool = False) -> str:
    """캐시된 사용자 PAT (없거나 force 면 발급). 사용자 단위로 직렬화한다."""
    key = (app_id, email)
    lock = _USER_PAT_LOCKS.setdefault(key, anyio.Lock())
    async with lock:
        hit = _USER_PATS.get(key)
        if hit and not force and hit[1] > time.monotonic():
            return hit[0]
        tok = await _mint_user_pat(PER_USER_SSO[app_id], email)
        _USER_PATS[key] = (tok, time.monotonic() + USER_PAT_TTL_S)
        log.info("user PAT minted for %s on %s", email, app_id)
        return tok


async def _call_as_user(b: "_Backend", original: str, arguments: dict, token: str, timeout_s: float,
                        extra_headers: dict | None = None):
    """이 호출만을 위한 단발 세션으로 백엔드를 부른다.

    영속 세션은 열 때의 헤더(서비스 계정)를 그대로 물고 있어 호출별 자격증명 교체가 안 된다.
    사용자별 스코프가 필요한 백엔드는 그래서 세션을 매번 새로 연다 — 핸드셰이크 비용이
    붙지만 대상이 로컬 앱이고, 대안은 '남의 데이터가 보이거나 아무것도 안 보이는' 둘 뿐이다.
    extra_headers 는 Authorization 외 헤더 교체용(예: RA 의 X-Workspace-Slug 를 그 사용자
    부서로) — 같은 이름의 서비스 계정 헤더를 대소문자 무관하게 밀어내고, 값이 None 이면
    **삭제**한다(사용자 부서가 비었을 때 서비스 부서가 새어 들어가 "부서를 찾을 수
    없습니다: dev" 가 나던 누수를 막는다 — cae00 실사고 2026-09-03).
    """
    base = dict(b.headers or {})
    if extra_headers:
        drop = {k.lower() for k in extra_headers}
        base = {k: v for k, v in base.items() if k.lower() not in drop}
    hdrs = {**base, "Authorization": f"Bearer {token}",
            **{k: v for k, v in (extra_headers or {}).items() if v is not None}}
    with anyio.fail_after(timeout_s):
        async with streamablehttp_client(b.url, headers=hdrs) as (read, write, _sid):
            async with ClientSession(read, write) as sess:
                await sess.initialize()
                return await sess.call_tool(original, arguments,
                                            read_timeout_seconds=timedelta(seconds=timeout_s))


@_low.list_tools()
async def _list_tools():
    # 도구 목록을 caller groups로 필터(보이지 않는 도구는 LLM이 알 수도 없음).
    return _visible_tools(_request_groups())


@_low.call_tool(validate_input=False)
async def _call_tool(name: str, arguments: dict):
    t0 = time.monotonic()
    # 범용 실행기 — 이름·인자를 안쪽 도구로 바꿔 끼우고 **아래 정상 경로를 그대로 탄다**
    # (인가·캐시·사용자 위임·감사 전부 기존 로직 적용). 재귀·파괴 도구만 여기서 차단.
    if name == INVOKE_TOOL.name:
        inner = str((arguments or {}).get("name") or "").strip()
        inner_args = (arguments or {}).get("arguments") or {}
        if not inner or inner == INVOKE_TOOL.name:
            return types.CallToolResult(content=[types.TextContent(
                type="text", text="invoke_tool: name 에 호출할 도구 이름을 주세요.")], isError=True)
        if inner.startswith(_INVOKE_DENY_PREFIX) or inner.endswith(_INVOKE_DENY_SUFFIX):
            _audit(name, None, False, f"invoke-denied:{inner}", 0)
            return types.CallToolResult(content=[types.TextContent(
                type="text", text=(f"invoke_tool: '{inner}' 은 파괴·제어성 도구라 범용 실행기로 "
                                   "부를 수 없습니다. 직접 바인딩된 도구로만 호출하세요."))],
                isError=True)
        if not isinstance(inner_args, dict):
            return types.CallToolResult(content=[types.TextContent(
                type="text", text="invoke_tool: arguments 는 객체여야 합니다.")], isError=True)
        log.info("invoke_tool → %s", inner)
        name, arguments = inner, inner_args
    if name == SAVE_CONV_TOOL.name:  # 게이트웨이 로컬 도구(백엔드 라우팅 없음)
        return await _save_conversation(arguments or {})
    if name == SEARCH_CONV_TOOL.name:
        return await _search_conversations(arguments or {})
    if name == LIST_APPS_TOOL.name:
        return await _list_tool_apps(arguments or {})
    if name == SEARCH_TOOLS_TOOL.name:
        return await _search_tools(arguments or {})
    if name not in route:
        _audit(name, None, False, "unknown tool", 0)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"unknown tool: {name}")],
            isError=True,
        )
    backend_key, original = route[name]
    # tools/list에서 숨겼더라도 직접 호출을 시도할 수 있으니 호출 시점에도 인가 재확인(enforcement).
    if not _backend_allowed(backend_key, _request_groups()):
        _audit(name, backend_key, False, "forbidden", 0)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"forbidden: {name}")],
            isError=True,
        )
    b = backends[backend_key]
    # ── 읽기 전용 캐시 ── 인가(위)를 통과한 뒤에 본다. 순서가 반대면 권한 없는 호출자가
    #    캐시된 남의 결과를 받는다. 키에도 신원이 들어간다(_cache_key 주석 참조).
    ckey = _cache_key(backend_key, original, arguments)
    if ckey is not None:
        _hit = _cache_get(ckey)
        if _hit is not None:
            _audit(name, backend_key, True, "cache-hit", 0)
            return _hit
    else:
        # 캐시 대상이 아니다 = 쓰기이거나 알 수 없는 도구. 그 백엔드의 캐시를 버린다 —
        # 방금 만든 것이 TTL 동안 목록에 안 보이는 read-after-write 를 막는다.
        _cache_flush_backend(backend_key)
    # 행 걸린 백엔드가 챗 SSE 체인 전체를 무기한 블록하지 않게 호출당 타임아웃을 건다.
    call_timeout = timedelta(seconds=CALL_TIMEOUT_S)

    # 사용자 위임 — 이 백엔드가 사용자별 스코프를 쓰고 호출자 신원이 있으면, 서비스 계정이 아니라
    # 그 사용자의 자격증명으로 부른다. 신원이 없으면 종전대로 서비스 계정(감사에 사유를 남긴다).
    app_id = backend_key[len(HEAX_PREFIX):] if backend_key.startswith(HEAX_PREFIX) else ""
    note = None   # 서비스 계정으로 강등된 사유 — 아래 정상 경로의 감사기록에 실린다.
    if app_id in PER_USER_SSO:
        email = _request_user()
        if not email:
            log.warning("per-user backend %s called without %s — 서비스 계정 시야로 응답한다",
                        backend_key, USER_HEADER)
            # 여기서 따로 감사하지 않는다 — 호출은 아래에서 실제로 일어나므로, 미리 남기면
            # 한 호출에 기록이 두 줄(가짜 성공 + 진짜)이 되어 감사로그가 호출 수를 부풀린다.
            note = "no-identity"
        else:
            for attempt in (0, 1):   # 폐기된 캐시 토큰은 1회 재발급 후 재시도
                try:
                    tok = await _user_pat(app_id, email, force=bool(attempt))
                    res = await _call_as_user(b, original, arguments, tok, CALL_TIMEOUT_S)
                except Exception as exc:  # noqa: BLE001
                    if attempt == 0:
                        log.warning("per-user call %s failed (%r) — 토큰 재발급 후 1회 재시도",
                                    name, exc)
                        continue
                    _audit(name, backend_key, False, f"per-user: {exc!r}",
                           round((time.monotonic() - t0) * 1000))
                    # 서비스 계정으로 조용히 강등하지 않는다 — 그러면 '내 모델 0건'이라는
                    # 사실과 다른 답이 나가고, 실패가 정상 응답과 구분되지 않는다.
                    return types.CallToolResult(
                        content=[types.TextContent(type="text", text=(
                            f"{backend_key}: {email} 자격증명으로 호출하지 못했습니다 ({exc!r}). "
                            "이 앱은 사용자별 데이터라 서비스 계정 결과로 대체하지 않습니다."))],
                        isError=True,
                    )
                _audit(name, backend_key, not getattr(res, "isError", False),
                       f"as:{email}", round((time.monotonic() - t0) * 1000))
                return _cache_put(ckey, res)
    elif backend_key in PORTAL_CONN_BACKENDS:
        # 포털 등록 연결 토큰 위임(RA 등) — 등록한 사용자만 본인 명의, 나머지는 서비스 계정.
        email = _request_user()
        if not email:
            note = "no-identity"
        else:
            conn = await _portal_connection(PORTAL_CONN_BACKENDS[backend_key], email)
            if conn is None:
                note = "no-connection"   # 미등록 — 종전 서비스 계정 경로로 폴백
            else:
                # 사용자 부서가 비어 있으면 헤더를 **지운다**(None) — 서비스 계정의
                # X-Workspace-Slug 가 남으면 그 부서 명의 오류가 사용자에게 뒤집어씌워진다.
                extra = {"X-Workspace-Slug": conn.get("workspace") or None}
                try:
                    res = await _call_as_user(b, original, arguments, conn["token"],
                                              CALL_TIMEOUT_S, extra_headers=extra)
                except Exception as exc:  # noqa: BLE001
                    _audit(name, backend_key, False, f"conn-user: {exc!r}",
                           round((time.monotonic() - t0) * 1000))
                    # 서비스 계정으로 조용히 강등하지 않는다 — 강등하면 보고서가 다시
                    # 서비스 계정 명의로 쌓여 오귀속이 재발한다. 재등록을 안내한다.
                    return types.CallToolResult(
                        content=[types.TextContent(type="text", text=(
                            f"{backend_key}: {email} 의 등록 토큰으로 호출하지 못했습니다 "
                            f"({exc!r}). 포털 API 토큰 페이지에서 Report Archive 토큰을 "
                            "다시 등록하세요(만료·폐기 가능성)."))],
                        isError=True,
                    )
                _audit(name, backend_key, not getattr(res, "isError", False),
                       f"as-conn:{email}", round((time.monotonic() - t0) * 1000))
                return _cache_put(ckey, res)

    # 이 호출이 쓰는 세션의 세대. 실패했을 때 "내가 죽었다고 본 그 세션" 을 가리키므로,
    # 그 사이 다른 호출이 이미 갈아 끼웠다면 새 세션을 또 부수지 않는다. try 밖에서 잡는다 —
    # 안에서 잡으면 session is None 분기에서 미정의가 된다.
    _gen = b._gen
    try:
        if b.session is None:
            raise RuntimeError("backend session down")
        res = await b.session.call_tool(original, arguments, read_timeout_seconds=call_timeout)
        _audit(name, backend_key, not getattr(res, "isError", False), note,
               round((time.monotonic() - t0) * 1000))
        return _cache_put(ckey, res)
    except Exception as e:  # noqa: BLE001
        log.warning("call %s on %s failed (%r), reconnecting once", name, backend_key, e)
        try:
            tg = _task_group_holder.get("tg")
            if tg is not None:
                await b.reconnect(tg, _gen)
                await b._ready.wait()
                if b.session is not None:
                    # 재연결했으면 그 백엔드의 도구 구성이 바뀌었을 수 있다(앱 교체). 호출 지연을
                    # 늘리지 않도록 여기서 재집계하지 않고 revive 루프에 예약만 건다(G3).
                    _REAGG["pending"] = True
                    res = await b.session.call_tool(original, arguments,
                                                    read_timeout_seconds=call_timeout)
                    _audit(name, backend_key, not getattr(res, "isError", False),
                           "reconnected" + (f"+{note}" if note else ""),
                           round((time.monotonic() - t0) * 1000))
                    return _cache_put(ckey, res)
        except Exception as e2:  # noqa: BLE001 — 재시도 실패도 정돈된 isError 로 (프로토콜 에러 방지)
            log.warning("retry of %s on %s failed too (%r)", name, backend_key, e2)
            e = e2
        _audit(name, backend_key, False, repr(e), round((time.monotonic() - t0) * 1000))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"backend {backend_key} unavailable: {e!r}")],
            isError=True,
        )


def _bearer_gate(app, pat_verifier=None):
    """순수 ASGI 미들웨어: /mcp 인가. Bearer <GW_TOKEN>(내부 에이전트) 또는 포털 PAT(개인 Claude 등).
    PAT 로 들어오면 PAT 의 groups 를 x-hwax-groups 로 강제 주입해 그룹별 도구 필터가 적용된다."""
    expected = f"Bearer {GW_TOKEN}"

    async def middleware(scope, receive, send):
        if scope["type"] != "http":
            await app(scope, receive, send)
            return
        if scope.get("path") == "/health":
            # 무인증 헬스: 오케스트레이터가 MCP 핸드셰이크 없이 싸게 프로브
            body = json.dumps({
                "status": "ok",
                "tools": len(exposed_tools),
                "backends": {k: (b.session is not None) for k, b in backends.items()},
                # 캐시 효과를 밖에서 볼 수 있게 — 안 보이면 켜졌는지도 모른다.
                "cache": {**_CACHE_STAT, "size": len(_RESP_CACHE), "ttl_s": CACHE_TTL_S},
                "policy": POLICY,
            }).encode()
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": body})
            return
        if scope.get("path") == "/tools-map":
            # 무인증: 도구 → 백엔드(소유 MCP 앱) 매핑. 도구가 166개로 평평하게 쏟아지면 고르기
            # 어려워, 클라이언트가 '어느 MCP 앱의 기능인지'로 계층화할 수 있게 노출한다.
            _map = {name: bk for name, (bk, _orig) in route.items()}
            # 게이트웨이 로컬 도구(save_conversation 등)는 route 에 없다 — 미분류로 남지 않게
            # '_gateway' 로 귀속시킨다(앱이 늘어도 분류 누락 0 을 유지).
            for _t in list(exposed_tools) + [SAVE_CONV_TOOL, SEARCH_CONV_TOOL]:
                _map.setdefault(_t.name, "_gateway")
            _map.setdefault(LIST_APPS_TOOL.name, "_gateway")
            # 앱 단위 선택 UI 용 계층 정보. map 만 주면 (a) 앱 라벨·설명이 없어 클라이언트가
            # 앱 키에서 이름을 추측하게 되고 (b) 세션이 끊긴 앱은 route 에 도구가 없어 목록에서
            # 통째로 사라진다. backends 를 먼저 채워 '앱은 있는데 지금 불통'을 보이게 한다.
            _counts: dict[str, int] = {k: 0 for k in backends}
            for _bk in _map.values():
                _counts[_bk] = _counts.get(_bk, 0) + 1
            _apps = []
            for _k in sorted(_counts, key=lambda k: -_counts[k]):
                _m = _app_meta(_k)
                _apps.append({
                    "app": _k, "label": _m["label"], "description": _m["description"],
                    "tool_count": _counts[_k],
                    "reachable": _k == "_gateway" or (
                        _k in backends and backends[_k].session is not None),
                })
            body = json.dumps({
                "map": _map,
                "backends": sorted(set(_map.values())),
                "apps": _apps,
            }, ensure_ascii=False).encode()
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": body})
            return
        if scope.get("path") == "/refresh" and scope.get("method") == "POST":
            # 외부 MCP 의 기능 변경을 **즉시** 반영시키는 트리거. 주기 루프가 60초마다 같은
            # 일을 하지만, 배포 직후 검증(update-all)이 그때까지 옛 목록으로 판정하게 된다.
            # 백엔드에 I/O 를 일으키므로 GW_TOKEN 을 요구한다(무인증 /health·/tools-map 과 다름).
            if dict(scope.get("headers") or {}).get(b"authorization", b"").decode("latin-1") != expected:
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json")]})
                await send({"type": "http.response.body", "body": b'{"error":"unauthorized"}'})
                return
            _tg = _task_group_holder.get("tg")
            if _tg is None:
                await send({"type": "http.response.start", "status": 503,
                            "headers": [(b"content-type", b"application/json")]})
                await send({"type": "http.response.body", "body": b'{"error":"not ready"}'})
                return
            _before = len(exposed_tools)
            try:
                _changed = await _revive_once(_tg)
                _body = json.dumps({"ok": True, "changed": bool(_changed),
                                    "tools_before": _before, "tools": len(exposed_tools),
                                    "backends": {k: (b.session is not None)
                                                 for k, b in backends.items()}}).encode()
                _status = 200
            except Exception as exc:  # noqa: BLE001 — 트리거 실패가 게이트웨이를 죽이면 안 된다
                log.warning("/refresh 실패: %r", exc)
                _body = json.dumps({"ok": False, "error": str(exc)[:200]}).encode()
                _status = 500
            await send({"type": "http.response.start", "status": _status,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": _body})
            return
        if scope.get("path", "").startswith("/api/"):
            # REST 프록시: GW_TOKEN이 아니라 라우트 핸들러가 포털 PAT(JWKS)로 자체 인증.
            await app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        auth = headers.get(b"authorization", b"").decode("latin-1")
        if auth == expected:
            # 내부 에이전트 서버: GW_TOKEN. groups 는 에이전트가 x-hwax-groups 로 실어 보냄(신뢰).
            await app(scope, receive, send)
            return
        # GW_TOKEN 이 아니면 포털 PAT(개인 Claude 등) 로 검증 시도 → 성공 시 PAT 의 groups 로 도구 필터.
        token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
        claims = await pat_verifier.verify(token, MCP_AUDIENCE) if (token and pat_verifier) else None
        if claims is not None:
            groups = ",".join(str(g) for g in (claims.get("groups") or []))
            # 클라이언트가 위조로 넣었을 x-hwax-groups 는 버리고, 검증된 PAT 의 groups 로 강제한다.
            # 신원 헤더도 groups 와 똑같이 다룬다 — 클라이언트가 실어 보낸 값은 버리고 검증된
            # PAT 의 것만 싣는다. PAT 에 이메일이 없으면 아무것도 싣지 않는다(위조로 남의 시야를
            # 얻는 경로가 생기면 안 되므로, 신원 없음 쪽으로 닫는다).
            fresh = [(k, v) for (k, v) in (scope.get("headers") or [])
                     if k.lower() not in (GROUPS_HEADER.encode(), USER_HEADER.encode())]
            # PAT 의 groups 에도 한글이 올 수 있다 — 같은 규칙으로 인코딩해 실어야 헤더가 안 깨진다.
            fresh.append((GROUPS_HEADER.encode(), quote(groups, safe=",").encode("latin-1")))
            _email = str(claims.get("email") or "").strip().lower()
            if _email:
                fresh.append((USER_HEADER.encode(), quote(_email, safe="@.").encode("latin-1")))
            await app({**scope, "headers": fresh}, receive, send)
            return
        await send({
            "type": "http.response.start",
            "status": 401,
            "headers": [(b"content-type", b"application/json")],
        })
        await send({
            "type": "http.response.body",
            "body": b'{"error":"unauthorized"}',
        })
        return

    return middleware


def main():
    star = fm.streamable_http_app()
    # REST 프록시 라우트(/api/<site>/<path>) 를 MCP 마운트보다 먼저 매칭되게 삽입.
    if REST:
        from rest_proxy import RestProxy
        proxy = RestProxy(REST, PORTAL, _audit)
        star.router.routes[:0] = proxy.routes()
        log.info("REST proxy enabled: %d sites (%s)", len(REST), ", ".join(REST))
    # streamable_http_app 의 lifespan 은 세션매니저 run() 만 돈다. 백엔드 집계 lifespan 을 함께 묶는다.
    sm_lifespan = star.router.lifespan_context

    @asynccontextmanager
    async def _combined(app):
        async with _backends_lifespan():
            async with sm_lifespan(app):
                yield

    star.router.lifespan_context = _combined
    # 포털 PAT 로 /mcp 를 여는 검증기(개인 Claude 등). portal.jwks_url 이 있을 때만 활성.
    pat_verifier = None
    if PORTAL.get("jwks_url"):
        from rest_proxy import PortalPatVerifier
        pat_verifier = PortalPatVerifier(PORTAL)
        log.info("MCP PAT auth enabled (audience=%s)", MCP_AUDIENCE)
    app = _bearer_gate(star, pat_verifier)
    log.info("starting hwax-mcp-gateway on %s:%d (path /mcp), %d backends", HOST, PORT, len(BACKENDS))
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")


if __name__ == "__main__":
    main()
