# 3개 백엔드 MCP를 집계해 단일 streamable-http 엔드포인트로 재노출하는 게이트웨이
import hashlib
import hmac
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

# 메서드 허용 규칙의 정본. REST 프록시 라우트와 MCP 다리가 **같은 함수**를 봐야 한다.
# (rest_proxy 는 gateway 를 import 하지 않으므로 이 방향은 순환이 아니다.)
from rest_proxy import allowed_methods, credential_mode

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
from urllib.parse import parse_qs, quote, unquote  # 비ASCII 그룹명 헤더 인/디코드 + 쿼리 파싱

GROUPS_HEADER = "x-hwax-groups"
POLICY: dict[str, list[str]] = {k: list(v.get("allowed_groups", [])) for k, v in BACKENDS.items()}

# 호출자 신원(이메일). groups 가 '무엇을 볼 수 있는 부류인가'라면 이쪽은 '누구인가'다.
# 백엔드가 사용자별 데이터를 스코프할 때 필요하다 — 게이트웨이는 백엔드마다 서비스 계정
# 자격증명 하나로 접속하므로, 이 헤더가 없으면 백엔드 눈에는 모든 호출이 '게이트웨이'다.
# 실제로 DynaForge 가 그랬다: 세션 12·K파일 25건이 있는데 심의는 0건을 봤다(2026-08-17).
# groups 와 같은 규칙으로 퍼센트 인코딩한다(헤더는 latin-1 만 담는다).
USER_HEADER = "x-hwax-user"
# 어느 대화·실행의 호출인가. 호출부가 실어 주면 감사에 남는다(없으면 안 남는다).
CORR_HEADER = "x-hwax-corr"
# 호출자의 **소속 id**(포털 원장). 앱이 "소속 단위 읽기 공유" 를 판정하는 값이다 — 자동 반입
# 리포트의 주인은 예약자이고 같은 소속은 읽을 수 있다(포털 W-93). SSO 발급 헤더
# (`X-Heax-User-Email` 과 같은 계열)와 이름을 맞춘다. 값은 groups·user 와 같은 규칙으로
# 퍼센트 인코딩한다 — 소속 id 에 한글이 올 수 있고 헤더는 latin-1 만 담는다.
# ⚠ **없으면 아예 안 싣는다.** 빈 문자열을 실으면 받는 쪽이 "소속 없음" 을 하나의 소속으로
# 묶을 수 있다 — 소속 없는 사람끼리 서로의 문서를 읽는 길이 된다.
AFF_HEADER = "X-Heax-User-Affiliation"
# ⚠⚠ **평문 헤더만으로는 앱이 이 값을 믿으면 안 된다.** 앱의 정문이 게이트웨이 하나가 아니다 —
# 사용자는 자기 PAT 로 앱 MCP(`:8443/mcp`)·REST 에 직접 붙을 수 있고, HEAXHub Caddy 가 지우는
# 위조 헤더 목록은 `X-Heax-User-Email`·`X-Heax-User-Name` **둘뿐**이다(proxy_manager.py `_IDENTITY_HEADERS`).
# 그래서 소속만 평문으로 보내면 "나는 CAEG 다" 를 사용자가 스스로 적어 남의 문서를 읽는다.
# 값을 **호출자에 결속된 서명**과 함께 보낸다 — 앱은 서명이 맞고 만료 전이고 **PAT 주인의
# 이메일과 같을 때만** 소속을 인정한다. 키는 이미 양쪽이 쥔 앱별 게이트웨이 시크릿이다
# (`per_user_sso.<app>.secret` == 앱의 `heax_gateway_secret` — SSO 발급이 쓰는 그 값).
AFF_PROOF_HEADER = "X-Heax-Aff-Proof"
# 이 호출이 **포털 절차 실행기**에서 왔나. 검증된 PAT 의 `purpose` 클레임에서만 나오고, 클라이언트가
# 실어 보낸 같은 이름 헤더는 미들웨어가 버린다(groups·user 와 같은 규칙).
# 쓰임은 하나다 — `invoke_tool` 의 **정확이름 차단 면제**(_INVOKE_DENY_EXACT). 절차는 늘 별칭으로
# 부르고, 그 도구들은 포털이 이미 `gate: human` 으로 사람 승인을 받은 것이다.
PURPOSE_HEADER = "x-hwax-purpose"
PROCEDURE_PURPOSE = "procedure"
AFF_PROOF_TTL_S = int(os.environ.get("GATEWAY_AFF_PROOF_TTL", "120"))


def _aff_proof(secret: str, email: str, aff: str, now: float | None = None) -> str:
    """`v1.<exp>.<hmac>` — 서명 대상은 **인코딩 전** 값이다(`v1|email|aff|exp`).

    앱은 헤더를 `unquote` 한 뒤 같은 문자열로 다시 계산해 `compare_digest` 로 본다.
    이메일을 넣는 것이 핵심이다 — 증명을 가로채도 **다른 사람의 호출에는 못 쓴다**.
    """
    exp = int((now if now is not None else time.time()) + AFF_PROOF_TTL_S)
    msg = f"v1|{email}|{aff}|{exp}"
    sig = hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"v1.{exp}.{sig}"
# 백엔드별 사용자 위임 설정 — {app_id: {sso_url, secret, client, base?}}.
# 값이 있는 백엔드만 사용자별 자격증명으로 호출한다(나머지는 종전대로 서비스 계정).
PER_USER_SSO: dict[str, dict] = {k: v for k, v in (HEAX.get("per_user_sso") or {}).items()
                                 if isinstance(v, dict) and v.get("sso_url") and v.get("secret")}
def _delegation_app_id(backend_key: str) -> str:
    """이 백엔드의 **사용자 위임 식별자**. 위임 대상이 아니면 빈 문자열.

    heax-hub 앱은 자동탐지되어 키에 `heax-` 접두사가 붙으므로 그것을 뗀 이름이 앱 id 다.
    설정 파일에 직접 적은 **정적 백엔드**(ste 등)는 접두사가 없으므로 **키가 곧 id** 다.

    ⚠ 예전엔 앞쪽만 봤다. 그래서 정적 백엔드를 `per_user_sso` 에 넣어도 이 분기에 영영
    들어오지 못했고, 위임을 켠 줄 알았는데 호출은 **서비스 계정**으로 나갔다 — 잡 소유자가
    한 명으로 뭉치고, 감사 원장에는 그 한 명이 전부 한 것으로 남는다.
    """
    if backend_key.startswith(HEAX_PREFIX):
        return backend_key[len(HEAX_PREFIX):]
    return backend_key if backend_key in PER_USER_SSO else ""


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
# ⚠ **시간에 따라 바뀌는 상태를 읽는 도구**는 접두사가 열어도 캐시하지 않는다. `get_` 이
#   `get_task`(odb-hub 비동기 폴링)·`get_job`(DynaForge)·`get_job_details`(STE) 를 열어 두고
#   있었다. 캐시되면 폴링이 TTL(300초) 동안 **첫 응답(running)을 그대로** 받는다 — 작업이 끝나도
#   "아직 도는 중" 이고 오류도 안 난다(2026-09-16, odb-hub 연계 대조에서 발견. 그때 이미 붙은
#   앱에서만 7개가 캐시되고 있었다). 이름 목록이 아니라 낱말로 막는 이유는 앱이 새로 붙을 때마다
#   같은 구멍이 다시 열리기 때문이다. 틀려도 캐시를 안 할 뿐이라 넓게 잡는다.
_CACHE_DENY_WORDS = re.compile(r"(task|status|progress|job)")
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


def _cache_key(backend_key: str, tool: str, arguments, aff: str = "") -> tuple | None:
    """캐시 키. 캐시 불가면 None.

    ⚠ 키에 **호출자 신원**을 넣는다. PER_USER_SSO 백엔드는 사용자별 시야로 답하므로,
      신원을 빼면 A 가 부른 결과를 B 가 받는다 — 권한 우회다.
    ⚠ **소속도 넣는다.** 앱이 소속으로 읽기를 넓히므로 같은 사람·같은 인자라도 소속이 바뀌면
      다른 답이다. 안 넣으면 권한 키가 안 바뀌는 소속 변경(관리자 이동, grants 가 같은 두 소속
      사이 이동)이 최대 300초 동안 **옛 소속 기준 결과**를 정상 응답으로 준다. 튜플 **끝**에
      붙인다 — `/conn-invalidate` 가 `k[3] == 이메일` 로 고르므로 앞을 밀면 그게 깨진다.
    """
    if (CACHE_TTL_S <= 0 or tool in _CACHE_DENY or not tool.startswith(_CACHEABLE)
            or _CACHE_DENY_WORDS.search(tool)):
        return None
    try:
        args = json.dumps(arguments or {}, sort_keys=True, ensure_ascii=False)
    except Exception:  # noqa: BLE001 — 직렬화 안 되는 인자는 캐시하지 않는다
        return None
    return (backend_key, tool, args, _request_user(), tuple(sorted(_request_groups())), aff)


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


# 봉투 판정을 할 본문 크기 상한. 봉투형 실패(`{"error": …, "hint": …}`)는 작다 — 큰 본문까지
# 매번 JSON 으로 풀면 캐시 경로가 느려진다. 이보다 크면 실패가 아닌 것으로 본다(종전 동작).
_ENVELOPE_SCAN_MAX = 64 * 1024


def _looks_failed(res) -> bool:
    """캐시에 넣으면 안 되는 **봉투형 실패**인가 — `isError` 는 아닌데 본문이 실패를 말하는 모양.

    ⚠ `isError` 만 보면 안 된다. odb-hub 처럼 200 + `{"error": "결과가 없습니다"}` 로 답하는 앱이
      있다(MCP 예외가 아니다). 그걸 캐시하면 방금 분석을 돌렸어도 TTL 동안 "결과 없음" 이 굳는다.

    ⚠ 포털 판정기·에이전트서버 `envelope_failed` 와 **목적이 다르다.** 그쪽은 성공/실패를 정확히
      갈라야 하지만 여기는 "캐시해도 되나" 만 묻는다 — 틀려도 캐시를 안 할 뿐이라 **넓게** 본다.
      그래서 규칙을 베끼지 않는다(베끼면 판정기가 셋이 되고 서로 어긋난다 — 포털 W-77).
    """
    for blk in getattr(res, "content", None) or []:
        txt = getattr(blk, "text", None)
        if not isinstance(txt, str):
            continue
        if len(txt) > _ENVELOPE_SCAN_MAX or not txt.lstrip().startswith("{"):
            return False
        try:
            obj = json.loads(txt)
        except Exception:  # noqa: BLE001 — JSON 이 아니면 봉투가 아니다
            return False
        if not isinstance(obj, dict):
            return False
        return bool(obj.get("error") or obj.get("errors") or obj.get("ok") is False
                    or obj.get("refused") is True
                    or str(obj.get("status", "")).lower() in ("error", "failed", "failure"))
    return False


def _cache_put(key, res):
    """성공 결과만 담는다 — 오류를 캐시하면 일시적 실패가 TTL 동안 굳는다."""
    if key is None or getattr(res, "isError", False) or _looks_failed(res):
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


def _audit(tool, backend, ok, err, ms, caller=None, mode=None, note=None, corr=None):
    """호출 1건을 JSONL 감사 로그에 append (감사 실패가 호출을 막지 않게).

    ⚠ **`error` 는 실패에만 쓴다.** 종전에는 위임 신원(`as:someone@…`)과 메모(`cache-hit`·
    `reconnected`)를 이 칸으로 날라서, `ok:true` 인 기록에 `error` 가 실렸다 — 12,787줄 중
    215줄이 그 모양이었다. 그러면 `error` 는 실패 신호로 못 쓰고 신원 질의에도 못 쓴다.
    **성공이 실패처럼 생긴 것**이라 이 리포가 싫어하는 그 모양이다. 칸을 갈랐다 —
      caller : 누가 불렀나(MCP 경로도 이제 남긴다. 종전엔 93%가 신원 0이었다)
      mode   : 어느 명의로 갔나(service | as-user | as-conn | identity-fwd)
      note   : 실패가 아닌 메모(cache-hit · reconnected)
      corr   : 어느 대화·실행의 호출인가(X-HWAX-Corr). 이게 없어서 감사와 대화를 못 이었다
      purpose: 포털 **절차 실행기**가 부른 호출이면 `procedure`. 절차는 정확이름 차단을 면제받으므로,
               이 칸이 없으면 "면제로 지나간 파괴 호출" 이 직접 호출과 글자 하나 다르지 않았다
               (2026-09-18 검토). `purpose=procedure` 이고 도구가 `_INVOKE_DENY_EXACT` 면 면제 건이다.
    """
    try:
        rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
               "tool": tool, "backend": backend, "ok": ok, "ms": ms}
        if caller:
            rec["caller"] = caller
        if mode:
            rec["mode"] = mode
        if corr:
            rec["corr"] = str(corr)[:120]
        if note:
            rec["note"] = str(note)[:120]
        if err:
            rec["error"] = err[:200]
        purpose = _request_purpose()
        if purpose:
            rec["purpose"] = purpose
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
# 호출 전용 별칭 — `<백엔드키>_<도구이름>` 은 **언제나** 부를 수 있다.
# ⚠ 없으면 도구의 노출 이름이 **제3자 앱의 가동 여부로 뒤집힌다** — 아래 _aggregate 는
# 접두어를 "지금 붙어 있는 백엔드들 사이에서 이름이 겹칠 때만" 붙이므로, 다른 앱이
# 재배포로 잠깐 빠지면 그 창에서 이름이 bare 로 돌아가고 클라이언트가 외운 반대쪽은
# 항상 `unknown tool` 이 된다(실측: StepForge 의 cancel_job·system_capabilities·
# system_status·whoami 4개가 DynaForge 하나에 물려 있었고, bare 로 노출된 나머지
# 수백 개도 같은 조건이다).
# ⚠ **목록에는 안 올린다** — tools/list·`/tools-map`·드리프트 검사는 `route` 만 본다.
# 별칭을 노출하면 게이트웨이 전체가 한꺼번에 개명되는 것과 같아진다.
# ⚠ **`route` 를 먼저 본다** — 기존 이름의 뜻은 하나도 바뀌지 않는다.
alias_route: dict[str, tuple[str, str]] = {}
_task_group_holder: dict[str, object] = {}


async def _aggregate():
    """모든 백엔드에서 list_tools 수집, 충돌 도구만 프리픽스, exposed_tools/route 구축."""
    collected: list[tuple[str, types.Tool]] = []  # (backend_key, tool)
    for key, b in backends.items():
        # ⚠ 이 두 await 에 데드라인이 없어서 **주기 루프가 이틀을 매달렸다**(실사고
        #   2026-09-12 18:07:54 ~ 09-14). 느린 백엔드 하나가 재집계 중에 응답을 안 주면
        #   _revive_loop 가 거기서 서고, 그때부터 죽은 백엔드 부활도 도구 목록 갱신도
        #   영영 멈춘다. 그런데 게이트웨이는 **옛 카탈로그로 정상 응답을 계속 낸다** —
        #   에러도 경고도 없어 아무도 못 본다. 실제로 StepForge 를 재배포했는데 새 도구가
        #   안 보였고, 원인이 여기였다.
        #   liveness(fail_after)·재연결(move_on_after) 경로엔 이미 데드라인이 있는데
        #   여기만 비어 있었다. "멈추면 예외가 아니라 행이라 except 도 안 탄다."
        with anyio.move_on_after(LIVENESS_TIMEOUT_S) as _sc:
            await b._ready.wait()
        if _sc.cancel_called:
            log.error("backend %s aggregate 준비대기 %.0fs 초과 — 이번 회차 건너뛴다",
                      key, LIVENESS_TIMEOUT_S)
            _keep_last(key, collected, "준비대기 초과")
            continue
        if b.session is None:
            log.error("backend %s NOT available at aggregate time: %r", key, b._failed)
            _keep_last(key, collected, "세션 없음")
            continue
        try:
            with anyio.fail_after(LIVENESS_TIMEOUT_S):
                res = await b.session.list_tools()
        except Exception as exc:  # noqa: BLE001 — 하나가 전체 재집계를 막으면 안 된다
            # 세션을 죽은 것으로 표시해 **다음 회차 재연결 루프가 집어 가게** 한다.
            log.error("backend %s list_tools 실패·초과 (%r) — 재연결 예약", key, exc)
            b.session = None
            _keep_last(key, collected, "list_tools 실패")
            continue
        _LAST_TOOLS[key] = (list(res.tools), 0)
        for t in res.tools:
            collected.append((key, t))
        log.info("backend %s -> %d tools", key, len(res.tools))

    name_counts = Counter(t.name for _, t in collected)
    exposed_tools.clear()
    route.clear()
    alias_route.clear()
    for key, t in collected:
        # 충돌 여부와 **무관하게** 별칭을 등록한다(호출 전용).
        _alias = f"{key.replace('-', '')}_{t.name}"
        if _alias in alias_route:
            # ⚠ 하이픈을 지우므로 `heax-step`+`forge_x` 와 `heax-step_forge`+`x` 가 같은
            # 별칭이 된다. 조용히 마지막 승자를 고르면 PER_USER_SSO 백엔드에서 **남의 앱
            # 자격증명**이 발급된다(실측). 라이브 462개에서 지금 충돌은 0건이라 동작은
            # 안 바꾸고 **보이게만** 한다 — 흔적이 alias 개수 차이뿐이면 아무도 못 본다.
            log.warning("alias collision %s: %s ← %s", _alias, alias_route[_alias], (key, t.name))
        alias_route[_alias] = (key, t.name)
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
    log.info("AGGREGATED %d exposed tools (unique names: %d, call-only aliases: %d)",
             len(exposed_tools), len(set(route)), len(alias_route))


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
# 레지스트리에 안 보인 연속 횟수. 한 번 빠졌다고 떼면 앱 재기동마다 카탈로그가 출렁인다.
# 백엔드별 **직전 성공** 도구 목록과 연속 실패 횟수.
# ⚠ 한 회차가 흔들렸다고 그 백엔드를 0종으로 집계하면 카탈로그가 통째로 출렁인다 —
# 실측 로그에 460→426→460 이 남아 있다. 그 사이 호출은 "그런 도구 없습니다" 를 받는다.
# 연속으로 실패할 때만 결국 비운다(영영 낡은 목록을 내걸지는 않는다).
_LAST_TOOLS: dict[str, tuple] = {}
AGG_STALE_ROUNDS = int(os.environ.get("GATEWAY_AGG_STALE_ROUNDS", "3"))


def _keep_last(key: str, collected: list, why: str) -> None:
    """이번 회차에 못 받은 백엔드는 **직전 목록**으로 메운다(상한까지)."""
    got = _LAST_TOOLS.get(key)
    if not got:
        return
    tools, misses = got
    if misses >= AGG_STALE_ROUNDS:
        log.warning("backend %s %d회 연속 실패 — 직전 목록(%d종)을 이제 버린다",
                    key, misses, len(tools))
        _LAST_TOOLS.pop(key, None)
        return
    _LAST_TOOLS[key] = (tools, misses + 1)
    collected.extend((key, t) for t in tools)
    log.warning("backend %s %s — 직전 목록 %d종을 유지한다(%d/%d)",
                key, why, len(tools), misses + 1, AGG_STALE_ROUNDS)


_HEAX_MISS: dict[str, int] = {}
HEAX_MISS_BEFORE_DROP = int(os.environ.get("GATEWAY_HEAX_MISS_DROP", "3"))
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
        # ⚠ **한 번 안 보인다고 떼지 않는다.** 폴링 실패(None)는 위에서 이미 지키는데,
        # 200 인데 앱이 빠진 경우 — 그 앱이 재기동하며 스스로 등록을 내렸다든가 레지스트리가
        # 순간 어긋났다든가 — 는 즉시 제거였다. 실측으로 백엔드 하나가 빠지며 **87종이
        # 61초 사라졌고**(보관 로그에 제거/복귀 쌍 4회), 2026-08 에 고친 "그런 도구
        # 없습니다" 가 다른 문으로 다시 들어온다. 연속으로 안 보일 때만 뗀다.
        gone = []
        if _allow_removal:
            for k in list(backends):
                if not k.startswith(HEAX_PREFIX):
                    continue
                if k in discovered:
                    _HEAX_MISS.pop(k, None)
                    continue
                _HEAX_MISS[k] = _HEAX_MISS.get(k, 0) + 1
                if _HEAX_MISS[k] >= HEAX_MISS_BEFORE_DROP:
                    gone.append(k)
                else:
                    log.info("heax MCP %s 레지스트리에 안 보인다(%d/%d) — 아직 유지",
                             k, _HEAX_MISS[k], HEAX_MISS_BEFORE_DROP)
        for key in gone:
            backends.pop(key)._stop.set()
            POLICY.pop(key, None)
            _HEAX_MISS.pop(key, None)
            log.info("heax MCP %s 제거 (레지스트리에서 %d회 연속 안 보임)",
                     key, HEAX_MISS_BEFORE_DROP)
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
        # 포털 권한 정책 — 디스크 캐시로 먼저 막고(포털이 늦게 떠도 권한이 풀린 채 돌지 않게),
        # 포털에서 받아 갱신한 뒤 주기적으로 다시 받는다.
        _load_access_cache()
        await _refresh_access_policy()
        tg.start_soon(_access_policy_loop)
        try:
            yield
        finally:
            for b in backends.values():
                b._stop.set()
            tg.cancel_scope.cancel()


# 서버 사용 지침 — MCP initialize 응답에 실려 **클라이언트(클로드)가 읽는다**. 비워 두면 도구
# 350개를 주고 "알아서 하라" 는 셈이라, 이 허브에서 실제로 났던 실패가 그대로 재현된다.
# 아래 문장은 전부 실측 사고에 근거한다(docs/gotchas.md · 무음 결함 점검 기록).
_INSTRUCTIONS = """HWAX 엔지니어링 허브 — 사내 설계·해석·품질 데이터와 도구 게이트웨이.

신중하게 쓰는 법(이 허브에서 실제로 났던 실패를 막는 순서다):

1. 도구가 수백 개다. 목록을 훑지 말고 `search_tools("하려는 일")` 로 찾아 `invoke_tool` 로
   불러라. 목록에 안 보이는 도구도 invoke_tool 로 즉시 호출된다.
2. **수치·이름·ID 를 기억으로 채우지 마라.** 이 허브의 가장 위험한 실패는 도구를 부르지 않고
   그럴듯한 값을 서술하는 것이다(표면이 완벽해 사용자가 진짜 데이터로 믿는다). 답에 쓰는 값은
   도구 결과에 있던 값이어야 하고, 결과의 record_id·section_id 를 함께 인용하라.
3. `refused: true` 는 '자료가 없다' 가 아니라 '근거 점수가 임계 밑' 이다. 추측으로 메우지 말고
   ① 질의를 현장 용어로 바꿔 다시 묻거나(예: "부풀어 올랐다" → "스웰링 가스발생")
   ② `recommend_agents` 로 다른 전문가를 찾아라.
4. 유사도 점수를 신뢰도로 읽지 마라. 이 코퍼스의 임베딩은 **무관한 문장끼리도 0.87~0.90** 이다.
   대신 응답의 `desc_match`(어휘 포함률)·`matched_sections`(소유 근거 수)·`low_confidence` 를 보라.
5. 사람에게 물을 일을 도구로 때우지 마라. 등록·발행·삭제·잡 제출처럼 되돌리기 어려운 도구는
   무엇을 어디에 쓸지 사용자에게 확인한 뒤 부른다.
6. 수치를 사용자에게 보내기 전에 `verify_answer(초안)` 로 대조하라 — 이번 세션에 실제로 조회한
   도구 출력에 없는 값을 코드가 집어 준다(기억으로 채운 값을 거기서 잡는다).
7. 전문가가 필요하면 `browse_experts` 로 조직도를 보여 주고 사람이 고르게 한 뒤,
   `use_experts(keys=[...])` 로 역할·도구를 받아 그 전문가로서 답하라(첫 명이 주 전문가).
8. 도구가 실패하면 인자만 바꿔 반복하지 마라. 응답이 '인자 문제가 아니다' 라고 말하면
   연결·시간초과이므로 다른 방법을 찾거나 사용자에게 알려라.
9. 권한 없는 앱은 `list_tool_apps` 목록에 없고 `denied_apps` 에 라벨·사유(`reason`)·필요 권한·요청 경로만
   있다. 그 앱의 도구 이름을 지어내거나 `invoke_tool` 로 우회하지 마라. 사유별로 안내가 다르다 —
   `portal_access`: 포털 '내 권한'(`request` = `/access?need=<권한>`)에서 요청하라, 승인은 관리자가 한다 ·
   `gateway_group`: 포털에서 청할 수 있는 것이 아니다, 포털 관리자에게 문의 · `policy_not_ready`(`retry:true`):
   게이트웨이가 정책을 아직 못 받은 일시 상태다, 잠시 뒤 같은 호출을 다시 하라(요청하라고 하지 마라).
"""

fm = FastMCP("hwax-mcp-gateway", instructions=_INSTRUCTIONS)
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


def _deny_reason(backend_key: str, groups: list[str]) -> str | None:
    """왜 막히는가 — None(허용) · "gateway_group"(allowed_groups 교집합 없음) ·
    "policy_not_ready"(포털 정책 미수신, 일시) · "portal_access"(포털 feat:/plat: 권한 없음).

    allowed_groups 비었으면 전체 공개, 아니면 caller groups와 교집합 필요. 포털 권한 정책(_ACCESS_POLICY)이
    이 백엔드에 필요 권한을 걸었으면 그것도 통과해야 한다(둘 다). POLICY 에 덮어쓰지 않는 이유 — heax
    registry 재탐지가 POLICY[key] 를 빈 값으로 되돌려 권한이 소리 없이 풀린다.
    사유를 구분해 돌려주는 이유 — denied_apps 안내가 "포털에서 청하라" 를 잘못 말했다(적대 검토 2026-09-25):
    게이트웨이 그룹으로 막힌 사람에게 이미 가진 포털 권한을 청하라 하고, 정책 미수신의 일시 닫힘을 영구
    제한처럼 말했다. 허용/거부 판정 자체는 _backend_allowed 그대로다."""
    gs = set(groups)
    allowed = POLICY.get(backend_key, [])
    if allowed and not (gs & set(allowed)):
        return "gateway_group"
    need = _ACCESS_POLICY.get(backend_key)
    # 내부 서비스(GW_TOKEN 으로 그룹 헤더 없이 부름)는 사람이 아니다 — 사람 권한 정책을 받지 않는다.
    if SERVICE_GROUP in gs:
        return None
    # ⚠ 정책을 **아직 못 받은** 상태는 "제한 없음" 이 아니다. 전면 fail-closed 는 가용성을 위해
    #   일부러 안 한 자리라(위 fail-open 주석), 사용자 위임으로 **계정을 만들 수 있는** 백엔드만 닫는다.
    #   새 클론(캐시 없음)·옛 포털(404)·포털 미기동 부팅에서 생기고, 60초마다 재시도해 곧 풀린다.
    #   ⚠ `_delegation_app_id` 는 heax- 접두 키면 위임 여부와 무관하게 id 를 돌려준다 — 실제 위임
    #   백엔드인지는 PER_USER_SSO 에 있는지까지 봐야 한다(처음에 이걸 빼먹어 step_forge 가 닫혔다).
    if not _ACCESS_POLICY_READY and _delegation_app_id(backend_key) in PER_USER_SSO:
        return "policy_not_ready"
    return None if (not need) or bool(gs & set(need)) else "portal_access"


def _backend_allowed(backend_key: str, groups: list[str]) -> bool:
    """백엔드 공개 여부 — 판정 규칙은 _deny_reason 에 있다(사유만 버린다)."""
    return _deny_reason(backend_key, groups) is None


def _deny_text(backend_key: str, groups: list[str]) -> str:
    """거부 응답에 붙이는 사유 한 줄 — list_tool_apps 의 denied_apps[].how 와 같은 말을 한다.
    호출 시점 거부(forbidden:)가 '권한 없음 → 포털에서 청하라' 로만 읽히면 정책 미수신의 일시 닫힘도
    영구 제한처럼 보인다(2라운드 검토)."""
    reason = _deny_reason(backend_key, groups)
    if reason == "policy_not_ready":
        return "게이트웨이가 포털 권한 정책을 아직 못 받았다(일시) — 잠시 뒤 다시 부르면 풀린다"
    if reason == "gateway_group":
        return "게이트웨이 그룹 제한 — 포털에서 청할 수 있는 것이 아니다, 포털 관리자에게 문의"
    needs = sorted(_ACCESS_POLICY.get(backend_key) or [])
    first = next((n for n in needs if n.startswith(("plat:", "feat:"))), None)
    return ("이 계정에는 권한이 없다 — 포털 '내 권한'" + (f"(/access?need={first})" if first else "") + " 에서 요청하라")


# ── 포털 권한 정책(HWAXPortal docs/access-control) ─────────────────────────────
# 백엔드별 필요 권한(feat:·plat:)의 정본은 포털 access.yaml 하나다. 여기서 받아 _backend_allowed 가
# 함께 본다. gateway_config.json 의 allowed_groups 는 provision 이 다시 쓰며 날아가서 쓰지 않는다.
# 받은 값은 디스크에 캐시한다 — 포털이 잠깐 죽어도 직전 정책으로 돈다(부팅 때 포털이 없으면 캐시로).
ACCESS_POLICY_TTL_S = int(os.environ.get("GATEWAY_ACCESS_POLICY_TTL", "60"))
ACCESS_ENT_TTL_S = int(os.environ.get("GATEWAY_ACCESS_ENT_TTL", "60"))
_ACCESS_CACHE_FILE = Path(__file__).resolve().parent / ".access_policy_cache.json"
# GW_TOKEN 으로 그룹 헤더 **없이** 오는 호출 = 사용자 대리가 아닌 내부 서비스 자신. 미들웨어가 이
# 표시 그룹을 붙인다. 에이전트서버는 사용자 호출에 늘 그룹 헤더를 싣는다(빈 값이라도 싣는다).
SERVICE_GROUP = "gateway:service"
_ACCESS_POLICY: dict[str, list[str]] = {}
# 정책을 **한 번이라도 받았는가**(캐시 파일 또는 포털). 비어 있음(=아무 백엔드에도 제한 없음)과
# 못 받음(=아직 모름)은 다르다 — 못 받은 상태에서 per_user 백엔드를 열면 시크릿을 쥔 게이트웨이가
# 임의 이메일로 그 앱 계정을 JIT 생성한다(2026-09-24 적대 검토). 그래서 그 백엔드만 닫는다.
_ACCESS_POLICY_READY = False
# {(email, 로그인 그룹): (권한 키 | None, 만료)} — PAT 호출자의 **지금** 권한.
_ENT_CACHE: dict[tuple[str, str], tuple[dict | None, float]] = {}
_ENT_LAST: dict[tuple[str, str], dict] = {}          # 포털이 죽었을 때 쓸 직전 값(만료 없음)


def _is_synthetic(group: str) -> bool:
    return group.startswith("feat:") or group.startswith("plat:")


def _load_access_cache() -> None:
    try:
        data = json.loads(_ACCESS_CACHE_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            _ACCESS_POLICY.clear()
            _ACCESS_POLICY.update({str(k): [str(x) for x in v] for k, v in data.items() if isinstance(v, list)})
            global _ACCESS_POLICY_READY
            _ACCESS_POLICY_READY = True
            log.info("권한 정책 캐시 적재 — 백엔드 %d개", len(_ACCESS_POLICY))
    except FileNotFoundError:
        pass
    except Exception as exc:  # noqa: BLE001 — 깨진 캐시는 무시(포털에서 다시 받는다)
        log.warning("권한 정책 캐시를 못 읽었다: %r", exc)


async def _refresh_access_policy() -> bool:
    """포털에서 백엔드별 필요 권한을 받아 바꾼다. 실패하면 지금 값을 그대로 둔다(False)."""
    base = _portal_api_base()
    if not base:
        return False
    try:
        async with httpx.AsyncClient(timeout=8) as cli:
            resp = await cli.get(f"{base.rstrip('/')}/internal/access/policy",
                                 headers={"Authorization": f"Bearer {GW_TOKEN}"})
        if resp.status_code == 404:
            return False                      # 권한 기능 이전 포털 — 종전대로(정책 없음)
        resp.raise_for_status()
        backends = (resp.json() or {}).get("backends") or {}
        new = {str(k): [str(x) for x in v] for k, v in backends.items() if isinstance(v, list)}
    except Exception as exc:  # noqa: BLE001 — 직전 정책 유지(가용성) + 경고
        log.warning("포털 권한 정책 조회 실패 — 직전 정책 유지(백엔드 %d개): %r", len(_ACCESS_POLICY), exc)
        return False
    global _ACCESS_POLICY_READY
    _ACCESS_POLICY_READY = True                 # 값이 같아도 "받았다" 는 사실은 남긴다
    if new != _ACCESS_POLICY:
        _ACCESS_POLICY.clear()
        _ACCESS_POLICY.update(new)
        log.info("권한 정책 갱신 — 백엔드 %d개", len(new))
        try:
            _ACCESS_CACHE_FILE.write_text(json.dumps(new, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        except OSError as exc:
            log.warning("권한 정책 캐시를 못 썼다: %r", exc)
    return True


async def _access_policy_loop() -> None:
    while True:
        await anyio.sleep(ACCESS_POLICY_TTL_S)
        await _refresh_access_policy()


async def _portal_access(email: str, base_groups: list[str], *,
                         allow_stale: bool = True) -> dict | None:
    """포털의 **지금** 권한·소속 응답 전체(`{keys, affiliation, affiliation_label}`).

    포털이 모르면(권한 기능 이전) None. 조회가 실패하면 직전에 받은 값, 그것도 없으면 None.
    권한과 소속이 **같은 조회**에서 온다 — 포털은 정지된 계정에 둘 다 빈 값을 주므로,
    따로 물으면 한쪽만 거둬진 순간이 생긴다."""
    key = (email, ",".join(sorted(base_groups)))
    hit = _ENT_CACHE.get(key)
    if hit and hit[1] > time.monotonic():
        return hit[0]
    base = _portal_api_base()
    if not base or not email:
        return None
    try:
        async with httpx.AsyncClient(timeout=8) as cli:
            resp = await cli.get(f"{base.rstrip('/')}/internal/access/entitlements",
                                 params={"email": email, "groups": ",".join(base_groups)},
                                 headers={"Authorization": f"Bearer {GW_TOKEN}"})
        if resp.status_code == 404:
            _ENT_CACHE[key] = (None, time.monotonic() + 300)
            return None
        resp.raise_for_status()
        got = resp.json() or {}
        if not isinstance(got, dict):
            raise TypeError(f"포털 응답이 객체가 아니다: {type(got).__name__}")
    except Exception as exc:  # noqa: BLE001 — 직전 값으로(가용성), 없으면 None
        # ⚠ `_ENT_LAST` 에는 **만료가 없다.** 권한 키는 그래도 직전 값으로 버티는 것이
        # 낫지만(포털이 죽었다고 도구가 다 사라지면 안 된다), **소속은 아니다** — 소속을
        # 벗어난 사람이 포털이 돌아올 때까지 **몇 시간이든** 남의 문서를 계속 읽는다.
        # 소속은 "모르면 안 싣는다" 가 규율이라 이 경로에서만 뒤집히면 안 된다.
        log.warning("포털 권한 조회 실패(%s) — 권한만 직전 값으로(소속은 버린다): %r", email, exc)
        return _ENT_LAST.get(key) if allow_stale else None
    _ENT_CACHE[key] = (got, time.monotonic() + ACCESS_ENT_TTL_S)
    _ENT_LAST[key] = got
    return got


async def _portal_entitlements(email: str, base_groups: list[str]) -> list[str] | None:
    """이 사람의 지금 권한 키 — PAT 에 박힌 발급 때 값 대신 쓴다. 포털이 모르면 None."""
    got = await _portal_access(email, base_groups)
    return None if got is None else [str(k) for k in got.get("keys") or []]


async def _portal_affiliation(email: str, base_groups: list[str]) -> str:
    """이 사람의 **소속 id** — 앱의 소속 단위 읽기 공유가 이 값에 걸린다(포털 W-93).

    ⚠ 발급 때가 아니라 **호출마다** 본다. 사용자 PAT 캐시는 12시간이라(`USER_PAT_TTL_S`)
    SSO 발급 헤더로만 넘기면 소속이 바뀌거나 빠진 사람이 반나절 동안 남의 소속 문서를 읽는다 —
    포털이 권한을 60초마다 다시 보는 이유(D-2)와 똑같은 자리다.

    `base_groups` 는 권한 조회와 **같은 값**을 줘야 한다 — 그래야 캐시가 한 항목이고 호출이 안
    는다. 소속 자체는 원장 행에서만 나오므로 그룹이 달라도 답은 같다.

    ⚠ `allow_stale=False` — 포털을 못 읽으면 **빈 값**이다. 권한 키는 만료 없는 직전 값으로
    버티지만(가용성), 소속까지 그러면 포털이 죽어 있는 동안 소속 해제가 반영되지 않는다."""
    got = await _portal_access(email, base_groups, allow_stale=False)
    return str((got or {}).get("affiliation") or "")


# ── 게이트웨이 로컬 도구: save_conversation ─────────────────────────────────
# Claude(MCP) 심의의 대화 전개를 포털 서버 대화 저장소에 남긴다(웹 챗에서 이어보기).
# 신원 귀속: 호출자의 Authorization(포털 PAT)을 그대로 포털 REST 에 포워딩 → 포털이
# 자체 검증해 owner_sub = PAT sub. 게이트웨이는 신원 매핑을 하지 않는다(위조 불가).
# GW_TOKEN 경로(내부 에이전트)는 포털이 401 → CONV_UNAVAILABLE 반환(비치명적 폴백).
SAVE_CONV_TOOL = types.Tool(
    name="save_conversation",
    description=(
        "심의/대화 로그를 포털 서버 대화 저장소에 저장한다(웹 챗에서 이어보기·GLM 이어가기용). "
        "messages: [{role: user|assistant|system|persona, content, persona?, round?, meta?}] 순서대로. "
        "meta 는 심의 발언의 {rebut:[{target,quote,counter,basis}], non_negotiable} — 웹 관계도·이어하기가 쓴다. "
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
                        "meta": {"type": "object",
                                 "description": "심의 발언 구조 — {rebut:[{target,quote,counter,basis}], non_negotiable}"},
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
        # meta — ⚠ 종전엔 여기서 role/content/persona/round 만 옮겨 meta 를 **조용히** 버렸다.
        # 그래서 MCP 심의는 반박 구조를 만들어도 포털 관계도·이어하기 조항 승계에 닿지 않았다.
        # 알려진 두 칸만, 웹 경로(포털 routes.py 발언 저장)와 같은 자르기로 옮긴다 — 임의 dict 를
        # 통째로 넘기면 크기 폭주로 배치 전체가 거부될 수 있다(위 사전 정규화와 같은 이유).
        meta = m.get("meta")
        if isinstance(meta, dict):
            mo: dict = {}
            if meta.get("non_negotiable"):
                mo["non_negotiable"] = str(meta["non_negotiable"])[:1200]
            if isinstance(meta.get("rebut"), list):
                rb = [{"target": str(r.get("target") or "")[:60], "quote": str(r.get("quote") or "")[:80],
                       "counter": str(r.get("counter") or "")[:160], "basis": str(r.get("basis") or "")[:60]}
                      for r in meta["rebut"][:4] if isinstance(r, dict)]
                if rb:
                    mo["rebut"] = rb
            if mo:
                out["meta"] = mo
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
    # 이 라벨은 챗 에이전트가 보는 도구 설명 앞에 그대로 붙고 search_tools 매칭 대상이기도 하다.
    # '심의' 를 찾는 요청이 여기로 오게 하려면 라벨에 그 낱말이 있어야 한다 — 없던 시절엔
    # 이름에 '심의' 가 든 유일한 앱(발표자료 생성기)으로 수렴해 슬라이드를 만들었다(실사고).
    # ⚠ 이 description 은 앱의 전 도구에 검색 가산점(app_hit)을 준다 — 사용자가 쓰는 업무 낱말을
    # 여기 다 넣어야 그 낱말로 찾을 때 심의가 후보에 오른다. 낱말이 빠지면 '원인 규명'·'리스크'로
    # 검색해도 심의가 순위권 밖으로 밀린다(실측).
    "smart-twin-mcp": {"label": "시뮬레이션 실행(SmartTwin)",
                       "description": "해석 잡 제출·후처리·결과 수집 — 낙하 시뮬레이션(단건·전각도) 실행, "
                                      "잡 상태·진단·재실행, 후처리 리포트 생성과 결과 회수. "
                                      "조회 전용인 '시뮬레이션 클러스터'(slurm)와 달리 실제로 돌린다."},
    "hwax-deliberation": {"label": "HWAX 전문가 심의",
                          "description": "전문가 심의 엔진 — 여러 도메인 좌석이 라운드를 돌며 도구 근거 위에서 수렴해 "
                                         "결정 문서를 만든다. 원인 규명·불량 원인 분석·안 선택·트레이드오프 결정·"
                                         "신뢰 판정·리스크 심사·위험 도출·해석 설계·시뮬레이션 심의·시험 계획·"
                                         "시험 설계·구축 계획·메커니즘 규명. 포털 웹 심의와 같은 엔진이며 "
                                         "심의는 길어서 시작·조회·회수 3단이다."},
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


# ── 도구 영역 분류 — tool_areas.json(추적 파일) ─────────────────────────────────
# 앱은 '누가 만들었나'이고 영역은 '무슨 일을 하나'다. 둘이 어긋난다 — StepForge 81개에 CAD 조작·
# 메시·재료가 섞여 있고, '해석 결과'는 앱 셋에 흩어져 있다. 사용자는 영역으로 찾는다.
# ⚠ gateway_config.json 에 두지 않는다(gitignore·--force 재생성에 날아감). 이 파일은 git 으로 간다.
_AREAS_PATH = Path(__file__).resolve().parent / "tool_areas.json"
_AREAS_CACHE: dict = {"mtime": None, "data": {}}


def _tool_areas() -> dict:
    """영역 분류표 — mtime 캐시라 파일을 고치면 재기동 없이 반영된다.

    읽기 실패는 게이트웨이를 죽이지 않는다(분류 없이 동작). 대신 **경고를 남기고** /tools-map 의
    unclassified 가 전량으로 차서 UI 에 '미분류 N' 으로 드러난다 — 조용히 틀린 분류를 내지 않는다."""
    try:
        mt = _AREAS_PATH.stat().st_mtime
    except OSError:
        return {}
    if _AREAS_CACHE["mtime"] != mt:
        try:
            raw = json.loads(_AREAS_PATH.read_text(encoding="utf-8"))
            raw["_patterns"] = [(re.compile(p), a) for p, a in (raw.get("patterns") or [])]
            _AREAS_CACHE.update({"mtime": mt, "data": raw})
        except (OSError, ValueError, re.error) as exc:
            log.warning("tool_areas.json 을 못 읽었다 — 영역 분류 없이 간다: %r", exc)
            _AREAS_CACHE.update({"mtime": mt, "data": {}})
    return _AREAS_CACHE["data"]


def _area_of(name: str, app: str) -> str:
    """도구 → 영역 키. 도구 지정 > 이름 패턴(첫 일치) > 앱 기본값. 없으면 ''(미분류)."""
    tx = _tool_areas()
    a = (tx.get("tools") or {}).get(name)
    if a:
        return a
    for rx, a in tx.get("_patterns") or []:
        if rx.search(name):
            return a
    return (tx.get("apps") or {}).get(app, "")


def _area_meta() -> list[dict]:
    return [{"area": a["key"], "label": a.get("label") or a["key"], "description": a.get("description") or ""}
            for a in (_tool_areas().get("areas") or []) if a.get("key")]


LIST_APPS_TOOL = types.Tool(
    name="list_tool_apps",
    description=(
        "이 게이트웨이에 연결된 MCP 앱(도메인) 목록과 각 앱의 도구를 계층적으로 반환한다. "
        "'무슨 앱/도구가 있냐', '어떤 기능이 되냐' 같은 질문에 전체 도구를 나열하는 대신 이걸 호출하라. "
        "각 앱마다 accessible(내 권한으로 사용 가능한지)·reachable(백엔드 생존)·tool_count·tools 를 준다. "
        "app 인자를 주면 그 앱의 도구만 상세(이름+설명)로 반환한다. "
        "by='area' 면 앱 대신 **하는 일(영역)** 로 묶는다 — CAD·형상 제어, 메시·해석 모델 구성, 시뮬레이션 실행·잡, "
        "해석 계산·예측, 해석 결과 분석, 물성·재료, VOC·시장 신호, 사내 지식 검색, 웹·논문 조사, 보고서·문서·발표, "
        "전문가·심의·리스크, 데이터 등록·온톨로지, 시스템·공통. '시뮬레이션 관련 도구 뭐 있어' 같은 질문엔 이걸 쓴다."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "app": {"type": "string", "description": "특정 앱 키(예: heax-thermal_shock_mcp). 생략 시 전체 앱 요약."},
            "include_tools": {"type": "boolean", "description": "전체 목록에도 도구 이름을 포함(기본 true)."},
            "by": {"type": "string", "enum": ["app", "area"],
                   "description": "묶는 기준 — app(소유 앱, 기본) 또는 area(하는 일)."},
            "area": {"type": "string", "description": "by='area' 에서 특정 영역 키만(예: sim, cad, voc). 도구 설명까지 준다."},
        },
    },
)


# ── REST 다리 ────────────────────────────────────────────────────────────────
# **용도를 가른다.** 이 게이트웨이의 도구는 두 갈래다.
#   ① **의도적으로 열어 놓은 MCP 도구** — 앱이 "이건 이렇게 쓰라" 고 골라서 낸 것. **이쪽이 먼저다.**
#      인자·검증·후처리가 그 도구 안에 들어 있어서, 부르는 쪽이 앱 내부를 몰라도 된다.
#   ② **REST 를 얇게 얹은 이 두 도구** — ①로 안 되는 것(웹 화면에서만 되던 조작)을 위한 우회로다.
#
# 왜 도구를 자동 생성하지 않았나 — 하위 앱의 REST 경로를 전부 도구로 펴면 수백 개가 된다.
# 그러면 도구 목록이 모델 컨텍스트를 먹고, 이름이 겹치고, 정작 ①의 좋은 도구가 묻힌다.
# 그래서 **둘만** 둔다: 무엇이 있는지 묻는 것과, 하나를 부르는 것.
REST_CATALOG_TOOL = types.Tool(
    name="rest_catalog",
    description='⚠ **먼저 전용 도구를 찾아라** — `list_tool_apps` / `search_tools` 로 그 일을 하는 도구가 있는지 \n보고, 있으면 그걸 써라. 이 도구는 **전용 도구로 안 되는 것**(웹 화면에서만 되던 조작)을 위한 우회로다.\n\n하위 사이트가 여는 REST API 목록을 돌려준다. 사이트별로 base 경로와, 그 사이트가 OpenAPI 를 \n내면 **경로·메서드·요약**까지 준다. 내 포털 권한으로 **쓸 수 있는 사이트만** 보인다.\n\nsite 를 주면 그 사이트만 상세히. q 를 주면 경로·요약에 그 말이 든 것만 추린다\n(경로가 많은 사이트는 q 없이 부르면 요약만 준다).',
    inputSchema={
        "type": "object",
        "properties": {
            "site": {"type": "string", "description": "특정 사이트만(생략 시 전체 요약)"},
            "q": {"type": "string", "description": "경로·요약에서 찾을 말(예: upload, job, report)"},
            "limit": {"type": "integer", "description": "사이트당 반환할 경로 수(기본 40)"},
        },
    },
)

REST_CALL_TOOL = types.Tool(
    name="rest_call",
    description='⚠ **먼저 전용 도구를 찾아라**(`list_tool_apps`/`search_tools`). 이건 그것으로 안 될 때의 우회로다.\n\n`rest_catalog` 로 확인한 하위 사이트 REST 를 **내 이름으로** 부른다. 게이트웨이가 그 사이트의 \n자격을 대신 붙이므로 사이트별 토큰이 따로 필요 없고, **내 포털 권한**으로 열리는 것만 통한다.\n\n경로·메서드를 추측하지 마라 — `rest_catalog` 에 없는 경로는 404 다. \n파일 본문은 이 도구로 나르지 않는다(대용량은 경로를 넘기는 전용 도구를 쓴다).',
    inputSchema={
        "type": "object",
        "properties": {
            "site": {"type": "string", "description": "rest_catalog 가 준 사이트 키"},
            "path": {"type": "string", "description": "사이트 기준 경로(예: /api/v1/jobs). 앞 슬래시 포함"},
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                       "description": "기본 GET"},
            "query": {"type": "object", "description": "쿼리 문자열로 붙일 값들"},
            "body": {"type": "object", "description": "JSON 본문(POST/PUT/PATCH)"},
        },
        "required": ["site", "path"],
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
def _secret_eq(got: str, want: str) -> bool:
    """공유 시크릿 비교는 **상수 시간**으로. `==` 는 앞에서부터 갈려 길이·접두를 흘린다.
    같은 코드베이스의 `require_csrf` 가 이미 `compare_digest` 를 쓴다 — 여기만 달랐다."""
    if not want:
        return False
    return hmac.compare_digest(got or "", want)


_INVOKE_DENY_PREFIX = ("delete_", "remove_", "cancel_", "purge_", "destroy_")
_INVOKE_DENY_SUFFIX = ("_control", "_set_state")
# ⚠ **이름 패턴만으로는 안 걸리는 것들이 있다.** 되돌리려면 **남의 손**이 필요한 바깥
# 방향 행위인데 위 접두·접미 어디에도 안 맞는다. 포털이 이미 같은 목록을 `MUST_GATE`
# 로 확정해 뒀으므로(HWAXPortal `app/procedures/models.py`) **그것을 그대로** 쓴다 —
# 여기서 따로 고르면 두 곳이 어긋나고, 어긋난 쪽이 늘 느슨한 쪽이다.
# 직접 바인딩으로는 여전히 부를 수 있다(사람이 고른 도구는 막지 않는다).
# 실측(2026-09-15): 그때는 이 도구들이 전부 **직접 호출**이었다. ⚠ 지금은 아니다 — 포털 절차
# 실행기가 **늘 별칭으로** invoke_tool 을 거쳐 부른다(R2c 축 태그 붙이기 등). 그래서 이 목록은
# 해석된 원본 이름으로도 보고(별칭 우회 차단), 절차 PAT 만 면제한다(`_request_purpose`).
# 면제를 걷어내면 사람이 승인한 절차 단계가 승인 **뒤에** 죽는다 — 걷어낼 근거로 읽지 마라.
_INVOKE_DENY_EXACT = frozenset({
    "publish_report", "publish_report_to_datahub", "request_unpublish",
    "trash_report", "restore_version", "job_stop", "risk_add_finding",
    "add_report_tags",
})


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
        # 낙하/충격 리포트(DynaForge) 계열 — 도구 이름이 report_angle_stats·report_part_energy·
        # report_scatter·report_geometry·report_upload_instructions 라 한국어 업무어가 이름을 못 맞힌다.
        "낙하": ("drop", "impact", "sphere"), "충격": ("impact",), "전각도": ("sphere", "angle"),
        "방향": ("angle", "direction", "scatter"), "각도": ("angle",), "산포": ("scatter",),
        "에너지": ("energy",), "소성": ("plastic", "strain"), "변형률": ("strain",),
        "응력": ("stress",), "속도": ("velocity",), "인테이크": ("intake", "upload"),
        "반입": ("intake", "upload"), "시각화": ("geometry", "render"),
        # 심의 계열 — 도구 이름이 deliberate_* 라 한국어 업무 낱말이 이름을 못 맞힌다.
        # 앱 설명만으로는 app_hit 가산점뿐이라 다른 앱에 밀린다(실측: '안 선택' 이 물성·VOC 에 밀림).
        # 이름까지 맞히게 이어 준다 — 한 글자 토큰('안')은 위에서 이미 버려지므로 두 글자 이상만.
        "심의": ("deliberate",), "토의": ("deliberate",), "심사": ("deliberate", "risk"),
        "규명": ("deliberate",), "원인": ("deliberate",), "불량": ("deliberate",),
        "선택": ("deliberate",), "대안": ("deliberate",), "판정": ("deliberate",),
        "신뢰": ("deliberate",), "리스크": ("deliberate", "risk"), "위험": ("deliberate", "risk"),
        "도출": ("deliberate",), "설계": ("deliberate",), "계획": ("deliberate", "plan"),
        "전문가심의": ("deliberate",), "회의": ("deliberate", "meeting"),
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


def _denied_entry(key: str, meta: dict, reason: str) -> dict:
    """권한 없는 앱의 안내 — 라벨·사유·필요 권한·요청 경로만. 도구 이름은 싣지 않는다(모델이 계획에 넣는다).
    사유(_deny_reason)에 따라 갈린다: 포털 권한이 없을 때만 feat:/plat: 키와 요청 경로를 준다. 게이트웨이
    그룹 제한은 포털에서 청할 수 있는 것이 아니고, 정책 미수신은 잠시 뒤 저절로 풀리는 일시 상태다."""
    entry: dict = {"app": key, "label": meta["label"], "reason": reason, "needs": [], "request": None}
    if reason == "portal_access":
        needs = sorted(_ACCESS_POLICY.get(key) or [])
        first = next((n for n in needs if n.startswith(("plat:", "feat:"))), None)
        entry.update(needs=needs, request=f"/access?need={first}" if first else None,
                     how="포털 '내 권한' 페이지에서 요청하면 관리자가 승인한다")
    elif reason == "policy_not_ready":
        entry.update(retry=True,
                     how="게이트웨이가 포털 권한 정책을 아직 못 받았다(부팅 직후·포털 미기동) — "
                         "잠시 뒤 다시 부르면 풀린다. 포털에서 청할 것이 아니다")
    else:
        entry.update(how="게이트웨이 그룹 제한 — 포털에서 청할 수 있는 것이 아니다. 포털 관리자에게 문의")
    return entry


async def _list_tool_apps(arguments: dict) -> types.CallToolResult:
    groups = _request_groups()
    want_app = str((arguments or {}).get("app") or "").strip()
    include = (arguments or {}).get("include_tools")
    include = True if include is None else bool(include)

    by_app: dict[str, list[types.Tool]] = {}
    for t in exposed_tools:
        by_app.setdefault(route[t.name][0], []).append(t)
    by_app.setdefault("_gateway", []).extend([SAVE_CONV_TOOL, SEARCH_CONV_TOOL, LIST_APPS_TOOL, SEARCH_TOOLS_TOOL, INVOKE_TOOL,
                                              BROWSE_EXPERTS_TOOL, USE_EXPERTS_TOOL, VERIFY_TOOL])
    if REST:                                   # _visible_tools 와 같은 조건 — 두 목록이 어긋나면 안 된다
        by_app["_gateway"].extend([REST_CATALOG_TOOL, REST_CALL_TOOL])
    # 연결이 끊긴 백엔드는 도구가 집계되지 않아 목록에서 통째로 사라진다 — 접근성 점검이
    # 목적이므로 '앱은 있는데 지금 불통'을 보이게 빈 항목으로 채운다.
    for _k in backends:
        by_app.setdefault(_k, [])

    if str((arguments or {}).get("by") or "").strip() == "area":
        return _list_by_area(by_app, groups, str((arguments or {}).get("area") or "").strip())

    apps = []
    denied = 0
    denied_apps: list[dict] = []
    for key in sorted(by_app, key=lambda k: -len(by_app[k])):
        tools = by_app[key]
        local = key == "_gateway"
        # 접근성: 그룹 인가(로컬 도구는 전 그룹) + 백엔드 세션 생존. 사유는 거부 안내에 쓴다.
        deny = None if local else _deny_reason(key, groups)
        accessible = deny is None
        reachable = True if local else (key in backends and backends[key].session is not None)
        if want_app and key != want_app:
            continue
        # 권한 없는 앱은 **목록에서 뺀다** — 예전엔 accessible:false 딱지만 붙여 도구 이름까지
        # 보여 줬고, 모델은 못 부를 도구를 계획에 넣었다(호출은 막히니 실패로만 끝난다).
        # 이름으로 콕 집어 물어도 도구는 안 준다 — 권한 없음만 알린다(되물음을 끊는다).
        meta = _app_meta(key)
        if not accessible:
            denied += 1
            denied_apps.append(_denied_entry(key, meta, deny))
            continue
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
        "hidden_no_access": denied,
        # 라벨·필요 권한·요청 경로만 — 도구 이름은 없다. 모델이 "그 앱이 있긴 한데 내 권한이
        # 아니다" 를 사용자에게 말할 수 있게 하는 것이 목적이다(권한 없음 ≠ 앱 없음).
        "denied_apps": denied_apps,
        "note": "여기 있는 앱은 모두 내 권한으로 호출 가능하다(reachable=백엔드 연결 정상). "
                "권한 없는 앱은 목록에 없고 denied_apps 에 라벨·사유·필요 권한·요청 경로만 있다 — 각 항목의 "
                "reason/how 를 따른다(portal_access 만 포털 '내 권한' 요청, policy_not_ready 는 잠시 뒤 재시도). "
                "특정 앱의 도구 설명은 list_tool_apps(app='<키>') 로 조회.",
    }
    if want_app and not apps:
        if denied:
            d0 = denied_apps[0]
            payload["error"] = (f"not_ready: {want_app} — {d0['how']}" if d0["reason"] == "policy_not_ready"
                                else f"no_access: {want_app} — 이 계정에는 권한이 없는 앱이다. {d0['how']}")
            payload["denied"] = d0
        else:
            payload["error"] = f"unknown app: {want_app}"
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(payload, ensure_ascii=False, indent=2))]
    )


def _list_by_area(by_app: dict, groups: list[str], want_area: str) -> types.CallToolResult:
    """list_tool_apps(by='area') — 앱이 아니라 하는 일로 묶는다. 내 권한으로 못 쓰는 앱의 도구는
    뺀다(영역 보기는 '무엇을 할 수 있나'가 목적이라, 못 쓰는 걸 늘어놓으면 오답이 된다)."""
    meta = {m["area"]: m for m in _area_meta()}
    buckets: dict[str, list] = {k: [] for k in meta}
    hidden = 0
    for app, tools in by_app.items():
        local = app == "_gateway"
        if not local and not (_backend_allowed(app, groups) and app in backends
                              and backends[app].session is not None):
            hidden += len(tools)
            continue
        for t in tools:
            buckets.setdefault(_area_of(t.name, app), []).append((t, app))
    areas = []
    for key, items in buckets.items():
        if want_area and key != want_area:
            continue
        m = meta.get(key) or {"label": "미분류", "description": "tool_areas.json 에 없는 도구 — 영역을 지정해야 한다."}
        entry = {"area": key or "", "label": m["label"], "description": m["description"], "tool_count": len(items)}
        if want_area:
            entry["tools"] = [{"name": t.name, "app": a, "description": (t.description or "")[:300]} for t, a in items]
        else:
            entry["tools"] = sorted(t.name for t, _ in items)
        if items or want_area:
            areas.append(entry)
    payload = {"areas": areas, "area_count": len(areas), "total_tools": sum(a["tool_count"] for a in areas),
               "hidden_no_access_or_down": hidden,
               "note": "영역 = 하는 일. 특정 영역의 도구 설명은 list_tool_apps(by='area', area='<키>')."}
    if want_area and not areas:
        payload["error"] = f"unknown area: {want_area} — 가능한 키: {', '.join(meta)}"
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(payload, ensure_ascii=False, indent=2))])



# ── 전문가 조직도 (클로드에서도 사람을 고르게 한다) ────────────────────────────────
# MCP 에는 UI 표면이 없다 — 패널을 띄울 수 없으므로 **도구 두 개**로 같은 일을 한다.
#   browse_experts : 조직도(루트→분류→분야→사람)와 검색 결과를 계층으로 돌려준다 → 클로드가 목록으로 보여 준다
#   use_experts    : 고른 사람의 역할 문서·운영 앱·입구 도구를 돌려준다 → 클로드가 그 전문가가 된다
# 라벨 정본은 포털의 orgTaxonomy.json 하나다(여기서 옮겨 적지 않는다 — 두 조직도가 갈린다).
_ORG_TAX: dict = {}
_ORG_TAX_AT = 0.0
ORG_TAX_TTL_S = int(os.environ.get("ORG_TAX_TTL_S", "600"))


async def _org_taxonomy() -> dict:
    """포털에서 조직도 라벨 표를 받아 캐시한다. 못 받으면 빈 표 — 그때는 도메인 코드가 그대로
    보이지만 목록 자체는 돌아간다(라벨이 없다고 조직도를 통째로 죽이지 않는다)."""
    global _ORG_TAX_AT
    if _ORG_TAX and time.monotonic() - _ORG_TAX_AT < ORG_TAX_TTL_S:
        return _ORG_TAX
    base = _portal_api_base()
    if not base:
        return _ORG_TAX
    try:
        async with httpx.AsyncClient(timeout=8) as cli:
            r = await cli.get(f"{base.rstrip('/')}/internal/org-taxonomy",
                              headers={"Authorization": f"Bearer {GW_TOKEN}"})
        r.raise_for_status()
        data = r.json() or {}
        if isinstance(data, dict) and data.get("domain_label"):
            _ORG_TAX.clear()
            _ORG_TAX.update(data)
            _ORG_TAX_AT = time.monotonic()
    except Exception as exc:  # noqa: BLE001 — 라벨은 있으면 좋은 것이지 필수가 아니다
        log.warning("조직도 라벨 표 조회 실패 — 코드로 보여 준다: %r", exc)
    return _ORG_TAX


BROWSE_EXPERTS_TOOL = types.Tool(
    name="browse_experts",
    description=(
        "전문가 조직도를 훑는다 — 인자 없이 부르면 루트→분류→분야(인원수)를, domain 을 주면 "
        "그 분야의 사람들을, q 를 주면 이름·키·설명으로 찾은 사람들을 돌려준다. "
        "사용자가 '누구한테 물어볼까'를 정할 때 이 목록을 보여 주고 고르게 하라. "
        "고른 뒤에는 use_experts(keys=[...]) 로 그 전문가의 역할과 도구를 받는다."),
    inputSchema={
        "type": "object",
        "properties": {
            "q": {"type": "string", "description": "검색어(이름·키워드). 비우면 분야 목록."},
            "domain": {"type": "string", "description": "분야 코드(cam·mech·he…) — 그 분야 사람들만."},
            "limit": {"type": "integer", "description": "최대 인원(기본 40)."},
        },
    },
)

USE_EXPERTS_TOOL = types.Tool(
    name="use_experts",
    description=(
        "고른 전문가로 답하기 위한 재료를 돌려준다 — 역할 문서(사전 지식·작업 순서·함정), "
        "HE팀 운영자면 그 앱과 입구 도구. **첫 명이 주 전문가**(목소리)이고 나머지는 보조로, "
        "도구와 판단 기준만 빌려준다(최대 5명). 받은 역할대로 답하되 관점이 갈리면 숨기지 말고 "
        "'이견:' 한 줄로 밝혀라. 보조의 사내 지식이 필요하면 agent_search(<키>, 질의) 를 쓴다."),
    inputSchema={
        "type": "object",
        "properties": {
            "keys": {"type": "array", "items": {"type": "string"},
                     "description": "전문가 키 목록(browse_experts 결과의 key). 첫 명이 주 전문가."},
        },
        "required": ["keys"],
    },
)


def _tax_domain_label(code: str) -> str:
    return (_ORG_TAX.get("domain_label") or {}).get(code) or code


async def _agents_json(args: dict) -> list[dict]:
    """AIDataHub 의 list_agents 를 **정상 경로**로 부른다 — 인가·캐시·감사가 그대로 적용된다
    (권한 없는 사람은 여기서 막힌다). 결과는 JSON 배열이어야 하고, 아니면 빈 목록이다."""
    res = await _call_tool("list_agents", args)
    if getattr(res, "isError", False):
        return []
    out: list[dict] = []
    for c in (getattr(res, "content", None) or []):
        txt = getattr(c, "text", "") or ""
        try:
            data = json.loads(txt)
        except Exception:  # noqa: BLE001 — 텍스트로 온 응답은 접지 않는다
            continue
        # ⚠ 목록 도구는 **블록 하나에 한 명씩** 실어 보낸다(796명이면 content 796개다).
        # 배열만 기대하면 0명으로 읽고, 화면에는 '전문가가 없다'로 보인다(실측).
        if isinstance(data, dict) and (data.get("agent_type") or data.get("id")):
            out.append(data)
            continue
        rows = data.get("result") if isinstance(data, dict) else data
        if isinstance(rows, dict):
            rows = rows.get("agents") or rows.get("data") or []
        if isinstance(rows, list):
            out.extend(r for r in rows if isinstance(r, dict))
    return out


async def _browse_experts(arguments: dict) -> types.CallToolResult:
    tax = await _org_taxonomy()
    q = str((arguments or {}).get("q") or "").strip()
    domain = str((arguments or {}).get("domain") or "").strip()
    limit = max(1, min(200, int((arguments or {}).get("limit") or 40)))

    rows = await _agents_json({"compact": True, **({"domain": domain} if domain else {})})
    people = []
    for r in rows:
        key = str(r.get("agent_type") or r.get("id") or "").strip()
        if key:
            people.append({"key": key, "name": str(r.get("name") or key),
                           "domain": key.split("-")[0] or "기타"})
    if q:
        ql = q.lower()
        hit = [p for p in people if ql in p["name"].lower() or ql in p["key"].lower()]
        payload = {"query": q, "found": len(hit),
                   "experts": [{**p, "domain_label": _tax_domain_label(p["domain"])} for p in hit[:limit]],
                   "note": "이름·키 일치만 본다. 주제로 찾으려면 recommend_agents(q) 를 쓰고, "
                           "고른 뒤에는 use_experts(keys=[...]) 로 역할과 도구를 받아라."}
        return types.CallToolResult(content=[types.TextContent(
            type="text", text=json.dumps(payload, ensure_ascii=False, indent=2))])

    if domain:
        payload = {"domain": domain, "domain_label": _tax_domain_label(domain),
                   "count": len(people), "experts": people[:limit],
                   "note": "use_experts(keys=[...]) 로 고른 사람의 역할·도구를 받아라(첫 명이 주 전문가)."}
        return types.CallToolResult(content=[types.TextContent(
            type="text", text=json.dumps(payload, ensure_ascii=False, indent=2))])

    # 분야 목록 — 라벨 표의 분류(루트→분류→분야)로 접는다. 표를 못 받았으면 코드로 보여 준다.
    counts: dict[str, int] = {}
    for p in people:
        counts[p["domain"]] = counts.get(p["domain"], 0) + 1
    cats = tax.get("categories") or []
    roots = {r["id"]: r["label"] for r in (tax.get("roots") or [])}
    app_doms = set(tax.get("app_analyst_domains") or [])
    seen: set[str] = set()
    tree = []
    for c in cats:
        doms = list(c.get("domains") or [])
        if c.get("id") == "apps":
            doms = [d for d in counts if d in app_doms]
        elif c.get("id") == "sw":
            doms = [d for d in counts if d == "sw"]
        entries = [{"domain": d, "label": _tax_domain_label(d), "count": counts.get(d, 0)}
                   for d in doms if counts.get(d)]
        seen.update(e["domain"] for e in entries)
        if entries:
            tree.append({"root": roots.get(c.get("root"), c.get("root")), "category": c.get("label"),
                         "count": sum(e["count"] for e in entries), "domains": entries})
    rest = [{"domain": d, "label": _tax_domain_label(d), "count": n}
            for d, n in sorted(counts.items(), key=lambda x: -x[1]) if d not in seen]
    if rest:
        tree.append({"root": "미분류", "category": "미분류", "count": sum(e["count"] for e in rest),
                     "domains": rest})
    payload = {"total": len(people), "chart": tree,
               "note": ("분야를 고르면 browse_experts(domain='<코드>'), 이름으로 찾으려면 q, "
                        "주제로 찾으려면 recommend_agents(q). 고른 뒤 use_experts(keys=[...])."
                        + ("" if tax else " ⚠ 라벨 표를 못 받아 코드로 보여 준다."))}
    return types.CallToolResult(content=[types.TextContent(
        type="text", text=json.dumps(payload, ensure_ascii=False, indent=2))])


async def _use_experts(arguments: dict) -> types.CallToolResult:
    """고른 전문가의 역할·운영 앱·입구 도구. 포털 챗의 pinned_agents 와 같은 규칙이다 —
    첫 명이 주 전문가(목소리)이고 나머지는 도구와 판단 기준만 빌려준다."""
    keys = [str(k).strip()[:120] for k in ((arguments or {}).get("keys") or []) if str(k).strip()]
    keys = list(dict.fromkeys(keys))[:5]
    if not keys:
        return types.CallToolResult(content=[types.TextContent(
            type="text", text="use_experts: keys 에 전문가 키를 하나 이상 주세요(browse_experts 참조).")],
            isError=True)
    out = []
    for i, k in enumerate(keys):
        res = await _call_tool("get_agent_session", {"agent_type": k})
        role, apps, key_tools, kind = "", [], [], "domain"
        for c in (getattr(res, "content", None) or []):
            try:
                d = json.loads(getattr(c, "text", "") or "")
            except Exception:  # noqa: BLE001
                continue
            d = d.get("result", d) if isinstance(d, dict) else d
            if isinstance(d, list) and d:
                d = d[0]
            if not isinstance(d, dict):
                continue
            d = d.get("data", d)
            role = str(d.get("system_prompt") or d.get("description") or "")[:8000]
            rc = d.get("response_config") if isinstance(d.get("response_config"), dict) else {}
            if rc.get("persona_kind") == "mcp_operator":
                kind = "operator"
                apps = [str(a) for a in (rc.get("mcp_apps") or [])][:3]
                key_tools = [str(t) for t in (rc.get("key_tools") or [])][:12]
        out.append({"key": k, "role": "lead" if i == 0 else "helper", "kind": kind,
                    "role_doc": role, "apps": apps, "entry_tools": key_tools})
    payload = {
        "lead": keys[0], "helpers": keys[1:], "experts": out,
        "how": ("첫 명의 목소리로 한 사람처럼 답하라. 보조는 이름으로 따로 말하지 말고 그들의 "
                "판단 기준과 도구를 녹여라. 운영자의 앱 도구는 search_tools 로 찾아 invoke_tool 로 "
                "부르고, 사내 지식은 agent_search(<키>, 질의) 로 조회한다. 관점이 갈리면 숨기지 "
                "말고 '이견:' 한 줄로 밝혀라."),
    }
    return types.CallToolResult(content=[types.TextContent(
        type="text", text=json.dumps(payload, ensure_ascii=False, indent=2))])



# ── 답변 수치 대조 (클로드용) ──────────────────────────────────────────────────
# 웹 챗에는 **코드가 만드는** 근거 블록이 있어 답의 수치를 도구 출력과 대조한다. MCP 에는 그게
# 없어 지침(부탁)뿐이었다 — 지침은 보장이 아니다. 호출자별로 최근 도구 출력을 들고 있다가
# verify_answer(초안) 로 대조해 준다. 판정 기준은 에이전트서버 evidence.py 와 같다:
# 소수점이 있거나 100 이상인 수치만 보고, 부분문자열로 대조한다(경고 남발이 기능을 죽인다).
# ⚠ 뒤 경계에 `(?!\w)` 를 쓰면 한글 단위가 붙은 수치를 놓친다 — 파이썬 \w 는 유니코드라
# 한글도 단어 글자다("408명"은 검사조차 안 되고 "1250.5원"은 "1250" 으로 잘린다, 실측).
# 에이전트서버 evidence.py 와 같은 패턴을 쓴다 — 두 화면의 경고 기준이 달라지면 안 된다.
_NUM_TOK_RE = re.compile(r"(?<![\w.])\d[\d,]*(?:\.\d+)?(?![\d.])")
# 호출자별 최근 도구 출력 — {키: (마감시각, [(도구, 출력조각), …])}. 메모리 상한을 건다.
_EVID: "OrderedDict[str, tuple]" = OrderedDict()
EVID_TTL_S = int(os.environ.get("EVID_TTL_S", "1800"))
EVID_MAX_CALLERS = int(os.environ.get("EVID_MAX_CALLERS", "64"))
EVID_MAX_CALLS = int(os.environ.get("EVID_MAX_CALLS", "20"))
EVID_MAX_CHARS = int(os.environ.get("EVID_MAX_CHARS", "200000"))


def _request_session() -> str:
    """현재 MCP 세션 id. 없으면 ''."""
    try:
        req = _low.request_context.request
    except LookupError:
        return ""
    raw = req.headers.get("mcp-session-id") if req is not None else None
    return (raw or "").strip()[:80]


def _evid_key() -> str:
    """근거 원장의 칸 이름. **절대 섞이면 안 된다.**

    ⚠ 예전엔 신원이 없으면 **그룹 문자열**, 그것도 없으면 `_anon` 한 칸을 모두가
    공유했다. 그래서 도구를 하나도 안 부른 새 세션에서 `verify_answer` 를 불러도
    **남이 조회한 도구 목록**이 나왔다(실측). 두 가지가 한꺼번에 깨진다 —
      ① 남이 조회한 수치를 "내 조회 결과에 있다" 로 **초록 판정**한다. 이 허브 안내문이
         지시하는 환각 방어의 **마지막 선**이 그것이다.
      ② 다른 호출자가 무엇을 돌렸는지 열거된다(`list_my_notifications` 같은 사람 단위
         도구 포함).
    신원이 있으면 신원(한 사람의 근거는 세션을 넘어 이어져야 한다), 없으면 **세션**으로
    가른다. 둘 다 없으면 **빈 문자열** — 호출부가 기록도 조회도 안 한다.
    **섞느니 안 쌓는다.**
    """
    u = _request_user()
    if u:
        return "u:" + u
    sid = _request_session()
    return "s:" + sid if sid else ""


def _evid_keep(tool: str, res):
    """도구 결과를 증거 칸에 쌓고 **그대로 돌려준다**(호출부 한 줄만 감싸면 되게)."""
    _evid_record(tool, res)
    return res


def _evid_record(tool: str, res) -> None:
    """도구 출력 원문을 호출자 칸에 쌓는다. 실패는 무시한다 — 검증 보조가 호출을 막으면 안 된다."""
    try:
        txt = "".join(getattr(c, "text", "") or "" for c in (getattr(res, "content", None) or []))
        if not txt:
            return
        key = _evid_key()
        if not key:
            return          # 누구 것인지 모르면 안 쌓는다 — 남의 칸에 들어가느니 없는 게 낫다
        now = time.monotonic()
        exp, calls = _EVID.get(key, (0.0, []))
        # ⚠ **만료를 무시하고 다시 도장 찍으면 안 된다.** 예전엔 저장된 exp 를 안 보고
        # `now + TTL` 로 덮어써서, 30분 지난 수치가 **무관한 호출 하나로 부활**했다.
        # 그러면 `verify_answer` 가 오래전 조회를 근거로 초록을 준다.
        if exp and exp < now:
            calls = []
        calls.append((tool, txt[:EVID_MAX_CHARS // 4]))
        del calls[:-EVID_MAX_CALLS]
        while sum(len(t) for _, t in calls) > EVID_MAX_CHARS and len(calls) > 1:
            calls.pop(0)
        _EVID[key] = (now + EVID_TTL_S, calls)
        _EVID.move_to_end(key)
        while len(_EVID) > EVID_MAX_CALLERS:
            _EVID.popitem(last=False)
    except Exception as exc:  # noqa: BLE001
        log.debug("evidence record skipped: %r", exc)


VERIFY_TOOL = types.Tool(
    name="verify_answer",
    description=(
        "답변 초안의 수치가 **이번 세션에 실제로 조회한 도구 출력**에 있는지 코드로 대조한다. "
        "사용자에게 수치를 보내기 전에 부르면, 근거 없는 값(기억으로 채운 값)을 집어 준다. "
        "소수점이 있거나 100 이상인 수치만 본다(작은 정수는 순번·개수라 오탐이 더 나쁘다)."),
    inputSchema={
        "type": "object",
        "properties": {"text": {"type": "string", "description": "사용자에게 보낼 답변 초안."}},
        "required": ["text"],
    },
)


async def _verify_answer(arguments: dict) -> types.CallToolResult:
    text = str((arguments or {}).get("text") or "")
    key = _evid_key()
    if not key:
        # ⚠ **없는 것과 못 잇는 것은 다르다.** 칸을 못 정하면 "조회 기록 0건" 이 아니라
        # "이을 수 없다" 다 — 전자로 답하면 사람이 '내가 조회를 안 했구나' 로 오독한다.
        return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(
            {"ok": False, "reason": "no_evidence_scope",
             "detail": "이 호출을 어느 조회 기록에 이을지 알 수 없습니다(신원·세션 없음) — "
                       "검증을 건너뛴 것이지 수치가 맞다는 뜻이 아닙니다."},
            ensure_ascii=False))], isError=False)
    exp, calls = _EVID.get(key, (0.0, []))
    if exp and exp < time.monotonic():
        calls = []
    src = " ".join(t for _, t in calls).replace(",", "")
    seen, bad, checked = set(), [], 0
    for m in _NUM_TOK_RE.finditer(text):
        raw = m.group(0)
        norm = raw.replace(",", "")
        try:
            val = float(norm)
        except ValueError:
            continue
        if "." not in norm and val < 100:
            continue
        if norm in seen:
            continue
        seen.add(norm)
        checked += 1
        if norm not in src:
            bad.append(raw)
    payload = {
        "checked": checked, "unsourced": bad[:12],
        "tool_calls": [t for t, _ in calls],
        "note": ("조회 기록이 없다 — 도구를 먼저 부르고 그 결과로 답하라."
                 if not calls else
                 ("모든 수치가 조회 결과에 있다." if not bad else
                  "위 수치는 이번 세션 조회 결과에서 찾지 못했다. 도구로 다시 확인하거나, "
                  "계산·추론한 값이면 그렇게 밝혀라 — 조회한 값처럼 말하지 마라.")),
    }
    return types.CallToolResult(content=[types.TextContent(
        type="text", text=json.dumps(payload, ensure_ascii=False, indent=2))])


# ── REST 다리 핸들러 ─────────────────────────────────────────────────────────
# 판정은 **MCP 경로와 같은 규칙**이다(`_backend_allowed`). 미들웨어가 이미 포털의 지금 값으로
# groups 를 다시 계산해 헤더에 실어 두었으므로 여기서 다시 묻지 않는다 — 다시 물으면 두 경로가
# 어긋난다(`_rest_allowed` 주석과 같은 이유).
_OPENAPI_TTL_S = 300
# rest_call 이 모델에 보여 줄 응답 상한. 넘으면 스트림을 끊는다(위 _rest_call 주석).
REST_CALL_MAX_BYTES = int(os.environ.get("GATEWAY_REST_CALL_MAX_BYTES", str(1024 * 1024)))
_openapi_cache: dict[str, tuple[dict | None, float]] = {}


def _rest_text(payload: dict) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(
        type="text", text=json.dumps(payload, ensure_ascii=False, indent=2))])


async def _openapi_of(site: str) -> dict | None:
    """사이트의 OpenAPI 문서(5분 캐시). 못 받으면 **None 이고 빈 dict 가 아니다** —
    빈 목록은 "경로가 없다" 로 읽히는데 실제로는 물어보지도 못한 것이다."""
    now = time.monotonic()
    hit = _openapi_cache.get(site)
    if hit and now - hit[1] < _OPENAPI_TTL_S:
        return hit[0]
    conf = REST.get(site) or {}
    base = str(conf.get("base") or "").rstrip("/")
    doc = None
    if base:
        headers = {}
        if credential_mode(conf) == "inject":
            headers[conf["inject"]["header"]] = conf["inject"]["value"]
        for suffix in ("/openapi.json", "/api/openapi.json", "/api/v1/openapi.json"):
            try:
                async with httpx.AsyncClient(timeout=8) as cli:
                    r = await cli.get(base + suffix, headers=headers)
                body = r.json() if r.status_code == 200 else None
                if isinstance(body, dict) and isinstance(body.get("paths"), dict):
                    doc = body
                    break
            except Exception:  # noqa: BLE001 — 못 받으면 base 만 안내한다
                continue
    _openapi_cache[site] = (doc, now)
    return doc


def _openapi_rows(doc: dict) -> list[dict]:
    rows = []
    for p, ops in (doc.get("paths") or {}).items():
        if not isinstance(ops, dict):
            continue
        for m, op in ops.items():
            if m.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
                continue
            text = ""
            if isinstance(op, dict):
                text = str(op.get("summary") or op.get("description") or "")
            summary = text.strip().splitlines()[0][:120] if text.strip() else ""
            rows.append({"method": m.upper(), "path": p, "summary": summary})
    rows.sort(key=lambda r: (r["path"], r["method"]))
    return rows


async def _rest_catalog(args: dict) -> types.CallToolResult:
    groups = _request_groups()
    want = str(args.get("site") or "").strip()
    q = str(args.get("q") or "").strip().lower()
    try:
        limit = max(1, min(200, int(args.get("limit") or 40)))
    except (TypeError, ValueError):
        limit = 40

    mine = [s for s in REST if _backend_allowed(s, groups)]
    if want:
        if want not in REST:
            return _rest_text({"error": f"unknown site: {want}", "known": mine})
        if want not in mine:
            return _rest_text({"error": f"forbidden: {want}", "detail": _deny_text(want, groups)})
        mine = [want]

    detailed = bool(want or q)
    out = []
    for s in mine:
        conf = REST[s]
        allowed = allowed_methods(conf)
        info = {
            "site": s,
            "methods": allowed or ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
            "readonly": allowed is not None and {m.upper() for m in allowed} <= {"GET", "HEAD"},
        }
        doc = await _openapi_of(s)
        if doc is None:
            info["paths"] = None
            info["note"] = ("이 사이트는 OpenAPI 를 내지 않는다(또는 지금 안 닿는다) — 경로를 "
                            "추측하지 말고 그 사이트 문서나 전용 MCP 도구를 보라.")
            out.append(info)
            continue
        title = str(((doc.get("info") or {}).get("title") or "")).strip()
        if title:
            info["title"] = title
        rows = _openapi_rows(doc)
        if q:
            rows = [r for r in rows if q in r["path"].lower() or q in r["summary"].lower()]
        info["path_count"] = len(rows)
        if detailed:
            info["paths"] = rows[:limit]
            if len(rows) > limit:
                info["truncated"] = f"{len(rows)}건 중 {limit}건만 보였다 — q 로 좁히거나 limit 를 올려라."
        else:
            info["hint"] = "경로 목록은 site 나 q 를 주면 나온다."
        out.append(info)

    payload = {
        "priority": ("전용 MCP 도구가 먼저다(`list_tool_apps`·`search_tools`). 이 표는 전용 도구로 "
                     "안 되는 것을 웹 API 로 직접 하려 할 때만 쓴다."),
        "sites": out,
        "how_to_call": "rest_call(site=…, path=…, method=…, query=…, body=…) — path 는 위 목록 그대로.",
    }
    if not mine:
        payload["note"] = ("내 권한으로 열리는 REST 사이트가 없다. 포털 '내 권한' 에서 요청하거나, "
                           "전용 MCP 도구로 같은 일이 되는지 `search_tools` 로 보라.")
    return _rest_text(payload)


async def _rest_call(args: dict) -> types.CallToolResult:
    site = str(args.get("site") or "").strip()
    path = str(args.get("path") or "").strip()
    method = (str(args.get("method") or "GET").strip() or "GET").upper()
    groups = _request_groups()
    caller = _request_user()
    t0 = time.monotonic()

    conf = REST.get(site)
    if not conf:
        return _rest_text({"error": f"unknown site: {site}",
                           "known": [s for s in REST if _backend_allowed(s, groups)]})
    if not _backend_allowed(site, groups):
        _audit(f"rest_call {method} {path}", site, False, "forbidden", 0, caller=caller)
        return _rest_text({"error": f"forbidden: {site}", "detail": _deny_text(site, groups)})
    if not path:
        return _rest_text({"error": "path 가 비었다", "detail": "rest_catalog 로 경로를 먼저 확인하라."})
    if not path.startswith("/"):
        path = "/" + path
    allowed = allowed_methods(conf)
    if allowed is not None and method not in {m.upper() for m in allowed}:
        _audit(f"rest_call {method} {path}", site, False, "method not allowed", 0, caller=caller)
        return _rest_text({"error": "method not allowed for this site",
                           "detail": f"{site} 는 {'/'.join(allowed)} 만 허용한다. 쓰기가 필요하면 "
                                     f"게이트웨이 설정의 rest.{site}.methods 에 명시해야 한다."})

    headers = {"accept": "application/json"}
    mode = credential_mode(conf)
    if mode == "per_user":
        app_id = str(conf["per_user"])
        if not caller:
            return _rest_text({"error": "신원이 없다",
                               "detail": f"{site} 는 본인 명의로만 부른다. 포털 PAT(이메일이 든 것)로 "
                                         f"게이트웨이에 붙어야 한다."})
        if app_id not in PER_USER_SSO:
            return _rest_text({"error": f"{site} 의 사용자 위임 설정이 없다",
                               "detail": f"게이트웨이 heax_registry.per_user_sso.{app_id} 가 비어 있다."})
        try:
            tok = await _user_pat(app_id, caller)
        except Exception as e:  # noqa: BLE001
            _audit(f"rest_call {method} {path}", site, False, f"per-user: {e!r}", 0, caller=caller)
            # 서비스 자격으로 조용히 강등하지 않는다 — 그러면 남의 시야로 답하고,
            # 실패가 정상 응답과 구분되지 않는다(MCP 경로와 같은 자세).
            return _rest_text({"error": f"{caller} 자격증명을 받지 못했다", "detail": str(e)[:300]})
        # Caddy forward_auth 뒤의 앱은 Authorization 을 그 문이 아는 토큰으로 지켜야 통과하므로
        # 앱 전용 자격을 따로 싣는다(`_call_as_user` 의 token_header 와 같은 이유).
        hdr = PER_USER_SSO[app_id].get("token_header")
        if hdr:
            headers[hdr] = tok
        else:
            headers["Authorization"] = f"Bearer {tok}"
    elif mode == "inject":
        inj = conf["inject"]
        headers[inj["header"]] = inj["value"]          # 그 사이트의 자기 서비스 자격
    if caller:
        headers["x-forwarded-user"] = caller           # 신원 힌트(사이트가 무시할 수 있다)
    body = args.get("body")
    query = args.get("query") or {}
    # ⚠ 응답을 **끝까지 받지 않는다.** 종전엔 `cli.request` 가 본문 전체를 메모리에 받은 뒤 json 을 시도하고
    #   text 로 한 벌 더 만들었다 — 모델이 `get_job_result` 설명대로 `result.zip` 을 이 도구로 부르면 게이트웨이가
    #   수 GB 를 삼킨다(120MB 응답에 피크 521MB 실측, 2026-09-24). 이 도구는 **텍스트/JSON 답을 모델에 보이는**
    #   용도라 상한을 두고, 넘치면 스트림을 끊고 error 로 돌려준다(파일은 전용 도구·ste-sync 로 받는다).
    cap = REST_CALL_MAX_BYTES
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as cli:
            async with cli.stream(method, conf["base"].rstrip("/") + path,
                                  params={k: str(v) for k, v in dict(query).items()},
                                  json=body if isinstance(body, (dict, list)) else None,
                                  headers=headers) as up:
                ctype = (up.headers.get("content-type") or "").lower()
                clen = up.headers.get("content-length")
                too_big = (clen is not None and clen.isdigit() and int(clen) > cap)
                chunks: list[bytes] = []
                got = 0
                if not too_big:
                    async for ch in up.aiter_bytes():
                        chunks.append(ch)
                        got += len(ch)
                        if got > cap:
                            too_big = True
                            break                       # 스트림을 여기서 끊는다 — 나머지는 안 받는다
                status = up.status_code
                raw = b"".join(chunks)
    except Exception as e:  # noqa: BLE001
        ms = round((time.monotonic() - t0) * 1000)
        _audit(f"rest_call {method} {path}", site, False, f"upstream: {e!r}", ms, caller=caller)
        return _rest_text({"error": "upstream unreachable", "site": site, "detail": str(e)[:300]})

    ms = round((time.monotonic() - t0) * 1000)
    if too_big:
        _audit(f"rest_call {method} {path}", site, False, f"response > {cap}B", ms, caller=caller)
        return _rest_text({"error": f"응답이 {cap // (1024 * 1024)}MB 를 넘는다 — 이 도구로 나르지 않는다",
                           "site": site, "method": method, "path": path, "status": status,
                           "content_type": ctype,
                           "detail": "파일·아카이브는 전용 도구(예: ste 의 get_job_file·ste-sync)로 받는다. "
                                     "rest_call 은 모델에 보일 텍스트/JSON 답 전용이다."})
    _audit(f"rest_call {method} {path}", site, status < 400, None, ms, caller=caller)
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001 — JSON 이 아니면 본문을 잘라서 그대로 보인다
        parsed = raw.decode("utf-8", errors="replace")[:8000]
    payload = {"site": site, "method": method, "path": path,
               "status": status, "ms": ms, "body": parsed}
    if status >= 400:
        # 실패를 성공처럼 생기게 두지 않는다 — 상태코드만 실으면 모델이 body 를 답으로 읽는다.
        payload["error"] = f"{site} 가 {status} 로 답했다"
    return _rest_text(payload)


def _visible_tools(groups: list[str]) -> list[types.Tool]:
    # 로컬 도구는 전 그룹 노출 — 실제 게이트는 포털 인증(PAT 포워딩)이 담당.
    local = [SAVE_CONV_TOOL, SEARCH_CONV_TOOL, LIST_APPS_TOOL, SEARCH_TOOLS_TOOL, INVOKE_TOOL,
             BROWSE_EXPERTS_TOOL, USE_EXPERTS_TOOL, VERIFY_TOOL]
    # REST 다리는 **등록된 사이트가 있을 때만** 낸다 — 쓸 수 없는 도구를 목록에 두면
    # 모델이 그것을 고르고 매번 빈손으로 돌아온다.
    if REST:
        local += [REST_CATALOG_TOOL, REST_CALL_TOOL]
    return [t for t in exposed_tools if _backend_allowed(route[t.name][0], groups)] + local


def _request_groups() -> list[str]:
    """현재 요청 헤더(X-HWAX-Groups)에서 caller groups 추출.
    요청 컨텍스트·헤더가 없으면 [](=제한 백엔드는 숨김 → fail-closed)."""
    try:
        req = _low.request_context.request
    except LookupError:
        return []
    raw = req.headers.get(GROUPS_HEADER) if req is not None else None
    return _parse_groups(raw)


def _request_purpose() -> str:
    """검증된 PAT 이 말한 호출 목적. 없으면 ''(=면제 없음, fail-closed)."""
    try:
        req = _low.request_context.request
    except LookupError:
        return ""
    raw = req.headers.get(PURPOSE_HEADER) if req is not None else None
    return (raw or "").strip()[:40]


def _request_corr() -> str:
    """현재 요청 헤더(X-HWAX-Corr)의 상관 ID — 어느 대화·실행의 호출인가.

    이게 없어서 감사 12,787줄을 대화에도 심의에도 이을 수 없었다. `(ts, tool, backend)`
    로 이어 붙이면 6,584줄이 키를 공유한다(최악의 키 하나에 109줄). 호출부가 실어 주면
    남기고, 안 실어 주면 그냥 없다 — **지어내지 않는다.**

    ⚠ **이 값은 호출자가 주는 라벨이지 주장이 아니다.** 신원 헤더(X-HWAX-User)는 PAT 에서
    다시 박아 위조를 막지만(2183행), 상관 ID 는 권한에 아무 영향이 없으므로 그대로 받는다.
    읽는 쪽은 이것을 **묶는 데만** 쓰고 누구인지 판정하는 데 쓰면 안 된다 — 그건 `caller` 다.
    """
    try:
        req = _low.request_context.request
    except LookupError:
        return ""
    raw = req.headers.get(CORR_HEADER) if req is not None else None
    return (raw or "").strip()[:120]


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
    headers = {
        "X-Heax-Gateway-Secret": conf["secret"],
        "X-Heax-User-Email": email,
        # 클라이언트를 구분해야 이 발급이 사용자의 웹 세션 토큰을 회수하지 않는다.
        "X-Heax-Client": conf.get("client") or "deliberation",
    }
    # heax-hub 앱(SIF)은 재배포마다 포트가 바뀐다 — 직접 포트를 박으면 다음 배포에 조용히 끊긴다.
    # 그래서 sso_url 을 Caddy 경로로 두고, 그 라우트의 forward_auth 를 서비스 토큰으로 통과한다.
    if conf.get("auth") == "heax" and HEAX.get("token"):
        headers["Authorization"] = f"Bearer {HEAX['token']}"
    async with httpx.AsyncClient(timeout=15) as cli:
        resp = await cli.post(conf["sso_url"], headers=headers)
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
                        extra_headers: dict | None = None, token_header: str | None = None):
    """이 호출만을 위한 단발 세션으로 백엔드를 부른다.

    영속 세션은 열 때의 헤더(서비스 계정)를 그대로 물고 있어 호출별 자격증명 교체가 안 된다.
    사용자별 스코프가 필요한 백엔드는 그래서 세션을 매번 새로 연다 — 핸드셰이크 비용이
    붙지만 대상이 로컬 앱이고, 대안은 '남의 데이터가 보이거나 아무것도 안 보이는' 둘 뿐이다.
    extra_headers 는 Authorization 외 헤더 교체용(예: RA 의 X-Workspace-Slug 를 그 사용자
    부서로) — 같은 이름의 서비스 계정 헤더를 대소문자 무관하게 밀어내고, 값이 None 이면
    **삭제**한다(사용자 부서가 비었을 때 서비스 부서가 새어 들어가 "부서를 찾을 수
    없습니다: dev" 가 나던 누수를 막는다 — cae00 실사고 2026-09-03).
    token_header 는 사용자 자격을 Authorization 이 아닌 그 헤더로 싣는 백엔드용이다 —
    Caddy forward_auth 뒤에 있는 heax 앱은 Authorization 을 heax 가 아는 토큰으로 지켜야
    문을 통과하므로, 앱 전용 자격은 따로 실어야 한다(안 그러면 Caddy 가 401 로 끊는다).
    """
    base = dict(b.headers or {})
    if extra_headers:
        drop = {k.lower() for k in extra_headers}
        base = {k: v for k, v in base.items() if k.lower() not in drop}
    auth = {token_header: token} if token_header else {"Authorization": f"Bearer {token}"}
    hdrs = {**base, **auth,
            **{k: v for k, v in (extra_headers or {}).items() if v is not None}}
    with anyio.fail_after(timeout_s):
        async with streamablehttp_client(b.url, headers=hdrs) as (read, write, _sid):
            async with ClientSession(read, write) as sess:
                await sess.initialize()
                return await sess.call_tool(original, arguments,
                                            read_timeout_seconds=timedelta(seconds=timeout_s))



# 호출자 신원을 **백엔드까지** 전달할 백엔드 키. 영속 세션은 열 때의 헤더(서비스 계정)를 그대로
# 물고 있어 호출마다 다른 신원이 닿지 않는다 — 그래서 MCP 심의는 늘 서비스 계정 시야로 돌았고,
# 사용자별 스코프 앱(DynaForge 등)이 "내 것이 하나도 없다" 로 답했다(실측 2026-09-12).
# 대상 백엔드는 호출당 단발 세션을 연다(핸드셰이크 비용 — 심의는 호출 빈도가 낮아 감당된다).
IDENTITY_FWD = {k.strip() for k in os.environ.get(
    "IDENTITY_FWD_BACKENDS", "hwax-deliberation").split(",") if k.strip()}


async def _call_with_identity(b: "_Backend", original: str, arguments: dict, timeout_s: float,
                              user: str, groups: list[str]):
    """백엔드의 자격은 그대로 두고 **신원 헤더만** 실어 단발 세션으로 부른다.

    그룹은 게이트웨이가 이미 검증·계산한 값이다(PAT 미들웨어가 위조 헤더를 버리고 포털의 지금
    권한으로 덮어쓴다) — 백엔드는 게이트웨이를 통해서만 닿으므로 이 값을 신뢰해도 된다."""
    hdrs = dict(b.headers or {})
    if groups:
        # ⚠ `:` 를 안전문자에 넣는다. 권한 키가 feat:chat·plat:aidatahub 꼴이라 인코딩하면
        # feat%3Achat 로 가고, 받는 쪽이 디코드하지 않으면 **전 키가 무효**가 된다(실측: 도구
        # 465 → 3개, 심의 좌석 0명). 헤더에 `:` 는 그대로 실어도 된다(latin-1 범위).
        hdrs[GROUPS_HEADER] = quote(",".join(groups), safe=",:")
    if user:
        hdrs[USER_HEADER] = quote(user, safe="@.")
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
        # ⚠ 차단은 **해석된 원본 도구 이름**으로 한다 — 호출자가 준 문자열로만 보면 같은
        # 도구의 다른 이름이 그대로 우회로가 된다. 호출 전용 별칭 `<백엔드키>_<도구>` 도,
        # 충돌 때 붙는 접두어 노출 이름도 `delete_`·`cancel_` 로 **시작할 수가 없다**
        # (접미어 `_control`·`_set_state` 만 보존돼 관문이 반쯤만 들었다).
        # 실측 — 별칭 도입으로 파괴 도구 9개가 이 관문을 그냥 지나가게 됐었고, 충돌
        # 접두어로 노출된 2개는 그 전부터 뚫려 있었다. `inner` 검사도 남긴다: 해석이
        # 안 되는 이름(오타·미접속 백엔드)이 파괴 꼴이면 `unknown tool` 보다 이 쪽이 낫다.
        _resolved = route.get(inner) or alias_route.get(inner)
        _orig = _resolved[1] if _resolved else inner
        # ⚠ **정확이름 목록도 해석된 원본으로 본다**(2026-09-18). 여태 `inner` 로만 봐서 별칭
        # (`reportarchive_trash_report`)이 그냥 통과했다 — 접두·접미 규칙만 원본으로 보고 있었다.
        # 실측으로 trash_report·publish_report·add_report_tags 가 백엔드까지 도달했다.
        _exact = inner in _INVOKE_DENY_EXACT or _orig in _INVOKE_DENY_EXACT
        # 면제는 **포털 절차 실행기**에만. 그 목록은 포털 `MUST_GATE` 와 같은 것이고, 절차는 그
        # 도구들을 `gate: human` 없이는 저장조차 못 한다 — 즉 사람이 이미 승인한 호출이다.
        # 면제가 없으면 절차는 이 도구들을 영영 못 부른다(늘 별칭으로 부르므로).
        _procedure = _request_purpose() == PROCEDURE_PURPOSE
        if _exact and _procedure:
            log.info("invoke_tool 정확이름 차단 면제(절차) — %s caller=%s corr=%s",
                     _orig, _request_user() or "-", _request_corr() or "-")
        if (_orig.startswith(_INVOKE_DENY_PREFIX) or _orig.endswith(_INVOKE_DENY_SUFFIX)
                or (_exact and not _procedure)
                or inner.startswith(_INVOKE_DENY_PREFIX)
                or inner.endswith(_INVOKE_DENY_SUFFIX)):
            _audit(name, None, False, f"invoke-denied:{inner}", 0,
                   caller=_request_user() or None, corr=_request_corr())
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
    if name == BROWSE_EXPERTS_TOOL.name:
        return await _browse_experts(arguments or {})
    if name == USE_EXPERTS_TOOL.name:
        return await _use_experts(arguments or {})
    if name == VERIFY_TOOL.name:
        return await _verify_answer(arguments or {})

    if name == REST_CATALOG_TOOL.name:
        return await _rest_catalog(arguments or {})
    if name == REST_CALL_TOOL.name:
        return await _rest_call(arguments or {})
    # `route` 를 **먼저** 본다 — bare 이름의 뜻은 그대로다. 없을 때만 호출 전용 별칭.
    resolved = route.get(name) or alias_route.get(name)
    if resolved is None:
        _audit(name, None, False, "unknown tool", 0,
               caller=_request_user() or None, corr=_request_corr())
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"unknown tool: {name}")],
            isError=True,
        )
    backend_key, original = resolved
    # tools/list에서 숨겼더라도 직접 호출을 시도할 수 있으니 호출 시점에도 인가 재확인(enforcement).
    if not _backend_allowed(backend_key, _request_groups()):
        _audit(name, backend_key, False, "forbidden", 0,
               caller=_request_user() or None, corr=_request_corr())
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"forbidden: {name} — {_deny_text(backend_key, _request_groups())}")],
            isError=True,
        )
    b = backends[backend_key]
    # 사용자 위임 백엔드인가 — **캐시 키에 소속이 들어가야** 하므로 조회보다 먼저 정한다.
    app_id = _delegation_app_id(backend_key)
    _aff = ""
    if app_id in PER_USER_SSO and _request_user():
        # 권한 조회와 같은 키라 이미 데워져 있다(추가 HTTP 없음). 실패하면 빈 값 — 모르면 안 싣는다.
        _aff = await _portal_affiliation(
            _request_user(), [g for g in _request_groups() if not _is_synthetic(g)])
    # ── 읽기 전용 캐시 ── 인가(위)를 통과한 뒤에 본다. 순서가 반대면 권한 없는 호출자가
    #    캐시된 남의 결과를 받는다. 키에도 신원이 들어간다(_cache_key 주석 참조).
    ckey = _cache_key(backend_key, original, arguments, _aff)
    if ckey is not None:
        _hit = _cache_get(ckey)
        if _hit is not None:
            _audit(name, backend_key, True, None, 0, caller=_request_user() or None,
                   note="cache-hit", corr=_request_corr())
            # ⚠ **캐시 적중도 근거다.** 이 줄만 `_evid_keep` 이 빠져 있었다(나머지 반환
            # 경로 다섯은 전부 감쌌다). 그래서 캐시가 데워진 뒤에는 `verify_answer` 가
            # **방금 제대로 조회한 수치**를 지어낸 값이라고 고발했다 — 간헐적이라
            # 모양이 가장 나쁘다(사람이 도구를 못 믿게 된다).
            return _evid_keep(name, _hit)
    else:
        # 캐시 대상이 아니다 = 쓰기이거나 알 수 없는 도구. 그 백엔드의 캐시를 버린다 —
        # 방금 만든 것이 TTL 동안 목록에 안 보이는 read-after-write 를 막는다.
        _cache_flush_backend(backend_key)
    # 행 걸린 백엔드가 챗 SSE 체인 전체를 무기한 블록하지 않게 호출당 타임아웃을 건다.
    call_timeout = timedelta(seconds=CALL_TIMEOUT_S)

    # 사용자 위임 — 이 백엔드가 사용자별 스코프를 쓰고 호출자 신원이 있으면, 서비스 계정이 아니라
    # 그 사용자의 자격증명으로 부른다. 신원이 없으면 종전대로 서비스 계정(감사에 사유를 남긴다).
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
            # 소속을 **이 호출에** 싣는다 — 앱이 소속 단위 읽기 공유를 판정한다(포털 W-93).
            # 값이 없으면 두 헤더를 **지운다**(None) — 서비스 계정 헤더가 남아 남의 소속으로
            # 읽히는 길을 만들지 않는다(RA X-Workspace-Slug 실사고와 같은 자세).
            # 증명을 같이 싣는 이유는 AFF_PROOF_HEADER 주석에 있다 — 앱의 정문이 여럿이다.
            extra = {AFF_HEADER: None, AFF_PROOF_HEADER: None}
            if _aff:
                extra = {AFF_HEADER: quote(_aff, safe=""),
                         AFF_PROOF_HEADER: _aff_proof(PER_USER_SSO[app_id]["secret"],
                                                      email, _aff)}
            for attempt in (0, 1):   # 폐기된 캐시 토큰은 1회 재발급 후 재시도
                try:
                    tok = await _user_pat(app_id, email, force=bool(attempt))
                    res = await _call_as_user(
                        b, original, arguments, tok, CALL_TIMEOUT_S, extra_headers=extra,
                        token_header=PER_USER_SSO[app_id].get("token_header"))
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
                _audit(name, backend_key, not getattr(res, "isError", False), None,
                       round((time.monotonic() - t0) * 1000),
                       caller=email, mode="as-user-pat", corr=_request_corr())
                return _cache_put(ckey, _evid_keep(name, res))
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
                _audit(name, backend_key, not getattr(res, "isError", False), None,
                       round((time.monotonic() - t0) * 1000),
                       caller=email, mode="as-conn", corr=_request_corr())
                return _cache_put(ckey, _evid_keep(name, res))

    # 이 호출이 쓰는 세션의 세대. 실패했을 때 "내가 죽었다고 본 그 세션" 을 가리키므로,
    # 그 사이 다른 호출이 이미 갈아 끼웠다면 새 세션을 또 부수지 않는다. try 밖에서 잡는다 —
    # 안에서 잡으면 session is None 분기에서 미정의가 된다.
    _gen = b._gen
    try:
        if b.session is None:
            raise RuntimeError("backend session down")
        _u, _g = _request_user(), _request_groups()
        if backend_key in IDENTITY_FWD and (_u or _g):
            # 신원이 있는 호출은 그 신원으로 간다 — 심의가 서비스 계정 시야로 돌면 사용자별
            # 데이터가 통째로 비어 보이고 보고서 귀속도 서비스 계정이 된다.
            res = await _call_with_identity(b, original, arguments, CALL_TIMEOUT_S, _u, _g)
            _audit(name, backend_key, not getattr(res, "isError", False), None,
                   round((time.monotonic() - t0) * 1000),
                   caller=_u or None, mode="identity-fwd", corr=_request_corr())
            return _cache_put(ckey, _evid_keep(name, res))
        res = await b.session.call_tool(original, arguments, read_timeout_seconds=call_timeout)
        _audit(name, backend_key, not getattr(res, "isError", False), None,
               round((time.monotonic() - t0) * 1000),
               caller=_u or None, mode="service", note=note, corr=_request_corr())
        return _cache_put(ckey, _evid_keep(name, res))
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
                    _audit(name, backend_key, not getattr(res, "isError", False), None,
                           round((time.monotonic() - t0) * 1000),
                           caller=_request_user() or None, mode="service",
                           note="reconnected" + (f"+{note}" if note else ""),
                           corr=_request_corr())
                    return _cache_put(ckey, _evid_keep(name, res))
        except Exception as e2:  # noqa: BLE001 — 재시도 실패도 정돈된 isError 로 (프로토콜 에러 방지)
            log.warning("retry of %s on %s failed too (%r)", name, backend_key, e2)
            e = e2
        _audit(name, backend_key, False, repr(e), round((time.monotonic() - t0) * 1000),
               caller=_request_user() or None, corr=_request_corr())
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
            # 무인증 헬스: 오케스트레이터가 MCP 핸드셰이크 없이 싸게 프로브.
            # ⚠ **무인증에는 프로브가 쓰는 것만 낸다.** 예전엔 `policy`(백엔드별 허용 그룹)와
            # `access_policy`(어느 자격이 어느 백엔드를 여는지)를 통째로 냈다 — nginx 가
            # 게이트웨이를 외부로 프록시하므로 내부 권한 지도가 그대로 나갔다. 운영자가
            # 보려면 **공유 시크릿**을 주면 된다(포털이 이미 그 값을 쓴다).
            _detail = _secret_eq(
                dict(scope.get("headers") or {}).get(b"authorization", b"").decode("latin-1"),
                expected)
            body = json.dumps({
                "status": "ok",
                "tools": len(exposed_tools),
                "backends": {k: (b.session is not None) for k, b in backends.items()},
                # 캐시 효과를 밖에서 볼 수 있게 — 안 보이면 켜졌는지도 모른다.
                "cache": {**_CACHE_STAT, "size": len(_RESP_CACHE), "ttl_s": CACHE_TTL_S},
                # 정책이 **실려 있는지**는 무인증으로도 봐야 한다 — 비어 있으면 권한이
                # 통째로 풀린 채 도는 것이고, 그건 프로브가 잡아야 할 사고다. 내용은 가린다.
                "access_policy_loaded": len(_ACCESS_POLICY),
                "access_policy_ready": _ACCESS_POLICY_READY,
                **({"policy": POLICY, "access_policy": _ACCESS_POLICY} if _detail else {}),
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
            # search_tools·invoke_tool 도 게이트웨이 로컬이다 — 빠뜨리면 /tools-map 의 _gateway
            # tool_count 와 list_tool_apps 가 서로 다른 수를 말해 클라이언트 카탈로그가 어긋난다.
            for _lt in (SEARCH_TOOLS_TOOL, INVOKE_TOOL, BROWSE_EXPERTS_TOOL, USE_EXPERTS_TOOL,
                        VERIFY_TOOL):
                _map.setdefault(_lt.name, "_gateway")
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
            # 영역 — 하는 일로 묶은 두 번째 축(tool_areas.json). 미분류는 숨기지 않고 따로 준다:
            # 새 앱이 붙어 분류표에 한 줄이 빠지면 그 도구들이 UI 에서 '미분류 N' 으로 보여야 한다.
            _areas = {n: _area_of(n, bk) for n, bk in _map.items()}
            _acnt = Counter(a for a in _areas.values() if a)
            body = json.dumps({
                "map": _map,
                "backends": sorted(set(_map.values())),
                "apps": _apps,
                "areas": _areas,
                "area_meta": [{**m, "tool_count": _acnt.get(m["area"], 0)} for m in _area_meta()],
                "unclassified": sorted(n for n, a in _areas.items() if not a),
            }, ensure_ascii=False).encode()
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": body})
            return
        if scope.get("path") == "/conn-invalidate" and scope.get("method") == "POST":
            # 포털이 사용자 연결(토큰·워크스페이스)을 바꾸면 이걸 부른다. 안 부르면 바뀐 값이
            # PORTAL_CONN_TTL_S(기본 300초) 동안 안 먹어서, 방금 조직을 바꾼 사용자의 보고서가
            # 옛 워크스페이스로 조용히 간다 — 설정이 안 듣는 것처럼 보이는 그 실패다.
            # GW_TOKEN 을 요구한다(포털이 /internal/connections 를 읽을 때 쓰는 값과 같다).
            if not _secret_eq(
                    dict(scope.get("headers") or {}).get(b"authorization", b"").decode("latin-1"),
                    expected):
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json")]})
                await send({"type": "http.response.body", "body": b'{"error":"unauthorized"}'})
                return
            _q = parse_qs((scope.get("query_string") or b"").decode("utf-8"))
            _email = (_q.get("email") or [""])[0].strip().lower()
            if _email:
                _gone = [k for k in _CONN_CACHE if k[1] == _email]
                for k in _gone:
                    _CONN_CACHE.pop(k, None)
            else:
                _gone = list(_CONN_CACHE)
                _CONN_CACHE.clear()
            # ⚠ **응답 캐시도 함께 비운다.** 연결 캐시만 지우면, 방금 워크스페이스를 바꾼
            # 사람의 **캐시된 읽기 결과**가 300초를 마저 산다 — 포털이 이 엔드포인트를
            # 부르는 이유가 "바뀐 값이 조용히 안 먹는 것" 을 막으려는 것인데 절반만 먹는다.
            # 캐시 키에 호출자 신원이 들어 있어(177행) 그 사람 것만 정확히 골라낼 수 있다.
            _rgone = [k for k in _RESP_CACHE if (not _email or (len(k) > 3 and k[3] == _email))]
            for k in _rgone:
                _RESP_CACHE.pop(k, None)
            # 그 사람 명의 PAT 캐시도 비운다 — 연결이 바뀌었으면 위임 토큰도 다시 받는다.
            _pgone = [k for k in _USER_PATS if (not _email or (isinstance(k, tuple) and _email in k)
                                               or k == _email)]
            for k in _pgone:
                _USER_PATS.pop(k, None)
            log.info("connection cache invalidated: %s (conn %d · resp %d · pat %d)",
                     _email or "(전체)", len(_gone), len(_rgone), len(_pgone))
            _body = json.dumps({"ok": True, "dropped": len(_gone),
                                "resp_dropped": len(_rgone),
                                "pat_dropped": len(_pgone)}).encode()
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": _body})
            return
        if scope.get("path") == "/refresh" and scope.get("method") == "POST":
            # 외부 MCP 의 기능 변경을 **즉시** 반영시키는 트리거. 주기 루프가 60초마다 같은
            # 일을 하지만, 배포 직후 검증(update-all)이 그때까지 옛 목록으로 판정하게 된다.
            # 백엔드에 I/O 를 일으키므로 GW_TOKEN 을 요구한다(무인증 /health·/tools-map 과 다름).
            if not _secret_eq(
                    dict(scope.get("headers") or {}).get(b"authorization", b"").decode("latin-1"),
                    expected):
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
        if _secret_eq(auth, expected):
            # 내부 에이전트 서버: GW_TOKEN. groups 는 에이전트가 x-hwax-groups 로 실어 보냄(신뢰).
            # 그룹 헤더가 아예 없으면 사용자를 대리하지 않는 내부 서비스 호출이다 — 표시 그룹을 붙여
            # 사람 권한 정책(포털)에서 뺀다. 권한 정책 이전과 같은 시야를 지킨다.
            # 목적 헤더는 **검증된 PAT 에서만** 나온다 — 이 경로(GW_TOKEN)는 PAT 검증을 안 하므로
            # 클라이언트가 실어 보낸 값을 버린다. 안 버리면 GW_TOKEN 을 쥔 쪽이 차단을 면제받는다.
            _kept = [(k, v) for (k, v) in (scope.get("headers") or [])
                     if k.lower() != PURPOSE_HEADER.encode()]
            if GROUPS_HEADER.encode() not in headers:
                _kept.append((GROUPS_HEADER.encode(), SERVICE_GROUP.encode()))
            await app({**scope, "headers": _kept}, receive, send)
            return
        # GW_TOKEN 이 아니면 포털 PAT(개인 Claude 등) 로 검증 시도 → 성공 시 PAT 의 groups 로 도구 필터.
        token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
        claims = await pat_verifier.verify(token, MCP_AUDIENCE) if (token and pat_verifier) else None
        if claims is not None:
            # 권한(feat:·plat:)은 PAT 에 박힌 발급 때 값이 아니라 포털의 **지금** 값으로 바꾼다 —
            # 거둔 권한이 PAT 수명(최대 100년) 동안 남지 않게. 포털이 모르면(None) PAT 값 그대로.
            _pat_groups = [str(g) for g in (claims.get("groups") or []) if str(g) != SERVICE_GROUP]
            _base = [g for g in _pat_groups if not _is_synthetic(g)]
            _now_keys = await _portal_entitlements(str(claims.get("email") or "").strip().lower(), _base)
            if _now_keys is not None:
                _pat_groups = _base + _now_keys
            groups = ",".join(_pat_groups)
            # 클라이언트가 위조로 넣었을 x-hwax-groups 는 버리고, 검증된 PAT 의 groups 로 강제한다.
            # 신원 헤더도 groups 와 똑같이 다룬다 — 클라이언트가 실어 보낸 값은 버리고 검증된
            # PAT 의 것만 싣는다. PAT 에 이메일이 없으면 아무것도 싣지 않는다(위조로 남의 시야를
            # 얻는 경로가 생기면 안 되므로, 신원 없음 쪽으로 닫는다).
            fresh = [(k, v) for (k, v) in (scope.get("headers") or [])
                     if k.lower() not in (GROUPS_HEADER.encode(), USER_HEADER.encode(),
                                          PURPOSE_HEADER.encode())]
            # PAT 의 groups 에도 한글이 올 수 있다 — 같은 규칙으로 인코딩해 실어야 헤더가 안 깨진다.
            fresh.append((GROUPS_HEADER.encode(), quote(groups, safe=",").encode("latin-1")))
            _email = str(claims.get("email") or "").strip().lower()
            if _email:
                fresh.append((USER_HEADER.encode(), quote(_email, safe="@.").encode("latin-1")))
            # 포털 절차 실행기가 찍은 토큰만 이 값을 가진다 — 사람이 `/auth/pat` 으로 만드는 토큰에는
            # 이 클레임을 넣는 자리가 없다(포털 `app/procedures/pat.py` 하나뿐, 시험이 건다).
            if str(claims.get("purpose") or "") == PROCEDURE_PURPOSE:
                fresh.append((PURPOSE_HEADER.encode(), PROCEDURE_PURPOSE.encode()))
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


async def _rest_mint(app_id: str, email: str) -> tuple[str, str | None]:
    """REST 프록시가 per_user 사이트를 부를 때 쓸 (토큰, 실을 헤더). MCP 경로와 같은 기계다."""
    if app_id not in PER_USER_SSO:
        raise RuntimeError(f"per_user_sso.{app_id} 설정이 없다")
    return await _user_pat(app_id, email), PER_USER_SSO[app_id].get("token_header")


async def _rest_allowed(site: str, pat_groups: list[str], email: str) -> bool:
    """REST 프록시의 자격 판정 — **MCP 경로와 같은 규칙**이다(`_backend_allowed`).

    권한은 PAT 에 박힌 발급 때 값이 아니라 포털의 **지금** 값으로 본다(2183행과 같은 자세) —
    거둔 권한이 PAT 수명(최대 100년) 동안 남으면 안 된다. 포털이 모르면 PAT 값 그대로 쓴다.
    """
    return _backend_allowed(site, await _rest_groups(pat_groups, email))


async def _rest_groups(pat_groups: list[str], email: str) -> list[str]:
    """REST 호출자의 **지금** 그룹 — PAT 의 발급 때 값이 아니라 포털의 현재 권한으로(_rest_allowed 와 같다)."""
    base = [g for g in pat_groups if g != SERVICE_GROUP and not _is_synthetic(g)]
    now_keys = await _portal_entitlements(email.strip().lower(), base) if email else None
    return base + (now_keys if now_keys is not None else [g for g in pat_groups if _is_synthetic(g)])


async def _rest_deny_text(site: str, pat_groups: list[str], email: str) -> str:
    """REST 프록시 403 의 사유 — MCP 쪽 forbidden 과 같은 문장(_deny_text). 3라운드 검토가 잡은 다섯 번째 소비처."""
    return _deny_text(site, await _rest_groups(pat_groups, email))


def main():
    star = fm.streamable_http_app()
    # REST 프록시 라우트(/api/<site>/<path>) 를 MCP 마운트보다 먼저 매칭되게 삽입.
    if REST:
        from rest_proxy import RestProxy
        proxy = RestProxy(REST, PORTAL, _audit, allow=_rest_allowed, mint=_rest_mint, deny_text=_rest_deny_text)
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
