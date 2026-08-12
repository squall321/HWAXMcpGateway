#!/usr/bin/env bash
# fresh 서버 1회 프로비저닝 — gateway_config.json + 에이전트 mcp_servers.json 자동 생성.
#
# 하는 일 (전부 이 박스 로컬에서, 네트워크 불필요):
#   1) GW_TOKEN 생성 (openssl rand -hex 32)
#   2) SignalForge 형제 레포의 .env 에서 SF_MCP_TOKEN(MCP)·API_KEY(REST) 읽기
#   3) mxwp_api 인스턴스 안에서 mxwp_ 서비스 토큰 2개(MCP용·REST용) 발급
#      (앱의 _gen_token/hash_password 를 그대로 import — 포맷/해시가 앱과 항상 일치)
#   4) gateway_config.json 작성(chmod 600) + HWAXAgentServer/mcp_servers.json 작성
#   5) ReportArchive 백엔드: RAT_TOKEN 환경변수가 있으면 포함, 없으면 생략(그 백엔드만 빠짐)
#      워크스페이스 슬러그는 RA_WORKSPACE_SLUG > 기존 config 값 > "dev" 순으로 정한다
#      (예전엔 "dev" 하드코딩이라 --force 마다 운영 박스 값을 덮어썼다).
#
# 백엔드 주소는 전부 오버라이드 가능하다 — 서비스가 다른 서버로 빠질 수 있기 때문이다.
# 우선순위는 env > 기존 config(.bak) > 같은 박스 localhost 기본값이다. env 를 안 쓰더라도
# 손으로 바꿔 둔 주소는 --force 재생성에서 보존된다.
#   RA_MCP_URL   SF_MCP_URL   MXWP_MCP_URL   AIDH_MCP_URL      (MCP 엔드포인트)
#   SF_REST_BASE MXWP_REST_BASE AIDH_REST_BASE                 (REST 베이스)
#   HEAX_MCP_SERVERS_URL / HEAX_MCP_BASE                       (heax registry — 기존부터 있던 손잡이)
#   6) ODB 자동화 허브: ODB_HUB_TOKEN 이 있으면 odb-hub 백엔드 포함(cae00 에서만 도달하는 사내 서버).
#      주의 — 게이트웨이는 "url" 키가 있는 항목만 백엔드로 읽는다(gateway.py:42). mcp-remote 의
#      {"command":"npx","args":[...]} 형식을 넣으면 에러 없이 조용히 무시되므로 url 형식으로 쓴다.
#
# 사용:  bash provision-config.sh            # 이미 config 있으면 건드리지 않음
#        bash provision-config.sh --force    # 재생성(기존은 .bak 백업)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT="$(dirname "$HERE")"
CFG="$HERE/gateway_config.json"
AGENT_DIR="$PARENT/HWAXAgentServer"
FORCE=0; [ "${1:-}" = "--force" ] && FORCE=1

if [ -f "$CFG" ] && [ "$FORCE" = 0 ]; then
  echo "이미 존재: $CFG — 재생성하려면 --force"
  exit 0
fi
[ -f "$CFG" ] && cp -f "$CFG" "$CFG.bak" && echo "기존 config 백업: $CFG.bak"

echo "▶ 1) GW_TOKEN 준비"
# --force 재생성 시 기존 토큰을 보존한다 — 회전하면 에이전트/PAT 소비자와의 정합이 깨질 수 있고,
# 백엔드 추가가 목적인 재프로비저닝에 토큰 회전은 불필요하다. 명시 회전은 ROTATE_GW_TOKEN=1.
GW_TOKEN=""
# 조건에 FORCE 가 빠져 있었다 — .bak 은 지워지지 않고 남으므로, config 만 지우고 재실행하면
# '신규 프로비저닝'인데도 예전 .bak 에서 토큰을 끌어와 회전이 안 된다(출력은 '✓ 보존'이라 경고도 없다).
# 이번 실행이 26행에서 방금 백업을 뜬 경우(=FORCE 이고 config 가 있었던 경우)에만 보존한다.
if [ "$FORCE" = 1 ] && [ "${ROTATE_GW_TOKEN:-0}" != "1" ] && [ -f "$CFG.bak" ]; then
  GW_TOKEN="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["_gateway"]["token"])' "$CFG.bak" 2>/dev/null || true)"
  # 토큰 앞자리를 찍지 않는다 — 이 출력은 update-all 로그에 그대로 남는다.
  [ -n "$GW_TOKEN" ] && echo "  ✓ 기존 GW_TOKEN 보존"
fi
[ -n "$GW_TOKEN" ] || { GW_TOKEN="$(openssl rand -hex 32)"; echo "  ✓ 신규 생성"; }

echo "▶ 2) SignalForge .env 에서 토큰 읽기"
SF_ENV="$PARENT/SignalForge/.env"
SF_MCP_TOKEN="$(grep -E '^SF_MCP_TOKEN=' "$SF_ENV" 2>/dev/null | head -1 | cut -d= -f2-)"
SF_API_KEY="$(grep -E '^API_KEY=' "$SF_ENV" 2>/dev/null | head -1 | cut -d= -f2-)"
# SF_MCP_TOKEN 미설정 = SF MCP 서버가 무인증(standalone) 모드로 도는 것 → 헤더 없이 붙는다.
[ -n "$SF_MCP_TOKEN" ] && echo "  ✓ SF_MCP_TOKEN (${SF_MCP_TOKEN:0:8}…)" \
  || echo "  · SF_MCP_TOKEN 미설정 — SF MCP 는 무인증 모드 → 헤더 없이 연결"
[ -n "$SF_API_KEY" ]   && echo "  ✓ API_KEY (${SF_API_KEY:0:6}…)"        || echo "  ⚠ API_KEY 없음 — signalforge REST inject 생략됨"

echo "▶ 3) mxwp 서비스 토큰 발급 (mxwp_api 인스턴스 안에서, 앱 코드로)"
mint_mxwp() {  # $1=토큰이름 $2=앱디렉토리 $3=DSN → stdout 마지막 줄이 평문 토큰. 실패 시 stderr 노출.
  apptainer exec instance://mxwp_api bash -lc "cd '$2' && python3 - '$1' '$3'" <<'PYEOF' | tail -1
import asyncio, sys
sys.path.insert(0, ".")
from app.routers.api_tokens import _gen_token
from app.core.security import hash_password
name, dsn = sys.argv[1], sys.argv[2].replace("postgresql+asyncpg://", "postgresql://")
tok, prefix = _gen_token()
h = hash_password(tok)
async def main():
    import asyncpg
    conn = await asyncpg.connect(dsn)
    uid = (await conn.fetchval("select id from users where email='admin@mx.local'")
           or await conn.fetchval("select id from users limit 1"))
    assert uid, "users 테이블이 비어 있음"
    # 재실행(--force) 시 같은 이름이 이미 있으면 토큰을 회전(rotate) — (user_id,name) 유니크 제약 대응.
    await conn.execute(
        "insert into api_tokens (user_id, name, token_prefix, token_hash, scopes)"
        " values ($1, $2, $3, $4, '[\"read\", \"write\"]'::jsonb)"
        " on conflict (user_id, name) do update set"
        " token_prefix=excluded.token_prefix, token_hash=excluded.token_hash,"
        " scopes=excluded.scopes, revoked_at=null, expires_at=null",
        uid, name, prefix, h)
    await conn.close()
try:
    asyncio.run(main())
except Exception as exc:  # traceback 대신 원인 한 줄 (프로비저닝 출력 가독성)
    print(f"MINT_FAIL: {exc!r}", file=sys.stderr)
    raise SystemExit(1)
print(tok)
PYEOF
}
# heax-hub MCP 토큰 자동 발급 — heax-hub 백엔드(호스트 venv)에서 pat_service 로 admin PAT 를 민팅.
# admin 유저여야 /api/v1/mcp/servers 가 전체 앱을 보인다(visible_app_ids=None). mxwp 자동 발급과 동형.
mint_heax() {  # $1=토큰이름 → stdout 마지막 줄이 평문 토큰. 실패 시 stderr.
  local hdir="$PARENT/HEAXHub/backend"
  [ -x "$hdir/.venv/bin/python" ] || { echo "heax-hub venv 없음: $hdir/.venv" >&2; return 1; }
  ( cd "$hdir" && .venv/bin/python - "$1" <<'PYEOF' ) | tail -1
import sys
sys.path.insert(0, ".")
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.db.models.user import User, UserRole
from app.db.models.personal_access_token import PersonalAccessToken
from app.services import pat_service
name = sys.argv[1]
# PAT 테이블은 alembic 마이그레이션에 없는 신규 테이블이라, cae00 처럼 alembic 로만 스키마를
# 만드는 배포엔 존재하지 않아 DELETE/INSERT 가 UndefinedTable 로 죽었다. 발급 전 멱등 create_all
# 로 이 테이블만 보장한다(기존 테이블은 불변 — 테스트가 쓰는 것과 동일한 패턴).
Base.metadata.create_all(engine, tables=[PersonalAccessToken.__table__])
db = SessionLocal()
try:
    user = (db.query(User).filter(User.role == UserRole.ADMIN).order_by(User.created_at.asc()).first()
            or db.query(User).order_by(User.created_at.asc()).first())
    assert user, "users 테이블이 비어 있음"
    # 재실행 누적 방지 — 같은 이름 기존 토큰 삭제 후 신규 발급(평문 회수 불가라 매번 신규 토큰)
    db.query(PersonalAccessToken).filter(
        PersonalAccessToken.user_id == user.id,
        PersonalAccessToken.name == name).delete()
    db.commit()
    _row, tok = pat_service.issue(db, user=user, name=name)
    print(tok)
finally:
    db.close()
PYEOF
}
# DynaForge(kooremapper) MCP 전용 kr_ PAT 발급 — heax 서비스 PAT 로는 이 앱이 안 열린다.
# 이 앱은 매니페스트가 portal_auth 를 일부러 빼고(launch.mode=proxy) Authorization 을 자기
# REST(:8700)로 넘겨 재검증한다. 그래서 heax_ 토큰을 주면 shared/auth.py 가 "토큰이 유효하지
# 않거나 만료되었습니다"로 전량 거절한다 — 도구 22개가 목록에만 뜨고 호출은 0% 성공이었다.
# 발급은 KooRemapper 의 게이트웨이 SSO(/api/v1/auth/sso)를 그대로 쓴다. 신뢰 근거는 공유
# 시크릿이고, 사용자당 직전 SSO PAT 를 회수하므로 재실행해도 토큰이 쌓이지 않는다.
mint_koorm() {  # → stdout 마지막 줄이 kr_ 평문 토큰. 실패 시 stderr.
  local envf="$PARENT/KooRemapper/platform/.env" base="${KOORM_BASE:-http://127.0.0.1:8700}"
  [ -f "$envf" ] || { echo "KooRemapper platform/.env 없음: $envf" >&2; return 1; }
  local sec; sec="$(awk -F= '/^KOORM_HEAX_GATEWAY_SECRET=/{sub(/^[^=]*=/,"");print;exit}' "$envf")"
  [ -n "$sec" ] || { echo "KOORM_HEAX_GATEWAY_SECRET 미설정 — SSO 엔드포인트가 닫혀 있다" >&2; return 1; }
  local body
  body="$(curl -sS -m 15 -X POST "$base/api/v1/auth/sso" \
      -H "X-Heax-Gateway-Secret: $sec" \
      -H "X-Heax-User-Email: ${KOORM_SVC_EMAIL:-hwax-gateway@heax.local}" \
      -H "X-Heax-User-Name: HWAX MCP Gateway (service)" 2>&1)" || {
    echo "SSO 호출 실패: $body" >&2; return 1; }
  printf '%s' "$body" | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: print("SSO 응답이 JSON 이 아님", file=sys.stderr); raise SystemExit(1)
def find(o):
    if isinstance(o,dict):
        for k,v in o.items():
            if k in ("access_token","token") and isinstance(v,str): return v
            r=find(v)
            if r: return r
    return None
t=find(d)
if not t: print(f"토큰 없음: {json.dumps(d,ensure_ascii=False)[:200]}", file=sys.stderr); raise SystemExit(1)
print(t)'
}

MXWP_MCP=""; MXWP_REST=""
if apptainer instance list 2>/dev/null | awk 'NR>1{print $1}' | grep -qx mxwp_api; then
  # 앱 코드 경로 자동 탐지 (배포마다 다를 수 있음: apps/api, dist/… 등)
  MXAPP="$(apptainer exec instance://mxwp_api bash -lc \
    'find /workspace -maxdepth 6 -path "*/app/routers/api_tokens.py" -not -path "*/node_modules/*" 2>/dev/null | head -1')"
  MXAPP="${MXAPP%/app/routers/api_tokens.py}"
  # DSN 자동 탐지: 실행 중인 API 프로세스 environ → 컨테이너 env → dev 기본값
  MXDSN="$(apptainer exec instance://mxwp_api bash -lc \
    'for e in /proc/[0-9]*/environ; do tr "\0" "\n" < "$e" 2>/dev/null | grep -m1 "^DATABASE_URL="; done 2>/dev/null | head -1 | cut -d= -f2-')"
  [ -n "$MXDSN" ] || MXDSN="postgresql://mxwp:mxwp_dev_password_change_me@127.0.0.1:5532/mxwp"
  if [ -z "$MXAPP" ]; then
    echo "  ⚠ 컨테이너에서 mxwp 앱 코드(app/routers/api_tokens.py)를 못 찾음 — mx 백엔드 생략"
  else
    echo "  · 앱 경로: $MXAPP | DSN: $(echo "$MXDSN" | sed 's/:[^:@]*@/:***@/')"
    MXWP_MCP="$(mint_mxwp hwax-gateway-mcp "$MXAPP" "$MXDSN")"
    MXWP_REST="$(mint_mxwp hwax-gateway-rest "$MXAPP" "$MXDSN")"
    case "$MXWP_MCP" in mxwp_*) echo "  ✓ MCP용 (${MXWP_MCP:0:13}…)" ;; *) echo "  ⚠ 발급 실패 — 위 에러 참조"; MXWP_MCP="" ;; esac
    case "$MXWP_REST" in mxwp_*) echo "  ✓ REST용 (${MXWP_REST:0:13}…)" ;; *) MXWP_REST="" ;; esac
  fi
else
  echo "  ⚠ mxwp_api 인스턴스 없음 — mx-white-paper 백엔드 생략됨(뜬 뒤 --force 재실행)"
fi

# heax_registry 자동 활성화 — HEAX_MCP_TOKEN 미설정 시 heax-hub 에서 admin PAT 를 자동 발급한다.
# (env 로 명시돼 있으면 그대로 존중.) 이걸로 update-all 만으로 heax 도구가 전량 챗까지 간다.
if [ -z "${HEAX_MCP_TOKEN:-}" ]; then
  if [ -x "$PARENT/HEAXHub/backend/.venv/bin/python" ]; then
    echo "▶ heax MCP 토큰 자동 발급(hwax-gateway-mcp)"
    HEAX_MCP_TOKEN="$(mint_heax hwax-gateway-mcp 2>/tmp/heaxmint.$$.err || true)"
    case "${HEAX_MCP_TOKEN:-}" in
      heax_*) echo "  ✓ heax MCP 토큰 (${HEAX_MCP_TOKEN:0:14}…) → heax_registry 활성" ;;
      *) echo "  ⚠ heax 토큰 자동 발급 실패 — heax_registry 생략(수동: provision.env 에 HEAX_MCP_TOKEN)"
         [ -s /tmp/heaxmint.$$.err ] && sed 's/^/    /' /tmp/heaxmint.$$.err >&2
         HEAX_MCP_TOKEN="" ;;
    esac
    rm -f /tmp/heaxmint.$$.err
  else
    echo "  · heax-hub 백엔드 venv 미발견 — heax_registry 생략(heax 앱 자동탐지 비활성)"
  fi
fi

# DynaForge MCP 는 자체 kr_ PAT 를 요구한다 — heax_registry 가 켜져 있을 때만 의미가 있다.
if [ -n "${HEAX_MCP_TOKEN:-}" ] && [ -z "${KOORM_MCP_TOKEN:-}" ]; then
  if [ -d "$PARENT/KooRemapper/platform" ]; then
    echo "▶ DynaForge MCP 토큰 자동 발급(kr_ PAT)"
    KOORM_MCP_TOKEN="$(mint_koorm 2>/tmp/koormint.$$.err || true)"
    case "${KOORM_MCP_TOKEN:-}" in
      kr_*) echo "  ✓ kr_ PAT 발급 → heax_registry.app_tokens.kooremapper_mcp" ;;
      *) echo "  ⚠ kr_ PAT 발급 실패 — DynaForge MCP 도구는 호출 시 인증 실패한다(목록에는 뜬다)"
         [ -s /tmp/koormint.$$.err ] && sed 's/^/    /' /tmp/koormint.$$.err >&2
         KOORM_MCP_TOKEN="" ;;
    esac
    rm -f /tmp/koormint.$$.err
  else
    echo "  · KooRemapper 레포 미발견 — DynaForge MCP 토큰 생략"
  fi
fi

if [ -z "${ODB_HUB_TOKEN:-}" ]; then
  echo "  · ODB_HUB_TOKEN 미설정 — odb-hub 백엔드 생략(provision.env 에 ODB_HUB_TOKEN=... 한 줄이면 편입)"
else
  echo "  ✓ odb-hub 토큰 확인 — ${ODB_HUB_BASE:-http://10.252.38.121:8000}/mcp 로 등록"
fi

echo "▶ 4) config 파일 작성"
GW_TOKEN="$GW_TOKEN" SF_MCP_TOKEN="$SF_MCP_TOKEN" SF_API_KEY="$SF_API_KEY" \
MXWP_MCP="$MXWP_MCP" MXWP_REST="$MXWP_REST" RAT_TOKEN="${RAT_TOKEN:-}" \
HEAX_MCP_TOKEN="${HEAX_MCP_TOKEN:-}" HEAX_MCP_SERVERS_URL="${HEAX_MCP_SERVERS_URL:-}" HEAX_MCP_BASE="${HEAX_MCP_BASE:-}" \
KOORM_MCP_TOKEN="${KOORM_MCP_TOKEN:-}" \
ODB_HUB_TOKEN="${ODB_HUB_TOKEN:-}" ODB_HUB_BASE="${ODB_HUB_BASE:-}" \
RA_WORKSPACE_SLUG="${RA_WORKSPACE_SLUG:-}" \
RA_MCP_URL="${RA_MCP_URL:-}" SF_MCP_URL="${SF_MCP_URL:-}" MXWP_MCP_URL="${MXWP_MCP_URL:-}" \
AIDH_MCP_URL="${AIDH_MCP_URL:-}" AIDH_REST_BASE="${AIDH_REST_BASE:-}" \
MXWP_REST_BASE="${MXWP_REST_BASE:-}" SF_REST_BASE="${SF_REST_BASE:-}" \
CFG="$CFG" AGENT_DIR="$AGENT_DIR" python3 - <<'PYEOF'
import json, os
e = os.environ


def _prev(key, field="url"):
    """직전 config(.bak)의 값 — --force 재생성이 손으로 바꾼 주소를 잃지 않게 한다."""
    try:
        with open(e["CFG"] + ".bak") as f:
            return (json.load(f).get(key) or {}).get(field)
    except Exception:
        return None


def _url(env_key, key, default, field="url"):
    """백엔드 주소: env > 기존 config > 기본값(같은 박스 localhost).

    서비스가 다른 서버로 빠질 수 있으므로 전부 오버라이드 가능해야 한다 —
    예전엔 127.0.0.1 이 리터럴로 박혀 있어 원격 배치를 표현할 방법이 없었다.
    heax_registry 만 이 손잡이를 갖고 있었는데, 나머지도 같은 이유로 필요하다.
    """
    return e.get(env_key) or _prev(key, field) or default


def _prev_ra_slug():
    """직전 config 의 reportarchive 슬러그. --force 재생성이 값을 잃지 않게 한다."""
    try:
        with open(e["CFG"] + ".bak") as f:
            return ((json.load(f).get("reportarchive") or {}).get("headers") or {}).get("X-Workspace-Slug")
    except Exception:
        return None

cfg = {"_gateway": {"host": "127.0.0.1", "port": 9110, "token": e["GW_TOKEN"]}}
if e.get("RAT_TOKEN"):
    cfg["reportarchive"] = {"url": _url("RA_MCP_URL", "reportarchive", "http://127.0.0.1:3002/mcp"),
        "transport": "streamable_http",
        "headers": {"Authorization": f"Bearer {e['RAT_TOKEN']}",
                    # 슬러그가 "dev" 로 하드코딩돼 있었다. 박스마다 다를 수 있는 값인데
                    # --force 가 돌 때마다 무조건 dev 로 덮어쓴다 — 운영 박스가 다른 워크스페이스를
                    # 쓰고 있었다면 조용히 엉뚱한 곳을 가리키게 된다(경고도 없다).
                    # 기존 config 값 > env > "dev" 순으로 존중한다.
                    "X-Workspace-Slug": e.get("RA_WORKSPACE_SLUG") or _prev_ra_slug() or "dev"}}
# SF MCP 는 SF_MCP_TOKEN 미설정 시 무인증 모드로 돌므로 헤더 없이도 포함한다.
cfg["signalforge"] = {"url": _url("SF_MCP_URL", "signalforge", "http://127.0.0.1:8013/mcp"),
                      "transport": "streamable_http"}
if e.get("SF_MCP_TOKEN"):
    cfg["signalforge"]["headers"] = {"Authorization": f"Bearer {e['SF_MCP_TOKEN']}"}
if e.get("MXWP_MCP"):
    cfg["mx-white-paper"] = {"url": _url("MXWP_MCP_URL", "mx-white-paper", "http://127.0.0.1:8765/mcp"),
        "transport": "streamable_http",
        "headers": {"Authorization": f"Bearer {e['MXWP_MCP']}"}}
# AIDH MCP 는 api_server 에 내장(:8001/mcp, auth_required=false → 무인증) — 항상 포함.
cfg["ai-data-hub"] = {"url": _url("AIDH_MCP_URL", "ai-data-hub", "http://127.0.0.1:8001/mcp/"),
                      "transport": "streamable_http"}
def _rest_base(env_key, key, default):
    try:
        with open(e["CFG"] + ".bak") as f:
            prev = ((json.load(f).get("rest") or {}).get(key) or {}).get("base")
    except Exception:
        prev = None
    return e.get(env_key) or prev or default


rest = {"ai-data-hub": {"base": _rest_base("AIDH_REST_BASE", "ai-data-hub", "http://127.0.0.1:8001")}}
if e.get("MXWP_REST"):
    rest["mx-white-paper"] = {"base": _rest_base("MXWP_REST_BASE", "mx-white-paper", "http://127.0.0.1:8800"),
        "inject": {"header": "Authorization", "value": f"Bearer {e['MXWP_REST']}"}}
if e.get("SF_API_KEY"):
    rest["signalforge"] = {"base": _rest_base("SF_REST_BASE", "signalforge", "http://127.0.0.1:17370"),
        "inject": {"header": "X-API-Key", "value": e["SF_API_KEY"]}}
cfg["rest"] = rest
cfg["portal"] = {"jwks_url": "http://127.0.0.1:8723/.well-known/jwks.json",
                 "revoked_url": "http://127.0.0.1:8723/auth/pat/revoked.json",
                 "audience_ok": ["mx-white-paper", "ai-data-hub", "signalforge"]}
# ODB 자동화 허브 — cae00 에서만 도달하는 사내 MCP 서버. dev 에서는 닿지 않는다(실측: 포트 차단).
# 반드시 url 형식이어야 한다 — 게이트웨이는 `"url" in v` 인 항목만 백엔드로 읽는다(gateway.py:42).
# mcp-remote 의 {"command":"npx","args":[...]} 형식을 그대로 넣으면 에러 없이 조용히 무시된다.
# mcp-remote 는 그 URL 로 가는 stdio 브리지일 뿐이라, HTTP 를 직접 말하는 이 게이트웨이에는 불필요하다.
# 토큰이 URL 쿼리에 들어가므로 레포에 박지 않는다 — provision.env 의 ODB_HUB_TOKEN 을 쓴다(RAT_TOKEN 과 동형).
if e.get("ODB_HUB_TOKEN"):
    # 호스트는 보존하되 토큰은 항상 env 의 현재 값을 쓴다.
    # URL 통째로 보존하면 .bak 에 박힌 옛 토큰이 되살아나 새 토큰을 덮어쓴다 —
    # 호스트는 '설정'이고 토큰은 '시크릿'이라 수명이 다르다.
    _odb_prev = _prev("odb-hub")            # 예: http://10.9.9.9:8000/mcp?token=old
    _odb_base = (e.get("ODB_HUB_BASE")
                 or (_odb_prev.split("/mcp")[0] if _odb_prev else None)
                 or "http://10.252.38.121:8000")
    cfg["odb-hub"] = {
        "url": f'{_odb_base}/mcp?token={e["ODB_HUB_TOKEN"]}',
        "transport": "streamable_http"}

# heax-hub MCP 앱 자동탐지(옵션) — heax registry 를 폴링해 mcp:{expose} 앱을 heax-<id> 백엔드로 흡수.
#   token: HEAX_MCP_TOKEN env(heax 'MCP 토큰' 메뉴/PAT). 없으면 heax_registry 생략(그 기능만 빠짐).
#   servers_url/base: dev 기본 localhost. prod 은 HEAX_MCP_SERVERS_URL/HEAX_MCP_BASE(도메인)로 오버라이드.
#   app_tokens: 자체 인증을 쓰는 앱의 토큰 예외표. heax 서비스 PAT 를 자기 백엔드로 넘겨
#     재검증하는 앱(kooremapper_mcp)은 종류가 안 맞아 호출이 전량 실패하므로 여기서 갈아끼운다.
#     발급이 실패한 실행에서 기존 토큰까지 날리면 멀쩡하던 앱이 죽으므로 이전 값을 보존한다.
if e.get("HEAX_MCP_TOKEN"):
    app_tokens = dict(_prev("heax_registry", "app_tokens") or {})
    if e.get("KOORM_MCP_TOKEN"):
        app_tokens["kooremapper_mcp"] = e["KOORM_MCP_TOKEN"]
    cfg["heax_registry"] = {
        "servers_url": e.get("HEAX_MCP_SERVERS_URL") or "http://127.0.0.1:4040/api/v1/mcp/servers",
        "base": e.get("HEAX_MCP_BASE") or "http://127.0.0.1:4180",
        "token": e["HEAX_MCP_TOKEN"]}
    if app_tokens:
        cfg["heax_registry"]["app_tokens"] = app_tokens
# 프로비저너가 만드는 키는 아래가 전부다. 그 밖의 백엔드는 손으로 붙인 것이므로 보존한다.
# 예전엔 cfg 를 빈 dict 에서 시작해 파일을 통째로 덮어썼다 — 그래서 --force 한 번에
# smart-twin-cluster(slurm 도구 19개)가 조용히 사라진다. update-all 의 기대 목록에도
# 없어서 사라진 사실조차 안 잡힌다(실측). 관리 키는 여기서 보존하지 않는다 —
# 이번 실행이 안 만든 관리 키(예: RAT_TOKEN 없어 빠진 reportarchive)는 의도된 제거다.
MANAGED = {"_gateway", "reportarchive", "signalforge", "mx-white-paper",
           "ai-data-hub", "rest", "portal", "heax_registry", "odb-hub"}
try:
    with open(e["CFG"]) as f:
        prev = json.load(f)
except Exception:
    prev = {}
for k, v in prev.items():
    if k not in MANAGED and k not in cfg:
        cfg[k] = v
        print(f"  · 보존: {k} (프로비저너가 만들지 않는 백엔드 — 덮어쓰지 않는다)")
with open(e["CFG"], "w") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False); f.write("\n")
print(f"  ✓ {e['CFG']}")

agent = os.path.join(e["AGENT_DIR"], "mcp_servers.json")
if os.path.isdir(e["AGENT_DIR"]):
    with open(agent, "w") as f:
        json.dump({"gateway": {"url": "http://127.0.0.1:9110/mcp", "transport": "streamable_http",
                   "headers": {"Authorization": f"Bearer {e['GW_TOKEN']}"}}}, f, indent=2); f.write("\n")
    print(f"  ✓ {agent} (같은 GW_TOKEN)")
else:
    print(f"  ⚠ {e['AGENT_DIR']} 없음 — mcp_servers.json 생략(에이전트 클론 후 --force 재실행)")
PYEOF
# 히어독의 성공 여부를 아무도 안 봤다 — config 작성이 통째로 실패해도 아래 chmod 를 지나
# '▶ 완료' 를 찍고 exit 0 으로 끝났다. 호출부(update-all §5)도 종료코드를 안 보므로
# 재프로비저닝 실패가 어디에도 안 남는다. set -e 는 켤 수 없다 — 이 파일엔 '실패가 정상'인
# grep/case 분기가 여럿이라 그것들까지 죽는다. 그래서 여기만 명시적으로 검사한다.
rc=$?
[ "$rc" = 0 ] || { echo "✗ config 작성 실패(python rc=$rc) — 기존 config 를 그대로 둔다" >&2; exit 1; }
# 있던 백엔드가 조용히 사라지는 것을 막는다. 관리 키는 토큰 env 가 없으면 만들어지지 않는데,
# 그게 '의도된 제거'인지 '이 박스에 provision.env 가 없을 뿐'인지 스크립트는 구분하지 못한다.
# 실제로 dev 에서 --force 한 번에 reportarchive(도구 24개)가 사라졌다. 최소한 말은 해야 한다.
if [ -f "$CFG.bak" ]; then
  CFG="$CFG" python3 - <<'PYCHK'
import json, os
cfg = os.environ["CFG"]
try:
    a = json.load(open(cfg)); b = json.load(open(cfg + ".bak"))
except Exception:
    raise SystemExit(0)
skip = {"rest", "portal"}
gone = sorted(k for k in b if k not in skip and k not in a)
if gone:
    print("  ⚠ 이전 config 에 있었으나 이번에 빠진 백엔드: " + ", ".join(gone))
    print("     해당 토큰 env 가 이 박스에 없으면 그 백엔드는 생성되지 않는다(예: RAT_TOKEN → reportarchive).")
    print("     의도한 제거가 아니라면 provision.env 를 채우고 --force 를 다시 돌리거나,")
    print(f"     {os.path.basename(cfg)}.bak 에서 해당 키만 복원하라.")
PYCHK
fi
chmod 600 "$CFG" 2>/dev/null
chmod 600 "$AGENT_DIR/mcp_servers.json" 2>/dev/null   # GW_TOKEN 평문 — config와 동일하게 보호

echo "▶ 완료 — 게이트웨이 기동: (포털) ./infra/scripts/services.sh up mcp-gateway agent-server"
