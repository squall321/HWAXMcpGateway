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
if [ "${ROTATE_GW_TOKEN:-0}" != "1" ] && [ -f "$CFG.bak" ]; then
  GW_TOKEN="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["_gateway"]["token"])' "$CFG.bak" 2>/dev/null || true)"
  [ -n "$GW_TOKEN" ] && echo "  ✓ 기존 GW_TOKEN 보존 (${GW_TOKEN:0:8}…)"
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

echo "▶ 4) config 파일 작성"
GW_TOKEN="$GW_TOKEN" SF_MCP_TOKEN="$SF_MCP_TOKEN" SF_API_KEY="$SF_API_KEY" \
MXWP_MCP="$MXWP_MCP" MXWP_REST="$MXWP_REST" RAT_TOKEN="${RAT_TOKEN:-}" \
HEAX_MCP_TOKEN="${HEAX_MCP_TOKEN:-}" HEAX_MCP_SERVERS_URL="${HEAX_MCP_SERVERS_URL:-}" HEAX_MCP_BASE="${HEAX_MCP_BASE:-}" \
CFG="$CFG" AGENT_DIR="$AGENT_DIR" python3 - <<'PYEOF'
import json, os
e = os.environ
cfg = {"_gateway": {"host": "127.0.0.1", "port": 9110, "token": e["GW_TOKEN"]}}
if e.get("RAT_TOKEN"):
    cfg["reportarchive"] = {"url": "http://127.0.0.1:3002/mcp", "transport": "streamable_http",
        "headers": {"Authorization": f"Bearer {e['RAT_TOKEN']}", "X-Workspace-Slug": "dev"}}
# SF MCP 는 SF_MCP_TOKEN 미설정 시 무인증 모드로 돌므로 헤더 없이도 포함한다.
cfg["signalforge"] = {"url": "http://127.0.0.1:8013/mcp", "transport": "streamable_http"}
if e.get("SF_MCP_TOKEN"):
    cfg["signalforge"]["headers"] = {"Authorization": f"Bearer {e['SF_MCP_TOKEN']}"}
if e.get("MXWP_MCP"):
    cfg["mx-white-paper"] = {"url": "http://127.0.0.1:8765/mcp", "transport": "streamable_http",
        "headers": {"Authorization": f"Bearer {e['MXWP_MCP']}"}}
# AIDH MCP 는 api_server 에 내장(:8001/mcp, auth_required=false → 무인증) — 항상 포함.
cfg["ai-data-hub"] = {"url": "http://127.0.0.1:8001/mcp/", "transport": "streamable_http"}
rest = {"ai-data-hub": {"base": "http://127.0.0.1:8001"}}
if e.get("MXWP_REST"):
    rest["mx-white-paper"] = {"base": "http://127.0.0.1:8800",
        "inject": {"header": "Authorization", "value": f"Bearer {e['MXWP_REST']}"}}
if e.get("SF_API_KEY"):
    rest["signalforge"] = {"base": "http://127.0.0.1:17370",
        "inject": {"header": "X-API-Key", "value": e["SF_API_KEY"]}}
cfg["rest"] = rest
cfg["portal"] = {"jwks_url": "http://127.0.0.1:8723/.well-known/jwks.json",
                 "revoked_url": "http://127.0.0.1:8723/auth/pat/revoked.json",
                 "audience_ok": ["mx-white-paper", "ai-data-hub", "signalforge"]}
# heax-hub MCP 앱 자동탐지(옵션) — heax registry 를 폴링해 mcp:{expose} 앱을 heax-<id> 백엔드로 흡수.
#   token: HEAX_MCP_TOKEN env(heax 'MCP 토큰' 메뉴/PAT). 없으면 heax_registry 생략(그 기능만 빠짐).
#   servers_url/base: dev 기본 localhost. prod 은 HEAX_MCP_SERVERS_URL/HEAX_MCP_BASE(도메인)로 오버라이드.
if e.get("HEAX_MCP_TOKEN"):
    cfg["heax_registry"] = {
        "servers_url": e.get("HEAX_MCP_SERVERS_URL") or "http://127.0.0.1:4040/api/v1/mcp/servers",
        "base": e.get("HEAX_MCP_BASE") or "http://127.0.0.1:4180",
        "token": e["HEAX_MCP_TOKEN"]}
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
chmod 600 "$CFG" 2>/dev/null
chmod 600 "$AGENT_DIR/mcp_servers.json" 2>/dev/null   # GW_TOKEN 평문 — config와 동일하게 보호

echo "▶ 완료 — 게이트웨이 기동: (포털) ./infra/scripts/services.sh up mcp-gateway agent-server"
