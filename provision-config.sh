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

echo "▶ 1) GW_TOKEN 생성"
GW_TOKEN="$(openssl rand -hex 32)"

echo "▶ 2) SignalForge .env 에서 토큰 읽기"
SF_ENV="$PARENT/SignalForge/.env"
SF_MCP_TOKEN="$(grep -E '^SF_MCP_TOKEN=' "$SF_ENV" 2>/dev/null | head -1 | cut -d= -f2-)"
SF_API_KEY="$(grep -E '^API_KEY=' "$SF_ENV" 2>/dev/null | head -1 | cut -d= -f2-)"
[ -n "$SF_MCP_TOKEN" ] && echo "  ✓ SF_MCP_TOKEN (${SF_MCP_TOKEN:0:8}…)" || echo "  ⚠ SF_MCP_TOKEN 없음($SF_ENV) — signalforge MCP 백엔드 생략됨"
[ -n "$SF_API_KEY" ]   && echo "  ✓ API_KEY (${SF_API_KEY:0:6}…)"        || echo "  ⚠ API_KEY 없음 — signalforge REST inject 생략됨"

echo "▶ 3) mxwp 서비스 토큰 발급 (mxwp_api 인스턴스 안에서, 앱 코드로)"
mint_mxwp() {  # $1 = 토큰 이름 → stdout 평문 토큰
  apptainer exec instance://mxwp_api bash -lc "cd /workspace/apps/api && python3 - '$1'" <<'PYEOF' 2>/dev/null | tail -1
import asyncio, os, sys
sys.path.insert(0, ".")
from app.routers.api_tokens import _gen_token
from app.core.security import hash_password
name = sys.argv[1]
tok, prefix = _gen_token()
h = hash_password(tok)
dsn = (os.environ.get("DATABASE_URL") or
       "postgresql://mxwp:mxwp_dev_password_change_me@127.0.0.1:5532/mxwp"
       ).replace("postgresql+asyncpg://", "postgresql://")
async def main():
    import asyncpg
    conn = await asyncpg.connect(dsn)
    uid = (await conn.fetchval("select id from users where email='admin@mx.local'")
           or await conn.fetchval("select id from users limit 1"))
    await conn.execute(
        "insert into api_tokens (user_id, name, token_prefix, token_hash, scopes)"
        " values ($1, $2, $3, $4, '[\"read\", \"write\"]'::jsonb)",
        uid, name, prefix, h)
    await conn.close()
asyncio.run(main())
print(tok)
PYEOF
}
MXWP_MCP=""; MXWP_REST=""
if apptainer instance list 2>/dev/null | awk 'NR>1{print $1}' | grep -qx mxwp_api; then
  MXWP_MCP="$(mint_mxwp hwax-gateway-mcp)"
  MXWP_REST="$(mint_mxwp hwax-gateway-rest)"
  case "$MXWP_MCP" in mxwp_*) echo "  ✓ MCP용 (${MXWP_MCP:0:13}…)" ;; *) echo "  ⚠ 발급 실패: $MXWP_MCP"; MXWP_MCP="" ;; esac
  case "$MXWP_REST" in mxwp_*) echo "  ✓ REST용 (${MXWP_REST:0:13}…)" ;; *) MXWP_REST="" ;; esac
else
  echo "  ⚠ mxwp_api 인스턴스 없음 — mx-white-paper 백엔드 생략됨(뜬 뒤 --force 재실행)"
fi

echo "▶ 4) config 파일 작성"
GW_TOKEN="$GW_TOKEN" SF_MCP_TOKEN="$SF_MCP_TOKEN" SF_API_KEY="$SF_API_KEY" \
MXWP_MCP="$MXWP_MCP" MXWP_REST="$MXWP_REST" RAT_TOKEN="${RAT_TOKEN:-}" \
CFG="$CFG" AGENT_DIR="$AGENT_DIR" python3 - <<'PYEOF'
import json, os
e = os.environ
cfg = {"_gateway": {"host": "127.0.0.1", "port": 9110, "token": e["GW_TOKEN"]}}
if e.get("RAT_TOKEN"):
    cfg["reportarchive"] = {"url": "http://127.0.0.1:3002/mcp", "transport": "streamable_http",
        "headers": {"Authorization": f"Bearer {e['RAT_TOKEN']}", "X-Workspace-Slug": "dev"}}
if e.get("SF_MCP_TOKEN"):
    cfg["signalforge"] = {"url": "http://127.0.0.1:8013/mcp", "transport": "streamable_http",
        "headers": {"Authorization": f"Bearer {e['SF_MCP_TOKEN']}"}}
if e.get("MXWP_MCP"):
    cfg["mx-white-paper"] = {"url": "http://127.0.0.1:8765/mcp", "transport": "streamable_http",
        "headers": {"Authorization": f"Bearer {e['MXWP_MCP']}"}}
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

echo "▶ 완료 — 게이트웨이 기동: (포털) ./infra/scripts/services.sh up mcp-gateway agent-server"
