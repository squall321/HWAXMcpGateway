#!/usr/bin/env bash
# gateway_config.json.bak 에서 provision.env 에 필요한 값을 뽑아 채운다.
#
# --force 재프로비저닝은 RAT_TOKEN 같은 env 가 없으면 그 백엔드를 통째로 빼 버린다.
# 그런데 직전까지 쓰던 값은 .bak 에 그대로 남아 있으므로, 새로 발급받을 필요 없이 여기서 복원한다.
#
#   bash sync-provision-env.sh          # 무엇이 추가될지만 보여준다(파일 안 건드림)
#   bash sync-provision-env.sh --write  # provision.env 에 실제로 추가(이미 있는 키는 건너뜀)
#
# 뽑는 것: RAT_TOKEN, RA_WORKSPACE_SLUG(dev 가 아닐 때만),
#          그리고 localhost 가 아닌 백엔드 주소들(= 손으로 원격 배치를 잡아둔 것).
# localhost 기본값은 일부러 안 넣는다 — 프로비저너가 같은 값을 만들어내므로 관리 지점만 늘어난다.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
[ -f gateway_config.json ] || [ -f gateway_config.json.bak ] \
  || { echo "✗ gateway_config.json / .bak 둘 다 없음 — --force 를 한 번 돌린 뒤에 쓴다" >&2; exit 1; }

OUT="$(python3 - <<'PY'
import json, os, re, sys
ENV = "provision.env"
# 정본은 '지금 돌고 있는' gateway_config.json 이다. .bak 은 직전 프로비저닝 시점이라
# 그 뒤에 손으로 붙인 백엔드가 없다. cae00 에서 실제로 이것 때문에 사고가 났다 —
# .bak 이 오래돼 reportarchive·odb-hub 가 없었고, 이 스크립트가 "추가할 것 없음" 이라고
# 답한 뒤 --force 가 두 백엔드(도구 24개+)를 그대로 떨궜다(2026-08-12).
# live 를 먼저 읽고 .bak 으로 빈 곳만 메운다.
d = {}
for path in ("gateway_config.json.bak", "gateway_config.json"):   # 뒤가 이긴다
    try:
        with open(path) as f:
            for k, v in json.load(f).items():
                if v:
                    d[k] = v
    except Exception:
        pass
have = set()
if os.path.exists(ENV):
    have = {m.group(1) for l in open(ENV) if (m := re.match(r'\s*([A-Za-z_][A-Za-z0-9_]*)=', l))}
out = []
h = ((d.get("reportarchive") or {}).get("headers") or {})
tok = (h.get("Authorization") or "").replace("Bearer ", "").strip()
if tok: out.append(("RAT_TOKEN", tok))
slug = h.get("X-Workspace-Slug")
if slug and slug != "dev": out.append(("RA_WORKSPACE_SLUG", slug))
def remote(v): return v and not re.search(r'//(127\.0\.0\.1|localhost)[:/]', v)
for ek, k in (("RA_MCP_URL","reportarchive"),("SF_MCP_URL","signalforge"),
              ("MXWP_MCP_URL","mx-white-paper"),("AIDH_MCP_URL","ai-data-hub")):
    v = (d.get(k) or {}).get("url")
    if remote(v): out.append((ek, v))
for ek, k in (("AIDH_REST_BASE","ai-data-hub"),("MXWP_REST_BASE","mx-white-paper"),("SF_REST_BASE","signalforge")):
    v = ((d.get("rest") or {}).get(k) or {}).get("base")
    if remote(v): out.append((ek, v))
# odb-hub 는 토큰이 URL 쿼리에 들어간다 — 여기서 안 뽑으면 --force 마다 이 백엔드가 사라진다.
odb = (d.get("odb-hub") or {}).get("url") or ""
if odb:
    m = re.search(r'[?&]token=([^&]+)', odb)
    if m: out.append(("ODB_HUB_TOKEN", m.group(1)))
    b = re.match(r'(https?://[^/]+)', odb)
    if b: out.append(("ODB_HUB_BASE", b.group(1)))
for k, v in out:
    if k not in have: print(f"{k}={v}")
    else: print(f"# 이미 있음(건너뜀): {k}", file=sys.stderr)
PY
)"

if [ -z "$OUT" ]; then echo "· 추가할 것 없음 — provision.env 가 이미 충분하다"; exit 0; fi

if [ "${1:-}" = "--write" ]; then
  printf '%s\n' "$OUT" >> provision.env
  chmod 600 provision.env
  echo "✓ provision.env 에 $(printf '%s\n' "$OUT" | grep -c '=') 개 추가 (chmod 600)"
  printf '%s\n' "$OUT" | sed -E 's/=(.*)/=…(값 생략)/' | sed 's/^/    /'
  echo "  다음: bash provision-config.sh --force  (또는 update-all 이 §5 에서 알아서 건다)"
else
  echo "· 추가될 키(값은 가림) — 실제 반영은 --write:"
  printf '%s\n' "$OUT" | sed -E 's/=(.*)/=…(값 생략)/' | sed 's/^/    /'
fi
