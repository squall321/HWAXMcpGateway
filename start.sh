#!/usr/bin/env bash
# HWAX MCP 게이트웨이를 에이전트 venv 파이썬으로 기동 (경로 하드코딩 금지 — 스크립트/형제 레포 기준).
#
#   ./start.sh                 # 포그라운드(오케스트레이터·systemd 가 쓰는 기본 — 동작 불변)
#   ./start.sh --bg            # 세션에서 분리해 백그라운드 기동(사람·에이전트가 손으로 띄울 때)
#   GATEWAY_PORT=9111 GATEWAY_CONFIG=/tmp/x.json ./start.sh   # 임시 실행 — 반드시 다른 포트로
#
# --bg 가 필요한 이유: 기본은 exec 포그라운드라 호출한 셸/세션이 끝나면 같이 죽는다. services.py 는
# start_new_session=True 로 분리해 주지만 손으로 ./start.sh 를 돌리면 그 보호가 없어, 세션이
# 끝날 때마다 게이트웨이가 사라졌다(운영 중 반복 발생). --bg 는 setsid 로 스스로 분리한다.
#
# 포트 선점 가드: 이미 그 포트를 누가 쓰고 있으면 정상 게이트웨이인지 확인해서
#   · 정상이면 아무것도 하지 않고 종료(중복 기동 방지)
#   · 남의 프로세스면 PID/커맨드를 찍고 실패 — 임시 repro 프로세스가 9110 을 점유한 채 돌던
#     사고를 조용히 덮지 않는다. 임시 실행은 GATEWAY_PORT 로 반드시 다른 포트를 쓸 것.
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # .../HWAXMcpGateway
PARENT="$(dirname "$HERE")"                             # 형제 레포들이 있는 부모 디렉토리
PY="$PARENT/HWAXAgentServer/.venv/bin/python"           # 에이전트 venv(형제 레포)
[ -x "$PY" ] || PY="$(command -v python3)"              # 없으면 시스템 python3 로 폴백

BG=0
[ "${1:-}" = "--bg" ] && BG=1

CONFIG="${GATEWAY_CONFIG:-$HERE/gateway_config.json}"
# 포트 결정: GATEWAY_PORT env > config 의 _gateway.port > 9110
if [ -n "${GATEWAY_PORT:-}" ]; then
  PORT="$GATEWAY_PORT"
else
  PORT="$("$PY" -c 'import json,sys
try: print(json.load(open(sys.argv[1]))["_gateway"].get("port",9110))
except Exception: print(9110)' "$CONFIG" 2>/dev/null || echo 9110)"
fi

# ── 포트 선점 확인 ────────────────────────────────────────────────────────────
if command -v ss >/dev/null 2>&1 && ss -tlnH "sport = :$PORT" 2>/dev/null | grep -q .; then
  if curl -sf -m 3 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
    echo "✓ 게이트웨이가 이미 :$PORT 에서 정상 동작 중 — 기동 생략(중복 방지)"
    exit 0
  fi
  OWNER="$(ss -tlnpH "sport = :$PORT" 2>/dev/null | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)"
  echo "✗ :$PORT 를 다른 프로세스가 점유 중입니다(헬스 응답 없음)." >&2
  [ -n "$OWNER" ] && echo "   pid=$OWNER  cmd: $(tr '\0' ' ' < "/proc/$OWNER/cmdline" 2>/dev/null | cut -c1-120)" >&2
  echo "   임시 실행이라면 다른 포트로:  GATEWAY_PORT=9111 GATEWAY_CONFIG=<임시cfg> ./start.sh" >&2
  exit 1
fi

if [ "$BG" = "1" ]; then
  LOG="${GATEWAY_LOG:-$HERE/gateway.log}"
  PIDF="${GATEWAY_PIDFILE:-$HERE/gateway.pid}"
  setsid "$PY" "$HERE/gateway.py" >>"$LOG" 2>&1 < /dev/null &   # 세션 분리 — --bg 의 핵심
  echo $! > "$PIDF"
  for _ in $(seq 1 60); do
    if curl -sf -m 2 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
      echo "✓ 게이트웨이 기동(백그라운드) :$PORT  pid=$(cat "$PIDF")  log=$LOG"
      exit 0
    fi
    sleep 1
  done
  echo "✗ 60s 안에 헬스 응답 없음 — 로그 확인: $LOG" >&2
  exit 1
fi

exec "$PY" "$HERE/gateway.py"
