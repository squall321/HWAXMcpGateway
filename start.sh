#!/usr/bin/env bash
# HWAX MCP 게이트웨이를 에이전트 venv 파이썬으로 기동 (경로 하드코딩 금지 — 스크립트/형제 레포 기준).
#
#   ./start.sh                 # 포그라운드(오케스트레이터·systemd 가 쓰는 기본 — 동작 불변)
#   ./start.sh --bg            # 세션에서 분리해 백그라운드 기동(사람·에이전트가 손으로 띄울 때)
#   ./start.sh restart        # 포트 점유자를 정확히 내리고 새로 띄움(pid 파일 불신)
#   ./start.sh stop            # 내리기만
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
STOP=0
case "${1:-}" in
  --bg) BG=1 ;;
  # restart/stop — pid 파일이 아니라 **포트 점유자**를 죽인다. pid 파일은 --bg 로 띄운
  # 회차만 정확하고, update-all/services 가 띄운 게이트웨이와는 어긋난다 — 그 상태에서
  # `kill $(cat gateway.pid)` 는 허공을 치고, 포트 가드가 "이미 응답 중" 으로 기동을
  # 생략해 옛 코드가 계속 돈다(cae00 실사고 2026-09-03).
  restart) BG=1; STOP=1 ;;
  stop) STOP=2 ;;
esac

CONFIG="${GATEWAY_CONFIG:-$HERE/gateway_config.json}"
# 포트 결정: GATEWAY_PORT env > config 의 _gateway.port > 9110
if [ -n "${GATEWAY_PORT:-}" ]; then
  PORT="$GATEWAY_PORT"
else
  PORT="$("$PY" -c 'import json,sys
try: print(json.load(open(sys.argv[1]))["_gateway"].get("port",9110))
except Exception: print(9110)' "$CONFIG" 2>/dev/null || echo 9110)"
fi

# ── stop / restart — 포트 점유자를 정확히 내린다 ─────────────────────────────
if [ "$STOP" != "0" ]; then
  OWNER="$(ss -tlnpH "sport = :$PORT" 2>/dev/null | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)"
  if [ -n "$OWNER" ]; then
    OWNER_CMD="$(tr '\0' ' ' < "/proc/$OWNER/cmdline" 2>/dev/null || true)"
    case "$OWNER_CMD" in
      *gateway.py*)
        echo "· :$PORT 게이트웨이 종료 (pid=$OWNER)"
        kill "$OWNER" 2>/dev/null || true
        for _ in $(seq 1 20); do
          ss -tlnH "sport = :$PORT" 2>/dev/null | grep -q . || break
          sleep 0.5
        done
        ss -tlnH "sport = :$PORT" 2>/dev/null | grep -q . && { kill -9 "$OWNER" 2>/dev/null || true; sleep 1; }
        ;;
      *)
        echo "✗ :$PORT 점유자가 게이트웨이가 아니다 — 손대지 않는다 (pid=$OWNER, cmd: $(printf '%s' "$OWNER_CMD" | cut -c1-100))" >&2
        exit 1
        ;;
    esac
  else
    echo "· :$PORT 에 떠 있는 게이트웨이 없음"
  fi
  [ "$STOP" = "2" ] && exit 0
fi

# ── 포트 선점 확인 ────────────────────────────────────────────────────────────
if command -v ss >/dev/null 2>&1 && ss -tlnH "sport = :$PORT" 2>/dev/null | grep -q .; then
  # 상태코드만 보면 안 된다 — /health 의 "status" 는 리터럴 "ok" 라 백엔드가 전멸하고
  # 도구가 0개여도 200 이 나온다(gateway.py:702). 그래서 '도구 0개짜리 좀비'가 정상으로
  # 판정돼 기동이 생략되고, 화면엔 초록 ✓ 만 찍혀 사람이 문제를 못 봤다.
  # 그렇다고 재기동 트리거로 바꾸면 안 된다 — tools=0 은 부팅 직후·백엔드 바운스 중의
  # 정상 과도 상태이고 _revive_loop(60s)가 고친다. 강제 재기동을 걸면 둘이 싸운다.
  # 기동 생략은 유지하되, 본문을 읽어 실제 상태를 함께 찍는다.
  GW_H="$(curl -sf -m 3 "http://127.0.0.1:$PORT/health" 2>/dev/null)" || GW_H=""
  if [ -n "$GW_H" ]; then
    GW_SUM="$(printf '%s' "$GW_H" | "$PY" -c 'import json,sys
try:
    h = json.load(sys.stdin)
    b = h.get("backends") or {}
    down = sorted(k for k, v in b.items() if not v)
    t = h.get("tools", 0)
    msg = f"도구 {t}개 / 백엔드 {len(b)}개"
    if down: msg += " / DOWN: " + ", ".join(down)
    if t == 0: msg += "  ← 도구 0개다. 부팅 직후면 60초 내 revive 로 채워진다."
    print(msg)
except Exception:
    print("본문 해석 실패")' 2>/dev/null || echo "본문 해석 실패")"
    echo "✓ 게이트웨이가 이미 :$PORT 에서 응답 중 — 기동 생략(중복 방지)  [$GW_SUM]"
    exit 0
  fi
  OWNER="$(ss -tlnpH "sport = :$PORT" 2>/dev/null | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)"
  OWNER_CMD="$(tr '\0' ' ' < "/proc/${OWNER:-0}/cmdline" 2>/dev/null || true)"
  case "$OWNER_CMD" in
    *gateway.py*)
      # 우리 게이트웨이가 포트를 물고 있는데 헬스가 죽었다 = 먹통. 여기서 거부하면
      # update-all 5단계의 자동 복구(services.sh up)가 막혀 되살릴 방법이 없어진다.
      # 그래서 정리하고 새로 띄운다 — 이게 치유 경로다.
      echo "· :$PORT 의 게이트웨이가 응답 불능 — 정리 후 재기동 (pid=$OWNER)"
      kill "$OWNER" 2>/dev/null || true
      for _ in $(seq 1 20); do
        ss -tlnH "sport = :$PORT" 2>/dev/null | grep -q . || break
        sleep 0.5
      done
      if ss -tlnH "sport = :$PORT" 2>/dev/null | grep -q .; then
        kill -9 "$OWNER" 2>/dev/null || true
        sleep 1
      fi
      ;;
    *)
      echo "✗ :$PORT 를 다른 프로세스가 점유 중입니다(헬스 응답 없음)." >&2
      [ -n "$OWNER" ] && echo "   pid=$OWNER  cmd: $(printf '%s' "$OWNER_CMD" | cut -c1-120)" >&2
      echo "   임시 실행이라면 다른 포트로:  GATEWAY_PORT=9111 GATEWAY_CONFIG=<임시cfg> ./start.sh" >&2
      exit 1
      ;;
  esac
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
