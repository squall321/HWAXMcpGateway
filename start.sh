#!/usr/bin/env bash
# HWAX MCP 게이트웨이를 에이전트 venv 파이썬으로 기동 (경로 하드코딩 금지 — 스크립트/형제 레포 기준).
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # .../HWAXMcpGateway
PARENT="$(dirname "$HERE")"                             # 형제 레포들이 있는 부모 디렉토리
PY="$PARENT/HWAXAgentServer/.venv/bin/python"           # 에이전트 venv(형제 레포)
[ -x "$PY" ] || PY="$(command -v python3)"              # 없으면 시스템 python3 로 폴백
exec "$PY" "$HERE/gateway.py"
