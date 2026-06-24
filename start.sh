#!/usr/bin/env bash
# HWAX MCP 게이트웨이를 에이전트 venv 파이썬으로 기동
set -e
PY=/home/koopark/claude/HWAXAgentServer/.venv/bin/python
exec "$PY" /home/koopark/claude/HWAXMcpGateway/gateway.py
