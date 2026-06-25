# 3개 백엔드 MCP를 집계해 단일 streamable-http 엔드포인트로 재노출하는 게이트웨이
import json
import logging
import os
import time
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import anyio
import uvicorn
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("hwax-mcp-gateway")

CONFIG_PATH = os.environ.get("GATEWAY_CONFIG", str(Path(__file__).with_name("gateway_config.json")))


def _load_config():
    with open(CONFIG_PATH, "r") as f:
        cfg = json.load(f)
    gw = cfg.pop("_gateway")
    backends = {k: v for k, v in cfg.items() if isinstance(v, dict) and "url" in v}
    return gw, backends


GW, BACKENDS = _load_config()
GW_TOKEN = GW["token"]
HOST = GW.get("host", "127.0.0.1")
PORT = int(GW.get("port", 9110))
AUDIT_PATH = os.environ.get("GATEWAY_AUDIT", str(Path(__file__).with_name("audit.jsonl")))


def _audit(tool, backend, ok, err, ms):
    """도구 호출 1건을 JSONL 감사 로그에 append (감사 실패가 호출을 막지 않게)."""
    try:
        rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "tool": tool, "backend": backend, "ok": ok, "ms": ms}
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

    async def reconnect(self, tg):
        """call 시 세션이 죽었으면 새 태스크로 1회 재연결."""
        self._stop.set()
        self.session = None
        self._ready = anyio.Event()
        self._stop = anyio.Event()
        self._failed = None
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


@asynccontextmanager
async def _backends_lifespan():
    """백엔드 영속 세션 + 도구 집계. streamable_http_app 의 세션매니저 lifespan 과 함께 돈다."""
    async with anyio.create_task_group() as tg:
        _task_group_holder["tg"] = tg
        for key, spec in BACKENDS.items():
            b = _Backend(key, spec["url"], spec.get("headers"))
            backends[key] = b
            await tg.start(b.run)
        await _aggregate()
        try:
            yield
        finally:
            for b in backends.values():
                b._stop.set()
            tg.cancel_scope.cancel()


fm = FastMCP("hwax-mcp-gateway")
_low = fm._mcp_server


@_low.list_tools()
async def _list_tools():
    return list(exposed_tools)


@_low.call_tool(validate_input=False)
async def _call_tool(name: str, arguments: dict):
    t0 = time.monotonic()
    if name not in route:
        _audit(name, None, False, "unknown tool", 0)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"unknown tool: {name}")],
            isError=True,
        )
    backend_key, original = route[name]
    b = backends[backend_key]
    try:
        if b.session is None:
            raise RuntimeError("backend session down")
        res = await b.session.call_tool(original, arguments)
        _audit(name, backend_key, not getattr(res, "isError", False), None,
               round((time.monotonic() - t0) * 1000))
        return res
    except Exception as e:  # noqa: BLE001
        log.warning("call %s on %s failed (%r), reconnecting once", name, backend_key, e)
        tg = _task_group_holder.get("tg")
        if tg is not None:
            await b.reconnect(tg)
            await b._ready.wait()
            if b.session is not None:
                res = await b.session.call_tool(original, arguments)
                _audit(name, backend_key, not getattr(res, "isError", False), "reconnected",
                       round((time.monotonic() - t0) * 1000))
                return res
        _audit(name, backend_key, False, repr(e), round((time.monotonic() - t0) * 1000))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"backend {backend_key} unavailable: {e!r}")],
            isError=True,
        )


def _bearer_gate(app):
    """순수 ASGI 미들웨어: Authorization: Bearer <GW_TOKEN> 검사 (streamable-http 응답버퍼링 회피)."""
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
            }).encode()
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": body})
            return
        headers = dict(scope.get("headers") or [])
        auth = headers.get(b"authorization", b"").decode("latin-1")
        if auth != expected:
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
        await app(scope, receive, send)

    return middleware


def main():
    star = fm.streamable_http_app()
    # streamable_http_app 의 lifespan 은 세션매니저 run() 만 돈다. 백엔드 집계 lifespan 을 함께 묶는다.
    sm_lifespan = star.router.lifespan_context

    @asynccontextmanager
    async def _combined(app):
        async with _backends_lifespan():
            async with sm_lifespan(app):
                yield

    star.router.lifespan_context = _combined
    app = _bearer_gate(star)
    log.info("starting hwax-mcp-gateway on %s:%d (path /mcp), %d backends", HOST, PORT, len(BACKENDS))
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")


if __name__ == "__main__":
    main()
