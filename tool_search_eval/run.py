# search_tools 평가 러너 — 카탈로그 스냅샷을 뜨고, 평가셋으로 부분문자열 순위와 RRF 순위의 1위·5위 적중·MRR 을 견준다
"""쓰는 법 — 리포 루트에서, 게이트웨이와 같은 파이썬(에이전트 venv)으로.

  PY=../HWAXAgentServer/.venv/bin/python
  # 1) 떠 있는 게이트웨이에서 카탈로그를 뜬다. 토큰은 설정 파일의 _gateway.token 에서 읽는다(인자로 받지 않는다)
  $PY tool_search_eval/run.py snapshot --gateway http://127.0.0.1:9110 --config gateway_config.json
  # 2) 견준다 — 임베더 주소를 주면 RRF 와 임베딩 순위(진단)도 잰다. 빼면 부분문자열만
  $PY tool_search_eval/run.py eval --embed-url http://127.0.0.1:8001/api/embed [--detail]

순위는 게이트웨이 코드 그대로다 — 이 러너는 gateway 를 import 해 스냅샷을 카탈로그로 앉히고 `_search_tools`(limit 20)를
옵션을 끄고 한 번, 켜고 한 번 부른다. 그래서 MRR 은 20위까지만 센다(MRR@20 — 20위 밖은 0).
정답은 `앱키:원래 도구 이름` 이다 — 노출 이름은 남의 앱이 떠 있느냐에 따라 접두가 붙었다 떨어졌다 한다.
스냅샷(`*.local.json`)은 추적하지 않는다. 결과의 숫자와 방법은 README.md 에 적는다.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DEFAULT_PAIRS = HERE / "pairs.jsonl"
DEFAULT_CATALOG = HERE / "catalog.local.json"
LIMIT = 20                 # search_tools 의 limit 상한 — MRR 을 여기까지 센다
HITS = (1, 5)


def _original(name: str, app: str) -> str:
    """노출 이름에서 충돌 접두(`<앱키에서 하이픈 뺀 것>_`)를 떼어 원래 이름을 돌려준다(gateway._aggregate 와 같은 규칙)."""
    prefix = app.replace("-", "") + "_"
    return name[len(prefix):] if name.startswith(prefix) else name


async def _snapshot(args) -> None:
    import httpx
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    token = json.loads(Path(args.config).read_text(encoding="utf-8"))["_gateway"]["token"]
    base = args.gateway.rstrip("/")
    async with httpx.AsyncClient(timeout=30) as cli:
        tmap = (await cli.get(f"{base}/tools-map")).json()
    tools = []
    async with streamablehttp_client(f"{base}/mcp", headers={"Authorization": f"Bearer {token}"}) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            cursor = None
            while True:
                res = await (s.list_tools(cursor=cursor) if cursor else s.list_tools())
                tools += res.tools
                cursor = getattr(res, "nextCursor", None)
                if not cursor:
                    break
    owner = tmap.get("map") or {}
    rows, local = [], []
    for t in tools:
        app = owner.get(t.name, "_gateway")
        if app == "_gateway":            # 로컬 도구는 러너가 import 한 게이트웨이 코드가 낸다 — 이름만 남긴다
            local.append(t.name)
            continue
        rows.append({"name": t.name, "app": app, "original": _original(t.name, app),
                     "description": t.description or "", "inputSchema": t.inputSchema or {"type": "object"}})
    out = {"taken_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "gateway": base,
           "apps": {a["app"]: {"label": a.get("label") or "", "description": a.get("description") or "",
                               "reachable": a.get("reachable"), "tool_count": a.get("tool_count")}
                    for a in tmap.get("apps") or []},
           "local_tools": sorted(local), "tools": rows}
    Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    down = sorted(k for k, a in out["apps"].items() if not a["reachable"])
    print(f"스냅샷 — 백엔드 도구 {len(rows)}개 · 로컬 도구 {len(local)}개 → {args.out}"
          + (f" (닿지 않는 앱: {', '.join(down)})" if down else ""))


def _import_gateway(tmp: Path):
    """임시 설정으로 게이트웨이를 import 한다 — 백엔드·포털 없이 순위 코드만 쓴다. 옵션은 러너가 모듈 변수로 켜고 끈다."""
    cfg = tmp / "cfg.json"
    cfg.write_text(json.dumps({"_gateway": {"token": "tool-search-eval"}}), encoding="utf-8")
    os.environ["GATEWAY_CONFIG"] = str(cfg)
    os.environ["GATEWAY_AUDIT"] = str(tmp / "audit.jsonl")
    os.environ.pop("GATEWAY_TOOL_SEARCH_EMBED_URL", None)
    os.environ["GATEWAY_TOOL_QUERY_LOG"] = "0"          # 평가 질의를 실사용 질의 파일(queries.local.jsonl)에 섞지 않는다
    sys.path.insert(0, str(ROOT))
    for name in ("hwax-mcp-gateway", "httpx"):                           # import·요청마다의 안내 줄은 평가와 무관하다
        logging.getLogger(name).setLevel(logging.WARNING)
    import gateway as gw
    return gw


def _install(gw, cat: dict) -> dict:
    """스냅샷을 카탈로그로 앉힌다 — 돌려주는 것은 노출 이름 → 정답 열쇠(`앱키:원래 이름`)."""
    import mcp.types as types
    gw.exposed_tools[:] = [types.Tool(name=r["name"], description=r["description"], inputSchema=r["inputSchema"])
                           for r in cat["tools"]]
    gw.route.clear()
    gw.route.update({r["name"]: (r["app"], r["original"]) for r in cat["tools"]})
    gw.DISCOVERED_META.update({k: {"label": a["label"], "description": a["description"]}
                               for k, a in cat["apps"].items() if k != "_gateway"})
    # 라이브에 REST 다리(rest_catalog·rest_call)가 있었으면 로컬 도구에 같이 서게 한다(_local_tools 는 REST 가 비지 않을 때만 낸다)
    gw.REST = {"(eval)": {}} if any(n.startswith("rest_") for n in cat.get("local_tools") or []) else {}
    gw.POLICY = {}
    gw._ACCESS_POLICY = {}
    keys = {r["name"]: f'{r["app"]}:{r["original"]}' for r in cat["tools"]}
    keys.update({t.name: f"_gateway:{t.name}" for t in gw._local_tools()})
    return keys


def _rank(ranked: list[str], keys: dict, gold: list[str]) -> int | None:
    """정답 가운데 가장 앞선 것의 순위(1부터) — 20위 안에 없으면 None."""
    for i, name in enumerate(ranked, 1):
        if keys.get(name) in gold:
            return i
    return None


def _summary(ranks: list[int | None]) -> dict:
    n = len(ranks)
    if not n:
        return {"n": 0}
    out = {"n": n}
    for k in HITS:
        out[f"hit@{k}"] = sum(1 for r in ranks if r is not None and r <= k) / n
    out["mrr@20"] = sum(1 / r for r in ranks if r is not None) / n
    return out


def _pct(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p * (len(xs) - 1))))] if xs else 0.0


async def _eval(args) -> None:
    cat = json.loads(Path(args.catalog).read_text(encoding="utf-8"))
    pairs = [json.loads(line) for line in Path(args.pairs).read_text(encoding="utf-8").splitlines() if line.strip()]
    with tempfile.TemporaryDirectory() as tmp:
        gw = _import_gateway(Path(tmp))
        keys = _install(gw, cat)
        have = set(keys.values())
        live = [p for p in pairs if any(g in have for g in p["gold"])]
        gone = [p["id"] for p in pairs if p not in live]
        down = sorted(k for k, a in cat["apps"].items() if not a.get("reachable"))
        print(f"카탈로그 — {cat['taken_at']} · 백엔드 도구 {len(cat['tools'])}개 + 로컬 {len(gw._local_tools())}개"
              + (f" · 닿지 않던 앱 {', '.join(down)}" if down else ""))
        print(f"평가셋 — {len(pairs)}쌍 중 {len(live)}쌍을 잰다"
              + (f" · 정답 도구가 카탈로그에 없어 뺀 {len(gone)}쌍: {', '.join(gone)}" if gone else ""))

        ranks: dict[str, dict[str, int | None]] = {}
        ms: dict[str, list[float]] = {}
        fallback: list[str] = []
        diag_fail: list[str] = []

        async def run(method: str) -> None:
            ranks[method], ms[method] = {}, []
            for p in live:
                t0 = time.perf_counter()
                res = await gw._search_tools({"query": p["query"], "limit": LIMIT})
                ms[method].append((time.perf_counter() - t0) * 1000)
                body = json.loads(res.content[0].text) if not res.isError else {"ranked": []}
                if method == "rrf" and body.get("mode") != "rrf":
                    fallback.append(f'{p["id"]}({body.get("mode_reason")})')
                ranks[method][p["id"]] = _rank(body.get("ranked") or [], keys, p["gold"])

        gw.TOOL_SEARCH_EMBED_URL = ""
        await run("substring")
        methods = ["substring"]
        if args.embed_url:
            gw.TOOL_SEARCH_EMBED_URL = args.embed_url
            gw.TOOL_SEARCH_EMBED_TIMEOUT_S = args.embed_timeout
            t0 = time.perf_counter()
            await gw._tool_index_refresh()
            visible = gw._visible_tools([])
            missing = [t.name for t in visible if gw._doc_key(gw._tool_doc(t)) not in gw._TOOL_VEC]
            if missing:
                sys.exit(f"색인이 다 차지 않았다({len(missing)}개 빠짐) — 임베더 주소·로그를 본다")
            print(f"색인 — 도구 {len(visible)}개 임베딩 {time.perf_counter() - t0:.1f}초")
            await run("rrf")
            # 진단 — 임베딩 순위만. 질의 벡터는 RRF 때 받은 것을 다시 쓴다(임베더를 두 번 부르지 않는다)
            ranks["embedding"] = {}
            seen: dict[str, list] = {}
            real = gw._embed_texts

            async def memo(texts, kind, timeout_s):
                if kind != "query":
                    return await real(texts, kind, timeout_s)
                if texts[0] not in seen:
                    seen[texts[0]] = await real(texts, kind, timeout_s)
                return seen[texts[0]]
            gw._embed_texts = memo
            for p in live:
                order, why = await gw._tool_embed_order(p["query"], visible)
                if order is None:
                    diag_fail.append(f'{p["id"]}({why})')
                ranks["embedding"][p["id"]] = _rank([t.name for t in order[:LIMIT]], keys, p["gold"]) if order else None
            methods += ["rrf", "embedding"]

    groups = [("doc", [p for p in live if p["source"] == "doc"]), ("auto", [p for p in live if p["source"] == "auto"]),
              ("전체", live)]
    print()
    print(f"{'방법':<10} {'출처':<5} {'n':>4} {'hit@1':>7} {'hit@5':>7} {'MRR@20':>7}")
    for m in methods:
        for g, ps in groups:
            s = _summary([ranks[m][p["id"]] for p in ps])
            if s["n"]:
                print(f"{m:<10} {g:<5} {s['n']:>4} {s['hit@1']:>7.3f} {s['hit@5']:>7.3f} {s['mrr@20']:>7.3f}")
    if "rrf" in methods:
        print()
        print("쌍별 견주기(RRF 대 부분문자열 — 정답 순위가 앞서면 나아짐, 20위 밖은 21로 친다)")
        for g, ps in groups:
            a = [ranks["substring"][p["id"]] or LIMIT + 1 for p in ps]
            b = [ranks["rrf"][p["id"]] or LIMIT + 1 for p in ps]
            better = sum(1 for x, y in zip(a, b) if y < x)
            worse = sum(1 for x, y in zip(a, b) if y > x)
            print(f"  {g:<5} 나아짐 {better:>3} · 나빠짐 {worse:>3} · 같음 {len(ps) - better - worse:>3}")
        print()
        print("search_tools 한 번의 시간(ms) — 중앙 · p95 · 최대")
        for m in ("substring", "rrf"):
            print(f"  {m:<10} {statistics.median(ms[m]):>8.1f} {_pct(ms[m], 0.95):>8.1f} {max(ms[m]):>8.1f}")
        print(f"  RRF 가 부분문자열로 떨어진 질의 {len(fallback)}개" + (f": {', '.join(fallback)}" if fallback else ""))
        print(f"  임베딩 순위(진단)를 못 낸 질의 {len(diag_fail)}개" + (f": {', '.join(diag_fail)}" if diag_fail else ""))
    if args.detail:
        print()
        print("쌍별 순위(20위 밖은 -)")
        for p in live:
            cells = " ".join(f"{m}={ranks[m][p['id']] or '-'}" for m in methods)
            print(f"  {p['id']:<10} {p['source']:<4} {cells}  {p['query']}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snapshot", help="떠 있는 게이트웨이에서 카탈로그를 뜬다")
    s.add_argument("--gateway", default="http://127.0.0.1:9110")
    s.add_argument("--config", default=str(ROOT / "gateway_config.json"), help="_gateway.token 을 읽을 설정 파일")
    s.add_argument("--out", default=str(DEFAULT_CATALOG))
    e = sub.add_parser("eval", help="평가셋으로 견준다")
    e.add_argument("--catalog", default=str(DEFAULT_CATALOG))
    e.add_argument("--pairs", default=str(DEFAULT_PAIRS))
    e.add_argument("--embed-url", default="", help="AIDataHub /api/embed — 주면 RRF·임베딩 순위도 잰다")
    e.add_argument("--embed-timeout", type=float, default=30.0,
                   help="잴 때의 질의 임베딩 한도(초) — 방법을 재는 것이라 넉넉히 둔다. 시간은 따로 찍는다")
    e.add_argument("--detail", action="store_true", help="쌍마다 방법별 순위를 찍는다")
    args = ap.parse_args()
    asyncio.run(_snapshot(args) if args.cmd == "snapshot" else _eval(args))


if __name__ == "__main__":
    main()
