# search_tools 평가 러너 — 카탈로그 스냅샷을 뜨고, 평가셋으로 부분문자열 순위와 RRF 순위의 1위·5위 적중·MRR 을 견준다
"""쓰는 법 — 리포 루트에서, 게이트웨이와 같은 파이썬(에이전트 venv)으로.

  PY=../HWAXAgentServer/.venv/bin/python
  # 1) 떠 있는 게이트웨이에서 카탈로그를 뜬다. 토큰은 설정 파일의 _gateway.token 에서 읽는다(인자로 받지 않는다)
  $PY tool_search_eval/run.py snapshot --gateway http://127.0.0.1:9110 --config gateway_config.json
  # 2) 견준다 — 임베더 주소를 주면 RRF 와 임베딩 순위(진단)도 잰다. 빼면 부분문자열만
  $PY tool_search_eval/run.py eval --embed-url http://127.0.0.1:8001/api/embed [--detail]
  # 3) 박스에서 바로 — 떠 있는 게이트웨이의 /search-eval 을 부른다(스냅샷 없이). 정답쌍은 추적(pairs.jsonl) + 박스 표시
  #    (pairs.local.jsonl), 손잡이는 덧씌운 값 · 기본값 · 보정 끔 · 묶음 하나씩 끔. 부분문자열 순위만 잰다(HWAXPortal docs/request-1029 E-9)
  $PY tool_search_eval/run.py live --gateway http://127.0.0.1:9110 --config gateway_config.json [--detail]
  # 4) 목적 표 대조용 이름표를 스냅샷에서 다시 뜬다(설명 · 스키마 없이 이름만 — 추적 파일 purpose_catalog.json, HWAXPortal docs/mcp-modernize M3)
  $PY tool_search_eval/run.py names --catalog tool_search_eval/catalog.local.json

eval 은 목적 층(검색 손잡이 purpose_boost · app_entry_first — tool_purposes.json)을 끈 판과 켠 판(기본)을 함께 재고 쌍별로 견준다. 출처가 purpose 인 쌍은
purpose@1(답의 purpose 가 그 목적인가), app 칸이 있는 쌍(he · appentry)은 app@1(첫 줄이 그 앱 도구인가)도 센다.

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
                     "description": t.description or "", "inputSchema": t.inputSchema or {"type": "object"},
                     # 표지 — 쓰기 감점이 읽기 · 쓰기 한 판정(앱 표지 먼저)을 본다(HWAXPortal docs/mcp-modernize M2). tools/list 사본의 표지다
                     **({"annotations": t.annotations.model_dump(exclude_none=True)} if getattr(t, "annotations", None) else {})})
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
    os.environ["GATEWAY_ADOPTION_LEDGER"] = "0"         # 평가는 채택 셈 원장에 쓰지 않는다
    sys.path.insert(0, str(ROOT))
    for name in ("hwax-mcp-gateway", "httpx"):                           # import·요청마다의 안내 줄은 평가와 무관하다
        logging.getLogger(name).setLevel(logging.WARNING)
    import gateway as gw
    # 박스 덧씌우기는 평가에 섞지 않는다 — 추적하는 기본값(손잡이 · 읽기 목록 · 목적 표)만 잰다(박스 값은 live 가 잰다)
    for attr in ("SEARCH_TUNING_LOCAL_PATH", "READ_TOOLS_LOCAL_PATH", "TOOL_PURPOSES_LOCAL_PATH"):
        if hasattr(gw, attr):
            setattr(gw, attr, tmp / f"{attr.lower()}.none.json")
    return gw


def _install(gw, cat: dict) -> dict:
    """스냅샷을 카탈로그로 앉힌다 — 돌려주는 것은 노출 이름 → 정답 열쇠(`앱키:원래 이름`)."""
    import mcp.types as types
    gw.exposed_tools[:] = [types.Tool(name=r["name"], description=r["description"], inputSchema=r["inputSchema"],
                                      **({"annotations": types.ToolAnnotations(**r["annotations"])} if r.get("annotations") else {}))
                           for r in cat["tools"]]                         # 표지가 없는 옛 스냅숏은 이름 꼴 · 읽기 목록으로만 가른다
    gw.route.clear()
    gw.route.update({r["name"]: (r["app"], r["original"]) for r in cat["tools"]})
    gw.DISCOVERED_META.update({k: {"label": a["label"], "description": a["description"]}
                               for k, a in cat["apps"].items() if k != "_gateway"})
    # 라이브에 REST 다리(rest_catalog·rest_call)가 있었으면 로컬 도구에 같이 서게 한다(_local_tools 는 REST 가 비지 않을 때만 낸다)
    gw.REST = {"(eval)": {}} if any(n.startswith("rest_") for n in cat.get("local_tools") or []) else {}
    if gw.REST and "artifact_to_ste_upload" in (cat.get("local_tools") or []):
        gw.REST[gw.STE_UPLOAD_SITE] = {}                                 # ste 사람별 REST 가 있던 박스 — 그 로컬 도구(P-1)도 서게 한다
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


def _summary(ranks: list[int | None], purpose_ok: list[bool] | None = None, app_ok: list[bool] | None = None) -> dict:
    """hit@1 · hit@5 · MRR@20 — purpose_ok(목적 쌍마다 답의 purpose 가 맞았나) · app_ok(첫 줄이 기대한 앱인가)를 주면 purpose@1 · app@1 도."""
    n = len(ranks)
    if not n:
        return {"n": 0}
    out = {"n": n}
    for k in HITS:
        out[f"hit@{k}"] = sum(1 for r in ranks if r is not None and r <= k) / n
    out["mrr@20"] = sum(1 / r for r in ranks if r is not None) / n
    if purpose_ok:
        out["purpose@1"] = sum(purpose_ok) / len(purpose_ok)
    if app_ok:
        out["app@1"] = sum(app_ok) / len(app_ok)
    return out


def _group(p: dict) -> str:
    """쌍의 무리 — doc · auto · onto(코어 · 앱 이름 — doc 가운데 id 가 onto-) · purpose · appentry · he · box."""
    return "onto" if p.get("source") == "doc" and str(p.get("id", "")).startswith("onto-") else str(p.get("source") or "?")


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
        purp: dict[str, dict[str, str | None]] = {}
        app1: dict[str, dict[str, str | None]] = {}
        ms: dict[str, list[float]] = {}
        fallback: list[str] = []
        diag_fail: list[str] = []
        base = gw._tuning()
        # 목적 층을 끈 판(HWAXPortal docs/mcp-modernize M3) — 검색 손잡이 purpose_boost · app_entry_first 를 끈다. 끄면 순위가 목적 층 이전과 바이트까지 같다
        no_purpose = {**base, "switches": {**base["switches"], "purpose_boost": False, "app_entry_first": False}}

        async def run(method: str, tuning: dict | None = None) -> None:
            ranks[method], purp[method], app1[method], ms[method] = {}, {}, {}, []
            for p in live:
                t0 = time.perf_counter()
                res = await gw._search_tools({"query": p["query"], "limit": LIMIT}, groups=[gw.SERVICE_GROUP], tuning=tuning, log_query=False)
                ms[method].append((time.perf_counter() - t0) * 1000)
                body = json.loads(res.content[0].text) if not res.isError else {"ranked": []}
                if method == "rrf" and body.get("mode") != "rrf":
                    fallback.append(f'{p["id"]}({body.get("mode_reason")})')
                ranked = body.get("ranked") or []
                ranks[method][p["id"]] = _rank(ranked, keys, p["gold"])
                purp[method][p["id"]] = (body.get("purpose") or {}).get("key")
                app1[method][p["id"]] = keys.get(ranked[0], ":").split(":")[0] if ranked else None

        gw.TOOL_SEARCH_EMBED_URL = ""
        await run("substring")
        await run("no-purpose", no_purpose)
        methods = ["substring", "no-purpose"]
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

    order = ["doc", "auto", "onto", "purpose", "appentry", "he", "box"]
    seen = {_group(p) for p in live}
    groups = [(g, [p for p in live if _group(p) == g]) for g in order + sorted(seen - set(order)) if g in seen] + [("전체", live)]
    print()
    print(f"{'방법':<10} {'출처':<8} {'n':>4} {'hit@1':>7} {'hit@5':>7} {'MRR@20':>7} {'purpose@1':>10} {'app@1':>7}")
    for m in methods:
        for g, ps in groups:
            s = _summary([ranks[m][p["id"]] for p in ps], [purp[m][p["id"]] == p["purpose"] for p in ps if p.get("purpose")],
                         [app1[m][p["id"]] == p["app"] for p in ps if p.get("app")])
            if s["n"]:
                pu = f"{s['purpose@1']:>10.3f}" if "purpose@1" in s else f"{'':>10}"
                ap = f"{s['app@1']:>7.3f}" if "app@1" in s else f"{'':>7}"
                print(f"{m:<10} {g:<8} {s['n']:>4} {s['hit@1']:>7.3f} {s['hit@5']:>7.3f} {s['mrr@20']:>7.3f} {pu} {ap}")
    print()
    print("목적 층 견주기(켬 = 기본 대 끔 — 정답 순위가 앞서면 나아짐, 20위 밖은 21로 친다). 받아들이는 기준은 doc · auto · onto 의 나빠짐 0 이다")
    for g, ps in groups:
        a = [ranks["no-purpose"][p["id"]] or LIMIT + 1 for p in ps]
        b = [ranks["substring"][p["id"]] or LIMIT + 1 for p in ps]
        better = sum(1 for x, y in zip(a, b) if y < x)
        worse = sum(1 for x, y in zip(a, b) if y > x)
        print(f"  {g:<8} 나아짐 {better:>3} · 나빠짐 {worse:>3} · 같음 {len(ps) - better - worse:>3}")
    for p in live:
        if _group(p) in ("doc", "auto", "onto") and (ranks["substring"][p["id"]] or LIMIT + 1) > (ranks["no-purpose"][p["id"]] or LIMIT + 1):
            print(f"    나빠짐 {p['id']}: {ranks['no-purpose'][p['id']] or '-'} → {ranks['substring'][p['id']] or '-'}  {p['query']}")
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
            extra = f" purpose={purp['substring'][p['id']]}" if p.get("purpose") else ""
            print(f"  {p['id']:<10} {p['source']:<4} {cells}{extra}  {p['query']}")


async def _live(args) -> None:
    import httpx
    token = json.loads(Path(args.config).read_text(encoding="utf-8"))["_gateway"]["token"]
    base = args.gateway.rstrip("/")
    async with httpx.AsyncClient(timeout=args.timeout) as cli:
        r = await cli.post(f"{base}/search-eval", headers={"Authorization": f"Bearer {token}"}, json={})
    if r.status_code != 200:
        sys.exit(f"/search-eval {r.status_code} — {r.text[:300]}")
    d = r.json()
    pc = d["pairs"]
    print(f"손잡이 지문 — 덧씌운 값 {d['fingerprint']} · 기본값 {d['base']}"
          + (" (덧씌우기 없음)" if d["fingerprint"] == d["base"] else ""))
    print(f"정답쌍 — {pc['total']}쌍 중 {pc['measured']}쌍을 잰다"
          + (f" · 정답 도구가 지금 카탈로그에 없어 뺀 {pc['missing_gold']}쌍" if pc["missing_gold"] else "")
          + " · " + " · ".join(f"{g} {pc[g]}" for g in ("doc", "auto", "box", "purpose", "appentry", "he") if g in pc) + f" · {d['seconds']}초")
    print()
    print(f"{'판':<16} {'출처':<8} {'n':>4} {'hit@1':>7} {'hit@5':>7} {'MRR@20':>7} {'purpose@1':>10} {'app@1':>7}")
    for name, by in d["variants"].items():
        for g, s in by.items():
            if s.get("n"):
                pu = f"{s['purpose@1']:>10.3f}" if "purpose@1" in s else f"{'':>10}"
                ap = f"{s['app@1']:>7.3f}" if "app@1" in s else f"{'':>7}"
                print(f"{name:<16} {g:<8} {s['n']:>4} {s['hit@1']:>7.3f} {s['hit@5']:>7.3f} {s['mrr@20']:>7.3f} {pu} {ap}")
    print()
    print(f"판마다 정답 순위가 다른 쌍 {d['changed_count']}개(덧씌운 값 · 기본값 · 보정 끔 — 20위 밖은 -)"
          + ("" if args.detail or not d["changed_count"] else " — 쌍별은 --detail"))
    if args.detail:
        for c in d["changed"]:
            cells = " ".join(f"{k}={c[k] or '-'}" for k in ("effective", "base", "off"))
            print(f"  {c['id']:<16} {c.get('source') or '':<4} {cells}  {c['query']}")
        if d["changed_count"] > len(d["changed"]):
            print(f"  … 그 밖 {d['changed_count'] - len(d['changed'])}개(창구는 앞의 {len(d['changed'])}개만 싣는다)")


def _names(args) -> None:
    """스냅샷 → 목적 표 대조용 이름표(purpose_catalog.json) — 백엔드마다 원래 이름 · 로컬 도구 이름만(설명 · 스키마 없음). expected_missing(앱 새 판의
    도구)은 지금 이름표의 것을 그대로 둔다 — 그 판이 붙으면 손으로 걷는다."""
    cat = json.loads(Path(args.catalog).read_text(encoding="utf-8"))
    out = Path(args.out)
    old = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
    tools: dict[str, list[str]] = {}
    for r in cat["tools"]:
        tools.setdefault(r["app"], []).append(r["original"])
    new = {"_doc": old.get("_doc") or ["목적 표(tool_purposes.json)의 단계 이름을 대조하는 카탈로그 이름표 — run.py names 가 짓는다."],
           "taken_at": cat.get("taken_at"), "tools": {k: sorted(v) for k, v in sorted(tools.items())},
           "local_tools": sorted(cat.get("local_tools") or []), "expected_missing": old.get("expected_missing") or {}}
    out.write_text(json.dumps(new, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"이름표 — 백엔드 {len(new['tools'])}개 · 도구 {sum(map(len, new['tools'].values()))}개 · 로컬 {len(new['local_tools'])}개 → {out}")


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
    v = sub.add_parser("live", help="떠 있는 게이트웨이의 /search-eval 로 박스에서 잰다(스냅샷 없이)")
    v.add_argument("--gateway", default="http://127.0.0.1:9110")
    v.add_argument("--config", default=str(ROOT / "gateway_config.json"), help="_gateway.token 을 읽을 설정 파일")
    v.add_argument("--timeout", type=float, default=600.0, help="평가 한 번의 한도(초) — 판이 아홉이라 쌍 수만큼 걸린다")
    v.add_argument("--detail", action="store_true", help="판마다 정답 순위가 다른 쌍을 찍는다")
    n = sub.add_parser("names", help="스냅샷에서 목적 표 대조용 이름표(purpose_catalog.json)를 다시 뜬다")
    n.add_argument("--catalog", default=str(DEFAULT_CATALOG))
    n.add_argument("--out", default=str(HERE / "purpose_catalog.json"))
    args = ap.parse_args()
    if args.cmd == "names":
        _names(args)
        return
    asyncio.run({"snapshot": _snapshot, "eval": _eval, "live": _live}[args.cmd](args))


if __name__ == "__main__":
    main()
