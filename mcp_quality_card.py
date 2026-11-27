# 앱별 MCP 품질 카드 — 떠 있는 게이트웨이의 카탈로그와 감사 원장을 앱마다 한 줄로 잰다(읽기만, dev · cae00 같은 꼴)
"""앱별 MCP 품질 카드(HWAXPortal docs/mcp-modernize M0 · 받은 편지함 점검 MQ-1 · MQ-2).

게이트웨이 리포 루트에서 돈다. 쓰는 것 · 바꾸는 것 · 재기동하는 것이 없다.

    python3 mcp_quality_card.py                     # 카탈로그 + 감사 30일 → JSON(표준 출력)
    python3 mcp_quality_card.py --days 7 --out card.json
    python3 mcp_quality_card.py --catalog tools-list.json --tools-map tools-map.json   # 받아 둔 파일로(오프라인)

답에는 설명 원문 · 사람 · 주소를 싣지 않는다 — 수와 도구 이름만. 앱마다 「나쁜 도구」 는 다섯까지만.
토큰은 gateway_config.json 의 `_gateway.token`(서비스 시야 — 끈 앱 · 개인 보기에 안 걸린 전체 카탈로그)을 읽고 찍지 않는다.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
_HISTORY_RE = re.compile(r"(20\d\d-\d\d-\d\d|\b\d{1,2}-\d{2} (?:결정|사용자)|\b[A-Z]{1,4}-D?\d{1,3}\b|실측)")
_NUM_TYPES = {"integer", "number"}


def _post(url: str, body: dict, token: str, sid: str | None) -> tuple[dict | None, str | None]:
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
         "Authorization": "Bearer " + token}
    if sid:
        h["mcp-session-id"] = sid
    with urllib.request.urlopen(urllib.request.Request(url, data=json.dumps(body).encode(), headers=h), timeout=180) as r:
        raw = r.read().decode("utf-8", "replace")
        new_sid = r.headers.get("mcp-session-id") or sid
    if not raw.strip():
        return None, new_sid
    if raw.lstrip().startswith("{"):
        return json.loads(raw), new_sid
    msgs = [json.loads(ln[5:]) for ln in raw.splitlines() if ln.startswith("data:") and ln[5:].strip()]
    return (msgs[-1] if msgs else None), new_sid


def fetch_catalog(base: str, token: str) -> list[dict]:
    """tools/list 전부(페이지 이어 받기). 세션을 내는 게이트웨이 · 안 내는 게이트웨이 둘 다 받는다."""
    url = base.rstrip("/") + "/mcp"
    _, sid = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mcp-quality-card", "version": "1"}}}, token, None)
    _post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, token, sid)
    tools, cur = [], None
    while True:
        res, sid = _post(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"cursor": cur} if cur else {}}, token, sid)
        if not res or "result" not in res:
            raise RuntimeError(f"tools/list 실패: {str(res)[:200]}")
        tools += res["result"].get("tools") or []
        cur = res["result"].get("nextCursor")
        if not cur:
            return tools


def _resolve(schema: dict, root: dict) -> dict:
    ref = schema.get("$ref") if isinstance(schema, dict) else None
    if isinstance(ref, str) and ref.startswith("#/"):
        node = root
        for part in ref[2:].split("/"):
            node = node.get(part, {}) if isinstance(node, dict) else {}
        return node if isinstance(node, dict) else {}
    return schema if isinstance(schema, dict) else {}


def _types(s: dict) -> set[str]:
    t = s.get("type")
    out = set(t) if isinstance(t, list) else ({t} if t else set())
    for k in ("anyOf", "oneOf"):
        for alt in s.get(k) or []:
            if isinstance(alt, dict) and alt.get("type"):
                out |= set(alt["type"]) if isinstance(alt["type"], list) else {alt["type"]}
    return out - {"null"}


def _has_bound(s: dict) -> bool:
    keys = ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum")
    return any(k in s for k in keys) or any(any(k in a for k in keys) for a in (s.get("anyOf") or []) if isinstance(a, dict))


def _has_enum(s: dict) -> bool:
    return "enum" in s or "const" in s or any(isinstance(a, dict) and ("enum" in a or "const" in a) for a in (s.get("anyOf") or []))


def walk_args(schema: dict, filled=()) -> dict:
    """인자 수 — 맨 위와 중첩(객체 속성 · 배열 항목 · $defs 참조)까지. 설명 · enum · 숫자 경계 · 자유형 객체를 함께 센다.
    filled 는 게이트웨이가 docstring 으로 채운 맨 위 인자(/tools-map gateway_filled) — 설명 없음으로 센다(앱의 실제 상태)."""
    root = schema or {}
    c = collections.Counter()
    top = (root.get("properties") or {}) if isinstance(root, dict) else {}
    c["args"] = len(top)
    c["args_described"] = sum(1 for k, v in top.items() if k not in filled and isinstance(v, dict)
                              and str(_resolve(v, root).get("description") or v.get("description") or "").strip())
    c["args_gateway_filled"] = sum(1 for k in top if k in filled)
    seen: set[int] = set()

    def visit(props: dict, depth: int):
        for k, v in props.items():
            if not isinstance(v, dict):
                continue
            s = _resolve(v, root)
            c["nested_args"] += 1
            c["nested_described"] += bool(not (depth == 0 and k in filled) and str(v.get("description") or s.get("description") or "").strip())
            ty = _types(s) or _types(v)
            if ty & _NUM_TYPES:
                c["numeric_args"] += 1
                c["numeric_bounded"] += _has_bound(s) or _has_bound(v)
            if _has_enum(s) or _has_enum(v):
                c["enum_args"] += 1
            if "object" in ty and not s.get("properties") and not any(isinstance(a, dict) and _resolve(a, root).get("properties") for a in (s.get("anyOf") or [])):
                c["free_objects"] += 1
            if depth < 4 and id(s) not in seen:
                seen.add(id(s))
                if s.get("properties"):
                    visit(s["properties"], depth + 1)
                items = _resolve(s.get("items") or {}, root)
                if items.get("properties"):
                    visit(items["properties"], depth + 1)
                for a in s.get("anyOf") or []:
                    ra = _resolve(a, root) if isinstance(a, dict) else {}
                    if ra.get("properties"):
                        visit(ra["properties"], depth + 1)

    visit(top, 0)
    return c


def _real_output_schema(t: dict) -> bool:
    """FastMCP 가 스칼라 · 목록을 감싼 껍데기({"result": …} 하나)가 아닌, 필드가 있는 결과 꼴인가."""
    o = t.get("outputSchema")
    if not isinstance(o, dict):
        return False
    props = o.get("properties") or {}
    return bool(props) and set(props) != {"result"}


def _q(vals: list, p: float):
    if not vals:
        return None
    s = sorted(vals)
    return s[min(len(s) - 1, int(len(s) * p))]


def catalog_card(tools: list[dict], tmap: dict) -> dict[str, dict]:
    """앱별 카탈로그 셈. 게이트웨이가 노출 사본에 채운 것(MM-5 표지 gateway_annotated · docstring 인자 gateway_filled)은 앱의 실제 상태로 세지
    않고 ro_gateway · args_gateway_filled 로 따로 센다. 부류(tool_class)가 있으면 cls_read · cls_write · cls_unknown 을 센다."""
    own = tmap.get("map") or {}
    write, rr = set(tmap.get("write") or []), set(tmap.get("routine_read") or [])
    panel, uncl, orig = set(tmap.get("panel_read") or []), set(tmap.get("unclassified") or []), tmap.get("orig") or {}
    gw_ann, gw_fill = set(tmap.get("gateway_annotated") or []), tmap.get("gateway_filled") or {}
    tclass = tmap.get("tool_class") or {}
    digest = lambda d: hashlib.sha1(d.encode("utf-8")).hexdigest()
    apps_of_desc: dict[str, set] = collections.defaultdict(set)
    for t in tools:
        if (t.get("description") or "").strip():
            apps_of_desc[digest(t["description"])].add(own.get(t["name"], "_gateway"))
    per: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    lens: dict[str, list] = collections.defaultdict(list)
    worst: dict[str, list] = collections.defaultdict(list)
    for t in tools:
        a, d = own.get(t["name"], "_gateway"), t.get("description") or ""
        ann = t.get("annotations") or {}
        ro = None if t["name"] in gw_ann else ann.get("readOnlyHint")     # 게이트웨이가 실은 표지는 앱 표지가 아니다
        c = per[a]
        c["tools"] += 1
        c["ro_true" if ro is True else "ro_false" if ro is False else "ro_none"] += 1
        c["ro_gateway"] += t["name"] in gw_ann
        cls = (tclass.get(t["name"]) or {}).get("class")
        if cls in ("read", "write", "unknown"):
            c["cls_" + cls] += 1
        c["destructive"] += ann.get("destructiveHint") is True
        c["idempotent"] += ann.get("idempotentHint") is True
        c["gw_write"] += t["name"] in write
        c["routine_read"] += t["name"] in rr
        c["panel_read"] += t["name"] in panel
        c["unclassified"] += t["name"] in uncl
        c["prefixed"] += t["name"] in orig
        c["desc_empty"] += not d.strip()
        c["desc_lt100"] += 0 < len(d.strip()) < 100
        c["desc_gt1000"] += len(d) > 1000
        c["desc_gt2400"] += len(d) > 2400
        c["desc_history"] += bool(_HISTORY_RE.search(d))
        c["desc_shared_other_app"] += bool(d.strip()) and len(apps_of_desc[digest(d)]) > 1
        c["output_schema_real"] += _real_output_schema(t)
        w = walk_args(t.get("inputSchema") or {}, frozenset(gw_fill.get(t["name"]) or ()))
        for k, v in w.items():
            c[k] += v
        missing = w["args"] - w["args_described"]
        if missing:
            worst[a].append((missing, t["name"]))
        lens[a].append(len(d))
    keys = ("tools", "ro_true", "ro_false", "ro_none", "ro_gateway", "destructive", "idempotent", "gw_write", "routine_read", "panel_read",
            "cls_read", "cls_write", "cls_unknown",
            "unclassified", "prefixed", "desc_empty", "desc_lt100", "desc_gt1000", "desc_gt2400", "desc_history",
            "desc_shared_other_app", "output_schema_real", "args", "args_described", "args_gateway_filled", "nested_args", "nested_described",
            "numeric_args", "numeric_bounded", "enum_args", "free_objects")
    out = {}
    for a, c in per.items():
        L = lens[a]
        row = {k: c.get(k, 0) for k in keys}       # 0 인 칸도 늘 싣는다 — 받는 쪽(cae00 답 · 표)이 칸 유무로 헷갈리지 않게
        row.update({
            "desc_p50": _q(L, .5), "desc_p95": _q(L, .95), "desc_max": max(L) if L else None,
            "ro_annotated_ratio": round((c["ro_true"] + c["ro_false"]) / c["tools"], 3) if c["tools"] else None,
            "arg_described_ratio": round(c["args_described"] / c["args"], 3) if c["args"] else None,
            "nested_described_ratio": round(c["nested_described"] / c["nested_args"], 3) if c["nested_args"] else None,
            "numeric_bounded_ratio": round(c["numeric_bounded"] / c["numeric_args"], 3) if c["numeric_args"] else None,
            "worst_args": [n for _, n in sorted(worst[a], reverse=True)[:5]],
        })
        out[a] = row
    return out


def audit_card(path: Path, days: int, now: datetime | None = None) -> dict[str, dict]:
    """감사 원장의 앱별 신뢰도 — 호출 · 실패 · 사유 빈 실패 · 지연 · 결과 크기(사람 · 주소 칸은 읽지 않는다)."""
    since = ((now or datetime.now(timezone.utc)) - timedelta(days=days)).isoformat()[:19]
    n, bad, noreason = collections.Counter(), collections.Counter(), collections.Counter()
    ms, ch = collections.defaultdict(list), collections.defaultdict(list)
    if not path.exists():
        return {}
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if not isinstance(e, dict) or str(e.get("ts", ""))[:19] < since:
                continue
            b = e.get("backend")
            if not b:          # 연결 단계 거절(토큰 만료 등)은 도구 호출이 아니다
                continue
            n[b] += 1
            if e.get("ok") is False:
                bad[b] += 1
                noreason[b] += not str(e.get("error") or "").strip()
            if isinstance(e.get("ms"), (int, float)):
                ms[b].append(e["ms"])
            if isinstance(e.get("chars"), int):
                ch[b].append(e["chars"])
    return {b: {"calls": n[b], "fail": bad[b], "fail_rate": round(bad[b] / n[b], 3), "fail_no_reason": noreason[b],
                "ms_p50": _q(ms[b], .5), "ms_p95": _q(ms[b], .95), "ms_max": max(ms[b], default=None),
                "chars_p50": _q(ch[b], .5), "chars_p95": _q(ch[b], .95), "over_50k": sum(x > 50000 for x in ch[b])} for b in n}


def build_card(tools: list[dict], tmap: dict, audit: dict[str, dict]) -> dict:
    cat = catalog_card(tools, tmap)
    # /tools-map 의 apps 열쇠는 app 이다(옛 받아 둔 파일 · 다른 꼴은 key · backend 도 본다) — key 로만 읽어 label 이 늘 null 이었다
    labels = {a.get("app") or a.get("key") or a.get("backend"): a.get("label") for a in (tmap.get("apps") or []) if isinstance(a, dict)}
    apps = []
    for a in sorted(set(cat) | set(audit), key=lambda k: -(cat.get(k, {}).get("tools") or 0)):
        apps.append({"app": a, "label": labels.get(a), **cat.get(a, {}), "audit": audit.get(a)})
    tot = collections.Counter()
    for r in cat.values():
        for k in ("tools", "args", "args_described", "args_gateway_filled", "ro_true", "ro_false", "ro_gateway", "nested_args",
                  "nested_described", "cls_read", "cls_write", "cls_unknown"):
            tot[k] += r.get(k) or 0
    summary = dict(tot)
    summary["arg_described_ratio"] = round(tot["args_described"] / tot["args"], 3) if tot["args"] else None
    summary["ro_annotated_ratio"] = round((tot["ro_true"] + tot["ro_false"]) / tot["tools"], 3) if tot["tools"] else None
    return {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "total": summary, "apps": apps}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", default=os.environ.get("GATEWAY_BASE", "http://127.0.0.1:9110"))
    ap.add_argument("--catalog", help="받아 둔 tools/list JSON(목록) — 주면 게이트웨이에 묻지 않는다")
    ap.add_argument("--tools-map", help="받아 둔 /tools-map JSON")
    ap.add_argument("--audit", default=os.environ.get("GATEWAY_AUDIT", str(HERE / "audit.jsonl")))
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    if a.tools_map:
        tmap = json.loads(Path(a.tools_map).read_text(encoding="utf-8"))
    else:
        with urllib.request.urlopen(a.base.rstrip("/") + "/tools-map", timeout=60) as r:
            tmap = json.loads(r.read().decode("utf-8"))
    if a.catalog:
        tools = json.loads(Path(a.catalog).read_text(encoding="utf-8"))
    else:
        cfg = json.loads((HERE / os.environ.get("GATEWAY_CONFIG_NAME", "gateway_config.json")).read_text(encoding="utf-8"))
        token = os.environ.get("GATEWAY_TOKEN") or (cfg.get("_gateway") or {}).get("token") or ""
        if not token:
            print("토큰 없음 — gateway_config.json 의 _gateway.token 또는 GATEWAY_TOKEN", file=sys.stderr)
            return 2
        tools = fetch_catalog(a.base, token)
    card = build_card(tools, tmap, audit_card(Path(a.audit), a.days))
    text = json.dumps(card, ensure_ascii=False, indent=1)
    if a.out:
        Path(a.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
