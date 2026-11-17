# 도구 등록 점검표(docs/tool-registration-checklist.md)의 읽기만 하는 훑기 — /tools-map 꼴 카탈로그로 앱마다 도구 · 데이터 주인 추정 · 보고만 하는 함수 의심 · 까닭을 표로 낸다
"""HWAXPortal docs/request-1117 GW-04(사용자 결정 — 점검표 문서 + 읽기만 하는 훑기, 관리자 도구 · 저장 없음).

배치 원칙 — 데이터를 가진 플랫폼이 함수를 갖는다. 포털 · 게이트웨이는 노출 · 연결만 한다. 보고만 하는 함수(다른 플랫폼의 데이터를 가져다 꼴만 바꿔
내는 것)는 그 데이터를 가진 플랫폼으로 돌려보낸다. 이 훑기는 그 원칙에서 벗어난 것으로 **보이는** 도구를 낱말 규칙으로 짚는다 — 짐작이다, 판정은
사람이 한다. 아무것도 쓰지 않고(파일 · 원장 · 게이트웨이), 감사 원장도 읽지 않는다.

  · 카탈로그 — /tools-map JSON(떠 있는 게이트웨이 --gateway, 또는 저장한 파일 --tools-map). 설명이 있으면 더 잘 짚는다 — tool_search_eval/run.py snapshot
    이 뜬 스냅숏(--snapshot, 도구마다 이름 · 앱 · 원래 이름 · 설명)을 함께 주면 설명 낱말도 본다.
  · 규칙 — 사용자 결정으로 굳은 것만 주인을 바꾼다(INTENT_RULES · DOMAIN_RULES — 지금은 D1: 낙하 · 부분 충격 해석 결과의 저장 · 조회는 DynaForge 만).
    보고 · 형식 낱말(report · summary · export · 그림 · 발표 …)이 든 도구가 게이트웨이 자체이거나 데이터 주인이 다른 앱이면 '보고만 의심' 이다.
  · 옛 키(app_keys.json 의 retired — GW-05)로 아직 붙어 있는 앱은 따로 짚는다.

    python3 tool_registration_scan.py                                    # 이 박스 게이트웨이(127.0.0.1:9110)의 /tools-map
    python3 tool_registration_scan.py --tools-map map.json --snapshot tool_search_eval/catalog.local.json --flagged
    python3 tool_registration_scan.py --app reportarchive --format json
"""
import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
APP_KEYS = HERE / "app_keys.json"                     # gateway.py APP_KEYS_PATH 와 같은 자리
CONNECTOR_APPS = frozenset({"_gateway"})              # 노출 · 연결만 하는 쪽(게이트웨이 자체 도구)
# 보고 · 형식 낱말 — 원래 이름의 밑줄 조각 또는 설명 글
REPORT_NAME = re.compile(r"(?:^|_)(report|reports|summary|summarize|export|render|figure|deck|docx|pptx|pdf|chart|plot|format|digest)(?:_|$)")
REPORT_DESC = ("보고서", "요약", "그림", "차트", "발표", "문서로", "report", "summary", "export")
# 결과를 담거나 찾는 낱말 — 도메인 규칙은 이것과 도메인 낱말이 함께 있을 때만 건다(해석을 '돌리는' 도구는 결과의 주인이 아니어도 된다)
RESULT_WORDS = ("결과", "조회", "result", "results", "runs", "peaks", "summary", "report", "worst", "compare")

# 사용자 결정으로 굳은 데이터 주인 — 도메인 낱말 + 결과 낱말이 든 다른 앱의 도구를 그 주인 쪽으로 짚는다
DOMAIN_RULES = [
    {"id": "D1", "owner": "heax-kooremapper_mcp", "owner_label": "DynaForge",
     "words": ("낙하", "전각도", "부분 충격", "부분충격", "drop", "full-angle", "fullangle", "partial impact", "partial-impact", "sphere"),
     "why": "낙하 · 부분 충격 해석 결과의 저장 · 조회는 DynaForge 만이다(사용자 결정 D1, 11-17)"},
]
# 질의 점검 — 그 질의에서 1위가 아니어야 하는 도구(앱 키, 원래 이름). 실제 순위는 cae00 에서 search_tools · tool_search_eval/run.py live 로 잰다
INTENT_RULES = [
    {"id": "D1", "owner": "heax-kooremapper_mcp", "owner_label": "DynaForge",
     "queries": ("전각도 낙하 결과", "낙하 해석 결과", "부분 충격 결과", "낙하 시험 결과 최악 케이스", "full-angle drop result", "partial impact result"),
     "not_first": (("reportarchive", "list_analysis_runs"), ("reportarchive", "get_analysis_summary"),
                   ("reportarchive", "get_analysis_peaks"), ("reportarchive", "compare_analysis_runs")),
     "why": ("낙하 · 부분 충격 해석 결과의 저장 · 조회는 DynaForge 만 — Report Archive 의 분석 실행 도구는 이 질의들에서 1위가 아니어야 한다"
             "(사용자 결정 D1, 11-17). 기본 검색 순위는 바꾸지 않는다 — 고칠 곳은 그 도구 설명 · 박스 덧씌우기다")},
]


def _original(name: str, app: str, orig_map: dict) -> str:
    """노출 이름 → 원래 이름 — /tools-map 의 orig 가 있으면 그것, 없으면 충돌 접두(<앱 키에서 하이픈 뺀 것>_)를 뗀다."""
    if name in orig_map:
        return orig_map[name]
    p = app.replace("-", "") + "_"
    return name[len(p):] if name.startswith(p) else name


def _tools_map(path: str | None, gateway: str) -> tuple[dict, str]:
    if path:
        return json.loads(Path(path).read_text(encoding="utf-8")), path
    # 박스 안 주소라 프록시를 타지 않는다(tool_usage_report.py 와 같다). /tools-map 은 무인증이고 밖(nginx)에서는 막혀 있다 — 박스에서 돌린다
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(gateway.rstrip("/") + "/tools-map", timeout=30) as r:
        return json.loads(r.read().decode("utf-8")), gateway.rstrip("/") + "/tools-map"


def _retired() -> dict:
    """옛 키 표(app_keys.json 의 retired) — 못 읽으면 빈 표."""
    try:
        return dict(json.loads(APP_KEYS.read_text(encoding="utf-8")).get("retired") or {})
    except (OSError, ValueError, AttributeError):
        return {}


def judge(app: str, orig: str, desc: str = "") -> dict:
    """도구 하나 → {owner, report_only, reasons, rules}. 주인은 기본이 그 앱이고, 굳은 규칙에 걸릴 때만 바뀐다."""
    text = f"{orig} {desc}".lower()
    owner, reasons, rules = app, [], []
    for r in INTENT_RULES:
        if (app, orig) in r["not_first"]:
            owner = r["owner"]
            rules.append(r["id"])
            reasons.append(f"{r['id']} — '{r['queries'][0]}' 같은 질의에서 1위가 아니어야 한다 · 결과의 주인은 {r['owner_label']}({r['owner']})")
    for r in DOMAIN_RULES:
        if app != r["owner"] and r["id"] not in rules and any(w in text for w in r["words"]) and any(w in text for w in RESULT_WORDS):
            owner = r["owner"]
            rules.append(r["id"])
            reasons.append(f"{r['id']} — 도메인 낱말 + 결과 낱말: {r['why']}")
    rep_name = REPORT_NAME.search(orig)
    rep_desc = next((w for w in REPORT_DESC if w in (desc or "").lower()), None)
    report_only = bool((rep_name or rep_desc) and (app in CONNECTOR_APPS or owner != app))
    if report_only:
        word = rep_name.group(1) if rep_name else rep_desc
        reasons.append(f"보고 · 형식 낱말 '{word}' + " + ("게이트웨이 자체 도구 — 노출 · 연결만인지 본다" if app in CONNECTOR_APPS else
                                                  f"데이터 주인이 다른 앱({owner}) — 보고만 하는 함수면 주인 플랫폼으로 돌려보낸다"))
    return {"owner": owner, "report_only": report_only, "reasons": reasons, "rules": rules}


def scan(tmap: dict, snapshot: dict | None = None, app_filter: str = "") -> dict:
    """카탈로그 → {apps: {앱: [줄]}, intents: [...], retired_live: [...]}. 줄은 {tool, original, owner, report_only, reasons, rules}."""
    desc = {}
    for t in (snapshot or {}).get("tools") or []:
        if isinstance(t, dict) and t.get("name"):
            desc[t["name"]] = str(t.get("description") or "")
    orig_map = tmap.get("orig") or {}
    labels = {a.get("app"): a.get("label") or "" for a in tmap.get("apps") or [] if isinstance(a, dict)}
    apps: dict[str, list] = {}
    seen: dict[tuple, str] = {}
    for name, app in sorted((tmap.get("map") or {}).items()):
        if not app or (app_filter and app != app_filter):
            continue
        orig = _original(name, app, orig_map)
        seen[(app, orig)] = name
        row = {"tool": name, "original": orig, **judge(app, orig, desc.get(name, ""))}
        apps.setdefault(app, []).append(row)
    intents = []
    for r in INTENT_RULES:
        present = [seen[k] for k in r["not_first"] if k in seen]
        intents.append({"id": r["id"], "owner": r["owner"], "owner_label": r["owner_label"], "queries": list(r["queries"]),
                        "not_first": [f"{a}:{o}" for a, o in r["not_first"]], "present": present, "why": r["why"]})
    retired = _retired()
    live = sorted({a for a in (tmap.get("map") or {}).values()} & set(retired))
    return {"apps": apps, "labels": labels, "intents": intents,
            "retired_live": [{"app": a, "now": retired[a].get("now")} for a in live]}


def _cell(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def render(res: dict, flagged_only: bool = False) -> str:
    """마크다운 — 앱마다 표 하나, 끝에 질의 점검 · 옛 키."""
    out = ["# 도구 등록 훑기 — 데이터 주인 · 보고만 하는 함수 의심", "",
           "배치 원칙 — 데이터를 가진 플랫폼이 함수를 갖는다. 포털 · 게이트웨이는 노출 · 연결만 한다. 보고만 하는 함수는 데이터를 가진 플랫폼으로 돌려보낸다. "
           "아래는 낱말 규칙으로 짚은 **짐작**이다 — 판정은 사람이 한다(docs/tool-registration-checklist.md).", ""]
    total = sum(len(v) for v in res["apps"].values())
    flagged = sum(1 for v in res["apps"].values() for r in v if r["rules"] or r["report_only"])
    out += [f"- 도구 {total}개 · 앱 {len(res['apps'])}개 · 짚은 도구 {flagged}개", ""]
    for app in sorted(res["apps"], key=lambda a: (a != "_gateway", a)):
        rows = [r for r in res["apps"][app] if not flagged_only or r["rules"] or r["report_only"]]
        if not rows:
            continue
        label = res["labels"].get(app) or ""
        out += [f"## {app}" + (f" — {label}" if label else ""), "", "| 도구 | 원래 이름 | 데이터 주인(추정) | 보고만 의심 | 까닭 |", "|---|---|---|---|---|"]
        for r in rows:
            out.append(f"| {_cell(r['tool'])} | {_cell(r['original'])} | {_cell(r['owner'])} | {'예' if r['report_only'] else ''} | "
                       f"{_cell(' · '.join(r['reasons']))} |")
        out.append("")
    out += ["## 질의 점검", ""]
    for i in res["intents"]:
        out += [f"### {i['id']} — 결과의 주인 {i['owner_label']}({i['owner']})", "", i["why"], "",
                "- 질의 — " + " · ".join(f"'{q}'" for q in i["queries"]),
                "- 1위가 아니어야 하는 도구 — " + " · ".join(i["not_first"]),
                "- 이 카탈로그에 있는 것 — " + (" · ".join(i["present"]) if i["present"] else "없음(그 앱이 지금 닿지 않거나 도구가 없다)"),
                "- 재는 법 — cae00 에서 search_tools(query=…) 의 ranked[0] 을 보거나 tool_search_eval/run.py live 로 잰다(이 훑기는 순위를 돌리지 않는다)", ""]
    if res["retired_live"]:
        out += ["## 옛 키로 아직 붙어 있는 앱(GW-05)", ""]
        out += [f"- {x['app']} → 지금 키 {x['now']}" for x in res["retired_live"]] + [""]
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="도구 등록 점검표의 읽기만 하는 훑기 — 앱마다 도구 · 데이터 주인 추정 · 보고만 하는 함수 의심 · 까닭")
    ap.add_argument("--tools-map", help="저장한 /tools-map JSON(주지 않으면 --gateway 에서 받는다)")
    ap.add_argument("--gateway", default="http://127.0.0.1:9110", help="게이트웨이 주소(기본 http://127.0.0.1:9110 — 박스 안에서 돌린다)")
    ap.add_argument("--snapshot", help="tool_search_eval/run.py snapshot 이 뜬 카탈로그(설명 낱말도 본다)")
    ap.add_argument("--app", default="", help="이 앱 키만")
    ap.add_argument("--flagged", action="store_true", help="짚은 도구만 싣는다")
    ap.add_argument("--format", choices=("md", "json"), default="md", help="md(기본) 또는 json")
    a = ap.parse_args(argv)
    try:
        tmap, _source = _tools_map(a.tools_map, a.gateway)
        snap = json.loads(Path(a.snapshot).read_text(encoding="utf-8")) if a.snapshot else None
    except (OSError, ValueError) as e:
        print(f"✗ 읽지 못했다 — {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    res = scan(tmap, snap, a.app)
    sys.stdout.write(json.dumps(res, ensure_ascii=False, indent=1) + "\n" if a.format == "json" else render(res, a.flagged) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
