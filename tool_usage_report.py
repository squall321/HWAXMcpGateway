# 게이트웨이 감사 기록으로 앱별 '오래 안 불린 도구' 보고서를 만든다(HWAXPortal docs/request-1029 E-3)
"""앱 주인에게 넘기는 보고서 — 지금 게이트웨이에 노출된 도구(/tools-map) 가운데 최근 N일(기본 30) 감사 기록(audit.jsonl)에 한 번도
나오지 않은 것을 앱별로 적는다.

  · 불렸다 = 성공 · 실패 · 거부를 가리지 않고 기록에 한 번이라도 나왔다(누군가 부르려 했다).
  · 별칭(<백엔드 키에서 하이픈 뺀 것>_<원래 이름>)으로 부른 호출 · 이름 겹침으로 접두가 붙기 전의 맨 이름 호출도 그 도구로 센다.
  · 게이트웨이 자체 도구(_gateway — search_tools 등)는 감사에 다 남지 않아 세지 않는다. 지금 도구가 없는 앱(불통)은 빠진다.
  · 도구가 언제 생겼는지는 모른다 — 최근에 붙은 앱이면 안 불린 것이 당연할 수 있다.
  · 보고서에는 도구 이름과 수만 싣는다(부른 사람 · 주소는 싣지 않는다).

    python3 tool_usage_report.py                              # 이 박스 게이트웨이(127.0.0.1:9110)와 감사 기록, 30일
    python3 tool_usage_report.py --days 60 --out unused.md
    python3 tool_usage_report.py --tools-map map.json --audit audit.jsonl
"""
import argparse
import json
import os
import sys
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

# 게이트웨이와 같은 규칙(gateway.py AUDIT_PATH)
AUDIT_DEFAULT = os.environ.get("GATEWAY_AUDIT", str(Path(__file__).with_name("audit.jsonl")))


def _names(exposed: str, backend: str) -> set:
    """이 도구로 셀 이름 — 맨 이름과 별칭(접두 붙은 이름) 둘. 노출 이름은 그 둘 중 하나다(gateway.py _aggregate)."""
    p = backend.replace("-", "") + "_"
    orig = exposed[len(p):] if exposed.startswith(p) else exposed
    return {orig, p + orig}


def _seen(audit: str, since: datetime) -> tuple[Counter, int]:
    """기간 안 감사 줄의 (도구, 백엔드) 수와 줄 수. 못 읽는 줄은 건너뛴다."""
    seen: Counter = Counter()
    lines = 0
    with open(audit, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                r = json.loads(line)
                ts = datetime.fromisoformat(r["ts"])
            except (ValueError, KeyError, TypeError):
                continue
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= since:
                seen[(r.get("tool"), r.get("backend"))] += 1
                lines += 1
    return seen, lines


def _tools_map(path: str | None, gateway: str) -> tuple[dict, str]:
    if path:
        return json.loads(Path(path).read_text(encoding="utf-8")), path
    # 박스 안 주소라 프록시를 타지 않는다(cae00 의 프록시 환경 변수를 물려받지 않게)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(gateway.rstrip("/") + "/tools-map", timeout=30) as r:
        return json.loads(r.read().decode("utf-8")), gateway.rstrip("/") + "/tools-map"


def usage_by_app(tmap: dict, seen: Counter) -> dict:
    """앱(백엔드 키)마다 {used: [노출 이름], unused: [노출 이름]} — 게이트웨이 자체 도구는 뺀다. 플랫폼별 피드백 보고서도 이것을 쓴다."""
    by_app: dict = {}
    for name, bk in sorted((tmap.get("map") or {}).items()):
        if not bk or bk == "_gateway":
            continue
        used = any(seen.get((n, bk)) for n in _names(name, bk))
        by_app.setdefault(bk, {"used": [], "unused": []})["used" if used else "unused"].append(name)
    return by_app


def report(tmap: dict, seen: Counter, *, days: int, since: datetime, until: datetime, audit: str, source: str, lines: int) -> str:
    label = {a.get("app"): a.get("label") or a.get("app") for a in tmap.get("apps") or []}
    by_app = usage_by_app(tmap, seen)
    rows = sorted(by_app.items(), key=lambda kv: (-len(kv[1]["unused"]), kv[0]))
    tot = sum(len(v["used"]) + len(v["unused"]) for v in by_app.values())
    unused = sum(len(v["unused"]) for v in by_app.values())
    out = [f"# 오래 안 불린 도구 — 최근 {days}일({since:%Y-%m-%d} ~ {until:%Y-%m-%d} UTC)", "",
           f"게이트웨이 감사 기록 `{audit}`(이 기간 {lines:,}줄) · 도구 지도 `{source}`.",
           "불렸다 = 성공 · 실패 · 거부를 가리지 않고 기록에 한 번이라도 나왔다. 게이트웨이 자체 도구는 세지 않는다. "
           "도구가 언제 생겼는지는 모른다 — 최근에 붙은 앱이면 안 불린 것이 당연할 수 있다.", "",
           f"전체 — 도구 {tot:,}개 중 {days}일 안에 불린 것 {tot - unused:,}개 · 안 불린 것 {unused:,}개"
           + (f"({100 * unused / tot:.0f}%)." if tot else "."), "",
           "| 앱 | 도구 | 불린 것 | 안 불린 것 |", "|---|---:|---:|---:|"]
    for bk, v in rows:
        out.append(f"| {label.get(bk, bk)} (`{bk}`) | {len(v['used']) + len(v['unused'])} | {len(v['used'])} | {len(v['unused'])} |")
    for bk, v in rows:
        if v["unused"]:
            out += ["", f"## {label.get(bk, bk)} (`{bk}`) — 안 불린 {len(v['unused'])}개", "",
                    " · ".join(f"`{n}`" for n in v["unused"])]
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="게이트웨이 감사 기록으로 앱별 '오래 안 불린 도구' 보고서를 만든다")
    ap.add_argument("--days", type=int, default=30, help="최근 며칠(기본 30)")
    ap.add_argument("--audit", default=AUDIT_DEFAULT, help="감사 기록(기본 게이트웨이와 같다 — GATEWAY_AUDIT 또는 이 파일 옆 audit.jsonl)")
    ap.add_argument("--tools-map", help="저장한 /tools-map JSON(주지 않으면 --gateway 에서 받는다)")
    ap.add_argument("--gateway", default="http://127.0.0.1:9110", help="게이트웨이 주소(기본 http://127.0.0.1:9110)")
    ap.add_argument("--out", help="보고서를 쓸 파일(주지 않으면 화면)")
    ap.add_argument("--now", help=argparse.SUPPRESS)                  # 시험용 — 기준 시각(ISO)
    a = ap.parse_args(argv)
    until = datetime.fromisoformat(a.now) if a.now else datetime.now(timezone.utc)
    since = until - timedelta(days=a.days)
    try:
        tmap, source = _tools_map(a.tools_map, a.gateway)
        seen, lines = _seen(a.audit, since)
    except (OSError, ValueError) as e:
        print(f"✗ 읽지 못했다 — {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    text = report(tmap, seen, days=a.days, since=since, until=until, audit=a.audit, source=source, lines=lines)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
        print(f"✓ {a.out}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
