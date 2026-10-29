# 플랫폼마다 '보정 덕에만 찾아진 질의 · 보이고도 안 불림 · 밖에서 불림 · 실패 · 큰 응답 · 인자 설명 · 안 불린 도구' 를 모은 피드백 보고서(HWAXPortal docs/request-1029 E-8)
"""우리가 다루지 않는 플랫폼에 돌려줄 피드백. 게이트웨이가 검색 순위를 보정하면 그쪽 도구 설명의 빈 곳이 가려진다 — 이 보고서는 그 보정이
무엇을 가렸는지와 감사 기록에서 그쪽이 고칠 것을 플랫폼(백엔드 키)마다 마크다운으로 적는다. cae00 에서 짓는다 — 실사용 질의가 거기 있다.

  1. 보정 덕에만 찾아진 질의 — 질의 기록의 boost_only(보정을 빼면 0점이거나 limit 밖이던 결과)와 via(점수를 보탠 규칙). 손 동의어(syn:)는
     손잡이 파일(search_tuning.json + 박스 덧씌우기 search_tuning.local.json)의 owner · source_fix 를 곁들인다.
  2. 상위 다섯에 보이고도 안 불림 — 같은 호출자가 찾은 뒤 600초 안에 그 도구를 부르지 않았다(다른 도구를 불렀나 · 아무것도 안 불렀나를 가른다).
  3. 상위 다섯 밖에서 불림 — 찾은 뒤 600초 안에 불렸는데 결과에 없었다(설명이 질의 낱말을 못 담는다) 또는 6위 아래였다.
  4. 실패 — 감사의 ok=false 가운데 플랫폼 쪽(도구가 isError · 오류 봉투 · 예외 · 시간 초과). 게이트웨이 · 권한에서 막힌 것(forbidden ·
     refused · per-user …)은 따로 센다 — 그쪽 탓이 아니다.
  5. 큰 응답 — 감사 chars(호출자에게 돌려준 결과 글자 수)가 기준(--big-chars, 기본 50,000)을 넘은 도구.
  6. 인자 설명 — /tools-map 의 arg_scores(게이트웨이 README '인자 설명 점수판').
  7. 안 불린 도구 — tool_usage_report.py 와 같은 셈(기간 안 감사에 한 번도 안 나왔다).

질의 원문은 싣는다 — 그쪽이 고칠 낱말이 거기 있다. 부른 사람 · 주소는 싣지 않는다(질의 기록에 없고, 감사의 신원 칸은 읽지 않는다).
실패 사유 글에 '@' 가 들었으면 싣지 않는다 — 옛 감사 줄은 사유 칸에 위임 신원을 실었다.
질의 기록은 KST 날짜로, 감사는 UTC 시각으로 기간을 끊는다(각각 게이트웨이가 적는 꼴 그대로). id 없는 옛 질의 줄(10-29 전 일회성 수집)은
결과 줄과 이을 수 없어 뺀다.

    python3 platform_feedback_report.py                                       # 이 박스 게이트웨이 · 감사 · 질의 기록, 30일, 전 플랫폼
    python3 platform_feedback_report.py --platform heax-step_forge --out stepforge.md
    python3 platform_feedback_report.py --tools-map map.json --audit audit.jsonl --qlog-dir tool_search_eval
"""
import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import tool_usage_report as tur

HERE = Path(__file__).resolve().parent
QLOG_DIR = HERE / "tool_search_eval"                 # gateway.py TOOL_QUERY_LOG_DIR 와 같은 자리
TUNING = HERE / "search_tuning.json"                 # gateway.py SEARCH_TUNING_PATH · 덧씌우기는 같은 자리의 .local.json
_KST = timezone(timedelta(hours=9))
_QLOG_FILE = re.compile(r"^queries-(\d{4}-\d{2}-\d{2})\.local\.jsonl$")
TOP = 5                                              # 질의 기록의 top · via · boost_only 는 상위 다섯이다(gateway.py _log_tool_query)
SAMPLES = 3
# 게이트웨이 · 권한에서 막힌 실패 — 플랫폼의 탓이 아니다(gateway.py 에서 _audit 을 부르는 자리의 사유 머리)
_GATE_SIDE = ("invoke-denied:", "forbidden", "unknown tool", "read-only", "backend removed", "refused:", "per-user:",
              "conn-user:", "unauthorized", "no-identity", "method not allowed")


def _merge_patch(target, patch):
    """JSON merge patch(RFC 7386) — gateway.py 의 같은 이름 함수와 같다(시험이 맞댄다)."""
    if not isinstance(patch, dict):
        return patch
    out = dict(target) if isinstance(target, dict) else {}
    for k, v in patch.items():
        if v is None:
            out.pop(k, None)
        else:
            out[k] = _merge_patch(out.get(k), v)
    return out


def _json_fp(obj) -> str:
    """값의 지문 — gateway.py 의 같은 이름 함수와 같다(질의 기록 · /health 의 fp 와 견준다)."""
    if isinstance(obj, dict):
        obj = {k: v for k, v in obj.items() if k != "_doc"}
    return hashlib.sha256(json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:12]


def _tuning_ok(d: dict) -> None:
    """게이트웨이가 덧씌우기를 버리는 꼴(gateway.py _tuning_parse 가 예외를 내는 꼴)이면 예외 — 그때는 이 보고서도 기본값으로 읽는다."""
    for k in (d.get("weights") or {}):
        v = d["weights"][k]
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise TypeError(f"weights.{k} 는 수여야 한다")
    for k, e in (d.get("synonyms") or {}).items():
        if not isinstance(e["to"], list):
            raise TypeError(f"synonyms.{k}.to 는 목록이어야 한다")


def load_tuning(base: Path, local: Path) -> dict:
    """손잡이 — 게이트웨이와 같은 규칙(기본값 + 박스 덧씌우기 merge patch, 덧씌우기가 깨지면 버린다). 낱말 → {to, owner, source_fix} 와 지문."""
    raw = json.loads(base.read_text(encoding="utf-8"))
    _tuning_ok(raw)
    eff, note = raw, "덧씌우기 없음"
    if local.exists():
        try:
            patch = json.loads(local.read_text(encoding="utf-8"))
            if not isinstance(patch, dict):
                raise TypeError("덧씌우기는 객체여야 한다")
            merged = _merge_patch(raw, patch)
            _tuning_ok(merged)
            eff, note = merged, "덧씌우기 있음"
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as e:
            note = f"덧씌우기를 버리고 기본값만({type(e).__name__})"
    syn = {str(k).lower(): {"to": [str(x) for x in (e or {}).get("to") or []], "owner": (e or {}).get("owner"),
                            "source_fix": (e or {}).get("source_fix")}
           for k, e in (eff.get("synonyms") or {}).items()}
    return {"synonyms": syn, "fingerprint": _json_fp(eff), "base_fingerprint": _json_fp(raw), "note": note}


def read_qlog(qdir: Path, days: int, today) -> tuple[dict, dict, int]:
    """질의 기록 — (질의 id → 질의 줄, 질의 id → 결과 줄 목록, 뺀 id 없는 질의 줄 수). gateway.py _qlog_read 와 같은 파일 · 같은 날짜 셈(KST)."""
    files = sorted(f for f in qdir.glob("queries-*.local.jsonl") if _QLOG_FILE.match(f.name))
    old = qdir / "queries.local.jsonl"
    if old.exists():
        files.insert(0, old)
    cut = (today - timedelta(days=days - 1)).isoformat()
    queries: dict = {}
    outs: dict = defaultdict(list)
    no_id = 0
    for f in files:
        try:
            lines = f.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if not isinstance(r, dict) or str(r.get("d") or "") < cut:
                continue
            if "q" in r:
                if r.get("id"):
                    queries[str(r["id"])] = r
                else:
                    no_id += 1
            elif "o" in r:
                outs[str(r["o"])].append(r)
    return queries, outs, no_id


def _index(tmap: dict) -> dict:
    """감사 줄의 (도구, 백엔드) → (백엔드, 원래 이름). 맨 이름과 별칭 둘 다 그 도구다(tool_usage_report._names)."""
    idx = {}
    for name, bk in (tmap.get("map") or {}).items():
        if not bk or bk == "_gateway":
            continue
        p = bk.replace("-", "") + "_"
        orig = name[len(p):] if name.startswith(p) else name
        for n in tur._names(name, bk):
            idx[(n, bk)] = (bk, orig)
    return idx


def _reason(err: str) -> str:
    if not err:
        return "(도구가 isError 로 답함 — 사유는 결과 본문에 있어 감사에 없다)"
    if "@" in err:
        return "(사유 글에 신원이 들어 싣지 않음)"
    t = re.sub(r"\s+", " ", re.sub(r"\d+", "#", err)).strip()
    return t[:80] + (" …" if len(t) > 80 else "")


def audit_stats(audit: str, since: datetime, idx: dict) -> dict:
    """기간 안 감사 줄을 플랫폼 · 도구마다 — 호출 · 플랫폼 쪽 실패 · 게이트웨이에서 막힘 · 사유 · 결과 글자 수. 지도에 없는 줄은 건너뛴다."""
    st: dict = defaultdict(lambda: defaultdict(lambda: {"calls": 0, "fail": 0, "blocked": 0, "reasons": Counter(), "chars": []}))
    with open(audit, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                r = json.loads(line)
                ts = datetime.fromisoformat(r["ts"])
            except (ValueError, KeyError, TypeError):
                continue
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            hit = idx.get((r.get("tool"), r.get("backend")))
            if ts < since or not hit:
                continue
            e = st[hit[0]][hit[1]]
            e["calls"] += 1
            if isinstance(r.get("chars"), int):
                e["chars"].append(r["chars"])
            if r.get("ok") is False:
                err = str(r.get("error") or "")
                if err.startswith(_GATE_SIDE):
                    e["blocked"] += 1
                else:
                    e["fail"] += 1
                    e["reasons"][_reason(err)] += 1
    return st


def _split(key: str) -> tuple[str, str]:
    app, _, orig = str(key).partition(":")
    return app, orig


def _add_sample(lst: list, q) -> None:
    if q and q not in lst and len(lst) < SAMPLES:
        lst.append(q)


def search_stats(queries: dict, outs: dict) -> tuple[dict, dict, dict]:
    """질의 기록을 플랫폼마다 — (보정 덕에만, 보이고도 안 불림, 상위 다섯 밖에서 불림)."""
    boost: dict = defaultdict(lambda: {"queries": set(), "rules": defaultdict(lambda: {"n": 0, "tools": Counter(), "samples": []})})
    shown: dict = defaultdict(lambda: defaultdict(lambda: {"shown": 0, "called": 0, "other": 0, "none": 0, "samples": []}))
    miss: dict = defaultdict(lambda: defaultdict(lambda: {"missing": 0, "low": 0, "ok": 0, "samples": []}))
    for qid, r in queries.items():
        via = r.get("via") or {}
        for key in r.get("boost_only") or []:
            app, orig = _split(key)
            b = boost[app]
            b["queries"].add(qid)
            for rule in via.get(key) or ["(규칙 없음)"]:
                e = b["rules"][rule]
                e["n"] += 1
                e["tools"][orig] += 1
                _add_sample(e["samples"], r.get("q"))
        called = {o.get("t") for o in outs.get(qid, [])}
        for key in (r.get("top") or [])[:TOP]:
            app, orig = _split(key)
            if app == "_gateway":
                continue
            s = shown[app][orig]
            s["shown"] += 1
            if key in called:
                s["called"] += 1
            elif called:
                s["other"] += 1
                _add_sample(s["samples"], r.get("q"))
            else:
                s["none"] += 1
    for qid, lst in outs.items():
        q = (queries.get(qid) or {}).get("q")
        for o in lst:
            rank = o.get("r")
            if rank is not None and rank <= TOP:
                continue                     # 상위 다섯에서 불린 것 — 2절의 '그 도구를 부름' 이다
            app, orig = _split(o.get("t"))
            e = miss[app][orig]
            e["missing" if rank is None else "low"] += 1
            e["ok"] += 1 if o.get("ok") else 0
            _add_sample(e["samples"], q)
    return boost, shown, miss


def _cell(s) -> str:
    return re.sub(r"\s+", " ", str(s)).replace("|", "\\|").strip()


def _qs(samples: list) -> str:
    return " · ".join(f"「{_cell(q)[:60]}」" for q in samples) or "—"


def _pctl(xs: list, p: float) -> int:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p * (len(xs) - 1))))] if xs else 0


def _rule_text(rule: str, app: str, tuning: dict) -> tuple[str, str]:
    """규칙 id → (규칙 글, 고칠 것)."""
    kind, _, word = rule.partition(":")
    if kind == "syn":
        e = tuning["synonyms"].get(word.lower()) or {}
        to = " · ".join(e.get("to") or []) or "?"
        owner = e.get("owner")
        if owner == app:
            fix = e.get("source_fix") or f"도구 설명 · 별칭에 넣을 낱말 — '{word}'"
        elif owner:
            fix = f"(이 낱말의 주인은 `{owner}` — 그쪽 몫)"
        else:
            fix = f"(일반 낱말 — 주인 없음. 그래도 도구 설명에 '{word}' 가 있으면 보정 없이 찾아진다)"
        return f"손 동의어 '{_cell(word)}' → {_cell(to)}", fix
    if kind == "vocab":
        return f"코어 어휘표 낱말 '{_cell(word)}'", "(코어 질문을 허브로 잇는 정책 — 그쪽이 고칠 것이 아닐 수 있다)"
    if kind == "quality":
        return "품질 낱말 가중", "(품질 · VOC 질의를 그 영역 도구로 올리는 정책)"
    if kind == "embedding":
        return "의미 순위(임베딩)", "도구 설명에 질의의 낱말이 없다 — 질의 예의 낱말을 설명 · 별칭에"
    return _cell(rule), "—"


def _platform_section(app, label, ntools, *, tuning, boost, shown, miss, st, arg, unused, days, big, rows) -> list[str]:
    out = ["", f"## {_cell(label)} (`{app}`) — 지금 도구 {ntools}개", ""]

    b = boost.get(app)
    out.append(f"### 1. 보정 덕에만 찾아진 질의 — {len(b['queries']) if b else 0}개")
    out.append("")
    if b:
        out += ["우리 쪽 손잡이가 점수를 보태서야 상위 다섯에 든 결과다. 그쪽 도구 설명 · 별칭에 그 낱말이 있으면 보정 없이 찾아진다.", "",
                "| 규칙 | 건수 | 도구 | 고칠 것 | 질의 예 |", "|---|---:|---|---|---|"]
        rules = sorted(b["rules"].items(), key=lambda kv: (-kv[1]["n"], kv[0]))
        for rule, e in rules[:rows]:
            text, fix = _rule_text(rule, app, tuning)
            tools = " · ".join(f"`{t}`({n})" for t, n in e["tools"].most_common(3))
            out.append(f"| {text} | {e['n']} | {tools} | {fix} | {_qs(e['samples'])} |")
        if len(rules) > rows:
            out.append(f"| … 그 밖 규칙 {len(rules) - rows}개 | | | | |")
    else:
        out.append("없음.")

    s = shown.get(app) or {}
    srows = sorted(((t, e) for t, e in s.items() if e["other"] or e["none"]), key=lambda kv: (-kv[1]["other"], -kv[1]["none"], kv[0]))
    out += ["", f"### 2. 상위 다섯에 보이고도 안 불림 — 도구 {len(srows)}개", ""]
    if srows:
        out += ["찾은 사람이 600초 안에 다른 도구를 불렀으면 그 도구의 설명이 질의에 덜 맞았을 수 있다. 아무것도 안 불렀으면 신호가 약하다"
                "(답이 검색 결과로 끝났을 수 있다).", "",
                "| 도구 | 보임 | 그 도구를 부름 | 다른 도구를 부름 | 아무것도 안 부름 | 다른 도구를 부른 질의 예 |", "|---|---:|---:|---:|---:|---|"]
        for t, e in srows[:rows]:
            out.append(f"| `{t}` | {e['shown']} | {e['called']} | {e['other']} | {e['none']} | {_qs(e['samples'])} |")
        if len(srows) > rows:
            out.append(f"| … 그 밖 도구 {len(srows) - rows}개 | | | | | |")
    else:
        out.append("없음.")

    m = miss.get(app) or {}
    mrows = sorted(m.items(), key=lambda kv: (-kv[1]["missing"], -kv[1]["low"], kv[0]))
    out += ["", f"### 3. 상위 다섯 밖에서 불림 — 도구 {len(mrows)}개", ""]
    if mrows:
        out += ["찾은 뒤 600초 안에 불렸는데 결과에 없었다(설명이 질의 낱말을 못 담는다 — 질의 예의 낱말이 고칠 곳이다) 또는 6위 아래였다.", "",
                "| 도구 | 결과에 없었는데 불림 | 6위 아래에서 불림 | 그중 성공 | 질의 예 |", "|---|---:|---:|---:|---|"]
        for t, e in mrows[:rows]:
            out.append(f"| `{t}` | {e['missing']} | {e['low']} | {e['ok']} | {_qs(e['samples'])} |")
        if len(mrows) > rows:
            out.append(f"| … 그 밖 도구 {len(mrows) - rows}개 | | | | |")
    else:
        out.append("없음.")

    a = st.get(app) or {}
    frows = sorted(((t, e) for t, e in a.items() if e["fail"]), key=lambda kv: (-kv[1]["fail"], kv[0]))
    blocked = sum(e["blocked"] for e in a.values())
    out += ["", f"### 4. 실패(플랫폼 쪽) — 도구 {len(frows)}개 · {sum(e['fail'] for _, e in frows)}건", ""]
    if frows:
        out += ["| 도구 | 호출 | 실패 | 비율 | 흔한 사유 |", "|---|---:|---:|---:|---|"]
        for t, e in frows[:rows]:
            n = e["calls"] - e["blocked"]
            why = " · ".join(f"{_cell(k)}({c})" for k, c in e["reasons"].most_common(2))
            out.append(f"| `{t}` | {n} | {e['fail']} | {100 * e['fail'] / n:.0f}% | {why} |")
        if len(frows) > rows:
            out.append(f"| … 그 밖 도구 {len(frows) - rows}개 | | | | |")
    else:
        out.append("없음.")
    if blocked:
        out += ["", f"게이트웨이 · 권한에서 막힌 호출 {blocked}건은 실패에서 뺐다(forbidden · refused · per-user …)."]

    brows = sorted(((t, e) for t, e in a.items() if e["chars"] and max(e["chars"]) >= big), key=lambda kv: (-max(kv[1]["chars"]), kv[0]))
    out += ["", f"### 5. 큰 응답(기준 {big:,}자) — 도구 {len(brows)}개", ""]
    if brows:
        out += ["감사 chars 는 호출자에게 돌려준 결과의 글자 수다. 챗은 기본 200,000자(에이전트 서버 TOOL_RESULT_MAX)에서 자른다 — "
                "큰 응답은 질문 하나의 LLM 비용을 키운다(요약 · 쪽 나누기 · 필드 고르기 인자가 고칠 곳이다).", "",
                "| 도구 | 잰 호출 | 중앙 | p95 | 최대 | 기준 넘음 |", "|---|---:|---:|---:|---:|---:|"]
        for t, e in brows[:rows]:
            cs = e["chars"]
            out.append(f"| `{t}` | {len(cs)} | {_pctl(cs, 0.5):,} | {_pctl(cs, 0.95):,} | {max(cs):,} | {sum(1 for c in cs if c >= big)} |")
        if len(brows) > rows:
            out.append(f"| … 그 밖 도구 {len(brows) - rows}개 | | | | | |")
    else:
        out.append("없음.")

    out += ["", "### 6. 인자 설명", ""]
    if arg and arg.get("args"):
        worst = " · ".join(f"`{w.get('tool')}`(인자 {w.get('args')}개 중 설명 {w.get('described')}개)" for w in arg.get("worst") or [])
        out.append(f"인자 {arg['args']}개 중 설명 있는 것 {arg.get('described', 0)}개({100 * (arg.get('described_ratio') or 0):.0f}%) · "
                   f"그중 단위 · 범위까지 든 것 {arg.get('unit_or_range', 0)}개." + (f" 설명이 가장 빈 도구 — {worst}." if worst else ""))
    else:
        out.append("인자가 없거나 점수판에 없다.")

    out += ["", f"### 7. {days}일 안 불린 도구 — {len(unused)}개", ""]
    out.append(" · ".join(f"`{n}`" for n in unused) if unused else "없음.")
    return out


def report(tmap: dict, *, tuning: dict, queries: dict, outs: dict, no_id: int, st: dict, seen: Counter, audit_lines: int,
           days: int, since: datetime, until: datetime, audit: str, qlog_dir: str, source: str, big: int, rows: int,
           only: list | None = None) -> str:
    label = {a.get("app"): a.get("label") or a.get("app") for a in tmap.get("apps") or []}
    usage = tur.usage_by_app(tmap, seen)
    arg = {a.get("app"): a for a in (tmap.get("arg_scores") or {}).get("apps") or []}
    boost, shown, miss = search_stats(queries, outs)
    apps = set(usage) | set(boost) | set(shown) | set(miss) | set(st)
    apps.discard("_gateway")
    apps.discard("")
    if only:
        apps &= set(only)

    def weight(app):
        return (len(boost[app]["queries"]) if app in boost else 0) + sum(e["other"] for e in (shown.get(app) or {}).values()) \
            + sum(e["missing"] for e in (miss.get(app) or {}).values()) + sum(e["fail"] for e in (st.get(app) or {}).values())
    order = sorted(apps, key=lambda a: (-weight(a), a))

    fps = Counter(r.get("fp") or "(없음)" for r in queries.values())
    n_out = sum(len(v) for v in outs.values())
    out = [f"# 플랫폼별 도구 피드백 — 최근 {days}일({since:%Y-%m-%d} ~ {until:%Y-%m-%d})", "",
           f"자료 — 감사 기록 `{audit}`(이 기간 {audit_lines:,}줄) · 질의 기록 `{qlog_dir}`(질의 {len(queries):,}개 · 결과 줄 {n_out:,}개"
           + (f" — id 없는 옛 질의 줄 {no_id:,}개는 뺐다" if no_id else "") + f") · 도구 지도 `{source}`.",
           f"손잡이 — 지금 파일의 지문 `{tuning['fingerprint']}`(기본값 `{tuning['base_fingerprint']}` · {tuning['note']}) · "
           "질의 때의 지문 " + (" · ".join(f"`{k}` {n:,}개" for k, n in fps.most_common()) or "—") + ".", "",
           "질의 원문은 싣는다 — 고칠 낱말이 거기 있다. 부른 사람 · 주소는 싣지 않는다. '보정' 은 게이트웨이 search_tools 의 손잡이(손 동의어 · "
           "코어 어휘표 · 품질 가중)와 의미 순위다. 2 · 3절은 같은 호출자가 찾은 뒤 600초 안에 부른 백엔드 도구(찾기 하나에 다섯까지)로 센다.", "",
           "| 플랫폼 | 도구 | 보정 덕에만 | 보이고도 다른 도구 | 결과에 없었는데 불림 | 실패 | 큰 응답 | 인자 설명 | 안 불린 도구 |",
           "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for app in order:
        u = usage.get(app) or {"used": [], "unused": []}
        a = st.get(app) or {}
        g = arg.get(app) or {}
        ratio = f"{100 * g['described_ratio']:.0f}%" if g.get("described_ratio") is not None else "—"
        out.append(f"| {_cell(label.get(app, app))} (`{app}`)" + ("" if app in usage else " · 지금 지도에 없음")
                   + f" | {len(u['used']) + len(u['unused'])} | {len(boost[app]['queries']) if app in boost else 0}"
                   f" | {sum(e['other'] for e in (shown.get(app) or {}).values())}"
                   f" | {sum(e['missing'] for e in (miss.get(app) or {}).values())}"
                   f" | {sum(e['fail'] for e in a.values())}"
                   f" | {sum(1 for e in a.values() if e['chars'] and max(e['chars']) >= big)}"
                   f" | {ratio} | {len(u['unused'])} |")
    for app in order:
        u = usage.get(app) or {"used": [], "unused": []}
        out += _platform_section(app, label.get(app, app), len(u["used"]) + len(u["unused"]), tuning=tuning, boost=boost,
                                 shown=shown, miss=miss, st=st, arg=arg.get(app), unused=u["unused"], days=days, big=big, rows=rows)
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="플랫폼별 도구 피드백 보고서(보정 덕에만 · 보이고도 안 불림 · 밖에서 불림 · 실패 · 큰 응답 · 인자 설명 · 안 불린 도구)")
    ap.add_argument("--days", type=int, default=30, help="최근 며칠(기본 30 — 질의 기록의 굴러가는 창과 같다)")
    ap.add_argument("--audit", default=tur.AUDIT_DEFAULT, help="감사 기록(기본 게이트웨이와 같다)")
    ap.add_argument("--qlog-dir", default=str(QLOG_DIR), help="질의 기록 자리(기본 이 파일 옆 tool_search_eval)")
    ap.add_argument("--tuning", default=str(TUNING), help="손잡이 기본값(덧씌우기는 같은 자리의 search_tuning.local.json)")
    ap.add_argument("--tools-map", help="저장한 /tools-map JSON(주지 않으면 --gateway 에서 받는다)")
    ap.add_argument("--gateway", default="http://127.0.0.1:9110", help="게이트웨이 주소(기본 http://127.0.0.1:9110)")
    ap.add_argument("--platform", action="append", help="이 백엔드 키만(여러 번 줄 수 있다) — 그쪽 주인에게 넘길 때")
    ap.add_argument("--big-chars", type=int, default=50_000, help="큰 응답 기준(글자, 기본 50,000)")
    ap.add_argument("--rows", type=int, default=10, help="표마다 줄 상한(기본 10 — 넘으면 '그 밖 N개' 로 적는다)")
    ap.add_argument("--out", help="보고서를 쓸 파일(주지 않으면 화면)")
    ap.add_argument("--now", help=argparse.SUPPRESS)                  # 시험용 — 기준 시각(ISO)
    a = ap.parse_args(argv)
    until = datetime.fromisoformat(a.now) if a.now else datetime.now(timezone.utc)
    since = until - timedelta(days=a.days)
    tuning_path = Path(a.tuning)
    try:
        tmap, source = tur._tools_map(a.tools_map, a.gateway)
        tuning = load_tuning(tuning_path, tuning_path.with_name(tuning_path.stem + ".local.json"))
        queries, outs, no_id = read_qlog(Path(a.qlog_dir), a.days, until.astimezone(_KST).date())
        seen, lines = tur._seen(a.audit, since)
        st = audit_stats(a.audit, since, _index(tmap))
    except (OSError, ValueError, TypeError, KeyError) as e:
        print(f"✗ 읽지 못했다 — {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    text = report(tmap, tuning=tuning, queries=queries, outs=outs, no_id=no_id, st=st, seen=seen, audit_lines=lines,
                  days=a.days, since=since, until=until, audit=a.audit, qlog_dir=a.qlog_dir, source=source,
                  big=a.big_chars, rows=a.rows, only=a.platform)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
        print(f"✓ {a.out}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
