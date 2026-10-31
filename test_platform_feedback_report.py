# 플랫폼별 피드백 보고서 — 질의 기록 · 감사 · 손잡이 · 도구 지도를 플랫폼마다 맞대는지(HWAXPortal docs/request-1029 E-8)
import json
from pathlib import Path

import platform_feedback_report as pfr

NOW = "2026-10-29T00:00:00+00:00"          # KST 로 10-29 09:00 — 질의 기록의 오늘은 10-29
KR = "heax-kooremapper_mcp"
SF = "signalforge"

TMAP = {
    "map": {"run_drop": KR, "heaxkooremapper_mcp_get_job": KR, "old_drop": KR,
            "search_voc": SF, "defect_profile": SF, "search_tools": "_gateway"},
    "apps": [{"app": KR, "label": "KooRemapper", "tool_count": 3, "reachable": True},
             {"app": SF, "label": "SignalForge", "tool_count": 2, "reachable": True},
             {"app": "_gateway", "label": "게이트웨이", "tool_count": 1, "reachable": True}],
    "arg_scores": {"threshold": 0.3, "total": {"apps": 2, "tools": 5, "args": 14, "described": 6},
                   "apps": [{"app": KR, "tools": 3, "args": 10, "described": 2, "unit_or_range": 1, "described_ratio": 0.2,
                             "unit_or_range_ratio": 0.1, "worst": [{"tool": "run_drop", "args": 6, "described": 0}]},
                            {"app": SF, "tools": 2, "args": 4, "described": 4, "unit_or_range": 2, "described_ratio": 1.0,
                             "unit_or_range_ratio": 0.5, "worst": []}]},
}

TUNING = {
    "_doc": ["시험 손잡이"], "version": 1,
    "switches": {"synonyms": True},
    "weights": {"name": 4, "desc_cap": 3, "app": 1, "coverage": 1, "write_penalty": 0.5, "quality_per_word": 2},
    "synonyms": {"낙하": {"to": ["drop", "impact"], "owner": KR, "source_fix": None},
                 "보고서": {"to": ["report"], "owner": None, "source_fix": None},
                 "불량": {"to": ["defect"], "owner": SF, "source_fix": "search_voc 설명 첫 줄에 '불량' 을 넣는다"}},
}


def _q(d, qid, q, top, via=None, boost=None, fp="fp-now"):
    r = {"d": d, "ts": 1, "id": qid, "q": q, "mode": "substring", "top": top, "fp": fp}
    if via:
        r["via"] = via
    if boost:
        r["boost_only"] = boost
    return r


def _o(d, qid, t, r, ok=True):
    return {"d": d, "ts": 2, "o": qid, "t": t, "r": r, "ok": ok}


QLOG = {
    "queries-2026-10-28.local.jsonl": [
        _q("2026-10-28", "a1", "낙하 해석 결과", [f"{KR}:run_drop", f"{SF}:search_voc"],
           via={f"{KR}:run_drop": ["syn:낙하"]}, boost=[f"{KR}:run_drop"]),
        _o("2026-10-28", "a1", f"{KR}:get_job", None),                         # 결과에 없던 도구를 불렀다
        _q("2026-10-28", "a2", "불량 현황", [f"{SF}:defect_profile", f"{SF}:search_voc"],
           via={f"{SF}:search_voc": ["syn:불량"]}, boost=[f"{SF}:search_voc"]),
        _o("2026-10-28", "a2", f"{SF}:search_voc", 2),                          # 상위 다섯에서 불렸다
        {"d": "2026-10-28", "q": "옛 일회성 질의", "mode": "substring", "top": [f"{KR}:run_drop"]},   # id 가 없다 — 뺀다
    ],
    "queries-2026-10-29.local.jsonl": [
        _q("2026-10-29", "a3", "낙하 보고서 | 표", [f"{KR}:run_drop"],
           via={f"{KR}:run_drop": ["syn:낙하", "syn:보고서"]}, boost=[f"{KR}:run_drop"], fp="fp-old"),
        _q("2026-10-29", "a4", "drop job", [f"{KR}:run_drop", f"{SF}:defect_profile"]),
        _o("2026-10-29", "a4", f"{KR}:old_drop", 7, ok=False),                 # 6위 아래에서 불렸다
    ],
    "queries-2026-09-01.local.jsonl": [                                        # 창(30일) 밖
        _q("2026-09-01", "z9", "낙하 옛날", [f"{KR}:run_drop"], via={f"{KR}:run_drop": ["syn:낙하"]}, boost=[f"{KR}:run_drop"]),
    ],
}

AUDIT = [
    {"ts": "2026-10-20T01:00:00.123+00:00", "tool": "run_drop", "backend": KR, "ok": True, "ms": 5, "chars": 120_000},
    {"ts": "2026-10-20T01:01:00.000+00:00", "tool": "run_drop", "backend": KR, "ok": True, "ms": 5, "chars": 2_000},
    {"ts": "2026-10-20T01:02:00.000+00:00", "tool": "run_drop", "backend": KR, "ok": False, "ms": 5},
    {"ts": "2026-10-20T01:03:00.000+00:00", "tool": "run_drop", "backend": KR, "ok": False, "ms": 5,
     "error": "RuntimeError('backend session down')"},
    {"ts": "2026-10-21T00:00:00.000+00:00", "tool": "heaxkooremapper_mcp_get_job", "backend": KR, "ok": False, "ms": 1,
     "error": "refused: no-connection"},
    {"ts": "2026-10-22T00:00:00.000+00:00", "tool": "search_voc", "backend": SF, "ok": False, "ms": 1,
     "error": "as:someone@example.com"},
    {"ts": "2026-10-22T00:01:00.000+00:00", "tool": "search_voc", "backend": SF, "ok": True, "ms": 1, "chars": 500,
     "caller": "someone@example.com"},
    {"ts": "2026-09-01T00:00:00.000+00:00", "tool": "old_drop", "backend": KR, "ok": False, "ms": 1, "error": "옛 실패"},
    "이건 JSON 이 아니다",
]


def _run(tmp_path, *extra, qlog=QLOG, audit=AUDIT, tuning=TUNING, overlay=None) -> str:
    (tmp_path / "map.json").write_text(json.dumps(TMAP, ensure_ascii=False), encoding="utf-8")
    qdir = tmp_path / "qlog"
    qdir.mkdir(exist_ok=True)
    for name, rows in qlog.items():
        (qdir / name).write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    (tmp_path / "audit.jsonl").write_text("\n".join(json.dumps(r, ensure_ascii=False) if isinstance(r, dict) else r
                                                    for r in audit) + "\n", encoding="utf-8")
    (tmp_path / "search_tuning.json").write_text(json.dumps(tuning, ensure_ascii=False), encoding="utf-8")
    if overlay is not None:
        (tmp_path / "search_tuning.local.json").write_text(overlay if isinstance(overlay, str) else json.dumps(overlay, ensure_ascii=False),
                                                           encoding="utf-8")
    out = tmp_path / "r.md"
    assert pfr.main(["--tools-map", str(tmp_path / "map.json"), "--audit", str(tmp_path / "audit.jsonl"), "--qlog-dir", str(qdir),
                     "--tuning", str(tmp_path / "search_tuning.json"), "--now", NOW, "--out", str(out), *extra]) == 0
    return out.read_text(encoding="utf-8")


def _section(text: str, app: str) -> str:
    start = text.index(f"(`{app}`) — 지금 도구")
    nxt = text.find("\n## ", start)
    return text[start:nxt if nxt > 0 else None]


def test_요약표는_플랫폼마다_한_줄이고_피드백이_많은_쪽이_먼저다(tmp_path):
    text = _run(tmp_path)
    rows = [ln for ln in text.splitlines() if ln.startswith("| KooRemapper") or ln.startswith("| SignalForge")]
    assert rows[0].startswith("| KooRemapper"), "보정 덕에만 2 · 다른 도구 2 · 밖에서 불림 1 · 실패 2 가 SignalForge 보다 많다"
    cells = [c.strip() for c in rows[0].split("|")[1:-1]]
    assert cells[1:] == ["3", "2", "2", "1", "2", "1", "20%", "1"], cells
    assert "게이트웨이" not in "".join(rows) and "`_gateway`" not in text, "게이트웨이 자체 도구는 플랫폼이 아니다"


def test_자료_줄은_기간_안의_수와_뺀_옛_줄과_질의_때의_지문을_말한다(tmp_path):
    text = _run(tmp_path)
    assert "질의 4개 · 결과 줄 3개 — id 없는 옛 질의 줄 1개는 뺐다" in text, "창 밖(09-01) 질의와 id 없는 줄은 세지 않는다"
    assert "이 기간 7줄" in text, "감사는 기간(30일) 안 · JSON 인 줄만"
    assert "질의 때의 지문 `fp-now` 3개 · `fp-old` 1개" in text
    fp = pfr._json_fp(TUNING)
    assert f"지금 파일의 지문 `{fp}`(기본값 `{fp}` · 덧씌우기 없음)" in text


def test_보정_덕에만은_규칙마다_고칠_것을_붙인다(tmp_path):
    kr, sf = _section(_run(tmp_path), KR), _section(_run(tmp_path), SF)
    assert "### 1. 보정 덕에만 찾아진 질의 — 2개" in kr
    row = next(ln for ln in kr.splitlines() if ln.startswith("| 손 동의어 '낙하'"))
    assert "| 2 |" in row and "`run_drop`(2)" in row and "도구 설명 · 별칭에 넣을 낱말 — '낙하'" in row, row
    assert "「낙하 해석 결과」" in row and "「낙하 보고서 \\| 표」" in row, "질의 예를 싣고 표 칸의 | 는 막는다"
    row = next(ln for ln in kr.splitlines() if ln.startswith("| 손 동의어 '보고서'"))
    assert "일반 낱말 — 주인 없음" in row, row
    row = next(ln for ln in sf.splitlines() if ln.startswith("| 손 동의어 '불량'"))
    assert "search_voc 설명 첫 줄에 '불량' 을 넣는다" in row, "손잡이 파일의 source_fix 가 있으면 그것"
    assert "낙하 옛날" not in kr, "창 밖 질의"


def test_비코어_낮추기는_보정_덕에만의_규칙이_아니다(tmp_path):
    """게이트웨이가 검색 손잡이 noncore_demote 를 켜면 질의 기록 via 에 demote:noncore 가 남는다(HWAXPortal docs/request-1029 E-2 E2-5). 점수를 뺀
    규칙이라 '보정 덕에만 찾아진' 규칙 칸에 싣지 않는다 — 실으면 그쪽에 고칠 것이 없는 줄을 고치라고 내민다."""
    qlog = {"queries-2026-10-29.local.jsonl": [
        _q("2026-10-29", "b1", "불량 고장모드 현황", [f"{SF}:search_voc"], via={f"{SF}:search_voc": ["demote:noncore", "syn:불량"]},
           boost=[f"{SF}:search_voc"])]}
    sf = _section(_run(tmp_path, qlog=qlog), SF)
    assert "### 1. 보정 덕에만 찾아진 질의 — 1개" in sf
    row = next(ln for ln in sf.splitlines() if ln.startswith("| 손 동의어 '불량'"))
    assert "| 1 |" in row, row
    assert "demote" not in sf and "비코어 낮추기" not in sf, sf
    assert pfr._rule_text("demote:noncore", SF, pfr.load_tuning(pfr.TUNING, pfr.TUNING.with_name("없음.local.json")))[0].startswith("비코어 낮추기")


def test_보이고도_안_불림과_밖에서_불림을_가른다(tmp_path):
    kr, sf = _section(_run(tmp_path), KR), _section(_run(tmp_path), SF)
    row = next(ln for ln in kr.splitlines() if ln.startswith("| `run_drop` | 3 |"))
    cells = [c.strip() for c in row.split("|")[1:-1]]
    assert cells[1:5] == ["3", "0", "2", "1"], "a1 · a4 는 다른 도구를 불렀고 a3 은 아무것도 안 불렀다"
    assert "### 3. 상위 다섯 밖에서 불림 — 도구 2개" in kr
    row = next(ln for ln in kr.splitlines() if ln.startswith("| `get_job` |"))
    assert [c.strip() for c in row.split("|")[1:-1]][1:4] == ["1", "0", "1"] and "「낙하 해석 결과」" in row, row
    row = next(ln for ln in kr.splitlines() if ln.startswith("| `old_drop` |"))
    assert [c.strip() for c in row.split("|")[1:-1]][1:4] == ["0", "1", "0"], row
    row = next(ln for ln in sf.splitlines() if ln.startswith("| `search_voc` |"))
    assert [c.strip() for c in row.split("|")[1:-1]][1:5] == ["2", "1", "1", "0"], "a2 에선 불렸고 a1 에선 다른 도구"


def test_실패는_플랫폼_쪽만_세고_신원이_든_사유는_싣지_않는다(tmp_path):
    text = _run(tmp_path)
    kr, sf = _section(text, KR), _section(text, SF)
    assert "### 4. 실패(플랫폼 쪽) — 도구 1개 · 2건" in kr
    row = next(ln for ln in kr.splitlines() if ln.startswith("| `run_drop` | 4 | 2 |"))
    assert "50%" in row and "isError" in row and "RuntimeError('backend session down')" in row, row
    assert "게이트웨이 · 권한에서 막힌 호출 1건은 실패에서 뺐다" in kr, "refused: 는 그쪽 탓이 아니다"
    assert "옛 실패" not in kr, "창 밖"
    assert "someone" not in text and "@" not in text, "부른 사람 · 신원이 든 사유는 싣지 않는다"
    assert "(사유 글에 신원이 들어 싣지 않음)(1)" in sf


def test_큰_응답_인자_설명_안_불린_도구(tmp_path):
    kr = _section(_run(tmp_path), KR)
    row = next(ln for ln in kr.splitlines() if ln.startswith("| `run_drop` | 2 |"))
    assert [c.strip() for c in row.split("|")[1:-1]] == ["`run_drop`", "2", "2,000", "120,000", "120,000", "1"], row
    assert "인자 10개 중 설명 있는 것 2개(20%) · 그중 단위 · 범위까지 든 것 1개. 설명이 가장 빈 도구 — `run_drop`(인자 6개 중 설명 0개)." in kr
    assert "### 7. 30일 안 불린 도구 — 1개" in kr and "`old_drop`" in kr.split("### 7.")[1], "old_drop 은 창 밖에서만 불렸다"
    kr = _section(_run(tmp_path, "--big-chars", "200000"), KR)
    assert "### 5. 큰 응답(기준 200,000자) — 도구 0개" in kr


def test_플랫폼을_고르면_그쪽만_내고_줄_상한은_남은_수를_적는다(tmp_path):
    text = _run(tmp_path, "--platform", SF)
    assert "(`signalforge`) — 지금 도구" in text and f"(`{KR}`)" not in text
    text = _run(tmp_path, "--rows", "1")
    kr = _section(text, KR)
    assert "| … 그 밖 규칙 1개 |" in kr and "| … 그 밖 도구 1개 |" in kr, "자른 것은 말한다"


def test_지도에_없는_앱의_기록도_빼지_않는다(tmp_path):
    qlog = {**QLOG, "queries-2026-10-27.local.jsonl": [_q("2026-10-27", "b1", "떠난 앱", ["gone-app:tool"])]}
    text = _run(tmp_path, qlog=qlog)
    assert "| gone-app (`gone-app`) · 지금 지도에 없음 |" in text, "기록에 있는 앱이 지도에서 빠졌으면 그렇다고 적는다"


def test_덧씌우기는_게이트웨이와_같이_얹고_깨지면_버린다(tmp_path):
    text = _run(tmp_path, overlay={"synonyms": {"낙하": {"source_fix": "run_drop 설명에 '낙하'"}, "보고서": None}})
    eff = pfr._merge_patch(TUNING, {"synonyms": {"낙하": {"source_fix": "run_drop 설명에 '낙하'"}, "보고서": None}})
    assert f"지금 파일의 지문 `{pfr._json_fp(eff)}`(기본값 `{pfr._json_fp(TUNING)}` · 덧씌우기 있음)" in text
    row = next(ln for ln in _section(text, KR).splitlines() if ln.startswith("| 손 동의어 '낙하'"))
    assert "run_drop 설명에 '낙하'" in row
    row = next(ln for ln in _section(text, KR).splitlines() if ln.startswith("| syn:보고서") or ln.startswith("| 손 동의어 '보고서'"))
    assert "→ ?" in row, "덧씌우기가 지운 낱말 — 기록에는 남았지만 지금 손잡이에 없다"
    for broken in ("{깨진 JSON", json.dumps({"weights": {"name": "넷"}}), json.dumps([1, 2])):
        text = _run(tmp_path, overlay=broken)
        assert f"지금 파일의 지문 `{pfr._json_fp(TUNING)}`" in text and "덧씌우기를 버리고 기본값만" in text, broken


def test_읽지_못하면_2_를_돌려준다(tmp_path, capsys):
    assert pfr.main(["--tools-map", str(tmp_path / "없음.json"), "--audit", str(tmp_path / "a"), "--qlog-dir", str(tmp_path),
                     "--tuning", str(tmp_path / "t.json"), "--now", NOW]) == 2
    assert "읽지 못했다" in capsys.readouterr().err


def test_추적하는_손잡이_파일을_그대로_읽는다():
    t = pfr.load_tuning(pfr.TUNING, pfr.TUNING.with_name("없는-덧씌우기.local.json"))
    assert len(t["synonyms"]) >= 70 and t["fingerprint"] == t["base_fingerprint"], "리포의 search_tuning.json"
    owned = {k: e for k, e in t["synonyms"].items() if e["owner"]}
    assert owned and all(isinstance(e["to"], list) and e["to"] for e in owned.values())
    assert Path(pfr.QLOG_DIR).name == "tool_search_eval"
