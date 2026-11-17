# 도구 등록 훑기 — 데이터 주인 추정 · 보고만 의심 · D1 질의 점검 · 옛 키를 짚고 아무것도 쓰지 않는지(HWAXPortal docs/request-1117 GW-04)
import json
import subprocess
import sys
from pathlib import Path

import tool_registration_scan as trs

HERE = Path(__file__).resolve().parent

TMAP = {
    "map": {"list_analysis_runs": "reportarchive", "get_analysis_summary": "reportarchive", "get_analysis_peaks": "reportarchive",
            "compare_analysis_runs": "reportarchive", "create_report": "reportarchive",
            "report_worst_cases": "heax-kooremapper_mcp", "report_summary": "heax-kooremapper_mcp",
            "list_parts": "heax-step_forge", "fullangle_drop_simulation": "smart-twin-mcp", "drop_result_digest": "heax-paper_ingest",
            "figure_to_report": "_gateway", "search_tools": "_gateway", "stepforgeprod_old_view": "stepforge-prod"},
    "orig": {"stepforgeprod_old_view": "old_view"},
    "apps": [{"app": "reportarchive", "label": "Report Archive"}, {"app": "heax-kooremapper_mcp", "label": "DynaForge"}],
}
SNAP = {"tools": [{"name": "create_report", "description": "보고서를 만든다"},
                  {"name": "fullangle_drop_simulation", "description": "전각도 낙하 해석을 클러스터에 돌린다"}]}


def _rows(res, app):
    return {r["tool"]: r for r in res["apps"][app]}


def test_D1_분석_실행_도구_넷을_짚고_결과의_주인을_DynaForge_로_적는다():
    res = trs.scan(TMAP, SNAP)
    ra = _rows(res, "reportarchive")
    for n in ("list_analysis_runs", "get_analysis_summary", "get_analysis_peaks", "compare_analysis_runs"):
        assert ra[n]["rules"] == ["D1"] and ra[n]["owner"] == "heax-kooremapper_mcp", n
        assert "1위가 아니어야 한다" in " ".join(ra[n]["reasons"]), n
    assert ra["get_analysis_summary"]["report_only"], "보고 낱말(summary) + 주인이 다른 앱"
    assert ra["create_report"]["owner"] == "reportarchive" and not ra["create_report"]["report_only"], "제 데이터의 보고 함수는 짚지 않는다"
    (d1,) = res["intents"]
    assert d1["id"] == "D1" and set(d1["present"]) == {"list_analysis_runs", "get_analysis_summary", "get_analysis_peaks", "compare_analysis_runs"}
    assert "전각도 낙하 결과" in d1["queries"]


def test_주인_앱의_도구와_해석을_돌리기만_하는_도구는_D1_로_짚지_않고_결과를_담는_다른_앱_도구는_짚는다():
    res = trs.scan(TMAP, SNAP)
    assert not _rows(res, "heax-kooremapper_mcp")["report_worst_cases"]["rules"], "주인 앱"
    assert not _rows(res, "smart-twin-mcp")["fullangle_drop_simulation"]["rules"], "돌리기만 한다(결과 낱말 없음)"
    other = _rows(res, "heax-paper_ingest")["drop_result_digest"]
    assert other["rules"] == ["D1"] and other["owner"] == "heax-kooremapper_mcp" and other["report_only"]
    gw_fig = _rows(res, "_gateway")["figure_to_report"]
    assert gw_fig["report_only"] and "게이트웨이 자체" in " ".join(gw_fig["reasons"])
    assert not _rows(res, "_gateway")["search_tools"]["report_only"]
    assert res["retired_live"] == [{"app": "stepforge-prod", "now": "heax-step_forge"}], "옛 키(app_keys.json)로 붙은 앱"
    assert _rows(res, "stepforge-prod")["stepforgeprod_old_view"]["original"] == "old_view"


def test_마크다운은_앱마다_표와_질의_점검을_싣고_flagged_는_짚은_것만():
    md = trs.render(trs.scan(TMAP, SNAP))
    assert "## reportarchive — Report Archive" in md and "| 도구 | 원래 이름 | 데이터 주인(추정) | 보고만 의심 | 까닭 |" in md
    assert "### D1 — 결과의 주인 DynaForge(heax-kooremapper_mcp)" in md and "list_analysis_runs" in md
    assert "## 옛 키로 아직 붙어 있는 앱(GW-05)" in md
    short = trs.render(trs.scan(TMAP, SNAP), flagged_only=True)
    assert "| list_parts |" in md and "| list_parts |" not in short and "| get_analysis_peaks |" in short


def test_명령줄은_파일만_읽고_아무것도_쓰지_않는다(tmp_path):
    m = tmp_path / "map.json"
    m.write_text(json.dumps(TMAP), encoding="utf-8")
    before = sorted(p.name for p in tmp_path.iterdir())
    r = subprocess.run([sys.executable, str(HERE / "tool_registration_scan.py"), "--tools-map", str(m), "--app", "reportarchive",
                        "--format", "json"], capture_output=True, text=True, cwd=tmp_path, timeout=60)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert set(out["apps"]) == {"reportarchive"} and sorted(p.name for p in tmp_path.iterdir()) == before
    bad = subprocess.run([sys.executable, str(HERE / "tool_registration_scan.py"), "--tools-map", str(tmp_path / "none.json")],
                         capture_output=True, text=True, timeout=60)
    assert bad.returncode == 2 and "읽지 못했다" in bad.stderr
