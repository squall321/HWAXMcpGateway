# 앱별 '오래 안 불린 도구' 보고서 — 감사 기록과 도구 지도를 맞대는지(HWAXPortal docs/request-1029 E-3)
import json
import subprocess
import sys
from pathlib import Path

import tool_usage_report as tur

HERE = Path(__file__).resolve().parent
NOW = "2026-10-29T00:00:00+00:00"

# /tools-map 꼴 — map 은 노출 이름 → 백엔드, apps 는 라벨
TMAP = {
    "map": {"list_parts": "heax-step_forge", "heaxstep_forge_get": "heax-step_forge", "mesh_it": "heax-step_forge",
            "get_material": "heax-materialtwin_web", "old_tool": "heax-materialtwin_web",
            "search_tools": "_gateway", "save_conversation": "_gateway"},
    "apps": [{"app": "heax-step_forge", "label": "StepForge", "tool_count": 3, "reachable": True},
             {"app": "heax-materialtwin_web", "label": "MaterialTwin", "tool_count": 2, "reachable": True},
             {"app": "_gateway", "label": "게이트웨이", "tool_count": 2, "reachable": True}],
}


def _audit(tmp_path, rows) -> Path:
    p = tmp_path / "audit.jsonl"
    lines = [json.dumps(r, ensure_ascii=False) if isinstance(r, dict) else r for r in rows]
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _run(tmp_path, rows, *extra) -> str:
    (tmp_path / "map.json").write_text(json.dumps(TMAP, ensure_ascii=False), encoding="utf-8")
    out = tmp_path / "r.md"
    assert tur.main(["--tools-map", str(tmp_path / "map.json"), "--audit", str(_audit(tmp_path, rows)), "--now", NOW,
                     "--out", str(out), *extra]) == 0
    return out.read_text(encoding="utf-8")


def test_기간_안에_한_번이라도_나온_도구만_불린_것이다(tmp_path):
    rows = [
        {"ts": "2026-10-20T01:00:00.123+00:00", "tool": "list_parts", "backend": "heax-step_forge", "ok": True, "ms": 5,
         "caller": "someone@corp.example", "ip": "10.1.2.3"},
        {"ts": "2026-10-21T01:00:00+00:00", "tool": "get_material", "backend": "heax-materialtwin_web", "ok": False, "ms": 0,
         "error": "forbidden"},                                                   # 거부도 '부르려 했다'
        {"ts": "2026-09-01T00:00:00+00:00", "tool": "old_tool", "backend": "heax-materialtwin_web", "ok": True, "ms": 1},  # 기간 밖
        {"ts": "2026-10-22T00:00:00+00:00", "tool": "mesh_it", "backend": "heax-other", "ok": True, "ms": 1},  # 다른 백엔드의 같은 이름
        {"ts": "2026-10-22T00:00:00+00:00", "tool": "search_tools", "backend": None, "ok": True, "ms": 1},
        "깨진 줄 {",
        {"tool": "list_parts"},                                                    # 시각 없음
    ]
    md = _run(tmp_path, rows)
    assert "도구 5개 중 30일 안에 불린 것 2개 · 안 불린 것 3개(60%)" in md, md
    assert "| StepForge (`heax-step_forge`) | 3 | 1 | 2 |" in md and "| MaterialTwin (`heax-materialtwin_web`) | 2 | 1 | 1 |" in md
    sf = md.split("## StepForge (`heax-step_forge`) — 안 불린 2개", 1)[1]
    assert "`heaxstep_forge_get` · `mesh_it`" in sf.split("##", 1)[0], "다른 백엔드의 같은 이름은 이 도구로 세지 않는다"
    assert "`old_tool`" in md.split("## MaterialTwin", 1)[1], "기간 밖 호출은 세지 않는다"
    assert "_gateway" not in md and "search_tools" not in md, "게이트웨이 자체 도구는 세지 않는다"
    assert "someone@corp.example" not in md and "10.1.2.3" not in md, "부른 사람 · 주소는 싣지 않는다"
    assert "이 기간 4줄" in md, "깨진 줄 · 시각 없는 줄 · 기간 밖 줄은 세지 않는다"


def test_별칭과_접두가_붙기_전의_맨_이름도_그_도구로_센다(tmp_path):
    rows = [
        {"ts": "2026-10-20T00:00:00+00:00", "tool": "get", "backend": "heax-step_forge", "ok": True, "ms": 1},   # 겹치기 전 맨 이름
        {"ts": "2026-10-20T00:00:00+00:00", "tool": "heaxstep_forge_mesh_it", "backend": "heax-step_forge", "ok": True, "ms": 1},  # 별칭
        {"ts": "2026-10-20T00:00:00", "tool": "list_parts", "backend": "heax-step_forge", "ok": True, "ms": 1},   # 시간대 없는 옛 줄
    ]
    md = _run(tmp_path, rows)
    assert "| StepForge (`heax-step_forge`) | 3 | 3 | 0 |" in md, md
    assert "## StepForge" not in md, "다 불린 앱은 목록 절을 쓰지 않는다"


def test_기간을_바꾸면_그만큼_본다(tmp_path):
    rows = [{"ts": "2026-09-01T00:00:00+00:00", "tool": "old_tool", "backend": "heax-materialtwin_web", "ok": True, "ms": 1}]
    md = _run(tmp_path, rows, "--days", "60")
    assert md.startswith("# 오래 안 불린 도구 — 최근 60일(2026-08-30 ~ 2026-10-29 UTC)") and "| 2 | 1 | 1 |" in md, md


def test_못_읽으면_2_로_끝나고_까닭을_말한다(tmp_path):
    p = subprocess.run([sys.executable, str(HERE / "tool_usage_report.py"), "--tools-map", str(tmp_path / "없음.json"),
                        "--audit", str(tmp_path / "없음.jsonl")], capture_output=True, text=True, timeout=60)
    assert p.returncode == 2 and "읽지 못했다" in p.stderr and "FileNotFoundError" in p.stderr, p.stderr


def test_감사_경로는_게이트웨이와_같은_규칙이다():
    import gateway  # noqa: PLC0415
    assert tur.AUDIT_DEFAULT == gateway.AUDIT_PATH
