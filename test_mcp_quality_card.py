# 앱별 MCP 품질 카드(mcp_quality_card.py)의 셈을 실제 tools/list · /tools-map · 감사 원장 꼴로 보는 시험
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import mcp_quality_card as qc

# 실제 dev tools/list 의 꼴 그대로 — FastMCP 1.x 가 낸 스키마(title 만 · anyOf null) · 앱이 Field 로 설명을 단 스키마 · $defs 참조 · 껍데기 outputSchema
TOOLS = [
    {"name": "search_reports", "description": "본문으로 보고서를 찾는다. 2026-11-21 결정 RS-6 이후 25건까지.",
     "inputSchema": {"type": "object", "properties": {
         "query": {"title": "Query", "type": "string"},
         "limit": {"default": 8, "title": "Limit", "type": "integer"},
         "last_days": {"anyOf": [{"type": "integer"}, {"type": "null"}], "default": None, "title": "Last Days"}},
         "required": ["query"]},
     "outputSchema": {"type": "object", "properties": {"result": {"type": "string"}}, "required": ["result"]}},
    {"name": "laminate_check", "description": "x" * 1200,
     "annotations": {"readOnlyHint": True, "idempotentHint": True},
     "inputSchema": {"type": "object", "$defs": {"Ply": {"type": "object", "properties": {
         "angle": {"type": "number", "description": "적층 각(도)", "minimum": -90, "maximum": 90},
         "material": {"type": "string", "enum": ["cfrp", "gfrp"], "description": "재료"}}}},
         "properties": {
             "plies": {"type": "array", "description": "층 목록", "items": {"$ref": "#/$defs/Ply"}},
             "options": {"type": "object", "description": "자유형 옵션"}}},
     "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}, "margin": {"type": "number"}}}},
    {"name": "heaxlam_delete_case", "description": "짧다", "annotations": {"readOnlyHint": False, "destructiveHint": True},
     "inputSchema": {"type": "object", "properties": {"case_id": {"type": "string", "description": "지울 케이스"}}}},
    {"name": "save_conversation", "description": "본문으로 보고서를 찾는다. 2026-11-21 결정 RS-6 이후 25건까지.",
     "inputSchema": {"type": "object", "properties": {}}},
]
TMAP = {
    "map": {"search_reports": "reportarchive", "laminate_check": "heax-lam", "heaxlam_delete_case": "heax-lam"},
    "write": ["heaxlam_delete_case"], "routine_read": ["laminate_check"], "panel_read": [], "unclassified": ["search_reports"],
    "orig": {"heaxlam_delete_case": "delete_case"},
    "apps": [{"app": "heax-lam", "label": "Laminate", "tool_count": 2, "reachable": True},    # 실제 /tools-map 꼴 — 열쇠는 app
             {"app": "reportarchive", "label": "RA", "tool_count": 1, "reachable": True}],
}


def _card():
    return qc.catalog_card(TOOLS, TMAP)


def test_top_level_arg_description_counts_fastmcp_title_only_as_missing():
    ra = _card()["reportarchive"]
    assert ra["args"] == 3 and ra["args_described"] == 0
    assert ra["arg_described_ratio"] == 0.0
    assert ra["worst_args"] == ["search_reports"]


def test_nested_args_follow_defs_ref_and_count_enum_bounds_free_objects():
    lam = _card()["heax-lam"]
    # 맨 위 plies · options · case_id = 3 개 모두 설명 있음
    assert lam["args"] == 3 and lam["args_described"] == 3
    # 중첩 — plies · options · case_id + Ply 의 angle · material = 5
    assert lam["nested_args"] == 5 and lam["nested_described"] == 5
    assert lam["enum_args"] == 1
    assert lam["numeric_args"] == 1 and lam["numeric_bounded"] == 1
    assert lam["free_objects"] == 1          # options 는 속성 없는 객체
    assert lam["output_schema_real"] == 1    # laminate_check 는 필드가 있는 결과 꼴


def test_annotations_and_gateway_classes():
    lam = _card()["heax-lam"]
    assert (lam["ro_true"], lam["ro_false"], lam["ro_none"]) == (1, 1, 0)
    assert lam["destructive"] == 1 and lam["idempotent"] == 1
    assert lam["gw_write"] == 1 and lam["routine_read"] == 1 and lam["prefixed"] == 1
    assert lam["ro_annotated_ratio"] == 1.0
    ra = _card()["reportarchive"]
    assert ra["ro_none"] == 1 and ra["unclassified"] == 1 and ra["output_schema_real"] == 0   # {"result"} 껍데기는 세지 않는다


def test_description_length_history_and_shared_across_apps():
    c = _card()
    assert c["heax-lam"]["desc_gt1000"] == 1 and c["heax-lam"]["desc_lt100"] == 1
    assert c["reportarchive"]["desc_history"] == 1
    # 같은 설명이 RA 와 게이트웨이 로컬(_gateway) 두 앱에 있다
    assert c["reportarchive"]["desc_shared_other_app"] == 1 and c["_gateway"]["desc_shared_other_app"] == 1


def test_audit_card_skips_connection_rejects_and_counts_empty_reasons(tmp_path: Path):
    p = tmp_path / "audit.jsonl"
    rows = [
        {"ts": "2026-11-27T01:00:00.000+00:00", "tool": "search_reports", "backend": "reportarchive", "ok": True, "ms": 100, "chars": 60000},
        {"ts": "2026-11-27T01:00:01.000+00:00", "tool": "search_reports", "backend": "reportarchive", "ok": False, "ms": 300, "error": None},
        {"ts": "2026-11-27T01:00:02.000+00:00", "tool": "search_reports", "backend": "reportarchive", "ok": False, "ms": 200, "error": "app:bad_args"},
        {"ts": "2026-11-27T01:00:03.000+00:00", "tool": "POST /mcp", "backend": None, "ok": False, "error": "unauthorized: expired"},
        {"ts": "2026-10-01T01:00:00.000+00:00", "tool": "search_reports", "backend": "reportarchive", "ok": False},
    ]
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\nnot json\n", encoding="utf-8")
    a = qc.audit_card(p, days=30, now=datetime(2026, 11, 27, 12, tzinfo=timezone.utc))
    assert set(a) == {"reportarchive"}                       # 연결 단계 거절 · 기간 밖 · 깨진 줄은 뺀다
    r = a["reportarchive"]
    assert (r["calls"], r["fail"], r["fail_no_reason"]) == (3, 2, 1)
    assert r["over_50k"] == 1 and r["ms_max"] == 300


def test_build_card_offline_files_and_no_description_text(tmp_path: Path):
    cat, tm = tmp_path / "tools.json", tmp_path / "tmap.json"
    cat.write_text(json.dumps(TOOLS), encoding="utf-8")
    tm.write_text(json.dumps(TMAP), encoding="utf-8")
    out = tmp_path / "card.json"
    assert qc.main(["--catalog", str(cat), "--tools-map", str(tm), "--audit", str(tmp_path / "none.jsonl"), "--out", str(out)]) == 0
    card = json.loads(out.read_text(encoding="utf-8"))
    assert card["total"]["tools"] == 4
    assert [a["app"] for a in card["apps"]][0] == "heax-lam"            # 도구 수가 많은 앱 먼저
    assert {a["app"]: a["label"] for a in card["apps"]}["heax-lam"] == "Laminate"
    assert "보고서를 찾는다" not in out.read_text(encoding="utf-8")        # 설명 원문을 싣지 않는다


def test_label_reads_the_real_tools_map_key_app_and_old_key_shape():
    card = qc.build_card(TOOLS, TMAP, {})
    assert {a["app"]: a["label"] for a in card["apps"]} == {"heax-lam": "Laminate", "reportarchive": "RA", "_gateway": None}
    old = {**TMAP, "apps": [{"key": "heax-lam", "label": "Laminate"}]}
    assert {a["app"]: a["label"] for a in qc.build_card(TOOLS, old, {})["apps"]}["heax-lam"] == "Laminate", "옛 꼴(key)도 읽는다"


def test_gateway_filled_annotations_and_args_are_not_counted_as_the_apps_own():
    tools = [{"name": "query_voc", "description": "d", "annotations": {"readOnlyHint": True},
              "inputSchema": {"type": "object", "properties": {"product": {"type": "string", "description": "제품 코드"},
                                                               "limit": {"type": "integer", "description": "앱이 쓴 설명"}}}}]
    tmap = {"map": {"query_voc": "signalforge"}, "apps": [{"app": "signalforge", "label": "SignalForge"}],
            "gateway_annotated": ["query_voc"], "gateway_filled": {"query_voc": ["product"]},
            "tool_class": {"query_voc": {"class": "read", "source": "confirmed_list"}}}
    sf = qc.catalog_card(tools, tmap)["signalforge"]
    assert (sf["ro_true"], sf["ro_none"], sf["ro_gateway"]) == (0, 1, 1), "게이트웨이가 실은 표지는 앱 표지 없음으로 센다"
    assert (sf["args"], sf["args_described"], sf["args_gateway_filled"]) == (2, 1, 1)
    assert sf["nested_described"] == 1 and sf["cls_read"] == 1 and sf["cls_unknown"] == 0
    total = qc.build_card(tools, tmap, {})["total"]
    assert total["args_gateway_filled"] == 1 and total["ro_gateway"] == 1 and total["arg_described_ratio"] == 0.5
