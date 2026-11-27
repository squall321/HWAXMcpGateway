# 이용 통계 창구의 셈(usage_rollup) — 감사 기록을 KST 날마다 접고 기간으로 낸다(HWAXPortal docs/ops-dashboard M2)
#
# 계정은 example.com 시험 신원만 쓴다 — 이 리포는 GitHub 에 있다. 원장 · 접은 표는 모두 임시 폴더에 만든다(게이트웨이 모듈을 읽지 않는다).
import json
import sqlite3
from contextlib import closing

import pytest

import usage_rollup as ur


def _line(ts, tool, backend, ok=True, ms=10, **kw):
    rec = {"ts": ts, "tool": tool, "backend": backend, "ok": ok, "ms": ms}
    rec.update({k: v for k, v in kw.items() if v is not None})
    return json.dumps(rec, ensure_ascii=False) + "\n"


class Box:
    def __init__(self, tmp_path):
        self.audit = tmp_path / "audit.jsonl"
        self.db = tmp_path / "usage-rollup.sqlite"

    def write(self, *lines, mode="a"):
        with open(self.audit, mode, encoding="utf-8") as f:
            f.write("".join(lines))

    def view(self, since="2026-11-01", until="2026-11-30", **kw):
        return ur.view(self.db, self.audit, {"since": since, "until": until, **kw})

    def calls(self, **kw):
        return {(r["day"], r["backend"], r["tool"], r["via"]): r for r in self.view(**kw)["calls"]}


def _only(rows):
    assert len(rows) == 1, rows
    return rows[0]


# ── 날 ─────────────────────────────────────────────────────────────────────────────────────────────────────
def test_날은_KST_로_가른다(tmp_path):
    """게이트웨이는 UTC 로 적는다 — 14:59:59Z 는 KST 23:59:59, 15:00:00Z 는 다음 날 00:00 이다."""
    box = Box(tmp_path)
    box.write(_line("2026-11-01T14:59:59.000+00:00", "t", "app", via="pat", caller="a@example.com"),
              _line("2026-11-01T15:00:00.000+00:00", "t", "app", via="pat", caller="a@example.com"))
    got = box.calls()
    assert {k[0]: v["calls"] for k, v in got.items()} == {"2026-11-01": 1, "2026-11-02": 1}
    assert box.view(since="2026-11-02", until="2026-11-02")["calls"][0]["day"] == "2026-11-02"


def test_시간대가_없는_ts_는_UTC_로_읽고_못_읽는_줄은_세어_버린다(tmp_path):
    box = Box(tmp_path)
    box.write(_line("2026-11-01T15:30:00", "t", "app"), "{깨진 줄\n", "[1, 2]\n", _line("어제쯤", "t", "app"), "\n")
    v = box.view()
    assert _only(v["calls"])["day"] == "2026-11-02"
    assert (v["audit"]["lines"], v["audit"]["bad"]) == (4, 3), "빈 줄은 줄로 세지 않는다"


# ── 이어 접기 ──────────────────────────────────────────────────────────────────────────────────────────────
def test_다시_물어도_두_번_세지_않고_덧붙은_줄만_더한다(tmp_path):
    box = Box(tmp_path)
    box.write(_line("2026-11-03T01:00:00+00:00", "t", "app"))
    assert _only(box.view()["calls"])["calls"] == 1
    assert _only(box.view()["calls"])["calls"] == 1, "같은 줄을 다시 세면 안 된다"
    box.write(_line("2026-11-03T02:00:00+00:00", "t", "app"), _line("2026-11-03T03:00:00+00:00", "t", "app"))
    v = box.view()
    assert _only(v["calls"])["calls"] == 3 and v["complete"] is True and v["audit"]["lines"] == 3


def test_덜_쓰인_끝_줄은_줄바꿈이_올_때까지_세지_않는다(tmp_path):
    box = Box(tmp_path)
    whole = _line("2026-11-03T01:00:00+00:00", "t", "app")
    half = _line("2026-11-03T02:00:00+00:00", "t", "app")
    box.write(whole, half[:25])
    assert _only(box.view()["calls"])["calls"] == 1
    box.write(half[25:])
    v = box.view()
    assert _only(v["calls"])["calls"] == 2 and v["audit"]["bad"] == 0, "잘린 앞 절반을 깨진 줄로 세고 넘어가면 안 된다"


def test_원장이_바뀌면_처음부터_다시_접는다(tmp_path):
    """줄어든 파일(잘림) · 다른 파일(옮김 · 바꿔치기) — 옛 셈 위에 더하면 두 번 센다."""
    box = Box(tmp_path)
    box.write(*[_line(f"2026-11-03T0{i}:00:00+00:00", "t", "app") for i in range(5)])
    assert _only(box.view()["calls"])["calls"] == 5
    box.write(_line("2026-11-04T01:00:00+00:00", "u", "app"), mode="w")           # 잘리고 새 줄 하나
    assert {k[2]: v["calls"] for k, v in box.calls().items()} == {"u": 1}
    box.audit.unlink()
    box.write(*[_line(f"2026-11-05T0{i}:00:00+00:00", "w", "app") for i in range(8)])     # 다른 파일(더 길다 — 크기로는 못 가른다)
    assert {k[2]: v["calls"] for k, v in box.calls().items()} == {"w": 8}


def test_원장이_없으면_빈_답이고_만들지_않는다(tmp_path):
    box = Box(tmp_path)
    v = box.view()
    assert v["calls"] == [] and v["actors"] == [] and v["complete"] is True and v["audit"]["lines"] == 0
    assert not box.audit.exists()


def test_한_번에_다_못_접으면_complete_가_거짓이고_다음_물음이_잇는다(tmp_path, monkeypatch):
    box = Box(tmp_path)
    box.write(*[_line(f"2026-11-03T01:00:{i:02d}+00:00", "t", "app") for i in range(50)])
    monkeypatch.setattr(ur, "CHUNK_LINES", 20)
    first = ur.view(box.db, box.audit, {"since": "2026-11-01", "until": "2026-11-30"}, budget_s=0.0)
    assert first["complete"] is False and _only(first["calls"])["calls"] == 20, "기한을 넘기면 접은 데까지만 내고 그렇다고 말한다"
    assert first["scanned_through"].startswith("2026-11-03T10:00:19")
    second = ur.view(box.db, box.audit, {"since": "2026-11-01", "until": "2026-11-30"}, budget_s=0.0)
    assert second["complete"] is False and _only(second["calls"])["calls"] == 40
    third = box.view()
    assert third["complete"] is True and _only(third["calls"])["calls"] == 50


# ── 이름 ───────────────────────────────────────────────────────────────────────────────────────────────────
def test_접두가_붙은_이름은_원래_이름으로_접는다(tmp_path):
    """E-2 — 같은 도구가 맨 이름 · 겹침 접두 이름 · 호출 별칭으로 적힌다. 떠 있는 경로표(resolve)가 알면 그 답을, 모르면 접두 규칙을 쓴다."""
    box = Box(tmp_path)
    box.write(_line("2026-11-03T01:00:00+00:00", "cancel_job", "heax-step_forge"),
              _line("2026-11-03T01:00:01+00:00", "heaxstep_forge_cancel_job", "heax-step_forge"),
              _line("2026-11-03T01:00:02+00:00", "sf_alias_cancel", "heax-step_forge"),
              _line("2026-11-03T01:00:03+00:00", "heaxstep_forge_info", "heax-step_forge"))
    routes = {"sf_alias_cancel": ("heax-step_forge", "cancel_job"), "heaxstep_forge_info": ("heax-step_forge", "heaxstep_forge_info")}
    v = ur.view(box.db, box.audit, {"since": "2026-11-01", "until": "2026-11-30"}, resolve=routes.get)
    got = {r["tool"]: r["calls"] for r in v["calls"]}
    assert got == {"cancel_job": 3, "heaxstep_forge_info": 1}, "경로표가 원래 이름이라고 한 것은 접두를 떼지 않는다"


def test_주소가_든_이름은_주소를_떼고_모르는_도구는_한_칸으로_접는다(tmp_path):
    box = Box(tmp_path)
    box.write(_line("2026-11-03T01:00:00+00:00", "rest_call GET /api/projects/123", "step-forge"),
              _line("2026-11-03T01:00:01+00:00", "rest_call GET /api/projects/456", "step-forge"),
              _line("2026-11-03T01:00:02+00:00", "resources/read ui://step_forge/atlas", "heax-step_forge"),
              _line("2026-11-03T01:00:03+00:00", "GET /fig", "_gateway"),
              _line("2026-11-03T01:00:04+00:00", "no_such_tool_xyz", None, ok=False, ms=0, error="unknown tool"),
              _line("2026-11-03T01:00:05+00:00", "secret question text?", None, ok=False, ms=0, error="unknown tool"),
              _line("2026-11-03T01:00:06+00:00", "이상한 이름 <script>", "app"))
    got = {(r["backend"], r["tool"]): r["calls"] for r in box.view()["calls"]}
    assert got == {("step-forge", "rest_call GET"): 2, ("heax-step_forge", "resources/read"): 1, ("_gateway", "GET /fig"): 1,
                   ("", "(unknown)"): 2, ("app", "(other)"): 1}
    blob = json.dumps(box.view(), ensure_ascii=False)
    for leak in ("projects/123", "ui://", "no_such_tool_xyz", "secret question", "script"):
        assert leak not in blob, leak


def test_상태_묻기_도구는_표지를_단다(tmp_path):
    box = Box(tmp_path)
    box.write(_line("2026-11-03T01:00:00+00:00", "deliberate_status", "hwax-deliberation"),
              _line("2026-11-03T01:00:01+00:00", "get_task", "heax-step_forge"),
              _line("2026-11-03T01:00:02+00:00", "risk_job_status", "heax-hwax_risk"),
              _line("2026-11-03T01:00:03+00:00", "search_cards", "ai-data-hub"))
    v = box.view()
    assert {r["tool"]: r["status"] for r in v["calls"]} == {"deliberate_status": True, "get_task": True, "risk_job_status": True,
                                                            "search_cards": False}
    assert "deliberate_status" in v["rules"]["status_tools"] and v["rules"]["status_suffix"] == "_status"


# ── 결과 · 지연 ────────────────────────────────────────────────────────────────────────────────────────────
def test_실패는_앱_쪽과_관문_쪽으로_가른다(tmp_path):
    box = Box(tmp_path)
    box.write(_line("2026-11-03T01:00:00+00:00", "t", "app"),
              _line("2026-11-03T01:00:01+00:00", "t", "app", ok=False, error="upstream: TimeoutError()"),
              _line("2026-11-03T01:00:02+00:00", "t", "app", ok=False, error="app 이 600초 안에 답하지 않았다"),
              _line("2026-11-03T01:00:03+00:00", "t", "app", ok=False, error="forbidden"),
              _line("2026-11-03T01:00:04+00:00", "t", "app", ok=False, error="read-only"),
              _line("2026-11-03T01:00:05+00:00", "t", "app", ok=False, error="뭔가", mode="refused"),
              _line("2026-11-03T01:00:06+00:00", "t", "app", ok=False, error="per-user: RuntimeError('x')"))
    r = _only(box.view()["calls"])
    assert (r["calls"], r["errors_app"], r["errors_gate"]) == (7, 2, 4)


def test_캐시_적중과_큰_응답을_세고_캐시_적중은_지연에서_뺀다(tmp_path):
    box = Box(tmp_path)
    box.write(_line("2026-11-03T01:00:00+00:00", "t", "app", ms=80, chars=120),
              _line("2026-11-03T01:00:01+00:00", "t", "app", ms=0, chars=120, note="cache-hit"),
              _line("2026-11-03T01:00:02+00:00", "t", "app", ms=0, chars=120, note="svc:abcd1234+cache-hit"),
              _line("2026-11-03T01:00:03+00:00", "t", "app", ms=900, chars=ur.BIG_CHARS),
              _line("2026-11-03T01:00:04+00:00", "t", "app", ms=40, ok=False, error="upstream: x"))
    r = _only(box.view()["calls"])
    assert (r["calls"], r["cache"], r["big"], r["chars"], r["chars_max"]) == (5, 2, 1, 360 + ur.BIG_CHARS, ur.BIG_CHARS)
    assert sum(r["lat"]) == 2, "지연은 백엔드에 다녀온 성공 호출만(캐시 적중 · 실패는 뺀다)"
    assert len(r["lat"]) == len(ur.LAT_LE_MS) + 1


def test_분위수는_칸_안_보간_어림이다(tmp_path):
    box = Box(tmp_path)
    box.write(*[_line(f"2026-11-03T01:00:{i:02d}+00:00", "t", "app", ms=ms)
                for i, ms in enumerate([3] * 5 + [70] * 4 + [20000])])
    r = _only(box.view()["calls"])
    assert 0 < r["ms_p50"] <= 5 and 10000 < r["ms_p95"] <= 30000, r
    assert ur.quantile([0] * (len(ur.LAT_LE_MS) + 1), 0.5) is None, "표본이 없으면 값도 없다"
    top = [0] * len(ur.LAT_LE_MS) + [3]
    assert ur.quantile(top, 0.95) == ur.LAT_LE_MS[-1], "마지막 칸(상한 없음)은 그 칸의 아래 끝으로 낸다"


# ── 사람 ───────────────────────────────────────────────────────────────────────────────────────────────────
def test_사람별_날마다_호출_수와_이름_없는_줄을_따로_낸다(tmp_path):
    box = Box(tmp_path)
    box.write(_line("2026-11-03T01:00:00+00:00", "t", "app", via="pat", caller="A@Example.com "),
              _line("2026-11-03T01:00:01+00:00", "u", "app", via="pat", caller="a@example.com"),
              _line("2026-11-03T01:00:02+00:00", "t", "app", via="chat", caller="a@example.com"),
              _line("2026-11-03T01:00:03+00:00", "t", "app", via="gw-token"),
              _line("2026-11-03T16:00:00+00:00", "t", "app", via="pat", caller="b@example.com"))
    v = box.view()
    assert sorted((r["day"], r["caller"], r["via"], r["n"]) for r in v["actors"]) == [
        ("2026-11-03", "a@example.com", "chat", 1), ("2026-11-03", "a@example.com", "pat", 2), ("2026-11-04", "b@example.com", "pat", 1)]
    assert v["anon"] == [{"day": "2026-11-03", "via": "gw-token", "n": 1}]


def test_뺄_계정은_호출_수_지연_사람_줄_모두에서_빠진다(tmp_path):
    box = Box(tmp_path)
    box.write(_line("2026-11-03T01:00:00+00:00", "t", "app", via="pat", caller="tester@example.com", ms=50, chars=10),
              _line("2026-11-03T01:00:01+00:00", "t", "app", via="pat", caller="real@example.com", ms=50, chars=10),
              _line("2026-11-03T01:00:02+00:00", "t", "app", via="pat", caller="real@example.com", ms=50, ok=False, error="upstream: x"))
    r = _only(box.view(exclude=[" Tester@Example.com "])["calls"])
    assert (r["calls"], r["errors_app"], r["chars"], sum(r["lat"])) == (2, 1, 10, 1)
    v = box.view(exclude=["tester@example.com"])
    assert [a["caller"] for a in v["actors"]] == ["real@example.com"] and v["excluded"] == 1
    assert _only(box.view()["calls"])["calls"] == 3, "뺄 계정은 물을 때마다 다시 건다(접은 표는 그대로다)"


def test_청한_도구의_성공_호출만_사람별로_낸다(tmp_path):
    box = Box(tmp_path)
    box.write(_line("2026-11-03T01:00:00+00:00", "create_report_draft", "reportarchive", via="chat", caller="a@example.com"),
              _line("2026-11-03T01:00:01+00:00", "reportarchive_create_report_draft", "reportarchive", via="chat", caller="a@example.com"),
              _line("2026-11-03T01:00:02+00:00", "create_report_draft", "reportarchive", via="chat", caller="a@example.com", ok=False,
                    error="upstream: x"),
              _line("2026-11-03T01:00:03+00:00", "create_report_draft", "reportarchive"),
              _line("2026-11-03T01:00:04+00:00", "search_reports", "reportarchive", via="chat", caller="a@example.com"))
    v = box.view(actor_tools=["create_report_draft"])
    assert v["actor_tools"] == [{"day": "2026-11-03", "caller": "a@example.com", "tool": "create_report_draft", "n": 2}]
    assert box.view()["actor_tools"] == []


def test_인증_실패는_도구_호출과_따로_센다(tmp_path):
    box = Box(tmp_path)
    box.write(_line("2026-11-03T01:00:00+00:00", "POST /mcp", None, ok=False, ms=0, error="unauthorized: expired", ip="203.0.113.5"),
              _line("2026-11-03T01:00:01+00:00", "GET /mcp", None, ok=False, ms=0, error="unauthorized: expired"),
              _line("2026-11-03T01:00:02+00:00", "POST /mcp", None, ok=False, ms=0, error="unauthorized: unverified-token"),
              _line("2026-11-03T01:00:03+00:00", "POST /mcp", None, ok=False, ms=0, error="unauthorized: <b>이상한 사유</b>"))
    v = box.view()
    assert v["calls"] == []
    assert sorted((r["reason"], r["n"]) for r in v["auth"]) == [("expired", 2), ("other", 1), ("unverified-token", 1)]
    assert "203.0.113.5" not in json.dumps(v)


def test_scanned_through_는_파일_차례의_마지막_줄이다(tmp_path):
    """시각이 뒤섞인 줄(앞날로 적힌 시험 줄 등)이 가운데 있어도 '어디까지 읽었나' 는 읽은 자리로 말한다 — 가장 늦은 날의 줄로 말하면 덜 접은 답을
    다 접은 것처럼 읽는다."""
    box = Box(tmp_path)
    box.write(_line("2026-11-03T01:00:00+00:00", "t", "app"), _line("2027-01-01T00:00:00+00:00", "t", "app"),
              _line("2026-11-04T01:00:00+00:00", "t", "app"))
    v = box.view(since="2026-11-01", until="2027-01-31")
    assert v["scanned_through"] == "2026-11-04T10:00:00+09:00" and v["audit"]["last_day"] == "2027-01-01"


def test_칸이_처음_나온_날을_싣는다(tmp_path):
    box = Box(tmp_path)
    box.write(_line("2026-09-01T01:00:00+00:00", "t", "app"),
              _line("2026-09-29T01:00:00+00:00", "t", "app", via="pat", caller="a@example.com", ip="203.0.113.5"),
              _line("2026-10-10T16:00:00+00:00", "t", "app", via="pat", caller="a@example.com", chars=3))
    v = box.view(since="2026-10-01", until="2026-10-31")
    assert v["fields"] == {"caller": "2026-09-29", "via": "2026-09-29", "ip": "2026-09-29", "chars": "2026-10-11"}
    assert (v["audit"]["first_day"], v["audit"]["last_day"]) == ("2026-09-01", "2026-10-11")


# ── 물음 ───────────────────────────────────────────────────────────────────────────────────────────────────
def test_기간은_KST_날_둘이고_틀린_꼴은_거절한다(tmp_path):
    box = Box(tmp_path)
    for bad in ({"since": "2026-11-05", "until": "2026-11-01"}, {"since": "어제", "until": "2026-11-01"},
                {"since": "2026-11-01", "until": "2026-11-31"}, {"since": 20261101, "until": "2026-11-02"},
                {"since": "2026-11-01", "until": "2026-11-02", "exclude": "a@example.com"},
                {"since": "2026-11-01", "until": "2026-11-02", "actor_tools": ["x"] * (ur.ACTOR_TOOLS_MAX + 1)}):
        with pytest.raises(ValueError):
            ur.view(box.db, box.audit, bad)
    with pytest.raises(ValueError):
        ur.view(box.db, box.audit, {"since": "2025-01-01", "until": "2026-11-02"})       # 400일을 넘는다 — 조용히 줄이지 않는다
    v = ur.view(box.db, box.audit, {}, today="2026-11-21")
    assert (v["since"], v["until"]) == ("2026-11-19", "2026-11-21"), "비우면 오늘까지 사흘"


def test_접은_표는_주인만_읽는다(tmp_path):
    box = Box(tmp_path)
    box.write(_line("2026-11-03T01:00:00+00:00", "t", "app", caller="a@example.com"))
    box.view()
    assert (box.db.stat().st_mode & 0o777) == 0o600, "사람별 줄이 든다 — 감사 원장보다 넓게 열지 않는다"
    with closing(sqlite3.connect(box.db)) as c:
        assert c.execute("SELECT SUM(n) FROM calls").fetchone()[0] == 1


# ── 누구의 일(audit_for — OD-52) ───────────────────────────────────────────────────────────────────────────
def test_호출자가_빈_줄의_누구의_일은_따로_내고_이름_없는_줄에서_뺀다(tmp_path):
    box = Box(tmp_path)
    box.write(_line("2026-11-03T01:00:00+00:00", "recommend_agents", "ai-data-hub", via="gw-token", audit_for="A@Example.com"),
              _line("2026-11-03T01:00:01+00:00", "recommend_agents", "ai-data-hub", via="gw-token", audit_for="a@example.com"),
              _line("2026-11-03T01:00:02+00:00", "create_report_draft", "reportarchive", via="gw-token", audit_for="a@example.com"),
              _line("2026-11-03T01:00:03+00:00", "create_report_draft", "reportarchive", via="gw-token", audit_for="a@example.com", ok=False,
                    error="upstream: x"),
              _line("2026-11-03T01:00:04+00:00", "list_agents", "ai-data-hub", via="gw-token"),
              _line("2026-11-03T01:00:05+00:00", "list_agents", "ai-data-hub", via="gw-token", audit_for="이메일 아님"),
              _line("2026-11-03T01:00:06+00:00", "list_agents", "ai-data-hub", via="gw-token", caller="b@example.com", audit_for="a@example.com"))
    v = box.view(actor_tools=["create_report_draft"])
    assert v["actors_for"] == [{"day": "2026-11-03", "user": "a@example.com", "via": "gw-token", "n": 4}]
    assert v["anon"] == [{"day": "2026-11-03", "via": "gw-token", "n": 2}], "꼴이 틀린 주장은 이름 없는 줄로 남는다"
    assert v["actors"] == [{"day": "2026-11-03", "caller": "b@example.com", "via": "gw-token", "n": 1}], "호출자가 있으면 그 줄은 호출자의 것이다"
    assert v["actor_tools_for"] == [{"day": "2026-11-03", "user": "a@example.com", "tool": "create_report_draft", "n": 1}]
    assert v["actor_tools"] == [] and sum(r["calls"] for r in v["calls"]) == 7, "합계 칸은 그대로 센다"
    assert v["fields"]["audit_for"] == "2026-11-03"


def test_뺄_계정은_누구의_일_칸에도_걸린다(tmp_path):
    box = Box(tmp_path)
    box.write(_line("2026-11-03T01:00:00+00:00", "t", "app", via="gw-token", audit_for="tester@example.com", ms=20),
              _line("2026-11-03T01:00:01+00:00", "t", "app", via="gw-token", audit_for="real@example.com", ms=20),
              # 호출자가 있는 줄의 주장은 접기도 버린다 — 남(뺄 계정)의 일이라는 주장이 호출자 본인의 호출을 빼지 못한다
              _line("2026-11-03T01:00:02+00:00", "t", "app", via="gw-token", caller="b@example.com", audit_for="tester@example.com", ms=20))
    v = box.view(exclude=["tester@example.com"])
    assert [a["user"] for a in v["actors_for"]] == ["real@example.com"] and _only(v["calls"])["calls"] == 2 and sum(_only(v["calls"])["lat"]) == 2
    assert [a["caller"] for a in v["actors"]] == ["b@example.com"]
    assert v["excluded"] == 1


def test_옛_꼴의_접은_표는_버리고_원장_처음부터_다시_접는다(tmp_path):
    box = Box(tmp_path)
    with closing(sqlite3.connect(box.db)) as c, c:             # 판 표지 없는 첫 판의 표 — 누구의 일 칸이 없다
        c.execute("CREATE TABLE calls (day TEXT, backend TEXT, tool TEXT, via TEXT, outcome TEXT, caller TEXT, n INTEGER, chars INTEGER,"
                  " chars_max INTEGER, cache INTEGER, big INTEGER, PRIMARY KEY (day, backend, tool, via, outcome, caller))")
        c.execute("CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
        c.execute("INSERT INTO calls VALUES ('2026-11-03', 'app', 't', '', 'ok', '', 99, 0, 0, 0, 0)")
        c.execute("INSERT INTO meta VALUES ('offset', '999999')")
    box.write(_line("2026-11-03T01:00:00+00:00", "t", "app", via="gw-token", audit_for="a@example.com"))
    v = box.view()
    assert _only(v["calls"])["calls"] == 1 and v["actors_for"][0]["user"] == "a@example.com", "옛 셈 · 읽은 자리를 버렸다"
    with closing(sqlite3.connect(box.db)) as c:
        assert c.execute("SELECT v FROM meta WHERE k = 'schema'").fetchone()[0] == ur.SCHEMA_VERSION
    assert _only(box.view()["calls"])["calls"] == 1, "새 꼴에서는 다시 버리지 않는다"


# ── 채택 셈(HWAXPortal docs/mcp-modernize M0 · M3) — 보기 · prompts · 자원 읽기의 날마다 수를 디스크에 ─────────────────────────────────────
def test_채택_셈은_날_갈래_열쇠마다_올리고_기간으로_낸다(tmp_path):
    p = tmp_path / "usage-adoption.sqlite"
    assert ur.adopt_query(p, "2026-11-01", "2026-11-30") == [] and not p.exists(), "원장이 없으면 만들지 않는다"
    for day, kind, key in (("2026-11-26", "tools_list", "full"), ("2026-11-27", "tools_list", "full"), ("2026-11-27", "tools_list", "full"),
                           ("2026-11-27", "view_purpose", "drop-prep"), ("2026-11-27", "prompt", "purpose-drop-prep"),
                           ("2026-11-27", "resource", "skill:drop-prep")):
        ur.adopt_note(p, kind, key, day=day)
    assert oct(p.stat().st_mode & 0o777) == "0o600", "주인만"
    got = ur.adopt_query(p, "2026-11-27", "2026-11-27")
    assert got == [{"day": "2026-11-27", "kind": "prompt", "key": "purpose-drop-prep", "n": 1},
                   {"day": "2026-11-27", "kind": "resource", "key": "skill:drop-prep", "n": 1},
                   {"day": "2026-11-27", "kind": "tools_list", "key": "full", "n": 2},
                   {"day": "2026-11-27", "kind": "view_purpose", "key": "drop-prep", "n": 1}]
    s = ur.adopt_summary(p, days=7, today="2026-11-27")
    assert (s["since"], s["until"]) == ("2026-11-21", "2026-11-27") and s["by_kind"]["tools_list"] == {"full": 3}
    with pytest.raises(ValueError):
        ur.adopt_note(p, "nope", "x")
    ur.adopt_note(p, "prompt", "질의 글은 싣지 않는다 <script>", day="2026-11-27")
    assert {r["key"] for r in ur.adopt_query(p, "2026-11-27", "2026-11-27") if r["kind"] == "prompt"} == {"purpose-drop-prep", "(other)"}


def test_이용_통계_창구는_채택_셈을_주면_같은_기간의_adoption_을_덧붙인다(tmp_path):
    box = Box(tmp_path)
    box.write(_line("2026-11-27T01:00:00+00:00", "x", "sf"))
    a = tmp_path / "usage-adoption.sqlite"
    ur.adopt_note(a, "tools_list", "light", day="2026-11-27")
    ur.adopt_note(a, "tools_list", "light", day="2026-10-01")
    assert "adoption" not in box.view(), "주지 않으면 종전과 같다"
    out = ur.view(box.db, box.audit, {"since": "2026-11-01", "until": "2026-11-30"}, adoption_path=a)
    assert out["adoption"] == [{"day": "2026-11-27", "kind": "tools_list", "key": "light", "n": 1}]
