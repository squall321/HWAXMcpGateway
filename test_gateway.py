# 게이트웨이 그룹 인가 순수 로직 단위 테스트 (네트워크·백엔드 불필요).
import json

import mcp.types as types
import pytest

import gateway as gw


@pytest.fixture(autouse=True)
def _no_prod_audit(monkeypatch, tmp_path):
    """감사원장 격리 — **모든 시험에 자동으로** 건다.

    ⚠ 안 걸면 시험이 운영 `audit.jsonl`(→ /data/svc/mcp-gateway/)에 `reportarchive_trash_report
    ok:true` 같은 **일어난 적 없는 파괴 도구 성공**을 남긴다. 실제 호출과 모양이 똑같아서 "누가
    보고서를 버렸나" 를 감사원장으로 물으면 허구가 잡힌다(2026-09-18 검토에서 29줄 발견).
    시험마다 격리하던 관례가 있었는데 새 시험 하나가 빠뜨렸다 — 그래서 자동으로 바꿨다.
    `AUDIT_PATH` 를 직접 거는 시험은 이 뒤에 다시 걸므로 그대로 돈다.
    """
    monkeypatch.setattr(gw, "AUDIT_PATH", str(tmp_path / "audit.jsonl"))


def _tool(name: str) -> types.Tool:
    return types.Tool(name=name, description="", inputSchema={"type": "object"})


def test_parse_groups():
    assert gw._parse_groups(None) == []
    assert gw._parse_groups("") == []
    assert gw._parse_groups("a") == ["a"]
    assert gw._parse_groups(" a , b ,, c ") == ["a", "b", "c"]   # 공백·빈값 제거


def test_backend_allowed(monkeypatch):
    monkeypatch.setattr(gw, "POLICY", {"pub": [], "sec": ["admin"], "voc": ["analyst", "admin"]})
    assert gw._backend_allowed("pub", []) is True            # allowed_groups 비었음 → 공개
    assert gw._backend_allowed("sec", []) is False           # 그룹 없음 → fail-closed
    assert gw._backend_allowed("sec", ["user"]) is False     # 교집합 없음 → 차단
    assert gw._backend_allowed("sec", ["admin"]) is True
    assert gw._backend_allowed("voc", ["analyst"]) is True
    assert gw._backend_allowed("unknown", []) is True        # 정책 미지정 백엔드 → 공개(기본)


def test_visible_tools(monkeypatch):
    monkeypatch.setattr(gw, "POLICY", {"ra": [], "sf": ["analyst"]})
    monkeypatch.setattr(gw, "exposed_tools", [_tool("t_pub"), _tool("t_sec")])
    monkeypatch.setattr(gw, "route", {"t_pub": ("ra", "t_pub"), "t_sec": ("sf", "t_sec")})
    # ⚠ `_visible_tools` 는 게이트웨이 **로컬 도구**(save_conversation 등)를 늘 덧붙인다 —
    # 그것들은 백엔드 인가와 무관하므로 백엔드에서 온 것만 골라 본다(이 테스트의 관심사다).
    local = {t.name for t in (gw.SAVE_CONV_TOOL, gw.SEARCH_CONV_TOOL, gw.LIST_APPS_TOOL,
                              gw.SEARCH_TOOLS_TOOL, gw.INVOKE_TOOL,
                              gw.BROWSE_EXPERTS_TOOL, gw.USE_EXPERTS_TOOL, gw.VERIFY_TOOL,
                              gw.REST_CATALOG_TOOL, gw.REST_CALL_TOOL)}

    def seen(groups):
        return {t.name for t in gw._visible_tools(groups)} - local

    assert seen([]) == {"t_pub"}                    # 공개만
    assert seen(["analyst"]) == {"t_pub", "t_sec"}
    assert seen(["other"]) == {"t_pub"}             # 무관 그룹 → 공개만


# ── 호출 전용 별칭 — 노출 이름이 남의 앱 가동 여부로 뒤집히지 않게 ────────────
class _Res:
    def __init__(self, tools): self.tools = tools


class _Sess:
    def __init__(self, tools): self._t = tools
    async def list_tools(self): return _Res(self._t)


class _B:
    """_aggregate 가 쓰는 최소 백엔드 — _ready.wait() 와 session.list_tools() 뿐."""
    def __init__(self, tools):
        import asyncio
        self.session = _Sess(tools)
        self._failed = None
        self._ready = asyncio.Event()
        self._ready.set()


def _aggregate_with(monkeypatch, spec: dict[str, list[str]]):
    import asyncio
    monkeypatch.setattr(gw, "backends", {k: _B([_tool(n) for n in v]) for k, v in spec.items()})
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "route", {})
    monkeypatch.setattr(gw, "alias_route", {})
    asyncio.run(gw._aggregate())


def test_exposed_names_do_not_flip_when_another_app_goes_away(monkeypatch):
    """**노출 이름이 제3자 앱의 가동 여부로 뒤집히면 안 된다.**

    `_aggregate` 는 접두어를 "지금 붙어 있는 백엔드들 사이에서 겹칠 때만" 붙인다.
    그래서 같은 이름을 내는 다른 앱이 재배포로 잠깐 빠지면 그 창에서 이름이 bare 로
    돌아가고, 클라이언트가 외운 반대쪽은 `unknown tool` 이 된다(실측: StepForge 의
    cancel_job·system_capabilities·system_status·whoami 가 DynaForge 하나에 물려
    있었다). 접두어 별칭은 **양쪽 상태 모두에서** 같은 백엔드로 풀려야 한다.
    """
    both = {"heax-step_forge": ["cancel_job", "list_parts"],
            "kooremapper_mcp": ["cancel_job"]}
    alone = {"heax-step_forge": ["cancel_job", "list_parts"]}

    _aggregate_with(monkeypatch, both)
    assert gw.route.get("cancel_job") is None, "충돌할 땐 bare 가 없다(현행 동작)"
    assert gw.alias_route["heaxstep_forge_cancel_job"] == ("heax-step_forge", "cancel_job")
    listed_both = {t.name for t in gw.exposed_tools}

    _aggregate_with(monkeypatch, alone)
    assert gw.route["cancel_job"] == ("heax-step_forge", "cancel_job"), "혼자면 bare 다"
    # ⚠ 여기가 요점 — 별칭은 **뒤집히지 않는다**
    assert gw.alias_route["heaxstep_forge_cancel_job"] == ("heax-step_forge", "cancel_job")
    listed_alone = {t.name for t in gw.exposed_tools}

    # 별칭은 **목록에 안 올린다** — 올리면 게이트웨이 전체가 개명되는 것과 같다
    assert "heaxstep_forge_cancel_job" not in listed_alone
    assert "heaxstep_forge_list_parts" not in listed_both | listed_alone


def test_bare_names_keep_their_meaning(monkeypatch):
    """별칭이 기존 이름을 **가리지 않는다** — `route` 를 먼저 본다.

    극단적으로, 어떤 백엔드가 남의 별칭과 같은 이름의 도구를 내더라도 bare 가 이긴다.
    """
    import asyncio

    # ⚠ **해석 순서를 테스트 안에 다시 쓰면 안 된다** — 처음 쓴 판이 그랬고, gateway.py 의
    # 순서를 뒤집어도 6개가 전부 통과했다(관문이 장식이었다). `_call_tool` 을 실제로 불러
    # **어느 백엔드가 받았는지**로 판정한다.
    mine = _CallB(["list_parts"])
    other = _CallB(["heaxstep_forge_list_parts"])       # 남의 별칭과 같은 이름
    monkeypatch.setattr(gw, "backends", {"heax-step_forge": mine, "other": other})
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "route", {})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    asyncio.run(gw._aggregate())

    assert gw.route["heaxstep_forge_list_parts"] == ("other", "heaxstep_forge_list_parts")
    asyncio.run(gw._call_tool("heaxstep_forge_list_parts", {}))
    assert other.session.calls == ["heaxstep_forge_list_parts"], \
        "route 가 먼저다 — 기존 이름의 뜻이 안 바뀐다"
    assert mine.session.calls == [], f"별칭이 기존 이름을 가로챘다: {mine.session.calls}"


def test_aliases_do_not_change_the_visible_catalogue(monkeypatch):
    """별칭은 tools/list·`/tools-map` 에 안 잡힌다 — 개수·드리프트 검사가 그대로다."""
    monkeypatch.setattr(gw, "POLICY", {})
    _aggregate_with(monkeypatch, {"heax-step_forge": ["a", "b"], "kooremapper_mcp": ["b", "c"]})
    listed = {t.name for t in gw.exposed_tools}
    assert listed == set(gw.route), "노출 목록과 route 가 1:1 이다"
    assert len(gw.alias_route) == 4, "별칭은 백엔드×도구 전부"
    assert not (listed & (set(gw.alias_route) - set(gw.route))), "별칭이 목록에 새지 않는다"


# ── invoke_tool 의 파괴 도구 차단이 별칭으로 뚫리지 않는가 ────────────────────
class _CallSess:
    """받은 호출을 기록한다 — **반환값이 아니라 피호출자 기록**으로 판정한다."""
    def __init__(self, tools):
        self._t = tools
        self.calls: list[str] = []

    async def list_tools(self): return _Res(self._t)

    async def call_tool(self, original, args, read_timeout_seconds=None):
        self.calls.append(original)
        return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])


class _CallB:
    def __init__(self, tools):
        import asyncio
        self.url, self.headers = "http://stub/mcp", {}
        self.session = _CallSess([_tool(n) for n in tools])
        self._failed, self._gen = None, 0
        self._ready = asyncio.Event(); self._ready.set()


def test_invoke_tool_deny_survives_the_call_only_alias(monkeypatch):
    """**파괴 도구 차단은 호출자가 준 이름이 아니라 해석된 원본으로 한다.**

    호출 전용 별칭 `<백엔드키>_<도구>` 는 `delete_`·`cancel_` 로 **시작할 수가 없다**.
    차단을 caller 문자열로만 보면 별칭이 그대로 우회로가 된다 — 실측으로 라이브 462개
    중 파괴 도구 9개가 별칭 도입만으로 invoke_tool 로 부를 수 있게 됐었다(충돌 접두어로
    노출된 2개는 그 전부터 뚫려 있었다).
    ⚠ 기존 테스트 6개도, 별칭 회귀 3개도 `_call_tool` 을 **한 번도 안 불렀다** —
    이 리포가 반복해 밟은 "이 경로를 덮는 테스트 0개" 다.
    """
    import asyncio

    b = _CallB(["delete_project", "cancel_job", "list_parts"])
    monkeypatch.setattr(gw, "backends", {"heax-step_forge": b})
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "route", {})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    asyncio.run(gw._aggregate())

    def invoke(name):
        return asyncio.run(gw._call_tool("invoke_tool", {"name": name, "arguments": {}}))

    assert invoke("delete_project").isError, "bare 는 원래 막힌다"
    assert invoke("heaxstep_forge_delete_project").isError, "별칭으로도 막혀야 한다"
    assert invoke("heaxstep_forge_cancel_job").isError, "별칭으로도 막혀야 한다"
    # ⚠ 요점 — 백엔드까지 **한 번도 안 갔어야** 한다(반환값만 보면 못 잡는다)
    assert b.session.calls == [], f"파괴 도구가 백엔드까지 갔다: {b.session.calls}"
    # 파괴 계열이 아니면 별칭으로도 그대로 된다 — **과차단 금지**
    assert not invoke("heaxstep_forge_list_parts").isError
    assert b.session.calls == ["list_parts"]


def test_an_alias_collision_is_not_silent(monkeypatch, caplog):
    """별칭이 겹치면 **조용히 마지막 승자를 고르지 않는다.**

    `key.replace('-','')` 는 `heax-step`+`forge_x` 와 `heax-step_forge`+`x` 를 같은
    별칭으로 뭉갠다. PER_USER_SSO 백엔드면 남의 앱 자격증명이 발급된다. 라이브에는
    지금 충돌이 0건이라 동작은 안 바꾸고 보이게만 한다.
    """
    import logging
    with caplog.at_level(logging.WARNING, logger="hwax-mcp-gateway"):
        _aggregate_with(monkeypatch, {"heax-step_forge": ["cancel_job"],
                                      "heax-step": ["forge_cancel_job"]})
    assert any("alias collision" in r.message for r in caplog.records), \
        f"충돌을 조용히 넘겼다 — {[r.message for r in caplog.records]}"


# ── save_conversation 이 meta 를 포털까지 옮기는지 ──────────────────────────────
# ⚠ 종전 _msg() 는 role/content/persona/round 만 옮겨 meta 를 조용히 버렸다. MCP 심의가 반박
#   구조를 만들어도 포털 관계도·이어하기 조항 승계에 닿지 않았다 — 이 테스트가 그 게이트를 지킨다.
def _drive_save(monkeypatch, messages):
    import asyncio
    from types import SimpleNamespace as NS

    sent = {}

    class _Resp:
        status_code = 200
        def json(self): return {"id": "c-1"}

    class _Cli:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None, headers=None):
            sent["body"] = json
            return _Resp()

    monkeypatch.setattr(gw, "_portal_api_base", lambda: "http://portal")
    monkeypatch.setattr(gw.httpx, "AsyncClient", _Cli)
    monkeypatch.setattr(gw, "_audit", lambda *a, **k: None)
    monkeypatch.setattr(gw, "_low", NS(request_context=NS(request=NS(headers={"authorization": "Bearer t"}))))
    asyncio.run(gw._save_conversation({"title": "심의", "messages": messages}))
    return sent["body"]["messages"]


def test_save_conversation_meta_를_옮긴다(monkeypatch):
    rb = [{"target": "sim-solder-fatigue", "quote": "사이클 800회에서 크랙이 관통한다", "counter": "가속시험 한정",
           "basis": "JESD22-A104"}]
    out = _drive_save(monkeypatch, [
        {"role": "persona", "persona": "a", "round": 2, "content": "x", "meta": {"rebut": rb}},
        {"role": "persona", "persona": "b", "round": 3, "content": "y", "meta": {"non_negotiable": "양산 금형 변경 불가"}},
    ])
    assert out[0]["meta"]["rebut"][0]["target"] == "sim-solder-fatigue"
    assert out[1]["meta"]["non_negotiable"] == "양산 금형 변경 불가"


def test_save_conversation_meta_는_알려진_칸만_잘라서(monkeypatch):
    big = [{"target": "t" * 500, "quote": "q" * 500, "counter": "c" * 500, "basis": "b" * 500, "junk": 1}] * 9
    out = _drive_save(monkeypatch, [
        {"role": "persona", "persona": "a", "content": "x", "meta": {"rebut": big, "evil": "x" * 99999}},
        {"role": "persona", "persona": "b", "content": "y", "meta": "문자열은 meta 가 아니다"},
        {"role": "persona", "persona": "c", "content": "z"},
    ])
    m = out[0]["meta"]
    assert set(m) == {"rebut"}                               # 모르는 칸은 옮기지 않는다
    assert len(m["rebut"]) == 4                              # 웹 경로와 같은 상한
    r = m["rebut"][0]
    assert (len(r["target"]), len(r["quote"]), len(r["counter"]), len(r["basis"])) == (60, 80, 160, 60)
    assert "junk" not in r
    assert "meta" not in out[1] and "meta" not in out[2]    # dict 아니면·없으면 칸 자체를 안 만든다


# ── 도구 영역 분류(tool_areas.json) ──────────────────────────────────────────────
# 손으로 고치는 파일이라 **조용한** 실패가 위험하다 — JSON 중복 키는 파이썬이 뒤엣것으로 말없이
# 덮고, 정의 안 된 영역을 가리키면 UI 에 라벨 없는 칸이 생긴다. 그 둘을 여기서 막는다.
def _load_areas_strict():
    import json as _j
    from pathlib import Path as _P

    def _no_dupes(pairs):
        keys = [k for k, _ in pairs]
        dup = {k for k in keys if keys.count(k) > 1}
        assert not dup, f"tool_areas.json 중복 키(뒤엣것이 조용히 이긴다): {sorted(dup)}"
        return dict(pairs)

    return _j.loads((_P(gw.__file__).parent / "tool_areas.json").read_text(encoding="utf-8"),
                    object_pairs_hook=_no_dupes)


def test_tool_areas_파일이_온전하다():
    import re as _re
    tx = _load_areas_strict()
    keys = [a["key"] for a in tx["areas"]]
    assert len(keys) == len(set(keys)), "영역 키 중복"
    assert all(a.get("label") for a in tx["areas"]), "라벨 없는 영역 — UI 에 빈 칸이 뜬다"
    refs = list(tx["apps"].values()) + list(tx["tools"].values()) + [a for _, a in tx["patterns"]]
    assert set(refs) <= set(keys), f"정의 안 된 영역을 가리킨다: {sorted(set(refs) - set(keys))}"
    for p, _ in tx["patterns"]:
        _re.compile(p)


def test_정적_백엔드는_앱_기본값이_있다():
    # 정적 백엔드(APP_META)가 기본값 없이 붙으면 그 앱 도구 전부가 미분류로 떨어진다.
    tx = _load_areas_strict()
    missing = [k for k in gw.APP_META if k not in tx["apps"]]
    assert not missing, f"영역 기본값 없는 정적 앱: {missing}"


def test_영역_판정_순서는_도구_패턴_앱(monkeypatch, tmp_path):
    f = tmp_path / "tool_areas.json"
    f.write_text(json.dumps({
        "areas": [{"key": k, "label": k} for k in ("cad", "mesh", "system")],
        "apps": {"heax-step_forge": "cad"},
        "patterns": [["_whoami$", "system"]],
        "tools": {"mesh_report": "mesh", "odd_whoami": "cad"},
    }), encoding="utf-8")
    monkeypatch.setattr(gw, "_AREAS_PATH", f)
    monkeypatch.setattr(gw, "_AREAS_CACHE", {"mtime": None, "data": {}})
    assert gw._area_of("find_parts", "heax-step_forge") == "cad"          # 앱 기본값
    assert gw._area_of("mesh_report", "heax-step_forge") == "mesh"        # 도구 지정이 앱을 이긴다
    assert gw._area_of("heaxstep_forge_whoami", "heax-step_forge") == "system"  # 패턴이 앱을 이긴다
    assert gw._area_of("odd_whoami", "heax-step_forge") == "cad"          # 도구 지정이 패턴도 이긴다
    assert gw._area_of("x", "unknown-app") == ""                          # 미분류는 빈 문자열


def test_깨진_분류표는_게이트웨이를_죽이지_않는다(monkeypatch, tmp_path):
    f = tmp_path / "tool_areas.json"
    f.write_text("{ 깨진 json", encoding="utf-8")
    monkeypatch.setattr(gw, "_AREAS_PATH", f)
    monkeypatch.setattr(gw, "_AREAS_CACHE", {"mtime": None, "data": {}})
    assert gw._area_of("find_parts", "heax-step_forge") == ""   # 분류 없이 — 전부 미분류로 드러난다
    assert gw._area_meta() == []


def test_list_tool_apps_영역보기(monkeypatch, tmp_path):
    import asyncio
    f = tmp_path / "tool_areas.json"
    f.write_text(json.dumps({
        "areas": [{"key": "cad", "label": "CAD"}, {"key": "mesh", "label": "메시"}],
        "apps": {"heax-step_forge": "cad"}, "patterns": [], "tools": {"mesh_report": "mesh"},
    }), encoding="utf-8")
    monkeypatch.setattr(gw, "_AREAS_PATH", f)
    monkeypatch.setattr(gw, "_AREAS_CACHE", {"mtime": None, "data": {}})

    class _S:
        session = object()
    monkeypatch.setattr(gw, "backends", {"heax-step_forge": _S(), "secret": _S()})
    monkeypatch.setattr(gw, "exposed_tools", [_tool("find_parts"), _tool("mesh_report"), _tool("s_tool")])
    monkeypatch.setattr(gw, "route", {"find_parts": ("heax-step_forge", "find_parts"),
                                      "mesh_report": ("heax-step_forge", "mesh_report"),
                                      "s_tool": ("secret", "s_tool")})
    monkeypatch.setattr(gw, "POLICY", {"secret": ["admin"]})
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    res = asyncio.run(gw._list_tool_apps({"by": "area"}))
    body = json.loads(res.content[0].text)
    by = {a["area"]: a for a in body["areas"]}
    assert by["cad"]["tools"] == ["find_parts"] and by["mesh"]["tools"] == ["mesh_report"]
    assert "s_tool" not in json.dumps(body), "권한 없는 앱의 도구가 영역 보기에 새어 나왔다"
    assert body["hidden_no_access_or_down"] == 1


def test_knox_bridge_와_plm_defect_도구는_미분류로_떨어지지_않는다(monkeypatch):
    """cae00 실측(2026-10-08) — /tools-map 미분류 70개 안에 bridge_* 6개가 전부 들어 있었고, plm-defect 의 quality
    영역은 박스 작업트리에만 있었다. **추적 파일 그대로** 영역 보기를 돌린다(change-request-8-10 #20)."""
    import asyncio
    monkeypatch.setattr(gw, "_AREAS_CACHE", {"mtime": None, "data": {}})

    class _S:
        session = object()
    monkeypatch.setattr(gw, "backends", {"knox-bridge": _S(), "plm-defect": _S()})
    monkeypatch.setattr(gw, "exposed_tools", [_tool("bridge_mail_search"), _tool("plm_case_detail")])
    monkeypatch.setattr(gw, "route", {"bridge_mail_search": ("knox-bridge", "bridge_mail_search"),
                                      "plm_case_detail": ("plm-defect", "plm_case_detail")})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    assert gw._area_of("bridge_mail_search", "knox-bridge") == "system"
    assert gw._area_of("plm_case_detail", "plm-defect") == "quality"
    body = json.loads(asyncio.run(gw._list_tool_apps({"by": "area"})).content[0].text)
    by = {a["area"]: a for a in body["areas"]}
    assert "" not in by, f"미분류로 떨어진 도구: {by.get('', {}).get('tools')}"
    assert "bridge_mail_search" in by["system"]["tools"]      # 게이트웨이 자체 도구(_gateway)와 같은 칸이다
    assert by["quality"]["tools"] == ["plm_case_detail"]
    # 영역이 정의돼 있어야 라벨이 선다 — apps 줄만 먼저 나가면 UI 에 라벨 없는 칸이 생긴다
    assert by["quality"]["label"] == "품질·불량 이력" and "PLM" in by["quality"]["description"]


# ── 포털 권한 정책(HWAXPortal docs/access-control) ────────────────────────────
import asyncio  # noqa: E402

import httpx  # noqa: E402


def _mock_http(monkeypatch, handler):
    real = httpx.AsyncClient
    monkeypatch.setattr(gw.httpx, "AsyncClient",
                        lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr(gw, "_portal_api_base", lambda: "http://portal")


def test_포털_권한_정책은_allowed_groups_와_함께_본다(monkeypatch):
    monkeypatch.setattr(gw, "POLICY", {"sf": [], "sec": ["admin"]})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {"sf": ["plat:stepforge"], "sec": ["plat:risk"]})
    assert gw._backend_allowed("sf", ["feat:chat"]) is False
    assert gw._backend_allowed("sf", ["plat:stepforge"]) is True
    assert gw._backend_allowed("sec", ["plat:risk"]) is False, "둘 다 통과해야 한다"
    assert gw._backend_allowed("sec", ["admin", "plat:risk"]) is True
    assert gw._backend_allowed("free", []) is True, "정책이 없는 백엔드는 종전대로 공개"


def test_권한_정책은_포털에서_받아_디스크에_남기고_포털이_죽으면_직전_값으로(monkeypatch, tmp_path):
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_CACHE_FILE", tmp_path / "ap.json")
    _mock_http(monkeypatch, lambda req: httpx.Response(200, json={"backends": {"sf": ["plat:stepforge"]}}))
    assert asyncio.run(gw._refresh_access_policy()) is True
    assert gw._ACCESS_POLICY == {"sf": ["plat:stepforge"]}
    assert json.loads((tmp_path / "ap.json").read_text(encoding="utf-8")) == {"sf": ["plat:stepforge"]}

    def boom(req):
        raise httpx.ConnectError("portal down")
    _mock_http(monkeypatch, boom)
    assert asyncio.run(gw._refresh_access_policy()) is False
    assert gw._ACCESS_POLICY == {"sf": ["plat:stepforge"]}, "실패하면 직전 정책을 지킨다(풀지 않는다)"
    gw._ACCESS_POLICY.clear()
    gw._load_access_cache()
    assert gw._ACCESS_POLICY == {"sf": ["plat:stepforge"]}, "재기동 때 포털이 없어도 캐시로 막는다"


def test_PAT_호출자는_포털의_지금_권한을_쓴다(monkeypatch):
    monkeypatch.setattr(gw, "_ENT_CACHE", {})
    monkeypatch.setattr(gw, "_ENT_LAST", {})
    calls = []

    def ok(req):
        calls.append(dict(req.url.params))
        return httpx.Response(200, json={"keys": ["feat:chat"]})
    _mock_http(monkeypatch, ok)
    assert asyncio.run(gw._portal_access("u@corp.com", ["mes-user"]))["keys"] == ["feat:chat"]
    assert asyncio.run(gw._portal_access("u@corp.com", ["mes-user"]))["keys"] == ["feat:chat"]
    assert len(calls) == 1 and calls[0] == {"email": "u@corp.com", "groups": "mes-user"}, "캐시"

    gw._ENT_CACHE.clear()
    def boom(req):
        raise httpx.ConnectError("portal down")
    _mock_http(monkeypatch, boom)
    assert asyncio.run(gw._portal_access("u@corp.com", ["mes-user"]))["keys"] == ["feat:chat"], \
        "포털이 죽으면 직전 값"
    _mock_http(monkeypatch, lambda req: httpx.Response(404))
    assert asyncio.run(gw._portal_access("new@corp.com", [])) is None, \
        "권한 기능 이전 포털 — PAT 값 그대로 쓰게 None"
    assert gw._is_synthetic("plat:stepforge") and not gw._is_synthetic("portal-admin")


def test_그룹_헤더_없는_내부_서비스는_사람_권한_정책을_받지_않는다(monkeypatch):
    monkeypatch.setattr(gw, "POLICY", {"sf": [], "sec": ["admin"]})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {"sf": ["plat:stepforge"], "sec": ["plat:risk"]})
    assert gw._backend_allowed("sf", [gw.SERVICE_GROUP]) is True
    assert gw._backend_allowed("sec", [gw.SERVICE_GROUP]) is False, "설정 allowed_groups 는 그대로 본다"

def test_list_tool_apps_는_권한없는_앱을_아예_안_보여준다(monkeypatch):
    """앱 목록도 영역 보기와 같은 규칙 — 못 쓰는 앱은 이름도 도구도 내보내지 않는다.
    예전엔 accessible:false 로 딱지만 붙여 도구 이름을 다 실었고, 모델이 그걸 계획에 넣었다."""
    class _S:
        session = object()
    monkeypatch.setattr(gw, "backends", {"open_app": _S(), "secret": _S()})
    monkeypatch.setattr(gw, "exposed_tools", [_tool("find_parts"), _tool("s_tool")])
    monkeypatch.setattr(gw, "route", {"find_parts": ("open_app", "find_parts"),
                                      "s_tool": ("secret", "s_tool")})
    monkeypatch.setattr(gw, "POLICY", {"secret": ["admin"]})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_request_groups", lambda: [])

    body = json.loads(asyncio.run(gw._list_tool_apps({})).content[0].text)
    keys = {a["app"] for a in body["apps"]}
    assert "open_app" in keys and "secret" not in keys
    assert "s_tool" not in json.dumps(body), "권한 없는 앱의 도구 이름이 새어 나왔다"
    assert body["hidden_no_access"] == 1

    # 이름으로 콕 집어 물어도 도구는 안 준다 — 권한 없음만 알린다.
    one = json.loads(asyncio.run(gw._list_tool_apps({"app": "secret"})).content[0].text)
    assert one["apps"] == [] and one["error"].startswith("no_access")
    assert "s_tool" not in json.dumps(one)
    # 라벨·필요 권한·요청 경로는 준다 — "권한 없음" 과 "그런 앱 없음" 을 모델이 가르게(S3 권한 안내).
    assert [d["app"] for d in body["denied_apps"]] == ["secret"] and body["denied_apps"][0]["label"]
    assert body["denied_apps"][0]["request"] is None, "게이트웨이 그룹 제한은 포털에서 청할 수 없다"
    assert body["denied_apps"][0]["reason"] == "gateway_group"
    assert one["denied"]["app"] == "secret"

    # 권한이 있으면 종전대로 보인다.
    monkeypatch.setattr(gw, "_request_groups", lambda: ["admin"])
    body2 = json.loads(asyncio.run(gw._list_tool_apps({})).content[0].text)
    assert {a["app"] for a in body2["apps"]} >= {"open_app", "secret"}
    assert body2["hidden_no_access"] == 0


def test_list_tool_apps_거부_안내는_포털_권한키와_요청_경로를_준다(monkeypatch):
    class _S:
        session = object()
    monkeypatch.setattr(gw, "backends", {"ste": _S()})
    monkeypatch.setattr(gw, "exposed_tools", [_tool("ste_submit_job")])
    monkeypatch.setattr(gw, "route", {"ste_submit_job": ("ste", "submit_job")})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {"ste": ["plat:smarttwin"]})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setattr(gw, "_request_groups", lambda: ["feat:chat"])

    body = json.loads(asyncio.run(gw._list_tool_apps({})).content[0].text)
    d = body["denied_apps"][0]
    assert d["app"] == "ste" and d["needs"] == ["plat:smarttwin"] and d["request"] == "/access?need=plat:smarttwin"
    assert d["reason"] == "portal_access"
    assert "ste_submit_job" not in json.dumps(body), "거부 안내에 도구 이름이 새면 모델이 계획에 넣는다"
    assert "denied_apps" in gw._INSTRUCTIONS and "/access?need=" in gw._INSTRUCTIONS


def _noop_async(value):
    async def _f(*_a, **_k):
        return value
    return _f


def test_거부_사유가_다르면_안내도_다르다(monkeypatch):
    """적대 검토(2026-09-25)에서 잡힌 둘 — 게이트웨이 그룹으로 막힌 사람에게 이미 가진 포털 권한을
    청하라 했고, 정책 미수신의 일시 닫힘을 '그룹 제한' 영구 상태처럼 말했다."""
    class _S:
        session = object()
    monkeypatch.setattr(gw, "backends", {"ste": _S()})
    monkeypatch.setattr(gw, "exposed_tools", [_tool("ste_submit_job")])
    monkeypatch.setattr(gw, "route", {"ste_submit_job": ("ste", "submit_job")})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {"ste": ["plat:smarttwin"]})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)

    # 1) 포털 권한은 이미 있는데 게이트웨이 그룹이 막는다 → 청할 것이 없다.
    monkeypatch.setattr(gw, "POLICY", {"ste": ["ops"]})
    monkeypatch.setattr(gw, "_request_groups", lambda: ["plat:smarttwin"])
    d = json.loads(asyncio.run(gw._list_tool_apps({})).content[0].text)["denied_apps"][0]
    assert d["reason"] == "gateway_group" and d["request"] is None and d["needs"] == []
    assert "청할 수 있는 것이 아니다" in d["how"]

    # 2) 정책을 아직 못 받아 per_user 백엔드가 잠시 닫힘 → 일시 상태, 재시도 안내.
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", False)
    monkeypatch.setattr(gw, "PER_USER_SSO", {"ste": {}})
    monkeypatch.setattr(gw, "_delegation_app_id", lambda k: k)
    body = json.loads(asyncio.run(gw._list_tool_apps({})).content[0].text)
    d = body["denied_apps"][0]
    assert d["reason"] == "policy_not_ready" and d.get("retry") is True and d["request"] is None
    assert "그룹 제한" not in d["how"]
    # 콕 집어 물어도·호출해도·지시문에서도 같은 사유를 말한다 — how 하나만 고치면 나머지가 반대로 말한다(2라운드).
    one = json.loads(asyncio.run(gw._list_tool_apps({"app": "ste"})).content[0].text)
    assert one["error"].startswith("not_ready:") and "권한이 없는 앱" not in one["error"]
    assert "일시" in gw._deny_text("ste", ["plat:smarttwin"])
    assert "policy_not_ready" in gw._INSTRUCTIONS and "gateway_group" in gw._INSTRUCTIONS
    assert "재시도" in body["note"] or "policy_not_ready" in body["note"]
    # 정책이 오면 같은 호출자가 바로 열린다 — 일시 상태였다는 증거.
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    assert "ste" in {a["app"] for a in json.loads(asyncio.run(gw._list_tool_apps({})).content[0].text)["apps"]}

    # 3) _backend_allowed 는 사유만 버린 같은 판정이다.
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {"ste": ["plat:smarttwin"]})
    assert gw._backend_allowed("ste", ["plat:smarttwin"]) and not gw._backend_allowed("ste", ["feat:chat"])

    # 4) REST 프록시 403 도 같은 사유 문장을 낸다(다섯 번째 소비처).
    monkeypatch.setattr(gw, "_portal_access", _noop_async(None))
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", False)
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    txt = asyncio.run(gw._rest_deny_text("ste", ["feat:chat"], "u@x.test"))
    assert "일시" in txt and "잠시 뒤" in txt
    from rest_proxy import RestProxy
    assert "deny_text" in RestProxy.__init__.__code__.co_varnames


def test_조직도_도구가_라벨없이도_돈다(monkeypatch):
    """라벨 표(포털 orgTaxonomy.json)를 못 받아도 목록 자체는 돌아야 한다 — 라벨이 없다고
    조직도를 통째로 죽이면 클로드 쪽에서 '전문가가 없다'로 보인다(코드로라도 보여 준다)."""
    import asyncio

    async def fake_call(name, args):
        assert name == "list_agents"
        rows = [{"agent_type": "cam-aa-process", "name": "카메라 조립"},
                {"agent_type": "he-calc-laminate", "name": "Laminate 운영자"}]
        return gw.types.CallToolResult(content=[gw.types.TextContent(
            type="text", text=json.dumps({"result": rows}, ensure_ascii=False))])

    monkeypatch.setattr(gw, "_call_tool", fake_call)
    monkeypatch.setattr(gw, "_ORG_TAX", {})
    monkeypatch.setattr(gw, "_portal_api_base", lambda: "")   # 라벨 표 없음
    body = json.loads(asyncio.run(gw._browse_experts({})).content[0].text)
    assert body["total"] == 2
    assert "라벨 표를 못 받아" in body["note"]
    doms = {d["domain"] for sec in body["chart"] for d in sec["domains"]}
    assert doms == {"cam", "he"}

    # 검색은 이름·키 모두에서 찾는다.
    hit = json.loads(asyncio.run(gw._browse_experts({"q": "laminate"})).content[0].text)
    assert [e["key"] for e in hit["experts"]] == ["he-calc-laminate"]


def test_서버_지침이_비어_있지_않다():
    """MCP initialize 응답의 instructions 는 **클라이언트(클로드)가 읽는** 유일한 사용 지침이다.
    비워 두면 도구 수백 개를 주고 '알아서 하라' 는 셈이라, 이 허브에서 실제로 났던 실패
    (도구를 안 부르고 수치를 지어내기·refused 를 자료 없음으로 읽기)가 그대로 재현된다."""
    assert gw._INSTRUCTIONS.strip(), "서버 지침이 비었다"
    for must in ("search_tools", "invoke_tool", "refused", "desc_match", "browse_experts"):
        assert must in gw._INSTRUCTIONS, f"지침에 {must} 안내가 빠졌다"
    assert gw.fm.instructions == gw._INSTRUCTIONS, "FastMCP 에 실려야 클라이언트로 간다"


def test_답변_수치를_조회기록과_대조한다(monkeypatch):
    """MCP 에는 웹의 근거 블록 같은 **코드 검증**이 없어 지침(부탁)뿐이었다. 조회 기록에 없는
    수치를 집어 주면 클로드가 보내기 전에 스스로 잡을 수 있다."""
    import asyncio

    monkeypatch.setattr(gw, "_EVID", gw.OrderedDict())
    monkeypatch.setattr(gw, "_request_user", lambda: "a@b.com")
    monkeypatch.setattr(gw, "_request_groups", lambda: [])

    # 조회 기록이 없으면 '먼저 도구를 부르라' 고 말한다 — 조용히 통과시키지 않는다.
    r0 = json.loads(asyncio.run(gw._verify_answer({"text": "응력 48039.32 MPa"})).content[0].text)
    assert r0["unsourced"] == ["48039.32"] and "도구를 먼저" in r0["note"]

    res = gw.types.CallToolResult(content=[gw.types.TextContent(
        type="text", text='{"stress": 48039.32, "count": 12}')])
    gw._evid_keep("compute_x", res)

    body = json.loads(asyncio.run(gw._verify_answer(
        {"text": "응력은 48039.32 MPa 이고 안전율은 1250.5 다. 항목 12개."})).content[0].text)
    assert body["unsourced"] == ["1250.5"], "조회에 없는 값만 집어야 한다"
    assert body["checked"] == 2, "작은 정수(12)는 오탐이 더 나쁘므로 보지 않는다"
    assert body["tool_calls"] == ["compute_x"]


def test_한글_단위_수치도_대조한다(monkeypatch):
    """에이전트서버와 같은 결함이 여기에도 있었다 — `(?!\\w)` 는 한글을 단어로 봐서 '408명'을
    통째로 건너뛴다. 두 화면의 판정 기준은 같아야 한다."""
    import asyncio

    monkeypatch.setattr(gw, "_EVID", gw.OrderedDict())
    monkeypatch.setattr(gw, "_request_user", lambda: "a@b.com")
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    gw._evid_keep("t", gw.types.CallToolResult(content=[gw.types.TextContent(
        type="text", text='{"n": 408}')]))
    body = json.loads(asyncio.run(gw._verify_answer(
        {"text": "전문가 408명, 비용 1250.5원"})).content[0].text)
    assert body["unsourced"] == ["1250.5"], "한글 단위가 붙어도 대조해야 한다"
    assert body["checked"] == 2


def test_신원_전달은_콜론을_인코딩하지_않는다():
    """권한 키는 feat:chat·plat:aidatahub 꼴이다. quote 의 안전문자에 `:` 가 없으면 feat%3Achat
    로 가고, 받는 쪽이 디코드하지 않으면 **전 키가 무효**가 된다(실측: 도구 465→3개, 좌석 0명)."""
    src = open(__file__.replace("test_gateway.py", "gateway.py"), encoding="utf-8").read()
    i = src.index("async def _call_with_identity(")
    body = src[i: src.index("\n@_low.list_tools()", i)]
    assert 'safe=",:"' in body, "그룹 헤더의 콜론은 그대로 실어야 한다"
    assert "IDENTITY_FWD" in src and "hwax-deliberation" in src


# ── 재집계가 백엔드 하나에 매달리면 게이트웨이 전체가 굳는다 ──────────────────
class _NeverReadyB:
    """`_ready` 를 영영 안 세우는 백엔드 — 재배포 중 아직 못 붙은 앱."""
    def __init__(self):
        import asyncio
        self.session = object()          # 여기까지 가면 안 된다
        self._failed = None
        self._ready = asyncio.Event()    # set() 하지 않는다


class _NeverAnswersSess:
    async def list_tools(self):
        import asyncio
        await asyncio.sleep(3600)        # 연결은 살아 있는데 응답을 안 준다


class _NeverAnswersB:
    def __init__(self):
        import asyncio
        self.session = _NeverAnswersSess()
        self._failed = None
        self._ready = asyncio.Event()
        self._ready.set()


def test_a_backend_that_never_answers_does_not_freeze_the_catalogue(monkeypatch):
    """**실사고 회귀(2026-09-12 18:07:54 ~ 09-14).**

    `_aggregate` 의 `_ready.wait()` 와 `list_tools()` 에 데드라인이 없었다. 느린 앱
    하나가 재집계 중에 응답을 멈추자 `_revive_loop` 가 거기서 섰고, 그 뒤 **이틀 동안**
    죽은 백엔드 부활도 도구 목록 갱신도 일어나지 않았다.

    최악인 것은 **아무도 못 봤다는 점**이다. 게이트웨이는 옛 카탈로그로 정상 응답을
    계속 냈다 — 에러도 경고도 없다. StepForge 를 재배포했는데 새 도구가 안 보여서야
    드러났다. 이 리포가 반복해서 만나는 "실패가 정상 응답과 똑같이 생겼다" 의 한 모양이다.

    멈추는 것은 **예외가 아니라 행**이라 `except` 로는 못 잡는다 — 데드라인만이 잡는다.
    """
    import asyncio

    monkeypatch.setattr(gw, "LIVENESS_TIMEOUT_S", 0.05)
    stuck_ready, stuck_answer = _NeverReadyB(), _NeverAnswersB()
    monkeypatch.setattr(gw, "backends", {
        "ok_before": _B([_tool("before")]),
        "stuck_ready": stuck_ready,
        "stuck_answer": stuck_answer,
        "ok_after": _B([_tool("after")]),      # 막힌 것 **뒤** 백엔드도 살아야 한다
    })
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "route", {})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "_LIVENESS_MISS", {})
    monkeypatch.setattr(gw, "_REAGG", {})
    monkeypatch.setattr(gw, "LIVENESS_STRIKES", 2)

    async def go():
        # 데드라인이 없으면 여기서 매달린다 — 그게 실제로 일어난 일이다
        await asyncio.wait_for(gw._aggregate(), timeout=5)
        first = ({t.name for t in gw.exposed_tools}, stuck_answer.session is not None, gw._REAGG.get("pending"))
        await asyncio.wait_for(gw._aggregate(), timeout=5)
        return first

    got, kept, again = asyncio.run(go())

    assert got == {"before", "after"}, f"막힌 백엔드가 나머지를 데려갔다: {got}"
    # 한 번 놓친 것으로는 세션을 갈지 않는다(잠깐 바쁜 건강한 백엔드의 진행 중 답을 버린다, gateway-06). 대신 다음 회차에
    # 목록을 다시 받게 예약한다 — 안 그러면 이 백엔드의 도구가 그 구성이 바뀔 때까지 카탈로그에 안 올라온다.
    assert kept and again is True
    # 연속으로 놓친 백엔드는 **죽은 것으로 표시**돼 다음 회차 재연결 루프가 집어 간다
    assert stuck_answer.session is None, "재연결 예약이 안 됐다 — 영영 안 돌아온다"
    assert {t.name for t in gw.exposed_tools} == {"before", "after"}


def test_the_stuck_backend_is_reported_not_swallowed(monkeypatch, caplog):
    """건너뛴 것을 조용히 넘기면 도구가 사라진 이유를 아무도 못 찾는다."""
    import asyncio
    import logging

    monkeypatch.setattr(gw, "LIVENESS_TIMEOUT_S", 0.05)
    monkeypatch.setattr(gw, "backends", {"stuck": _NeverAnswersB()})
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "route", {})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "_LIVENESS_MISS", {})
    monkeypatch.setattr(gw, "_REAGG", {})

    with caplog.at_level(logging.ERROR, logger="hwax-mcp-gateway"):
        asyncio.run(asyncio.wait_for(gw._aggregate(), timeout=5))

    blob = caplog.text
    assert "stuck" in blob and ("초과" in blob or "실패" in blob), f"조용히 넘겼다: {blob!r}"


# ── 감사 기록 — 성공에 `error` 가 실리면 안 된다 ─────────────────────────
def test_감사의_error_는_실패에만_쓴다(tmp_path, monkeypatch):
    """**실측 사고.** 위임 신원(`as:someone@…`)과 메모(`cache-hit`)를 `error` 칸으로 날라서
    `ok:true` 인 기록에 `error` 가 실렸다 — 12,787줄 중 215줄이 그 모양이었다.
    그러면 `error` 는 실패 신호로도, 신원 질의로도 못 쓴다. **성공이 실패처럼 생긴 것**이다.
    """
    import json as _j

    f = tmp_path / "a.jsonl"
    monkeypatch.setattr(gw, "AUDIT_PATH", str(f))
    gw._audit("t", "b", True, None, 12, caller="a@b.c", mode="as-user-pat", corr="conv-9")
    gw._audit("t", "b", True, None, 0, note="cache-hit")
    gw._audit("t", "b", False, "진짜 실패", 5, caller="a@b.c")

    rows = [_j.loads(x) for x in f.read_text(encoding="utf-8").splitlines()]
    ok_rows = [r for r in rows if r["ok"]]
    assert ok_rows and all("error" not in r for r in ok_rows), \
        f"성공 기록에 error 가 실렸다: {ok_rows}"
    assert rows[0]["caller"] == "a@b.c" and rows[0]["mode"] == "as-user-pat"
    assert rows[0]["corr"] == "conv-9"
    assert rows[1]["note"] == "cache-hit"
    assert rows[2]["error"] == "진짜 실패", "실패에는 error 가 있어야 한다"


def test_감사_시각이_밀리초까지_남는다(tmp_path, monkeypatch):
    """초 단위라 같은 초의 호출들을 구분할 수 없었다 — 12,787줄이 7,879 키로 뭉갰다."""
    import json as _j

    f = tmp_path / "a.jsonl"
    monkeypatch.setattr(gw, "AUDIT_PATH", str(f))
    gw._audit("t", "b", True, None, 1)
    ts = _j.loads(f.read_text(encoding="utf-8").strip())["ts"]
    assert "." in ts, f"초 단위다: {ts}"


def test_안_준_칸은_안_남긴다(tmp_path, monkeypatch):
    """빈 칸을 만들면 '없다' 와 '빈 값이다' 가 섞인다."""
    import json as _j

    f = tmp_path / "a.jsonl"
    monkeypatch.setattr(gw, "AUDIT_PATH", str(f))
    gw._audit("t", "b", True, None, 1)
    rec = _j.loads(f.read_text(encoding="utf-8").strip())
    assert set(rec) == {"ts", "tool", "backend", "ok", "ms"}


def test_감사_쓰기_실패가_호출을_막지_않는다(monkeypatch):
    monkeypatch.setattr(gw, "AUDIT_PATH", "/없는디렉터리/a.jsonl")
    gw._audit("t", "b", True, None, 1)   # 예외가 올라오면 실패


def test_모든_호출자리가_error_칸을_메모로_쓰지_않는다():
    """소스 정적 검사 — 새 자리가 다시 오남용하면 여기서 걸린다."""
    import re

    src = open("gateway.py", encoding="utf-8").read()
    for m in re.finditer(r"_audit\((.{0,200}?)\)\n", src, re.S):
        blob = m.group(1)
        if 'True' not in blob:
            continue
        for bad in ('"cache-hit"', '"reconnected"', 'f"as:', 'f"as-conn:', 'f"as-user:'):
            assert bad not in blob or "note=" in blob or "mode=" in blob, \
                f"성공 기록의 error 칸에 메모를 넣는다: {blob[:90]}"


# ── REST 프록시가 자격 체계를 우회하던 것(2026-09-15 6차 감사) ──────────────
def test_rest_프록시가_MCP_와_같은_규칙을_본다(monkeypatch):
    """PAT 서명·aud·scope·폐기목록까지만 보고 **groups 를 안 봤다** — 자격 0개인 사람이
    MCP 로는 `forbidden:` 을 받는 백엔드를 이 경로로는 200 으로 읽었다(실측).
    `inject` 없는 사이트는 권한 상승이 없다고 봤는데, 상류 AIDataHub 가 **인증 없이 200**
    이라 이 프록시가 유일한 관문이었다.
    """
    import asyncio

    import gateway as gw

    monkeypatch.setitem(gw._ACCESS_POLICY, "ai-data-hub", ["plat:aidatahub"])

    async def _no_portal(email, base):
        return None
    monkeypatch.setattr(gw, "_portal_access", _no_portal)

    run = asyncio.get_event_loop_policy().new_event_loop().run_until_complete
    assert run(gw._rest_allowed("ai-data-hub", ["plat:aidatahub"], "")) is True
    assert run(gw._rest_allowed("ai-data-hub", [], "")) is False
    assert run(gw._rest_allowed("ai-data-hub", ["plat:stepforge"], "")) is False
    # ⚠ PAT 이 서비스 그룹을 **주장해도** 인정하지 않는다 — 그러면 아무나 스스로 찍어
    # 내부 서비스 면제를 받는다. MCP 경로가 그 그룹을 떼는 이유가 같다.
    assert run(gw._rest_allowed("ai-data-hub", [gw.SERVICE_GROUP], "")) is False


def test_rest_프록시에_규칙이_실제로_주입된다():
    """함수만 있고 안 꽂혀 있으면 아무것도 안 지킨다."""
    import re
    from pathlib import Path

    src = Path(__file__).resolve().parent.joinpath("gateway.py").read_text(encoding="utf-8")
    assert re.search(r"RestProxy\([^)]*allow=_rest_allowed", src), \
        "RestProxy 에 allow 가 안 꽂혔다"


# ── 6차 감사 뒤 굳히는 것들(2026-09-15) ────────────────────────────────────
def test_근거_원장이_섞이지_않는다(monkeypatch):
    """신원이 없으면 그룹 문자열, 그것도 없으면 `_anon` 한 칸을 **모두가 공유**했다.
    그래서 도구를 하나도 안 부른 새 세션에서 `verify_answer` 가 **남이 조회한 목록**을
    냈다 — 환각 방어의 마지막 선이 그것이다."""
    import gateway as gw

    monkeypatch.setattr(gw, "_request_user", lambda: "")
    monkeypatch.setattr(gw, "_request_groups", lambda: ["plat:x", "plat:y"])
    monkeypatch.setattr(gw, "_request_session", lambda: "")
    assert gw._evid_key() == "", "가를 수 없으면 빈 칸이어야 한다(섞느니 안 쌓는다)"

    monkeypatch.setattr(gw, "_request_session", lambda: "S1")
    k1 = gw._evid_key()
    monkeypatch.setattr(gw, "_request_session", lambda: "S2")
    assert k1 != gw._evid_key(), "세션이 다르면 칸도 달라야 한다"

    monkeypatch.setattr(gw, "_request_user", lambda: "a@corp.com")
    ku = gw._evid_key()
    monkeypatch.setattr(gw, "_request_session", lambda: "S9")
    assert gw._evid_key() == ku, "한 사람의 근거는 세션을 넘어 이어져야 한다"


def test_파괴_관문이_이름_패턴_밖도_막는다():
    """되돌리려면 남의 손이 필요한데 `delete_`·`_control` 어디에도 안 맞는 것들이 있다."""
    import gateway as gw

    for n in ("trash_report", "publish_report", "publish_report_to_datahub",
              "request_unpublish", "restore_version", "job_stop"):
        assert n in gw._INVOKE_DENY_EXACT, n
    # 조회는 그대로 통과한다 — 관문이 너무 넓으면 범용 실행기가 무용지물이다
    for n in ("list_operations", "get_material", "create_report_draft"):
        assert n not in gw._INVOKE_DENY_EXACT, n


def test_무인증_헬스는_권한_지도를_안_낸다():
    """nginx 가 게이트웨이를 외부로 프록시한다 — 무인증 프로브에 내부 권한 지도가
    나갈 이유가 없다. 다만 **실려 있는지**는 봐야 한다(비면 권한이 통째로 풀린 것)."""
    import re
    from pathlib import Path

    src = Path(__file__).resolve().parent.joinpath("gateway.py").read_text(encoding="utf-8")
    i = src.index('scope.get("path") == "/health"')
    blk = src[i:i + 1800]
    assert "access_policy_loaded" in blk
    assert re.search(r'if _detail else \{\}', blk), "상세가 시크릿 뒤로 안 갔다"


# ── 응답 캐시 — 상태 조회·봉투형 실패는 담지 않는다 (2026-09-16, odb-hub 연계 대조) ──────────
def _txt(s: str):
    return types.CallToolResult(content=[types.TextContent(type="text", text=s)])


def test_상태_조회는_접두사가_열어도_캐시하지_않는다(monkeypatch):
    """`get_` 접두가 `get_task`(odb-hub 폴링)·`get_job`(DynaForge)을 열어 두면 폴링이 300초 동안
    첫 응답(running)을 그대로 받는다 — 작업이 끝나도 "도는 중" 이고 오류도 안 난다."""
    monkeypatch.setattr(gw, "CACHE_TTL_S", 300.0)
    for name in ("get_task", "get_job", "get_job_details", "get_job_outputs", "list_jobs",
                 "list_recent_jobs", "list_session_jobs", "describe_search_status"):
        assert gw._cache_key("b", name, {"id": "x"}) is None, f"{name} 가 캐시된다"
    # 이 검사가 캐시를 통째로 꺼서 통과하는 게 아니라는 확인 — 보통 읽기는 여전히 담긴다
    for name in ("get_part_detail", "list_parts", "get_board_layers", "report_summary"):
        assert gw._cache_key("b", name, {"id": "x"}) is not None, f"{name} 가 캐시에서 빠졌다"


def test_봉투형_실패는_캐시에_넣지_않는다(monkeypatch):
    """odb-hub 는 미실행 결과를 200 + `{"error": …}` 로 준다(isError 아님). 그걸 담으면 방금
    분석을 돌렸어도 TTL 동안 "결과가 없습니다" 가 굳는다."""
    monkeypatch.setattr(gw, "CACHE_TTL_S", 300.0)
    monkeypatch.setattr(gw, "_RESP_CACHE", gw.OrderedDict())
    # odb-hub 원문 표본 그대로(reference.md §4.13) — 게이트웨이가 넘기는 들여쓰기 모양으로
    env = json.dumps({"error": "동박율 결과가 없습니다",
                      "hint": "run_analysis(job_id, analysis=\"copper\") 로 계산을 실행하고 "
                              "get_task 로 완료를 확인한 뒤 다시 조회하세요"},
                     ensure_ascii=False, indent=2)
    for i, body in enumerate((env, '{"ok": false, "reason": "x"}', '{"refused": true}',
                              '{"status": "error", "detail": "x"}', '{"errors": ["bad"]}')):
        k = gw._cache_key("b", f"get_copper_result_{i}", {})
        gw._cache_put(k, _txt(body))
        assert k not in gw._RESP_CACHE, f"봉투형 실패가 캐시됐다: {body[:40]}"
    # 담아야 할 것은 담긴다 — 판정이 넓다고 성공까지 버리면 캐시가 죽는다
    for i, body in enumerate(('{"verdict": "standard", "error": null}', '{"errors": []}',
                              '{"status": "ok", "jobs": 108}', "평문 결과", "[1, 2]")):
        k = gw._cache_key("b", f"get_board_layers_{i}", {})
        gw._cache_put(k, _txt(body))
        assert k in gw._RESP_CACHE, f"성공 결과가 캐시되지 않았다: {body[:40]}"


# ── 소속을 호출마다 싣는다(포털 W-93) ──────────────────────────────────────
def test_소속은_권한과_같은_조회에서_온다(monkeypatch):
    """따로 물으면 **한쪽만 거둬진 순간**이 생긴다(정지 계정은 둘 다 빈 값이어야 한다).
    캐시도 한 항목이라 호출이 늘지 않는다."""
    import asyncio

    monkeypatch.setattr(gw, "_ENT_CACHE", {})
    monkeypatch.setattr(gw, "_ENT_LAST", {})
    calls = []

    def ok(req):
        calls.append(dict(req.url.params))
        return httpx.Response(200, json={"keys": ["feat:chat"], "affiliation": "CAEG",
                                         "affiliation_label": "CAE그룹"})
    _mock_http(monkeypatch, ok)
    assert asyncio.run(gw._portal_access("u@corp.com", ["mes-user"]))["keys"] == ["feat:chat"]
    assert asyncio.run(gw._portal_affiliation("u@corp.com", ["mes-user"])) == "CAEG"
    assert len(calls) == 1, f"같은 조회를 두 번 했다: {calls}"

    # 권한 기능 이전 포털(404) — 소속은 빈 값이고 권한은 None(PAT 값 그대로)
    gw._ENT_CACHE.clear(); gw._ENT_LAST.clear()
    _mock_http(monkeypatch, lambda req: httpx.Response(404))
    assert asyncio.run(gw._portal_affiliation("new@corp.com", [])) == ""
    assert asyncio.run(gw._portal_access("new@corp.com", [])) is None

    # 소속 칸이 없는 응답(구 포털)도 빈 값이지 예외가 아니다
    gw._ENT_CACHE.clear(); gw._ENT_LAST.clear()
    _mock_http(monkeypatch, lambda req: httpx.Response(200, json={"keys": []}))
    assert asyncio.run(gw._portal_affiliation("u@corp.com", [])) == ""


class _StubCM:
    """async with 한 겹 — streamablehttp_client·ClientSession 자리를 대신한다."""

    def __init__(self, value): self.value = value

    async def __aenter__(self): return self.value

    async def __aexit__(self, *a): return False


def _per_user_kit(monkeypatch, aff_payload, base_headers=None, sso_extra=None,
                  groups=("mes-user", "plat:dynaforge")):
    """사용자 위임 경로를 실제로 태우고 **백엔드에 닿은 헤더**를 돌려준다.

    ⚠ `_call_as_user` 를 가짜로 갈아끼우면 안 된다 — 처음에 그렇게 짰다가 검토에서 잡혔다.
    그 함수의 병합 규칙(같은 이름 헤더 제거 + `None` 이면 삭제)을 테스트가 **베껴** 검사하고
    있어서, 진짜 병합을 깨뜨려도(예: `if v is not None` 삭제) 네 테스트가 전부 초록이었다.
    막으려던 것이 바로 그 회귀다. 그래서 전송 계층(streamablehttp_client·ClientSession)만
    막고 진짜 함수를 태운다.
    """
    import asyncio

    b = _CallB(["report_summary"])
    b.headers = dict(base_headers or {})
    seen = {}

    class _Sess:
        async def initialize(self): return None

        async def call_tool(self, original, arguments, read_timeout_seconds=None):
            seen["tool"] = original
            return types.CallToolResult(
                content=[types.TextContent(type="text", text="{}")], isError=False)

    def fake_stream(url, headers=None, **_kw):
        seen["headers"] = dict(headers or {})
        return _StubCM((None, None, "sid"))

    monkeypatch.setattr(gw, "streamablehttp_client", fake_stream)
    monkeypatch.setattr(gw, "ClientSession", lambda read, write: _StubCM(_Sess()))

    # ⚠ 응답 캐시가 300초라 같은 테스트의 두 번째 호출이 백엔드에 안 닿는다(처음에 이걸로 깨졌다).
    gw._RESP_CACHE.clear()
    monkeypatch.setattr(gw, "backends", {"heax-kooremapper_mcp": b})
    monkeypatch.setattr(gw, "route", {"report_summary": ("heax-kooremapper_mcp", "report_summary")})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)   # 이 시험의 관심사는 위임 헤더다 — 정책은 '받았고 비었다'
    monkeypatch.setattr(gw, "PER_USER_SSO", {"kooremapper_mcp": {"sso_url": "http://x",
                                                                 "secret": "app-secret",
                                                                 **(sso_extra or {})}})
    monkeypatch.setattr(gw, "_request_user", lambda: "u@corp.com")
    monkeypatch.setattr(gw, "_request_groups", lambda: list(groups))

    async def fake_pat(app_id, email, *, force=False):
        return "kr_tok"
    monkeypatch.setattr(gw, "_user_pat", fake_pat)
    seen_groups = []

    async def fake_access(email, base_groups, *, allow_stale=True):
        seen_groups.append((list(base_groups), allow_stale))
        return aff_payload
    monkeypatch.setattr(gw, "_portal_access", fake_access)
    asyncio.run(gw._call_tool("report_summary", {"report_id": "r1"}))
    seen["lookups"] = seen_groups
    return seen


def test_사용자_위임_호출에_소속이_증명과_함께_실린다(monkeypatch):
    """발급 때가 아니라 **호출마다**다 — 사용자 PAT 캐시는 12시간이라 발급 헤더로만 넘기면
    소속이 바뀐 사람이 반나절 동안 남의 소속 문서를 읽는다.

    그리고 **평문만으로는 안 된다.** 앱의 정문이 게이트웨이 하나가 아니라(사용자가 자기 PAT 로
    앱 MCP 에 직접 붙는다) 소속을 평문으로만 보내면 "나는 CAEG 다" 를 사용자가 스스로 적는다.
    """
    import hashlib
    import hmac

    seen = _per_user_kit(monkeypatch, {"keys": ["plat:dynaforge"], "affiliation": "CAEG"})
    assert seen["headers"][gw.AFF_HEADER] == "CAEG"
    assert seen["headers"]["Authorization"] == "Bearer kr_tok"
    assert seen["lookups"] == [(["mes-user"], False)], \
        "권한 조회와 같은 키여야 캐시가 하나다(합성 그룹은 뺀다) · 소속은 낡은 값을 안 쓴다"

    ver, exp, sig = seen["headers"][gw.AFF_PROOF_HEADER].split(".")
    assert ver == "v1" and int(exp) > 0
    want = hmac.new(b"app-secret", f"v1|u@corp.com|CAEG|{exp}".encode(), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(sig, want), "서명이 이메일·소속·만료에 결속돼야 한다"


def test_사람별_호출에서는_strip_headers_의_서비스_헤더를_뺀다(monkeypatch):
    """RA 를 ste 방식(per_user_sso)으로 부를 때 서비스 설정의 X-Workspace-Slug(서비스 부서)가 사람별 호출에 남으면
    그 부서로 읽고 쓴다 — 포털 연결 경로가 이미 막던 것과 같은 사고다(docs/sso-delegation). 손잡이가 없으면 종전대로 둔다."""
    svc = {"X-Workspace-Slug": "svc", "X-Keep": "1"}
    seen = _per_user_kit(monkeypatch, None, base_headers=svc, sso_extra={"strip_headers": ["X-Workspace-Slug"]})
    assert "X-Workspace-Slug" not in seen["headers"] and seen["headers"]["X-Keep"] == "1"
    assert seen["headers"]["Authorization"] == "Bearer kr_tok"
    seen = _per_user_kit(monkeypatch, None, base_headers=svc)
    assert seen["headers"]["X-Workspace-Slug"] == "svc", "손잡이가 없는 앱(ste·DynaForge)은 그대로"
    seen = _per_user_kit(monkeypatch, None, base_headers=svc, sso_extra={"strip_headers": "X-Workspace-Slug"})
    assert seen["headers"]["X-Workspace-Slug"] == "svc", "목록이 아니면 글자 단위로 쪼개 엉뚱한 헤더를 지우지 않는다"


def test_증명은_다른_사람의_호출에는_못_쓴다(monkeypatch):
    """증명을 가로채도 남의 호출에 실으면 안 맞아야 한다 — 그래서 이메일을 서명에 넣는다."""
    import hashlib
    import hmac

    seen = _per_user_kit(monkeypatch, {"keys": [], "affiliation": "CAEG"})
    _v, exp, sig = seen["headers"][gw.AFF_PROOF_HEADER].split(".")
    other = hmac.new(b"app-secret", f"v1|bob@corp.com|CAEG|{exp}".encode(),
                     hashlib.sha256).hexdigest()
    assert sig != other


def test_소속이_없으면_두_헤더를_아예_안_싣는다(monkeypatch):
    """빈 문자열을 실으면 받는 쪽이 '소속 없음' 을 하나의 소속으로 묶을 수 있다 —
    소속 없는 사람끼리 서로의 문서를 읽는 길이 된다. 백엔드 설정에 남아 있던 값도 지운다."""
    svc = {gw.AFF_HEADER: "SVC", gw.AFF_PROOF_HEADER: "v1.0.dead", "X-Keep": "1"}
    seen = _per_user_kit(monkeypatch, {"keys": [], "affiliation": ""}, base_headers=svc)
    assert gw.AFF_HEADER not in seen["headers"], "서비스 계정 헤더가 남으면 남의 소속으로 읽힌다"
    assert gw.AFF_PROOF_HEADER not in seen["headers"]
    assert seen["headers"]["X-Keep"] == "1", "관계없는 백엔드 헤더까지 지우면 안 된다"

    # 포털을 아예 못 읽는 경우(None)도 같다 — 모르면 안 싣는다
    seen = _per_user_kit(monkeypatch, None, base_headers=svc)
    assert gw.AFF_HEADER not in seen["headers"]


def test_소속에_한글이_와도_헤더가_안_깨진다(monkeypatch):
    """헤더는 latin-1 만 담는다 — groups·user 와 같은 규칙으로 인코딩한다(받는 쪽은 unquote).
    서명은 **인코딩 전** 값으로 한다 — 앱이 unquote 한 뒤 같은 문자열로 계산하기 때문이다."""
    import hashlib
    import hmac
    from urllib.parse import unquote

    seen = _per_user_kit(monkeypatch, {"keys": [], "affiliation": "CAE그룹"})
    got = seen["headers"][gw.AFF_HEADER]
    got.encode("latin-1")            # 안 깨지는지
    assert unquote(got) == "CAE그룹"
    _v, exp, sig = seen["headers"][gw.AFF_PROOF_HEADER].split(".")
    want = hmac.new(b"app-secret", f"v1|u@corp.com|CAE그룹|{exp}".encode(), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(sig, want)


def test_소속이_캐시_키에_들어간다(monkeypatch):
    """앱이 소속으로 읽기를 넓히므로 같은 사람·같은 인자라도 소속이 다르면 다른 답이다.
    키에 없으면 권한 키가 안 바뀌는 소속 변경이 300초 동안 옛 결과를 정상 응답으로 준다."""
    monkeypatch.setattr(gw, "_request_user", lambda: "u@corp.com")
    monkeypatch.setattr(gw, "_request_groups", lambda: ["mes-user"])
    a = gw._cache_key("b", "get_x", {"i": 1}, "CAEG")
    b = gw._cache_key("b", "get_x", {"i": 1}, "")
    assert a is not None and a != b
    assert a[3] == "u@corp.com", "/conn-invalidate 가 k[3] 로 고른다 — 앞을 밀면 안 된다"


# ── 별칭이 정확이름 차단을 우회하던 것(2026-09-18) ─────────────────────────
def _set_request_headers(monkeypatch, headers: dict):
    """`_low.request_context.request.headers` 를 세운다 — `_request_*` 들이 실제로 읽는 자리다."""
    from types import SimpleNamespace as NS
    monkeypatch.setattr(gw, "_low", NS(request_context=NS(request=NS(headers=headers))))


def test_목적_헤더를_실제로_읽는다(monkeypatch):
    """면제 판정의 **입력**이다. fail-open 이면(헤더를 안 보고 늘 'procedure') 이번 변경이 막으려던
    구멍이 통째로 되돌아온다 — 그래서 없음·다른 값·요청 문맥 없음을 전부 닫힘으로 본다."""
    from types import SimpleNamespace as NS

    class _NoCtx:
        @property
        def request_context(self):
            raise LookupError
    monkeypatch.setattr(gw, "_low", _NoCtx())
    assert gw._request_purpose() == "", "요청 문맥이 없으면 면제 없음"
    _set_request_headers(monkeypatch, {})
    assert gw._request_purpose() == "", "헤더가 없으면 면제 없음"
    _set_request_headers(monkeypatch, {gw.PURPOSE_HEADER: "chat"})
    assert gw._request_purpose() != gw.PROCEDURE_PURPOSE, "다른 값은 면제가 아니다"
    _set_request_headers(monkeypatch, {gw.PURPOSE_HEADER: gw.PROCEDURE_PURPOSE})
    assert gw._request_purpose() == gw.PROCEDURE_PURPOSE
    monkeypatch.setattr(gw, "_low", NS(request_context=NS(request=None)))
    assert gw._request_purpose() == ""


def _deny_kit(monkeypatch, purpose=""):
    """RA 백엔드 하나를 세우고 invoke_tool 을 실제로 태운다. 반환은 (호출함수, 백엔드)."""
    import asyncio

    # ⚠ delete_project 를 **실재하는 도구로** 둔다. 없으면 별칭이 해석되지 않아 "unknown tool"
    # 로 막히고, 그러면 "차단됐다" 가 아니라 "이름이 없다" 를 시험하게 된다(실제로 그렇게
    # 짰다가 변이 시험에서 잡혔다 — 면제를 이름 패턴까지 넓혀도 초록이었다).
    b = _CallB(["trash_report", "add_report_tags", "publish_report", "get_report",
                "delete_project"])
    monkeypatch.setattr(gw, "backends", {"reportarchive": b})
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "route", {})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    monkeypatch.setattr(gw, "_request_user", lambda: "")
    # ⚠ `_request_purpose` 를 갈아끼우면 안 된다 — 처음에 그렇게 짰다가 검토에서 잡혔다. 그 함수를
    # `return "procedure"` 로 바꿔(= 모든 호출자에게 면제) 48개가 전부 초록이었다. 헤더를 **싣는 쪽**
    # (미들웨어)과 면제를 **판정하는 쪽**만 걸려 있고 헤더를 **읽는 쪽**은 아무도 안 봤다.
    # 그래서 요청 문맥에 실제 헤더를 싣고 진짜 함수를 태운다.
    _set_request_headers(monkeypatch, {gw.PURPOSE_HEADER: purpose} if purpose else {})
    asyncio.run(gw._aggregate())

    def invoke(name):
        gw._RESP_CACHE.clear()
        r = asyncio.run(gw._call_tool("invoke_tool", {"name": name, "arguments": {}}))
        return bool(getattr(r, "isError", False))

    return invoke, b


def test_별칭도_정확이름_차단에_걸린다(monkeypatch):
    """`inner` 로만 보면 별칭이 그대로 우회로다 — 실측으로 trash_report·publish_report·
    add_report_tags 가 백엔드까지 도달했다(2026-09-18 재현). 접두·접미 규칙은 이미 원본을
    보고 있었는데 **정확이름 목록만** 호출자 문자열을 보고 있었다."""
    invoke, b = _deny_kit(monkeypatch)
    for n in ("trash_report", "reportarchive_trash_report",
              "publish_report", "reportarchive_publish_report",
              "add_report_tags", "reportarchive_add_report_tags"):
        assert invoke(n), f"{n} 이 차단을 지났다"
    assert b.session.calls == [], f"파괴 도구가 백엔드까지 갔다: {b.session.calls}"
    assert not invoke("reportarchive_get_report"), "파괴 계열이 아니면 별칭으로도 돌아야 한다"
    assert b.session.calls == ["get_report"]


def test_절차_실행기만_정확이름_차단을_면제받는다(monkeypatch):
    """면제가 없으면 절차는 MUST_GATE 도구를 영영 못 부른다(늘 별칭으로 부른다).
    면제의 근거는 포털이 이미 `gate: human` 으로 사람 승인을 받았다는 것이다."""
    invoke, b = _deny_kit(monkeypatch, purpose=gw.PROCEDURE_PURPOSE)
    assert not invoke("reportarchive_add_report_tags"), "절차는 통과해야 한다"
    assert b.session.calls == ["add_report_tags"]
    # 이름 패턴 차단(delete_·cancel_)은 절차에도 그대로다 — 면제는 정확이름 목록에만 준다.
    b.session.calls.clear()
    assert invoke("delete_project"), "bare 이름은 절차라도 막힌다"
    assert invoke("reportarchive_delete_project"), "별칭이어도 원본이 delete_ 면 절차라도 막힌다"
    assert b.session.calls == [], f"파괴 도구가 백엔드까지 갔다: {b.session.calls}"


def test_목적_헤더는_검증된_PAT_에서만_나온다(monkeypatch):
    """사람이 헤더에 직접 적으면 아무나 면제를 받는다. 미들웨어가 클라이언트 값을 버리고
    PAT 클레임으로만 싣는지 — 그리고 GW_TOKEN 경로에서도 버리는지 본다."""
    import asyncio

    seen = {}

    async def app(scope, receive, send):
        seen["headers"] = {k.decode().lower(): v.decode() for k, v in scope["headers"]}

    async def no_portal(email, base, **_kw):
        return None
    monkeypatch.setattr(gw, "_portal_access", no_portal)      # PAT 분기가 부르는 쪽 — 안 막으면 dev 포털로 실제 요청이 간다
    monkeypatch.setattr(gw, "GW_TOKEN", "gw-secret")

    class _V:
        def __init__(self, claims): self.claims = claims
        async def verify(self, token, aud): return self.claims

    def run(auth, claims, client_purpose=b"procedure"):
        seen.clear()
        mw = gw._bearer_gate(app, _V(claims))
        hdrs = [(b"authorization", auth), (gw.PURPOSE_HEADER.encode(), client_purpose)]
        asyncio.run(mw({"type": "http", "path": "/mcp", "headers": hdrs}, None, None))
        return seen.get("headers", {})

    # ① 클라이언트가 실어 보낸 값은 버린다(PAT 에 클레임이 없을 때)
    h = run(b"Bearer user-pat", {"email": "u@x.io", "groups": []})
    assert gw.PURPOSE_HEADER not in h, "위조 헤더가 살아남으면 아무나 면제를 받는다"
    # ② PAT 클레임이 있으면 싣는다
    h = run(b"Bearer proc-pat", {"email": "u@x.io", "groups": [], "purpose": "procedure"})
    assert h[gw.PURPOSE_HEADER] == "procedure"
    # ③ GW_TOKEN(서비스) 경로에서도 클라이언트 값은 버린다
    h = run(b"Bearer gw-secret", None)
    assert gw.PURPOSE_HEADER not in h, "GW_TOKEN 을 쥔 쪽이 면제를 자칭하면 안 된다"


def test_면제된_호출은_감사원장에서_구별된다(monkeypatch):
    """면제로 지나간 파괴 호출이 직접 호출과 똑같이 찍히면 '이 문을 누가 몇 번 썼나' 를 감사로
    영영 못 묻는다. 절차 호출에는 `purpose` 칸이 붙고, 사람 호출에는 안 붙는다."""
    invoke, b = _deny_kit(monkeypatch, purpose=gw.PROCEDURE_PURPOSE)
    assert not invoke("reportarchive_add_report_tags")
    rows = [json.loads(ln) for ln in open(gw.AUDIT_PATH, encoding="utf-8")]
    hit = [r for r in rows if "add_report_tags" in r["tool"]]
    assert hit and all(r.get("purpose") == gw.PROCEDURE_PURPOSE for r in hit), hit

    invoke2, _ = _deny_kit(monkeypatch, purpose="")
    open(gw.AUDIT_PATH, "w").close()
    assert invoke2("reportarchive_get_report") is False
    rows = [json.loads(ln) for ln in open(gw.AUDIT_PATH, encoding="utf-8")]
    assert rows and all("purpose" not in r for r in rows), "사람 호출에 purpose 가 붙으면 구분이 무너진다"


def test_포털이_찍는_목적_값과_게이트웨이가_보는_값이_같다():
    """두 리포에 흩어진 문자열이다 — 한쪽만 바꾸면 양쪽 시험이 **각자 초록인 채** 면제만 꺼지고,
    증상은 사람이 게이트를 승인한 **뒤에** 그 단계가 '범용 실행기로 부를 수 없습니다' 로 죽는 것이다.
    형제 리포가 이 박스에 있을 때만 본다(없으면 건너뛴다)."""
    from pathlib import Path
    portal = Path(gw.__file__).resolve().parent.parent / "HWAXPortal" / "backend" / "app" / "procedures" / "pat.py"
    if not portal.exists():
        pytest.skip("형제 리포 HWAXPortal 이 이 박스에 없다")
    src = portal.read_text(encoding="utf-8")
    assert f'"purpose": "{gw.PROCEDURE_PURPOSE}"' in src, \
        f"포털 절차 PAT 의 purpose 값이 게이트웨이 PROCEDURE_PURPOSE({gw.PROCEDURE_PURPOSE!r})와 다르다"


# ── 사용자 위임 식별자 — 정적 백엔드도 위임 대상이 될 수 있다 ───────────────
#
# 이 한 줄이 틀리면 **위임을 켠 줄 알았는데 서비스 계정으로 나간다.** 호출은 성공하고
# 도구 목록도 정상이라, 잡 소유자가 한 명으로 뭉친 것을 한참 뒤에야 안다.
def test_heax_backend_keys_drop_the_prefix(monkeypatch):
    monkeypatch.setattr(gw, "PER_USER_SSO", {"hwax_risk": {"sso_url": "x", "secret": "y"}})
    assert gw._delegation_app_id("heax-hwax_risk") == "hwax_risk"


def test_a_static_backend_in_per_user_sso_uses_its_own_key(monkeypatch):
    """ste 처럼 설정에 직접 적은 백엔드는 접두사가 없다 — 키가 곧 식별자다."""
    monkeypatch.setattr(gw, "PER_USER_SSO", {"ste": {"sso_url": "x", "secret": "y"}})
    assert gw._delegation_app_id("ste") == "ste"


def test_a_static_backend_not_in_per_user_sso_is_not_delegated(monkeypatch):
    """위임 설정이 없는 백엔드까지 끌어들이면 없는 SSO 를 부르다 매 호출이 실패한다."""
    monkeypatch.setattr(gw, "PER_USER_SSO", {"ste": {"sso_url": "x", "secret": "y"}})
    assert gw._delegation_app_id("ai-data-hub") == ""
    assert gw._delegation_app_id("smart-twin-mcp") == ""


def test_empty_per_user_sso_delegates_nothing_static(monkeypatch):
    monkeypatch.setattr(gw, "PER_USER_SSO", {})
    assert gw._delegation_app_id("ste") == ""
    # heax 앱은 목록과 무관하게 접두사를 뗀다(그다음 단계에서 PER_USER_SSO 를 다시 본다)
    assert gw._delegation_app_id("heax-kooremapper_mcp") == "kooremapper_mcp"


# ── REST 다리(rest_catalog·rest_call) ─────────────────────────────────────────
# 이 표면이 틀리면 **실패가 성공처럼 생긴다.** 세 모양을 특히 못 하게 못박는다.
#   ① 권한 없는 사이트가 '빈 목록' 으로 보여 "REST 가 없다" 로 읽히는 것
#   ② OpenAPI 를 못 받았는데 paths:[] 로 내려 "경로가 없다" 로 읽히는 것
#   ③ 상류가 4xx 인데 payload 에 error 가 없어 모델이 body 를 답으로 읽는 것
def _payload(res):
    return json.loads(res.content[0].text)


@pytest.fixture
def _rest(monkeypatch):
    """rest 사이트 둘 — inject 있는 것(읽기전용)과 없는 것(제한 없음)."""
    conf = {
        "locked": {"base": "http://127.0.0.1:1", "inject": {"header": "X-Key", "value": "k"}},
        "open": {"base": "http://127.0.0.1:2"},
    }
    monkeypatch.setattr(gw, "REST", conf)
    monkeypatch.setattr(gw, "POLICY", {"locked": [], "open": ["analyst"]})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    monkeypatch.setattr(gw, "_request_user", lambda: "me@x.com")
    gw._openapi_cache.clear()
    return conf


def test_rest_tools_hidden_without_sites(monkeypatch):
    """사이트가 0개면 다리를 아예 안 낸다 — 못 쓰는 도구를 목록에 두면 모델이 그것을 고른다."""
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "route", {})
    monkeypatch.setattr(gw, "REST", {})
    assert {"rest_catalog", "rest_call"} & {t.name for t in gw._visible_tools([])} == set()
    monkeypatch.setattr(gw, "REST", {"s": {"base": "http://x"}})
    assert {"rest_catalog", "rest_call"} <= {t.name for t in gw._visible_tools([])}


def test_allowed_methods_is_one_definition():
    """메서드 규칙의 정본은 rest_proxy 하나다 — 게이트웨이가 그것을 부른다."""
    import rest_proxy
    assert gw.allowed_methods is rest_proxy.allowed_methods
    assert gw.allowed_methods({"inject": {"header": "a", "value": "b"}}) == ["GET", "HEAD"]
    assert gw.allowed_methods({"inject": {}, "methods": ["POST"]}) == ["POST"]   # 명시가 이긴다
    # **쓰기의 기본은 닫힘이다.** 자격이 아무것도 없는 사이트(`none`)도 묶는다 —
    # 상류가 무인증 200 이면(ai-data-hub 실측) 이 관문이 유일한 통제라, 여기서 열면
    # 전문가챗 허가만 가진 사람이 LLM 으로 변경 op 를 그대로 부른다.
    assert gw.allowed_methods({}) == ["GET", "HEAD"]
    # per_user 만 제한이 풀린다 — 호출자 본인 토큰이라 그 사이트 규칙이 그대로 적용된다.
    assert gw.allowed_methods({"per_user": "ste"}) is None


@pytest.mark.anyio
async def test_rest_catalog_hides_what_i_cannot_use(_rest, monkeypatch):
    monkeypatch.setattr(gw, "_openapi_of", _noop_openapi)
    out = _payload(await gw._rest_catalog({}))
    assert [s["site"] for s in out["sites"]] == ["locked"]      # open 은 analyst 전용
    assert "note" not in out                                    # 하나라도 보이면 잔소리 안 한다
    monkeypatch.setattr(gw, "_request_groups", lambda: ["analyst"])
    out = _payload(await gw._rest_catalog({}))
    assert sorted(s["site"] for s in out["sites"]) == ["locked", "open"]
    # 하나도 못 쓰면 **빈 목록만 주고 끝내지 않는다** — 왜 비었고 어디서 권한을 받는지 말한다.
    monkeypatch.setattr(gw, "POLICY", {"locked": ["x"], "open": ["y"]})
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    out = _payload(await gw._rest_catalog({}))
    assert out["sites"] == [] and "내 권한" in out["note"]


@pytest.mark.anyio
async def test_rest_catalog_forbidden_is_not_an_empty_list(_rest, monkeypatch):
    """권한 없는 사이트를 콕 찍으면 **사유**가 온다. 빈 목록은 '없다' 로 읽힌다."""
    monkeypatch.setattr(gw, "_openapi_of", _noop_openapi)
    out = _payload(await gw._rest_catalog({"site": "open"}))
    assert out["error"].startswith("forbidden:")
    out = _payload(await gw._rest_catalog({"site": "nope"}))
    assert out["error"].startswith("unknown site:") and out["known"] == ["locked"]


async def _noop_openapi(site):
    return None


@pytest.mark.anyio
async def test_rest_catalog_unreachable_openapi_says_so(_rest, monkeypatch):
    """OpenAPI 를 못 받으면 paths 는 **None** 이고 note 가 붙는다(빈 목록이 아니다)."""
    monkeypatch.setattr(gw, "_openapi_of", _noop_openapi)
    row = _payload(await gw._rest_catalog({"site": "locked"}))["sites"][0]
    assert row["paths"] is None and "note" in row and "path_count" not in row
    assert row["readonly"] is True and row["methods"] == ["GET", "HEAD"]


@pytest.mark.anyio
async def test_rest_catalog_summary_until_asked(_rest, monkeypatch):
    doc = {"info": {"title": "T"}, "paths": {
        "/api/jobs": {"get": {"summary": "잡 목록"}, "post": {"summary": "잡 제출"}},
        "/api/health": {"get": {"description": "상태\n둘째줄"}},
        "/api/x": {"options": {}},                              # 대상 메서드가 아니면 버린다
    }}

    async def _doc(site):
        return doc
    monkeypatch.setattr(gw, "_openapi_of", _doc)
    bare = _payload(await gw._rest_catalog({}))["sites"][0]
    assert bare["path_count"] == 3 and "paths" not in bare and "hint" in bare
    got = _payload(await gw._rest_catalog({"site": "locked"}))["sites"][0]
    assert [(r["method"], r["path"]) for r in got["paths"]] == [
        ("GET", "/api/health"), ("GET", "/api/jobs"), ("POST", "/api/jobs")]
    assert got["paths"][0]["summary"] == "상태"                  # 첫 줄만
    q = _payload(await gw._rest_catalog({"q": "제출"}))["sites"][0]
    assert [r["path"] for r in q["paths"]] == ["/api/jobs"] and q["path_count"] == 1
    cut = _payload(await gw._rest_catalog({"site": "locked", "limit": 1}))["sites"][0]
    assert len(cut["paths"]) == 1 and "truncated" in cut        # 잘랐으면 잘랐다고 말한다


@pytest.mark.anyio
async def test_rest_call_gates_before_touching_upstream(_rest, monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("막혀야 하는 호출이 상류로 나갔다")
    monkeypatch.setattr(gw.httpx, "AsyncClient", _boom)
    assert _payload(await gw._rest_call({"site": "nope", "path": "/x"}))["error"] \
        .startswith("unknown site:")
    assert _payload(await gw._rest_call({"site": "open", "path": "/x"}))["error"] \
        .startswith("forbidden:")
    assert "path 가 비었다" in _payload(await gw._rest_call({"site": "locked", "path": " "}))["error"]
    bad = _payload(await gw._rest_call({"site": "locked", "path": "/x", "method": "post"}))
    assert bad["error"] == "method not allowed for this site" and "GET/HEAD" in bad["detail"]


class _Up:
    """rest_call 이 이제 `cli.stream()` 으로 받는다 — 본문을 청크로 흘리는 가짜 응답."""
    def __init__(self, status, raw: bytes, ctype="application/json", clen=None):
        self.status_code, self._raw = status, raw
        self.headers = {"content-type": ctype}
        if clen is not None:
            self.headers["content-length"] = str(clen)
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def aiter_bytes(self):
        for i in range(0, len(self._raw), 4096):
            _Cli.streamed += 1
            yield self._raw[i:i + 4096]


class _Cli:
    seen = {}
    status = 200
    raw = b'{"ok": true}'
    ctype = "application/json"
    clen = None
    streamed = 0

    def __init__(self, *a, **k): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False

    def stream(self, method, url, params=None, json=None, headers=None):
        _Cli.seen = {"method": method, "url": url, "params": params, "json": json,
                     "headers": headers}
        return _Up(_Cli.status, _Cli.raw, _Cli.ctype, _Cli.clen)


@pytest.mark.anyio
async def test_rest_call_forwards_and_marks_failure(_rest, monkeypatch):
    monkeypatch.setattr(gw.httpx, "AsyncClient", _Cli)
    _Cli.status, _Cli.raw, _Cli.ctype, _Cli.clen = 200, b'{"ok": true}', "application/json", None
    out = _payload(await gw._rest_call({"site": "locked", "path": "health",
                                        "query": {"n": 2}}))
    assert out["status"] == 200 and out["body"] == {"ok": True} and "error" not in out
    assert _Cli.seen["url"] == "http://127.0.0.1:1/health"      # 앞 슬래시를 붙여 준다
    assert _Cli.seen["params"] == {"n": "2"}
    assert _Cli.seen["headers"]["X-Key"] == "k"                 # 사이트 자기 자격 주입
    assert _Cli.seen["headers"]["x-forwarded-user"] == "me@x.com"
    _Cli.status = 404
    bad = _payload(await gw._rest_call({"site": "locked", "path": "/nope"}))
    assert bad["status"] == 404 and bad["error"].endswith("404 로 답했다")



# ── 정책을 못 받은 상태 — per_user 백엔드만 닫는다 ─────────────────────────────
# 정책 dict 가 비어 있으면 `_backend_allowed` 는 "제한 없음" 으로 허용한다. 그런데 **못 받음**(새 클론에
# 캐시 없음·옛 포털 404·포털 미기동 부팅)도 같은 빈 dict 다. 그 상태에서 ste·kooremapper 를 부르면
# 시크릿을 쥔 게이트웨이가 임의 이메일로 그 앱 계정을 JIT 생성한다(2026-09-24 적대 검토).
def test_per_user_backend_is_denied_until_policy_is_received(monkeypatch):
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "PER_USER_SSO", {"ste": {"sso_url": "http://x", "secret": "s"},
                                             "kooremapper_mcp": {"sso_url": "http://y", "secret": "s"}})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", False)
    assert gw._backend_allowed("ste", ["plat:smarttwin"]) is False           # 위임 백엔드 — 닫힘
    assert gw._backend_allowed("heax-kooremapper_mcp", ["plat:dynaforge"]) is False  # heax 접두 위임도
    assert gw._backend_allowed("heax-step_forge", ["plat:stepforge"]) is True  # heax 접두지만 위임 아님 — 열림
    assert gw._backend_allowed("ai-data-hub", ["plat:aidatahub"]) is True     # 위임 아님 — 종전대로(가용성)
    assert gw._backend_allowed("ste", [gw.SERVICE_GROUP]) is True             # 내부 서비스는 사람이 아니다
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    assert gw._backend_allowed("ste", ["plat:smarttwin"]) is True             # 받았고 비었다 = 제한 없음


def test_receiving_an_unchanged_policy_still_marks_ready(monkeypatch, tmp_path):
    """값이 같아도 '받았다' 는 사실은 남아야 한다 — 안 남기면 재기동마다 위임이 60초 동안 닫힌다."""
    import httpx as _h
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {"sf": ["plat:stepforge"]})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", False)
    monkeypatch.setattr(gw, "_ACCESS_CACHE_FILE", tmp_path / "c.json")
    monkeypatch.setattr(gw, "_portal_api_base", lambda: "http://portal")

    class _R:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {"backends": {"sf": ["plat:stepforge"]}}

    class _C:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, *a, **k): return _R()
    monkeypatch.setattr(gw.httpx, "AsyncClient", _C)
    asyncio.run(gw._refresh_access_policy())
    assert gw._ACCESS_POLICY_READY is True and gw._ACCESS_POLICY == {"sf": ["plat:stepforge"]}


def test_loading_the_disk_cache_marks_ready(monkeypatch, tmp_path):
    f = tmp_path / "c.json"; f.write_text(json.dumps({"ste": ["plat:smarttwin"]}), encoding="utf-8")
    monkeypatch.setattr(gw, "_ACCESS_CACHE_FILE", f)
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", False)
    gw._load_access_cache()
    assert gw._ACCESS_POLICY_READY is True and gw._ACCESS_POLICY == {"ste": ["plat:smarttwin"]}



# ── rest_call 응답 상한 — 모델에 보일 텍스트/JSON 전용이다 ─────────────────────────
# 종전엔 본문 전체를 받은 뒤 json·text 로 두 벌을 더 만들었다. 모델이 `result.zip` 을 이 도구로 부르면
# 게이트웨이가 수 GB 를 삼킨다(120MB 에 피크 521MB 실측, 2026-09-24). 넘치면 **스트림을 끊는다.**
@pytest.mark.anyio
async def test_rest_call_cuts_the_stream_when_the_body_exceeds_the_cap(_rest, monkeypatch):
    monkeypatch.setattr(gw.httpx, "AsyncClient", _Cli)
    monkeypatch.setattr(gw, "REST_CALL_MAX_BYTES", 10_000)
    _Cli.status, _Cli.raw, _Cli.ctype, _Cli.clen, _Cli.streamed = 200, b"x" * 100_000, "application/zip", None, 0
    out = _payload(await gw._rest_call({"site": "locked", "path": "/big.zip"}))
    assert "넘는다" in out["error"] and out["content_type"] == "application/zip"
    # 100KB 를 다 읽지 않았다 — 4KB 청크로 상한(10KB)을 넘긴 직후 끊었다
    assert _Cli.streamed <= 4, _Cli.streamed


@pytest.mark.anyio
async def test_rest_call_trusts_content_length_and_reads_nothing(_rest, monkeypatch):
    """상류가 크기를 미리 말하면 한 바이트도 안 읽는다."""
    monkeypatch.setattr(gw.httpx, "AsyncClient", _Cli)
    monkeypatch.setattr(gw, "REST_CALL_MAX_BYTES", 10_000)
    _Cli.status, _Cli.raw, _Cli.ctype, _Cli.clen, _Cli.streamed = 200, b"x" * 20, "application/zip", 5_000_000, 0
    out = _payload(await gw._rest_call({"site": "locked", "path": "/big.zip"}))
    assert "넘는다" in out["error"] and _Cli.streamed == 0


@pytest.mark.anyio
async def test_rest_call_small_text_still_passes(_rest, monkeypatch):
    monkeypatch.setattr(gw.httpx, "AsyncClient", _Cli)
    _Cli.status, _Cli.raw, _Cli.ctype, _Cli.clen = 200, b"hello", "text/plain", 5
    out = _payload(await gw._rest_call({"site": "locked", "path": "/t"}))
    assert out["status"] == 200 and out["body"] == "hello" and "error" not in out


# ── RA 위임이 조용히 꺼지던 것(2026-09-29) ───────────────────────────────────
# 프로비저너 --force 가 portal 블록을 api_base 없이 다시 쓰자 `_portal_connection` 이 포털에 묻지도
# 않고 전원을 '미등록' 으로 돌려, 연결을 등록한 사람의 RA 글까지 서비스 토큰 주인 명의로 올라갔다.
class _Portal:
    """httpx.AsyncClient 자리 — /internal/connections 응답을 정한다. 받은 요청을 기록한다."""
    status, payload, exc = 200, None, None
    seen: list = []

    def __init__(self, *a, **k): pass

    async def __aenter__(self): return self

    async def __aexit__(self, *a): return False

    async def get(self, url, params=None, headers=None):
        _Portal.seen.append((url, dict(params or {}), dict(headers or {})))
        if _Portal.exc is not None:
            raise _Portal.exc
        from types import SimpleNamespace as NS
        return NS(status_code=_Portal.status, json=lambda: _Portal.payload)


def _portal(monkeypatch, status=200, payload=None, exc=None, portal_cfg=None):
    _Portal.status, _Portal.payload, _Portal.exc, _Portal.seen = status, payload, exc, []
    monkeypatch.setattr(gw.httpx, "AsyncClient", _Portal)
    monkeypatch.setattr(gw, "PORTAL", portal_cfg if portal_cfg is not None
                        else {"jwks_url": "http://127.0.0.1:8723/.well-known/jwks.json"})
    gw._CONN_CACHE.clear()


def test_연결조회는_api_base_없이도_jwks_주소로_포털에_묻는다(monkeypatch):
    import asyncio
    _portal(monkeypatch, 200, {"token": "rat_u", "workspace": "dept"})     # 프로비저너가 쓰는 모양 그대로
    conn = asyncio.run(gw._portal_connection("reportarchive", "u@corp.com"))
    assert conn == {"token": "rat_u", "workspace": "dept"}
    url, params, headers = _Portal.seen[0]
    assert url == "http://127.0.0.1:8723/internal/connections/reportarchive"
    assert params == {"email": "u@corp.com"} and headers["Authorization"] == f"Bearer {gw.GW_TOKEN}"


def test_연결조회_없음과_모름을_가른다(monkeypatch):
    import asyncio
    _portal(monkeypatch, 404)
    assert asyncio.run(gw._portal_connection("reportarchive", "u@corp.com")) is None
    for status in (403, 503, 500):
        _portal(monkeypatch, status)
        with pytest.raises(gw._ConnLookupError, match=str(status)):
            asyncio.run(gw._portal_connection("reportarchive", "u@corp.com"))
    _portal(monkeypatch, exc=OSError("refused"))
    with pytest.raises(gw._ConnLookupError):
        asyncio.run(gw._portal_connection("reportarchive", "u@corp.com"))
    _Portal.exc = None                                   # 포털이 살아나도 짧은 캐시 동안은 모름이다
    with pytest.raises(gw._ConnLookupError):
        asyncio.run(gw._portal_connection("reportarchive", "u@corp.com"))
    assert len(_Portal.seen) == 1
    _portal(monkeypatch, portal_cfg={})                  # 주소를 아예 모른다 — 묻지도 못한다
    with pytest.raises(gw._ConnLookupError, match="주소"):
        asyncio.run(gw._portal_connection("reportarchive", "u@corp.com"))
    assert _Portal.seen == []


def _ra_kit(monkeypatch, tool, *, backend="reportarchive", svc_headers=None, **portal):
    """RA 백엔드 하나로 `_call_tool` 을 실제로 태운다. 사용자 세션은 전송 계층만 막는다(`_call_as_user` 는 진짜).
    `backend`·`svc_headers` 로 같은 등록 토큰 길의 다른 백엔드(TestScope)를 태운다."""
    import asyncio
    b = _CallB([tool])
    b.headers = (dict(svc_headers) if svc_headers is not None
                 else {"Authorization": "Bearer rat_service", "X-Workspace-Slug": "svc"})
    user = {}

    class _Sess:
        async def initialize(self): return None

        async def call_tool(self, original, arguments, read_timeout_seconds=None):
            user["tool"] = original
            return types.CallToolResult(content=[types.TextContent(type="text", text="{}")], isError=False)

    def fake_stream(url, headers=None, **_kw):
        user["headers"] = dict(headers or {})
        return _StubCM((None, None, "sid"))

    monkeypatch.setattr(gw, "streamablehttp_client", fake_stream)
    monkeypatch.setattr(gw, "ClientSession", lambda read, write: _StubCM(_Sess()))
    gw._RESP_CACHE.clear()
    monkeypatch.setattr(gw, "backends", {backend: b})
    monkeypatch.setattr(gw, "route", {tool: (backend, tool)})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setattr(gw, "_request_user", lambda: "u@corp.com")
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    _portal(monkeypatch, **portal)
    res = asyncio.run(gw._call_tool(tool, {}))
    rows = [json.loads(ln) for ln in open(gw.AUDIT_PATH, encoding="utf-8")]
    return res, b.session.calls, user, rows[-1]


def test_등록한_사람의_RA_쓰기는_api_base_없이도_본인_명의다(monkeypatch):
    res, svc, user, row = _ra_kit(monkeypatch, "create_report_draft",
                                  status=200, payload={"token": "rat_u", "workspace": "dept"})
    assert not res.isError and svc == [], "서비스 세션으로 가면 서비스 토큰 주인이 글쓴이가 된다"
    assert user["headers"]["Authorization"] == "Bearer rat_u" and user["headers"]["X-Workspace-Slug"] == "dept"
    assert row["mode"] == "as-conn" and row["caller"] == "u@corp.com"


def test_포털을_못_물으면_RA_를_서비스_계정으로_부르지_않는다(monkeypatch):
    for tool in ("create_report_draft", "get_report"):
        for kw in ({"status": 403}, {"status": 503}, {"exc": OSError("refused")}, {"portal_cfg": {}}):
            res, svc, user, row = _ra_kit(monkeypatch, tool, **kw)
            assert res.isError and svc == [] and user == {}, (tool, kw)
            assert "관리자" in res.content[0].text
            assert row["mode"] == "refused" and row["note"] == "conn-lookup-error" and row["ok"] is False
            assert row["caller"] == "u@corp.com"


def test_미등록_사람의_RA_호출은_읽기든_쓰기든_거부하고_등록을_안내한다(monkeypatch):
    """VOC(2026-09-29): 본인 PAT 로 붙었는데 'mine' 이 personal-5(서비스 토큰 주인 공간)로 풀리고 보고서도 그리로
    갔다. 서비스 계정 폴백이 실제 사람의 RA 토큰 행세였다 — 사용자 결정으로 거부한다."""
    for tool in ("create_report_draft", "list_reports", "get_report"):
        res, svc, user, row = _ra_kit(monkeypatch, tool, status=404)
        assert res.isError and svc == [] and user == {}, tool
        assert "외부 연결" in res.content[0].text and "등록" in res.content[0].text
        assert row["mode"] == "refused" and row["note"] == "no-connection" and row["caller"] == "u@corp.com"


def test_신원_없는_내부_호출만_서비스_계정으로_간다(monkeypatch):
    import asyncio
    b = _CallB(["list_templates"])
    monkeypatch.setattr(gw, "backends", {"reportarchive": b})
    monkeypatch.setattr(gw, "route", {"list_templates": ("reportarchive", "list_templates")})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setattr(gw, "_request_user", lambda: "")
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    _portal(monkeypatch, 404)
    gw._RESP_CACHE.clear()
    res = asyncio.run(gw._call_tool("list_templates", {}))
    row = [json.loads(ln) for ln in open(gw.AUDIT_PATH, encoding="utf-8")][-1]
    assert not res.isError and b.session.calls == ["list_templates"] and _Portal.seen == []
    assert row["mode"] == "service" and row["note"] == "no-identity"


# ── TestScope 도 등록 토큰 방식(다른 조직의 포털이라 ste 방식 위임 대신 — 2026-10-03 사용자 결정) ─────────
def test_TestScope_는_본인이_등록한_토큰으로만_가고_부서_헤더를_싣지_않는다(monkeypatch):
    """포털이 workspace 를 돌려줘도 X-Workspace-Slug 는 RA 의 것이다 — TestScope 에는 싣지 않는다.
    손으로 붙인 다른 헤더는 건드리지 않는다."""
    assert gw.PORTAL_CONN_BACKENDS["testscope"] == "testscope"
    res, svc, user, row = _ra_kit(monkeypatch, "list_equipment", backend="testscope",
                                  svc_headers={"X-Keep": "1"},
                                  status=200, payload={"token": "tsc_pat_u", "workspace": "dept"})
    assert not res.isError and svc == []
    assert _Portal.seen[0][0].endswith("/internal/connections/testscope")
    assert user["headers"]["Authorization"] == "Bearer tsc_pat_u" and user["headers"]["X-Keep"] == "1"
    assert not any(k.lower() == "x-workspace-slug" for k in user["headers"])
    assert row["mode"] == "as-conn" and row["caller"] == "u@corp.com"


def test_미등록_사람의_TestScope_호출은_거부하고_TestScope_토큰_등록을_안내한다(monkeypatch):
    res, svc, user, row = _ra_kit(monkeypatch, "list_equipment", backend="testscope", svc_headers={}, status=404)
    text = res.content[0].text
    assert res.isError and svc == [] and user == {}, "토큰 없이 부르면 남의 포털에 익명으로 간다"
    assert "TestScope" in text and "tsc_pat_" in text and "외부 연결" in text and "등록" in text
    assert "Report Archive" not in text and "rat_" not in text
    assert row["mode"] == "refused" and row["note"] == "no-connection"
    res, svc, user, row = _ra_kit(monkeypatch, "list_equipment", backend="testscope", svc_headers={}, status=503)
    assert res.isError and svc == [] and user == {} and "관리자" in res.content[0].text
    assert row["note"] == "conn-lookup-error"


def test_신원_없는_TestScope_호출은_서비스_세션으로_간다(monkeypatch):
    import asyncio
    b = _CallB(["list_equipment"])
    monkeypatch.setattr(gw, "backends", {"testscope": b})
    monkeypatch.setattr(gw, "route", {"list_equipment": ("testscope", "list_equipment")})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setattr(gw, "_request_user", lambda: "")
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    _portal(monkeypatch, 404)
    gw._RESP_CACHE.clear()
    res = asyncio.run(gw._call_tool("list_equipment", {}))
    row = [json.loads(ln) for ln in open(gw.AUDIT_PATH, encoding="utf-8")][-1]
    assert not res.isError and b.session.calls == ["list_equipment"] and _Portal.seen == []
    assert row["mode"] == "service" and row["note"] == "no-identity"


# ── TestScope 도 RA 처럼 두 방식 — per_user_sso.testscope 가 있으면 ste 방식 위임이 등록 토큰보다 먼저(2026-10-03) ──
_TS_SSO = {"sso_url": "http://testscope.example/api/auth/sso", "secret": "ts-s", "client": "gateway"}


def _ts_kit(monkeypatch, per_user_sso, sso_status=200):
    """testscope 백엔드 하나로 `_call_tool` 을 태운다. 발급(`_user_pat`·`_mint_user_pat`)과 포털 연결 조회
    (`_portal_connection`)는 진짜이고 둘이 같은 가짜 HTTP 를 지나므로, 어느 길을 탔는지 요청 기록으로 본다."""
    import asyncio
    http = []

    def handler(req):
        http.append((req.method, str(req.url), dict(req.headers)))
        if req.url.path == "/api/auth/sso":
            return httpx.Response(sso_status, json={"access_token": "tsc_pat_minted", "expires_in": 86400})
        return httpx.Response(200, json={"token": "tsc_pat_registered", "workspace": "dept"})
    _mock_http(monkeypatch, handler)
    b = _CallB(["list_equipment"])
    b.headers = {"X-Keep": "1"}
    user = {}

    class _Sess:
        async def initialize(self): return None

        async def call_tool(self, original, arguments, read_timeout_seconds=None):
            return types.CallToolResult(content=[types.TextContent(type="text", text="{}")], isError=False)

    def fake_stream(url, headers=None, **_kw):
        user["headers"] = dict(headers or {})
        return _StubCM((None, None, "sid"))

    async def fake_access(email, base_groups, **_kw):
        return {"keys": [], "affiliation": ""}
    monkeypatch.setattr(gw, "streamablehttp_client", fake_stream)
    monkeypatch.setattr(gw, "ClientSession", lambda read, write: _StubCM(_Sess()))
    monkeypatch.setattr(gw, "_portal_access", fake_access)
    monkeypatch.setattr(gw, "PER_USER_SSO", per_user_sso)
    monkeypatch.setattr(gw, "_USER_PATS", {})
    monkeypatch.setattr(gw, "_USER_PAT_LOCKS", {})
    gw._RESP_CACHE.clear()
    gw._CONN_CACHE.clear()
    monkeypatch.setattr(gw, "backends", {"testscope": b})
    monkeypatch.setattr(gw, "route", {"list_equipment": ("testscope", "list_equipment")})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setattr(gw, "_request_user", lambda: "u@corp.com")
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    res = asyncio.run(gw._call_tool("list_equipment", {}))
    return res, b.session.calls, user, http, _rows()[-1]


def test_TestScope_위임이_있으면_발급한_토큰으로_가고_등록_토큰은_묻지_않는다(monkeypatch):
    res, svc, user, http, row = _ts_kit(monkeypatch, {"testscope": dict(_TS_SSO)})
    assert not res.isError and svc == []
    assert user["headers"]["Authorization"] == "Bearer tsc_pat_minted"
    assert user["headers"]["X-Keep"] == "1", "strip_headers 가 없으니 서비스 헤더는 그대로"
    assert not any(k.lower() == "x-workspace-slug" for k in user["headers"])
    assert [(m, u) for m, u, _h in http] == [("POST", "http://testscope.example/api/auth/sso")], \
        "포털 /internal/connections 를 묻지 않는다 — 위임이 먼저다"
    h = http[0][2]
    assert (h["x-heax-gateway-secret"], h["x-heax-user-email"], h["x-heax-client"]) == ("ts-s", "u@corp.com", "gateway")
    assert row["mode"] == "as-user-pat" and row["caller"] == "u@corp.com"


def test_TestScope_위임이_없으면_같은_백엔드가_등록_토큰으로_간다(monkeypatch):
    """위 시험과 같은 장치에서 항목만 뺀다 — 방식을 가르는 것은 설정 한 줄이다."""
    res, svc, user, http, row = _ts_kit(monkeypatch, {})
    assert not res.isError and svc == [] and user["headers"]["Authorization"] == "Bearer tsc_pat_registered"
    assert [(m, u) for m, u, _h in http] == [("GET", "http://portal/internal/connections/testscope?email=u%40corp.com")]
    assert row["mode"] == "as-conn"


def test_TestScope_가_발급을_못_하면_거부하고_등록_토큰으로_돌아가지_않는다(monkeypatch):
    """비밀을 자동으로 만들지 않는 이유다 — TestScope 에 /api/auth/sso 가 생기기 전에 위임이 켜지면 사람별 호출이 전부 이렇게 된다."""
    res, svc, user, http, row = _ts_kit(monkeypatch, {"testscope": dict(_TS_SSO)}, sso_status=404)
    assert res.isError and svc == [] and user == {}
    assert "자격증명으로 호출하지 못했습니다" in res.content[0].text
    assert [u for _m, u, _h in http] == ["http://testscope.example/api/auth/sso"] * 2, "1회 재발급 뒤 멈추고 포털은 묻지 않는다"
    assert row["ok"] is False



# ── 허브에서 끈 앱(개인 MCP 시야에서 숨김 — HWAXPortal docs/mcp-app-toggle) ─────────────────────────
def _gate(monkeypatch, portal_resp):
    """인증 미들웨어를 실제로 태워 **앱이 받는 헤더**를 돌려준다. 포털 응답만 가짜."""
    import asyncio
    seen = {}

    async def app(scope, receive, send):
        seen["headers"] = {k.decode().lower(): v.decode() for k, v in scope["headers"]}

    async def fake_access(email, base, **_kw):
        return portal_resp
    monkeypatch.setattr(gw, "_portal_access", fake_access)
    monkeypatch.setattr(gw, "GW_TOKEN", "gw-secret")

    class _V:
        def __init__(self, claims): self.claims = claims
        async def verify(self, token, aud): return self.claims

    def run(auth, claims, forged=b"heax-step_forge"):
        seen.clear()
        mw = gw._bearer_gate(app, _V(claims))
        hdrs = [(b"authorization", auth), (gw.MUTED_HEADER.encode(), forged)]
        asyncio.run(mw({"type": "http", "path": "/mcp", "headers": hdrs}, None, None))
        return seen.get("headers", {})
    return run


def test_끈_앱은_개인_PAT_에만_실리고_챗_절차_PAT_와_서비스_경로는_면제다(monkeypatch):
    run = _gate(monkeypatch, {"keys": [], "muted_apps": ["signalforge", "heax-step_forge"]})
    h = run(b"Bearer me", {"email": "u@x.io", "groups": []})
    assert h[gw.MUTED_HEADER] == "signalforge,heax-step_forge", "포털 값이 그대로(클라이언트 값이 아니라)"
    h = run(b"Bearer chat", {"email": "u@x.io", "groups": [], "pat_name": gw.CHAT_PAT_NAME, "jti": "chat-u-1790000000"})
    assert gw.MUTED_HEADER not in h, "웹 챗 PAT 까지 거르면 /보고서·띵킹이 코드로 부르는 도구가 사라진다"
    h = run(b"Bearer mine", {"email": "u@x.io", "groups": [], "pat_name": gw.CHAT_PAT_NAME, "jti": "k3Jd9…random"})
    assert h[gw.MUTED_HEADER], "개인 토큰 이름을 chat-session 으로 지어도 챗 PAT 가 아니다(이름은 사용자가 정한다)"
    h = run(b"Bearer proc", {"email": "u@x.io", "groups": [], "purpose": gw.PROCEDURE_PURPOSE})
    assert gw.MUTED_HEADER not in h, "절차는 tools/list 로 카탈로그를 만든다"
    h = run(b"Bearer gw-secret", None)
    assert gw.MUTED_HEADER not in h, "GW_TOKEN(에이전트서버·심의)에는 싣지 않고 클라이언트 사본도 버린다"
    run2 = _gate(monkeypatch, {"keys": []})                       # 끈 앱이 없으면
    assert gw.MUTED_HEADER not in run2(b"Bearer me", {"email": "u@x.io", "groups": []}), "위조 사본이 살아남으면 안 된다"


def _muted_ctx(monkeypatch, muted: str, groups: str = ""):
    _set_request_headers(monkeypatch, {gw.MUTED_HEADER: muted, gw.GROUPS_HEADER: groups})
    monkeypatch.setattr(gw, "exposed_tools", [_tool("sf_q"), _tool("step_x"), _tool("ra_get")])
    monkeypatch.setattr(gw, "route", {"sf_q": ("signalforge", "sf_q"), "step_x": ("heax-step_forge", "step_x"),
                                      "ra_get": ("reportarchive", "get_report")})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)


def test_끈_앱은_도구_목록과_검색에서_빠진다(monkeypatch):
    import asyncio
    _muted_ctx(monkeypatch, "heax-step_forge,signalforge")
    names = {t.name for t in gw._visible_tools([])}
    assert "step_x" not in names and "sf_q" not in names and "ra_get" in names
    assert "search_tools" in names and "invoke_tool" in names, "허브 자체 도구는 끌 수 없다"
    for q, want in (("ra_get", True), ("step_x", False), ("sf_q", False)):
        out = json.loads(asyncio.run(gw._search_tools({"query": q})).content[0].text)
        got = {r["tool"] for r in out["matches"]}
        assert (q in got) is want, (q, got)                         # 켠 앱은 찾고(대조군) 끈 앱은 못 찾는다


def test_끈_앱은_권한없음과_다른_칸에_나오고_콕_집으면_도구를_보인다(monkeypatch):
    import asyncio
    _muted_ctx(monkeypatch, "heax-step_forge")
    monkeypatch.setattr(gw, "backends", {k: _CallB([]) for k in ("signalforge", "heax-step_forge", "reportarchive")})
    body = json.loads(asyncio.run(gw._list_tool_apps({})).content[0].text)
    assert "heax-step_forge" not in {a["app"] for a in body["apps"]}
    assert [m["app"] for m in body["muted_apps"]] == ["heax-step_forge"]
    assert not body["denied_apps"], "끈 앱을 권한 없음으로 적으면 모델이 권한을 요청하라고 안내한다"
    one = json.loads(asyncio.run(gw._list_tool_apps({"app": "heax-step_forge"})).content[0].text)
    assert one["apps"][0]["muted"] is True and one["apps"][0]["tools"][0]["name"] == "step_x"
    area = json.loads(asyncio.run(gw._list_tool_apps({"by": "area"})).content[0].text)
    assert area["hidden_muted"] == 1 and all("step_x" not in a["tools"] for a in area["areas"])


def test_끈_앱도_이름을_주면_호출된다(monkeypatch):
    """숨김만 한다(D-3) — 끄기는 권한이 아니라 선호다."""
    import asyncio
    b = _CallB(["step_x"])
    _muted_ctx(monkeypatch, "heax-step_forge")
    monkeypatch.setattr(gw, "backends", {"heax-step_forge": b})
    monkeypatch.setattr(gw, "route", {"step_x": ("heax-step_forge", "step_x")})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "_request_user", lambda: "")
    gw._RESP_CACHE.clear()
    r = asyncio.run(gw._call_tool("invoke_tool", {"name": "step_x", "arguments": {}}))
    assert not r.isError and b.session.calls == ["step_x"]


def test_운영자_전문가의_앱을_끈_사람에게는_먼저_알리라고_표시한다(monkeypatch):
    import asyncio
    _muted_ctx(monkeypatch, "heax-step_forge")
    sess = {"data": {"system_prompt": "역할", "response_config": {
        "persona_kind": "mcp_operator", "mcp_apps": ["heax-step_forge"], "key_tools": ["step_x"]}}}

    async def fake_call(name, args):
        return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(sess))])
    monkeypatch.setattr(gw, "_call_tool", fake_call)
    out = json.loads(asyncio.run(gw._use_experts({"keys": ["op.step"]})).content[0].text)
    e = out["experts"][0]
    assert e["muted_apps"] == ["heax-step_forge"] and "먼저 알리" in e["muted_note"]


def test_포털이_앱_설정을_바꾸면_권한_캐시도_비워_바로_반영된다(monkeypatch):
    import asyncio
    monkeypatch.setattr(gw, "GW_TOKEN", "gw-secret")
    gw._ENT_CACHE.clear()
    gw._ENT_CACHE[("u@x.io", "")] = ({"keys": [], "muted_apps": []}, 1e12)
    gw._ENT_CACHE[("other@x.io", "")] = ({"keys": []}, 1e12)
    sent = []

    async def send(m): sent.append(m)
    mw = gw._bearer_gate(None, None)
    asyncio.run(mw({"type": "http", "path": "/conn-invalidate", "method": "POST", "query_string": b"email=u@x.io",
                    "headers": [(b"authorization", b"Bearer gw-secret")]}, None, send))
    assert sent[0]["status"] == 200
    assert ("u@x.io", "") not in gw._ENT_CACHE and ("other@x.io", "") in gw._ENT_CACHE
    gw._ENT_CACHE.clear()


def test_계정을_정지하면_그_사람의_위임_토큰_연결_응답_캐시만_비운다(monkeypatch):
    """포털의 계정 정지(HWAXPortal `auth/routes/local.py` `_revoke_app_credentials`)가 이 호출에 기댄다. ste 는 토큰을
    클라이언트별로 회수하므로 포털의 ste 회수는 게이트웨이가 쥔 토큰을 죽이지 못한다 — `_USER_PATS` 에서 빼는 것이 유일한
    제거다. 이 줄이 사라져도 시험이 전부 통과했다(포털 쪽 시험의 게이트웨이는 200 만 답하는 대역이다) — 그러면 포털은
    `app_revocations.gateway = "ok"` 라고 답하는데 정지된 사람의 토큰은 캐시 수명(12시간) 동안 남는다."""
    import asyncio
    from collections import OrderedDict
    monkeypatch.setattr(gw, "GW_TOKEN", "gw-secret")
    monkeypatch.setattr(gw, "_USER_PATS", {("ste", "u@x.io"): ("tok-u-ste", 1e12),
                                           ("reportarchive", "u@x.io"): ("tok-u-ra", 1e12),
                                           ("ste", "other@x.io"): ("tok-o-ste", 1e12)})
    monkeypatch.setattr(gw, "_CONN_CACHE", {("reportarchive", "u@x.io"): ({"token": "c-u"}, 1e12),
                                            ("reportarchive", "other@x.io"): ({"token": "c-o"}, 1e12)})
    # 응답 캐시 키의 넷째 칸이 호출자 신원이다(`_cache_key`).
    monkeypatch.setattr(gw, "_RESP_CACHE", OrderedDict([(("ste", "list_x", "{}", "u@x.io", (), ""), ("r-u", 1e12)),
                                                        (("ste", "list_x", "{}", "other@x.io", (), ""), ("r-o", 1e12))]))
    monkeypatch.setattr(gw, "_ENT_CACHE", {})
    monkeypatch.setattr(gw, "_ENT_LAST", {})
    sent = []

    async def send(m): sent.append(m)
    mw = gw._bearer_gate(None, None)
    asyncio.run(mw({"type": "http", "path": "/conn-invalidate", "method": "POST", "query_string": b"email=u@x.io",
                    "headers": [(b"authorization", b"Bearer gw-secret")]}, None, send))
    assert sent[0]["status"] == 200
    assert json.loads(sent[1]["body"]) == {"ok": True, "dropped": 1, "resp_dropped": 1, "pat_dropped": 2}
    assert set(gw._USER_PATS) == {("ste", "other@x.io")}, "정지된 사람의 ste·RA 위임 토큰이 게이트웨이에 남았다"
    assert set(gw._CONN_CACHE) == {("reportarchive", "other@x.io")}
    assert list(gw._RESP_CACHE) == [("ste", "list_x", "{}", "other@x.io", (), "")]


def test_포털이_알리면_불통_때_쓰는_직전_권한도_그_사람_것만_버린다(monkeypatch):
    """`_ENT_CACHE`(60초)만 비우고 만료 없는 `_ENT_LAST` 를 두면, 그 사람의 다음 호출이 포털 불통과 겹칠 때 회수 전 답이
    되살아난다. 포털이 알렸다는 것은 **쥐고 있는 답이 틀렸다**는 뜻이다."""
    import asyncio
    monkeypatch.setattr(gw, "GW_TOKEN", "gw-secret")
    monkeypatch.setattr(gw, "_ENT_CACHE", {})
    monkeypatch.setattr(gw, "_ENT_LAST", {("u@x.io", "mes-user"): {"keys": ["plat:risk"], "is_admin": True},
                                          ("u@x.io", ""): {"keys": ["plat:risk"]},
                                          ("other@x.io", "mes-user"): {"keys": ["feat:chat"]}})

    def post(query):
        sent = []

        async def send(m): sent.append(m)
        asyncio.run(gw._bearer_gate(None, None)({"type": "http", "path": "/conn-invalidate", "method": "POST",
                                                 "query_string": query,
                                                 "headers": [(b"authorization", b"Bearer gw-secret")]}, None, send))
        return sent[0]["status"]
    assert post(b"email=U@x.io") == 200
    assert set(gw._ENT_LAST) == {("other@x.io", "mes-user")}, \
        "그 사람 것은 로그인 그룹이 달라도 전부, 남의 것은 그대로 — 남의 것까지 버리면 불통 때 그 사람의 도구가 사라진다"
    assert post(b"") == 200 and gw._ENT_LAST == {}, "이메일 없이 부르면 전부 비운다(다른 캐시와 같다)"


def test_지침이_끈_앱을_권한_문제와_구분하라고_말한다():
    assert "muted_apps" in gw._INSTRUCTIONS and "요청하라고 하지 마라" in gw._INSTRUCTIONS
    assert len(gw._INSTRUCTIONS) < 2048, "Claude Code 는 서버 지침을 2048자에서 자른다"


def test_포털이_찍는_챗_PAT_표지와_게이트웨이가_보는_값이_같다():
    """한쪽만 바꾸면 웹 챗 PAT 에도 끄기가 걸려 /보고서·띵킹이 코드로 부르는 도구가 사라진다. 형제 리포가 있을 때만 본다."""
    from pathlib import Path
    src = Path(gw.__file__).resolve().parent.parent / "HWAXPortal" / "backend" / "app" / "agent" / "routes.py"
    if not src.exists():
        pytest.skip("형제 HWAXPortal 리포가 없다")
    text = src.read_text(encoding="utf-8")
    assert f'"pat_name": "{gw.CHAT_PAT_NAME}"' in text
    assert '"jti": f"chat-' in text, "게이트웨이는 챗 PAT 를 jti 의 'chat-' 머리로도 가린다"


# ── 감사에 호출 주소·자격(HWAXPortal docs/gateway-audit-ip) ─────────────────
# 주소는 문서용 예약 대역(TEST-NET)만 쓴다 — 이 리포는 GitHub 에 있다.
def _set_request(monkeypatch, headers: dict, host):
    """`_set_request_headers` 에 **주소**를 더한다 — 실제 요청은 Starlette Request 라 `.client.host` 가 있다."""
    from types import SimpleNamespace as NS
    client = NS(host=host) if host is not None else None
    monkeypatch.setattr(gw, "_low", NS(request_context=NS(request=NS(headers=headers, client=client))))


def _rows():
    return [json.loads(ln) for ln in open(gw.AUDIT_PATH, encoding="utf-8")]


def test_감사가_호출_주소와_자격과_계정을_스스로_남긴다(monkeypatch):
    """호출부 23곳은 그대로 두고 `_audit` 이 요청에서 읽는다 — 넘기게 하면 빠뜨린 자리가 빈 칸이 된다
    (대화 저장·검색 줄이 그래서 계정이 비어 있었다, D-6)."""
    _set_request(monkeypatch, {gw.VIA_HEADER: "pat", gw.USER_HEADER: "u%40x.io"}, "203.0.113.7")
    gw._audit("save_conversation", "portal", True, None, 3)            # caller 를 안 넘기던 자리
    r = _rows()[-1]
    assert (r["ip"], r["via"], r["caller"]) == ("203.0.113.7", "pat", "u@x.io")
    gw._audit("t", "b", True, None, 1, caller="given@x.io", ip="198.51.100.2", via="gw-token")
    r = _rows()[-1]
    assert (r["ip"], r["via"], r["caller"]) == ("198.51.100.2", "gw-token", "given@x.io"), "넘긴 값이 우선"


@pytest.mark.parametrize("host,want", [
    ('evil"}{ x', None),            # uvicorn 은 X-Forwarded-For 토큰을 그대로 client 로 쓴다(검증 2026-09-29)
    ("testclient", None),
    ("", None),
    ("2001:DB8::1", "2001:db8::1"),
    (" 203.0.113.9 ", "203.0.113.9"),
    ('fe80::1%attacker said "hi" <b>', None),   # IPv6 영역 표기 — ip_address 는 % 뒤를 아무 글자나 받는다(검토 1차)
    ("::1%203.0.113.9", None),
    ("::ffff:203.0.113.4", "203.0.113.4"),     # IPv4 로 풀어 적어야 주소로 찾을 때 안 빠진다
])
def test_주소가_아닌_값은_칸만_빼고_줄은_남긴다(monkeypatch, host, want):
    _set_request(monkeypatch, {}, host)
    gw._audit("t", "b", True, None, 1)
    r = _rows()[-1]
    assert r["tool"] == "t" and r.get("ip") == want


def test_주소를_못_읽어도_줄이_사라지지_않는다(monkeypatch):
    """`_audit` 은 통째로 except 로 감싼다 — 주소 읽기가 터지면 **줄 전체**가 사라진다(D-4)."""
    from types import SimpleNamespace as NS
    _set_request_headers(monkeypatch, {gw.PURPOSE_HEADER: "procedure"})      # .client 가 없는 가짜
    gw._audit("t1", "b", True, None, 1)
    assert _rows()[-1]["tool"] == "t1" and _rows()[-1]["purpose"] == "procedure" and "ip" not in _rows()[-1]

    class _Boom:
        headers: dict = {}

        @property
        def client(self):
            raise RuntimeError("boom")
    monkeypatch.setattr(gw, "_low", NS(request_context=NS(request=_Boom())))
    gw._audit("t2", "b", True, None, 1)
    assert _rows()[-1]["tool"] == "t2", "주소 읽기가 터져도 줄은 남는다"


def _via_seen(monkeypatch, auth, claims, extra=()):
    """인증 미들웨어를 태워 앱이 받는 `x-hwax-via` 를 **전부**(중복 포함) 돌려준다."""
    import asyncio
    seen = {}

    async def app(scope, receive, send):
        seen["h"] = list(scope["headers"])

    async def fake_access(email, base, **_kw):
        return {"keys": []}
    monkeypatch.setattr(gw, "_portal_access", fake_access)
    monkeypatch.setattr(gw, "GW_TOKEN", "gw-secret")

    class _V:
        async def verify(self, token, aud):
            return claims
    mw = gw._bearer_gate(app, _V())
    asyncio.run(mw({"type": "http", "path": "/mcp", "headers": [(b"authorization", auth), *extra]}, None, None))
    return [v.decode() for k, v in seen.get("h", []) if k.lower() == gw.VIA_HEADER.encode()]


def test_들어온_자격은_게이트웨이가_정하고_보낸_사본은_버린다(monkeypatch):
    """127.0.0.1 만으로는 '웹 챗 경유' 와 '박스 안 Claude Code' 를 못 가른다 — 자격을 게이트웨이가 적는다(D-5)."""
    forged = ((gw.VIA_HEADER.encode(), b"gw-token"),)
    me = {"email": "u@x.io", "groups": []}
    assert _via_seen(monkeypatch, b"Bearer me", me, forged) == ["pat"]
    assert _via_seen(monkeypatch, b"Bearer c", {**me, "pat_name": gw.CHAT_PAT_NAME, "jti": "chat-u-1"},
                     forged) == ["chat"]
    assert _via_seen(monkeypatch, b"Bearer c", {**me, "pat_name": gw.CHAT_PAT_NAME, "jti": "random"}) == ["pat"], \
        "이름만 chat-session 인 개인 토큰은 챗이 아니다(이름은 사용자가 정한다)"
    assert _via_seen(monkeypatch, b"Bearer p", {**me, "purpose": gw.PROCEDURE_PURPOSE}, forged) == ["procedure"]
    assert _via_seen(monkeypatch, b"Bearer gw-secret", None, ((gw.VIA_HEADER.encode(), b"pat"),)) == ["gw-token"]


def test_인증_실패는_주소와_사유를_남기고_계정은_적지_않는다(monkeypatch):
    """누가 틀린 토큰으로 두드렸는지 — 계정은 모르므로(검증 안 된 토큰의 주장) 주소와 사유만(D-7)."""
    import asyncio
    monkeypatch.setattr(gw, "GW_TOKEN", "gw-secret")

    class _V:
        async def verify(self, token, aud):
            return {"email": "a@x.io", "groups": []} if token == "valid" else None

    async def app(scope, receive, send):
        raise AssertionError("인증 없이 앱까지 가면 안 된다")
    sent = []

    async def send(m):
        sent.append(m)
    mw = gw._bearer_gate(app, _V())

    def hit(path, *auth, method="POST"):
        hdrs = [(b"authorization", a) for a in auth]
        asyncio.run(mw({"type": "http", "method": method, "path": path, "headers": hdrs,
                        "client": ("198.51.100.9", 0)}, None, send))
    hit("/mcp")
    hit("/mcp", b"Bearer forged.jwt.value")
    hit("/mcp/.well-known/openid-configuration")
    # 두 번 실린 Authorization 은 **둘 다 유효해도** 거절한다 — 검증은 마지막, 대화 저장·검색은 첫 것을 쓴다(검토 1차)
    hit("/mcp", b"Bearer other", b"Bearer valid")
    hit("/mcp", method="A" * 7000)                               # 토큰 없이 보낸 긴 메서드가 원장에 그대로 실리면 안 된다
    rows = _rows()
    assert [r["error"] for r in rows] == ["unauthorized: no-bearer", "unauthorized: unverified-token",
                                          "unauthorized: duplicate-authorization", "unauthorized: no-bearer"], \
        "클라이언트의 OAuth 메타데이터 조회(.well-known)는 정상 동작 중에도 401 이라 적지 않는다"
    assert [r["tool"] for r in rows] == ["POST /mcp"] * 3 + ["OTHER /mcp"]
    assert all(r["ip"] == "198.51.100.9" and not r["ok"] and "caller" not in r for r in rows)
    assert sum(1 for m in sent if m.get("status") == 401) == 5


def test_REST_다리도_주소와_이메일_계정을_남긴다(monkeypatch):
    """REST 다리(/api/)는 MCP 컨텍스트 밖이라 `_audit` 이 스스로 못 읽는다 — 직접 넘긴다. 계정은 `sub` 가 아니라
    이메일(MCP 줄과 같게, D-6)."""
    import asyncio
    from starlette.requests import Request
    from rest_proxy import RestProxy

    async def deny(site, groups, email):
        return False

    async def no_revoked():
        return set()
    p = RestProxy({"s": {"base": "http://upstream.invalid"}}, {"audience_ok": ["s"]}, gw._audit, allow=deny)
    p._verify = lambda token, site: {"sub": "S-123", "email": "U@X.io", "jti": "j", "groups": []}
    p._revoked_set = no_revoked

    def call(auth, path="x"):
        hdrs = [(b"authorization", auth)] if auth else []
        return asyncio.run(p.handle(Request({
            "type": "http", "method": "GET", "path": f"/api/s/{path}", "headers": hdrs, "query_string": b"",
            "path_params": {"site": "s", "path": path}, "client": ("203.0.113.5", 0)})))
    assert call(b"Bearer t").status_code == 403                  # 권한 없음 — 상류는 안 부른다
    assert call(None).status_code == 401
    rows = _rows()
    assert (rows[0]["error"], rows[0]["caller"], rows[0]["ip"], rows[0]["via"]) == \
        ("forbidden", "u@x.io", "203.0.113.5", "pat")
    assert rows[1]["error"] == "pat: missing bearer" and rows[1]["ip"] == "203.0.113.5" and "caller" not in rows[1]
    call(None, "p" * 8000)                                        # 토큰 없이 보낸 긴 경로 — 원장 한 줄이 8KB 가 되면 안 된다
    assert len(_rows()[-1]["tool"]) <= 220


# ── ste 가 사용자 토큰을 거절한 결과면 1회 재발급(HWAXPortal docs/ste-cae00 D-30) ─────────────────
def _remint_kit(monkeypatch, replies: list[str | None]):
    """위임 경로를 실제로 태운다(전송 계층만 막는다). `replies` 는 호출마다 백엔드가 돌려줄 결과 — None 이면 성공,
    문자열이면 그 문구의 isError 결과다. 호출마다 **어느 토큰을 실었는지**와 발급 때의 force 를 돌려준다."""
    import asyncio

    b = _CallB(["cluster_info"])
    seen = {"tokens": [], "force": [], "calls": 0}
    queue = list(replies)

    class _Sess:
        async def initialize(self): return None

        async def call_tool(self, original, arguments, read_timeout_seconds=None):
            seen["calls"] += 1
            err = queue.pop(0)
            return types.CallToolResult(content=[types.TextContent(type="text", text=err or '{"nodes": []}')],
                                        isError=err is not None)

    def fake_stream(url, headers=None, **_kw):
        seen["tokens"].append((headers or {}).get("Authorization"))
        return _StubCM((None, None, "sid"))

    async def fake_pat(app_id, email, *, force=False):
        seen["force"].append(force)
        return "new-tok" if force else "old-tok"

    async def fake_access(email, base_groups, **_kw):
        return {"keys": [], "affiliation": ""}
    monkeypatch.setattr(gw, "streamablehttp_client", fake_stream)
    monkeypatch.setattr(gw, "ClientSession", lambda read, write: _StubCM(_Sess()))
    gw._RESP_CACHE.clear()
    monkeypatch.setattr(gw, "backends", {"ste": b})
    monkeypatch.setattr(gw, "route", {"cluster_info": ("ste", "cluster_info")})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setattr(gw, "PER_USER_SSO", {"ste": {"sso_url": "http://x", "secret": "s"}})
    monkeypatch.setattr(gw, "_request_user", lambda: "u@corp.com")
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    monkeypatch.setattr(gw, "_user_pat", fake_pat)
    monkeypatch.setattr(gw, "_portal_access", fake_access)
    res = asyncio.run(gw._call_tool("cluster_info", {}))
    seen["result"] = res
    return seen


_STE_401 = ('Error executing tool cluster_info: GET /api/cluster → HTTP 401: {"detail":"토큰이 폐기됐다"}'
            ' — 신원이 없거나 토큰이 죽었다.')


def test_ste_가_토큰을_거절하면_한_번_다시_받아_부른다(monkeypatch):
    """401 은 예외가 아니라 isError 결과로 온다 — 예외에만 재발급하던 탓에 폐기된 캐시 토큰을 12시간 계속 썼다."""
    seen = _remint_kit(monkeypatch, [_STE_401, None])
    assert seen["calls"] == 2 and seen["force"] == [False, True]
    assert seen["tokens"] == ["Bearer old-tok", "Bearer new-tok"], "두 번째는 새로 받은 토큰이어야 한다"
    assert not seen["result"].isError
    row = _rows()[-1]
    assert (row["mode"], row["ok"], row.get("note")) == ("as-user-pat", True, "re-minted")


def test_다시_받아도_거절되면_두_번에서_멈추고_그대로_알린다(monkeypatch):
    seen = _remint_kit(monkeypatch, [_STE_401, _STE_401])
    assert seen["calls"] == 2 and seen["result"].isError
    assert "HTTP 401" in seen["result"].content[0].text, "무엇이 실패했는지 그대로 전한다"


@pytest.mark.parametrize("err", [
    "Error executing tool cluster_info: GET /api/cluster → HTTP 503: 클러스터 조회 실패",   # 토큰 문제가 아니다(slurm)
    "Error executing tool fetch_url: 원격 서버가 HTTP 401 을 냈다",                        # 도구가 바깥에서 받은 401
    "GET /api/cluster → HTTP 401: x",                                                    # FastMCP 가 감싼 모양이 아니다
])
def test_토큰_거절이_아니면_다시_부르지_않는다(monkeypatch, err):
    """쓰기 도구를 두 번 부를 수 있으니 모양을 좁게 본다."""
    seen = _remint_kit(monkeypatch, [err, None])
    assert seen["calls"] == 1 and seen["force"] == [False] and seen["result"].isError


# ── 위임 토큰 캐시는 토큰 제 수명을 넘기지 않는다(RA 위임 JWT 12시간 = 캐시 12시간, docs/sso-delegation) ──
class _Clock:
    """gateway 가 보는 `time` 만 갈아끼운다 — 전역 time.monotonic 을 바꾸면 이벤트 루프까지 흔들린다."""
    def __init__(self):
        import time as _t
        self._t, self.now = _t, 1000.0

    def monotonic(self):
        return self.now

    def __getattr__(self, n):
        return getattr(self._t, n)


def _mint_kit(monkeypatch, body_for):
    """실제 `_user_pat`·`_mint_user_pat` 을 태우고 SSO 엔드포인트만 가짜로 둔다. 발급 횟수를 센다."""
    n = {"mints": 0}

    def handler(req):
        n["mints"] += 1
        return httpx.Response(200, json=body_for(n["mints"]))
    _mock_http(monkeypatch, handler)
    clk = _Clock()
    monkeypatch.setattr(gw, "time", clk)
    monkeypatch.setattr(gw, "_USER_PATS", {})
    monkeypatch.setattr(gw, "_USER_PAT_LOCKS", {})
    monkeypatch.setattr(gw, "USER_PAT_TTL_S", 43200)
    monkeypatch.setattr(gw, "PER_USER_SSO", {"reportarchive": {"sso_url": "http://ra/api/auth/sso", "secret": "s"}})
    return n, clk


def _pat_at(clk, t):
    clk.now = 1000.0 + t
    return gw._user_pat("reportarchive", "u@corp.com")


def test_사용자_토큰_캐시는_expires_in_보다_먼저_버린다(monkeypatch):
    # RA 봉투 모양 그대로 — expires_in 은 토큰과 같은 객체에 있다.
    n, clk = _mint_kit(monkeypatch, lambda i: {"success": True, "data": {"access_token": f"t{i}", "expires_in": 600}})

    async def run():
        return [await _pat_at(clk, 0), await _pat_at(clk, 479), await _pat_at(clk, 481)]
    assert asyncio.run(run()) == ["t1", "t1", "t2"], "만료 2분 전(600-120=480초)에 다시 받아야 한다"
    assert n["mints"] == 2


@pytest.mark.parametrize("body", [{"access_token": "t"}, {"access_token": "t", "expires_in": "600"},
                                  {"access_token": "t", "expires_in": True}, {"access_token": "t", "expires_in": 0}])
def test_expires_in_이_없거나_이상하면_캐시_수명대로(monkeypatch, body):
    n, clk = _mint_kit(monkeypatch, lambda i: body)

    async def run():
        await _pat_at(clk, 0)
        await _pat_at(clk, 43199)
        await _pat_at(clk, 43201)
    asyncio.run(run())
    assert n["mints"] == 2


def test_expires_in_이_캐시보다_길면_캐시_수명이_이긴다(monkeypatch):
    """TestScope 위임 PAT 는 1일 — 권한 회수 반영은 캐시 수명(12시간)이 정한다."""
    n, clk = _mint_kit(monkeypatch, lambda i: {"access_token": f"t{i}", "expires_in": 86400})

    async def run():
        return [await _pat_at(clk, 0), await _pat_at(clk, 43199), await _pat_at(clk, 43201)]
    assert asyncio.run(run()) == ["t1", "t1", "t2"]


def test_expires_in_이_2분도_안_남으면_캐시하지_않는다(monkeypatch):
    n, clk = _mint_kit(monkeypatch, lambda i: {"access_token": f"t{i}", "expires_in": 60})

    async def run():
        return [await _pat_at(clk, 0), await _pat_at(clk, 0)]
    assert asyncio.run(run()) == ["t1", "t2"]


# ── 재연결 재시도도 신원을 싣는다(HWAXPortal docs/change-request-8-10 #17) ─────────────────────────
class _DeadSess(_CallSess):
    """객체는 살아 있는데 호출하면 터지는 상주 세션 — 앱이 재기동된 뒤의 모양이다."""
    async def call_tool(self, original, args, read_timeout_seconds=None):
        raise RuntimeError("session closed")


class _ReconB(_CallB):
    """`_call_tool` 의 재연결 분기를 태우는 백엔드 — reconnect 가 새 상주 세션을 세우고 횟수를 센다."""
    def __init__(self, tools, session="up"):
        super().__init__(tools)
        self._tools, self.reconnects = tools, 0
        self.session = {"up": self.session, "dead": _DeadSess([]), "none": None}[session]

    async def reconnect(self, tg, seen_gen=None):
        self.reconnects += 1
        self.session = _CallSess([_tool(n) for n in self._tools])


def _recon_kit(monkeypatch, backend, *, session="up", oneshot_fails=0, user="u@corp.com",
               groups=("mes-user", "feat:chat"), headers=None):
    """재연결 분기를 실제로 태운다(전송 계층만 막는다). 단발 세션(신원 호출)의 연결은 `oneshot_fails` 번까지 터진다.
    돌려주는 것 — 결과 · 백엔드(상주 세션이 받은 호출·재연결 횟수) · 단발 세션이 연결마다 실은 헤더 · 감사 마지막 줄.
    `headers` 를 주면 신원을 흉내 내지 않고 그 요청 헤더에서 읽는다(인증 미들웨어가 만든 헤더를 그대로 얹을 때)."""
    b = _ReconB(["deliberate_status"], session)
    shots = []

    class _Sess:
        async def initialize(self): return None

        async def call_tool(self, original, arguments, read_timeout_seconds=None):
            return types.CallToolResult(content=[types.TextContent(type="text", text="{}")], isError=False)

    def fake_stream(url, headers=None, **_kw):
        shots.append(dict(headers or {}))
        if len(shots) <= oneshot_fails:
            raise httpx.ConnectError("refused")
        return _StubCM((None, None, "sid"))

    monkeypatch.setattr(gw, "streamablehttp_client", fake_stream)
    monkeypatch.setattr(gw, "ClientSession", lambda read, write: _StubCM(_Sess()))
    gw._RESP_CACHE.clear()
    monkeypatch.setattr(gw, "backends", {backend: b})
    monkeypatch.setattr(gw, "route", {"deliberate_status": (backend, "deliberate_status")})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setattr(gw, "PER_USER_SSO", {})
    monkeypatch.setattr(gw, "IDENTITY_FWD", {"hwax-deliberation"})
    monkeypatch.setattr(gw, "_task_group_holder", {"tg": object()})
    monkeypatch.setattr(gw, "_REAGG", {})
    if headers is None:
        monkeypatch.setattr(gw, "_request_user", lambda: user)
        monkeypatch.setattr(gw, "_request_groups", lambda: list(groups))
    else:
        _set_request_headers(monkeypatch, headers)
    res = asyncio.run(gw._call_tool("deliberate_status", {"job_id": "j1"}))
    return res, b, shots, _rows()[-1]


def _carries_identity(headers: dict) -> bool:
    return (headers.get(gw.USER_HEADER) == "u@corp.com"
            and headers.get(gw.GROUPS_HEADER) == "mes-user,feat:chat")


def test_재연결_재시도도_신원을_싣는다(monkeypatch):
    """신원 호출이 터져 재연결한 뒤의 재시도가 **상주 세션(서비스 계정)** 으로 나갔다 — 심의가 서비스 계정 시야로
    돌아 '내 것이 하나도 없다' 가 된다(실측 2026-10-07 04:13Z `deliberate_status`·`via=pat`). 정상 경로와 같은 분기를 탄다."""
    res, b, shots, row = _recon_kit(monkeypatch, "hwax-deliberation", oneshot_fails=1)
    assert not res.isError and b.reconnects == 1
    assert b.session.calls == [], f"재시도가 서비스 세션으로 나갔다: {b.session.calls}"
    assert len(shots) == 2 and _carries_identity(shots[1]), "재시도의 단발 세션이 신원 헤더를 실어야 한다"
    assert (row["mode"], row["note"], row["caller"], row["ok"]) == ("identity-fwd", "reconnected", "u@corp.com", True)
    assert gw._REAGG.get("pending") is True, "재연결했으면 카탈로그 재집계를 예약한다(종전대로)"


def test_상주_세션이_죽어_있어도_신원_호출은_재연결_없이_나간다(monkeypatch):
    """신원 호출은 상주 세션을 쓰지 않는다(호출마다 단발 세션) — 그런데 세션 검사가 먼저라 죽은 상주 세션 때문에
    재연결 분기로 떨어졌고, 거기서 서비스 계정으로 나갔다."""
    res, b, shots, row = _recon_kit(monkeypatch, "hwax-deliberation", session="none")
    assert not res.isError and b.reconnects == 0 and b.session is None
    assert len(shots) == 1 and _carries_identity(shots[0])
    assert (row["mode"], row["caller"]) == ("identity-fwd", "u@corp.com") and "note" not in row


def test_상주_세션이_죽은_채_단발_호출도_터지면_재연결_뒤_신원으로_다시_부른다(monkeypatch):
    res, b, shots, row = _recon_kit(monkeypatch, "hwax-deliberation", session="none", oneshot_fails=1)
    assert not res.isError and b.reconnects == 1 and b.session.calls == []
    assert len(shots) == 2 and _carries_identity(shots[1])
    assert (row["mode"], row["note"]) == ("identity-fwd", "reconnected")


def test_재시도까지_터지면_서비스_계정으로_돌아가지_않고_실패를_알린다(monkeypatch):
    res, b, shots, row = _recon_kit(monkeypatch, "hwax-deliberation", oneshot_fails=2)
    assert res.isError and "unavailable" in res.content[0].text
    assert b.session.calls == [] and len(shots) == 2 and row["ok"] is False


@pytest.mark.parametrize("backend,session,user,groups", [
    ("signalforge", "none", "u@corp.com", ("mes-user",)),     # 신원 전달 대상이 아닌 백엔드 — 세션이 없던 경우
    ("signalforge", "dead", "u@corp.com", ("mes-user",)),     # 〃 — 세션은 있는데 호출이 터진 경우
    ("hwax-deliberation", "none", "", ()),                    # 대상 백엔드라도 신원이 아예 없으면 서비스 세션
    ("hwax-deliberation", "dead", "", ()),
])
def test_신원_전달_대상이_아니면_재시도는_종전대로_서비스_세션이다(monkeypatch, backend, session, user, groups):
    """과하게 넓히지 않는다 — 그리고 첫 시도가 세션 검사에서 던진 경우에도 재시도가 터지지 않는다(변수 미정의)."""
    res, b, shots, row = _recon_kit(monkeypatch, backend, session=session, user=user, groups=groups)
    assert not res.isError, res.content[0].text
    assert b.reconnects == 1 and b.session.calls == ["deliberate_status"] and shots == []
    assert (row["mode"], row["note"], row.get("caller")) == ("service", "reconnected", user or None)


# ── 내부 목적지는 사내 프록시를 거치지 않는다(HWAXPortal docs/change-request-8-10 #2 · D-8) ───────────
#
# httpx 는 **클라이언트를 만드는 순간**의 환경으로 프록시를 정한다(trust_env 기본값). 그래서 판정은 "이 환경에서 새로 만든
# 클라이언트가 이 주소를 어디로 보내는가" 로 한다 — 연결은 하지 않는다(프록시 주소도 가짜다).
import logging  # noqa: E402
import os  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402

_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy")
_REAL_ASYNC_CLIENT = httpx.AsyncClient      # `_mock_http` 류가 모듈 속성을 갈아 끼우므로 진짜를 잡아 둔다
_LOOPBACK = "127.0.0.1,localhost,::1"
_INSIDE = ["http://ra.corp.test:3002/mcp", "https://ra.corp.test/api/auth/sso", "http://192.0.2.10:8000/mcp"]
_OUTSIDE = "https://example.com/"


def _proxy_env(monkeypatch, upper=None, lower=None):
    """사내 프록시가 걸린 환경. `NO_PROXY` 두 철자는 준 대로 둔다(None = 변수 없음)."""
    for k in _PROXY_VARS:
        monkeypatch.setenv(k, "")       # 먼저 한 번 적어야 시험 뒤에 원래대로 돌아간다 — 없던 변수의 delenv 는 기록이 안 남는다
        monkeypatch.delenv(k)
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    if upper is not None:
        monkeypatch.setenv("NO_PROXY", upper)
    if lower is not None:
        monkeypatch.setenv("no_proxy", lower)


def _route(url: str) -> str:
    """지금 환경에서 **새로 만든** httpx 클라이언트가 이 주소를 보내는 곳 — 'direct' | 'proxy'."""
    c = _REAL_ASYNC_CLIENT(timeout=8)
    try:
        return "direct" if c._transport_for_url(httpx.URL(url)) is c._transport else "proxy"
    finally:
        asyncio.run(c.aclose())


@pytest.mark.parametrize("upper,lower,want_upper,want_lower", [
    (None, None, f"{_LOOPBACK},ra.corp.test,192.0.2.10", f"{_LOOPBACK},ra.corp.test,192.0.2.10"),
    # 한쪽 철자에만 있던 값은 다른 쪽이 이어받는다 — 파이썬은 소문자를 먼저 보므로, 소문자를 우리 호스트만으로 새로
    # 만들면 대문자에 적어 둔 것이 통째로 무시된다(있던 우회가 사라진다).
    ("a.test", None, f"a.test,{_LOOPBACK},ra.corp.test,192.0.2.10", f"a.test,{_LOOPBACK},ra.corp.test,192.0.2.10"),
    (None, "a.test", f"a.test,{_LOOPBACK},ra.corp.test,192.0.2.10", f"a.test,{_LOOPBACK},ra.corp.test,192.0.2.10"),
    ("a.test", "", f"a.test,{_LOOPBACK},ra.corp.test,192.0.2.10", f"a.test,{_LOOPBACK},ra.corp.test,192.0.2.10"),
    # 둘 다 있으면 서로 섞지 않는다 — 각자 제 값 뒤에 붙인다
    ("a.test", "b.test, c.test", f"a.test,{_LOOPBACK},ra.corp.test,192.0.2.10",
     f"b.test,c.test,{_LOOPBACK},ra.corp.test,192.0.2.10"),
    # 이미 있는 것은 다시 적지 않는다(대소문자 무관). 포트가 붙은 항목은 그 포트만 덮으므로 호스트를 따로 더한다
    ("localhost,RA.Corp.Test,192.0.2.10:9", None, f"localhost,RA.Corp.Test,192.0.2.10:9,127.0.0.1,::1,192.0.2.10",
     f"localhost,RA.Corp.Test,192.0.2.10:9,127.0.0.1,::1,192.0.2.10"),
])
def test_NO_PROXY_에_더하되_있던_값은_지우지_않는다(monkeypatch, upper, lower, want_upper, want_lower):
    _proxy_env(monkeypatch, upper, lower)
    gw._bypass_proxy_for(_INSIDE)
    assert (os.environ["NO_PROXY"], os.environ["no_proxy"]) == (want_upper, want_lower)
    assert [_route(u) for u in _INSIDE + ["http://127.0.0.1:9009/mcp", "http://localhost:8723/", "http://[::1]:3002/mcp"]] \
        == ["direct"] * 6
    assert _route(_OUTSIDE) == "proxy", "바깥 주소까지 우회시키면 안 된다"
    assert gw._bypass_proxy_for(_INSIDE) == [], "두 번 불러도 같은 값이다"
    assert (os.environ["NO_PROXY"], os.environ["no_proxy"]) == (want_upper, want_lower)


@pytest.mark.parametrize("upper,lower,want,outside", [
    ("*", None, ("*", "*"), "direct"),            # 이미 전부 우회 — 뒤에 덧붙이면 urllib 은 더는 '전부' 로 읽지 않는다
    (None, "*", ("*", "*"), "direct"),
    # 파이썬이 실제로 보는 것은 소문자다 — 대문자의 `*` 를 소문자로 끌어오지 않는다(바깥 호출까지 프록시를 벗어난다)
    ("*", "a.test", ("*", f"a.test,{_LOOPBACK},ra.corp.test,192.0.2.10"), "proxy"),
])
def test_NO_PROXY_가_별표면_그대로_둔다(monkeypatch, upper, lower, want, outside):
    _proxy_env(monkeypatch, upper, lower)
    gw._bypass_proxy_for(_INSIDE)
    assert (os.environ["NO_PROXY"], os.environ["no_proxy"]) == want
    assert [_route(u) for u in _INSIDE] == ["direct"] * 3 and _route(_OUTSIDE) == outside


def test_대역과_점_표기가_이미_있어도_주소를_따로_더한다(monkeypatch):
    """httpx 는 `NO_PROXY` 의 CIDR 을 대역으로 읽지 않고(네트워크 주소 하나로만 맞춘다) `.corp.test` 는 하위 도메인만 덮는다.
    '이미 덮여 있겠지' 하고 건너뛰면 그 주소만 계속 프록시로 간다."""
    _proxy_env(monkeypatch, "192.0.2.0/24,.corp.test", "192.0.2.0/24,.corp.test")
    urls = ["http://192.0.2.10:8000/mcp", "https://corp.test/mcp"]
    assert [_route(u) for u in urls] == ["proxy", "proxy"], "이 시험의 전제 — httpx 가 달리 읽게 되면 여기서 알린다"
    assert gw._bypass_proxy_for(urls) == ["127.0.0.1", "localhost", "::1", "192.0.2.10", "corp.test"]
    assert [_route(u) for u in urls] == ["direct", "direct"]
    assert os.environ["NO_PROXY"].startswith("192.0.2.0/24,.corp.test,")


def test_NO_PROXY_에는_호스트만_적고_로그에도_호스트만_남긴다(monkeypatch, caplog):
    """주소에 계정·`?token=` 이 실린 백엔드가 있다 — 환경변수와 기동 로그에 새면 안 된다. 그리고 못 읽는 항목 하나가
    `NO_PROXY` 에 들어가면 httpx 는 **클라이언트를 만드는 자리마다** 던진다(`[::1]` 로 재현) — 이상한 호스트는 적지 않는다."""
    _proxy_env(monkeypatch)
    with caplog.at_level(logging.INFO, logger="hwax-mcp-gateway"):
        added = gw._bypass_proxy_for([
            "http://user:PW-SECRET@ra.corp.test:3002/mcp?token=QUERY-SECRET", "https://[2001:db8::7]:8443/mcp",
            None, "", "nohost", "http://*/x", "http://[fe80::1%25eth0]:9/x", "http://exa mple/x", "http://[::1/x"])
    assert added == ["127.0.0.1", "localhost", "::1", "ra.corp.test", "2001:db8::7"]
    assert os.environ["NO_PROXY"] == os.environ["no_proxy"] == f"{_LOOPBACK},ra.corp.test,2001:db8::7"
    said = "\n".join(r.getMessage() for r in caplog.records)
    assert "ra.corp.test" in said and "2001:db8::7" in said
    for leak in ("SECRET", "token=", "user:", "3002"):
        assert leak not in said, f"로그에 주소의 다른 부분이 샜다: {leak}"
    assert _route("https://[2001:db8::7]:8443/mcp") == "direct", "클라이언트가 만들어지고 IPv6 도 맞는다"
    assert any(r.levelno == logging.WARNING and "*" in r.getMessage() for r in caplog.records), \
        "못 적은 호스트는 조용히 넘기지 않는다 — 그 주소는 여전히 프록시를 탄다"


def test_레지스트리로_뒤늦게_발견된_앱의_호스트도_더한다(monkeypatch):
    _proxy_env(monkeypatch, "a.test")
    monkeypatch.setattr(gw, "HEAX", {"servers_url": "http://hub.corp.test:4040/servers", "base": "http://late.corp.test:4180"})
    monkeypatch.setattr(gw.httpx, "AsyncClient", lambda **kw: _REAL_ASYNC_CLIENT(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, json={"servers": [{"id": "app1", "path": "/app1/mcp"}]})), **kw))
    assert _route("http://late.corp.test:4180/app1/mcp") == "proxy"
    found = asyncio.run(gw._discover_heax())
    assert found["heax-app1"]["url"] == "http://late.corp.test:4180/app1/mcp"
    assert _route("http://late.corp.test:4180/app1/mcp") == "direct", "이 뒤에 여는 세션이 프록시를 타면 안 된다"
    assert os.environ["NO_PROXY"].split(",")[0] == "a.test" and _route(_OUTSIDE) == "proxy"


_PROXY_PROBE = r'''
import asyncio, json, os, sys, urllib.request
import httpx
made, sent = [], []
def _spy(cls):
    init = cls.__init__
    def spied(self, *a, **kw):
        made.append(self)
        init(self, *a, **kw)
    cls.__init__ = spied
_spy(httpx.AsyncClient); _spy(httpx.Client)
async def _no_send(self, request, **kw):
    sent.append(str(request.url))
    raise httpx.ConnectError("이 탐침은 연결하지 않는다")
httpx.AsyncClient.send = _no_send
import gateway as gw
import rest_proxy
at_import = len(made)
urls = json.loads(sys.argv[1])
def routes(c):
    return {u: "direct" if c._transport_for_url(httpx.URL(u)) is c._transport else "proxy" for u in urls}
async def main():
    out = {}
    async with gw.httpx.AsyncClient(timeout=8) as cli:               # gateway.py 의 호출별 클라이언트 모양
        out["per_call"] = routes(cli)
    n = len(made)
    async with gw.streamablehttp_client(urls[0], headers={}):        # MCP SDK 가 안에서 만드는 클라이언트
        pass
    out["sdk_made"] = len(made) - n
    out["sdk"] = routes(made[n]) if len(made) > n else {}
    out["rest_proxy"] = routes(rest_proxy.RestProxy(gw.REST, gw.PORTAL, lambda *a, **k: None)._client)   # main() 이 만드는 상주 둘
    out["pat_verifier"] = routes(rest_proxy.PortalPatVerifier(gw.PORTAL)._client)
    return out
out = asyncio.run(main())
out.update(at_import=at_import, sent=sent, env=[os.environ.get("NO_PROXY"), os.environ.get("no_proxy")],
           urllib=[bool(urllib.request.proxy_bypass(h)) for h in ("jwks.corp.test:8723", "example.com:443")])   # PyJWKClient 는 urllib 이다
print(json.dumps(out))
'''


def test_기동하면_설정의_내부_목적지가_전부_프록시를_벗어난다(tmp_path):
    """게이트웨이를 **실제로 import** 해(설정은 임시 파일) 그 뒤에 만들어지는 클라이언트 넷을 본다 — gateway.py 의 호출별
    클라이언트 · MCP SDK 가 안에서 만드는 것 · main() 이 만드는 상주 둘(REST 프록시 · PAT 검증기). 고치기 전에는
    루프백까지 전부 프록시로 갔다 — RA 가 IP 허용목록으로 거절해 사람별 위임이 403 이었다(실측 2026-10-03).
    import 시점에 만들어지는 클라이언트가 없다는 것도 본다 — 있으면 환경을 세우기 전의 프록시 설정으로 굳는다."""
    cfg = {
        "_gateway": {"host": "127.0.0.1", "port": 9110, "token": "gw-test-token"},
        "ra": {"url": "http://ra.corp.test:3002/mcp"},
        "odb": {"url": "http://192.0.2.10:8000/mcp?token=QUERY-SECRET"},
        "rest": {"site": {"base": "https://rest.corp.test:8443"}},
        "portal": {"api_base": "http://portal.corp.test:8723",
                   "jwks_url": "http://jwks.corp.test:8723/.well-known/jwks.json",
                   "revoked_url": "http://revoked.corp.test:8723/auth/pat/revoked.json"},
        "heax_registry": {"servers_url": "http://hub.corp.test:4040/api/v1/mcp/servers",
                          "base": "http://caddy.corp.test:4180",
                          "per_user_sso": {"ste": {"sso_url": "http://user:PW-SECRET@198.51.100.7:5012/api/auth/sso",
                                                   "secret": "s"}}},
    }
    (tmp_path / "cfg.json").write_text(json.dumps(cfg), encoding="utf-8")
    inside = ["http://ra.corp.test:3002/mcp", "http://192.0.2.10:8000/mcp", "https://rest.corp.test:8443/api/x",
              "http://portal.corp.test:8723/internal/access/policy", "http://jwks.corp.test:8723/.well-known/jwks.json",
              "http://revoked.corp.test:8723/auth/pat/revoked.json", "http://hub.corp.test:4040/api/v1/mcp/servers",
              "http://caddy.corp.test:4180/app/mcp", "http://198.51.100.7:5012/api/auth/sso", "http://127.0.0.1:9009/mcp"]
    env = {k: v for k, v in os.environ.items() if k not in _PROXY_VARS}
    env.update(HTTP_PROXY="http://proxy.invalid:3128", HTTPS_PROXY="http://proxy.invalid:3128",
               NO_PROXY="keep.test",                               # 대문자에만 있던 값 — 지워지면 안 된다
               GATEWAY_CONFIG=str(tmp_path / "cfg.json"), GATEWAY_AUDIT=str(tmp_path / "audit.jsonl"),
               PYTHONDONTWRITEBYTECODE="1")
    run = subprocess.run([sys.executable, "-c", _PROXY_PROBE, json.dumps(inside + [_OUTSIDE])],
                         cwd=os.path.dirname(os.path.abspath(gw.__file__)), env=env,
                         capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stderr[-2000:]
    out = json.loads(run.stdout)
    assert out["at_import"] == 0 and out["sent"] == [] and out["sdk_made"] == 1
    for kind in ("per_call", "sdk", "rest_proxy", "pat_verifier"):
        assert {u: out[kind][u] for u in inside} == dict.fromkeys(inside, "direct"), kind
        assert out[kind][_OUTSIDE] == "proxy", f"{kind}: 바깥 주소까지 우회시키면 안 된다"
    assert out["urllib"] == [True, False], "JWKS 는 httpx 가 아니라 urllib 로 받는다 — 같은 환경을 따라야 한다"
    assert out["env"][0] == out["env"][1] and out["env"][0].startswith(f"keep.test,{_LOOPBACK},")
    for name in ("ra.corp.test", "192.0.2.10", "rest.corp.test", "portal.corp.test", "hub.corp.test", "198.51.100.7"):
        assert name in run.stderr, f"기동 로그에 더한 호스트가 남아야 한다: {name}"
    for leak in ("SECRET", "token=", "user:"):
        assert leak not in run.stderr and leak not in "".join(out["env"]), f"주소의 비밀이 샜다: {leak}"


# ── 관리자 표지는 PAT 에 박힌 것을 믿지 않는다(HWAXPortal docs/change-request-8-10 #6 · D-3) ─────────────
_OLD_ADMIN_TOKEN = ["mes-user", "portal-admin", "feat:old"]      # 관리자이던 때 발급된 PAT 의 groups


def _admin_gate(monkeypatch, portal_resp):
    """인증 미들웨어를 실제로 태운다(포털 응답만 가짜). 돌려주는 것 — 앱이 받는 헤더 · 그 안의 그룹 · 포털에 물은 로그인 그룹."""
    seen, asked = {}, []

    async def app(scope, receive, send):
        seen["h"] = {k.decode().lower(): v.decode() for k, v in scope["headers"]}

    async def fake_access(email, base, **_kw):
        asked.append(list(base))
        return portal_resp
    monkeypatch.setattr(gw, "_portal_access", fake_access)
    monkeypatch.setattr(gw, "GW_TOKEN", "gw-secret")

    class _V:
        def __init__(self, claims): self.claims = claims
        async def verify(self, token, aud): return self.claims

    def run(token_groups):
        seen.clear(); asked.clear()
        mw = gw._bearer_gate(app, _V({"email": "u@corp.com", "groups": list(token_groups)}))
        asyncio.run(mw({"type": "http", "path": "/mcp", "headers": [(b"authorization", b"Bearer me")]}, None, None))
        return seen["h"], gw._parse_groups(seen["h"][gw.GROUPS_HEADER]), asked[0]
    return run


def test_토큰에_박힌_관리자_표지는_넘기지_않는다(monkeypatch):
    """관리자에서 내려온 사람의 옛 PAT 에는 `portal-admin` 이 박혀 있다(수명 최대 100년 — mock 시절 공용 계정 PAT 가 아직
    쓰인다). 게이트웨이가 PAT 의 그룹을 그대로 싣던 때는 해제가 하위까지 먹지 않았다."""
    _h, groups, asked = _admin_gate(monkeypatch, {"keys": ["feat:chat"], "is_admin": False})(_OLD_ADMIN_TOKEN)
    assert groups == ["mes-user", "feat:chat"]
    assert asked == ["mes-user", "portal-admin"], \
        "포털에는 토큰의 로그인 그룹을 그대로 묻는다 — 누가 관리자인지는 포털이 정한다(옛 포털에서 권한 키가 달라지지 않게)"


def test_포털이_지금_관리자라고_답할_때만_표지를_붙인다(monkeypatch):
    run = _admin_gate(monkeypatch, {"keys": ["feat:chat"], "is_admin": True})
    assert run(_OLD_ADMIN_TOKEN)[1] == ["mes-user", "feat:chat", "portal-admin"]
    assert run(["mes-user"])[1] == ["mes-user", "feat:chat", "portal-admin"], \
        "표지 없이 발급된 토큰이어도 지금 관리자면 붙는다 — 토큰이 아니라 포털의 답이 정본이다"


@pytest.mark.parametrize("resp,want", [
    # 옛 포털 — is_admin 칸이 없다. 붙이지 않는다: 표지를 읽는 하위가 없어 아무도 막히지 않고, 권한 키는 포털이 제 규칙으로
    # 준 그대로다. 칸이 없다고 토큰 값을 넘기면 포털이 보증할 수 없는 바로 그 구성에서 옛 표지가 계속 샌다.
    ({"keys": ["feat:chat"]}, ["mes-user", "feat:chat"]),
    # 포털이 모른다(권한 기능 이전·불통) — 권한 키는 종전대로 PAT 값, 표지는 뺀다
    (None, ["mes-user", "feat:old"]),
    # 불리언 참만 인정한다
    ({"keys": ["feat:chat"], "is_admin": "true"}, ["mes-user", "feat:chat"]),
    ({"keys": ["feat:chat"], "is_admin": 1}, ["mes-user", "feat:chat"]),
    ({"keys": ["feat:chat"], "is_admin": None}, ["mes-user", "feat:chat"]),
])
def test_포털이_관리자라고_답하지_않으면_표지를_넘기지_않는다(monkeypatch, resp, want):
    assert _admin_gate(monkeypatch, resp)(_OLD_ADMIN_TOKEN)[1] == want


@pytest.mark.parametrize("is_admin,want", [(False, ["mes-user", "feat:chat"]),
                                           (True, ["mes-user", "feat:chat", "portal-admin"])])
def test_하위_백엔드가_받는_그룹도_포털의_답을_따른다(monkeypatch, is_admin, want):
    """미들웨어가 만든 헤더를 그대로 요청에 얹어 신원 전달 호출까지 태운다 — 하위(hwax-deliberation)가 **실제로 받는** 그룹."""
    headers, _g, _a = _admin_gate(monkeypatch, {"keys": ["feat:chat"], "is_admin": is_admin})(_OLD_ADMIN_TOKEN)
    res, _b, shots, _row = _recon_kit(monkeypatch, "hwax-deliberation", headers=headers)
    assert not res.isError and len(shots) == 1
    assert gw._parse_groups(shots[0][gw.GROUPS_HEADER]) == want and shots[0][gw.USER_HEADER] == "u@corp.com"


def test_소속_조회는_게이트웨이가_붙인_관리자_표지를_로그인_그룹으로_되묻지_않는다(monkeypatch):
    """표지는 이제 로그인 그룹이 아니라 포털의 답이다. 소속 조회가 그것까지 실어 물으면 인증 때의 권한 조회와 키가 갈려
    관리자 호출마다 포털을 한 번 더 부른다(`_portal_affiliation` — 같은 값을 줘야 캐시가 한 항목이다)."""
    seen = _per_user_kit(monkeypatch, {"keys": ["plat:dynaforge"], "affiliation": "CAEG", "is_admin": True},
                         groups=("mes-user", "plat:dynaforge", "portal-admin"))
    assert seen["lookups"] == [(["mes-user"], False)]


# ── REST 프록시(/api/<site>/…)도 같은 규칙이다 — 두 경로가 그룹을 따로 계산한다(검토 2026-10-07) ─────────────
def _rest_gate(monkeypatch, portal_resp, token_groups, site="sec"):
    """REST 프록시 라우트를 실제로 태운다 — `main()` 과 같은 배선이고 가짜는 서명 검증·폐기 목록·상류 전송·포털 응답뿐이다.
    돌려주는 것 — 응답 · 상류에 닿은 주소 · 포털에 물은 로그인 그룹."""
    from starlette.requests import Request
    from rest_proxy import RestProxy
    shots, asked = [], []

    async def fake_access(email, base, **_kw):
        asked.append(list(base))
        return portal_resp
    monkeypatch.setattr(gw, "_portal_access", fake_access)
    p = RestProxy({site: {"base": "http://upstream.invalid"}}, {"audience_ok": [site]}, gw._audit,
                  allow=gw._rest_allowed, mint=gw._rest_mint, deny_text=gw._rest_deny_text)
    p._verify = lambda token, s: {"sub": "S-1", "email": "u@corp.com", "jti": "j", "groups": list(token_groups)}
    p._revoked_set = _noop_async(set())

    async def fake_send(req, stream=False):
        shots.append(str(req.url))
        return httpx.Response(200, content=b"ok", request=req)
    monkeypatch.setattr(p._client, "send", fake_send)
    resp = asyncio.run(p.handle(Request({
        "type": "http", "method": "GET", "path": f"/api/{site}/x", "headers": [(b"authorization", b"Bearer me")],
        "query_string": b"", "path_params": {"site": site, "path": "x"}, "client": ("203.0.113.5", 0)})))
    return resp, shots, asked


def _admin_only_site(monkeypatch):
    monkeypatch.setattr(gw, "POLICY", {"sec": [gw.ADMIN_GROUP]})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)


@pytest.mark.parametrize("resp", [{"keys": ["feat:chat"], "is_admin": False}, {"keys": ["feat:chat"]}, None,
                                  {"keys": ["feat:chat"], "is_admin": "true"}, {"keys": ["feat:chat"], "is_admin": 1},
                                  {"keys": ["feat:chat"], "is_admin": None}])
def test_REST_프록시는_토큰에_박힌_관리자_표지로_열리지_않는다(monkeypatch, resp):
    """`/api/<site>/` 는 인증 미들웨어의 PAT 분기를 타지 않고 `_rest_groups` 로 따로 계산한다. 거기서는 표지를 떼지 않아,
    관리자에서 내려온 사람의 옛 PAT 가 `/mcp` 에서는 막히는 백엔드를 이 길로는 200 으로 읽었다(사본 재현)."""
    _admin_only_site(monkeypatch)
    got, shots, asked = _rest_gate(monkeypatch, resp, _OLD_ADMIN_TOKEN)
    assert got.status_code == 403 and shots == [], "해제된 관리자의 옛 토큰으로 상류까지 갔다"
    assert "그룹 제한" in json.loads(got.body)["detail"], "403 의 사유도 같은 그룹으로 말해야 한다(_rest_deny_text)"
    assert asked[0] == ["mes-user", "portal-admin"], \
        "포털에는 토큰의 로그인 그룹을 그대로 묻는다 — 떼고 물으면 `/mcp` 와 캐시 키가 갈리고 D-10 #6 을 어긴다"


def test_REST_프록시도_포털이_지금_관리자라고_답하면_연다(monkeypatch):
    """반대쪽 어긋남 — 표지 없이 발급된 토큰의 지금 관리자가 `/mcp` 로는 들어가는데 이 길로는 403 이었다."""
    _admin_only_site(monkeypatch)
    for token in (["mes-user"], _OLD_ADMIN_TOKEN):
        got, shots, _asked = _rest_gate(monkeypatch, {"keys": ["feat:chat"], "is_admin": True}, token)
        assert got.status_code == 200 and shots == ["http://upstream.invalid/x"], token


@pytest.mark.parametrize("token", [_OLD_ADMIN_TOKEN, ["mes-user"]])
@pytest.mark.parametrize("resp", [{"keys": ["feat:chat"], "is_admin": False}, {"keys": ["feat:chat"], "is_admin": True},
                                  {"keys": ["feat:chat"]}, None, {"keys": ["feat:chat"], "is_admin": "true"},
                                  {"keys": ["feat:chat"], "is_admin": 1}, {"keys": ["feat:chat"], "is_admin": None}])
def test_REST_경로의_그룹은_인증_미들웨어가_앱에_넘기는_그룹과_같다(monkeypatch, resp, token):
    """정본은 미들웨어다 — 한쪽만 고치면 같은 토큰이 `/mcp` 에서는 막히고 `/api` 에서는 통한다. 순서는 보지 않는다
    (포털이 모를 때 두 경로가 토큰의 그룹을 늘어놓는 순서가 다르다)."""
    _h, mcp, mcp_asked = _admin_gate(monkeypatch, resp)(token)
    asked = []

    async def fake_access(email, base, **_kw):
        asked.append(list(base))
        return resp
    monkeypatch.setattr(gw, "_portal_access", fake_access)
    assert sorted(asyncio.run(gw._rest_groups(list(token), "u@corp.com"))) == sorted(mcp)
    assert asked == [mcp_asked], "포털에 묻는 그룹도 같아야 캐시가 한 항목이다"


# ── 포털 불통 때 쓰는 직전 값(`_ENT_LAST`)이 거둔 것을 되살리지 않는다(검토 2026-10-07) ─────────────────────
def _stale_kit(monkeypatch):
    """인증 미들웨어·`_portal_access`·`/conn-invalidate` 는 실제 코드다 — 가짜는 포털의 HTTP 응답 하나뿐이다.
    `_admin_gate` 는 `_portal_access` 를 통째로 갈아 끼워, 그 표의 '불통' 줄이 직전 값 분기를 한 번도 타지 않았다.
    돌려주는 것 — 포털 상태(`down`·`answer`) · PAT 호출(앱이 받는 그룹) · 포털이 부르는 무효화."""
    monkeypatch.setattr(gw, "GW_TOKEN", "gw-secret")
    monkeypatch.setattr(gw, "_ENT_CACHE", {})
    monkeypatch.setattr(gw, "_ENT_LAST", {})
    portal = {"down": False, "answer": {"keys": ["feat:chat", "plat:risk"], "is_admin": True}}

    def handler(req):
        if portal["down"]:
            raise httpx.ConnectError("portal down", request=req)
        return httpx.Response(200, json=portal["answer"])
    _mock_http(monkeypatch, handler)
    seen = {}

    async def app(scope, receive, send):
        seen["h"] = {k.decode().lower(): v.decode() for k, v in scope["headers"]}

    class _V:
        async def verify(self, token, aud): return {"email": "u@corp.com", "groups": ["mes-user"]}

    def call():
        seen.clear()
        asyncio.run(gw._bearer_gate(app, _V())({"type": "http", "path": "/mcp",
                                                "headers": [(b"authorization", b"Bearer me")]}, None, None))
        return gw._parse_groups(seen["h"][gw.GROUPS_HEADER])

    def invalidate():
        sent = []

        async def send(m): sent.append(m)
        asyncio.run(gw._bearer_gate(None, None)({"type": "http", "path": "/conn-invalidate", "method": "POST",
                                                 "query_string": b"email=u@corp.com",
                                                 "headers": [(b"authorization", b"Bearer gw-secret")]}, None, send))
        return sent[0]["status"]
    return portal, call, invalidate


def test_포털이_불통이면_권한_키는_직전_값으로_버티고_관리자_표지는_싣지_않는다(monkeypatch):
    """직전 값에는 만료가 없다. 권한 키는 그것으로 버티지만(포털이 죽었다고 도구가 다 사라지면 안 된다) 관리자 표지는
    "포털이 **지금** 관리자라고 답할 때만" 붙는 것이다(D-3) — 직전 값은 그 답이 아니다. 무효화가 없어도 60초 뒤의 불통이면
    해제된 관리자에게 표지가 다시 붙었다(고정 목록 `PORTAL_ADMIN_EMAILS` 에서 뺀 사람은 무효화 호출조차 없다)."""
    portal, call, _invalidate = _stale_kit(monkeypatch)
    assert call() == ["mes-user", "feat:chat", "plat:risk", "portal-admin"]
    gw._ENT_CACHE.clear()                                   # 60초가 지난 것과 같다
    portal["down"] = True
    assert call() == ["mes-user", "feat:chat", "plat:risk"]
    assert asyncio.run(gw._rest_groups(["mes-user"], "u@corp.com")) == ["mes-user", "feat:chat", "plat:risk"], \
        "REST 프록시도 같은 조회를 쓴다"
    portal["down"] = False
    assert call() == ["mes-user", "feat:chat", "plat:risk", "portal-admin"], "포털이 돌아오면 첫 호출에 다시 붙는다"


def test_포털이_거두었다고_알린_뒤의_불통은_거두기_전_권한으로_돌아가지_않는다(monkeypatch):
    """관리자 해제·허가 회수·정지 뒤 포털이 `/conn-invalidate` 를 부른다(HWAXPortal 479d767). 그 사람의 다음 호출이 포털
    재기동과 겹치면 직전 값이 회수 전 답(`plat:risk`·관리자)을 그대로 돌려줘, 정책이 건 백엔드가 불통 내내 열렸다."""
    portal, call, invalidate = _stale_kit(monkeypatch)
    monkeypatch.setattr(gw, "POLICY", {"risk": []})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {"risk": ["plat:risk"]})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    assert gw._backend_allowed("risk", call())
    portal["answer"] = {"keys": ["feat:chat"], "is_admin": False}      # 포털에서 해제하고 허가를 거뒀다
    assert invalidate() == 200
    portal["down"] = True
    during = call()
    assert during == ["mes-user"], "포털이 모른다 — 토큰의 값만 남는다(로그인 그룹만 굽는 지금의 PAT 에는 권한 키가 없다)"
    assert not gw._backend_allowed("risk", during)
    assert call() == during, "실패는 캐시되지 않는다 — 불통이 이어지는 동안 매 호출이 같아야 한다"
    portal["down"] = False
    assert call() == ["mes-user", "feat:chat"]


# ── 시간 한도 — 느린 도구는 한 번으로 끝내고, 죽은 상대는 짧게 재고, 만료는 손잡이를 말한다(2026-10-08 결정표 gateway-01~05) ──
# 실사용 팀의 리스크 심사는 17~22석이 공용 LLM·백엔드를 같이 쓴다. 120초 한도는 이미 걸리고 있었고(dev 감사 15,429건 중 5건이
# 재시도까지 약 240초에 실패), 시간 초과가 세션을 갈아 같은 백엔드의 멀쩡한 호출까지 끊었다.
_LIMITS_PROBE = r'''
import json, sys
import gateway as gw
print(json.dumps({k: getattr(gw, k, None) for k in sys.argv[1:]}))
'''


def _limits(tmp_path, names, **env):
    """게이트웨이를 **실제로 import** 해(설정은 임시 파일) 손잡이가 닿는지 본다 — 상수를 monkeypatch 하는 시험은 env 를 읽는
    줄이 사라져도 통과한다. 돌려주는 것 — {이름: 값} · 기동 로그."""
    (tmp_path / "cfg.json").write_text(json.dumps({"_gateway": {"token": "gw-test-token"}}), encoding="utf-8")
    full = {k: v for k, v in os.environ.items() if not k.startswith("GATEWAY_")}
    full.update(GATEWAY_CONFIG=str(tmp_path / "cfg.json"), GATEWAY_AUDIT=str(tmp_path / "audit.jsonl"),
                PYTHONDONTWRITEBYTECODE="1", **env)
    run = subprocess.run([sys.executable, "-c", _LIMITS_PROBE, *names], cwd=os.path.dirname(os.path.abspath(gw.__file__)),
                         env=full, capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stderr[-2000:]
    return json.loads(run.stdout), run.stderr


_CALL_LIMITS = ["CALL_TIMEOUT_S", "RECONNECT_TIMEOUT_S", "BACKEND_HTTP_TIMEOUT_S", "BACKEND_READ_TIMEOUT_S"]


def test_호출_한도의_기본값은_안쪽이_바깥보다_작다(tmp_path):
    """핸드셰이크·재연결 30 < 호출 600 < 전송 read 660. 게이트웨이는 `.env` 를 읽지 않고 포털 services.yaml 도 env 를 넘기지
    않는다 — **코드 기본값이 곧 운영값**이라 기본값을 건다."""
    got, _ = _limits(tmp_path, _CALL_LIMITS)
    assert got == {"CALL_TIMEOUT_S": 600, "RECONNECT_TIMEOUT_S": 30.0, "BACKEND_HTTP_TIMEOUT_S": 30.0,
                   "BACKEND_READ_TIMEOUT_S": 660.0}


def test_호출_한도를_올리면_전송_한도가_따라_오르고_뒤집힌_설정은_따르지_않는다(tmp_path):
    got, log_ = _limits(tmp_path, _CALL_LIMITS, GATEWAY_CALL_TIMEOUT="900", GATEWAY_RECONNECT_TIMEOUT="12",
                        GATEWAY_BACKEND_HTTP_TIMEOUT="7")
    assert got == {"CALL_TIMEOUT_S": 900, "RECONNECT_TIMEOUT_S": 12.0, "BACKEND_HTTP_TIMEOUT_S": 7.0,
                   "BACKEND_READ_TIMEOUT_S": 960.0}, "전송 read 는 호출 한도 + 60 으로 유도된다"
    assert "GATEWAY_BACKEND_READ_TIMEOUT" not in log_, "유도된 값은 경고 없이 맞아야 한다(호출 한도만 올린 운영자에게 거짓 경고)"
    got, _ = _limits(tmp_path, _CALL_LIMITS, GATEWAY_BACKEND_READ_TIMEOUT="1200")
    assert got["BACKEND_READ_TIMEOUT_S"] == 1200.0
    # 전송 한도가 호출 한도보다 작으면 ping 을 안 보내는 백엔드에서 그것이 먼저 걸려 세션째 무너진다 — 조용히 따르지 않는다
    got, log_ = _limits(tmp_path, _CALL_LIMITS, GATEWAY_BACKEND_READ_TIMEOUT="300")
    assert got["BACKEND_READ_TIMEOUT_S"] == 660.0
    assert "GATEWAY_BACKEND_READ_TIMEOUT" in log_ and "GATEWAY_CALL_TIMEOUT" in log_, "왜 다른 값을 쓰는지 기동 로그가 말해야 한다"


def test_호출_한도_줄의_마지막_숫자가_기본값이다():
    """HWAXPortal 절차 시험(test_procedures_census)은 이 줄의 **마지막 숫자**를 게이트웨이 기본값으로 읽어 30~600 으로 묶고,
    절차 단계 상한 < 이 값 < 워밍업을 단언한다. 줄 끝에 숫자 든 주석을 달거나 600 을 넘기면 저쪽이 조용히 다른 값을 읽는다."""
    import re
    line = re.search(r"^CALL_TIMEOUT_S\s*=.*$", open(gw.__file__, encoding="utf-8").read(), re.M).group(0)
    assert re.findall(r"\d+(?:\.\d+)?", line)[-1] == "600", line


class _SlowSess(_CallSess):
    """부르면 답이 오지 않는 세션 — 도구가 느린 것이고 세션은 멀쩡하다."""
    async def call_tool(self, original, args, read_timeout_seconds=None):
        self.calls.append(original)
        await asyncio.sleep(3600)


_LATE_BACKEND = {"shared": "signalforge", "identity": "hwax-deliberation", "per-user": "ste", "conn": "reportarchive"}


def _late_kit(monkeypatch, path, *, hang="call", call_s=0.05, handshake_s=5.0):
    """답이 오지 않는 백엔드를 실제 `_call_tool` 로 부른다(전송 계층만 막는다).
    path — shared(상주 세션) · identity(신원 전달) · per-user(사람별 위임) · conn(등록 토큰).
    hang — call(도구가 안 끝난다) · handshake(단발 세션의 initialize 가 안 끝난다).
    돌려주는 것 — 결과 글 · 걸린 초 · 센 것(도구 호출 · 단발 세션 · 재연결 · 토큰 발급의 force) · 감사 줄 전부.
    하네스 자체의 상한은 5초다 — 고치기 전의 상주 세션 길은 여기서 끝나지 않았다."""
    import time as _time
    backend = _LATE_BACKEND[path]
    b = _ReconB(["slow_tool"])
    b.session = _SlowSess([])
    n = {"calls": b.session.calls, "shots": 0, "mints": []}

    class _Sess:
        async def initialize(self):
            if hang == "handshake":
                await asyncio.sleep(3600)

        async def call_tool(self, original, arguments, read_timeout_seconds=None):
            n["calls"].append(original)
            await asyncio.sleep(3600)

    def fake_stream(url, headers=None, **_kw):
        n["shots"] += 1
        return _StubCM((None, None, "sid"))

    async def fake_pat(app_id, email, *, force=False):
        n["mints"].append(force)
        return "tok"

    async def fake_access(email, base_groups, **_kw):
        return {"keys": [], "affiliation": ""}

    async def fake_conn(service, email):
        return {"token": "rat_x", "workspace": ""}
    monkeypatch.setattr(gw, "streamablehttp_client", fake_stream)
    monkeypatch.setattr(gw, "ClientSession", lambda read, write: _StubCM(_Sess()))
    monkeypatch.setattr(gw, "CALL_TIMEOUT_S", call_s)
    monkeypatch.setattr(gw, "RECONNECT_TIMEOUT_S", handshake_s)
    gw._RESP_CACHE.clear()
    monkeypatch.setattr(gw, "backends", {backend: b})
    monkeypatch.setattr(gw, "route", {"slow_tool": (backend, "slow_tool")})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setattr(gw, "PER_USER_SSO", {"ste": {"sso_url": "http://x", "secret": "s"}} if path == "per-user" else {})
    monkeypatch.setattr(gw, "IDENTITY_FWD", {"hwax-deliberation"})
    monkeypatch.setattr(gw, "_task_group_holder", {"tg": object()})
    monkeypatch.setattr(gw, "_REAGG", {})
    monkeypatch.setattr(gw, "_request_user", lambda: "u@corp.com")
    monkeypatch.setattr(gw, "_request_groups", lambda: ["mes-user"])
    monkeypatch.setattr(gw, "_user_pat", fake_pat)
    monkeypatch.setattr(gw, "_portal_access", fake_access)
    monkeypatch.setattr(gw, "_portal_connection", fake_conn)
    t0 = _time.monotonic()
    res = asyncio.run(asyncio.wait_for(gw._call_tool("slow_tool", {}), 5))
    n["reconnects"] = b.reconnects
    return res.content[0].text, _time.monotonic() - t0, n, _rows(), res


@pytest.mark.parametrize("path", ["shared", "identity", "per-user", "conn"])
def test_시간_초과는_한_번으로_끝내고_손잡이를_말한다(monkeypatch, path):
    """종전에는 시간 초과에도 세션을 갈고(사람별 길은 토큰을 다시 받고) 도구를 한 번 더 불렀다 — 실효 한도가 두 배였고, 같은
    세션의 멀쩡한 호출이 전부 끊겨 다시 돌았고, 쓰기 도구가 두 번 실행될 수 있었다. 문구는 `unavailable: TimeoutError()` ·
    '자격증명으로 호출하지 못했습니다' · '토큰을 다시 등록하세요' 여서 느린 도구가 죽은 백엔드·틀린 토큰으로 읽혔다."""
    text, took, n, rows, res = _late_kit(monkeypatch, path)
    assert res.isError and took < 2
    assert n["calls"] == ["slow_tool"], f"도구는 한 번만 불린다(쓰기 도구가 두 번 실행되면 안 된다): {n['calls']}"
    assert n["reconnects"] == 0, "시간 초과는 세션이 죽었다는 뜻이 아니다 — 갈면 같은 세션의 다른 호출이 끊긴다"
    assert n["mints"] == ([False] if path == "per-user" else []), "재발급하면 같은 사람의 다른 좌석이 쥔 토큰이 폐기된다"
    assert f"backend {_LATE_BACKEND[path]}: slow_tool 이 0.05초 안에 답하지 않았다(GATEWAY_CALL_TIMEOUT)" in text, text
    assert "다시 보내지 말고" in text
    for wrong in ("unavailable", "TimeoutError", "자격증명으로 호출하지 못했습니다", "다시 등록"):
        assert wrong not in text, f"느린 도구를 다른 고장으로 읽게 한다: {wrong}"
    assert len(rows) == 1, "호출 한 건에 감사 한 줄"
    assert rows[0]["ok"] is False and "GATEWAY_CALL_TIMEOUT" in rows[0]["error"] and rows[0]["caller"] == "u@corp.com"


@pytest.mark.parametrize("path", ["identity", "per-user", "conn"])
def test_단발_세션을_못_여는_백엔드는_호출_한도가_아니라_핸드셰이크_한도에_드러난다(monkeypatch, path):
    """바깥 기한과 안쪽 호출 한도가 같은 값이었다 — 핸드셰이크를 못 끝내는 백엔드도 호출 한도를 다 채운 뒤에야(그리고 한 번 더)
    이름 없는 `TimeoutError()` 로 끝났다. 한도를 600 으로 올리면 그것이 10분씩이다."""
    text, took, n, rows, res = _late_kit(monkeypatch, path, hang="handshake", call_s=3.0, handshake_s=0.05)
    assert res.isError and took < 1, f"호출 한도(3초)를 기다렸다: {took:.2f}s"
    assert "0.05초 안에 세션을 열지 못했다(GATEWAY_RECONNECT_TIMEOUT)" in text, text
    assert text.startswith(f"backend {_LATE_BACKEND[path]} unavailable:"), "죽은 상대는 포털 판정기가 '불통' 으로 읽어야 한다"
    assert n["calls"] == [] and n["shots"] == 1 and n["reconnects"] == 0
    assert len(rows) == 1 and "GATEWAY_RECONNECT_TIMEOUT" in rows[0]["error"]


def test_만료_문구를_포털_절차_판정기가_제_갈래로_읽는다():
    """HWAXPortal 절차 판정기는 게이트웨이 평문의 **머리**로 갈래를 가른다(`backend … unavailable:` = 불통, 다시 해 볼 만하다).
    죽은 상대는 그 갈래에 남아야 하고, 느린 도구는 들어가면 안 된다 — 도구가 아직 돌고 있을 수 있어 다시 보내면 쓰기가 두 번
    실행된다. 문구를 고치면 저쪽 시험은 초록인 채(그 머리가 소스 어딘가에만 있으면 통과한다) 갈래만 조용히 바뀐다."""
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(gw.__file__))),
                        "HWAXPortal", "backend", "app", "procedures", "judge.py")
    if not os.path.exists(path):
        pytest.skip("HWAXPortal 리포가 옆에 없다")
    spec = importlib.util.spec_from_file_location("_portal_judge", path)
    judge = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = judge              # dataclass 가 제 모듈을 sys.modules 에서 찾는다
    keep, sys.dont_write_bytecode = sys.dont_write_bytecode, True      # 남의 리포에 .pyc 를 남기지 않는다
    try:
        spec.loader.exec_module(judge)
    finally:
        sys.dont_write_bytecode = keep
        sys.modules.pop(spec.name, None)

    def read(what):
        v = judge.judge(is_error=True, text=gw._late_text(gw._Late(what), "ste", "submit_job"))
        return v.kind, v.retriable
    assert read("handshake") == ("unavailable", True)
    assert read("reconnect") == ("unavailable", True)
    assert read("call") == ("tool_error", False), "느린 도구를 '다시 해 볼 만하다' 로 읽히게 하면 안 된다"


def test_답을_받은_뒤_세션_닫기가_매달려도_답을_돌려준다(monkeypatch):
    """도구는 이미 실행됐다 — 닫다가 바깥 기한이 걸렸다고 실패로 돌려주면 호출자가 쓰기를 다시 보낸다."""
    class _Sess:
        async def initialize(self): return None

        async def call_tool(self, original, arguments, read_timeout_seconds=None):
            return types.CallToolResult(content=[types.TextContent(type="text", text="saved")])

    class _HangOnClose(_StubCM):
        async def __aexit__(self, *a):
            await asyncio.sleep(3600)
    monkeypatch.setattr(gw, "streamablehttp_client", lambda url, headers=None, **kw: _HangOnClose((None, None, "sid")))
    monkeypatch.setattr(gw, "ClientSession", lambda read, write: _StubCM(_Sess()))
    monkeypatch.setattr(gw, "RECONNECT_TIMEOUT_S", 0.05)
    res = asyncio.run(asyncio.wait_for(gw._oneshot(_CallB([]), {}, "save_report", {}, 0.05), 5))
    assert res.content[0].text == "saved"


def test_핸드셰이크에_쓴_시간이_호출_한도를_깎지_않는다(monkeypatch):
    """바깥 기한이 핸드셰이크 **전에** 출발해 호출 한도와 같은 값이던 때는, 세션을 여는 데 쓴 시간만큼 도구가 일찍 잘렸다.
    핸드셰이크 0.6초(한도 1초) + 도구 1.6초(한도 2초) = 2.2초 — 둘 다 제 한도 안이므로 답이 와야 한다."""
    class _Sess:
        async def initialize(self):
            await asyncio.sleep(0.6)

        async def call_tool(self, original, arguments, read_timeout_seconds=None):
            await asyncio.sleep(1.6)
            return types.CallToolResult(content=[types.TextContent(type="text", text="done")])
    monkeypatch.setattr(gw, "streamablehttp_client", lambda url, headers=None, **kw: _StubCM((None, None, "sid")))
    monkeypatch.setattr(gw, "ClientSession", lambda read, write: _StubCM(_Sess()))
    monkeypatch.setattr(gw, "RECONNECT_TIMEOUT_S", 1.0)
    res = asyncio.run(asyncio.wait_for(gw._oneshot(_CallB([]), {}, "report_summary", {}, 2.0), 10))
    assert res.content[0].text == "done"


def test_전송_한도는_상주_세션과_단발_세션에_모두_넘긴다(monkeypatch):
    """MCP SDK 의 숨은 read 300초가 호출 한도(600) 아래에 깔려 있으면, ping 을 안 보내는 백엔드에서는 그것이 실제 상한이고
    걸리면 세션째 무너진다. 세션을 여는 자리 둘 다 넘겨야 한다."""
    seen = []

    class _Sess:
        async def initialize(self): return None

        async def call_tool(self, original, arguments, read_timeout_seconds=None):
            return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])

    def fake_stream(url, headers=None, **kw):
        seen.append(kw)
        return _StubCM((None, None, "sid"))
    monkeypatch.setattr(gw, "streamablehttp_client", fake_stream)
    monkeypatch.setattr(gw, "ClientSession", lambda read, write: _StubCM(_Sess()))

    async def go():
        b = gw._Backend("k", "http://stub/mcp", {})
        b._stop.set()                                   # 세션을 열자마자 내려온다
        await b.run()
        await gw._oneshot(b, {}, "t", {}, gw.CALL_TIMEOUT_S)
    asyncio.run(asyncio.wait_for(go(), 5))
    want = {"timeout": gw.BACKEND_HTTP_TIMEOUT_S, "sse_read_timeout": gw.BACKEND_READ_TIMEOUT_S}
    assert seen == [want, want]
    assert gw.BACKEND_READ_TIMEOUT_S > gw.CALL_TIMEOUT_S > gw.RECONNECT_TIMEOUT_S


class _NeverBackB(_ReconB):
    """재연결을 걸어도 돌아오지 않는 백엔드 — 준비 이벤트를 새로 갈아 끼우고 아무도 세우지 않는다."""
    async def reconnect(self, tg, seen_gen=None):
        self.reconnects += 1
        self.session, self._ready = None, asyncio.Event()


def test_실패한_호출이_백엔드가_돌아오기를_끝없이_기다리지_않는다(monkeypatch):
    """한도가 없던 자리다. 멈춘 백엔드를 만난 호출은 백엔드가 복구된 뒤에도 돌아오지 않았고 감사 줄도 남지 않았다
    (사본 재현: 40초 뒤 복구, 42초에 다른 세션이 섰는데 그 호출은 75초째 대기)."""
    b = _NeverBackB(["deliberate_status"], "dead")
    gw._RESP_CACHE.clear()
    monkeypatch.setattr(gw, "backends", {"signalforge": b})
    monkeypatch.setattr(gw, "route", {"deliberate_status": ("signalforge", "deliberate_status")})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setattr(gw, "PER_USER_SSO", {})
    monkeypatch.setattr(gw, "_task_group_holder", {"tg": object()})
    monkeypatch.setattr(gw, "_request_user", lambda: "u@corp.com")
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    monkeypatch.setattr(gw, "RECONNECT_TIMEOUT_S", 0.05)
    res = asyncio.run(asyncio.wait_for(gw._call_tool("deliberate_status", {}), 5))
    assert res.isError and b.reconnects == 1
    assert res.content[0].text == "backend signalforge unavailable: 0.05초 안에 돌아오지 않았다(GATEWAY_RECONNECT_TIMEOUT)"
    row = _rows()[-1]
    assert row["ok"] is False and "GATEWAY_RECONNECT_TIMEOUT" in row["error"], "끝난 호출은 감사에 남아야 한다"


def test_취소된_시작도_준비_이벤트를_세운다(monkeypatch):
    """재활 패스의 기한이 핸드셰이크 중인 시작을 취소하면 예외가 아니라 취소라 준비 이벤트가 영영 안 섰다 — 그 이벤트를
    기다리던 호출이 위 시험의 끝없는 대기였다. 기한은 마지막 그물이고, 이쪽이 원인이다."""
    class _Hang:
        async def __aenter__(self):
            await asyncio.sleep(3600)

        async def __aexit__(self, *a): return False
    monkeypatch.setattr(gw, "streamablehttp_client", lambda url, headers=None, **kw: _Hang())

    async def go():
        import anyio
        b = gw._Backend("stuck", "http://stub/mcp", {})
        ready = b._ready
        async with anyio.create_task_group() as tg:
            with anyio.move_on_after(0.05):
                await tg.start(b.run)
        return ready.is_set(), b.session
    assert asyncio.run(asyncio.wait_for(go(), 5)) == (True, None)


# ── 생사 탐침 — 한 번 놓쳤다고 세션을 갈지 않고, 갈 때는 그 세션에 걸린 호출을 풀어 준다(결정표 gateway-06) ──────────
# 탐침(list_tools 10초)을 한 번 놓치면 세션을 갈았다. 이벤트 루프가 잠깐 바쁜 건강한 백엔드(동기 도구·동기 임베딩)가 그렇게
# 갈렸고(dev 로그에 liveness 실패 62건), 갈린 세션에 걸려 있던 호출은 통보 없이 호출 한도까지 기다린 뒤 실패했다 — 사본 실측:
# 백엔드가 5초 만에 끝낸 호출 둘이 한도 30초를 다 채웠다. 한도가 600초가 되면 그 대기가 10분이다.
class _ProbeSess(_CallSess):
    """탐침(list_tools)과 도구 호출의 동작을 따로 정하는 상주 세션. `probes` — 탐침마다의 답: "hang"(답 없음) · "ok" ·
    예외 객체(그 예외를 던진다). 다 쓰면 마지막 것을 되풀이한다. `call_s` — 도구가 답하기까지의 초."""
    def __init__(self, probes, call_s=3600.0):
        super().__init__([_tool("slow_tool")])
        self.probes, self.call_s, self.probed = list(probes), call_s, 0

    async def list_tools(self):
        how = self.probes[min(self.probed, len(self.probes) - 1)]
        self.probed += 1
        if how == "hang":
            await asyncio.sleep(3600)
        if isinstance(how, Exception):
            raise how
        return _Res(self._t)

    async def call_tool(self, original, args, read_timeout_seconds=None):
        self.calls.append(original)
        await asyncio.sleep(self.call_s)
        return types.CallToolResult(content=[types.TextContent(type="text", text="answered")])


def _probe_kit(monkeypatch, sess, *, strikes=2, backend="signalforge"):
    """재활 패스(`_revive_once`)와 `_call_tool` 을 같은 백엔드 위에서 실제로 돌릴 판 — 백엔드 핸들을 돌려준다."""
    b = _ReconB(["slow_tool"])
    b.session = sess
    gw._RESP_CACHE.clear()
    monkeypatch.setattr(gw, "HEAX", {})                       # 레지스트리 폴링 없음 — 탐침·재연결·재집계만 돈다
    monkeypatch.setattr(gw, "backends", {backend: b})
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "route", {"slow_tool": (backend, "slow_tool")})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setattr(gw, "PER_USER_SSO", {})
    monkeypatch.setattr(gw, "IDENTITY_FWD", {"hwax-deliberation"})
    monkeypatch.setattr(gw, "_task_group_holder", {"tg": object()})
    monkeypatch.setattr(gw, "_REAGG", {})
    monkeypatch.setattr(gw, "_FP", {})
    monkeypatch.setattr(gw, "_LAST_TOOLS", {})
    monkeypatch.setattr(gw, "_LIVENESS_MISS", {})
    monkeypatch.setattr(gw, "_INFLIGHT", {})
    monkeypatch.setattr(gw, "LIVENESS_TIMEOUT_S", 0.05)
    monkeypatch.setattr(gw, "LIVENESS_STRIKES", strikes)
    monkeypatch.setattr(gw, "CALL_TIMEOUT_S", 30)
    monkeypatch.setattr(gw, "_request_user", lambda: "u@corp.com")
    monkeypatch.setattr(gw, "_request_groups", lambda: ["mes-user"])
    return b


def test_탐침을_한_번_놓친_백엔드의_세션은_갈지_않고_진행_중_호출이_답을_받는다(monkeypatch):
    sess = _ProbeSess(["hang", "ok", "hang"], call_s=0.3)
    b = _probe_kit(monkeypatch, sess)

    async def go():
        call = asyncio.create_task(gw._call_tool("slow_tool", {}))
        await asyncio.sleep(0)                                # 호출이 세션에 걸리게 한다
        await gw._revive_once(object())                       # 탐침 1회 무응답
        after_first = (b.session is sess, b.reconnects, gw._LIVENESS_MISS.get("signalforge"))
        res = await asyncio.wait_for(call, 5)
        await gw._revive_once(object())                       # 답했다 — 센 것을 지운다
        cleared = gw._LIVENESS_MISS.get("signalforge")
        await gw._revive_once(object())                       # 다시 한 번 놓쳐도 '연속' 이 아니다
        return after_first, res, cleared
    after_first, res, cleared = asyncio.run(go())
    assert after_first == (True, 0, 1), "한 번 놓쳤다고 세션을 갈았다 — 건강한 백엔드의 진행 중 답이 버려진다"
    assert not res.isError and res.content[0].text == "answered"
    assert cleared is None and b.session is sess and b.reconnects == 0, "놓친 횟수는 연속일 때만 쌓인다"


def test_재집계에서_목록을_받았으면_놓친_횟수가_끊긴다(monkeypatch):
    """재집계도 같은 세션에 list_tools 를 보낸다 — 그 사이에 답을 받았으면 앞뒤의 무응답은 '연속' 이 아니다."""
    sess = _ProbeSess(["hang", "ok", "hang"])
    b = _probe_kit(monkeypatch, sess)

    async def go():
        await gw._revive_once(object())                       # 무응답 1회
        await gw._aggregate()                                 # 다른 앱이 바뀌어 재집계가 돌았고, 이 백엔드는 답했다
        await gw._revive_once(object())                       # 무응답 — 다시 1회째다
    asyncio.run(asyncio.wait_for(go(), 5))
    assert b.session is sess and b.reconnects == 0 and gw._LIVENESS_MISS == {"signalforge": 1}


def test_탐침을_연속으로_놓치면_세션을_갈고_그_세션의_진행_중_호출을_곧바로_풀어_준다(monkeypatch):
    """갈린 세션의 답은 어차피 버려진다. 알리지 않으면 호출자는 호출 한도(여기서는 30초, 운영 600초)까지 기다렸다."""
    import time as _time
    sess = _ProbeSess(["hang"])
    b = _probe_kit(monkeypatch, sess)

    async def go():
        call = asyncio.create_task(gw._call_tool("slow_tool", {}))
        await asyncio.sleep(0)
        await gw._revive_once(object())
        assert not call.done() and b.session is sess, "첫 번째에는 아직 둔다"
        t0 = _time.monotonic()
        await gw._revive_once(object())                       # 연속 2회째 — 세션을 갈고 호출을 풀어 준다
        return await asyncio.wait_for(call, 2), _time.monotonic() - t0
    res, took = asyncio.run(go())
    assert res.isError and took < 2, "호출 한도까지 기다렸다"
    assert res.content[0].text == ("backend signalforge 가 탐침에 2회 연속 답하지 않아 세션을 갈았다"
                                   "(GATEWAY_LIVENESS_TIMEOUT × GATEWAY_LIVENESS_STRIKES) — slow_tool 의 실행 여부는 모른다")
    assert sess.calls == ["slow_tool"] and b.session.calls == [], "실행 여부를 모르는 호출을 새 세션에 다시 보내면 안 된다"
    assert b.reconnects == 1 and b.session is not sess, "죽은 세션은 같은 패스의 재연결 루프가 갈아 끼운다"
    assert gw._INFLIGHT.get("signalforge") == {}, "풀어 준 호출이 장부에 남으면 안 된다"
    row = _rows()[-1]
    assert row["ok"] is False and "GATEWAY_LIVENESS_STRIKES" in row["error"]


def test_탐침이_예외로_실패하면_종전대로_한_번에_간다(monkeypatch):
    """세션 종료·연결 거부는 답이 늦은 것이 아니다. 미루면 앱 재배포 직후의 `POST /refresh` 한 번으로 새 도구가 올라오지 않는다
    (update-all 이 그 한 번으로 카탈로그를 검증한다)."""
    sess = _ProbeSess([RuntimeError("Session terminated")])
    b = _probe_kit(monkeypatch, sess)

    async def go():
        call = asyncio.create_task(gw._call_tool("slow_tool", {}))
        await asyncio.sleep(0)
        changed = await gw._revive_once(object())
        return changed, await asyncio.wait_for(call, 2)
    changed, res = asyncio.run(go())
    assert changed is True and b.reconnects == 1 and b.session is not sess
    assert res.isError and "탐침에 실패해 세션을 갈았다" in res.content[0].text and "실행 여부는 모른다" in res.content[0].text


def test_상주_세션이_갈려도_단발_세션의_호출은_답을_받는다(monkeypatch):
    """신원 전달·사람별 호출은 제 연결을 따로 쥔다 — 상주 세션의 탐침 결과로 끊으면 건강한 호출을 죽인다."""
    b = _probe_kit(monkeypatch, _ProbeSess(["hang"]), backend="hwax-deliberation")
    monkeypatch.setattr(gw, "route", {"slow_tool": ("hwax-deliberation", "slow_tool")})

    class _Sess:
        async def initialize(self): return None

        async def call_tool(self, original, arguments, read_timeout_seconds=None):
            await asyncio.sleep(0.4)
            return types.CallToolResult(content=[types.TextContent(type="text", text="identity-ok")])
    monkeypatch.setattr(gw, "streamablehttp_client", lambda url, headers=None, **kw: _StubCM((None, None, "sid")))
    monkeypatch.setattr(gw, "ClientSession", lambda read, write: _StubCM(_Sess()))

    async def go():
        call = asyncio.create_task(gw._call_tool("slow_tool", {}))
        await asyncio.sleep(0)
        await gw._revive_once(object())
        await gw._revive_once(object())
        return await asyncio.wait_for(call, 5)
    res = asyncio.run(go())
    assert b.reconnects == 1, "상주 세션은 갈렸다"
    assert not res.isError and res.content[0].text == "identity-ok"


def test_재집계의_목록_조회가_예외로_실패하면_종전대로_한_번에_죽은_것으로_표시한다(monkeypatch):
    class _Broken:
        async def list_tools(self):
            raise RuntimeError("Session terminated")
    b = _B([])
    b.session = _Broken()
    monkeypatch.setattr(gw, "backends", {"gone": b})
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "route", {})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "_LIVENESS_MISS", {})
    monkeypatch.setattr(gw, "_REAGG", {})
    asyncio.run(asyncio.wait_for(gw._aggregate(), 5))
    assert b.session is None and "pending" not in gw._REAGG


def test_탐침_횟수_손잡이(tmp_path):
    assert _limits(tmp_path, ["LIVENESS_STRIKES", "LIVENESS_TIMEOUT_S"])[0] == {"LIVENESS_STRIKES": 2, "LIVENESS_TIMEOUT_S": 10.0}
    assert _limits(tmp_path, ["LIVENESS_STRIKES"], GATEWAY_LIVENESS_STRIKES="3")[0] == {"LIVENESS_STRIKES": 3}
    assert _limits(tmp_path, ["LIVENESS_STRIKES"], GATEWAY_LIVENESS_STRIKES="0")[0] == {"LIVENESS_STRIKES": 1}, \
        "0 이하는 1 로 읽는다(한 번 놓치면 간다 — 종전 동작)"


# ── 첫 핸드셰이크 — 매달린 백엔드 하나가 부팅과 재활 패스를 세우지 않는다(결정표 gateway-26) ─────────────────────
class _HangCM:
    """연결은 받는데 한 글자도 답하지 않는 백엔드 — 세션을 여는 데서 매달린다."""
    async def __aenter__(self):
        await asyncio.sleep(3600)

    async def __aexit__(self, *a): return False


def _boot_kit(monkeypatch, hung: set):
    """실제 `_Backend`·`_backends_lifespan`·`_revive_once` 를 돌릴 판 — 전송 계층만 막는다. `hung` 에 든 주소는 핸드셰이크가
    매달린다(시험 중에 비우면 그때부터 붙는다). 포털 권한 정책·주기 루프는 이 시험의 관심사가 아니라 끈다."""
    class _Sess:
        async def initialize(self): return None

        async def list_tools(self): return _Res([_tool("ok_tool")])

    def fake_stream(url, headers=None, **_kw):
        return _HangCM() if url in hung else _StubCM((None, None, "sid"))

    async def _noop(*a, **k):
        return None
    monkeypatch.setattr(gw, "streamablehttp_client", fake_stream)
    monkeypatch.setattr(gw, "ClientSession", lambda read, write: _StubCM(_Sess()))
    monkeypatch.setattr(gw, "LIVENESS_TIMEOUT_S", 0.05)
    for name in ("backends", "route", "alias_route", "_task_group_holder", "_REAGG", "_FP", "_LAST_TOOLS",
                 "_LIVENESS_MISS", "_HEAX_MISS", "DISCOVERED_META", "POLICY"):
        monkeypatch.setattr(gw, name, {})
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "_load_access_cache", lambda: None)
    monkeypatch.setattr(gw, "_refresh_access_policy", _noop)
    monkeypatch.setattr(gw, "_access_policy_loop", _noop)
    monkeypatch.setattr(gw, "_revive_loop", _noop)


@pytest.mark.parametrize("where", ["설정에 적은 백엔드", "레지스트리로 찾은 앱"])
def test_부팅은_첫_핸드셰이크가_매달린_백엔드를_놓고_간다(monkeypatch, caplog, where):
    """기한이 없어서 매달린 백엔드 하나가 MCP 클라이언트의 read 한도(종전 300초)가 찰 때까지 부팅을 세웠다 — start.sh 의
    헬스 대기 60초를 넘겨 '기동 실패' 로 보이고 로그에는 아무것도 없다."""
    import time as _time
    _boot_kit(monkeypatch, {"http://hung/mcp"})
    static = where == "설정에 적은 백엔드"
    hung_key = "hung" if static else "heax-hung"
    monkeypatch.setattr(gw, "BACKENDS", {**({"hung": {"url": "http://hung/mcp"}} if static else {}),
                                         "ok": {"url": "http://ok/mcp"}})
    monkeypatch.setattr(gw, "HEAX", {} if static else {"servers_url": "http://hub/servers"})

    async def found():
        return {} if static else {"heax-hung": {"url": "http://hung/mcp", "headers": {}, "allowed_groups": [],
                                                "label": "", "description": ""}}
    monkeypatch.setattr(gw, "_discover_heax", found)

    async def go():
        t0 = _time.monotonic()
        async with gw._backends_lifespan():
            return _time.monotonic() - t0, {k: b.session is not None for k, b in gw.backends.items()}, sorted(gw.route)
    with caplog.at_level(logging.WARNING, logger="hwax-mcp-gateway"):
        took, up, tools = asyncio.run(asyncio.wait_for(go(), 5))
    assert took < 2 and up == {hung_key: False, "ok": True} and tools == ["ok_tool"], "멀쩡한 백엔드까지 못 붙었다"
    said = [r.getMessage() for r in caplog.records if "첫 연결" in r.getMessage()]
    assert len(said) == 1 and hung_key in said[0] and "GATEWAY_LIVENESS_TIMEOUT" in said[0], caplog.text


def test_재활_패스에서_합류하는_앱이_매달려도_패스가_서지_않고_다음_패스에_붙는다(monkeypatch):
    """패스가 서면 그동안 다른 백엔드의 탐침·재연결·카탈로그 갱신이 전부 멈춘다."""
    import anyio
    hung = {"http://hub/new/mcp"}
    _boot_kit(monkeypatch, hung)
    monkeypatch.setattr(gw, "HEAX", {"servers_url": "http://hub/servers"})

    async def found():
        return {"heax-new": {"url": "http://hub/new/mcp", "headers": {}, "allowed_groups": [], "label": "", "description": ""}}
    monkeypatch.setattr(gw, "_discover_heax", found)

    async def go():
        async with anyio.create_task_group() as tg:
            first = await gw._revive_once(tg)               # 합류를 시도하다 놓고 간다(같은 패스의 재연결도 기한 안에 놓는다)
            b = gw.backends["heax-new"]
            mid = (b.session is None, sorted(gw.route))
            hung.clear()                                    # 백엔드가 답하기 시작했다
            second = await gw._revive_once(tg)
            out = first, mid, second, b.session is not None, sorted(gw.route)
            b._stop.set()
            tg.cancel_scope.cancel()
        return out
    first, mid, second, up, tools = asyncio.run(asyncio.wait_for(go(), 5))
    assert first is False and mid == (True, [])
    assert second is True and up and tools == ["ok_tool"], "놓고 간 백엔드를 다음 패스가 다시 붙여야 한다"


# ── 닿지 않는 백엔드의 도구를 카탈로그에서 빼기까지(결정표 gateway-08) ───────────────────────────────────
# 3패스(약 3분)였다. 수 시간짜리 심의 도중에 앱 재배포가 그보다 길면 좌석이 `unknown tool` 을 받는다 — '도구가 없다' 로 읽힌다.
# 항목이 남아 있는 동안은 `backend <키> unavailable: … backend session down` 이라는 맞는 말이 나온다.
def test_카탈로그_보존_횟수의_기본값과_손잡이(tmp_path):
    names = ["AGG_STALE_ROUNDS", "HEAX_MISS_BEFORE_DROP"]
    assert _limits(tmp_path, names)[0] == {"AGG_STALE_ROUNDS": 10, "HEAX_MISS_BEFORE_DROP": 10}
    assert _limits(tmp_path, names, GATEWAY_AGG_STALE_ROUNDS="4", GATEWAY_HEAX_MISS_DROP="6")[0] == {
        "AGG_STALE_ROUNDS": 4, "HEAX_MISS_BEFORE_DROP": 6}


def test_세션이_없는_백엔드의_도구는_재집계_열_번_동안_남는다(monkeypatch):
    down = _B([])
    down.session = None
    monkeypatch.setattr(gw, "backends", {"heax-step_forge": down})
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "route", {})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "_LAST_TOOLS", {"heax-step_forge": ([_tool("list_parts")], 0)})

    async def go():
        seen = []
        for _ in range(gw.AGG_STALE_ROUNDS + 1):
            await gw._aggregate()
            seen.append("list_parts" in gw.route)
        return seen
    seen = asyncio.run(asyncio.wait_for(go(), 5))
    assert len(seen) == 11 and seen == [True] * 10 + [False], "기본값(10)대로 — 영영 낡은 목록을 내걸지는 않는다"


def test_레지스트리에서_빠진_앱은_열_패스째에_뗀다(monkeypatch):
    from types import SimpleNamespace as NS
    b, stopped = _ReconB(["list_parts"]), []
    b._stop = NS(set=lambda: stopped.append(1))
    monkeypatch.setattr(gw, "HEAX", {"servers_url": "http://hub/servers"})
    monkeypatch.setattr(gw, "backends", {"heax-step_forge": b})
    for name in ("route", "alias_route", "_REAGG", "_FP", "_LAST_TOOLS", "_LIVENESS_MISS", "_HEAX_MISS", "DISCOVERED_META",
                 "POLICY"):
        monkeypatch.setattr(gw, name, {})
    monkeypatch.setattr(gw, "exposed_tools", [])

    async def nothing():
        return {}                                           # 레지스트리는 답했는데(200) 그 앱이 목록에 없다
    monkeypatch.setattr(gw, "_discover_heax", nothing)

    async def go():
        seen = []
        for _ in range(gw.HEAX_MISS_BEFORE_DROP):
            await gw._revive_once(object())
            seen.append("heax-step_forge" in gw.backends)
        return seen
    seen = asyncio.run(asyncio.wait_for(go(), 5))
    assert len(seen) == 10 and seen == [True] * 9 + [False] and stopped == [1]


# ── save_conversation — 수 시간의 전사를 남기는 한 번의 쓰기(결정표 gateway-15) ──────────────────────────────
def _save_kit(monkeypatch, post):
    """`_save_conversation` 을 실제로 태우고 포털 POST 만 `post` 로 바꾼다 → (결과, 클라이언트를 만든 timeout)."""
    from types import SimpleNamespace as NS
    made = {}

    class _Cli:
        def __init__(self, *a, **k): made["timeout"] = k.get("timeout")
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None, headers=None): return await post()
    monkeypatch.setattr(gw, "_portal_api_base", lambda: "http://portal")
    monkeypatch.setattr(gw.httpx, "AsyncClient", _Cli)
    monkeypatch.setattr(gw, "_low", NS(request_context=NS(request=NS(headers={"authorization": "Bearer t"}, client=None))))
    res = asyncio.run(gw._save_conversation({"title": "심의", "messages": [{"role": "user", "content": "q"}]}))
    return res, made["timeout"]


def test_대화_저장은_포털의_확인을_넉넉히_기다리고_죽은_포털은_짧게_잰다(monkeypatch):
    async def ok():
        return httpx.Response(200, json={"id": "c-1"})
    res, timeout = _save_kit(monkeypatch, ok)
    assert not res.isError and json.loads(res.content[0].text) == {"ok": True, "conversation_id": "c-1"}
    assert isinstance(timeout, httpx.Timeout), "종전에는 connect·read·write·pool 이 전부 15초였다"
    assert (timeout.read, timeout.connect) == (gw.PORTAL_SAVE_TIMEOUT_S, 8.0)


def test_대화_저장이_한도를_넘기면_손잡이와_다시_보내기_전에_할_일을_말한다(monkeypatch):
    """종전 문구는 `CONV_UNAVAILABLE: ReadTimeout('')` 였다 — 얼마를 기다렸는지도, 포털이 이미 저장했을 수 있다는 것도 없어
    오케스트레이터는 전사 없이 넘어가거나 같은 대화를 두 벌 만들었다."""
    async def slow():
        raise httpx.ReadTimeout("")
    res, _ = _save_kit(monkeypatch, slow)
    text = res.content[0].text
    assert res.isError and text.startswith("CONV_UNAVAILABLE: ")
    assert f"{gw.PORTAL_SAVE_TIMEOUT_S:g}초 안에 저장을 확인하지 않았다(GATEWAY_PORTAL_SAVE_TIMEOUT)" in text
    assert "대화 목록을 확인" in text
    row = _rows()[-1]
    assert row["ok"] is False and "GATEWAY_PORTAL_SAVE_TIMEOUT" in row["error"]


def test_대화_저장_한도의_기본값과_손잡이(tmp_path):
    assert _limits(tmp_path, ["PORTAL_SAVE_TIMEOUT_S"])[0] == {"PORTAL_SAVE_TIMEOUT_S": 120.0}
    assert _limits(tmp_path, ["PORTAL_SAVE_TIMEOUT_S"], GATEWAY_PORTAL_SAVE_TIMEOUT="300")[0] == {"PORTAL_SAVE_TIMEOUT_S": 300.0}


# ── rest_call — 전용 도구가 없을 때의 다리도 도구 호출과 같은 한도를 받는다(결정표 gateway-21) ───────────────────
class _SlowUp(_Up):
    """헤더조차 오지 않는 상류 — 사이트가 느리다."""
    async def __aenter__(self):
        await asyncio.sleep(3600)


class _TimedCli(_Cli):
    made = {}
    fail = None

    def __init__(self, *a, **k): _TimedCli.made = k

    def stream(self, method, url, **kw):
        if _TimedCli.fail == "hang":
            return _SlowUp(200, b"")
        if _TimedCli.fail is not None:
            raise _TimedCli.fail
        return _Up(200, b'{"ok": true}')


@pytest.mark.anyio
async def test_rest_call_은_도구_호출과_같은_한도를_받고_연결은_짧게_잰다(_rest, monkeypatch):
    monkeypatch.setattr(gw.httpx, "AsyncClient", _TimedCli)
    _TimedCli.fail = None
    out = _payload(await gw._rest_call({"site": "locked", "path": "/health"}))
    assert out["status"] == 200
    t = _TimedCli.made["timeout"]
    assert isinstance(t, httpx.Timeout) and (t.read, t.connect) == (gw.REST_CALL_TIMEOUT_S, 10.0), \
        "종전에는 connect·read·write·pool 이 전부 30초였다 — MCP 길(GATEWAY_CALL_TIMEOUT)보다 엄했다"


@pytest.mark.anyio
@pytest.mark.parametrize("how", ["hang", httpx.ReadTimeout("")], ids=["전체 기한", "read 침묵"])
async def test_rest_call_이_한도를_넘기면_느리다고_말하고_손잡이를_말한다(_rest, monkeypatch, how):
    """종전 문구는 `upstream unreachable` 이었다 — 느린 사이트를 안 닿는 사이트로 읽게 한다. 전체 기한도 없었다."""
    monkeypatch.setattr(gw.httpx, "AsyncClient", _TimedCli)
    monkeypatch.setattr(gw, "REST_CALL_TIMEOUT_S", 0.05)
    _TimedCli.fail = how
    out = _payload(await asyncio.wait_for(gw._rest_call({"site": "locked", "path": "/slow"}), 5))
    assert out["error"] == "locked 가 0.05초 안에 답하지 않았다(GATEWAY_REST_CALL_TIMEOUT)" and "unreachable" not in out["error"]
    row = _rows()[-1]
    assert row["ok"] is False and "GATEWAY_REST_CALL_TIMEOUT" in row["error"] and row["tool"] == "rest_call GET /slow"


@pytest.mark.anyio
async def test_rest_call_연결_시간_초과는_여전히_안_닿는_사이트다(_rest, monkeypatch):
    monkeypatch.setattr(gw.httpx, "AsyncClient", _TimedCli)
    _TimedCli.fail = httpx.ConnectTimeout("")
    out = _payload(await gw._rest_call({"site": "locked", "path": "/x"}))
    assert out["error"] == "upstream unreachable"


def test_rest_call_한도는_호출_한도를_따르고_따로_줄_수도_있다(tmp_path):
    names = ["REST_CALL_TIMEOUT_S", "CALL_TIMEOUT_S"]
    assert _limits(tmp_path, names)[0] == {"REST_CALL_TIMEOUT_S": 600.0, "CALL_TIMEOUT_S": 600}
    assert _limits(tmp_path, names, GATEWAY_CALL_TIMEOUT="900")[0] == {"REST_CALL_TIMEOUT_S": 900.0, "CALL_TIMEOUT_S": 900}
    assert _limits(tmp_path, names, GATEWAY_REST_CALL_TIMEOUT="45")[0] == {"REST_CALL_TIMEOUT_S": 45.0, "CALL_TIMEOUT_S": 600}
