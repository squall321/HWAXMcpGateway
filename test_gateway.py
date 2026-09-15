# 게이트웨이 그룹 인가 순수 로직 단위 테스트 (네트워크·백엔드 불필요).
import json

import mcp.types as types

import gateway as gw


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
                              gw.BROWSE_EXPERTS_TOOL, gw.USE_EXPERTS_TOOL, gw.VERIFY_TOOL)}

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
    assert asyncio.run(gw._portal_entitlements("u@corp.com", ["mes-user"])) == ["feat:chat"]
    assert asyncio.run(gw._portal_entitlements("u@corp.com", ["mes-user"])) == ["feat:chat"]
    assert len(calls) == 1 and calls[0] == {"email": "u@corp.com", "groups": "mes-user"}, "캐시"

    gw._ENT_CACHE.clear()
    def boom(req):
        raise httpx.ConnectError("portal down")
    _mock_http(monkeypatch, boom)
    assert asyncio.run(gw._portal_entitlements("u@corp.com", ["mes-user"])) == ["feat:chat"], \
        "포털이 죽으면 직전 값"
    _mock_http(monkeypatch, lambda req: httpx.Response(404))
    assert asyncio.run(gw._portal_entitlements("new@corp.com", [])) is None, \
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

    # 권한이 있으면 종전대로 보인다.
    monkeypatch.setattr(gw, "_request_groups", lambda: ["admin"])
    body2 = json.loads(asyncio.run(gw._list_tool_apps({})).content[0].text)
    assert {a["app"] for a in body2["apps"]} >= {"open_app", "secret"}
    assert body2["hidden_no_access"] == 0


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

    async def go():
        # 데드라인이 없으면 여기서 매달린다 — 그게 실제로 일어난 일이다
        await asyncio.wait_for(gw._aggregate(), timeout=5)

    asyncio.run(go())

    got = {t.name for t in gw.exposed_tools}
    assert got == {"before", "after"}, f"막힌 백엔드가 나머지를 데려갔다: {got}"
    # 응답 안 준 백엔드는 **죽은 것으로 표시**돼 다음 회차 재연결 루프가 집어 간다
    assert stuck_answer.session is None, "재연결 예약이 안 됐다 — 영영 안 돌아온다"


def test_the_stuck_backend_is_reported_not_swallowed(monkeypatch, caplog):
    """건너뛴 것을 조용히 넘기면 도구가 사라진 이유를 아무도 못 찾는다."""
    import asyncio
    import logging

    monkeypatch.setattr(gw, "LIVENESS_TIMEOUT_S", 0.05)
    monkeypatch.setattr(gw, "backends", {"stuck": _NeverAnswersB()})
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "route", {})
    monkeypatch.setattr(gw, "alias_route", {})

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
    monkeypatch.setattr(gw, "_portal_entitlements", _no_portal)

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
