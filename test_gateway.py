# 게이트웨이 그룹 인가 순수 로직 단위 테스트 (네트워크·백엔드 불필요).
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
                              gw.SEARCH_TOOLS_TOOL, gw.INVOKE_TOOL)}

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
    _aggregate_with(monkeypatch, {
        "heax-step_forge": ["cancel_job"],
        "other": ["heaxstep_forge_cancel_job"],       # 남의 별칭과 같은 이름
    })
    assert gw.route["heaxstep_forge_cancel_job"] == ("other", "heaxstep_forge_cancel_job")
    resolved = gw.route.get("heaxstep_forge_cancel_job") or gw.alias_route.get(
        "heaxstep_forge_cancel_job")
    assert resolved[0] == "other", "route 가 먼저다 — 기존 이름의 뜻이 안 바뀐다"


def test_aliases_do_not_change_the_visible_catalogue(monkeypatch):
    """별칭은 tools/list·`/tools-map` 에 안 잡힌다 — 개수·드리프트 검사가 그대로다."""
    monkeypatch.setattr(gw, "POLICY", {})
    _aggregate_with(monkeypatch, {"heax-step_forge": ["a", "b"], "kooremapper_mcp": ["b", "c"]})
    listed = {t.name for t in gw.exposed_tools}
    assert listed == set(gw.route), "노출 목록과 route 가 1:1 이다"
    assert len(gw.alias_route) == 4, "별칭은 백엔드×도구 전부"
    assert not (listed & (set(gw.alias_route) - set(gw.route))), "별칭이 목록에 새지 않는다"
