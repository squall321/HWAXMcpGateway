# 게이트웨이 그룹 인가 순수 로직 단위 테스트 (네트워크·백엔드 불필요).
import base64
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
    # search_tools 질의 모으기도 같다 — 안 걸면 시험 질의가 실사용 질의 파일(tool_search_eval/queries.local.jsonl)에 쌓인다.
    monkeypatch.setattr(gw, "TOOL_QUERY_LOG_DIR", tmp_path / "qlog")
    monkeypatch.setattr(gw, "TOOL_QUERY_LOG", tmp_path / "qlog" / "queries.local.jsonl")
    monkeypatch.setattr(gw, "_QLOG", {"day": None})
    monkeypatch.setattr(gw, "_RECENT_SEARCH", gw.OrderedDict())
    # 박스 정답쌍(사람 표시 — /search-review 가 쓴다)도 같다 — 안 걸면 시험 표시가 실제 박스 파일에 쌓인다(E-9 ②)
    monkeypatch.setattr(gw, "SEARCH_PAIRS_LOCAL_PATH", tmp_path / "qlog" / "pairs.local.jsonl")
    # 검색 손잡이 덧씌우기도 같다 — 박스에 search_tuning.local.json 이 있으면 시험 순위가 그 박스 값으로 돈다. 기본값만 보게 없는 자리를 건다.
    monkeypatch.setattr(gw, "SEARCH_TUNING_LOCAL_PATH", tmp_path / "search_tuning.local.json")
    monkeypatch.setattr(gw, "_TUNING", {"key": None, "data": None, "error": "아직 읽지 않음", "overlay": None})


@pytest.fixture(autouse=True)
def _no_real_portal(monkeypatch):
    """포털 격리 — 설정 파일(gateway_config.json)의 실제 포털 주소로 시험이 묻지 않게 **모든 시험에 자동으로** 비운다.

    ⚠ 심의 신원 호출이 소속을 포털에 묻게 되자(결정 6, 10-18) 그 길을 타는 시험이 dev 포털의 /internal/access/entitlements
    를 실제로 불렀다(읽기지만 시험이 박스 상태에 기대게 된다). 포털이 필요한 시험은 본문에서 `PORTAL`·`_portal_api_base` 를 다시
    건다(종전대로). 권한 캐시도 시험마다 새것이다."""
    monkeypatch.setattr(gw, "PORTAL", {})
    monkeypatch.setattr(gw, "_ENT_CACHE", {})


# 형제 포털 리포의 코어 어휘표 정본(HWAXPortal backend/config/core_vocab.json) — 아래 격리가 걸기 전의 기본 경로다.
_REAL_CORE_VOCAB = gw.CORE_VOCAB_PATH


@pytest.fixture(autouse=True)
def _no_core_vocab(monkeypatch, tmp_path):
    """코어 어휘표 격리 — 기본은 '없음'(지금 동작)이다. 형제 리포의 실제 표를 읽는 시험은 본문에서 _REAL_CORE_VOCAB 를 다시 건다.

    ⚠ 안 걸면 실제 표가 검색 순위 · 도구 설명(정본 소개 줄) · 재집계 예약을 바꾸고, 모듈 상태라 앞 시험의 것이 뒤 시험에 남는다
    (HWAXPortal docs/request-1029 C-11). '없음' 을 이미 아는 상태로 두어 시험마다 경고 줄이 생기지 않게 한다."""
    monkeypatch.setattr(gw, "CORE_VOCAB_PATH", tmp_path / "no-core-vocab.json")
    # 박스 덧씌우기도 늘 '없음' — 실제 표를 읽는 시험에도 박스의 core_vocab.local.json 이 끼어들지 않게 한다(E-7 ②)
    monkeypatch.setattr(gw, "CORE_VOCAB_LOCAL_PATH", tmp_path / "no-core-vocab.local.json")
    monkeypatch.setattr(gw, "_CORE_VOCAB", {"mtime": None, "data": None, "error": "없음", "tag_applied": None, "overlay": None})


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
                              gw.REST_CATALOG_TOOL, gw.REST_CALL_TOOL, *gw.ROUTINE_TOOLS)}

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


def test_save_conversation_meta_는_알려진_칸만_자르지_않고(monkeypatch):
    """알려진 두 칸(rebut·non_negotiable)만 옮긴다 — 임의 dict 는 넘기지 않는다. 다만 자르지 않는다: 종전엔 웹 경로처럼
    반박 4건·요지 160자·조항 1,200자로 잘랐는데, 포털 입력 모델은 meta 에 한도가 없고 이어하기는 그 조항을 다음 심의에 넘긴다."""
    big = [{"target": "t" * 500, "quote": "q" * 500, "counter": "c" * 500, "basis": "b" * 500, "junk": 1}] * 9
    out = _drive_save(monkeypatch, [
        {"role": "persona", "persona": "a", "content": "x",
         "meta": {"rebut": big, "non_negotiable": "조" * 5000, "evil": "x" * 99999}},
        {"role": "persona", "persona": "b", "content": "y", "meta": "문자열은 meta 가 아니다"},
        {"role": "persona", "persona": "c", "content": "z"},
    ])
    m = out[0]["meta"]
    assert set(m) == {"rebut", "non_negotiable"}             # 모르는 칸은 옮기지 않는다
    assert len(m["rebut"]) == 9 and m["non_negotiable"] == "조" * 5000
    r = m["rebut"][0]
    assert (len(r["target"]), len(r["quote"]), len(r["counter"]), len(r["basis"])) == (500, 500, 500, 500)
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


@pytest.mark.parametrize("app, tool, want", [
    # 코어 허브의 읽기 도구는 '사내 지식 검색' — 10-27 cae00 그 영역(55개)에 코어 허브 도구가 0개였다(HWAXPortal docs/request-1027 HG-05)
    ("rootdesigndatahub", "rootdesigndatahub_object_resolve", "knowledge"),
    ("failuretrace", "failuretrace_graph_neighbors", "knowledge"),
    ("caegroupdatahub", "caegroupdatahub_objects_summary", "knowledge"),
    ("rootdesigndatahub", "rootdesigndatahub_objects_upsert", "data"),     # 허브의 나머지는 앱 기본값
    # 미분류 996/1612(61.8%) — 앱 기본값이 없던 것들(외부 연결 선언 플랫폼 포함)
    ("componentcore", "find_component", "cad"), ("matnexus", "matnexus_search", "material"), ("fmea", "fmea_defect_cases", "quality"),
    ("odb-hub", "odb_open", "cad"), ("arp", "arp_list", "result"), ("simflow", "open_workflow_panel", "sim"),
    ("simengbay", "list_engines", "sim"), ("ste", "ste_submit_job", "sim"), ("dynaforge-prod", "dynaforgeprod_whoami", "system"),
    ("dynaforge-prod", "report_summary", "result"), ("stepforge-prod", "list_parts", "cad"),
    ("matnexus", "voc_breakdown", "voc"),                                  # voc_* 는 어느 앱이든 VOC
])
def test_HG05_코어_허브_읽기는_지식_검색이고_앱_기본값이_미분류를_메운다(monkeypatch, app, tool, want):
    monkeypatch.setattr(gw, "_AREAS_CACHE", {"mtime": None, "data": {}})     # 추적 파일 그대로
    assert gw._area_of(tool, app) == want


def test_HG05_영역_요약도_include_tools_false_면_도구_이름을_싣지_않는다(monkeypatch):
    import asyncio
    monkeypatch.setattr(gw, "_AREAS_CACHE", {"mtime": None, "data": {}})

    class _S:
        session = object()
    monkeypatch.setattr(gw, "backends", {"heax-step_forge": _S()})
    monkeypatch.setattr(gw, "exposed_tools", [_tool("find_parts")])
    monkeypatch.setattr(gw, "route", {"find_parts": ("heax-step_forge", "find_parts")})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    slim = json.loads(asyncio.run(gw._list_tool_apps({"by": "area", "include_tools": False})).content[0].text)
    assert slim["areas"] and all("tools" not in a for a in slim["areas"]), slim
    assert {a["area"]: a["tool_count"] for a in slim["areas"]}["cad"] == 1, "개수는 남는다"
    full = json.loads(asyncio.run(gw._list_tool_apps({"by": "area"})).content[0].text)
    assert {a["area"]: a for a in full["areas"]}["cad"]["tools"] == ["find_parts"], "기본은 종전대로"
    one = json.loads(asyncio.run(gw._list_tool_apps({"by": "area", "area": "cad", "include_tools": False})).content[0].text)
    assert one["areas"][0]["tools"][0]["name"] == "find_parts", "영역을 고르면 그 영역의 도구 설명을 준다"


def _hg10(monkeypatch, *, user="u@corp.com", conns=None, lookup_fails=(), sso=None):
    """토큰 등록 앱 둘(fmea · reportarchive)과 위임 앱 하나(testscope — per_user_sso) · 평범한 앱 하나로 list_tool_apps 를 부른다."""
    import asyncio

    class _S:
        session = object()
    keys = ("fmea", "reportarchive", "testscope", "heax-step_forge")
    monkeypatch.setattr(gw, "backends", {k: _S() for k in keys})
    monkeypatch.setattr(gw, "exposed_tools", [_tool(f"t_{i}") for i, _k in enumerate(keys)])
    monkeypatch.setattr(gw, "route", {f"t_{i}": (k, f"t_{i}") for i, k in enumerate(keys)})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    monkeypatch.setattr(gw, "_request_user", lambda: user)
    monkeypatch.setattr(gw, "PORTAL_CONN_BACKENDS", {"fmea": "fmea", "reportarchive": "reportarchive", "testscope": "testscope"})
    monkeypatch.setattr(gw, "PER_USER_SSO", sso if sso is not None else {"testscope": {"sso_url": "http://x", "secret": "s"}})
    asked = []

    async def fake_conn(service, email):
        asked.append(service)
        if service in lookup_fails:
            raise gw._ConnLookupError("포털 불통")
        return (conns or {}).get(service)
    monkeypatch.setattr(gw, "_portal_connection", fake_conn)
    body = json.loads(asyncio.run(gw._list_tool_apps({})).content[0].text)
    return {a["app"]: a for a in body["apps"]}, sorted(asked), body


def test_HG10_토큰을_등록하지_않은_외부_연결은_needs_connect_와_등록_안내를_싣는다(monkeypatch):
    """10-25 dynaforge-prod 72 tools ok 인데 같은 사람의 whoami 는 'refused: no-connection'(64 ms)이었다(HWAXPortal docs/request-1027 HG-10)."""
    by, asked, body = _hg10(monkeypatch, conns={"reportarchive": {"token": "rat_x", "workspace": ""}})
    assert by["fmea"]["status"] == "needs_connect" and by["fmea"]["needs_connect"] is True
    assert "/tokens?tab=connect" in by["fmea"]["connect_note"]
    assert by["reportarchive"]["status"] == "ok" and "needs_connect" not in by["reportarchive"], "등록한 앱은 그대로"
    assert by["heax-step_forge"]["status"] == "ok"
    assert asked == ["fmea", "reportarchive"], "위임으로 가는 앱(testscope)은 등록을 묻지 않는다"
    assert "needs_connect" in body["note"]


def test_HG10_신원이_없거나_포털을_못_물으면_표시하지_않는다(monkeypatch):
    by, asked, _b = _hg10(monkeypatch, user="")
    assert asked == [] and all("needs_connect" not in a for a in by.values()), "신원 없는 호출은 등록과 상관없다"
    by, asked, _b = _hg10(monkeypatch, lookup_fails=("fmea",), conns={"reportarchive": {"token": "rat_x"}})
    assert by["fmea"]["status"] == "ok" and "needs_connect" not in by["fmea"], "모름을 없음으로 읽지 않는다"


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


def test_지침의_유사도_안내는_임베딩_모델에_묶이지_않는다():
    """옛 e5 기준 「무관한 문장끼리도 0.87~0.90」 이 남아 있었다 — BGE-M3 는 무관 1위가 0.57 안팎이라 그 숫자를 믿으면 거꾸로 읽는다
    (HWAXPortal docs/request-1027 HG-13). 모델을 바꿔도 맞는 말만 둔다."""
    import re
    assert not re.search(r"0\.\d+\s*[~∼-]\s*0\.\d+", gw._INSTRUCTIONS), "지침에 모델 고유의 유사도 구간이 있다"
    assert "유사도 점수를 신뢰도로 읽지 마라" in gw._INSTRUCTIONS and "desc_match" in gw._INSTRUCTIONS


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

    monkeypatch.setattr(gw, "HEAX", {})
    monkeypatch.setattr(gw, "_FP", {})
    monkeypatch.setattr(gw, "_LAST_TOOLS", {})

    async def go():
        # 데드라인이 없으면 여기서 매달린다 — 그게 실제로 일어난 일이다
        await asyncio.wait_for(gw._aggregate(), timeout=5)
        first = ({t.name for t in gw.exposed_tools}, stuck_answer.session is not None, gw._REAGG.get("pending"))
        await asyncio.wait_for(gw._aggregate(), timeout=5)
        second = stuck_answer.session is not None
        await asyncio.wait_for(gw._revive_once(object()), timeout=5)
        third = stuck_answer.session is not None
        await asyncio.wait_for(gw._revive_once(object()), timeout=5)
        return first, second, third

    (got, kept, again), kept2, kept3 = asyncio.run(go())

    assert got == {"before", "after"}, f"막힌 백엔드가 나머지를 데려갔다: {got}"
    # 재집계의 무응답으로는 세션을 갈지 않는다(잠깐 바쁜 건강한 백엔드의 진행 중 답을 버린다, gateway-06) — 몇 번을 놓쳐도
    # 같다. 대신 다음 회차에 목록을 다시 받게 예약한다 — 안 그러면 이 백엔드의 도구가 그 구성이 바뀔 때까지 카탈로그에
    # 안 올라온다.
    assert kept and again is True and kept2
    # 생사는 재활 패스의 탐침이 가린다 — 연속으로 놓친 백엔드는 **죽은 것으로 표시**돼 재연결 루프가 집어 간다
    assert kept3, "탐침 한 번으로는 아직 둔다"
    assert stuck_answer.session is None, "재연결 예약이 안 됐다 — 영영 안 돌아온다"
    assert {"before", "after"} <= {t.name for t in gw.exposed_tools}


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

    async def fake_pat(app_id, email, *, stale=None, notes=None):
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


@pytest.mark.parametrize("key", ["Authorization", "authorization", "AUTHORIZATION"])
def test_사람별_호출은_바탕의_서비스_토큰을_그_사람_토큰_하나로_갈아_끼운다(monkeypatch, key):
    """ODB 처럼 서비스 토큰을 헤더로 싣는 백엔드(HWAXPortal docs/request-1027 HG-02) — 두 토큰이 한 요청에 같이 가면 앱이 서비스
    쪽을 먼저 읽어 그 사람 호출이 팀 계정으로 찍힌다. 철자가 달라도 하나만 간다."""
    seen = _per_user_kit(monkeypatch, None, base_headers={key: "Bearer team-tok", "X-Keep": "1"})
    auth = [(k, v) for k, v in seen["headers"].items() if k.lower() == "authorization"]
    assert auth == [("Authorization", "Bearer kr_tok")] and seen["headers"]["X-Keep"] == "1", seen["headers"]
    # 자격을 다른 헤더로 싣는 앱(Caddy 뒤 heax 앱)은 바탕 Authorization 을 그대로 둔다 — 문을 지나는 자격이다
    seen = _per_user_kit(monkeypatch, None, base_headers={key: "Bearer heax-svc"}, sso_extra={"token_header": "X-App-Token"})
    assert seen["headers"][key] == "Bearer heax-svc" and seen["headers"]["X-App-Token"] == "kr_tok"


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


def test_바란_앱에만_plat_권한이_증명과_함께_실린다(monkeypatch):
    """MX WhitePaper 위키는 plat:plmdefect 같은 플랫폼 권한으로 읽기 범위를 가른다(HWAXPortal docs/mxwp-wiki P4).
    소속과 같은 까닭으로 평문만으로는 안 되고(앱 정문이 여럿), 바라지 않은 앱에는 권한 목록을 퍼뜨리지 않는다."""
    import hashlib
    import hmac
    from urllib.parse import unquote

    groups = ("mes-user", "plat:plmdefect", "feat:chat", "plat:mxwhitepaper")
    seen = _per_user_kit(monkeypatch, {"keys": [], "affiliation": "CAEG"}, groups=groups,
                         sso_extra={"send_plat": True})
    got = unquote(seen["headers"][gw.PLAT_HEADER])
    assert got == "plat:mxwhitepaper,plat:plmdefect", "plat: 만, 정렬해서 — feat: · 로그인 그룹은 싣지 않는다"
    ver, exp, sig = seen["headers"][gw.PLAT_PROOF_HEADER].split(".")
    assert ver == "v1" and int(exp) > 0
    want = hmac.new(b"app-secret", f"v1|u@corp.com|plat:mxwhitepaper,plat:plmdefect|{exp}".encode(),
                    hashlib.sha256).hexdigest()
    assert hmac.compare_digest(sig, want), "서명이 이메일 · 목록 · 만료에 결속돼야 한다"
    for other in (f"v1|bob@corp.com|plat:mxwhitepaper,plat:plmdefect|{exp}",      # 남의 호출
                  f"v1|u@corp.com|plat:mxwhitepaper,plat:plmdefect,plat:x|{exp}",  # 목록에 하나 더
                  f"v1|u@corp.com|plat:mxwhitepaper|{exp}"):                       # 목록에서 하나 빼기
        assert sig != hmac.new(b"app-secret", other.encode(), hashlib.sha256).hexdigest()
    assert seen["headers"][gw.AFF_HEADER] == "CAEG", "소속 헤더는 그대로 같이 간다"

    seen = _per_user_kit(monkeypatch, {"keys": [], "affiliation": "CAEG"}, groups=groups)
    assert gw.PLAT_HEADER not in seen["headers"] and gw.PLAT_PROOF_HEADER not in seen["headers"], \
        "send_plat 을 켜지 않은 앱(DynaForge · ste …)에는 싣지 않는다"
    seen = _per_user_kit(monkeypatch, {"keys": [], "affiliation": "CAEG"}, groups=groups,
                         sso_extra={"send_plat": "yes"})
    assert gw.PLAT_HEADER not in seen["headers"], "참(True)일 때만 — 문자열 설정은 켠 것으로 보지 않는다"


def test_plat_권한이_없으면_두_헤더를_아예_안_싣고_서비스_값도_지운다(monkeypatch):
    svc = {gw.PLAT_HEADER: "plat:svc", gw.PLAT_PROOF_HEADER: "v1.0.dead", "X-Keep": "1"}
    seen = _per_user_kit(monkeypatch, {"keys": [], "affiliation": ""}, base_headers=svc,
                         groups=("mes-user", "feat:chat"), sso_extra={"send_plat": True})
    assert gw.PLAT_HEADER not in seen["headers"] and gw.PLAT_PROOF_HEADER not in seen["headers"], \
        "빈 목록을 싣거나 서비스 계정 설정의 값이 남으면 받는 쪽이 그것을 그 사람의 권한으로 읽는다"
    assert seen["headers"]["X-Keep"] == "1"


@pytest.mark.anyio
async def test_rest_call_사람별_사이트에도_소속_plat_증명이_실린다(_rest, monkeypatch):
    """MCP 사람별 경로에만 실었더니 같은 사람이 rest_call 로 부르면 앱이 소속 · plat 범위를 못 봤다(HWAXPortal docs/mxwp-wiki P4).
    서명 · 인코딩은 MCP 경로와 같다. 소속은 그 경로처럼 합성 그룹을 뺀 로그인 그룹으로, 낡은 값 없이 묻는다."""
    import hashlib
    import hmac
    from urllib.parse import unquote

    monkeypatch.setattr(gw.httpx, "AsyncClient", _Cli)
    _Cli.status, _Cli.raw, _Cli.ctype, _Cli.clen = 200, b'{"ok": true}', "application/json", None
    _rest["mx"] = {"base": "http://127.0.0.1:3", "per_user": "mxapp"}
    monkeypatch.setattr(gw, "POLICY", {"locked": [], "open": ["analyst"], "mx": []})
    monkeypatch.setattr(gw, "PER_USER_SSO", {"mxapp": {"sso_url": "http://x", "secret": "app-secret", "send_plat": True}})
    monkeypatch.setattr(gw, "_request_groups", lambda: ["mes-user", "plat:plmdefect", "plat:mxwhitepaper", "feat:chat"])

    async def fake_pat(app_id, email, *, stale=None, notes=None):
        return "mx_tok"
    monkeypatch.setattr(gw, "_user_pat", fake_pat)
    asked = []

    async def fake_access(email, base, *, allow_stale=True):
        asked.append((email, list(base), allow_stale))
        return {"keys": [], "affiliation": "CAEG"}
    monkeypatch.setattr(gw, "_portal_access", fake_access)

    res = await gw._rest_call({"site": "mx", "path": "/api/v1/wiki/index"})
    assert not res.isError
    h = _Cli.seen["headers"]
    assert h["Authorization"] == "Bearer mx_tok"
    assert h[gw.AFF_HEADER] == "CAEG" and unquote(h[gw.PLAT_HEADER]) == "plat:mxwhitepaper,plat:plmdefect"
    _v, exp, sig = h[gw.AFF_PROOF_HEADER].split(".")
    assert hmac.compare_digest(sig, hmac.new(b"app-secret", f"v1|me@x.com|CAEG|{exp}".encode(), hashlib.sha256).hexdigest())
    _v, exp, sig = h[gw.PLAT_PROOF_HEADER].split(".")
    want = hmac.new(b"app-secret", f"v1|me@x.com|plat:mxwhitepaper,plat:plmdefect|{exp}".encode(), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(sig, want), "MCP 경로와 같은 서명이어야 앱 검증 하나로 두 길을 다 받는다"
    assert asked[-1] == ("me@x.com", ["mes-user"], False)

    # 소속이 없고 send_plat 을 켜지 않은 앱이면 증명은 하나도 안 실린다(빈 값을 싣지 않는다)
    monkeypatch.setattr(gw, "PER_USER_SSO", {"mxapp": {"sso_url": "http://x", "secret": "app-secret"}})
    monkeypatch.setattr(gw, "_portal_access", _noop_async({"keys": [], "affiliation": ""}))
    assert not (await gw._rest_call({"site": "mx", "path": "/api/v1/wiki/index"})).isError
    proofs = {gw.AFF_HEADER, gw.AFF_PROOF_HEADER, gw.PLAT_HEADER, gw.PLAT_PROOF_HEADER}
    assert not (proofs & set(_Cli.seen["headers"]))


def test_REST_프록시_사람별_사이트는_게이트웨이가_지은_증명만_보낸다(monkeypatch):
    """`/api/<site>/` 는 클라이언트 헤더를 대부분 그대로 넘긴다 — 사람이 직접 실어 보낸 증명 헤더는 떼고(서명이 맞을 리 없지만
    같은 이름이 둘 가면 앱이 어느 쪽을 읽을지 모른다) 게이트웨이가 포털의 지금 값으로 지은 것만 보낸다."""
    import hashlib
    import hmac
    from urllib.parse import unquote
    from starlette.requests import Request
    from rest_proxy import RestProxy

    monkeypatch.setattr(gw, "PER_USER_SSO", {"mxapp": {"sso_url": "http://x", "secret": "app-secret", "send_plat": True}})

    async def fake_pat(app_id, email, *, stale=None, notes=None):
        return "mx_tok"
    monkeypatch.setattr(gw, "_user_pat", fake_pat)
    monkeypatch.setattr(gw, "_portal_access",
                        _noop_async({"keys": ["plat:plmdefect", "plat:mxwhitepaper", "feat:chat"], "affiliation": "CAEG"}))
    p = RestProxy({"mx": {"base": "http://upstream.invalid", "per_user": "mxapp"}}, {"audience_ok": ["mx"]}, gw._audit,
                  mint=gw._rest_mint, proofs=gw._rest_proofs)
    p._verify = lambda token, s: {"sub": "S-1", "email": "u@corp.com", "jti": "j", "groups": ["mes-user"]}
    p._revoked_set = _noop_async(set())
    sent = []

    async def fake_send(req, stream=False):
        sent.append([(k.lower(), v) for k, v in req.headers.items()])
        return httpx.Response(200, content=b"ok", request=req)
    monkeypatch.setattr(p._client, "send", fake_send)
    resp = asyncio.run(p.handle(Request({
        "type": "http", "method": "GET", "path": "/api/mx/api/v1/wiki/index",
        "headers": [(b"authorization", b"Bearer me"), (b"x-heax-user-plat", b"plat:everything"),
                    (b"x-heax-plat-proof", b"v1.0.dead"), (b"x-heax-user-affiliation", b"OTHER")],
        "query_string": b"", "path_params": {"site": "mx", "path": "api/v1/wiki/index"}, "client": ("203.0.113.5", 0)})))
    assert resp.status_code == 200
    (got,) = sent
    plat = [v for k, v in got if k == "x-heax-user-plat"]
    aff = [v for k, v in got if k == "x-heax-user-affiliation"]
    assert len(plat) == 1 and unquote(plat[0]) == "plat:mxwhitepaper,plat:plmdefect", "위조 사본이 떨어지고 포털의 지금 값만 간다"
    assert aff == ["CAEG"]
    (proof,) = [v for k, v in got if k == "x-heax-plat-proof"]
    _v, exp, sig = proof.split(".")
    assert hmac.compare_digest(sig, hmac.new(b"app-secret", f"v1|u@corp.com|plat:mxwhitepaper,plat:plmdefect|{exp}".encode(),
                                             hashlib.sha256).hexdigest())
    assert dict(got)["authorization"] == "Bearer mx_tok"


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
    assert [u for _m, u, _h in http] == ["http://testscope.example/api/auth/sso"], \
        "발급 실패는 다시 받지 않는다(HG-03 — 다시 받아도 같은 자리다) · 포털은 묻지 않는다"
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
    문자열이면 그 문구의 isError 결과다. 호출마다 **어느 토큰을 실었는지**와 발급 때의 stale(거절된 토큰)을 돌려준다."""
    import asyncio

    b = _CallB(["cluster_info"])
    seen = {"tokens": [], "stale": [], "calls": 0}
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

    async def fake_pat(app_id, email, *, stale=None, notes=None):
        seen["stale"].append(stale)
        return "new-tok" if stale else "old-tok"

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
    assert seen["calls"] == 2 and seen["stale"] == [None, "old-tok"], "거절된 토큰을 짚어 다시 받는다"
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
    assert seen["calls"] == 1 and seen["stale"] == [None] and seen["result"].isError


# ── 사람별 위임은 백엔드가 401 로 거절했을 때만 다시 받는다(HWAXPortal docs/request-1027 HG-03) ─────────────────────
# 종전에는 시간 초과만 빼고 어떤 실패에도 다시 받았다 — 발급마다 직전 토큰을 폐기하는 앱(SimFlow)에서 같은 사람의 다른 좌석이 죽었고,
# 발급 엔드포인트가 500 이면 한 호출이 발급을 두 번 불렀다(10-16). 진짜 `_user_pat` · `_mint_user_pat` · `_call_as_user` · `_oneshot` ·
# MCP 클라이언트를 태우고 HTTP 만 가짜로 둔다 — 백엔드의 401 이 진짜 꼴(ExceptionGroup 안의 httpx.HTTPStatusError)로 올라온다.
_HG03_SSO, _HG03_MCP = "http://simflow.example/api/auth/sso", "http://simflow.example/mcp"


def _hg03_kit(monkeypatch, decide, *, sso_status=200, calls=1):
    """`decide(Authorization, n)` 이 tools/call 마다 백엔드의 HTTP 상태를 정한다(200 이면 성공, 예외면 그 예외). `calls` 번을 한꺼번에
    부른다 → (결과 목록, 센 것 — 발급 · tools/call 이 실은 토큰, 감사 줄)."""
    n = {"mints": 0, "tokens": []}

    def handler(req):
        u = str(req.url)
        if u == _HG03_SSO:
            n["mints"] += 1
            if sso_status != 200:
                return httpx.Response(sso_status, json={"detail": "발급 실패"})
            return httpx.Response(200, json={"access_token": f"t{n['mints']}", "expires_in": 3600})
        assert u == _HG03_MCP, u
        if req.method != "POST":
            return httpx.Response(405)
        msg = json.loads(req.content)
        if msg.get("method") == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": msg["id"], "result": {
                "protocolVersion": msg["params"]["protocolVersion"], "capabilities": {"tools": {}},
                "serverInfo": {"name": "simflow", "version": "1"}}})
        if "id" not in msg:
            return httpx.Response(202)
        if msg.get("method") == "tools/list":    # 진짜 클라이언트는 tools/call 뒤에 출력 스키마를 보러 목록을 부른다(mcp 1.28)
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": [
                {"name": "list_workflows", "inputSchema": {"type": "object"}}]}})
        assert msg.get("method") == "tools/call", msg
        auth = req.headers.get("authorization")
        n["tokens"].append(auth)
        code = decide(auth, len(n["tokens"]))
        if isinstance(code, Exception):
            raise code
        if code != 200:
            return httpx.Response(code, json={"detail": "거절"})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": msg["id"], "result": {
            "content": [{"type": "text", "text": '{"rows": []}'}], "isError": False}})
    _mock_http(monkeypatch, handler)
    b = _CallB(["list_workflows"])
    b.url = _HG03_MCP

    async def fake_access(email, base_groups, **_kw):
        return {"keys": [], "affiliation": ""}
    gw._RESP_CACHE.clear()
    monkeypatch.setattr(gw, "backends", {"simflow": b})
    monkeypatch.setattr(gw, "route", {"list_workflows": ("simflow", "list_workflows")})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setattr(gw, "PER_USER_SSO", {"simflow": {"sso_url": _HG03_SSO, "secret": "s"}})
    monkeypatch.setattr(gw, "_USER_PATS", {})
    monkeypatch.setattr(gw, "_USER_PAT_LOCKS", {})
    monkeypatch.setattr(gw, "_request_user", lambda: "u@corp.com")
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    monkeypatch.setattr(gw, "_portal_access", fake_access)

    async def run():
        return await asyncio.gather(*(gw._call_tool("list_workflows", {"q": str(i)}) for i in range(calls)))
    res = asyncio.run(run())
    return res, n, [r for r in _rows() if r["tool"] == "list_workflows"]


def test_HG03_백엔드가_401_로_거절하면_그_토큰을_짚어_한_번_다시_받는다(monkeypatch):
    res, n, rows = _hg03_kit(monkeypatch, lambda auth, i: 401 if auth == "Bearer t1" else 200)
    assert not res[0].isError, res[0].content[0].text
    assert (n["mints"], n["tokens"]) == (2, ["Bearer t1", "Bearer t2"])
    assert [(r["ok"], r["mode"], r.get("note")) for r in rows] == [(True, "as-user-pat", "re-minted")]


def test_HG03_같은_사람이_한꺼번에_401_을_받아도_발급은_한_번이다(monkeypatch):
    """각자 받던 때는 발급마다 직전 토큰을 폐기하는 앱에서 서로의 새 토큰을 죽였다 — 거절된 토큰이 아직 캐시에 있을 때만 받는다."""
    res, n, rows = _hg03_kit(monkeypatch, lambda auth, i: 401 if auth == "Bearer t1" else 200, calls=3)
    assert [r.isError for r in res] == [False] * 3, [r.content[0].text for r in res]
    assert n["mints"] == 2, f"t1 을 거절당한 세 호출이 t2 하나를 나눠 써야 한다: 발급 {n['mints']}"
    assert sorted(n["tokens"]) == ["Bearer t1"] * 3 + ["Bearer t2"] * 3


@pytest.mark.parametrize("why", [500, 503, 403, httpx.ConnectError("연결 거부")], ids=["500", "503", "403", "연결-오류"])
def test_HG03_401_이_아닌_실패에는_다시_받지도_다시_부르지도_않는다(monkeypatch, why):
    res, n, rows = _hg03_kit(monkeypatch, lambda auth, i: why)
    assert res[0].isError and "자격증명으로 호출하지 못했습니다" in res[0].content[0].text
    assert (n["mints"], len(n["tokens"])) == (1, 1), n
    assert [(r["ok"], r["error"].startswith("per-user: ")) for r in rows] == [(False, True)], rows


def test_HG03_발급이_실패하면_다시_받지_않는다(monkeypatch):
    """10-16 SimFlow `/auth/sso` 500 — 한 호출이 발급을 두 번 불렀다."""
    res, n, rows = _hg03_kit(monkeypatch, lambda auth, i: 200, sso_status=500)
    assert res[0].isError and (n["mints"], n["tokens"]) == (1, [])
    assert rows[-1]["ok"] is False and "SSO 500" in rows[-1]["error"], rows


def test_HG03_다시_받은_토큰도_거절되면_두_번에서_멈춘다(monkeypatch):
    res, n, rows = _hg03_kit(monkeypatch, lambda auth, i: 401)
    assert res[0].isError and (n["mints"], n["tokens"]) == (2, ["Bearer t1", "Bearer t2"])
    assert "401" in rows[-1]["error"], rows


# ── REST 다리 — 위층이 우리가 실은 사람 토큰을 401 로 거절하면 캐시에서 버린다(HWAXPortal docs/request-1027 HG-04) ─────────────
# 버리지 않던 때는 위층이 폐기한 토큰을 캐시 수명(12시간) 동안 계속 실었다. SimFlow 는 발급할 때마다 직전 토큰을 폐기한다.
_HG04_KEY = ("simflow", "u@corp.com")


def _hg04_proxy(monkeypatch, conf, status, *, swap_to=None):
    """`/api/simflow/…` 한 번 — 위층은 `status` 로 답한다. `swap_to` 를 주면 위층이 답하기 전에 다른 호출이 캐시를 그 토큰으로 갈아 둔다."""
    from starlette.requests import Request
    from rest_proxy import RestProxy
    monkeypatch.setattr(gw, "PER_USER_SSO", {"simflow": {"sso_url": _HG03_SSO, "secret": "s"}})
    monkeypatch.setattr(gw, "_USER_PATS", {_HG04_KEY: ("t1", gw.time.monotonic() + 3600)})
    monkeypatch.setattr(gw, "_USER_PAT_LOCKS", {})
    p = RestProxy({"simflow": conf}, {"audience_ok": ["simflow"]}, gw._audit, mint=gw._rest_mint, forget=gw._forget_user_pat)
    p._verify = lambda token, s: {"sub": "S-1", "email": "u@corp.com", "jti": "j", "groups": []}
    p._revoked_set = _noop_async(set())
    sent = []

    async def fake_send(req, stream=False):
        sent.append(req.headers.get("authorization"))
        if swap_to:
            gw._USER_PATS[_HG04_KEY] = (swap_to, gw.time.monotonic() + 3600)
        return httpx.Response(status, json={"detail": "x"}, request=req)
    monkeypatch.setattr(p._client, "send", fake_send)
    resp = asyncio.run(p.handle(Request({
        "type": "http", "method": "GET", "path": "/api/simflow/api/v1/workflows", "headers": [(b"authorization", b"Bearer me")],
        "query_string": b"", "path_params": {"site": "simflow", "path": "api/v1/workflows"}, "client": ("203.0.113.5", 0)})))
    return resp, sent, gw._USER_PATS.get(_HG04_KEY), _rows()[-1]


def test_HG04_REST_프록시는_위층_401_이면_쓴_토큰을_버리고_게이트웨이_401_과_가르는_표지를_단다(monkeypatch):
    resp, sent, cached, row = _hg04_proxy(monkeypatch, {"base": "http://upstream.invalid", "per_user": "simflow"}, 401)
    assert (resp.status_code, sent) == (401, ["Bearer t1"])
    assert resp.headers.get("x-gateway-token-evicted") == "1" and cached is None
    assert (row["ok"], row.get("note")) == (False, "token-evicted")


def test_HG04_그_사이_다른_호출이_받아_둔_새_토큰은_버리지_않는다(monkeypatch):
    resp, _sent, cached, _row = _hg04_proxy(monkeypatch, {"base": "http://upstream.invalid", "per_user": "simflow"}, 401, swap_to="t2")
    assert resp.headers.get("x-gateway-token-evicted") == "1" and cached[0] == "t2"


@pytest.mark.parametrize("conf, status", [({"base": "http://upstream.invalid", "per_user": "simflow"}, 200),
                                          ({"base": "http://upstream.invalid", "per_user": "simflow"}, 403),
                                          ({"base": "http://upstream.invalid",
                                            "inject": {"header": "Authorization", "value": "Bearer svc"}}, 401)],
                         ids=["200", "403", "inject-401"])
def test_HG04_사람_토큰의_401_이_아니면_캐시를_두고_표지도_없다(monkeypatch, conf, status):
    resp, _sent, cached, row = _hg04_proxy(monkeypatch, conf, status)
    assert "x-gateway-token-evicted" not in resp.headers and cached[0] == "t1" and row.get("note") is None


def _hg04_rest_call(monkeypatch, decide):
    """진짜 `_user_pat` 으로 `rest_call` 한 번 — HTTP 만 가짜다. `decide(Authorization)` 가 위층의 상태를 정한다."""
    n = {"mints": 0, "auth": []}

    def handler(req):
        u = str(req.url)
        if u == _HG03_SSO:
            n["mints"] += 1
            return httpx.Response(200, json={"access_token": f"t{n['mints']}", "expires_in": 3600})
        assert u.startswith("http://simflow.example/api/v1/"), u
        n["auth"].append(req.headers.get("authorization"))
        code = decide(req.headers.get("authorization"))
        return httpx.Response(code, json={"ok": code == 200})
    _mock_http(monkeypatch, handler)

    async def fake_access(email, base_groups, **_kw):
        return {"keys": [], "affiliation": ""}
    monkeypatch.setattr(gw, "REST", {"simflow": {"base": "http://simflow.example", "per_user": "simflow"}})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setattr(gw, "PER_USER_SSO", {"simflow": {"sso_url": _HG03_SSO, "secret": "s"}})
    monkeypatch.setattr(gw, "_USER_PATS", {})
    monkeypatch.setattr(gw, "_USER_PAT_LOCKS", {})
    monkeypatch.setattr(gw, "_request_user", lambda: "u@corp.com")
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    monkeypatch.setattr(gw, "_portal_access", fake_access)
    out = _payload(asyncio.run(gw._rest_call({"site": "simflow", "path": "/api/v1/workflows"})))
    return out, n, [r for r in _rows() if r["tool"].startswith("rest_call")][-1]


def test_HG04_rest_call_은_위층_401_이면_토큰을_버리고_새로_받아_한_번_다시_보낸다(monkeypatch):
    out, n, row = _hg04_rest_call(monkeypatch, lambda auth: 401 if auth == "Bearer t1" else 200)
    assert (out["status"], "error" in out) == (200, False), out
    assert (n["mints"], n["auth"]) == (2, ["Bearer t1", "Bearer t2"])
    assert (row["ok"], row.get("note")) == (True, "re-minted")
    assert gw._USER_PATS[_HG04_KEY][0] == "t2", "다음 호출도 새 토큰으로 간다"


def test_HG04_rest_call_은_다시_보내도_401_이면_두_번에서_멈추고_그대로_알린다(monkeypatch):
    out, n, row = _hg04_rest_call(monkeypatch, lambda auth: 401)
    assert out["status"] == 401 and "401" in out["error"]
    assert (n["mints"], len(n["auth"])) == (2, 2) and row["ok"] is False


@pytest.mark.parametrize("code", [403, 500])
def test_HG04_rest_call_은_401_이_아니면_다시_보내지_않는다(monkeypatch, code):
    out, n, _row = _hg04_rest_call(monkeypatch, lambda auth: code)
    assert out["status"] == code and (n["mints"], len(n["auth"])) == (1, 1)
    assert gw._USER_PATS[_HG04_KEY][0] == "t1", "토큰 문제가 아니면 캐시를 둔다"


def test_HG03_http_401_은_묶음을_안까지_본다():
    from exceptiongroup import ExceptionGroup
    resp = httpx.Response(401, request=httpx.Request("POST", _HG03_MCP))
    e401 = httpx.HTTPStatusError("401", request=resp.request, response=resp)
    resp5 = httpx.Response(500, request=httpx.Request("POST", _HG03_MCP))
    e500 = httpx.HTTPStatusError("500", request=resp5.request, response=resp5)
    assert gw._http_401(e401) and gw._http_401(ExceptionGroup("a", [ExceptionGroup("b", [e401])]))
    assert not gw._http_401(ExceptionGroup("a", [e500])) and not gw._http_401(RuntimeError("SSO 401: x"))
    assert not gw._http_401(httpx.ConnectError("x"))


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
               groups=("mes-user", "feat:chat"), headers=None, aff="CAEG"):
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
    # 신원 호출은 소속을 포털에 묻는다(결정 6) — 이 시험 묶음의 포털 답
    monkeypatch.setattr(gw, "_portal_access", _noop_async({"keys": [], "affiliation": aff}))
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
def _rest_gate(monkeypatch, portal_resp, token_groups, site="sec", query=b"", headers=(), sent=None):
    """REST 프록시 라우트를 실제로 태운다 — `main()` 과 같은 배선이고 가짜는 서명 검증·폐기 목록·상류 전송·포털 응답뿐이다.
    돌려주는 것 — 응답 · 상류에 닿은 주소 · 포털에 물은 로그인 그룹. `headers` 는 클라이언트가 더 실어 보낸 헤더이고,
    `sent`(목록)를 주면 상류에 닿은 요청 헤더를 거기 담는다."""
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
        if sent is not None:
            sent.append({k.lower(): v for k, v in req.headers.items()})
        return httpx.Response(200, content=b"ok", request=req)
    monkeypatch.setattr(p._client, "send", fake_send)
    resp = asyncio.run(p.handle(Request({
        "type": "http", "method": "GET", "path": f"/api/{site}/x",
        "headers": [(b"authorization", b"Bearer me"), *headers],
        "query_string": query, "path_params": {"site": site, "path": "x"}, "client": ("203.0.113.5", 0)})))
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
import json
import gateway as gw
out = {n: getattr(gw, n) for n in dir(gw)
       if n.isupper() and isinstance(getattr(gw, n), (int, float)) and not isinstance(getattr(gw, n), bool)}
out["_line"] = gw._limits_line()
print(json.dumps(out))
'''
_LIMITS_SEEN: dict = {}
# 손잡이를 한꺼번에 바꿔 준 환경 — 시험마다 따로 띄우면 import 가 스무 번이다(부하 걸린 박스에서 스위트가 20초 넘게 는다).
_KNOBS_SET = dict(GATEWAY_CALL_TIMEOUT="900", GATEWAY_RECONNECT_TIMEOUT="12", GATEWAY_BACKEND_HTTP_TIMEOUT="7",
                  GATEWAY_LIVENESS_STRIKES="3", GATEWAY_AGG_STALE_ROUNDS="4", GATEWAY_HEAX_MISS_DROP="6",
                  GATEWAY_PORTAL_SAVE_TIMEOUT="300", GATEWAY_JWKS_TIMEOUT="2", REST_PROXY_UPSTREAM_TIMEOUT_S="45")


def _limits(tmp_path, names, **env):
    """게이트웨이를 **실제로 import** 해(설정은 임시 파일) 손잡이가 닿는지 본다 — 상수를 monkeypatch 하는 시험은 env 를 읽는
    줄이 사라져도 통과한다. 돌려주는 것 — {이름: 값} · 기동 로그. 같은 env 는 한 번만 띄운다(`_line` 은 기동 로그의 시간 한도 줄)."""
    key = tuple(sorted(env.items()))
    if key not in _LIMITS_SEEN:
        (tmp_path / "cfg.json").write_text(json.dumps({"_gateway": {"token": "gw-test-token"}}), encoding="utf-8")
        full = {k: v for k, v in os.environ.items() if not k.startswith(("GATEWAY_", "REST_PROXY_"))}
        full.update(GATEWAY_CONFIG=str(tmp_path / "cfg.json"), GATEWAY_AUDIT=str(tmp_path / "audit.jsonl"),
                    PYTHONDONTWRITEBYTECODE="1", **env)
        run = subprocess.run([sys.executable, "-c", _LIMITS_PROBE], cwd=os.path.dirname(os.path.abspath(gw.__file__)),
                             env=full, capture_output=True, text=True, timeout=120)
        assert run.returncode == 0, run.stderr[-2000:]
        _LIMITS_SEEN[key] = (json.loads(run.stdout), run.stderr)
    got, log_ = _LIMITS_SEEN[key]
    return {n: got.get(n) for n in names}, log_


_CALL_LIMITS = ["CALL_TIMEOUT_S", "RECONNECT_TIMEOUT_S", "BACKEND_HTTP_TIMEOUT_S", "BACKEND_READ_TIMEOUT_S"]


def test_호출_한도의_기본값은_안쪽이_바깥보다_작다(tmp_path):
    """핸드셰이크·재연결 30 < 호출 600 < 전송 read 660. 게이트웨이는 `.env` 를 읽지 않고 포털 services.yaml 도 env 를 넘기지
    않는다 — **코드 기본값이 곧 운영값**이라 기본값을 건다."""
    got, _ = _limits(tmp_path, _CALL_LIMITS)
    assert got == {"CALL_TIMEOUT_S": 600, "RECONNECT_TIMEOUT_S": 30.0, "BACKEND_HTTP_TIMEOUT_S": 30.0,
                   "BACKEND_READ_TIMEOUT_S": 660.0}


def test_호출_한도를_올리면_전송_한도가_따라_오르고_뒤집힌_설정은_따르지_않는다(tmp_path):
    got, log_ = _limits(tmp_path, _CALL_LIMITS, **_KNOBS_SET)
    assert got == {"CALL_TIMEOUT_S": 900, "RECONNECT_TIMEOUT_S": 12.0, "BACKEND_HTTP_TIMEOUT_S": 7.0,
                   "BACKEND_READ_TIMEOUT_S": 960.0}, "전송 read 는 호출 한도 + 60 으로 유도된다"
    assert "GATEWAY_BACKEND_READ_TIMEOUT" not in log_, "유도된 값은 경고 없이 맞아야 한다(호출 한도만 올린 운영자에게 거짓 경고)"
    got, _ = _limits(tmp_path, _CALL_LIMITS, GATEWAY_BACKEND_READ_TIMEOUT="1200")
    assert got["BACKEND_READ_TIMEOUT_S"] == 1200.0
    # 전송 한도가 호출 한도보다 작으면 ping 을 안 보내는 백엔드에서 그것이 먼저 걸려 세션째 무너진다 — 조용히 따르지 않는다
    got, log_ = _limits(tmp_path, _CALL_LIMITS, GATEWAY_BACKEND_READ_TIMEOUT="300")
    assert got["BACKEND_READ_TIMEOUT_S"] == 660.0
    assert "GATEWAY_BACKEND_READ_TIMEOUT" in log_ and "GATEWAY_CALL_TIMEOUT" in log_, "왜 다른 값을 쓰는지 기동 로그가 말해야 한다"


def test_호출_한도와_재연결_한도에_0_이하를_적으면_따르지_않는다(tmp_path):
    """0 은 '끔' 이 아니다 — 기한 0 은 백엔드에 닿기도 전에 걸린다. 호출 한도가 0 이면 모든 도구 호출이 `0초 안에 답하지 않았다` 로,
    재연결 한도가 0 이면 단발 세션(사람별·등록 토큰·신원 전달)의 호출이 `0초 안에 세션을 열지 못했다` 로 곧바로 실패했다.
    엔진의 `MCP_CALL_TIMEOUT_S`·`DELIB_TIMEOUT_S` 는 0=없음이라 같은 뜻으로 적기 쉽다. 적지 않은 것과 **같아야** 한다 —
    유도되는 값까지(종전에는 전송 read 가 60, rest_call 이 운영자가 적지도 않은 손잡이 이름을 대며 0 이 됐다)."""
    names = _CALL_LIMITS + ["REST_CALL_TIMEOUT_S"]
    got, log_ = _limits(tmp_path, names, GATEWAY_CALL_TIMEOUT="0", GATEWAY_RECONNECT_TIMEOUT="-1")
    assert got == _limits(tmp_path, names)[0]
    for said in ("GATEWAY_CALL_TIMEOUT=0 ", "GATEWAY_RECONNECT_TIMEOUT=-1 "):
        assert said in log_, f"적은 값을 왜 안 따르는지 기동 로그가 말해야 한다({said.strip()})"


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
    돌려주는 것 — 결과 글 · 걸린 초 · 센 것(도구 호출 · 단발 세션 · 재연결 · 토큰 발급의 stale) · 감사 줄 전부.
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

    async def fake_pat(app_id, email, *, stale=None, notes=None):
        n["mints"].append(stale)
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
    assert n["mints"] == ([None] if path == "per-user" else []), "재발급하면 같은 사람의 다른 좌석이 쥔 토큰이 폐기된다"
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


def test_같은_패스_안에서_탐침과_재집계가_연달아_놓쳐도_한_번이다(monkeypatch):
    """재집계는 탐침 바로 뒤에 같은 세션으로 list_tools 를 또 보낸다. 그것까지 세면 20초 남짓 바빴던 백엔드가 한 패스 안에서
    '연속 2회' 가 되어 갈린다 — 횟수는 패스마다 한 번(재활 주기 간격)이어야 한다."""
    sess = _ProbeSess(["hang"])
    b = _probe_kit(monkeypatch, sess)
    monkeypatch.setattr(gw, "_REAGG", {"pending": True})            # 다른 앱이 바뀌어 이번 패스에 재집계가 돈다

    async def go():
        await gw._revive_once(object())
        return sess.probed
    probed = asyncio.run(asyncio.wait_for(go(), 5))
    assert probed == 2, "탐침과 재집계가 둘 다 돌았어야 이 시험이 뜻이 있다"
    assert b.session is sess and b.reconnects == 0 and gw._LIVENESS_MISS == {"signalforge": 1}
    assert gw._REAGG.get("pending") is True, "목록을 못 받았으니 다음 패스에 다시 받는다"


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
    assert _limits(tmp_path, ["LIVENESS_STRIKES"], **_KNOBS_SET)[0] == {"LIVENESS_STRIKES": 3}
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
    assert _limits(tmp_path, names, **_KNOBS_SET)[0] == {
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
    assert _limits(tmp_path, ["PORTAL_SAVE_TIMEOUT_S"], **_KNOBS_SET)[0] == {"PORTAL_SAVE_TIMEOUT_S": 300.0}


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
    assert _limits(tmp_path, names, **_KNOBS_SET)[0] == {"REST_CALL_TIMEOUT_S": 900.0, "CALL_TIMEOUT_S": 900}
    assert _limits(tmp_path, names, GATEWAY_REST_CALL_TIMEOUT="45")[0] == {"REST_CALL_TIMEOUT_S": 45.0, "CALL_TIMEOUT_S": 600}


# ── 호출자 토큰 검증 — 포털 키 조회가 게이트웨이를 세우지 않고, 만료는 만료라고 말한다(결정표 gateway-23) ──────────
# 키 조회(PyJWKClient)는 urllib 로 **동기**이고 기본 한도가 30초다. 요청 인증 안에서 이벤트 루프를 붙잡으므로, 포털이 매달리면
# 게이트웨이 전체(진행 중인 도구 호출과 호출자에게 보내는 15초 ping 까지)가 그만큼 멈춘다.
import threading  # noqa: E402
import time as _clock  # noqa: E402

import jwt as _jwt  # noqa: E402
import rest_proxy  # noqa: E402

_RSA = {}


def _rsa():
    """시험용 RS256 키 한 벌(한 번만 만든다) — 서명은 맞고 수명만 끝난 토큰을 **진짜로** 만들어야 만료 갈래가 실행된다."""
    if not _RSA:
        from cryptography.hazmat.primitives.asymmetric import rsa
        _RSA["priv"] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _RSA["pub"] = _RSA["priv"].public_key()
    return _RSA["priv"], _RSA["pub"]


def _pat(aud, *, exp_in=600, key=None, **claims):
    priv, _ = _rsa()
    body = {"sub": "S-1", "email": "u@corp.com", "jti": "j-1", "scope": "api", "aud": aud, "groups": [],
            "exp": int(_clock.time()) + exp_in, **claims}
    return _jwt.encode(body, key or priv, algorithm="RS256", headers={"kid": "k1"})


def _verifier(monkeypatch, key_lookup=None):
    """실제 `PortalPatVerifier` — 포털 키 조회만 대역이다(네트워크 없음)."""
    from types import SimpleNamespace as NS
    v = rest_proxy.PortalPatVerifier({"jwks_url": "http://portal.invalid/.well-known/jwks.json"})
    monkeypatch.setattr(v.jwks, "get_signing_key_from_jwt", key_lookup or (lambda token: NS(key=_rsa()[1])))
    return v


async def _ticks_while(coro):
    """`coro` 가 도는 동안 이벤트 루프가 10ms 마다 몇 번 돌았나 — 루프가 붙잡히면 0 에 가깝다."""
    n = {"ticks": 0}

    async def ticker():
        while True:
            await asyncio.sleep(0.01)
            n["ticks"] += 1
    task = asyncio.create_task(ticker())
    try:
        return await coro, n["ticks"]
    finally:
        task.cancel()


def test_포털_키_조회는_짧은_한도로_이벤트_루프_밖에서_한다(monkeypatch):
    where = []

    def slow_lookup(token):
        where.append(threading.current_thread() is threading.main_thread())
        _clock.sleep(0.4)                                   # 포털이 답이 늦다(동기 urllib)
        raise _jwt.PyJWKClientError("portal hung")
    v = _verifier(monkeypatch, slow_lookup)
    assert v.jwks.timeout == rest_proxy.JWKS_TIMEOUT_S, "PyJWKClient 기본 30초가 그대로다"
    got, ticks = asyncio.run(_ticks_while(v.verify("any.jwt.value", "mcp-gateway")))
    assert got is None and where == [False], "키 조회가 이벤트 루프 스레드에서 돌았다"
    assert ticks >= 10, f"조회 0.4초 동안 루프가 {ticks}번밖에 못 돌았다 — 진행 중인 호출과 ping 이 같이 멈춘다"


def test_REST_프록시의_키_조회도_이벤트_루프_밖에서_한다(monkeypatch):
    from starlette.requests import Request
    where = []
    p = rest_proxy.RestProxy({"s": {"base": "http://upstream.invalid"}},
                             {"audience_ok": ["s"], "jwks_url": "http://portal.invalid/.well-known/jwks.json"}, gw._audit)

    def slow_lookup(token):
        where.append(threading.current_thread() is threading.main_thread())
        _clock.sleep(0.4)
        raise _jwt.PyJWKClientError("portal hung")
    monkeypatch.setattr(p.jwks, "get_signing_key_from_jwt", slow_lookup)
    assert p.jwks.timeout == rest_proxy.JWKS_TIMEOUT_S
    req = Request({"type": "http", "method": "GET", "path": "/api/s/x", "query_string": b"", "client": ("198.51.100.9", 0),
                   "headers": [(b"authorization", b"Bearer any.jwt.value")], "path_params": {"site": "s", "path": "x"}})
    resp, ticks = asyncio.run(_ticks_while(p.handle(req)))
    assert resp.status_code == 401 and where == [False] and ticks >= 10


def test_만료된_토큰은_틀린_토큰과_다르게_답하고_감사에도_그렇게_남는다(monkeypatch):
    """수 시간짜리 심의에서 시작할 때 받은 챗 토큰이 도중에 끝나면 좌석 조회와 마지막 보고서 저장이 여기서 거절된다.
    틀린 토큰과 같은 `unauthorized` 면 엔진이 서비스 계정으로 넘기며 원인을 적을 수 없다."""
    monkeypatch.setattr(gw, "GW_TOKEN", "gw-secret")
    v = _verifier(monkeypatch)
    from cryptography.hazmat.primitives.asymmetric import rsa
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired, forged = _pat(gw.MCP_AUDIENCE, exp_in=-3600), _pat(gw.MCP_AUDIENCE, exp_in=-3600, key=other)

    async def app(scope, receive, send):
        raise AssertionError("인증 없이 앱까지 가면 안 된다")
    sent = []

    async def send(m):
        sent.append(m)
    mw = gw._bearer_gate(app, v)
    for tok in (expired, forged):
        asyncio.run(mw({"type": "http", "method": "POST", "path": "/mcp", "client": ("198.51.100.9", 0),
                        "headers": [(b"authorization", b"Bearer " + tok.encode())]}, None, send))
    statuses = [m["status"] for m in sent if m["type"] == "http.response.start"]
    bodies = [json.loads(m["body"]) for m in sent if m["type"] == "http.response.body"]
    assert statuses == [401, 401]
    assert bodies[0] == {"error": "expired", "detail": "토큰 수명이 끝났다(포털 CHAT_PAT_TTL_S 또는 PAT 만료)"}
    raw = [m["body"] for m in sent if m["type"] == "http.response.body"][0].decode("utf-8")
    assert "토큰 수명이 끝났다" in raw, "curl·로그에서 읽히게 /api/ 와 같은 UTF-8 로 낸다(\\uXXXX 로 풀어 쓰지 않는다)"
    assert bodies[1] == {"error": "unauthorized"}, "서명이 틀린 토큰은 exp 가 지났어도 만료가 아니다(주장일 뿐이다)"
    assert [r["error"] for r in _rows()] == ["unauthorized: expired", "unauthorized: unverified-token"]
    assert all("caller" not in r for r in _rows())


def test_수명이_남은_토큰은_검증을_통과하고_폐기된_것은_아니다(monkeypatch):
    v = _verifier(monkeypatch)

    async def none_revoked():
        return set()

    async def revoked():
        return {"j-1"}
    monkeypatch.setattr(v, "_revoked_set", none_revoked)
    claims = asyncio.run(v.verify(_pat(gw.MCP_AUDIENCE), gw.MCP_AUDIENCE))
    assert claims["email"] == "u@corp.com" and claims["jti"] == "j-1"
    assert asyncio.run(v.verify(_pat("other-site"), gw.MCP_AUDIENCE)) is None, "청중이 다르면 만료가 아니라 그냥 거절이다"
    monkeypatch.setattr(v, "_revoked_set", revoked)
    assert asyncio.run(v.verify(_pat(gw.MCP_AUDIENCE), gw.MCP_AUDIENCE)) is None


def test_REST_프록시도_만료를_같은_말로_답한다(monkeypatch):
    from starlette.requests import Request
    from types import SimpleNamespace as NS
    p = rest_proxy.RestProxy({"s": {"base": "http://upstream.invalid"}},
                             {"audience_ok": ["s"], "jwks_url": "http://portal.invalid/.well-known/jwks.json"}, gw._audit)
    monkeypatch.setattr(p.jwks, "get_signing_key_from_jwt", lambda token: NS(key=_rsa()[1]))

    def call(tok):
        req = Request({"type": "http", "method": "GET", "path": "/api/s/x", "query_string": b"",
                       "client": ("198.51.100.9", 0), "headers": [(b"authorization", b"Bearer " + tok.encode())],
                       "path_params": {"site": "s", "path": "x"}})
        resp = asyncio.run(p.handle(req))
        return resp.status_code, json.loads(resp.body)
    assert call(_pat("s", exp_in=-3600)) == (401, rest_proxy.EXPIRED_BODY)
    code, body = call(_pat("other"))
    assert code == 401 and body["error"] == "invalid PAT"
    assert [r["error"][:12] for r in _rows()] == ["pat: expired", "pat: Invalid"]


def test_키_조회_한도의_기본값과_손잡이(tmp_path):
    assert _limits(tmp_path, ["JWKS_TIMEOUT_S"])[0] == {"JWKS_TIMEOUT_S": 5.0}
    assert _limits(tmp_path, ["JWKS_TIMEOUT_S"], **_KNOBS_SET)[0] == {"JWKS_TIMEOUT_S": 2.0}


# ── verify_answer — 낡아서 버린 조회 기록을 '조회한 적 없다' 로 말하지 않는다(결정표 gateway-19, 값은 그대로) ─────────
def test_조회_기록이_만료됐으면_없다고_하지_않고_만료라고_손잡이와_함께_말한다(monkeypatch):
    monkeypatch.setattr(gw, "_EVID", gw.OrderedDict())
    monkeypatch.setattr(gw, "_request_user", lambda: "a@b.com")
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    clk = _Clock()
    monkeypatch.setattr(gw, "time", clk)
    gw._evid_keep("compute_x", types.CallToolResult(content=[types.TextContent(type="text", text='{"stress": 48039.32}')]))

    def note():
        body = json.loads(asyncio.run(gw._verify_answer({"text": "응력 48039.32 MPa"})).content[0].text)
        return body["note"], body["unsourced"], body["tool_calls"]
    assert note() == ("모든 수치가 조회 결과에 있다.", [], ["compute_x"])
    clk.now += gw.EVID_TTL_S + 1                            # 30분 넘게 아무 도구도 안 불렀다(긴 심의를 기다렸다)
    said, unsourced, calls = note()
    assert unsourced == ["48039.32"] and calls == [], "낡은 기록으로 초록을 주면 안 된다(값은 그대로다)"
    assert "만료" in said and "EVID_TTL_S" in said and str(gw.EVID_TTL_S) in said and "도구를 다시" in said
    assert "조회 기록이 없다" not in said, "조회를 안 한 것으로 읽힌다"


# ── 사람별 위임 토큰의 수명은 호출 한도보다 길어야 한다(결정표의 계약 — gateway-12 는 값을 그대로 둔다) ──────────────
@pytest.mark.parametrize("expires_in,warned", [(900, False), (601, False), (600, True), (300, True)])
def test_위임_토큰의_수명이_호출_한도보다_길지_않으면_발급_때_말한다(monkeypatch, caplog, expires_in, warned):
    """캐시 여유(2분)를 호출 한도만큼 늘리지 않기로 했다 — 수명 짧은 발급자에서 호출마다 재발급·폐기가 일어난다. 그 대신
    발급자의 수명이 호출 한도보다 길어야 하는데, 그 값은 남의 리포에 있어 어긋나도 아무도 모른다. 실제로 받은 값으로 말한다.
    hwax_risk 의 900초는 맞는 값이다 — 거짓 경고를 내면 안 된다."""
    monkeypatch.setattr(gw, "CALL_TIMEOUT_S", 600)
    n, clk = _mint_kit(monkeypatch, lambda i: {"access_token": f"secret-tok-{i}", "expires_in": expires_in})
    with caplog.at_level(logging.WARNING, logger="hwax-mcp-gateway"):
        asyncio.run(_pat_at(clk, 0))
    said = [r.getMessage() for r in caplog.records if "GATEWAY_CALL_TIMEOUT" in r.getMessage()]
    assert len(said) == (1 if warned else 0), said
    if warned:
        assert "reportarchive" in said[0] and str(expires_in) in said[0] and "600" in said[0]
    assert "secret-tok" not in caplog.text, "토큰은 찍지 않는다"


def test_리스크_앱의_위임_토큰_수명이_게이트웨이_호출_한도보다_길다():
    """두 리포에 걸친 계약이다 — 한쪽만 바꾸면 리스크 앱의 긴 도구가 도는 중에 자격이 끝난다. 소스의 기본값끼리 본다
    (배포값은 발급 때의 경고가 본다)."""
    import re
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(gw.__file__))), "HWAXRisk", "backend", "app", "config.py")
    if not os.path.exists(path):
        pytest.skip("HWAXRisk 리포가 옆에 없다")
    m = re.search(r'"HWAXRISK_SSO_TTL_S",\s*"(\d+)"', open(path, encoding="utf-8").read())
    assert m, "HWAXRisk 에서 HWAXRISK_SSO_TTL_S 기본값을 못 읽었다 — 이름이 바뀌었나"
    src = open(gw.__file__, encoding="utf-8").read()
    call = int(re.findall(r"\d+", re.search(r"^CALL_TIMEOUT_S\s*=.*$", src, re.M).group(0))[-1])
    assert int(m.group(1)) > call, f"위임 토큰 {m.group(1)}초가 호출 한도 {call}초보다 길지 않다"


# ── 호출자들이 기대는 전제 — 게이트웨이는 응답 스트림에 15초마다 ping 을 싣는다(결정표의 계약) ─────────────────────
def test_응답_스트림의_15초_ping_전제가_그대로다():
    """sse-starlette 의 기본값이고 MCP SDK 는 간격을 따로 주지 않는다. 호출자들의 한도가 이 수에 기대어 있다 — httpx 침묵
    한도가 15초보다 크면 죽은 게이트웨이만 잡고(포털 `upload.mcp_call` 의 timeout·절차 실행기 `CLIENT_TIMEOUT`, 리스크 앱
    `HWAXRISK_SOURCE_CALL_TIMEOUT_S`·`ra_client.DEFAULT_TIMEOUT` — 값은 각 리포가 정본이라 여기 적지 않는다) 15초보다 작으면
    그것이 실제 호출 상한이며(리스크 앱의 필드 근거 조회 `field_source.FIELD_TIMEOUT_S`), nginx `/mcp-gw/` 의 침묵 1시간과
    수 시간짜리 `deliberate_status` 폴링 세션도 이 ping 덕에 끊기지 않는다. 라이브러리를 올려 간격이 바뀌거나 꺼지면 그
    값들의 뜻이 조용히 바뀐다 — 여기서 걸리면 저쪽 한도를 같이 본다."""
    import inspect
    import re

    import mcp.server.streamable_http as sh
    from sse_starlette.sse import EventSourceResponse
    assert EventSourceResponse.DEFAULT_PING_INTERVAL == 15
    made = re.findall(r"EventSourceResponse\((.*?)\)", inspect.getsource(sh), re.S)
    assert made and not any("ping" in args for args in made), "MCP SDK 가 ping 을 따로 준다 — 실제 간격을 확인하라"


# ── 기동 로그 — 손잡이가 닿았는지 볼 자리 ─────────────────────────────────────────────────────────────
def test_기동_로그의_시간_한도_줄은_이_프로세스에_실제로_걸린_값을_말한다(tmp_path):
    """게이트웨이는 `.env` 를 읽지 않는다 — 적었는데 닿지 않은 손잡이와 재기동 뒤의 옛 코드를 볼 자리가 이 줄뿐이다.
    손잡이 이름을 그대로 적어 로그에서 찾을 수 있게 하고, 바꿔 준 값이 그대로 나오는지 본다."""
    said = _limits(tmp_path, ["_line"])[0]["_line"]
    for want in ("GATEWAY_CALL_TIMEOUT=600 ", "GATEWAY_RECONNECT_TIMEOUT=30 ", "GATEWAY_BACKEND_READ_TIMEOUT=660 ",
                 "GATEWAY_BACKEND_HTTP_TIMEOUT=30 ", "GATEWAY_LIVENESS_TIMEOUT=10 × GATEWAY_LIVENESS_STRIKES=2(주기 60)",
                 "GATEWAY_AGG_STALE_ROUNDS=10 ", "GATEWAY_HEAX_MISS_DROP=10 ", "GATEWAY_REST_CALL_TIMEOUT=600 ",
                 "REST_PROXY_UPSTREAM_TIMEOUT_S=110 ", "GATEWAY_PORTAL_SAVE_TIMEOUT=120 ", "GATEWAY_JWKS_TIMEOUT=5"):
        assert want in said, f"{want!r} 가 없다: {said}"
    said = _limits(tmp_path, ["_line"], **_KNOBS_SET)[0]["_line"]
    for want in ("GATEWAY_CALL_TIMEOUT=900 ", "GATEWAY_RECONNECT_TIMEOUT=12 ", "GATEWAY_BACKEND_READ_TIMEOUT=960 ",
                 "GATEWAY_BACKEND_HTTP_TIMEOUT=7 ", "GATEWAY_LIVENESS_STRIKES=3(", "GATEWAY_AGG_STALE_ROUNDS=4 ",
                 "GATEWAY_HEAX_MISS_DROP=6 ", "GATEWAY_REST_CALL_TIMEOUT=900 ", "REST_PROXY_UPSTREAM_TIMEOUT_S=45 ",
                 "GATEWAY_PORTAL_SAVE_TIMEOUT=300 "):
        assert want in said, f"{want!r} 가 없다: {said}"
    assert said.endswith("GATEWAY_JWKS_TIMEOUT=2")


def test_기동할_때_그_줄을_남긴다():
    src = open(gw.__file__, encoding="utf-8").read()
    main = src[src.index("\ndef main():"):]
    assert 'log.info("%s", _limits_line())' in main[:main.index("_GracefulServer(uvicorn.Config(")], "main() 이 기동 전에 시간 한도 줄을 남겨야 한다"


# ── 1백만 토큰 창 — 게이트웨이는 도구 결과를 자르지 않고, 남는 절단은 조용하지 않다(리스크 심사 재설계 M1) ─────────
# 운영 모델은 GLM-5.2·창 1,048,576 토큰이다. 실사용 팀은 Claude 에서 이 게이트웨이를 거쳐 도구를 부르고 그 결과로 심의한다 —
# 여기서 잘리면 잘린 근거로 심의한다. 작은 창이 필요한 소비자(에이전트 서버의 웹 챗)는 자기 쪽에서 자른다(TOOL_RESULT_MAX).
def _result_kit(monkeypatch, text: str):
    """백엔드 하나에 결과가 `text` 인 읽기 도구를 세운다 — 상주 세션 길(신원 없음)."""
    b = _CallB(["get_big"])

    async def _ct(original, args, read_timeout_seconds=None):
        b.session.calls.append(original)
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)])
    b.session.call_tool = _ct
    monkeypatch.setattr(gw, "backends", {"sf": b})
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "route", {})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    monkeypatch.setattr(gw, "_request_user", lambda: "")
    gw._RESP_CACHE.clear()
    asyncio.run(gw._aggregate())
    return b


def _audit_rows():
    return [json.loads(ln) for ln in open(gw.AUDIT_PATH, encoding="utf-8")]


def test_백엔드_도구_결과는_직접_불러도_invoke_tool_로_불러도_캐시에서_와도_한_글자도_안_잘린다(monkeypatch):
    big = '{"rows": "' + "가1" * 400_000 + '"}'           # 80만 자 — 옛 상한 어느 것보다 크다
    b = _result_kit(monkeypatch, big)
    # 1.6MB(UTF-8)라 캐시 한 칸 상한(1MiB)을 넘는다 — 이 시험은 캐시 길의 무절단을 보므로 그 상한만 올린다.
    monkeypatch.setattr(gw, "CACHE_ITEM_MAX_BYTES", 4 * 1024 * 1024)
    direct = asyncio.run(gw._call_tool("get_big", {}))
    assert direct.content[0].text == big
    via = asyncio.run(gw._call_tool("invoke_tool", {"name": "get_big", "arguments": {}}))
    assert via.content[0].text == big
    assert b.session.calls == ["get_big"], "두 번째는 캐시 적중이어야 한다(캐시 길도 같이 본다)"


def test_감사_원장에_도구_결과의_크기가_남는다(monkeypatch):
    """도구 결과가 몇 자였는지를 사후에 원장으로 알 길이 없었다 — '남는 절단은 원장에 남긴다' 의 자리가 비어 있었다."""
    text = "x" * 12_345
    _result_kit(monkeypatch, text)
    asyncio.run(gw._call_tool("get_big", {}))
    asyncio.run(gw._call_tool("get_big", {}))              # 캐시 적중
    rows = [r for r in _audit_rows() if r["tool"] == "get_big"]
    assert [r.get("note") for r in rows] == [None, "cache-hit"]
    assert [r.get("chars") for r in rows] == [12_345, 12_345]


def test_감사_원장에_잘린_글은_원문_길이를_단다(tmp_path, monkeypatch):
    """감사 줄의 크기는 둘 수 있다(무기한 보존·한 호출 한 줄). 다만 잘린 오류가 온전한 오류처럼 보이면 안 된다."""
    f = tmp_path / "a.jsonl"
    monkeypatch.setattr(gw, "AUDIT_PATH", str(f))
    gw._audit("t", "b", False, "E" * 5000, 1, note="n" * 500, corr="c" * 500)
    gw._audit("t", "b", False, "짧은 실패", 1, note="cache-hit", corr="conv-9")
    long_, short = [json.loads(x) for x in f.read_text(encoding="utf-8").splitlines()]
    assert long_["error"].startswith("E" * 200) and "5000" in long_["error"] and len(long_["error"]) < 260
    assert long_["note"].startswith("n" * 120) and "500" in long_["note"]
    assert long_["corr"].startswith("c" * 120) and "500" in long_["corr"]
    assert (short["error"], short["note"], short["corr"]) == ("짧은 실패", "cache-hit", "conv-9"), "짧은 글은 그대로다"


# ── 오류 봉투는 isError 가 아니어도 감사에 ok=false(HWAXPortal docs/request-1027 HG-06) ─────────────────────────────
# 점검기 · 사용 통계가 감사 원장의 ok 로 실패를 센다. 호출부가 `ok=not isError` 만 적어서 200 + {"error": …} 가 성공으로 세였다.
_ENVELOPE_CASES = [
    ('{"error": {"code": "APP-GRAPH-0001", "message": "노드가 없다"}}', "envelope: APP-GRAPH-0001 노드가 없다"),
    ('{"error": "numpy 없음"}', "envelope: numpy 없음"),
    ('{"ok": false, "message": "x"}', "envelope: ok=false"),
    ('{"refused": true}', "envelope: refused"),
    ('{"status": "error", "errors": [{"message": "판 두께가 0"}]}', "envelope: 판 두께가 0"),
    ('{"exit_code": 2}', "envelope: exit_code=2"),
    ('{"valid": true, "error": "백엔드 불통"}', "envelope: 백엔드 불통"),      # 단수 error 는 판정 꼴이어도 오류 채널이다
    ('{"valid": false, "errors": [{"message": "형이 틀렸다"}]}', None),     # 검사기의 산출물이지 고장이 아니다
    ('{"ok": true, "errors": ["경고 하나"]}', None),
    ('{"error": null, "rows": [1]}', None),
    ('{"rows": []}', None),
    ("결과가 없습니다", None),                                               # 평문은 봉투가 아니다
    ('{"exit_code": 0, "out": "done"}', None),
]


@pytest.mark.parametrize("body, want", _ENVELOPE_CASES)
def test_HG06_오류_봉투는_isError_가_아니어도_감사에_ok_false_와_사유로_남는다(monkeypatch, body, want):
    _result_kit(monkeypatch, body)
    res = asyncio.run(gw._call_tool("get_big", {}))
    assert res.content[0].text == body and not res.isError, "호출자가 받는 응답은 그대로다 — 감사만 고친다"
    row = [r for r in _audit_rows() if r["tool"] == "get_big"][-1]
    assert (row["ok"], row.get("error")) == (want is None, want), row


def test_HG06_isError_와_예외는_종전대로고_구조화_본문만_있어도_본다(tmp_path, monkeypatch):
    f = tmp_path / "a.jsonl"
    monkeypatch.setattr(gw, "AUDIT_PATH", str(f))
    gw._audit("t", "b", False, None, 1, res=types.CallToolResult(
        content=[types.TextContent(type="text", text="boom")], isError=True))
    gw._audit("t", "b", False, "per-user: X", 1)
    gw._audit("t", "b", True, None, 1, res=types.CallToolResult(content=[], structuredContent={"error": "구조화만"}))
    gw._audit("t", "b", True, None, 1, res=types.CallToolResult(
        content=[types.TextContent(type="text", text='{"error": "' + "x" * (gw._ENVELOPE_SCAN_MAX + 1) + '"}')]))
    rows = [json.loads(x) for x in f.read_text(encoding="utf-8").splitlines()]
    assert [(r["ok"], r.get("error")) for r in rows] == [
        (False, None), (False, "per-user: X"), (False, "envelope: 구조화만"), (True, None)], rows


def test_HG06_판정이_포털_판정기와_같다():
    """판정기마다 답이 달랐던 사고(포털 W-77)를 되풀이하지 않는다 — 형제 리포의 포털 판정기를 오라클로 견준다."""
    import importlib.util
    from pathlib import Path
    p = Path(__file__).resolve().parent.parent / "HWAXPortal/backend/app/procedures/judge.py"
    if not p.is_file():
        pytest.skip("형제 리포 HWAXPortal 이 없다")
    spec = importlib.util.spec_from_file_location("_portal_judge", p)
    judge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(judge)
    extra = ['{"status": "FAILED"}', '{"status": "warning", "errors": ["w"]}', '{"errors": []}', '{"errors": 12}',
             '{"exit_code": true}', '{"error": ""}', '{"error": {}}', '{"refused": "yes"}', '[{"error": "x"}]']
    for body in [b for b, _ in _ENVELOPE_CASES] + extra:
        try:
            parsed = json.loads(body)
        except ValueError:
            continue
        res = types.CallToolResult(content=[types.TextContent(type="text", text=body)])
        assert (gw._envelope_reason(res) is not None) == (judge._envelope_fail(parsed) is not None), body


def _fastmcp_tool(fn) -> types.Tool:
    """백엔드(FastMCP)가 함수에서 도구를 만드는 **실제 경로**로 만든다 — 인자 스키마를 손으로 쓰지 않는다."""
    from mcp.server.fastmcp.tools.base import Tool as _FTool
    ft = _FTool.from_function(fn)
    return types.Tool(name=ft.name, description=ft.description, inputSchema=ft.parameters)


def _deliberate_start_like():
    def deliberate_start(question: str, job: str = "default", rounds: int = 0, modifiers: list[str] | None = None,
                         evidence: list[dict] | None = None, personas: list[dict] | None = None,
                         tools: list[str] | None = None, apps: list[str] | None = None, human_note: str = "",
                         search_sources: list[str] | None = None, options: list[str] | None = None,
                         stop_after_round: int = 0, save_report: bool = True, advanced: dict | None = None) -> dict:
        """심의를 연다. 즉시 job_id 를 돌려주고 심의는 뒤에서 계속 돈다 — 결과는 deliberate_status 로 받는다.

        Args:
            question: 심의할 화두. 구체적일수록 좌석 발굴이 정확하다.
            job: 심의 종류 — diagnosis(원인 규명) · option-select(안 선택) · credibility(신뢰 판정) ·
                 risk-review(리스크 심사) · mechanism(메커니즘 규명) · sim-plan(해석 설계 2단) · default(자유 심의).
            modifiers: 얹을 층 — voi · premortem · toulmin · eliminative · anon1r.
            save_report: 끝나면 보고서를 저장한다.
        """
        return {}
    return _fastmcp_tool(deliberate_start)


def test_search_tools_는_도구_설명과_인자_스키마를_자르지_않는다(monkeypatch):
    """invoke_tool 로 부르기 전에 모델이 보는 계약이 이것뿐이다. 설명 220자·인자 12개·type 만 남기던 때는
    deliberate_start 의 `job` 값 목록(설명 뒤쪽)이 잘리고 13·14번째 인자(save_report·advanced)가 사라졌으며,
    `anyOf` 인자(modifiers 등)는 type 이 없어 `any` 로 보였다 — 모델이 스키마를 추측해 넣는 바로 그 실패 모드다."""
    t = _deliberate_start_like()
    assert len(t.description) > 220 and len(t.inputSchema["properties"]) == 14     # 전제 — 옛 상한을 넘는 도구다
    monkeypatch.setattr(gw, "exposed_tools", [t])
    monkeypatch.setattr(gw, "route", {t.name: ("hwax-deliberation", t.name)})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    monkeypatch.setattr(gw, "_request_muted", lambda: set())
    out = json.loads(asyncio.run(gw._search_tools({"query": "deliberate 심의", "detail": True})).content[0].text)
    hit = next(m for m in out["matches"] if m["tool"] == "deliberate_start")
    assert hit["description"] == t.description.strip()
    assert "default(자유 심의)" in hit["description"]
    assert hit["args"]["required"] == ["question"]
    assert hit["args"]["properties"] == t.inputSchema["properties"], "인자 스키마는 생산자가 준 그대로여야 한다"
    assert hit["args"]["properties"]["modifiers"]["anyOf"][0]["type"] == "array"
    assert "advanced" in hit["args"]["properties"] and "save_report" in hit["args"]["properties"]
    # 기본은 한 줄 요약과 필수 인자의 스키마 · 선택 인자의 이름이다(HWAXPortal docs/request-1027 HG-12) — 선택 인자를 지우지는 않는다
    brief = json.loads(asyncio.run(gw._search_tools({"query": "deliberate 심의"})).content[0].text)
    b = next(m for m in brief["matches"] if m["tool"] == "deliberate_start")
    assert "\n" not in b["description"] and t.description.strip().startswith(b["description"].rstrip(" …"))
    assert b["args"]["required"] == ["question"] and list(b["args"]["properties"]) == ["question"]
    assert b["args"]["properties"]["question"] == t.inputSchema["properties"]["question"]
    assert set(b["args"]["optional"]) == set(t.inputSchema["properties"]) - {"question"}, "선택 인자 이름은 남는다"
    assert "detail=true" in brief["note"]


def test_search_tools_의_인자_계약은_참조하는_정의까지_싣는다(monkeypatch):
    """모델 인자를 받는 도구는 FastMCP 가 정의를 `$defs` 에 두고 속성은 `$ref` 로 가리킨다 — properties 만 실으면 참조가 끊긴다."""
    from pydantic import BaseModel

    class Seat(BaseModel):
        key: str
        stance: str = "neutral"

    def seat_panel(seats: list[Seat], note: str = "") -> dict:
        """좌석을 앉힌다."""
        return {}
    t = _fastmcp_tool(seat_panel)
    assert "$defs" in t.inputSchema                                              # 전제 — 생산자가 정의를 따로 둔다
    monkeypatch.setattr(gw, "exposed_tools", [t])
    monkeypatch.setattr(gw, "route", {t.name: ("sf", t.name)})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    monkeypatch.setattr(gw, "_request_muted", lambda: set())
    out = json.loads(asyncio.run(gw._search_tools({"query": "seat_panel"})).content[0].text)
    args = next(m for m in out["matches"] if m["tool"] == "seat_panel")["args"]
    assert args["$defs"] == t.inputSchema["$defs"] and "Seat" in args["$defs"]


def test_list_tool_apps_는_앱_상세와_영역_상세의_도구_설명을_자르지_않는다(monkeypatch, tmp_path):
    """search_tools 와 같은 계약 자리다 — 이 허브는 도구 설명에 함정·인자 규칙을 길게 적는다(deliberate_start). 300자에서
    자르면 tools/list 원문에는 있는 것이 이 길로만 사라진다."""
    t = _deliberate_start_like()
    assert len(t.description) > 300                                             # 전제 — 옛 상한을 넘는다
    f = tmp_path / "tool_areas.json"
    f.write_text(json.dumps({"areas": [{"key": "expert", "label": "전문가"}],
                             "apps": {"hwax-deliberation": "expert"}, "patterns": [], "tools": {}}), encoding="utf-8")
    monkeypatch.setattr(gw, "_AREAS_PATH", f)
    monkeypatch.setattr(gw, "_AREAS_CACHE", {"mtime": None, "data": {}})

    class _S:
        session = object()
    monkeypatch.setattr(gw, "backends", {"hwax-deliberation": _S()})
    monkeypatch.setattr(gw, "exposed_tools", [t])
    monkeypatch.setattr(gw, "route", {t.name: ("hwax-deliberation", t.name)})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    monkeypatch.setattr(gw, "_request_muted", lambda: set())
    app = json.loads(asyncio.run(gw._list_tool_apps({"app": "hwax-deliberation"})).content[0].text)
    assert app["apps"][0]["tools"] == [{"name": t.name, "description": t.description}]
    area = json.loads(asyncio.run(gw._list_tool_apps({"by": "area", "area": "expert"})).content[0].text)
    assert area["areas"][0]["tools"] == [{"name": t.name, "app": "hwax-deliberation", "description": t.description}]


def test_레지스트리가_준_앱_설명을_자르지_않는다(monkeypatch):
    """앱 설명은 list_tool_apps 로 모델이 읽고 search_tools 의 앱 가산점 낱말이기도 하다 — 300자 뒤의 업무 낱말이 사라졌다."""
    desc = "열충격 해석 앱 — " + "사이클·크랙·솔더·피로 " * 60
    assert len(desc) > 300
    monkeypatch.setattr(gw, "_bypass_proxy_for", lambda urls: [])
    monkeypatch.setattr(gw, "HEAX", {"servers_url": "http://hub.test/servers", "base": "http://hub.test"})
    monkeypatch.setattr(gw.httpx, "AsyncClient", lambda **kw: _REAL_ASYNC_CLIENT(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, json={"servers": [{"id": "ts", "path": "/ts/mcp", "name": "열충격",
                                                          "description": desc}]})), **kw))
    found = asyncio.run(gw._discover_heax())
    assert found["heax-ts"]["description"] == desc.strip() and found["heax-ts"]["label"] == "열충격"


def test_use_experts_는_역할_문서를_자르지_않고_상한을_넘긴_것은_알린다(monkeypatch):
    """역할 문서는 Claude 가 그 전문가가 되려고 읽는 전부다 — 8,000자에서 자르면 뒤쪽 함정·작업 순서가 사라진다.
    5명·앱 3·입구 도구 12 는 포털 pinned_agents·에이전트 서버 페르소나와 같은 제품 규칙이라 둔다 — 다만 넘긴 것을 말한다.
    (get_agent_session 은 AIDataHub 의 도구다 — 응답 키 system_prompt·response_config 는 mcp_runtime.get_agent_session 의 것.)"""
    role = "역할 " + "함정·작업순서 " * 3000
    assert len(role) > 8000
    sess = {"system_prompt": role, "response_config": {
        "persona_kind": "mcp_operator", "mcp_apps": [f"app{i}" for i in range(5)],
        "key_tools": [f"tool{i}" for i in range(15)]}}

    async def fake_call(name, args):
        assert name == "get_agent_session"
        return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(sess, ensure_ascii=False))])
    monkeypatch.setattr(gw, "_call_tool", fake_call)
    monkeypatch.setattr(gw, "_request_muted", lambda: set())
    keys = [f"k{i}" for i in range(7)]
    out = json.loads(asyncio.run(gw._use_experts({"keys": keys})).content[0].text)
    e = out["experts"][0]
    assert e["role_doc"] == role
    assert [x["key"] for x in out["experts"]] == keys[:5]
    assert out["dropped_keys"] == ["k5", "k6"] and "5명" in out["dropped_note"]
    assert len(e["apps"]) == 3 and e["apps_omitted"] == ["app3", "app4"]
    assert len(e["entry_tools"]) == 12 and e["entry_tools_omitted"] == ["tool12", "tool13", "tool14"]
    few = json.loads(asyncio.run(gw._use_experts({"keys": ["k0"]})).content[0].text)
    assert "dropped_keys" not in few, "넘지 않았으면 칸을 만들지 않는다"


def test_browse_experts_가_limit_로_자르면_잘랐다고_말한다(monkeypatch):
    rows = [{"agent_type": f"cam-p{i:02d}", "name": f"카메라 {i}"} for i in range(50)]

    async def fake_call(name, args):
        return types.CallToolResult(content=[types.TextContent(
            type="text", text=json.dumps({"result": rows}, ensure_ascii=False))])
    monkeypatch.setattr(gw, "_call_tool", fake_call)
    monkeypatch.setattr(gw, "_ORG_TAX", {})
    monkeypatch.setattr(gw, "_portal_api_base", lambda: "")
    hit = json.loads(asyncio.run(gw._browse_experts({"q": "카메라"})).content[0].text)
    assert hit["found"] == 50 and len(hit["experts"]) == 40 and "50" in hit["truncated"] and "limit" in hit["truncated"]
    dom = json.loads(asyncio.run(gw._browse_experts({"domain": "cam"})).content[0].text)
    assert dom["count"] == 50 and len(dom["experts"]) == 40 and "50" in dom["truncated"]
    whole = json.loads(asyncio.run(gw._browse_experts({"domain": "cam", "limit": 50})).content[0].text)
    assert len(whole["experts"]) == 50 and "truncated" not in whole


def _evid_ctx(monkeypatch):
    monkeypatch.setattr(gw, "_EVID", gw.OrderedDict())
    monkeypatch.setattr(gw, "_request_user", lambda: "a@b.com")
    monkeypatch.setattr(gw, "_request_groups", lambda: [])


def _keep(tool, text):
    gw._evid_keep(tool, types.CallToolResult(content=[types.TextContent(type="text", text=text)]))


def _verify(text):
    return json.loads(asyncio.run(gw._verify_answer({"text": text})).content[0].text)


def test_verify_answer_는_큰_도구_출력의_뒤쪽_수치도_조회한_값으로_본다(monkeypatch):
    """근거 원장이 호출당 50,000자에서 잘라, 큰 결과(카드 묶음·곡선·rest_call JSON)의 뒤쪽 수치를 '지어낸 값' 으로 고발했다 —
    거짓 경고는 사람이 도구를 못 믿게 만든다. 운영 창이 1,048,576 토큰이라 모델은 그 뒤쪽까지 읽는다."""
    _evid_ctx(monkeypatch)
    _keep("get_curve", '{"pts": "' + "가나다라 " * 60_000 + '", "peak": 48039.32}')   # 30만 자 뒤의 값
    body = _verify("최대값은 48039.32 MPa")
    assert body["unsourced"] == [] and body["checked"] == 1


def test_verify_answer_는_스무_번째보다_앞선_조회도_기억한다(monkeypatch):
    _evid_ctx(monkeypatch)
    for i in range(30):
        _keep(f"t{i}", '{"v": %d.5}' % (1000 + i))
    body = _verify("첫 값 1000.5, 끝 값 1029.5")
    assert body["unsourced"] == [] and len(body["tool_calls"]) == 30


def test_verify_answer_는_못_찾은_수치를_전부_말한다(monkeypatch):
    _evid_ctx(monkeypatch)
    _keep("t", '{"v": 1}')
    nums = [f"{100 + i}.5" for i in range(20)]
    body = _verify(", ".join(nums))
    assert body["unsourced"] == nums, "13번째부터 '없다' 는 말도 없이 빠졌다"


def test_verify_answer_의_판정표(monkeypatch):
    """원장은 숫자 줄기만 남기고, 판정은 '답의 수치가 원장의 어느 수치 하나와 같은가' 다 — 그 수 전체이거나, 정수부이거나(답에
    소수점이 없을 때), 소수 자리를 덜 적은 꼴(답에 소수점이 있을 때). 다른 수의 한가운데에 걸린 것은 근거가 아니다(gw-adh GA-6).
    쉼표는 두 가지로 읽는다 — 천 단위('1,250.5' → 1250.5)와 목록 구분('[100,200,300]' → 100·200·300)."""
    _evid_ctx(monkeypatch)
    srcs = ['{"a": "1,250.5원", "b": "v1.2.3", "c": "12.5.6", "d": "x408명", "e": "0.25%", "f": "2026-10-10"}',
            '배열 [100,200,300] · 좌표 (35.123, 129.04) · ID ABC12345XYZ · 1.0e5',
            # 산문의 문장 끝 마침표 — 줄기가 '0.85.' 가 되어 그 '.' 를 다른 수의 소수점으로 읽었다(RR2-GW-2)
            'thickness was 0.85. 인장강도는 450.5. 그 뒤 Fig. 3.2. shows 12.75. 합계 7,310.']
    for i, s in enumerate(srcs):
        _keep(f"t{i}", s)
    want = {"1250.5": True, "1,250.5": True, "250.5": True,       # 250.5 — '1,250.5' 를 목록으로 읽은 꼴(쉼표의 두 읽기)
            "12.5": False,                                         # '12.5.6' 은 수가 아니다(판 번호 꼴)
            "408": True, "4080": False, "0.25": True, "2026": True, "1010": False,
            "100200300": True, "200300": False, "200": True, "100,200": False,
            "35.123": True, "35.1": True, "35": None, "129.04": True, "129.040": False, "129": True,
            "12345": True, "123456": False, "2345": False, "1.0": True,
            # 소수 뒤 문장 마침표는 근거다(같은 수·소수 덜 적은 꼴·정수부 모두). 판 번호 꼴('12.5.6')의 앞 마디는 여전히 아니다.
            "0.85": True, "0.8": True, "450.5": True, "450": True, "3.2": True, "12.75": True, "12.7": True,
            "7,310": True, "7310": True, "0.855": False, "450.55": False}
    for a, sourced in want.items():
        m = gw._NUM_TOK_RE.search(a)
        norm = m.group(0).replace(",", "")
        if "." not in norm and float(norm) < 100:
            assert sourced is None, a                              # 작은 정수는 보지 않는다
            continue
        got = m.group(0) not in _verify(a)["unsourced"]
        assert got is sourced, (a, sourced, got)


def test_verify_answer_는_다른_수치의_한가운데에_걸린_것을_근거로_치지_않는다(monkeypatch):
    """부분문자열 대조는 원장이 클수록 아무 수나 통과시킨다 — 곡선 조회가 쌓인 세션에서 원장은 숫자 덩어리라, 지어낸 '232' 가
    '1232' 에, '125' 가 '0.125' 에 걸려 '모든 수치가 조회 결과에 있다' 로 초록을 받았다. 원장을 1백만 자로 키운 뒤(9a2b3d5)
    지어낸 수의 통과율이 크게 늘었다(GA-6)."""
    _evid_ctx(monkeypatch)
    _keep("t", '{"a": 1232, "b": 0.125, "c": 1250.47, "d": 98765, "e": [1.5,2.5]}')
    body = _verify("232 · 125 · 250.47 · 876 · 50.4 · 1232 · 98765 · 1250 · 1250.4 · 1250.47 · 2.5 · 1.5")
    assert body["unsourced"] == ["232", "125", "250.47", "876", "50.4"], body["unsourced"]


def test_verify_answer_의_우연_일치는_원장이_커져도_늘지_않는다(monkeypatch):
    """곡선(변형률 6자리 소수·응력 0~600)을 1번·12번 조회한 세션에서, 데이터에 없는 값(응력 범위 밖 정수·소수)을 지어내 묻는다.
    그 숫자들은 변형률 '0.123456' 같은 수의 한가운데에는 흔히 있다 — 옛 부분문자열 대조는 원장이 클수록 그것을 근거로 쳤다
    (같은 자료에서 3자리 정수 0.8 → 0.97). 새 판정은 몇 번을 조회했든 하나도 통과시키지 않고, 진짜 값(같은 수·정수부·소수 덜 적은
    꼴)은 늘 통과시킨다."""
    import random
    _evid_ctx(monkeypatch)
    rnd = random.Random(7)

    def curve(seed):
        r = random.Random(seed)
        return json.dumps({"points": [{"strain": round(i * 0.0004 + r.random() * 1e-5, 6),
                                       "stress": round(600 * (1 - 2.718281828 ** (-i / 400)) + r.gauss(0, 2), 3)}
                                      for i in range(1500)]}, indent=2)
    fab = ([str(rnd.randint(620, 999)) for _ in range(150)] + [str(rnd.randint(1000, 9999)) for _ in range(150)]
           + [f"{rnd.uniform(700, 999):.1f}" for _ in range(150)])

    def passed():
        bad = set(_verify(" , ".join(fab))["unsourced"])
        return [n for n in fab if n not in bad]
    _keep("get_curve", curve(0))
    assert passed() == []
    for sd in range(1, 12):
        _keep("get_curve", curve(sd))
    assert passed() == [], "원장이 12배가 되자 지어낸 수가 다른 수의 한가운데에 걸려 통과했다"
    old_src = " ".join(curve(sd).replace(",", "") for sd in range(12))
    assert sum(n in old_src for n in fab[:150]) / 150 > 0.9, "옛 부분문자열 대조로는 대부분 통과한다 — 시험이 이빨이 있는지"
    real = [p["stress"] for p in json.loads(curve(11))["points"][::30] if p["stress"] >= 100]
    assert _verify(" , ".join(f"{v} · {int(v)} · {int(v * 10) / 10:.1f}" for v in real))["unsourced"] == []


def test_verify_answer_는_원장을_메모리_상한에서_줄였으면_그렇다고_말한다(monkeypatch):
    """상한(EVID_MAX_CHARS)은 메모리 보호라 남긴다 — 다만 넘쳐 버린 근거로 '찾지 못했다' 를 말할 때는 그 사실을 같이 말한다."""
    _evid_ctx(monkeypatch)
    monkeypatch.setattr(gw, "EVID_MAX_CHARS", 50)
    _keep("old", '{"v": 11111.5, "w": 22222.5, "x": 33333.5}')
    _keep("new", '{"v": ' + ", ".join(f"{90000 + i}.5" for i in range(10)) + "}")
    body = _verify("옛 값 11111.5")
    assert body["unsourced"] == ["11111.5"]
    assert body["evidence_trimmed"]["calls_dropped"] >= 1 and "EVID_MAX_CHARS" in body["note"]
    _evid_ctx(monkeypatch)
    _keep("t", '{"v": 48039.32}')
    assert "evidence_trimmed" not in _verify("값 48039.32"), "줄이지 않았으면 칸이 없다"


@pytest.mark.anyio
async def test_rest_call_로_읽은_수치도_조회한_값이다(_rest, monkeypatch):
    """rest_call 출력이 근거 원장에 안 쌓여, 그 길로 읽은 수치는 verify_answer 가 늘 '조회 결과에 없다' 고 했다."""
    monkeypatch.setattr(gw, "_EVID", gw.OrderedDict())
    monkeypatch.setattr(gw.httpx, "AsyncClient", _Cli)
    _Cli.status, _Cli.raw, _Cli.ctype, _Cli.clen = 200, b'{"stress": 48039.32}', "application/json", None
    await gw._rest_call({"site": "locked", "path": "/x"})
    body = json.loads((await gw._verify_answer({"text": "응력 48039.32"})).content[0].text)
    assert body["unsourced"] == [] and body["tool_calls"] == ["rest_call"]


def _fastapi_openapi() -> dict:
    """하위 사이트(FastAPI)가 OpenAPI 를 만드는 **실제 경로**로 문서를 만든다 — 손으로 쓰지 않는다."""
    from fastapi import FastAPI, Query
    from pydantic import BaseModel, Field

    class Window(BaseModel):
        start: str = Field(description="시작일(YYYY-MM-DD)")
        days: int = 7

    class JobIn(BaseModel):
        name: str = Field(description="잡 이름")
        cores: int = Field(128, description="코어 수 — ste 는 128 고정")
        window: Window | None = None

    app = FastAPI(title="T")
    long_summary = "잡을 제출한다 — " + "입력 덱 경로·코어 수·라이선스 서버를 확인한 뒤 큐에 넣는다 " * 5

    @app.post("/api/jobs", summary=long_summary)
    def submit(job: JobIn, dry_run: bool = Query(False, description="검증만")):
        return {}

    @app.get("/api/jobs/{job_id}")
    def get_job(job_id: int, fields: str | None = None):
        """잡 하나."""
        return {}
    return app.openapi()


@pytest.mark.anyio
async def test_rest_catalog_는_요약을_자르지_않고_경로의_인자와_본문_스키마를_싣는다(_rest, monkeypatch):
    """rest_call 설명이 '경로·메서드를 추측하지 마라' 고 하는데 쿼리·본문은 추측할 수밖에 없었다 — 표가 경로·메서드·요약(120자)
    만 주고 OpenAPI 의 parameters·requestBody 를 버렸다. search_tools 의 인자 요약과 같은 실패 꼴이다."""
    doc = _fastapi_openapi()

    async def _doc(site):
        return doc
    monkeypatch.setattr(gw, "_openapi_of", _doc)
    rows = {(r["method"], r["path"]): r for r in _payload(await gw._rest_catalog({"site": "locked"}))["sites"][0]["paths"]}
    post = rows[("POST", "/api/jobs")]
    want_summary = doc["paths"]["/api/jobs"]["post"]["summary"]
    assert len(want_summary) > 120 and post["summary"] == want_summary.strip()
    assert post["params"] == [{"name": "dry_run", "in": "query", "required": False,
                               "schema": doc["paths"]["/api/jobs"]["post"]["parameters"][0]["schema"],
                               "description": "검증만"}]
    body = post["body"]
    assert body["content_type"] == "application/json" and body["required"] is True
    props = body["schema"]["properties"]                          # `$ref` 를 문서 안에서 풀었다
    assert props["cores"]["description"] == "코어 수 — ste 는 128 고정" and body["schema"]["required"] == ["name"]
    win = props["window"]["anyOf"][0]                             # 중첩 참조도 풀었다
    assert win["properties"]["start"]["description"] == "시작일(YYYY-MM-DD)"
    assert "$ref" not in json.dumps(post), "풀지 못한 참조가 남았다"
    get = rows[("GET", "/api/jobs/{job_id}")]
    assert [(p["name"], p["in"], p["required"]) for p in get["params"]] == [("job_id", "path", True), ("fields", "query", False)]
    assert "body" not in get


def test_openapi_참조가_순환이면_그_자리에_참조를_남긴다():
    doc = {"components": {"schemas": {"Node": {"type": "object", "properties": {
        "child": {"$ref": "#/components/schemas/Node"}, "name": {"type": "string"}}}}}}
    got = gw._openapi_deref(doc, {"$ref": "#/components/schemas/Node"})
    assert got["properties"]["name"] == {"type": "string"}
    assert got["properties"]["child"] == {"$ref": "#/components/schemas/Node"}


@pytest.mark.anyio
async def test_rest_call_은_JSON_이_아닌_본문도_자르지_않는다(_rest, monkeypatch):
    """JSON 이면 바이트 상한까지 통째인데 텍스트(로그·CSV·마크다운)는 8,000자에서 표지 없이 끊겼다 — 좌석이 잡 로그를 이 길로
    읽으면 앞 8,000자만 봤다."""
    monkeypatch.setattr(gw.httpx, "AsyncClient", _Cli)
    text = "줄 " + "로그 한 줄 끝에 결론이 있다\n" * 2000 + "최종 판정 PASS"
    assert len(text) > 8000
    _Cli.status, _Cli.raw, _Cli.ctype, _Cli.clen = 200, text.encode("utf-8"), "text/plain", None
    out = _payload(await gw._rest_call({"site": "locked", "path": "/log"}))
    assert out["body"] == text and "error" not in out


@pytest.mark.anyio
async def test_rest_call_이_상한을_넘겨_거부할_때는_크기와_좁히는_법을_말한다(_rest, monkeypatch):
    """상한은 메모리 보호라 둔다(120MB 응답에 피크 521MB 실측) — 자르지 않고 거부한다. 다만 `0MB 를 넘는다` 처럼 상한을 MB 로
    내림해 말했고, 목록을 좁혀 다시 부르는 법이 없었다."""
    monkeypatch.setattr(gw.httpx, "AsyncClient", _Cli)
    monkeypatch.setattr(gw, "REST_CALL_MAX_BYTES", 10_000)
    _Cli.status, _Cli.raw, _Cli.ctype, _Cli.clen, _Cli.streamed = 200, b"[" + b"1," * 50_000 + b"1]", "application/json", None, 0
    out = _payload(await gw._rest_call({"site": "locked", "path": "/rows"}))
    assert "넘는다" in out["error"] and "10,000" in out["error"] and "GATEWAY_REST_CALL_MAX_BYTES" in out["error"]
    assert "rest_catalog" in out["detail"] and "좁혀" in out["detail"]


# ── save_conversation — MCP 심의 전사의 유일한 서버 사본이다. 포털 한도(발언 20,000자·한 번에 200건)를 넘는 것을 버리지 않는다 ──
def _drive_save_all(monkeypatch, arguments, fail_at=None):
    """포털 자리에 앉아 받은 요청을 **전부** 기록한다. fail_at=n 이면 n번째 요청(0부터)에 500 으로 답한다."""
    from types import SimpleNamespace as NS
    posts, audits = [], []

    class _Resp:
        def __init__(self, code): self.status_code = code
        def json(self): return {"id": "c-1"} if self.status_code == 200 else {}

    class _Cli:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None, headers=None):
            posts.append((url, json))
            return _Resp(500 if fail_at is not None and len(posts) - 1 == fail_at else 200)

    monkeypatch.setattr(gw, "_portal_api_base", lambda: "http://portal")
    monkeypatch.setattr(gw.httpx, "AsyncClient", _Cli)
    monkeypatch.setattr(gw, "_audit", lambda *a, **k: audits.append((a, k)))
    monkeypatch.setattr(gw, "_low", NS(request_context=NS(request=NS(headers={"authorization": "Bearer t"}))))
    res = asyncio.run(gw._save_conversation(arguments))
    return res, posts, audits


def _stored(posts):
    """포털에 실제로 쌓인 순서 — 일괄 생성의 messages 뒤에 덧붙이기들."""
    out = list(posts[0][1]["messages"])
    out += [b for url, b in posts[1:] if url.endswith("/messages")]
    return out


def test_save_conversation_은_포털_한도를_넘는_발언을_나눠_싣고_한_글자도_버리지_않는다(monkeypatch):
    """1백만 토큰 창의 좌석 발언·결정문은 20,000자를 넘는다. 종전엔 표지 없이 잘라 저장했고, 이어하기가 그 잘린 글을 정본으로
    읽었다. 포털 한도는 그대로 지키되(넘으면 배치 전체가 422) 이어지는 메시지로 나눠 싣는다."""
    say = "결정문 " + "".join(f"[{i:05d}] 근거와 판정을 적는다. " for i in range(3000))
    assert len(say) > 2 * 20000
    rb = [{"target": "b", "quote": "q", "counter": "c", "basis": "x"}]
    res, posts, audits = _drive_save_all(monkeypatch, {"title": "심의", "messages": [
        {"role": "user", "content": "질문"},
        {"role": "persona", "persona": "의장", "round": 3, "content": say, "meta": {"rebut": rb}},
        {"role": "persona", "persona": "b", "round": 3, "content": "짧다"}]})
    assert not res.isError
    got = _stored(posts)
    parts = [m for m in got if m.get("persona") == "의장"]
    assert len(parts) >= 3 and all(len(m["content"]) <= 20000 for m in got)
    import re as _re
    assert "".join(_re.sub(r"^\(긴 발언 나눔 \d+/\d+\)\n", "", m["content"]) for m in parts) == say
    assert parts[0]["meta"]["rebut"] == rb and all("meta" not in m for m in parts[1:]), "meta 는 첫 조각에만"
    assert {m["round"] for m in parts} == {3} and got[-1]["content"] == "짧다", "순서가 그대로다"
    body = json.loads(res.content[0].text)
    assert body["ok"] is True and body["split"] == [{"index": 1, "chars": len(say), "parts": len(parts)}]


def test_save_conversation_은_200건을_넘는_전사를_덧붙이기로_마저_보낸다(monkeypatch):
    """한 번에 200건(포털 ConvCreate 한도)을 넘으면 첫 항목 + 꼬리 199 만 남겨 가운데 발언이 통째로 사라졌다. 포털에는 한 건씩
    덧붙이는 길(POST /agent/conversations/{id}/messages)이 있다 — 200건으로 만들고 나머지를 순서대로 덧붙인다."""
    msgs = [{"role": "user", "content": "질문"}] + [
        {"role": "persona", "persona": f"s{i % 20}", "round": i // 20 + 1, "content": f"발언 {i}"} for i in range(258)
    ] + [{"role": "assistant", "content": "결정문"}]
    res, posts, _ = _drive_save_all(monkeypatch, {"title": "심의", "messages": msgs})
    assert not res.isError
    assert posts[0][0] == "http://portal/agent/conversations" and len(posts[0][1]["messages"]) == 200
    assert {u for u, _ in posts[1:]} == {"http://portal/agent/conversations/c-1/messages"} and len(posts) == 61
    assert [m["content"] for m in _stored(posts)] == [m["content"] for m in msgs], "가운데도 끝도 순서대로 전부"
    assert json.loads(res.content[0].text)["messages_saved"] == 260


def test_save_conversation_이_덧붙이다_실패하면_어디까지_저장됐는지_말한다(monkeypatch):
    msgs = [{"role": "persona", "persona": "s", "content": f"발언 {i}"} for i in range(230)]
    res, posts, audits = _drive_save_all(monkeypatch, {"title": "심의", "messages": msgs}, fail_at=11)
    assert res.isError
    text = res.content[0].text
    assert text.startswith("CONV_PARTIAL:")
    body = json.loads(text.split(":", 1)[1])
    assert (body["conversation_id"], body["saved_messages"], body["total_messages"]) == ("c-1", 210, 230)
    assert audits and audits[-1][0][2] is False and "partial" in str(audits[-1])


def test_save_conversation_이_포털_한도로_자른_이름과_제목은_원문_길이와_함께_알린다(monkeypatch):
    res, posts, audits = _drive_save_all(monkeypatch, {"title": "제" * 300, "messages": [
        {"role": "persona", "persona": "p" * 150, "content": "x"}]})
    assert posts[0][1]["title"] == "제" * 200 and posts[0][1]["messages"][0]["persona"] == "p" * 120
    body = json.loads(res.content[0].text)
    assert body["ok"] is True
    assert {"field": "title", "chars": 300, "kept": 200} in body["clipped"]
    assert {"field": "persona", "index": 0, "chars": 150, "kept": 120} in body["clipped"]
    assert "clipped" in (audits[-1][1].get("note") or "")
    plain, _, _ = _drive_save_all(monkeypatch, {"title": "t", "messages": [{"role": "user", "content": "x"}]})
    assert json.loads(plain.content[0].text) == {"ok": True, "conversation_id": "c-1"}, "아무것도 안 바꿨으면 종전 응답 그대로"


def test_대화_저장_상한은_포털_입력_모델의_한도를_넘지_않는다():
    """두 리포에 걸친 계약이다 — 게이트웨이가 포털보다 크게 보내면 배치 전체가 422 로 거부돼 심의 전사가 통째로 유실된다(전기박리
    심의 사고). 작게 보내는 것은 안전하다(조각이 늘 뿐). 포털이 한도를 올리면 이 상수를 따라 올린다. 형제 리포가 있을 때만 본다."""
    import re
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(gw.__file__))),
                        "HWAXPortal", "backend", "app", "agent", "routes.py")
    if not os.path.exists(path):
        pytest.skip("HWAXPortal 리포가 옆에 없다")
    src = open(path, encoding="utf-8").read()

    def cap(cls: str, field: str) -> int:
        body = re.search(rf"class {cls}\(BaseModel\):(.*?)\n\n\n", src, re.S)
        assert body, f"포털에서 {cls} 를 못 찾았다 — 이름이 바뀌었나"
        m = re.search(rf"^\s+{field}:[^\n]*max_length=(\d+)", body.group(1), re.M)
        assert m, f"포털 {cls}.{field} 의 max_length 를 못 읽었다"
        return int(m.group(1))
    assert gw.CONV_CONTENT_MAX <= cap("ConvMessageIn", "content")
    assert gw.CONV_PERSONA_MAX <= cap("ConvMessageIn", "persona")
    assert gw.CONV_TITLE_MAX <= cap("ConvCreate", "title")
    assert gw.CONV_BATCH_MAX <= cap("ConvCreate", "messages")


# ── 같은 쿼리 키를 여러 번 주는 필터(`?tags=a&tags=b`)가 하나로 접히거나 글자로 깨지지 않는다 ─────────────────────
@pytest.mark.anyio
async def test_rest_call_은_목록_쿼리값을_키를_되풀이해_보낸다(_rest, monkeypatch):
    """종전 `{k: str(v)}` 는 목록을 `"['a', 'b']"` 라는 글자 하나로 보냈다 — 필터가 깨지거나 엉뚱한 결과가 온다."""
    monkeypatch.setattr(gw.httpx, "AsyncClient", _Cli)
    _Cli.status, _Cli.raw, _Cli.ctype, _Cli.clen = 200, b'{"ok": true}', "application/json", None
    await gw._rest_call({"site": "locked", "path": "/rows", "query": {"tags": ["a", "b"], "n": 2}})
    url = httpx.Request("GET", "http://s/rows", params=_Cli.seen["params"]).url
    assert url.query == b"tags=a&tags=b&n=2"


def test_REST_프록시는_같은_쿼리_키를_하나로_접지_않는다(monkeypatch):
    """`dict(request.query_params)` 는 같은 키의 마지막 값만 남겼다 — `?tags=a&tags=b` 가 `tags=b` 로 갔다."""
    monkeypatch.setattr(gw, "POLICY", {"sec": []})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    resp, shots, _ = _rest_gate(monkeypatch, {"keys": []}, [], query=b"tags=a&tags=b&n=1")
    assert resp.status_code == 200 and shots == ["http://upstream.invalid/x?tags=a&tags=b&n=1"]


def test_search_tools_가_limit_로_자르면_잘랐다고_말한다(monkeypatch):
    """순위 목록이라 건수(기본 8·최대 20)는 둔다 — 다만 더 맞은 도구가 있다는 것을 match_count 만으로 두지 않고 말한다."""
    tools = [_tool(f"report_x{i:02d}") for i in range(25)]
    monkeypatch.setattr(gw, "exposed_tools", tools)
    monkeypatch.setattr(gw, "route", {t.name: ("sf", t.name) for t in tools})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    monkeypatch.setattr(gw, "_request_muted", lambda: set())
    out = json.loads(asyncio.run(gw._search_tools({"query": "report_x"})).content[0].text)
    assert out["match_count"] == 25 and len(out["matches"]) == 8
    assert "25" in out["truncated"] and "limit" in out["truncated"]
    whole = json.loads(asyncio.run(gw._search_tools({"query": "report_x0"})).content[0].text)
    assert whole["match_count"] == 10 and len(whole["matches"]) == 8 and "truncated" in whole
    few = json.loads(asyncio.run(gw._search_tools({"query": "report_x2"})).content[0].text)
    assert few["match_count"] == 5 and "truncated" not in few


# ── 리스크 앱 위임 — 호출자를 Caddy 가 지우지 않는 X-Hwax-Delegate-Email 로 싣는다(risk-entry SEC-1 게이트웨이 반쪽) ──────
# 발급 요청은 Caddy 경로(/apps/hwax_risk/api/auth/sso)로 가고, 그 라우트의 forward_auth(copy_identity)가 X-Heax-User-Email 을
# 지운 뒤 authz 가 준 이메일 — 게이트웨이 서비스 토큰의 주인(heax 첫 관리자) — 로 다시 싣는다(HEAXHub proxy_manager
# `_forward_auth_handler`). 그래서 그 헤더만 보내면 게이트웨이를 거친 모든 사람이 한 사람으로 단언을 받았다. 앱(HWAXRisk 8e327d6)은
# 시크릿 대조 뒤 X-Hwax-Delegate-Email 을 먼저 읽는다. 아래 가짜 상류는 그 둘(Caddy 덮어쓰기 + 앱의 단언 발급)을 흉내 낸다.
_RISK_SSO = {"sso_url": "http://caddy.invalid/apps/hwax_risk/api/auth/sso", "secret": "rs", "client": "deliberation",
             "auth": "heax", "token_header": "X-Heax-Sso-Assertion"}
_FIRST_ADMIN = "first-admin@corp.com"


def _rrsso(email: str, *, delegated: bool = False) -> str:
    """앱 identity.mint_sso_assertion 과 같은 꼴 — `rrsso_<b64u({"e","x"[,"d"]})>.<서명>`(서명은 게이트웨이가 보지 않는다).
    `delegated` 는 앱이 X-Hwax-Delegate-Email 로 발급했을 때만 싣는 위임 표지 d 다(HWAXRisk 2eecb36 — 위임을 아는 판만 넣는다)."""
    import base64
    claims = {"e": email, "x": 4102444800, **({"d": 1} if delegated else {})}
    body = base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode()).decode()
    return f"rrsso_{body.rstrip('=')}.c2ln"


def _risk_kit(monkeypatch, *, app_reads_delegate=True, caddy_overwrites_delegate=False, user="a@corp.com",
              tool="risk_create_project"):
    """heax-hwax_risk 백엔드 하나로 `_call_tool` 을 태운다. 발급(`_user_pat`·`_mint_user_pat`)은 진짜이고 상류는 가짜다.
    `app_reads_delegate=False` 는 위임 헤더를 모르는 옛 앱(HWAXRisk main — 단언에 d 가 없다), `caddy_overwrites_delegate` 는 허브·Caddy
    가 위임 헤더마저 서비스 토큰 주인으로 덮게 바뀐 경우다(앱은 위임을 알아 d 를 싣는데 이메일이 남의 것이다).
    돌려주는 것 — 결과 · 앱에 닿은 발급 요청 헤더(Caddy 를 지난 뒤) · 백엔드에 닿은 헤더 · 감사 마지막 줄."""
    reached, backend = [], {}

    def handler(req):
        h = {k.lower(): v for k, v in req.headers.items()}
        # Caddy forward_auth(copy_identity=True): 동명 헤더를 지우고 authz 가 Bearer(서비스 PAT)의 주인으로 다시 싣는다.
        assert h.get("authorization") == "Bearer heax-svc-pat", "Caddy 문은 서비스 토큰으로 지난다(auth=heax)"
        h.pop("x-heax-user-email", None)
        h["x-heax-user-email"] = _FIRST_ADMIN
        if caddy_overwrites_delegate:
            h["x-hwax-delegate-email"] = _FIRST_ADMIN
        reached.append(h)
        if h.get("x-heax-gateway-secret") != "rs":
            return httpx.Response(401, json={"error": "unauthorized"})
        delegate = h.get("x-hwax-delegate-email") if app_reads_delegate else None
        email = (delegate if delegate is not None else h["x-heax-user-email"]).strip().lower()
        return httpx.Response(200, json={"access_token": _rrsso(email, delegated=delegate is not None),
                                         "token_type": "bearer", "expires_in": 900})
    _mock_http(monkeypatch, handler)
    b = _CallB([tool])

    class _Sess:
        async def initialize(self): return None

        async def call_tool(self, original, arguments, read_timeout_seconds=None):
            return types.CallToolResult(content=[types.TextContent(type="text", text='{"created": true}')], isError=False)

    def fake_stream(url, headers=None, **_kw):
        backend["headers"] = dict(headers or {})
        return _StubCM((None, None, "sid"))

    async def fake_access(email, base_groups, **_kw):
        return {"keys": [], "affiliation": ""}
    monkeypatch.setattr(gw, "streamablehttp_client", fake_stream)
    monkeypatch.setattr(gw, "ClientSession", lambda read, write: _StubCM(_Sess()))
    monkeypatch.setattr(gw, "_portal_access", fake_access)
    monkeypatch.setitem(gw.HEAX, "token", "heax-svc-pat")
    monkeypatch.setattr(gw, "PER_USER_SSO", {"hwax_risk": dict(_RISK_SSO)})
    monkeypatch.setattr(gw, "_USER_PATS", {})
    monkeypatch.setattr(gw, "_USER_PAT_LOCKS", {})
    gw._RESP_CACHE.clear()
    monkeypatch.setattr(gw, "backends", {"heax-hwax_risk": b})
    monkeypatch.setattr(gw, "route", {tool: ("heax-hwax_risk", tool)})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setattr(gw, "_request_user", lambda: user)
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    res = asyncio.run(gw._call_tool(tool, {"code": "P1", "name": "n", "classification": "internal"}))
    return res, reached, backend.get("headers"), _rows()[-1]


def _assertion_email(tok: str) -> str:
    import base64
    body = tok[len("rrsso_"):].partition(".")[0]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))["e"]


def test_리스크_위임_단언은_Caddy_가_신원_헤더를_덮어도_호출자_본인이다(monkeypatch):
    res, reached, backend, row = _risk_kit(monkeypatch)
    assert reached[0]["x-heax-user-email"] == _FIRST_ADMIN, "가짜 상류가 Caddy 덮어쓰기를 흉내 내야 시험이 뜻이 있다"
    assert reached[0].get("x-hwax-delegate-email") == "a@corp.com", "Caddy 가 지우지 않는 위임 헤더로 호출자를 싣는다"
    assert not res.isError
    assert _assertion_email(backend["X-Heax-Sso-Assertion"]) == "a@corp.com", \
        "단언이 서비스 토큰 주인(첫 관리자)으로 접혔다 — 그러면 모든 사용자의 과제가 그 한 사람 것이 된다"
    assert row["mode"] == "as-user-pat" and row["caller"] == "a@corp.com"
    assert "note" not in row, "접히지 않은 단언에 접힘 표기를 달았다"


def test_리스크_위임_단언이_다른_사람으로_접히면_발급을_실패로_돌린다(monkeypatch):
    """위임을 아는 앱(단언에 d)인데도 Caddy·허브 쪽 변화로 다시 접히면 **조용히 성공하지 않는다** — 첫 관리자 명의로 남의 과제를
    쓰고 잡을 세우느니 거부한다. 서비스 계정으로 내려가지도 않는다(사용자별 앱의 종전 자세). 거부 문구는 원인을 말한다 — 운영자가
    앱 판을 의심하지 않고 곧장 그 헤더의 길을 보게(RR2-GW-1 처방 4)."""
    res, reached, backend, row = _risk_kit(monkeypatch, caddy_overwrites_delegate=True)
    assert res.isError and backend is None, "접힌 단언으로 백엔드를 불렀다"
    text = res.content[0].text
    assert "a@corp.com" in text and "단언" in text and _FIRST_ADMIN not in text, \
        "누구로 접혔는지(남의 이메일)는 호출자에게 내보이지 않는다 — 로그에만"
    assert "위임을 아는 판" in text and gw.DELEGATE_HEADER in text, "거부 문구에 원인(어느 헤더가 어디서 바뀌었나)이 없다"
    assert len(reached) == 1, "실패한 발급은 다시 받지 않는다(HG-03 — 발급마다 직전 토큰을 폐기하는 앱이 있다)"
    assert row["ok"] is False and "단언" in row["error"]


def test_위임을_모르는_옛_리스크_앱이면_접힌_단언도_거부하지_않고_경고와_감사_표기만_남긴다(monkeypatch, caplog):
    """위임 헤더를 모르는 앱(HWAXRisk main — 단언에 위임 표지 d 가 없다)과 이 게이트웨이가 섞인 박스(dev 10-10 재부팅 뒤)에서는
    접힘 대조가 첫 관리자가 아닌 모든 사람의 hwax_risk 호출을 읽기까지 거부했다 — risk_taxonomy 도 실패했다(RV-2·RR2-GW-1).
    d 가 없으면 종전 동작대로 부르고 경고 로그 한 줄과 감사 note 만 남긴다. 접힌 신원의 쓰기는 위임을 아는 새 앱이 스스로 막는다."""
    import logging
    with caplog.at_level(logging.WARNING, logger=gw.log.name):
        res, reached, backend, row = _risk_kit(monkeypatch, app_reads_delegate=False, tool="risk_taxonomy")
        assert not res.isError, res.content[0].text
        assert _assertion_email(backend["X-Heax-Sso-Assertion"]) == _FIRST_ADMIN, "옛 앱에서는 종전 동작(접힌 단언) 그대로다"
        assert len(reached) == 1, "거부·재발급 없이 한 번 발급한다"
        assert row["ok"] is True and row["mode"] == "as-user-pat" and row["caller"] == "a@corp.com"
        assert row.get("note") == "folded-old-app", row
        # 캐시된 단언으로 부르는 다음 호출에도 표기가 남는다 — 발급 때 한 번만 적으면 그 뒤 12시간의 호출이 접힌 줄 모른다.
        again = asyncio.run(gw._call_tool("risk_taxonomy", {"code": "P2"}))
        assert not again.isError and len(reached) == 1
        assert _rows()[-1].get("note") == "folded-old-app", _rows()[-1]
    warns = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING and "d 없음" in r.getMessage()]
    assert len(warns) == 1, warns
    assert "a@corp.com" in warns[0] and "HWAXRisk" in warns[0], warns


def test_위임_헤더는_바깥에서_실어_보내도_게이트웨이를_지나지_못한다(monkeypatch):
    """게이트웨이만 `X-Hwax-Delegate-Email` 을 싣는다(확인한 신원으로, 발급 요청에만). 클라이언트가 같은 이름을 실어 보내면
    /mcp 는 인증 미들웨어가 두 분기(PAT·GW_TOKEN) 모두 버리고, /api/ 는 REST 프록시가 상류로 넘기지 않는다 —
    앱은 시크릿 대조 뒤 이 헤더를 그대로 믿는다."""
    seen = {}

    async def app(scope, receive, send):
        seen["headers"] = {k.decode().lower(): v.decode() for k, v in scope["headers"]}

    async def no_portal(email, base, **_kw):
        return None
    monkeypatch.setattr(gw, "_portal_access", no_portal)
    monkeypatch.setattr(gw, "GW_TOKEN", "gw-secret")

    class _V:
        async def verify(self, token, aud): return {"email": "u@x.io", "groups": []}

    forged = (gw.DELEGATE_HEADER.lower().encode(), b"victim@x.io")
    for auth in (b"Bearer user-pat", b"Bearer gw-secret"):
        seen.clear()
        asyncio.run(gw._bearer_gate(app, _V())({"type": "http", "path": "/mcp",
                                                "headers": [(b"authorization", auth), forged]}, None, None))
        assert seen["headers"] and gw.DELEGATE_HEADER.lower() not in seen["headers"], auth

    monkeypatch.setattr(gw, "POLICY", {"sec": []})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    sent = []
    resp, shots, _ = _rest_gate(monkeypatch, {"keys": []}, [], headers=[forged, (b"x-keep", b"1")], sent=sent)
    assert resp.status_code == 200 and sent[0].get("x-keep") == "1", "다른 헤더는 종전대로 넘긴다"
    assert gw.DELEGATE_HEADER.lower() not in sent[0], "REST 프록시가 위조 위임 헤더를 상류로 넘겼다"


def test_위임_헤더_이름과_단언_꼴이_리스크_앱과_같다():
    """두 리포에 흩어진 문자열이다 — 한쪽만 바꾸면 양쪽 시험이 각자 초록인 채 위임이 다시 접히거나(헤더 이름), 접힘 대조가 말없이
    꺼진다(단언 꼴이 바뀌면 `_sso_assertion_claims` 가 None 이다). 형제 리포가 이 박스에 있을 때만 본다."""
    import rest_proxy
    from pathlib import Path
    assert gw.DELEGATE_HEADER.lower() in rest_proxy._NEVER_FORWARD, "REST 프록시가 버리는 이름과 게이트웨이가 싣는 이름이 같아야 한다"
    app = Path(gw.__file__).resolve().parent.parent / "HWAXRisk" / "backend" / "app"
    if not (app / "identity.py").exists():
        pytest.skip("HWAXRisk 리포가 이 박스에 없다")
    ident = (app / "identity.py").read_text(encoding="utf-8")
    assert f'SSO_PREFIX = "{gw._SSO_ASSERTION_PREFIX}"' in ident and '{"e": email' in ident, \
        "리스크 앱 단언의 꼴이 바뀌었다 — 게이트웨이의 접힘 대조(_sso_assertion_claims)를 같이 고친다"
    routes = (app / "routes.py").read_text(encoding="utf-8")
    if "x-hwax-delegate" not in routes.lower():
        pytest.skip("이 체크아웃의 리스크 앱은 아직 위임 헤더를 읽지 않는다(HWAXRisk 8e327d6 이전)")
    assert f'"{gw.DELEGATE_HEADER.lower()}"' in routes, "앱이 읽는 위임 헤더 이름이 게이트웨이가 싣는 것과 다르다"
    assert f'claims["{gw._SSO_DELEGATED_CLAIM}"]' in ident, \
        "위임을 아는 앱의 단언에 위임 표지가 없다 — 게이트웨이가 그 앱을 옛 앱으로 읽어 접힌 단언을 거부하지 않는다(_mint_user_pat)"


def test_지침이_리스크_심사는_risk_next_step_부터라고_말한다():
    """리스크 앱의 Claude 입구(쓰기 9종 + 길잡이)는 id 를 여럿 잇는 긴 길이라, 모델이 도구 목록에서 아무 쓰기나 먼저 고르면
    과제·소스가 엉뚱한 자리에 생긴다(소스는 지울 수 없다). 길잡이가 단계·막힌 곳·다음 호출을 한 번에 준다 — 허브 지침에서 그리로
    보낸다. 길잡이가 채워 주는 쓰기 인자도 사람 확인을 건너뛰는 근거가 아니다(5번)."""
    full = gw._INSTRUCTIONS + gw._INSTR_RISK_NEXT          # 길잡이가 카탈로그에 있을 때 실리는 꼴(아래 시험)
    assert "risk_next_step" in full
    i = full.index("risk_next_step")
    item = full[full.rfind("\n", 0, i):]
    assert "리스크 심사" in item and "확인" in item and "consent" in item, item
    assert len(full) < 2048, "Claude Code 는 서버 지침을 2048자에서 자른다"


def test_지침_11번은_risk_next_step_이_카탈로그에_있을_때만_싣는다(monkeypatch):
    """위임을 모르는 옛 리스크 앱(HWAXRisk main — 도구 14종, 길잡이·입구 도구 없음)이 붙은 박스에서 허브 지침 11번이 없는 도구부터
    부르라고 시켰다(RR2-GW-1 (c), dev 10-10 재부팅 뒤). 지침은 MCP initialize 때 클라이언트에 실리므로, 그때 카탈로그(`route`)에
    risk_next_step 이 있을 때만 싣는다 — 재집계가 앱 판이 바뀐 것을 보면 다음 세션부터 따라간다."""
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "route", {})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "_LAST_TOOLS", {})
    monkeypatch.setattr(gw._low, "instructions", gw._low.instructions)

    def served(tools):
        monkeypatch.setattr(gw, "backends", {"heax-hwax_risk": _CallB(tools)})
        asyncio.run(gw._aggregate())
        return gw._low.create_initialization_options().instructions      # initialize 응답에 실리는 그 값

    old = served(["risk_taxonomy", "risk_list_projects"])
    assert "risk_next_step" not in old, "옛 앱 박스에서 지침이 없는 도구를 가리킨다"
    assert "browse_experts" in old and "muted_apps" in old, "나머지 지침은 그대로 실려야 한다"
    new = served(["risk_taxonomy", "risk_next_step"])
    assert "risk_next_step" in new and new.startswith(old), "길잡이가 붙으면 11번이 실려야 한다"
    assert len(new) < 2048, "Claude Code 는 서버 지침을 2048자에서 자른다"
    assert "risk_next_step" not in served(["risk_taxonomy"]), "길잡이가 빠진 판으로 돌아가면 11번도 빠져야 한다"


# ── 응답 캐시의 바이트 상한(gw-adh GA-5) ─────────────────────────────────────────────────────────────────────
def test_응답_캐시는_큰_결과를_담지_않고_합도_바이트로_묶는다(monkeypatch):
    """검색 도구의 top_k 천장과 200자 스니펫이 걷혀 결과 한 건이 수십 MB 가 될 수 있다(hybrid_search(top_k=5000) 약 21MB 추정).
    캐시는 건수(512)만 봐서 그런 결과를 300초 쥐었다 — rest_call 이 1MiB 로 막는 그 꼴이 MCP 길에서는 안 막혔다. 결과는 자르지
    않고 그대로 돌려주되(호출자 몫) 캐시에는 담지 않고, 담는 것도 합을 바이트로 묶어 오래된 것부터 버린다."""
    monkeypatch.setattr(gw, "CACHE_TTL_S", 300.0)
    monkeypatch.setattr(gw, "_RESP_CACHE", gw.OrderedDict())
    big = _txt('{"hits": "' + "가" * 600_000 + '"}')                      # 한글 60만 자 ≈ 1.8MB(UTF-8)
    k = gw._cache_key("ai-data-hub", "hybrid_search", {"q": "x", "top_k": 5000})
    assert gw._cache_put(k, big) is big, "결과는 자르지 않고 그대로 돌려준다"
    assert k not in gw._RESP_CACHE, "1MiB 를 넘는 결과가 캐시에 300초 남았다"
    assert gw._cache_put(k, _txt('{"hits": []}')) and k in gw._RESP_CACHE, "작은 결과는 종전대로 담는다"

    monkeypatch.setattr(gw, "_RESP_CACHE", gw.OrderedDict())
    monkeypatch.setattr(gw, "CACHE_MAX_BYTES", 2500)
    keys = [gw._cache_key("b", "get_x", {"i": i}) for i in range(4)]
    for kk in keys:
        gw._cache_put(kk, _txt("x" * 1000))
    assert list(gw._RESP_CACHE) == keys[2:], "합이 상한을 넘으면 오래된 것부터 버린다"
    assert gw._cache_get(keys[3]).content[0].text == "x" * 1000


# ── 순위 목록은 작은 창 소비자의 글자 절단을 견딘다(gw-adh GA-7) ─────────────────────────────────────────────────
def _long_tools(monkeypatch, n, app="heax-hwax_risk"):
    """설명·스키마가 리스크 앱 입구 도구만큼 긴 도구 n 개(실측: 8건 검색 결과 7,000~8,400자)."""
    tools = [types.Tool(name=f"risk_tool_{i:02d}", description=f"리스크 심사 도구 {i} — " + "설명 " * 300,
                        inputSchema={"type": "object", "properties": {"project_id": {"type": "string", "description": "과제 " * 60}},
                                     "required": ["project_id"]}) for i in range(n)]
    monkeypatch.setattr(gw, "exposed_tools", tools)
    monkeypatch.setattr(gw, "route", {t.name: (app, t.name) for t in tools})
    monkeypatch.setattr(gw, "backends", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    monkeypatch.setattr(gw, "_request_muted", lambda: set())
    return [t.name for t in tools]


def test_search_tools_는_찾은_도구_이름을_순위대로_먼저_싣는다(monkeypatch):
    """게이트웨이는 결과를 자르지 않는다 — 작은 창의 소비자(dev 웹 챗 TOOL_RESULT_MAX=6,000)가 앞에서부터 글자로 자른다. 설명·스키마
    전문이 앞서면 그 절단에 6~8위 도구는 이름조차 사라져 '없다' 로 읽힌다. 이름 순위를 먼저 실으면 잘려도 순위는 남는다."""
    _long_tools(monkeypatch, 12)
    out = asyncio.run(gw._search_tools({"query": "리스크 심사"})).content[0].text
    body = json.loads(out)
    assert len(out) > 6000 and len(body["matches"]) == 8, "시험 입력이 dev 상한을 넘어야 뜻이 있다"
    ranked = [m["tool"] for m in body["matches"]]
    assert body["ranked"] == ranked, "순위 목록은 matches 와 같은 순서다"
    head = out[:6000]
    assert all(f'"{n}"' in head for n in ranked), "6,000자에서 잘려도 8건 이름이 다 남아야 한다"
    assert head.index('"ranked"') < head.index('"matches"') and head.index('"note"') < head.index('"matches"')


def test_list_tool_apps_앱_상세는_도구_이름을_먼저_싣는다(monkeypatch):
    names = _long_tools(monkeypatch, 40)
    out = asyncio.run(gw._list_tool_apps({"app": "heax-hwax_risk"})).content[0].text
    entry = json.loads(out)["apps"][0]
    assert len(out) > 6000 and [t["name"] for t in entry["tools"]] == names, "설명은 전부 그대로다"
    assert entry["tool_names"] == names
    assert all(f'"{n}"' in out[:6000] for n in names), "6,000자에서 잘려도 40개 이름이 다 남아야 한다"


# ── 포털 PAT 건네기 — 리스크 앱 발급 응답이 바라면 호출자 PAT 로 포털에서 바꿔 받아 앱에 넘긴다(HWAXPortal docs/risk-credentials §4.2) ──
# 앱은 사람이 시작한 잡을 그 사람의 포털 PAT 로만 돌린다(U-3). Claude 로 온 사람은 PAT 를 앱에 등록한 적이 없으니, 앱이 단언 발급
# 응답에 `portal_pat_wanted` 를 실으면 게이트웨이가 호출자 본인의 포털 PAT 로 `POST /auth/pat/exchange` 를 불러 좁힌 PAT 를 받아
# `portal_pat_url` 로 넘긴다. 아래 가짜 상류 셋은 앱 SSO · 포털 교환 · 앱 등록이다. 토큰 값은 모양만 흉내 내고 눈에 띄게 둔다 —
# 로그·감사에 새는지를 글자로 찾는다.
_PP_WANTED = {"name": "hwax-risk", "audiences": ["mcp-gateway"], "scopes": ["read"], "ttl_days": 90}
# 운영자가 앱마다 박는 교환 본문의 상한(provision-config.sh 가 hwax_risk 에 적는 것과 같다).
_PP_SPEC = {"name": "hwax-risk", "audiences": ["mcp-gateway", "step-forge"], "scopes": ["read"], "max_ttl_days": 90}
_PP_CALLER_PAT = "eyJ.caller-portal-pat.CALLERSECRET"
_PP_NEW_PAT = "eyJ.exchanged-pat.NEWSECRET"
_PP_URL = "http://caddy.invalid/apps/hwax_risk/api/auth/portal-pat"
_PP_TOOL = "risk_create_project"


def _pp_ok(req):
    return httpx.Response(200, json={"jti": "j-1", "name": "hwax-risk", "audiences": ["mcp-gateway"], "scopes": ["read"],
                                     "created": 1, "exp": 2, "revoked": False, "token": _PP_NEW_PAT})


def _pp_setup(monkeypatch, *, wanted=_PP_WANTED, exchange=_pp_ok, register=None, backend_rejects_first=False, spec=_PP_SPEC,
              revoke=None):
    """heax-hwax_risk 하나로 `_call_tool` 을 태울 판을 세운다 — 발급·건네기는 진짜이고 상류 셋(앱 SSO · 포털 교환·폐기 · 앱 등록)은
    가짜다. 돌려주는 것 — 한 번 부르는 함수 `call(via, auth, user) → (결과, 감사 마지막 줄)` · 일어난 순서 · 상류가 받은 요청 ·
    상류의 답을 호출 사이에 바꿀 수 있는 `state`(wanted·exchange·register·revoke). 요청 문맥은 인증 미들웨어가 남기는
    꼴(Authorization 원본 · via · 확인한 신원)이다."""
    ev, got = [], {"exchange": [], "register": [], "revoke": []}
    state = {"wanted": wanted, "exchange": exchange, "register": register, "revoke": revoke}
    steps = {"http://portal/auth/pat/exchange": "exchange", _PP_URL: "register", "http://portal/auth/pat/revoke-self": "revoke"}

    async def handler(req):
        u, h = str(req.url), {k.lower(): v for k, v in req.headers.items()}
        if u == _RISK_SSO["sso_url"]:
            ev.append("mint")
            body = {"access_token": _rrsso(h["x-hwax-delegate-email"], delegated=True), "token_type": "bearer",
                    "expires_in": 900}
            if state["wanted"] is not None:
                body["portal_pat_wanted"] = state["wanted"]
            return httpx.Response(200, json=body)
        step = steps[u]
        fn = state[step]
        ev.append(step)
        got[step].append({"headers": h, "json": json.loads(req.content) if req.content else None})
        r = fn(req) if fn else httpx.Response(200, json={"revoked": "j-1"} if step == "revoke" else {"registered": True})
        return r if isinstance(r, httpx.Response) else await r
    _mock_http(monkeypatch, handler)
    calls = {"n": 0}

    class _Sess:
        async def initialize(self): return None

        async def call_tool(self, original, arguments, read_timeout_seconds=None):
            ev.append("call")
            calls["n"] += 1
            if backend_rejects_first and calls["n"] == 1:
                return types.CallToolResult(content=[types.TextContent(
                    type="text", text=f"Error executing tool {original}: POST /api/x → HTTP 401: expired")], isError=True)
            return types.CallToolResult(content=[types.TextContent(type="text", text='{"created": true}')], isError=False)

    async def fake_access(email, base_groups, **_kw):
        return {"keys": [], "affiliation": ""}
    monkeypatch.setattr(gw, "streamablehttp_client", lambda url, headers=None, **_kw: _StubCM((None, None, "sid")))
    monkeypatch.setattr(gw, "ClientSession", lambda read, write: _StubCM(_Sess()))
    monkeypatch.setattr(gw, "_portal_access", fake_access)
    monkeypatch.setitem(gw.HEAX, "token", "heax-svc-pat")
    monkeypatch.setattr(gw, "PER_USER_SSO", {"hwax_risk": {**_RISK_SSO, "portal_pat_url": _PP_URL,
                                                          **({"portal_pat_spec": spec} if spec is not None else {})}})
    monkeypatch.setattr(gw, "_USER_PATS", {})
    monkeypatch.setattr(gw, "_USER_PAT_LOCKS", {})
    monkeypatch.setattr(gw, "_PORTAL_PAT_TRIED", {})
    monkeypatch.setattr(gw, "_PORTAL_PAT_PENDING", gw.OrderedDict())
    gw._RESP_CACHE.clear()
    monkeypatch.setattr(gw, "backends", {"heax-hwax_risk": _CallB([_PP_TOOL])})
    monkeypatch.setattr(gw, "route", {_PP_TOOL: ("heax-hwax_risk", _PP_TOOL)})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)

    def call(*, via="pat", auth=f"Bearer {_PP_CALLER_PAT}", user="a@corp.com"):
        _set_request(monkeypatch, {"authorization": auth, gw.VIA_HEADER: via, gw.USER_HEADER: user.replace("@", "%40")},
                     "203.0.113.9")
        res = asyncio.run(asyncio.wait_for(gw._call_tool(_PP_TOOL, {"code": "P1"}), 10))
        return res, _rows()[-1]
    return call, ev, got, state


def _pp_kit(monkeypatch, *, via="pat", auth=f"Bearer {_PP_CALLER_PAT}", user="a@corp.com", **kw):
    """`_pp_setup` 의 한 번 부르기 — 결과 · 일어난 순서 · 상류가 받은 요청 · 감사 마지막 줄."""
    call, ev, got, _ = _pp_setup(monkeypatch, **kw)
    res, row = call(via=via, auth=auth, user=user)
    return res, ev, got, row


def test_포털_PAT_를_바라면_호출자_PAT_로_바꿔_받아_도구_호출_전에_앱에_넘긴다(monkeypatch):
    res, ev, got, row = _pp_kit(monkeypatch)
    assert not res.isError, res.content[0].text
    assert ev == ["mint", "exchange", "register", "call"], "등록이 그 도구 호출보다 먼저여야 앱이 이번 호출에 PAT 를 쓴다"
    ex = got["exchange"][0]
    assert ex["headers"]["authorization"] == f"Bearer {_PP_CALLER_PAT}", "교환은 호출자가 낸 Authorization 그대로다"
    assert ex["json"] == _PP_WANTED, "바람이 명세 안이면 본문은 바란 것과 같다"
    assert "x-heax-gateway-secret" not in ex["headers"] and "heax-svc-pat" not in json.dumps(ex), "포털에 앱 비밀을 보내지 않는다"
    rg = got["register"][0]
    assert rg["json"] == {"pat": _PP_NEW_PAT}
    h = rg["headers"]
    assert (h["x-heax-gateway-secret"], h["x-heax-user-email"], h[gw.DELEGATE_HEADER.lower()], h["x-heax-client"],
            h["authorization"]) == ("rs", "a@corp.com", "a@corp.com", "deliberation", "Bearer heax-svc-pat"), \
        "등록은 단언 발급과 같은 헤더로 간다(Caddy 문 · 앱 비밀 · 위임 이메일)"
    assert _PP_CALLER_PAT not in json.dumps(got["register"]), "호출자의 원 PAT 는 앱으로 가지 않는다 — 좁힌 PAT 만"
    assert row["ok"] is True and row["mode"] == "as-user-pat" and row["note"] == "portal-pat:registered", row


def _pp_jwt(aud, **extra) -> str:
    seg = base64.urlsafe_b64encode(json.dumps({"aud": aud, "email": "a@corp.com", **extra}).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJSUzI1NiJ9.{seg}.SIGNATURE"


@pytest.mark.parametrize("caller_aud, sent", [(["mcp-gateway", "heax-hub"], ["mcp-gateway"]),
                                              (["mcp-gateway", "step-forge"], ["mcp-gateway", "step-forge"])])
def test_바란_청중은_호출자_PAT_의_청중과_겹치는_것만_교환에_싣는다(monkeypatch, caller_aud, sent):
    """앱은 REST 다리(step-forge)까지 바란다. step-forge 가 없는 옛 PAT 로 그대로 부르면 포털이 widen_audience 로 통째 거절한다 —
    겹치는 청중만 실어 교환은 되게 한다(context-notes C-10). 둘 다 있으면 둘 다 싣는다."""
    res, ev, got, row = _pp_kit(monkeypatch, auth=f"Bearer {_pp_jwt(caller_aud)}",
                                wanted={**_PP_WANTED, "audiences": ["mcp-gateway", "step-forge"]})
    assert not res.isError and ev == ["mint", "exchange", "register", "call"], ev
    assert got["exchange"][0]["json"]["audiences"] == sent, got["exchange"][0]["json"]


def test_겹치는_청중이_없으면_교환하지_않는다(monkeypatch):
    res, ev, got, row = _pp_kit(monkeypatch, auth=f"Bearer {_pp_jwt('heax-hub')}",
                                wanted={**_PP_WANTED, "audiences": ["mcp-gateway"]})
    assert not res.isError and ev == ["mint", "call"], ev
    assert row["note"] == "portal-pat:skipped-no-audience", row


def test_교환_본문은_명세_안에서만_만들고_바람의_다른_칸은_포털에_보내지_않는다(monkeypatch):
    """앱이 넓게 바라도(남의 이름·명세 밖 청중·쓰기 범위·10년) 본문은 운영자가 박은 명세를 넘지 못한다(D1). 바람의 `reason`·
    `require_audiences`·모르는 칸은 포털 계약에 없다 — 보내지 않는다. `min_remaining_s` 는 0 이상 정수일 때만 싣는다."""
    wide = {"name": "evil-admin", "audiences": ["mcp-gateway", "step-forge", "heax-hub", "mcp-gateway"],
            "scopes": ["read", "write"], "ttl_days": 3650, "min_remaining_s": 3600, "reason": "absent",
            "require_audiences": [], "extra": {"x": 1}}
    res, ev, got, row = _pp_kit(monkeypatch, auth=f"Bearer {_pp_jwt(['mcp-gateway', 'step-forge', 'heax-hub'])}",
                                wanted=wide)
    assert not res.isError and ev == ["mint", "exchange", "register", "call"], ev
    assert got["exchange"][0]["json"] == {"name": "hwax-risk", "audiences": ["mcp-gateway", "step-forge"], "scopes": ["read"],
                                          "ttl_days": 90, "min_remaining_s": 3600}
    assert row["note"] == "portal-pat:registered", row


@pytest.mark.parametrize("ttl, mr, want_ttl, has_mr", [(30, 0, 30, True), (None, -1, 90, False), (0, True, 90, False),
                                                       ("30", "60", 90, False), (True, 1.5, 90, False)])
def test_교환_수명은_바람과_명세의_상한_중_짧은_것이다(monkeypatch, ttl, mr, want_ttl, has_mr):
    wanted = {**_PP_WANTED, "min_remaining_s": mr}
    if ttl is None:
        del wanted["ttl_days"]
    else:
        wanted["ttl_days"] = ttl
    res, ev, got, row = _pp_kit(monkeypatch, wanted=wanted)
    body = got["exchange"][0]["json"]
    assert body["ttl_days"] == want_ttl and ("min_remaining_s" in body) == has_mr, body


@pytest.mark.parametrize("spec, note", [
    (None, "portal-pat:skipped-no-spec"),
    ({"name": "hwax-risk", "audiences": ["mcp-gateway"], "scopes": ["read"]}, "portal-pat:skipped-bad-spec"),
    ({"name": " ", "audiences": ["mcp-gateway"], "scopes": ["read"], "max_ttl_days": 90}, "portal-pat:skipped-bad-spec"),
    ({**_PP_SPEC, "max_ttl_days": True}, "portal-pat:skipped-bad-spec"),
    ({**_PP_SPEC, "scopes": "read"}, "portal-pat:skipped-bad-spec"),
])
def test_명세가_없거나_틀리면_교환하지_않고_앱에_설정_탓이라고_알린다(monkeypatch, spec, note):
    """명세가 없으면 앱이 바란 그대로 보내지 않는다. 그러나 조용히 건너뛰면 앱은 'Claude 에서 부르면 등록된다' 고 계속 안내하고
    due 는 영영 참이다(반대 검토 R2-4) — 앱에 gateway_misconfigured 를 알린다(포털은 부르지 않는다)."""
    res, ev, got, row = _pp_kit(monkeypatch, spec=spec)
    assert not res.isError and ev == ["mint", "register", "call"], ev
    assert got["exchange"] == [] and got["register"][0]["json"]["error"] == "gateway_misconfigured", got
    assert "pat" not in got["register"][0]["json"]
    assert row["note"] == note, row


@pytest.mark.parametrize("spec, note", [
    ({**_PP_SPEC, "scopes": ["admin"]}, "portal-pat:skipped-no-scope"),
    ({**_PP_SPEC, "audiences": ["heax-hub"]}, "portal-pat:skipped-no-audience"),
])
def test_겹침이_비면_교환하지_않고_앱에도_알리지_않는다(monkeypatch, spec, note):
    """범위·청중 겹침이 비면 포털을 부르지 않는다(넓히기로 거절될 뿐이다)."""
    res, ev, got, row = _pp_kit(monkeypatch, spec=spec)
    assert not res.isError and ev == ["mint", "call"], ev
    assert row["note"] == note, row


def test_명세_없는_앱은_기동에서_경고_목록에_든다(monkeypatch):
    monkeypatch.setattr(gw, "PER_USER_SSO", {
        "hwax_risk": {**_RISK_SSO, "portal_pat_url": _PP_URL},
        "ok_app": {**_RISK_SSO, "portal_pat_url": _PP_URL, "portal_pat_spec": _PP_SPEC},
        "plain": dict(_RISK_SSO)})
    assert gw._portal_pat_misconfigured() == ["hwax_risk"]


@pytest.mark.parametrize("caller_aud, spec_auds, need, note", [
    (["mcp-gateway"], None, ["step-forge"], "portal-pat:skipped-aud-unavailable"),
    (None, None, ["step-forge"], "portal-pat:skipped-aud-unavailable"),
    (["mcp-gateway", "step-forge"], ["mcp-gateway"], ["step-forge"], "portal-pat:skipped-aud-unavailable"),
    (["mcp-gateway", "step-forge"], None, ["step-forge"], "portal-pat:registered"),
    (["mcp-gateway"], None, [], "portal-pat:registered"),
    (None, None, [], "portal-pat:registered"),
])
def test_앱이_요구한_청중을_줄_수_없으면_포털을_부르지_않는다(monkeypatch, caller_aud, spec_auds, need, note):
    """등록된 PAT 에 step-forge 가 없어서 바란 것이면(`require_audiences`), 원 PAT 에 그 청중이 없는 사람의 교환은 아무것도 고치지
    못하고 단언을 받을 때마다 되풀이된다(BEH-1). 호출자 청중을 못 읽어도(None) 줄 수 있는지 모르므로 하지 않는다. 명세가 그 청중을
    빼도 같다. 비어 있으면 요구가 없는 것이다."""
    auth = f"Bearer {_pp_jwt(caller_aud)}" if caller_aud is not None else f"Bearer {_PP_CALLER_PAT}"
    spec = _PP_SPEC if spec_auds is None else {**_PP_SPEC, "audiences": spec_auds}
    res, ev, got, row = _pp_kit(monkeypatch, auth=auth, spec=spec,
                                wanted={**_PP_WANTED, "audiences": ["mcp-gateway", "step-forge"], "require_audiences": need})
    assert not res.isError and row["note"] == note, row
    if note.endswith("aud-unavailable"):
        assert ev == ["mint", "call"], ev
    else:
        assert "require_audiences" not in got["exchange"][0]["json"], "포털 계약에 없는 칸이다"


@pytest.mark.parametrize("par", ["j-root", ""])
def test_교환으로_받은_자식_PAT_로_들어온_호출은_교환하지_않고_앱에도_알리지_않는다(monkeypatch, par):
    """포털은 교환 PAT 에 `par`(원 jti)를 찍고 그것을 원으로 받지 않는다(포털 C-7). 그 PAT 로 들어온 호출은 대개 앱이 그 사람
    자격으로 게이트웨이를 다시 부른 것이다 — 교환하면 거절이 앱에 가서 앱이 실패 쉼에 든다(D5). 값이 비어도 칸이 있으면 자식이다."""
    res, ev, got, row = _pp_kit(monkeypatch, auth=f"Bearer {_pp_jwt(['mcp-gateway', 'step-forge'], par=par)}")
    assert not res.isError and ev == ["mint", "call"], ev
    assert row["note"] == "portal-pat:skipped-child", row


def test_앱이_바라지_않으면_교환하지_않는다(monkeypatch):
    res, ev, got, row = _pp_kit(monkeypatch, wanted=None)
    assert not res.isError and ev == ["mint", "call"], ev
    assert "note" not in row, row


@pytest.mark.parametrize("via, auth", [("gw-token", "Bearer gw-secret"), ("chat", f"Bearer {_PP_CALLER_PAT}"),
                                       ("procedure", f"Bearer {_PP_CALLER_PAT}"), ("", f"Bearer {_PP_CALLER_PAT}")])
def test_포털_PAT_로_들어온_호출이_아니면_교환하지_않는다(monkeypatch, via, auth):
    """GW_TOKEN(에이전트 서버)은 넘길 사람의 PAT 가 없다 — Authorization 이 GW_TOKEN 이다. 웹 챗·절차 PAT 는 포털이 원으로 받지 않으니
    (기록되지 않은 PAT) 부르지 않는다 — 그 거절을 앱에 알리면 앱이 실패 쉼에 들어 Claude 길의 교환까지 막힌다."""
    res, ev, got, row = _pp_kit(monkeypatch, via=via, auth=auth)
    assert not res.isError and ev == ["mint", "call"], ev
    assert row["note"] == f"portal-pat:skipped-{via or 'no-via'}", row



def test_건네기가_읽는_Authorization_은_미들웨어가_검증한_그_원본이다(monkeypatch):
    """건네기는 요청의 Authorization 을 호출자 PAT 로 포털에 보낸다 — PAT 분기가 그 헤더를 바꾸거나 더하지 않아야 포털이 받는 것이
    게이트웨이가 검증한 바로 그 토큰이다(두 번 실린 요청은 미들웨어가 401 로 막는다). via=pat 도 그 분기만 싣는다(위 시험)."""
    seen = {}

    async def app(scope, receive, send):
        seen["h"] = list(scope["headers"])

    async def fake_access(email, base, **_kw):
        return {"keys": []}
    monkeypatch.setattr(gw, "_portal_access", fake_access)
    monkeypatch.setattr(gw, "GW_TOKEN", "gw-secret")

    class _V:
        async def verify(self, token, aud):
            return {"email": "u@x.io", "groups": []} if token == _PP_CALLER_PAT else None
    asyncio.run(gw._bearer_gate(app, _V())({"type": "http", "path": "/mcp", "headers": [
        (b"authorization", f"Bearer {_PP_CALLER_PAT}".encode())]}, None, None))
    assert [v for k, v in seen["h"] if k.lower() == b"authorization"] == [f"Bearer {_PP_CALLER_PAT}".encode()]
    assert [v for k, v in seen["h"] if k.lower() == gw.VIA_HEADER.encode()] == [b"pat"]

def test_요청_문맥이_없는_발급은_교환하지_않는다(monkeypatch):
    """REST 다리(`_rest_mint`)처럼 MCP 요청 밖에서 도는 발급 — 호출자 PAT 를 쥐고 있지 않다."""
    _pp_kit(monkeypatch)                                     # 상류·설정만 세운다(이 호출의 결과는 보지 않는다)
    monkeypatch.setattr(gw, "_USER_PATS", {})
    monkeypatch.setattr(gw, "_PORTAL_PAT_TRIED", {})

    class _NoCtx:
        @property
        def request_context(self):
            raise LookupError
    monkeypatch.setattr(gw, "_low", _NoCtx())
    notes: list = []
    assert asyncio.run(gw._user_pat("hwax_risk", "a@corp.com", notes=notes)).startswith("rrsso_")
    assert notes == ["portal-pat:skipped-no-request"]


def test_교환이_거절되면_앱에_사유를_알리고_도구_호출은_그대로_간다(monkeypatch):
    def refuse(req):
        return httpx.Response(403, json={"detail": {"code": "source_not_exchangeable", "message": "기록되지 않은 PAT"}})
    res, ev, got, row = _pp_kit(monkeypatch, exchange=refuse)
    assert not res.isError and ev == ["mint", "exchange", "register", "call"], ev
    assert got["register"][0]["json"] == {"error": "source_not_exchangeable", "message": "기록되지 않은 PAT"}
    assert row["ok"] is True and row["note"] == "portal-pat:exchange-source_not_exchangeable", row


def test_교환_응답이_시간_초과면_그_까닭을_앱에_알린다(monkeypatch):
    def late(req):
        raise httpx.ReadTimeout("slow", request=req)
    res, ev, got, row = _pp_kit(monkeypatch, exchange=late)
    assert not res.isError and got["register"][0]["json"]["error"] == "timeout"
    assert row["note"] == "portal-pat:exchange-timeout", row


@pytest.mark.parametrize("status, body, want", [
    (403, {"detail": {"code": "source_not_exchangeable", "message": "m"}}, ("source_not_exchangeable", "m")),
    (401, {"detail": "invalid_token"}, ("invalid_token", "invalid_token")),
    (401, {"detail": "토큰이 틀렸다"}, ("http_401", "토큰이 틀렸다")),
    (422, {"detail": [{"loc": ["body", "ttl_days"], "msg": "x"}]}, ("http_422", "포털이 교환을 거절했다(HTTP 422)")),
    (502, "<html>bad gateway</html>", ("http_502", "포털이 교환을 거절했다(HTTP 502)")),
    (403, {"detail": {"code": "a b; c", "message": "m"}}, ("http_403", "m")),
])
def test_포털_거절은_코드_꼴만_감사_code_로_쓴다(status, body, want):
    resp = (httpx.Response(status, json=body) if not isinstance(body, str) else httpx.Response(status, text=body))
    assert gw._portal_pat_refusal(resp) == want


def test_앱_등록이_실패해도_도구_호출은_가고_감사에_남는다(monkeypatch):
    res, ev, got, row = _pp_kit(monkeypatch, register=lambda req: httpx.Response(422, json={"detail": "pat_invalid"}))
    assert not res.isError and ev == ["mint", "exchange", "register", "revoke", "call"], ev
    assert row["ok"] is True and row["note"] == "portal-pat:register-422+portal-pat:revoked-unused", row


def _pp_raise(exc_type):
    def f(req):
        raise exc_type("x", request=req)
    return f


@pytest.mark.parametrize("register, note", [
    (lambda req: httpx.Response(409, json={"detail": {"code": "portal_pat_auto_off", "message": "m"}}), "portal-pat:register-409"),
    (_pp_raise(httpx.ConnectError), "portal-pat:register-unreachable"),
])
def test_앱이_새_PAT_를_받지_못하면_그_PAT_스스로_폐기한다(monkeypatch, register, note):
    """교환은 됐는데 앱이 **확실히** 받지 않으면(4xx 거절·앱에 닿지 못한 연결 실패) 새 PAT 는 아무도 쥐지 않은 채 원 PAT 만큼
    (최대 90일) 산다(SEC-1). 포털 `/auth/pat/revoke-self` 를 **그 새 PAT** 를 Bearer 로 불러 스스로 폐기한다 — 호출자의 원 PAT 를
    쓰면 원이 폐기된다."""
    res, ev, got, row = _pp_kit(monkeypatch, register=register)
    assert not res.isError and ev == ["mint", "exchange", "register", "revoke", "call"], ev
    rv = got["revoke"][0]
    assert rv["headers"]["authorization"] == f"Bearer {_PP_NEW_PAT}", "폐기는 새 PAT 자신으로 한다"
    assert _PP_CALLER_PAT not in json.dumps(rv), "호출자의 원 PAT 로 폐기하면 원이 죽는다"
    assert row["ok"] is True and row["note"] == f"{note}+portal-pat:revoked-unused", row


async def _pp_never(req):
    await asyncio.sleep(30)


@pytest.mark.parametrize("revoke", [lambda req: httpx.Response(401, json={"detail": {"code": "invalid_token", "message": "m"}}),
                                    _pp_raise(httpx.ConnectError), _pp_raise(httpx.ReadTimeout), _pp_never])
def test_폐기가_실패하면_그렇다고_감사에_남기고_한도_안에서_끝난다(monkeypatch, revoke):
    monkeypatch.setattr(gw, "_PORTAL_PAT_BUDGET_S", 0.8)
    t0 = _clock.monotonic()
    res, ev, got, row = _pp_kit(monkeypatch, register=lambda req: httpx.Response(422, text="no"), revoke=revoke)
    assert _clock.monotonic() - t0 < 5, "폐기가 도구 호출을 한도 넘게 붙들었다"
    assert not res.isError and ev[-1] == "call" and ev.count("revoke") == 1, ev
    assert row["note"] == "portal-pat:register-422+portal-pat:revoke-failed", row


@pytest.mark.parametrize("register, note", [
    (lambda req: httpx.Response(503, text="down"), "portal-pat:register-503"),
    (lambda req: httpx.Response(500, text="boom"), "portal-pat:register-500"),
    (_pp_raise(httpx.ReadTimeout), "portal-pat:register-timeout"),
    (_pp_raise(httpx.RemoteProtocolError), "portal-pat:register-unreachable"),
])
def test_앱이_받았는지_모르면_새_PAT_를_폐기하지_않는다(monkeypatch, register, note):
    """5xx·읽기 시간 초과·도중 끊김은 앱이 이미 받아 저장하고 옛 PAT 를 폐기했을 수 있다. 그때 새것까지 폐기하면 둘 다 죽어
    도는 카드 대조가 credential 보류(자동 재개 없음)로 멈춘다 — 결과를 모르면 두고, 남은 토큰은 원 PAT 수명과 자식 상한이 묶는다."""
    res, ev, got, row = _pp_kit(monkeypatch, register=register)
    assert not res.isError and "revoke" not in ev and got["revoke"] == [], ev
    assert row["note"] == note, row


@pytest.mark.parametrize("exchange, register", [(_pp_ok, None),
                                                (_pp_raise(httpx.ReadTimeout), lambda req: httpx.Response(503, text="x"))])
def test_앱이_받았거나_받은_새_PAT_가_없으면_폐기하지_않는다(monkeypatch, exchange, register):
    res, ev, got, row = _pp_kit(monkeypatch, exchange=exchange, register=register)
    assert "revoke" not in ev and got["revoke"] == [], ev


@pytest.mark.parametrize("hang", ["exchange", "register"])
def test_교환과_등록은_시간_한도_안에서_끝나고_도구_호출을_붙들지_않는다(monkeypatch, hang):
    """가짜 전송은 httpx 의 요청 한도를 모른다 — 응답을 끝없이 미루는 상류에서 전체 한도(_PORTAL_PAT_BUDGET_S)만으로 끝나야 한다.
    등록이 한도를 다 써도 교환으로 받은 새 PAT 는 남은 몫(_PORTAL_PAT_REVOKE_SHARE) 안에서 폐기한다 — 폐기도 실제 왕복처럼 잠깐
    걸리게 둔다(곧바로 답하는 가짜는 이벤트 루프에 양보하지 않아 0초 몫으로도 통과한다 — 변이로 확인)."""
    monkeypatch.setattr(gw, "_PORTAL_PAT_BUDGET_S", 0.8)

    async def never(req):
        await asyncio.sleep(30)

    async def revoke(req):
        await asyncio.sleep(0.05)
        return httpx.Response(200, json={"revoked": "j-1"})
    t0 = _clock.monotonic()
    res, ev, got, row = _pp_kit(monkeypatch, revoke=revoke, **{hang: never})
    assert _clock.monotonic() - t0 < 5, "건네기가 도구 호출을 한도 넘게 붙들었다"
    assert not res.isError and ev[-1] == "call" and ev.count("call") == 1, ev
    if hang == "exchange":
        assert row["note"] == "portal-pat:exchange-timeout", row
        assert got["register"] == [] and got["revoke"] == [], "한도를 다 쓴 뒤에는 등록을 보내지 않고, 받은 PAT 가 없으니 폐기도 없다"
    else:
        # 등록이 한도를 다 쓰면 앱이 받았는지 모른다 — 폐기하지 않는다(받았다면 새것까지 죽여 둘 다 잃는다).
        assert row["note"] == "portal-pat:register-timeout", row
        assert got["revoke"] == [], got["revoke"]


def test_토큰_재발급이_같은_사람의_교환을_되풀이하지_않는다(monkeypatch):
    """앱이 캐시 단언을 401 로 거절하면 같은 호출이 한 번 다시 발급한다(종전 규칙). 그 발급도 PAT 를 바라지만 방금 건넸으니 쉰다."""
    res, ev, got, row = _pp_kit(monkeypatch, backend_rejects_first=True)
    assert not res.isError, res.content[0].text
    assert ev == ["mint", "exchange", "register", "call", "mint", "call"], ev
    assert row["note"] == "re-minted+portal-pat:registered+portal-pat:skipped-cooldown", row


def _pp_echo(req):
    """거절 글에 받은 Authorization(호출자의 원 PAT)을 되울리는 포털 앞단."""
    return httpx.Response(401, json={"detail": {"code": "invalid_token", "message": f"거절 — {req.headers['authorization']}"}})


@pytest.mark.parametrize("exchange, register, note", [
    (_pp_ok, None, "portal-pat:registered"),
    (_pp_echo, None, "portal-pat:exchange-invalid_token"),
    (_pp_ok, lambda req: httpx.Response(422, text="no"), "portal-pat:register-422+portal-pat:revoked-unused"),
    (_pp_ok, lambda req: httpx.Response(422, text="no"), "portal-pat:register-422+portal-pat:revoke-failed"),
])
def test_건네기는_토큰_값을_로그에도_감사에도_적지_않는다(monkeypatch, caplog, exchange, register, note):
    """두 토큰(호출자의 원 PAT · 바꿔 받은 PAT) 어느 것도 글자로 남지 않는다. 포털 거절 글이 원 PAT 를 되울려도 앱으로 넘기지 않는다.
    폐기 길(새 PAT 를 Bearer 로 싣는다)이 실패해도 같다 — 폐기 응답이 그 PAT 를 되울려도 적지 않는다."""
    import logging
    caplog.set_level(logging.DEBUG)

    def revoke_echo(req):
        return httpx.Response(401, json={"detail": {"code": "invalid_token", "message": req.headers["authorization"]}})
    res, ev, got, row = _pp_kit(monkeypatch, exchange=exchange, register=register,
                                revoke=revoke_echo if note.endswith("revoke-failed") else None)
    assert not res.isError and row["note"] == note, row
    assert _PP_CALLER_PAT not in json.dumps(got["register"], ensure_ascii=False), got["register"]
    audit = open(gw.AUDIT_PATH, encoding="utf-8").read()
    for secret in (_PP_CALLER_PAT, _PP_NEW_PAT):
        assert secret not in caplog.text, f"로그에 토큰이 있다: {secret}"
        assert secret not in audit, f"감사에 토큰이 있다: {secret}"


# ── 건네지 못한 바람은 캐시된 단언 뒤에 묻히지 않는다(반대 검토 SEC-3·BEH-5) ──────────────────────────────────────────────
# 앱은 발급 응답에만 바람을 싣는다. 그 발급이 GW_TOKEN·챗·REST 다리·쉼 안·잠깐의 실패로 건네지 못하면, 단언이 캐시에 사는 동안
# (hwax_risk 900초 − 2분) 포털 PAT 로 온 같은 사람의 호출도 발급을 거치지 않아 건네지 못했다.
@pytest.mark.parametrize("via, auth", [("gw-token", "Bearer gw-secret"), ("chat", f"Bearer {_PP_CALLER_PAT}")])
def test_건네지_못한_바람은_캐시된_단언으로_가는_다음_포털_PAT_호출이_건넨다(monkeypatch, via, auth):
    call, ev, got, _ = _pp_setup(monkeypatch)
    _, row = call(via=via, auth=auth)
    assert ev == ["mint", "call"] and row.get("note") == f"portal-pat:skipped-{via}", (ev, row)
    del ev[:]
    _, row = call(via=via, auth=auth)
    assert ev == ["call"] and row.get("note") is None, "포털 PAT 가 아닌 호출은 남은 바람을 조용히 둔다(호출마다 같은 줄을 붙이지 않는다)"
    del ev[:]
    _, row = call(auth=f"Bearer {_pp_jwt(['mcp-gateway'], par='j-root')}")
    assert ev == ["call"] and row.get("note") is None, "교환 자식으로 온 호출도 건네지 않고 바람을 남긴다"
    del ev[:]
    _, row = call()
    assert ev == ["exchange", "register", "call"], "캐시된 단언 그대로(발급 없이) 남은 바람을 건넨다"
    assert row.get("note") == "portal-pat:registered" and got["register"][-1]["json"] == {"pat": _PP_NEW_PAT}
    del ev[:]
    _, row = call()
    assert ev == ["call"] and row.get("note") is None, "등록됐으면 바람을 지운다"
    assert not gw._PORTAL_PAT_PENDING


def _pp_age_cooldown(email="a@corp.com"):
    gw._PORTAL_PAT_TRIED[("hwax_risk", email)] -= gw._PORTAL_PAT_COOLDOWN_S + 1


@pytest.mark.parametrize("fail, note", [
    ({"exchange": _pp_raise(httpx.ReadTimeout)}, "portal-pat:exchange-timeout"),
    ({"exchange": _pp_raise(httpx.ConnectError)}, "portal-pat:exchange-unreachable"),
    ({"exchange": lambda req: httpx.Response(502, text="bad gateway")}, "portal-pat:exchange-http_502"),
    ({"register": lambda req: httpx.Response(503, text="down")}, "portal-pat:register-503"),
    ({"register": _pp_raise(httpx.ConnectError)}, "portal-pat:register-unreachable+portal-pat:revoked-unused"),
])
def test_잠깐의_실패는_바람을_남겨_쉼이_지난_뒤_캐시_길에서_다시_건넨다(monkeypatch, fail, note):
    call, ev, got, state = _pp_setup(monkeypatch, **fail)
    _, row = call()
    assert row.get("note") == note, row
    del ev[:]
    _, row = call()
    assert ev == ["call"] and row.get("note") is None, "쉼(5분) 안에는 다시 하지 않고 줄도 붙이지 않는다"
    state.update(exchange=_pp_ok, register=None)
    _pp_age_cooldown()
    del ev[:]
    _, row = call()
    assert ev == ["exchange", "register", "call"] and row.get("note") == "portal-pat:registered", (ev, row)


@pytest.mark.parametrize("fail", [
    {"exchange": lambda req: httpx.Response(403, json={"detail": {"code": "source_not_exchangeable", "message": "m"}})},
    {"exchange": lambda req: httpx.Response(409, json={"detail": {"code": "too_many_children", "message": "m"}})},
    {"register": lambda req: httpx.Response(422, json={"detail": "pat_invalid"})},
    {"spec": {**_PP_SPEC, "scopes": ["admin"]}},
])
def test_거절이나_설정_탓이면_바람을_남기지_않는다(monkeypatch, fail):
    """포털 거절은 앱에 알렸고(앱이 실패 쉼에 든다) 다시 해도 같다. 앱의 등록 거절(4xx)·명세 밖도 같다."""
    call, ev, got, _ = _pp_setup(monkeypatch, **fail)
    call()
    assert not gw._PORTAL_PAT_PENDING
    if ("hwax_risk", "a@corp.com") in gw._PORTAL_PAT_TRIED:
        _pp_age_cooldown()                         # 쉼 때문에 안 하는 것이 아니다
    del ev[:]
    _, row = call()
    assert ev == ["call"] and row.get("note") is None, (ev, row)


def test_다음_발급이_바람을_싣지_않으면_남은_바람을_지운다(monkeypatch):
    call, ev, got, state = _pp_setup(monkeypatch)
    call(via="gw-token", auth="Bearer gw-secret")
    assert list(gw._PORTAL_PAT_PENDING) == [("hwax_risk", "a@corp.com")]
    state["wanted"] = None
    gw._USER_PATS[("hwax_risk", "a@corp.com")] = ("old", 0.0)     # 단언 캐시가 끝났다 — 다음 호출이 다시 발급한다
    del ev[:]
    call(via="gw-token", auth="Bearer gw-secret")
    assert ev == ["mint", "call"] and not gw._PORTAL_PAT_PENDING
    del ev[:]
    _, row = call()
    assert ev == ["call"] and row.get("note") is None, "앱이 더는 바라지 않는다 — 낡은 바람으로 교환하지 않는다"


def test_남은_바람은_상한을_넘으면_오래된_것부터_버린다(monkeypatch):
    _pp_setup(monkeypatch)
    monkeypatch.setattr(gw, "_PORTAL_PAT_PENDING_MAX", 3)
    _set_request(monkeypatch, {"authorization": "Bearer gw-secret", gw.VIA_HEADER: "gw-token"}, "203.0.113.9")
    for i in range(5):
        asyncio.run(gw._portal_pat_serve("hwax_risk", f"u{i}@corp.com", dict(_PP_WANTED), None, cached=False))
    assert list(gw._PORTAL_PAT_PENDING) == [("hwax_risk", f"u{i}@corp.com") for i in (2, 3, 4)]
    asyncio.run(gw._portal_pat_serve("hwax_risk", "u2@corp.com", dict(_PP_WANTED), None, cached=True))
    asyncio.run(gw._portal_pat_serve("hwax_risk", "u5@corp.com", dict(_PP_WANTED), None, cached=False))
    assert list(gw._PORTAL_PAT_PENDING) == [("hwax_risk", f"u{i}@corp.com") for i in (4, 2, 5)], "손댄 것은 뒤로 간다"


# ── REST 프록시의 상류 한도 — 안쪽이 바깥보다 짧다(반대 검토 BEH-3) ─────────────────────────────────────────────────────────
# 리스크 앱은 원천 호출을 120초 기다린다. 위임 캡처가 게이트웨이 /api/step-forge 로 큰 트리를 읽으면 이 프록시만 30초에 끊고 502
# `upstream unreachable` 이라고 말했다 — 같은 트리를 앱이 직접 읽으면 통했다.
def test_REST_프록시_상류_한도의_기본값과_손잡이(tmp_path):
    assert _limits(tmp_path, ["REST_PROXY_UPSTREAM_TIMEOUT_S"])[0] == {"REST_PROXY_UPSTREAM_TIMEOUT_S": 110.0}
    assert _limits(tmp_path, ["REST_PROXY_UPSTREAM_TIMEOUT_S"], **_KNOBS_SET)[0] == {"REST_PROXY_UPSTREAM_TIMEOUT_S": 45.0}
    t = rest_proxy.RestProxy({"s": {"base": "http://upstream.invalid"}}, {"audience_ok": ["s"]}, gw._audit)._client.timeout
    want = rest_proxy.REST_PROXY_UPSTREAM_TIMEOUT_S
    assert (t.read, t.write, t.pool, t.connect) == (want, want, want, 30.0), "연결은 죽은 상대를 재는 값이라 종전 30초 그대로다"


def test_REST_프록시_상류_한도는_리스크_앱의_원천_호출_한도보다_짧다(tmp_path):
    """안쪽이 먼저 걸려야 원인을 말하는 쪽이 이 길이다(시간 한도는 층이다). 형제 리포가 있을 때만 본다."""
    import re
    from pathlib import Path
    src = Path(gw.__file__).resolve().parent.parent / "HWAXRisk" / "backend" / "app" / "config.py"
    if not src.exists():
        pytest.skip("형제 HWAXRisk 리포가 없다")
    outer = int(re.search(r"^DEFAULT_SOURCE_CALL_TIMEOUT_S\s*=\s*(\d+)", src.read_text(encoding="utf-8"), re.M).group(1))
    assert _limits(tmp_path, ["REST_PROXY_UPSTREAM_TIMEOUT_S"])[0]["REST_PROXY_UPSTREAM_TIMEOUT_S"] < outer, \
        f"리스크 앱이 {outer}초에 먼저 끊는다 — 이 프록시의 기본 상류 한도를 그 밑으로 둔다"


@pytest.mark.parametrize("exc, status", [(httpx.ReadTimeout, 504), (httpx.WriteTimeout, 504), (httpx.PoolTimeout, 504),
                                         (httpx.ConnectTimeout, 502), (httpx.ConnectError, 502)])
def test_REST_프록시는_상류가_한도_안에_답하지_않으면_504_로_손잡이를_말한다(monkeypatch, exc, status):
    """느린 것(504, 손잡이와 초)과 안 닿는 것(502)을 가른다 — 종전엔 둘 다 502 `upstream unreachable` 이었다."""
    from starlette.requests import Request
    p = rest_proxy.RestProxy({"s": {"base": "http://upstream.invalid"}}, {"audience_ok": ["s"]}, gw._audit)
    p._verify = lambda token, s: {"sub": "S-1", "email": "u@corp.com", "jti": "j", "groups": []}
    p._revoked_set = _noop_async(set())

    async def slow(req, stream=False):
        raise exc("x", request=req)
    monkeypatch.setattr(p._client, "send", slow)
    resp = asyncio.run(p.handle(Request({
        "type": "http", "method": "GET", "path": "/api/s/tree", "headers": [(b"authorization", b"Bearer me")],
        "query_string": b"", "path_params": {"site": "s", "path": "tree"}, "client": ("203.0.113.5", 0)})))
    body = json.loads(resp.body)
    assert resp.status_code == status, body
    if status == 504:
        knob = f"{rest_proxy.REST_PROXY_UPSTREAM_TIMEOUT_S:g}초 안에 답하지 않았다(REST_PROXY_UPSTREAM_TIMEOUT_S)"
        assert body["error"] == "upstream timeout" and knob in body["detail"], body
        assert knob in _rows()[-1]["error"], "감사에도 손잡이를 남긴다"
    else:
        assert body["error"] == "upstream unreachable", body


# ── 인자 설명 점수판(HWAXPortal docs/improvement-1015 §6) ─────────────────────
def _stool(name: str, props: dict | None = None) -> types.Tool:
    """인자 스키마가 있는 가짜 도구. props 의 값은 설명 글(None 이면 설명 없음) 또는 속성 스키마 그대로다."""
    p = {k: (v if isinstance(v, dict) else {"type": "string", **({"description": v} if v is not None else {})})
         for k, v in (props or {}).items()}
    return types.Tool(name=name, description="", inputSchema={"type": "object", "properties": p})


def _aggregate_tools(monkeypatch, spec: dict[str, list[types.Tool]]):
    monkeypatch.setattr(gw, "backends", {k: _B(v) for k, v in spec.items()})
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "route", {})
    monkeypatch.setattr(gw, "alias_route", {})
    asyncio.run(gw._aggregate())


@pytest.fixture
def _fresh_scores(monkeypatch):
    """점수판·'이미 본 앱' 은 프로세스 상태다 — 시험마다 새로 두고, 로컬 도구 수가 설정에 따라 달라지지 않게 REST 를 비운다."""
    monkeypatch.setattr(gw, "_ARG_SCORE", {})
    monkeypatch.setattr(gw, "_ARG_JUDGED", set())
    monkeypatch.setattr(gw, "_ARG_BOOTED", False)
    monkeypatch.setattr(gw, "ARG_DESC_WARN_RATIO", 0.3)
    monkeypatch.setattr(gw, "REST", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})


def test_인자_점수판은_실측처럼_맨_위_속성만_센다():
    """실측(HWAXPortal docs/procedures/gaps/hub-arg-descriptions.yaml)은 `inputSchema.properties[].description` 의 유무를
    셌다. 객체 속성·배열 항목 안으로 내려가면 인자 수가 실측과 다른 눈금이 된다. 공백뿐인 설명·`title`·글이 아닌 설명은
    설명이 아니고, 스키마가 깨진 속성도 인자로는 센다(세다가 죽지 않는다)."""
    t = types.Tool(name="t", description="", inputSchema={"type": "object", "properties": {
        "a": {"type": "string", "description": "부품 이름(글롭)"},
        "b": {"type": "string", "description": "   "},
        "c": {"type": "string", "title": "C"},
        "d": {"type": "object", "properties": {"x": {"type": "number", "description": "안쪽 설명"},
                                                "y": {"type": "number", "description": "안쪽 설명"}}},
        "e": {"type": "array", "items": {"type": "object", "properties": {"z": {"description": "항목 설명"}}}},
        "f": True,
        "g": {"description": 7, "anyOf": 5, "items": "x"},
    }})
    assert gw._arg_counts(t) == (7, 1, 0)
    assert gw._arg_counts(types.Tool(name="u", description="", inputSchema={"type": "object"})) == (0, 0, 0)
    assert gw._arg_counts(types.Tool(name="v", description="", inputSchema={"type": "object", "properties": []})) == (0, 0, 0)


@pytest.mark.parametrize("desc", [
    "판 두께 [mm]", "길이(mm)", "10mm 간격", "탄성계수 MPa", "시간 한도 30 s", "30초 뒤 끊는다", "각도 deg", "회전 90°",
    "가중치 %", "샘플링 주파수 Hz", "이완 시정수 [s]", "온도 ℃", "2시간", "120자까지", "timeout in seconds",
    "0 이상", "100 이하", "허용 범위", "최소 1", "최대 20", "min 1", "Max 10", "between 1 and 5", "default 8",
    "Defaults to 10", "포아송비 (-1 < nu < 0.5)", "<= 20", "1~10", "0..1", "기본 8"])
def test_인자_설명의_단위_범위_낱말을_읽는다(desc):
    assert gw._ARG_UNIT_RANGE_RE.search(desc), desc


@pytest.mark.parametrize("desc", [
    "user's name", "도구 이름", "N개의 결과", "초기값을 쓴다", "부분 문자열", "items to return", "날짜 YYYY-MM-DD",
    "name(s) of tools", "Page token", "1st item", "admin account", "max_results 와 같다", "이상치 제거 여부", "검색어"])
def test_단위_범위가_아닌_설명은_세지_않는다(desc):
    m = gw._ARG_UNIT_RANGE_RE.search(desc)
    assert m is None, f"{desc!r} 에서 {m.group(0)!r} 를 단위·범위로 읽었다"


def test_허용값을_스키마가_말하면_범위다_다만_설명이_있을_때만():
    """`enum`·숫자 경계(pydantic 의 ge·gt·le·lt)는 낱말이 없어도 범위다. Optional 은 경계를 anyOf 갈래에, 목록은 항목에 둔다.
    기준이 '설명에 단위와 범위' 라 설명 없는 인자는 enum 이 있어도 세지 않는다 — 이 수는 '설명 있음' 을 넘지 않는다."""
    props = {
        "mode": {"type": "string", "enum": ["fast", "exact"], "description": "계산 방식"},
        "k": {"anyOf": [{"type": "number", "exclusiveMinimum": 0, "maximum": 1}, {"type": "null"}], "description": "기울기"},
        "tags": {"type": "array", "items": {"enum": ["a", "b"]}, "description": "고를 꼬리표"},
        "bare_enum": {"type": "string", "enum": ["x", "y"]},
        "plain": {"type": "string", "description": "부품 이름"},
    }
    assert gw._arg_counts(_stool("t", props)) == (5, 4, 3)


def test_가장_나쁜_도구_다섯과_앱_순서():
    """도구는 설명 없는 인자가 많은 순, 같으면 인자가 많은 순, 그다음 이름이다. 설명이 다 있는 도구는 '나쁜 도구' 가 아니다.
    앱은 설명 비율이 낮은 순, 같으면 설명 없는 인자가 많은 순이고, 인자가 없는 앱(비율 없음)은 맨 뒤다."""
    def tool(name, n, d):
        return _stool(name, {f"a{i}": ("설명" if i < d else None) for i in range(n)})
    pairs = ([("A", tool(*x)) for x in (("t_full", 3, 3), ("t5of5", 5, 0), ("t5of8", 8, 3), ("t6", 6, 0), ("t1", 2, 1),
                                        ("t2b", 2, 0), ("t2a", 2, 0), ("t0", 0, 0))]
             + [("B", tool("b1", 4, 2)), ("C", tool("c0", 0, 0)), ("D", tool("d1", 4, 1))])
    board = gw._arg_scoreboard(pairs)
    assert [r["app"] for r in board["apps"]] == ["A", "D", "B", "C"], "A·D 는 둘 다 25% — 설명 없는 인자가 많은 A 가 먼저다"
    a = board["apps"][0]
    assert (a["tools"], a["args"], a["described"], a["described_ratio"]) == (8, 28, 7, 0.25)
    assert a["worst"] == [{"tool": "t6", "args": 6, "described": 0}, {"tool": "t5of8", "args": 8, "described": 3},
                          {"tool": "t5of5", "args": 5, "described": 0}, {"tool": "t2a", "args": 2, "described": 0},
                          {"tool": "t2b", "args": 2, "described": 0}]
    assert board["apps"][-1]["described_ratio"] is None and board["apps"][-1]["worst"] == []
    assert board["total"] == {"apps": 4, "tools": 11, "args": 36, "described": 10, "unit_or_range": 0,
                              "described_ratio": 0.278, "unit_or_range_ratio": 0.0}


def test_tools_map_은_점수판을_덧붙이고_있던_칸은_그대로다(monkeypatch, _fresh_scores):
    """무인증 `/tools-map` 에 `arg_scores` 를 **덧붙인다** — 있던 칸의 이름·순서·뜻은 그대로다. 수만 싣는다: 인자 이름·설명·
    기본값이 새면 무인증 표면에 스키마 내용이 나간다."""
    def tools_map():
        sent = []

        async def send(m): sent.append(m)
        asyncio.run(gw._bearer_gate(None, None)({"type": "http", "path": "/tools-map", "headers": []}, None, send))
        assert sent[0]["status"] == 200
        return json.loads(sent[1]["body"])

    monkeypatch.setattr(gw, "backends", {})
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "route", {})
    empty = tools_map()["arg_scores"]            # 첫 재집계 전에도 모양은 같다
    assert empty["apps"] == [] and empty["total"]["args"] == 0 and empty["total"]["described_ratio"] is None

    leaky = _stool("ra_find", {"workspace_token": {"type": "string", "description": "SECRET-DESC", "default": "SECRET-DEFAULT"},
                               "q": None})
    _aggregate_tools(monkeypatch, {"reportarchive": [leaky, _stool("ra_get", {"id": "보고서 id"})]})
    body = tools_map()
    assert list(body) == ["map", "backends", "apps", "areas", "area_meta", "unclassified", "arg_scores"]
    assert body["map"]["ra_find"] == "reportarchive" and body["map"]["save_conversation"] == "_gateway"
    assert body["backends"] == ["_gateway", "reportarchive"]
    assert {a["app"]: a["tool_count"] for a in body["apps"]} == {"_gateway": 14, "reportarchive": 2}   # 로컬 8 + 분석 루틴 6
    sc = body["arg_scores"]
    assert list(sc) == ["threshold", "total", "apps"] and sc["threshold"] == 0.3
    assert list(sc["total"]) == ["apps", "tools", "args", "described", "unit_or_range", "described_ratio",
                                 "unit_or_range_ratio"]
    row = {r["app"]: r for r in sc["apps"]}["reportarchive"]
    assert list(row) == ["app", "tools", "args", "described", "unit_or_range", "described_ratio",
                         "unit_or_range_ratio", "worst"]
    assert (row["tools"], row["args"], row["described"]) == (2, 3, 2)
    assert row["worst"] == [{"tool": "ra_find", "args": 2, "described": 1}]
    blob = json.dumps(sc, ensure_ascii=False)
    for leak in ("SECRET-DESC", "SECRET-DEFAULT", "workspace_token", "보고서 id"):
        assert leak not in blob, f"점수판에 스키마 내용({leak})이 샜다"


def test_기준_미만으로_처음_붙는_앱만_한_번_경고하고_막지_않는다(monkeypatch, caplog, _fresh_scores):
    """기동(첫 재집계) 때는 기준 **미만** 앱 수를 요약 한 줄로 — 거의 모든 앱이 기준 아래라 앱마다 한 줄이면 기동마다 열댓 줄이 쌓인다.
    그 뒤 새로 붙는 앱은 붙을 때 한 줄(앱 이름·비율·가장 나쁜 도구). 같은 앱은 다시 말하지 않고(재집계는 60초마다 돈다), 기준과
    같으면 말하지 않으며, 0 이면 끈다. 도구는 막지도 숨기지도 않는다."""
    low = [_stool("low_big", {**{f"a{i}": None for i in range(9)}, "z": "설명"}), _stool("low_small", {"q": None})]
    edge = [_stool("edge_t", {f"a{i}": ("설명" if i < 3 else None) for i in range(10)})]     # 정확히 30%
    good = [_stool("good_t", {"a": "설명", "b": None})]
    spec = {"low": low, "edge": edge, "good": good}

    def warned():
        msgs = [r.getMessage() for r in caplog.records]
        assert not [m for m in msgs if "세지 못했다" in m], msgs
        return [m for m in msgs if "인자 설명 부족" in m]

    with caplog.at_level(logging.WARNING, logger="hwax-mcp-gateway"):
        _aggregate_tools(monkeypatch, spec)
        first = warned()
        assert len(first) == 1, first
        assert "기동 때 붙은 앱 4개 가운데 1개가 기준 30% 미만" in first[0], first[0]      # low · edge · good · _gateway
        assert "/tools-map 의 arg_scores" in first[0] and "— low 의" not in first[0], first[0]
        assert {"low_big", "low_small"} <= set(gw.route), "경고한 앱의 도구를 숨겼다"
        assert {"low_big", "low_small"} <= {t.name for t in gw._visible_tools([])}

        caplog.clear()
        _aggregate_tools(monkeypatch, spec)
        assert warned() == [], "같은 앱을 재집계마다 다시 말했다"

        caplog.clear()
        _aggregate_tools(monkeypatch, {**spec, "late": [_stool("late_t", {"x": None, "y": None})]})
        assert len(warned()) == 1 and "— late 의 인자 2개 가운데 설명 있는 것이 0개(0.0%)로 기준 30% 미만" in warned()[0], \
            "나중에 붙은 앱은 붙을 때 한 번, 앱 이름과 비율로 말한다"
        assert "가장 나쁜 도구는 late_t(인자 2개 중 설명 0개)" in warned()[0], warned()[0]

        caplog.clear()
        monkeypatch.setattr(gw, "_ARG_JUDGED", set())
        monkeypatch.setattr(gw, "_ARG_BOOTED", True)
        _aggregate_tools(monkeypatch, spec)
        later = warned()
        assert len(later) == 1 and "— low 의 인자 11개 가운데 설명 있는 것이 1개(9.1%)로 기준 30% 미만" in later[0], later
        assert "가장 나쁜 도구는 low_big(인자 10개 중 설명 1개)" in later[0], later[0]

        caplog.clear()
        monkeypatch.setattr(gw, "_ARG_JUDGED", set())
        monkeypatch.setattr(gw, "_ARG_BOOTED", False)
        monkeypatch.setattr(gw, "ARG_DESC_WARN_RATIO", 0.0)
        _aggregate_tools(monkeypatch, spec)
        assert warned() == [], "0 이면 경고가 꺼진다"


def test_게이트웨이_로컬_도구는_제_앱으로_센다(monkeypatch, _fresh_scores):
    """로컬 도구는 route 에 없다 — `_gateway` 앱으로 세고, tools/list 가 붙이는 것과 같은 목록이다(REST 다리는 사이트가 있을
    때만). 목록이 따로 있으면 점수판이 모델이 보는 것과 어긋난다."""
    for rest, n_local in (({}, 14), ({"s": {"base": "http://x"}}, 16)):      # 로컬 8 + 분석 루틴 6(+ REST 다리 둘)
        monkeypatch.setattr(gw, "REST", rest)
        _aggregate_tools(monkeypatch, {"sf": [_stool("sf_q", {"q": None})]})
        row = {r["app"]: r for r in gw._ARG_SCORE["apps"]}["_gateway"]
        assert {t.name for t in gw._visible_tools([])} - {"sf_q"} == {t.name for t in gw._local_tools()}
        assert row["tools"] == len(gw._local_tools()) == n_local
        assert row["args"] == sum(gw._arg_counts(t)[0] for t in gw._local_tools())
        assert gw._ARG_SCORE["total"]["tools"] == n_local + 1


def test_점수판이_터져도_재집계는_막지_않는다(monkeypatch, caplog, _fresh_scores):
    """보고만 하는 기능이 부팅(첫 재집계)을 죽이면 안 된다 — 백엔드가 이상한 스키마를 내도 카탈로그는 그대로 선다."""
    def boom(pairs):
        raise RuntimeError("bad schema")
    monkeypatch.setattr(gw, "_arg_scoreboard", boom)
    with caplog.at_level(logging.WARNING, logger="hwax-mcp-gateway"):
        _aggregate_tools(monkeypatch, {"sf": [_stool("sf_q", {"q": None})]})
    assert "sf_q" in gw.route, "점수판이 카탈로그를 막았다"
    assert any("인자 설명 점수판을 세지 못했다" in r.getMessage() for r in caplog.records)


# ── search_tools 의미 순위(선택, 기본 꺼짐) — 부분문자열 순위에 임베딩 순위를 RRF 로 더한다(HWAXPortal docs/improvement-1015 §2 4) ──
# 꺼져 있으면 답이 종전과 바이트 단위로 같아야 하고, 켜져 있어도 임베더가 죽거나 느리면 그 호출은 종전 순위로 답한다.
# 순위만 쓴다 — 코사인 값으로 거르지 않는다(e5 는 무관한 문장끼리도 0.89 남짓이다).
@pytest.fixture(autouse=True)
def _tool_search_embed_off(monkeypatch):
    """의미 순위는 시험마다 끈 채로 시작한다 — 시험을 돌리는 셸에 GATEWAY_TOOL_SEARCH_EMBED_URL 이 있어도 다른 search_tools 시험이
    임베더를 부르지 않게. 켜는 시험은 본문에서 다시 건다. 색인과 갱신 상태도 시험마다 새것이다."""
    monkeypatch.setattr(gw, "TOOL_SEARCH_EMBED_URL", "")
    monkeypatch.setattr(gw, "_TOOL_VEC", {})
    monkeypatch.setattr(gw, "_TOOL_VEC_JOB", {"running": False, "again": False})


# 의미 순위를 끈 `_search_tools` 의 기준본이다 — 옵션을 끈 답이 이것과 바이트 단위로 같아야 한다. 처음엔 master 303f023 원문이었고,
# 순위 · 응답 꼴을 일부러 바꾼 10-28(HWAXPortal docs/request-1027 HG-01 · HG-12)과 10-29(request-1029 R-3 · R-4 · R-5 — 어휘표 ·
# 정본이 대표하는 사본 접기 · 코어 질문의 심의 가중)에 그 판에서 RRF · 질의 기록 줄만 빼고 다시 떴다.
# 순위를 일부러 바꿀 때만 다시 뜬다 — RRF 를 고치다 끈 길이 바뀌면 이 시험이 잡는다.
# 10-29 저녁(E-7)에 손잡이를 search_tuning.json 으로 옮긴 판에서 다시 떴다 — 옮기기 전 사본과 응답이 바이트까지 같은 것을 먼저 보였다
# (옛 사본은 코드 상수를 읽고 새 함수는 손잡이 파일을 읽었다). 귀속 · 기록 줄도 RRF 처럼 뺐다.
_SEARCH_TOOLS_MASTER = r'''async def _search_tools(arguments: dict, *, groups: list[str] | None = None, tuning: dict | None = None,
                        embed: bool = True, log_query: bool = True) -> types.CallToolResult:
    """도구 검색 안내대 — 351개 평면 노출의 선택 비용을 줄이는 입구(실측: 상위 40개가
    호출의 79%, 30%는 한 번도 안 불림 — 롱테일은 검색으로 찾게 한다). 기본은 임베딩 없이
    부분문자열 매칭(한국어는 조사 탓에 토큰 경계가 흐려 substring 이 더 잘 맞는다). 켜면 임베딩 순위를 RRF 로
    더한다(TOOL_SEARCH_EMBED_URL — 기본 꺼짐)."""
    raw_q = str((arguments or {}).get("query") or "").strip()     # 임베딩에는 대소문자를 살린 원문을 준다
    q = raw_q.lower()
    limit = max(1, min(20, int((arguments or {}).get("limit") or 8)))
    detail = (arguments or {}).get("detail") is True
    if len(q) < 2:
        return types.CallToolResult(content=[types.TextContent(
            type="text", text='{"error": "query 를 2자 이상 주세요"}')], isError=True)
    terms = [w for w in re.split(r"[\s,;·/()\[\]{}\"']+", q) if len(w) >= 2]
    # 손잡이(search_tuning.json + 박스 덧씌우기 — E-7). 도구 이름이 전부 영어라 한국어 질의가 이름을 못 맞힌다 — 손 동의어로 넓힌다
    # (조사가 붙어도 substring 이라 '보고서를'→'보고서' 매칭은 된다). 낱말마다 어느 규칙에서 온 갈래인지(src) 함께 든다 — 귀속(E-9 ①).
    # 키워드 인자는 평가 창구(/search-eval)만 쓴다 — 서비스 시야(groups) · 바꾼 손잡이(tuning) · 임베딩 끔 · 기록 끔(E-9 ③)
    tun = tuning or _tuning()
    sw, wt = tun["switches"], tun["weights"]
    syn = tun["synonyms"] if sw["synonyms"] else {}
    q_flat = re.sub(r"\s+", "", q)
    vocab = _core_vocab()
    # 코어 질문에서는 일반 업무 낱말 → deliberate_start 를 심의를 청할 때만 잇는다(R-5 — 조회 질문이 심의 시작으로 끌렸다).
    no_delib = (sw["delib_narrow"] and bool(vocab) and not any(w in q for w in tun["delib_ask"])
                and any(f in q_flat for f, _p, _t in vocab["syn"]))
    expand: dict[str, tuple] = {}
    src: dict[str, dict[str, list]] = {}
    for w in terms:
        vs, sm = [w], {}
        for k, ss in syn.items():
            if k in w:
                for v in ss:
                    if no_delib and v == "deliberate_start":
                        continue
                    vs.append(v)
                    sm.setdefault(v, []).append(f"syn:{k}")
        expand[w], src[w] = tuple(vs), sm
    write_intent = any(w in q + " " for w in tun["write_intent"])
    if vocab and sw["core_vocab"]:
        # 코어 낱말 → 허브 읽기 도구 이름(R-4 — 타입 이름에 이으면 어느 도구 이름 · 설명에도 없어 0점이었다). 띄어 쓴 꼴('관리 기준')은
        # 붙여 쓴 꼴이 질의에 있으면 그 조각을 담은 낱말마다 잇는다 — 낱말은 빈칸에서 갈라지므로 '관리기준' 열쇠로는 못 맞힌다.
        for flat, parts, tools in vocab["syn"]:
            hit = [w for w in expand if flat in w]
            if not hit and parts and flat in q_flat:
                hit = [w for w in expand if any(p in w for p in parts)]
            for w in hit:
                add = tuple(t for t in tools if t not in expand[w])
                expand[w] += add
                for v in add:
                    src[w].setdefault(v, []).append(f"vocab:{flat}")
    canon = (vocab or {}).get("canonical")
    quality_n = sum(1 for w in tun["quality_words"] if w in q) if sw["quality"] else 0
    w_name, w_app, cap, w_cov = wt["name"], wt["app"], wt["desc_cap"], wt["coverage"]
    groups = _request_groups() if groups is None else groups
    visible = _visible_tools(groups)
    rows = []
    named_apps: set[str] = set()          # 질의가 이름을 부른 앱 — 사본 무리에서 그 앱 줄을 올린다
    for t in visible:
        name = t.name.lower()
        desc = (t.description or "").lower()
        app, original = route.get(t.name, ("_gateway", t.name))[:2]
        meta = _app_meta(app) if app != "_gateway" else {"label": "gateway", "description": ""}
        label = str(meta.get("label") or "")
        hay_app = (label + " " + str(meta.get("description") or "")).lower()
        names = _label_names(label)
        score, covered = 0, 0
        base, base_cov = 0, 0             # 보정 없이 — 질의 낱말 그 자체만으로 낸 점수(귀속 · boost_only 판정)
        via: set[str] = set()
        for w, variants in expand.items():
            name_hit = any(v in name for v in variants)
            desc_freq = max(min(desc.count(v), cap) for v in variants)
            app_hit = any(v in hay_app for v in variants)
            # 질의가 앱 이름을 불렀으면(진짜 앱 라벨 적중) 이름 적중과 같은 가중이다 — 종전엔 라벨 · 설명 어디에 맞든 1점이었다(HG-01).
            named = any(_named(names, v, q_flat) for v in variants)
            if named:
                named_apps.add(app)
            if name_hit or desc_freq or app_hit or named:
                covered += 1
                score += w_name * (name_hit or named) + desc_freq + w_app * app_hit
                b_name, b_desc, b_app, b_named = w in name, min(desc.count(w), cap), w in hay_app, _named(names, w, q_flat)
                if b_name or b_desc or b_app or b_named:
                    base_cov += 1
                    base += w_name * (b_name or b_named) + b_desc + w_app * b_app
                for v in variants[1:]:
                    if v in name or v in desc or v in hay_app or _named(names, v, q_flat):
                        via.update(src[w].get(v, ()))
        if score > 0:
            if quality_n and _area_of(t.name, app) in tun["quality_areas"]:
                score += wt["quality_per_word"] * quality_n          # 품질 질의 — 품질 · VOC 도구를 위로(HG-01)
                via.add("quality")
            # 커버리지 승수 — 질의어를 더 많이 맞힌 도구가 개별 단어 빈도보다 앞선다.
            final = score * (1 + w_cov * covered / max(1, len(terms)))
            base_final = base * (1 + w_cov * base_cov / max(1, len(terms))) if base > 0 else 0
            is_write = _tool_is_write(t, original)
            if is_write and not write_intent and sw["write_penalty"]:
                final *= wt["write_penalty"]                     # 쓰기 낱말이 없는 질문 — 쓰기 · 잡 시작 도구를 내린다(HG-01)
                base_final *= wt["write_penalty"]
            # 줄 꼴 — (점수, 이름, 앱, 설명, 도구, 쓰기, 원래 이름, 사본 표지, 보정 뺀 점수, 점수를 보탠 규칙)
            rows.append((final, t.name, app, (t.description or "").strip(), t, is_write, original,
                         1 if _COPY_LABEL.search(label) else 0, base_final, tuple(sorted(via))))
    rows.sort(key=lambda r: (-r[0], r[7], r[1]))
    # 같은 도구의 사본 — 원래 이름과 설명(정본 소개 줄은 뗀다)이 같으면 한 줄만 올리고 나머지는 same_in 으로 접는다(HG-01).
    # 그 한 줄은 무리에서 가장 앞선 줄의 자리에 서는 정본이다(R-4) — 질의가 사본의 앱을 콕 불렀을 때만 그 사본이다(OT-12 허브 건너기).
    # 형제 사본은 겹침 접두 · 라벨 낱말(failuretrace 의 failure)이 동의어에 맞아 정본보다 앞서고, 정본 사본은 점수가 0 이라 줄에 없기도
    # 하다 — 점수로는 정본을 못 세운다. 그래서 정본에 같은 도구가 있으면 그 도구가 무리를 대표한다.
    # 접힌 것도 이름으로 부를 수 있다(호출 별칭은 그대로다). 순위에서만 빠진다. 손잡이 copy_fold 를 끄면 접지 않는다.
    folded: dict[tuple, list] = {}
    if sw["copy_fold"]:
        copies: dict[tuple, list] = {}
        for r in rows:
            copies.setdefault((r[6], _core_untagged(r[2], r[3])), []).append(r)
        canon_tools = {(route[t.name][1], _core_untagged(canon, (t.description or "").strip())): t
                       for t in visible if route.get(t.name, ("",))[0] == canon} if canon else {}
        kept = []
        for k, g in copies.items():              # 넣은 차례 — 무리의 가장 앞선 줄 순서다
            head = g[0]
            if head[2] != canon and head[2] not in named_apps:
                mine = next((r for r in g if r[2] == canon), None)
                if mine is None and k in canon_tools:          # 정본 사본이 점수 0 이라 줄에 없다 — 이 무리의 자리에 세운다
                    ct = canon_tools[k]
                    mine = (head[0], ct.name, canon, (ct.description or "").strip(), ct, _tool_is_write(ct, k[0]), k[0],
                            1 if _COPY_LABEL.search(str(_app_meta(canon).get("label") or "")) else 0, head[8], head[9])
                    g = [mine] + g
                head = mine or head
            kept.append(head)
            folded[(head[6], head[3])] = [{"tool": r[1], "app": r[2]} for r in g if r is not head]
        rows = kept

    def _args_summary(t) -> dict:
        """invoke_tool 로 바로 부를 수 있게 인자 계약을 붙인다 — 이게 없으면 모델이
        스키마를 추측해 넣는다(범용 실행기의 최대 실패 모드).

        ⚠ 요약하지 않는다. 종전엔 인자 12개까지·`type` 만 남겼다 — 13번째부터는 안 보였고(deliberate_start 의
        save_report·advanced), `anyOf` 인자는 type 이 없어 `any` 로 보였으며 enum·default·설명도 빠졌다. 설명도 220자에서
        잘라 docstring 의 인자 설명(job 의 값 목록)이 사라졌다. 운영 창이 1,048,576 토큰이라 결과 8~20건의 전체 스키마는
        묶이지 않는다. 작은 창의 소비자(에이전트 서버 웹 챗)는 자기 쪽 상한(TOOL_RESULT_MAX)으로 자른다."""
        sch = getattr(t, "inputSchema", None) or {}
        out = {
            "required": sch.get("required") or [],
            "properties": sch.get("properties") or {},
        }
        # 모델 인자의 정의 — 속성이 `$ref` 로 가리키는 곳이다. 빼면 참조가 끊긴다(FastMCP 는 `$defs`, 옛 생성기는 `definitions`).
        for k in ("$defs", "definitions"):
            if sch.get(k):
                out[k] = sch[k]
        return out
    def _args_brief(t) -> dict:
        """기본 — 필수 인자의 스키마와 선택 인자의 이름만(HG-12). 응답이 도구 설명 전문(각 수천 자)과 스키마를 그대로 실어 LLM 문맥을
        먹었다(10-25 PLM-23). 선택 인자는 이름을 남긴다 — 빼면 모르는 인자가 된다(종전 13번째부터 안 보이던 사고). 전부는 detail=true."""
        sch = getattr(t, "inputSchema", None) or {}
        req = list(sch.get("required") or [])
        props = sch.get("properties") or {}
        out = {"required": req, "properties": {k: props[k] for k in req if k in props}}
        opt = [k for k in props if k not in req]
        if opt:
            out["optional"] = opt
        refs = json.dumps(out["properties"], ensure_ascii=False, default=str)
        for k in ("$defs", "definitions"):
            if sch.get(k) and "#/" + k + "/" in refs:
                out[k] = sch[k]
        return out

    matches = []
    for _, n, a, d, t, w, orig, _c, *_attr in rows[:limit]:
        m = {"tool": n, "app": a, "description": d if detail else _brief_desc(d),
             "args": _args_summary(t) if detail else _args_brief(t)}
        if w:
            m["write"] = True                    # 쓰기 · 잡 시작 — 사람에게 확인한 뒤 부른다(지침 5)
        if folded.get((orig, d)):
            m["same_in"] = folded[(orig, d)]
        matches.append(m)
    # ⚠ 순서가 뜻이다 — 이름 순위·안내를 먼저, 설명·스키마 전문(matches)을 맨 뒤에 둔다. 작은 창의 소비자(dev 웹 챗
    #   TOOL_RESULT_MAX=6,000)는 앞에서부터 글자로 자르므로, 전문이 앞서면 6~8위 도구는 이름조차 사라져 '없다' 로 읽혔다(gw-adh GA-7,
    #   리스크 앱 도구 실측 8건 7,000~8,400자). 게이트웨이는 자르지 않는다 — 잘려도 순위가 남게 놓을 뿐이다.
    payload = {"query": q}
    payload["match_count"] = len(rows)
    payload["ranked"] = [m["tool"] for m in matches]
    if len(rows) > limit:
        # 순위 목록이라 건수는 둔다 — 다만 더 맞은 도구가 있다는 것을 match_count 숫자로만 두지 않는다.
        payload["truncated"] = (f"{len(rows)}건 중 상위 {limit}건만 보였다 — limit 를 올리거나(최대 20) 질의를 좁혀라. "
                                "보이지 않는 도구가 없다는 뜻이 아니다.")
    payload["note"] = ("여기 나온 도구는 현재 목록에 없어도 invoke_tool(name, arguments) 로 즉시 "
                       "호출할 수 있다(args 의 required 를 채워라). 원하는 게 없으면 질문을 바꿔 "
                       "다시 검색하거나 list_tool_apps(app='<키>') 로 앱 상세를 보라."
                       + ("" if detail else " 설명은 한 줄 요약이고 args 는 필수 인자만 스키마를 싣는다 — 선택 인자(optional)까지 "
                                            "쓰려면 detail=true 로 다시 찾아라.")
                       + (" same_in 은 설명까지 같은 사본이다 — 위 도구를 먼저 쓴다." if any("same_in" in m for m in matches) else ""))
    payload["matches"] = matches
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(payload, ensure_ascii=False, indent=2))]
    )
'''


def _search_tools_master():
    """원문을 게이트웨이 모듈의 이름공간에서 정의한다 — monkeypatch 한 카탈로그·요청 문맥을 지금 코드와 똑같이 본다."""
    ns: dict = {}
    exec(compile(_SEARCH_TOOLS_MASTER, "master:_search_tools", "exec"), gw.__dict__, ns)
    return ns["_search_tools"]


_SEARCH_SPECS = [
    ("hwax-deliberation", "deliberate_start", "HWAX 전문가 심의를 시작한다 — 원인 규명·안 선택·리스크 심사·시험 계획."),
    ("hwax-deliberation", "deliberate_status", "심의가 어디까지 갔는지 본다. 잡 상태와 라운드."),
    ("heax-web_design_agents", "meeting_start", "회의를 생성한다 — 페르소나 회의체가 시나리오를 심의한다."),
    ("signalforge", "search_voc", "키워드로 VOC 를 검색합니다. 한국어·영어 모두 가능합니다."),
    ("signalforge", "get_top_issues", "제품에서 가장 많이 언급된 이슈 TOP N 을 반환합니다."),
    ("heax-materialtwin_web", "list_materials", "재료 목록을 조회한다 — 이름 부분일치."),
    ("heax-materialtwin_web", "get_material_properties", "재료의 화·물리 물성값을 도메인별로 전부 반환한다."),
    ("heax-materialtwin_web", "plot_curve", "시험 1건의 응력-변형률 곡선을 PNG 로 그린다(plot)."),
    ("heax-step_forge", "mesh_report", "메시 잡 결과 요약 — 파트별 요소 수·품질 지표(mesh quality)."),
    ("heax-step_forge", "measure_distance", "두 파트 사이 최소거리를 잰다."),
    ("heax-step_forge", "list_parts", "파트 목록 — 이름·부피·재질. 낙하 덱 전에 본다."),
    ("heax-laminate_analyzer_mcp", "compute_buckling", "직교이방 판의 좌굴 임계하중."),
    ("heax-laminate_analyzer_mcp", "analyze_laminate", "적층 정의를 받아 ABD·중립면·지표를 계산한다."),
    ("smart-twin-mcp", "job_rerun", "실패/미완료 DOE만 재실행. 낙하 충격 해석 잡."),
    ("ste", "ste_submit_job", "해석 잡을 제출한다(slurm)."),
    ("mx-white-paper", "export_document", "위키 문서를 docx 로 내보낸다. report 작성에 쓴다."),
] + [("signalforge", f"report_x{i:02d}", "보고서 report 묶음 — 같은 점수로 겹치는 도구들.") for i in range(12)]


def _search_catalog(monkeypatch, specs=None):
    """search_tools 가 보는 카탈로그를 앉힌다 — 앱 라벨·설명(app_hit)까지 실제와 같은 길로 읽힌다."""
    specs = specs or _SEARCH_SPECS
    tools = [types.Tool(name=n, description=d, inputSchema={"type": "object", "properties": {"q": {"type": "string"}}})
             for _, n, d in specs]
    monkeypatch.setattr(gw, "exposed_tools", tools)
    monkeypatch.setattr(gw, "route", {n: (a, n) for a, n, _ in specs})
    monkeypatch.setattr(gw, "DISCOVERED_META", {
        "heax-step_forge": {"label": "StepForge", "description": "STEP 어셈블리 점검·메시·K파일 내보내기 도구"},
        "heax-materialtwin_web": {"label": "MaterialTwin Web", "description": "재료 물성 디지털트윈"}})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    monkeypatch.setattr(gw, "_request_muted", lambda: set())
    return tools


def _no_embed(monkeypatch):
    async def boom(texts, kind, timeout_s):
        raise AssertionError("꺼진 길이 임베더를 불렀다")
    monkeypatch.setattr(gw, "_embed_texts", boom)


# ── search_tools 순위 — cae00 모양(허브 셋 · 심의 여덟 · 품질 · VOC)으로 본다(HWAXPortal docs/request-1027 HG-01) ──────────────────────
# 실측(10-25 · 10-27) — 코어 질문 16개 중 15개에서 상위 8에 허브 온톨로지 읽기 도구가 0개, '시장 불량 원인 대책'(limit 10)은 deliberate_* 8개 ·
# plm_defect_search · VOC 0개, 조회 질문(OT-16)의 상위 8 중 6개가 쓰기 · 적용 도구, 점수가 같으면 이름순이라 사본 허브가 앞이었다.
_HUBS = (("heax-designhub_copy", "designhubcopy", "자주검증 Datahub (사본)"), ("heax-failuretrace", "failuretrace", "FailureTrace"),
         ("heax-rootdesigndatahub", "rootdesigndatahub", "자주검증 Datahub"))
_HUB_TOOLS = (
    ("object_resolve", "이름 · 코드 · 별칭으로 코어 객체(part · model · plm_task · failure_mode · test_item · sim_capability · criterion · "
                       "material_property)를 찾아 id 를 준다."),
    ("objects_list", "한 타입의 객체 목록 — type 은 part · model · plm_task · failure_mode · test_item · sim_capability · criterion."),
    ("graph_neighbors", "한 객체의 이웃 — predecessor · successor · uses · verifies 관계를 따라간다."),
    ("objects_upsert", "객체를 만들거나 고친다(part · model · failure_mode …)."),
)
_HG01_SPECS = [(key, f"{pre}_{n}", d) for key, pre, _l in _HUBS for n, d in _HUB_TOOLS] + [
    ("hwax-deliberation", "deliberate_start", "HWAX 전문가 심의를 시작한다 — 원인 규명 · 불량 원인 분석 · 안 선택 · 리스크 심사 · 시험 계획."),
    ("hwax-deliberation", "deliberate_continue", "끝난 심의를 이어서 한 번 더 돌린다."),
    ("hwax-deliberation", "deliberate_status", "심의가 어디까지 갔는지 본다 — 잡 상태와 라운드."),
    ("hwax-deliberation", "deliberate_result", "심의 결정문을 받는다."),
    ("hwax-deliberation", "deliberate_list", "내가 돌린 심의 목록."),
    ("hwax-deliberation", "deliberate_transcript", "심의 라운드마다 좌석이 한 말 원문."),
    ("hwax-deliberation", "deliberate_jobs", "도는 심의 잡과 줄."),
    ("hwax-deliberation", "deliberate_cancel", "도는 심의를 멈춘다."),
    ("plm-search-agent", "plm_defect_search", "PLM 문제점(불량) 사례를 증상 · 모델 · 과제로 찾는다 — 원인 · 대책 · 처리 이력."),
    ("plm-search-agent", "plm_defect_detail", "문제점 한 건의 상세 — 원인 분석 · 대책 · 첨부."),
    ("signalforge", "defect_profile", "제품별 결함 프로필 — 시장 커뮤니티 VOC 의 불량 유형 분포."),
    ("signalforge", "search_voc", "키워드로 VOC 를 검색합니다."),
    ("heax-step_forge", "list_parts", "파트 목록 — 이름 · 부피 · 재질."),
    ("heax-step_forge", "set_part_metadata", "파트에 이름 · 재질 같은 메타를 적는다."),
    ("heax-step_forge", "find_plm_task", "PLM 과제를 과제 코드 · 이름으로 찾는다."),
]


def _hg01(monkeypatch, query: str, limit: int = 10, specs=None) -> dict:
    specs = specs or _HG01_SPECS
    _search_catalog(monkeypatch, specs)
    monkeypatch.setattr(gw, "route", {n: (a, n.split("_", 1)[1] if a.startswith("heax-") and a not in (
        "heax-step_forge",) else n) for a, n, _ in specs})
    monkeypatch.setattr(gw, "DISCOVERED_META", {**{k: {"label": l, "description": "코어 온톨로지 허브"} for k, _p, l in _HUBS},
                                                "heax-step_forge": {"label": "StepForge", "description": "STEP 어셈블리 점검"}})
    _no_embed(monkeypatch)
    return json.loads(asyncio.run(gw._search_tools({"query": query, "limit": limit})).content[0].text)


def test_HG01_품질_질의는_심의_가족이_아니라_품질_VOC_도구를_올린다(monkeypatch):
    out = _hg01(monkeypatch, "시장 불량 원인 대책", 10)
    delib = [t for t in out["ranked"] if t.startswith("deliberate_")]
    assert len(delib) <= 2, f"심의 가족이 일반 낱말로 한꺼번에 올랐다: {out['ranked']}"
    assert set(out["ranked"][:4]) == {"plm_defect_search", "plm_defect_detail", "defect_profile", "search_voc"}, out["ranked"]


@pytest.mark.parametrize("query, want", [("고장모드 목록", "objects_list"), ("과제코드로 객체 찾기", "object_resolve"),
                                         ("이 모델의 전작", "graph_neighbors")])
def test_HG01_온톨로지_낱말이_허브_읽기_도구에_닿고_사본은_정본_밑에_접힌다(monkeypatch, query, want):
    out = _hg01(monkeypatch, query, 8)
    hub = [m for m in out["matches"] if m["tool"].endswith("_" + want)]
    assert len(hub) == 1, f"같은 설명의 허브 셋이 접히지 않았다: {out['ranked']}"
    top = hub[0]
    assert out["ranked"].index(top["tool"]) < 3, out["ranked"]
    assert top["app"] != "heax-designhub_copy", "점수가 같으면 라벨에 사본 표지가 없는 앱이 앞이다"
    assert sorted(x["app"] for x in top["same_in"]) == sorted(k for k, _p, _l in _HUBS if k != top["app"])
    assert "same_in" in out["note"]


def test_HG01_쓰기_낱말이_없으면_쓰기_도구를_내리고_표지를_단다(monkeypatch):
    read = _hg01(monkeypatch, "고장모드 객체 보기", 20)
    names = [x.split("_", 1)[1] if x.split("_", 1)[0] in {p for _k, p, _l in _HUBS} else x for x in read["ranked"]]
    assert names.index("objects_list") < names.index("objects_upsert"), names
    up = next(m for m in read["matches"] if m["tool"].endswith("_objects_upsert"))
    assert up.get("write") is True and not next(m for m in read["matches"] if m["tool"].endswith("_objects_list")).get("write")
    # 쓰기 낱말이 있으면 감점하지 않는다 — 같은 질의에 '등록' 만 더하면 쓰기 도구가 위로 온다
    write = _hg01(monkeypatch, "고장모드 객체 등록", 20)
    names_w = [x.split("_", 1)[1] if x.split("_", 1)[0] in {p for _k, p, _l in _HUBS} else x for x in write["ranked"]]
    assert names_w.index("objects_upsert") < names.index("objects_upsert"), (names_w, names)


def test_HG01_앱_이름을_부르면_이름_적중과_같은_가중이고_라벨_안의_일반_낱말은_아니다():
    assert gw._label_names("StepForge") == {"stepforge"}
    assert gw._label_names("시뮬레이션 실행(SmartTwin)") == {"시뮬레이션실행", "smarttwin"}
    assert gw._label_names("WebDesignAgents — 발표자료·슬라이드 자동 생성") == {"webdesignagents"}
    assert gw._label_names("자주검증 Datahub (사본)") == {"자주검증datahub"}
    ai = gw._label_names("AI 데이터 허브")
    assert gw._named(ai, "데이터", "데이터등록") is False, "라벨 안의 일반 낱말 — 그 앱 도구 전부가 오르면 안 된다"
    assert gw._named(ai, "데이터", "ai데이터허브에서찾기") is True, "띄어 쓴 이름 전체를 부르면 그 조각도 앱 이름이다"
    assert gw._named(gw._label_names("Ste"), "steel", "steel") is False and gw._named(gw._label_names("Ste"), "ste", "ste") is True


def test_HG01_StepForge_를_부르면_그_앱_도구가_다른_앱의_비슷한_도구보다_앞선다(monkeypatch):
    """다른 앱의 도구가 설명 적중으로 조금 앞서는 판 — 앱 이름을 부른 가중(4)이 있어야 뒤집힌다(종전 라벨 적중은 1점)."""
    specs = [("heax-step_forge", "zz_list_parts", "파트 목록을 준다."),
             ("heax-other_cad", "aa_list_parts", "파트 목록 — 파트 목록 · 파트 목록을 준다.")]
    out = _hg01(monkeypatch, "StepForge 파트 목록", 10, specs=specs)
    assert out["ranked"][:2] == ["zz_list_parts", "aa_list_parts"], out["ranked"]
    out = _hg01(monkeypatch, "파트 목록", 10, specs=specs)
    assert out["ranked"][:2] == ["aa_list_parts", "zz_list_parts"], "앱을 부르지 않으면 설명 적중대로다"


# ── 코어 어휘표 — 정본 소개 줄 · 코어 낱말 → 허브 읽기 도구 · 사본 접기 · 심의 가중(HWAXPortal docs/request-1029 B-1 · R-3 · R-4 · R-5) ──────
# 10-29 cae00 웹 챗 QA — 고장모드 · 시험항목 · 가상검증 · 관리 기준 · 물성 질문 다섯이 코어를 건너뛰었고, 챗이 부른 search_tools 8건의 상위 5에
# 자주검증 도구가 0개였다. 허브 셋은 키 · 도구 이름 · 설명까지 cae00 꼴이다(이름이 겹쳐 셋 다 접두가 붙는다). 집계(_aggregate)를 실제로 돌린다.
_CORE_HUBS = (("rootdesigndatahub", "자주검증 Datahub(rootdesign)"), ("failuretrace", "FailureTrace"),
              ("caegroupdatahub", "CAE 그룹 Datahub"))
_CORE_HUB_TOOLS = (
    ("object_resolve", "이름 하나가 어느 객체인지 찾아 id 를 준다 — 이름 · 코드 · 별칭으로 찾는다."),
    ("objects_list", "한 타입의 객체 목록을 준다 — 조건 · 정렬 · 쪽."),
    ("objects_summary", "조건에 맞는 객체를 세고 묶어 요약한다 — 개수 · 분포."),
    ("object_get", "객체 하나의 필드와 관계를 준다."),
    ("graph_neighbors", "객체의 이웃을 관계를 따라 준다."),
    ("objects_upsert", "객체를 만들거나 고친다."),
)
# 코어 질문을 가로챈 앱(FMEA · ARP · ODB 허브 · MatNexus)과 낙하 · 심의 도구 — 설명에 그 앱의 업무 낱말을 싣는다(요청서 R-3: FMEA 는 '규격 ·
# 시험 · 고장모드' 를 설명에 싣는다).
_CORE_OTHER = {
    "fmea": ("FMEA", [("gather_evidence_tool", "고장모드 · 원인 · 대책의 사례 근거를 모은다(FMEA 사례 · 규격)."),
                      ("list_candidate_specs", "질문에 맞는 사내 시험 규격 후보 목록 — 시험항목 · 불량 모드."),
                      ("get_spec_details", "규격 한 건의 상세 — 시험 방법 · 판정 기준 · 고장모드.")]),
    "arp": ("ARP", [("compare_items", "해석 항목끼리 실측 값을 견준다."),
                    ("search_data", "해석 · 시험 실측 데이터를 찾는다 — 모델 · 항목 · 조건.")]),
    "odb-hub": ("ODB 허브", [("list_rules", "보드 설계 규칙 목록."), ("find_job", "보드 잡을 이름 · 모델로 찾는다.")]),
    "matnexus": ("MatNexus", [("resolve_property", "물성 이름을 표준 물성으로 푼다 — 영률 · 항복강도.")]),
    "hwax-deliberation": ("HWAX 전문가 심의", [
        ("deliberate_start", "HWAX 전문가 심의를 시작한다 — 원인 규명 · 불량 원인 분석 · 안 선택 · 신뢰 판정 · 리스크 심사 · 시험 계획 · "
                             "해석 설계 · 검증 항목.")]),
    "smart-twin-mcp": ("SmartTwin", [("single_drop_simulation", "단일 낙하 해석 잡 — 철판 · 낙하 높이 · 자세."),
                                     ("fullangle_drop_simulation", "전각도 낙하 해석 잡.")]),
}


def _core_search(monkeypatch, query: str, limit: int = 8, *, vocab: bool = True) -> dict:
    """cae00 꼴 카탈로그로 search_tools — vocab=False 면 어휘표가 없는 박스(지금 동작)다."""
    monkeypatch.setattr(gw, "CORE_VOCAB_PATH", _REAL_CORE_VOCAB if vocab else _REAL_CORE_VOCAB.with_name("__none__.json"))
    spec = {k: [types.Tool(name=n, description=d, inputSchema={"type": "object", "properties": {"q": {"type": "string"}}})
                for n, d in _CORE_HUB_TOOLS] for k, _l in _CORE_HUBS}
    spec.update({k: [types.Tool(name=n, description=d, inputSchema={"type": "object", "properties": {}}) for n, d in ts]
                 for k, (_l, ts) in _CORE_OTHER.items()})
    _aggregate_tools(monkeypatch, spec)
    monkeypatch.setattr(gw, "DISCOVERED_META", {**{k: {"label": l, "description": "코어 온톨로지 허브"} for k, l in _CORE_HUBS},
                                                **{k: {"label": l, "description": ""} for k, (l, _t) in _CORE_OTHER.items()}})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    monkeypatch.setattr(gw, "_request_muted", lambda: set())
    _no_embed(monkeypatch)
    return json.loads(asyncio.run(gw._search_tools({"query": query, "limit": limit})).content[0].text)


def test_코어_어휘표_정본을_형제_포털_리포에서_읽고_health_에_싣는다(monkeypatch):
    """C-11 — 소비자의 해석이 정본의 꼴과 어긋나지 않게 실제 파일을 읽는다. 경로는 /health 에 싣지 않는다(박스 배치가 드러난다)."""
    monkeypatch.setattr(gw, "CORE_VOCAB_PATH", _REAL_CORE_VOCAB)
    d = gw._core_vocab()
    assert d is not None, f"형제 리포의 어휘표를 못 읽었다: {gw._CORE_VOCAB['error']}"
    assert d["canonical"] == "rootdesigndatahub" and d["tag"][0] == "rootdesigndatahub" and d["tag"][1].startswith("사내 코어 정본")
    syn = {flat: (parts, tools) for flat, parts, tools in d["syn"]}
    assert syn["관리기준"][0] in ((), ("관리", "기준")) and "object_resolve" in syn["관리기준"][1]
    assert ("관리", "기준") in {parts for parts, _t in syn.values()}, "띄어 쓴 꼴은 조각까지 든다"
    for w in ("고장모드", "시험항목", "가상검증", "기준", "영률", "대책", "실패모드"):
        assert w in syn, w
    assert "메커니즘" not in syn and "물성" in syn, "검색 낱말은 R-4 의 목록이다 — 메커니즘은 '메커니즘 규명'(심의)을 가로챈다"
    monkeypatch.setattr(gw, "backends", {})
    h = gw._core_vocab_health()
    assert h["loaded"] is True and h["canonical"] == "rootdesigndatahub" and h["words"] == len(d["syn"])
    assert h["tagline_applied"] is False, "아직 집계 전이다"
    assert h["canonical_backend"] is False, "정본 키의 백엔드가 이 박스에 없다 — 소개 줄 · 정본 대표가 조용히 꺼진 것을 말한다"
    monkeypatch.setattr(gw, "backends", {"rootdesigndatahub": _B([])})
    assert gw._core_vocab_health()["canonical_backend"] is True
    assert "HWAXPortal" not in json.dumps(h, ensure_ascii=False)


def test_코어_어휘표는_바뀐_시각에_다시_읽고_없거나_깨지면_지금_동작으로_돈다(monkeypatch, tmp_path, caplog):
    import os
    p = tmp_path / "core_vocab.json"
    monkeypatch.setattr(gw, "CORE_VOCAB_PATH", p)
    monkeypatch.setattr(gw, "_REAGG", {})
    monkeypatch.setattr(gw, "exposed_tools", [_tool("x")])
    body = {"version": 1, "canonical": {"app": "hub", "label": "Hub", "tagline": "소개 하나"},
            "search": [{"words": ["관리 기준"], "tools": ["object_resolve"]}], "apps": {}}
    p.write_text(json.dumps(body, ensure_ascii=False), encoding="utf-8")
    assert gw._core_vocab()["tag"] == ("hub", "소개 하나")
    assert gw._REAGG.get("pending") is True, "붙어 있는 소개 줄(없음)과 다르다 — 다음 재활 회차에 다시 집계한다"
    gw._REAGG.clear()
    gw._CORE_VOCAB["tag_applied"] = ("hub", "소개 하나")          # 집계가 붙였다
    assert gw._core_vocab()["tag"] == ("hub", "소개 하나") and not gw._REAGG, "같으면 다시 집계하지 않는다"
    body["canonical"]["tagline"] = "소개 둘"
    p.write_text(json.dumps(body, ensure_ascii=False), encoding="utf-8")
    st = p.stat()
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
    assert gw._core_vocab()["tag"] == ("hub", "소개 둘") and gw._REAGG.get("pending") is True
    with caplog.at_level(logging.WARNING, logger="hwax-mcp-gateway"):
        p.write_text("{깨진", encoding="utf-8")
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 2_000_000_000))
        assert gw._core_vocab() is None and gw._CORE_VOCAB["error"] == "못 읽음(JSONDecodeError)"
        p.unlink()
        assert gw._core_vocab() is None and gw._CORE_VOCAB["error"] == "없음"
        assert gw._core_vocab_health() == {"loaded": False, "error": "없음"}
    assert sum("코어 어휘표" in r.getMessage() for r in caplog.records) == 2, "깨짐 · 없어짐을 한 번씩 알린다"


def test_R3_집계는_정본_앱_도구에만_소개_줄을_붙이고_어휘표가_없으면_설명은_그대로다(monkeypatch):
    same = "이름 하나가 어느 객체인지 찾아 id 를 준다."
    spec = {k: [types.Tool(name="object_resolve", description=same, inputSchema={"type": "object"})] for k, _l in _CORE_HUBS}
    _aggregate_tools(monkeypatch, spec)
    assert {t.description for t in gw.exposed_tools} == {same}, "어휘표가 없으면 지금 동작이다"
    monkeypatch.setattr(gw, "CORE_VOCAB_PATH", _REAL_CORE_VOCAB)
    monkeypatch.setattr(gw, "_CORE_VOCAB", {"mtime": None, "data": None, "error": "없음", "tag_applied": None})
    _aggregate_tools(monkeypatch, spec)
    desc = {t.name: t.description for t in gw.exposed_tools}
    assert desc["rootdesigndatahub_object_resolve"] == f"[{gw._CORE_VOCAB['data']['tag'][1]}] {same}"
    assert desc["failuretrace_object_resolve"] == desc["caegroupdatahub_object_resolve"] == same
    assert gw._core_untagged("rootdesigndatahub", desc["rootdesigndatahub_object_resolve"]) == same
    assert gw._core_vocab_health()["tagline_applied"] is True


@pytest.mark.parametrize("query", [
    "가상검증 항목 해석으로 확인하는 검증 리스트", "관리 기준 개수", "철판 낙하 기준", "규격 실패모드", "가상검증", "관리 기준",
    "Which test items detect drop failure modes"])
def test_R4_요청서_시험_질의는_상위_5에_정본_읽기_도구가_둘_이상이다(monkeypatch, query):
    """요청서 HG-01 이 이름을 댄 질의 일곱(cae00 질의 기록의 여덟 가운데 일곱 — 원문 여덟은 cae00 재시험에서 다시 잰다)과 OT-07 의 영어 질문.
    '낙하 해석 담당' 은 뺐다 — 코어 낱말이 없어 어휘표가 닿지 않는다(context-notes C-14)."""
    out = _core_search(monkeypatch, query)
    top = [m for m in out["matches"][:5] if m["app"] == "rootdesigndatahub" and not m.get("write")]
    assert len(top) >= 2, out["ranked"]
    assert "deliberate_start" not in out["ranked"][:5], out["ranked"]
    # 어휘표가 없으면(지금 동작) 같은 질의의 정본이 줄어든다 — 위 결과가 어휘표에서 왔다는 것. 0 은 아니다: 정본 라벨 '자주검증' 이
    # '검증' 에 맞는다(앱 적중 1점).
    off = _core_search(monkeypatch, query, vocab=False)
    assert sum(1 for m in off["matches"][:5] if m["app"] == "rootdesigndatahub") < len(top), off["ranked"]


def test_R4_같은_도구의_사본은_정본_한_줄로_접히고_사본을_부르면_그_사본이다(monkeypatch):
    out = _core_search(monkeypatch, "고장모드 목록")
    rows = [m for m in out["matches"] if m["tool"].endswith("_objects_list")]
    assert [m["app"] for m in rows] == ["rootdesigndatahub"], out["ranked"]
    assert sorted(x["app"] for x in rows[0]["same_in"]) == ["caegroupdatahub", "failuretrace"]
    # FailureTrace 의 라벨 낱말(failure)이 동의어에 맞아 사본이 1 ~ 2점 앞서도 정본이 그 자리에 선다 — 영어 질문 · '불량' 질문
    for q in ("Which test items detect drop failure modes", "솔더 접합 불량 고장모드 원인 대책"):
        out = _core_search(monkeypatch, q, 10)
        hub = [m for m in out["matches"] if m["app"] in {k for k, _l in _CORE_HUBS}]
        assert hub and {m["app"] for m in hub} == {"rootdesigndatahub"}, (q, out["ranked"])
    # 사본의 앱을 콕 부르면(허브 건너기 OT-12) 그 사본이 무리를 대표한다
    out = _core_search(monkeypatch, "FailureTrace 고장모드 목록")
    rows = [m for m in out["matches"] if m["tool"].endswith("_objects_list")]
    assert [m["app"] for m in rows] == ["failuretrace"] and out["ranked"][0] == "failuretrace_objects_list", out["ranked"]
    assert "rootdesigndatahub" in {x["app"] for x in rows[0]["same_in"]}


def test_R4_띄어_쓴_코어_낱말도_허브_읽기_도구에_닿는다(monkeypatch):
    """질의 낱말은 빈칸에서 갈라진다 — '시험 항목' 은 '시험' · '항목' 둘이라 붙여 쓴 열쇠로는 못 맞힌다. 어휘표의 띄어 쓴 꼴은 붙여 쓴 꼴이 질의에
    있으면 그 조각을 담은 낱말마다 잇는다(요청서 R-4 '관리 기준 처럼 띄어 쓴 꼴도 받는다')."""
    for q in ("시험 항목 목록", "시험항목 목록"):
        out = _core_search(monkeypatch, q)
        assert out["ranked"][0] == "rootdesigndatahub_objects_list", (q, out["ranked"])


def test_R5_코어_질문은_심의를_청할_때만_일반_낱말이_deliberate_start_에_닿는다(monkeypatch):
    """요청서 R-5 는 '심의 · 토의 · 회의가 없으면 끈다' 였다. 그대로 하면 코어 낱말이 없는 심의 업무 낱말 14쌍 중 7쌍이 밀려(10-29 dev
    카탈로그 — '안 선택' 1 → 10위 · '신뢰 판정' 2 → 20위) 코어 질문에만 건다(context-notes C-13)."""
    def pos(q, vocab=True):
        r = _core_search(monkeypatch, q, 20, vocab=vocab)["ranked"]
        return r.index("deliberate_start") + 1 if "deliberate_start" in r else None
    q = "기준 판정 설계 선택"                    # 코어 낱말(기준) 하나에 일반 낱말 셋 — 잇는다면 deliberate_start 가 1위다
    assert pos(q, vocab=False) == 1, "어휘표가 없으면 지금 동작이다"
    core = pos(q)
    assert core is None or core > 5, core
    assert pos(q + " 심의") == 1, "심의를 청하면 종전대로 잇는다"
    assert pos("신뢰 판정") == pos("해석 설계") == 1, "코어 낱말이 없으면 종전대로 잇는다"


def test_R6_시험_사본은_목록_검색에서_빠지고_이름으로_부르면_닿는다(monkeypatch):
    """어휘표에서 역할이 '시험'(staging)인 앱(stepforge-prod · dynaforge-prod) — 10-29 에도 6번 불렸고 OT-02 는 사본 결과를 '운영도 같다' 는 근거로
    썼다(HWAXPortal docs/request-1029 R-6 · 결정 D-2). 숨김만이다 — invoke_tool 이나 노출 이름으로 부르면 그대로 닿는다."""
    monkeypatch.setattr(gw, "CORE_VOCAB_PATH", _REAL_CORE_VOCAB)
    prod, real = _CallB(["find_plm_task"]), _CallB(["find_plm_task"])
    calls: list = []
    for key, b in (("stepforge-prod", prod), ("heax-step_forge", real)):
        async def _ct(original, args, read_timeout_seconds=None, _k=key):
            calls.append((_k, original))
            return types.CallToolResult(content=[types.TextContent(type="text", text=f"{_k} 결과")])
        b.session.call_tool = _ct
    monkeypatch.setattr(gw, "backends", {"stepforge-prod": prod, "heax-step_forge": real})
    for k in ("exposed_tools", "route", "alias_route"):
        monkeypatch.setattr(gw, k, [] if k == "exposed_tools" else {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    monkeypatch.setattr(gw, "_request_muted", lambda: set())
    monkeypatch.setattr(gw, "_request_user", lambda: "")
    gw._RESP_CACHE.clear()
    asyncio.run(gw._aggregate())
    staged = next(n for n, (k, _o) in gw.route.items() if k == "stepforge-prod")
    visible = {t.name for t in gw._visible_tools([])}
    assert staged not in visible and any(gw.route.get(n, ("",))[0] == "heax-step_forge" for n in visible), visible
    _no_embed(monkeypatch)
    out = json.loads(asyncio.run(gw._search_tools({"query": "PLM 과제 찾기", "limit": 10})).content[0].text)
    assert staged not in out["ranked"] and all(m["app"] != "stepforge-prod" for m in out["matches"]), out["ranked"]
    assert asyncio.run(gw._call_tool("invoke_tool", {"name": staged, "arguments": {}})).content[0].text == "stepforge-prod 결과"
    assert asyncio.run(gw._call_tool(staged, {})).content[0].text == "stepforge-prod 결과"
    assert ("stepforge-prod", "find_plm_task") in calls
    assert gw._core_vocab_health()["staging_hidden"] == ["stepforge-prod"]
    monkeypatch.setattr(gw, "CORE_VOCAB_PATH", _REAL_CORE_VOCAB.with_name("__none__.json"))
    gw._core_vocab()
    assert staged in {t.name for t in gw._visible_tools([])}, "어휘표가 없으면 지금 동작이다(숨기지 않는다)"


def test_search_tools_의미_순위를_끄면_답이_master_와_바이트까지_같다(monkeypatch):
    """옵션을 끈 것이 기본값이다 — 그때 search_tools 는 종전 코드와 글자 하나 다르지 않아야 하고 임베더를 부르지 않는다.
    질의는 손으로 고른 가장자리(짧음·빈 낱말·대소문자·조사·limit)와 평가셋의 질의 전부다."""
    from pathlib import Path
    _search_catalog(monkeypatch)
    _no_embed(monkeypatch)
    legacy = _search_tools_master()
    queries = ["심의", "  리스크 심사  ", "보고서를 요약해줘", "MESH Quality check", "낙하 충격 에너지", "물성 곡선 그래프",
               "VOC 검색", "잡 상태 조회", "x y", "a", "", "report", "적층 ABD 계산", "안 선택"]
    pairs = Path(gw.__file__).with_name("tool_search_eval") / "pairs.jsonl"
    if pairs.exists():
        queries += [json.loads(line)["query"] for line in pairs.read_text(encoding="utf-8").splitlines() if line.strip()]
    seen = {"error": 0, "hit": 0, "truncated": 0}
    for q in queries:
        for extra in ({}, {"limit": 3}, {"limit": 20}):
            args = {"query": q, **extra}
            new, old = asyncio.run(gw._search_tools(args)), asyncio.run(legacy(args))
            assert (new.isError, new.content[0].text) == (old.isError, old.content[0].text), args
            seen["error"] += bool(old.isError)
            seen["hit"] += '"match_count": 0' not in old.content[0].text
            seen["truncated"] += '"truncated"' in old.content[0].text
    assert seen["error"] and seen["hit"] > 20 and seen["truncated"], seen          # 전제 — 오류·적중·자름이 모두 지나갔다


def _embed_fake(monkeypatch, sims: dict, calls: list | None = None, dim: int = 2):
    """질의와의 코사인이 sims[도구 이름] 이 되는 가짜 임베더 — 질의는 (1, 0, …), 도구는 (s, √(1-s²), 0, …). 이름은 글에서 읽는다."""
    async def fake(texts, kind, timeout_s):
        if calls is not None:
            calls.append((kind, list(texts)))
        if kind == "query":
            return [[1.0] + [0.0] * (dim - 1) for _ in texts], 0
        out = []
        for text in texts:
            s = sims.get(text.split(" · ", 1)[1].split(":", 1)[0], -1.0)
            out.append([s, (1 - s * s) ** 0.5] + [0.0] * (dim - 2))
        return out, 0
    monkeypatch.setattr(gw, "_embed_texts", fake)


def _fused_kit(monkeypatch, specs, sims, calls=None):
    """옵션을 켜고 가짜 임베더로 색인을 채운 search_tools — 돌려주는 것은 질의 → 답(JSON)."""
    tools = _search_catalog(monkeypatch, specs)
    monkeypatch.setattr(gw, "_local_tools", lambda: [])
    monkeypatch.setattr(gw, "TOOL_SEARCH_EMBED_URL", "http://embedder.invalid/api/embed")
    _embed_fake(monkeypatch, sims, calls)
    asyncio.run(gw._tool_index_refresh())
    assert len(gw._TOOL_VEC) == len(tools)

    def search(q, **kw):
        return json.loads(asyncio.run(gw._search_tools({"query": q, **kw})).content[0].text)
    return search


_CURVE_SPECS = [("app1", "curve_a", "곡선 곡선 곡선"), ("app1", "plot_b", "곡선"),
                ("app1", "other_c", "무관"), ("app1", "other_d", "무관")]


def test_의미_순위는_두_순위를_RRF_로_섞는다(monkeypatch):
    """부분문자열은 curve_a(1위)·plot_b(2위)만 맞힌다. 임베딩은 other_c > plot_b > other_d > curve_a. RRF(k=60) —
    plot_b 1/62+1/62 > curve_a 1/61+1/64 > other_c 1/61 > other_d 1/63. 두 순위에 다 든 도구가 하나에만 든 도구를 앞선다."""
    search = _fused_kit(monkeypatch, _CURVE_SPECS, {"other_c": 0.99, "plot_b": 0.95, "other_d": 0.90, "curve_a": 0.85})
    out = search("곡선")
    assert out["mode"] == "rrf" and "mode_reason" not in out
    assert out["ranked"] == ["plot_b", "curve_a", "other_c", "other_d"] and out["match_count"] == 4
    assert list(out)[:4] == ["query", "mode", "match_count", "ranked"], "mode 는 앞에 — 잘려도 남는다"
    assert list(out)[-1] == "matches" and [m["tool"] for m in out["matches"]] == out["ranked"]
    monkeypatch.setattr(gw, "TOOL_SEARCH_EMBED_URL", "")
    off = search("곡선")
    assert off["ranked"] == ["curve_a", "plot_b"] and "mode" not in off, "대조군 — 끄면 부분문자열 순위 그대로다"


def test_의미_순위는_코사인_문턱을_쓰지_않는다(monkeypatch):
    """같은 차례면 코사인의 크기와 상관없이 답이 같다 — e5 처럼 다 높아도(0.85~0.99), 다 음수여도, 거의 같아도, 문턱이 있을 법한
    자리를 사이에 두고 갈려도. 부분문자열에 안 걸린 도구는 코사인이 가장 낮아도(-0.8) 순위로 후보에 든다."""
    answers = []
    for sims in ({"other_c": 0.99, "plot_b": 0.95, "other_d": 0.90, "curve_a": 0.85},
                 {"other_c": -0.5, "plot_b": -0.6, "other_d": -0.7, "curve_a": -0.8},
                 {"other_c": 0.99994, "plot_b": 0.99993, "other_d": 0.99992, "curve_a": 0.99991},
                 {"other_c": 0.9, "plot_b": 0.3, "other_d": -0.2, "curve_a": -0.6}):
        gw._TOOL_VEC.clear()
        out = _fused_kit(monkeypatch, _CURVE_SPECS, sims)("곡선")
        answers.append((out["ranked"], out["match_count"], out["mode"]))
    assert answers == [(["plot_b", "curve_a", "other_c", "other_d"], 4, "rrf")] * 4


def test_임베딩만으로_드는_후보는_순위로_자른다(monkeypatch):
    """부분문자열이 아무것도 못 맞히면 임베딩 순위 상위 20개가 후보다 — 21위는 코사인이 높아도(0.97) 들지 않는다."""
    specs = [("app1", f"t{i:02d}", "무관") for i in range(25)]
    search = _fused_kit(monkeypatch, specs, {f"t{i:02d}": 0.99 - 0.001 * i for i in range(25)})
    out = search("zzqq", limit=20)
    assert out["match_count"] == 20 == gw._TOOL_EMBED_DEPTH
    assert out["ranked"] == [f"t{i:02d}" for i in range(20)] and "t20" not in out["ranked"]
    assert "truncated" not in out


def test_부분문자열_점수가_같으면_같은_순위로_섞는다(monkeypatch):
    """점수가 같은 두 도구를 이름 차례로 1·2위에 두면 그 차례가 섞기에 끼어든다 — 같은 순위로 쳐서 임베딩이 가르게 한다."""
    specs = [("app1", "plot_x1", "곡선"), ("app1", "plot_x2", "곡선")]
    search = _fused_kit(monkeypatch, specs, {"plot_x1": 0.8, "plot_x2": 0.9})
    assert search("곡선")["ranked"] == ["plot_x2", "plot_x1"]
    monkeypatch.setattr(gw, "TOOL_SEARCH_EMBED_URL", "")
    assert search("곡선")["ranked"] == ["plot_x1", "plot_x2"], "전제 — 부분문자열은 동점을 이름 차례로 둔다"


def _drop_mode(out: dict) -> dict:
    return {k: v for k, v in out.items() if k not in ("mode", "mode_reason")}


def test_임베더가_실패하면_그_호출은_부분문자열_순위로_답하고_까닭을_말한다(monkeypatch):
    search = _fused_kit(monkeypatch, _SEARCH_SPECS, {})
    monkeypatch.setattr(gw, "TOOL_SEARCH_EMBED_URL", "")
    off = search("보고서 요약 report")
    monkeypatch.setattr(gw, "TOOL_SEARCH_EMBED_URL", "http://embedder.invalid/api/embed")

    async def down(texts, kind, timeout_s):
        raise httpx.ConnectError("connection refused")
    monkeypatch.setattr(gw, "_embed_texts", down)
    out = search("보고서 요약 report")
    assert out["mode"] == "substring" and out["mode_reason"] == "임베더 오류(ConnectError)"
    assert _drop_mode(out) == off, "까닭 두 칸 말고는 끈 답과 같다"


def test_임베더가_느리면_한도에서_끊고_부분문자열_순위로_답한다(monkeypatch):
    import time as _t
    search = _fused_kit(monkeypatch, _SEARCH_SPECS, {})
    monkeypatch.setattr(gw, "TOOL_SEARCH_EMBED_URL", "")
    off = search("물성 곡선")
    monkeypatch.setattr(gw, "TOOL_SEARCH_EMBED_URL", "http://embedder.invalid/api/embed")
    monkeypatch.setattr(gw, "TOOL_SEARCH_EMBED_TIMEOUT_S", 0.05)

    async def slow(texts, kind, timeout_s):
        await asyncio.sleep(5)
    monkeypatch.setattr(gw, "_embed_texts", slow)
    t0 = _t.monotonic()
    out = search("물성 곡선")
    assert _t.monotonic() - t0 < 2, "한도에서 끊어야 한다 — 임베더를 기다리지 않는다"
    assert out["mode"] == "substring" and "0.05초" in out["mode_reason"]
    assert _drop_mode(out) == off


def test_색인이_덜_찼으면_기다리지_않고_부분문자열로_답하며_색인을_건다(monkeypatch):
    calls = []
    _search_catalog(monkeypatch)
    monkeypatch.setattr(gw, "TOOL_SEARCH_EMBED_URL", "http://embedder.invalid/api/embed")
    _embed_fake(monkeypatch, {}, calls)

    class _TG:
        def __init__(self):
            self.started = []

        def start_soon(self, fn, *a):
            self.started.append(fn)
    tg = _TG()
    monkeypatch.setattr(gw, "_task_group_holder", {"tg": tg})
    out = json.loads(asyncio.run(gw._search_tools({"query": "심의"})).content[0].text)
    assert out["mode"] == "substring" and "색인" in out["mode_reason"]
    assert calls == [], "색인이 없으면 질의도 임베딩하지 않는다"
    assert tg.started == [gw._tool_index_refresh], "다음 검색 전에 색인을 채우게 뒤에서 건다"


def test_색인은_글의_해시로_두고_바뀐_것만_다시_임베딩한다(monkeypatch):
    calls = []
    tools = _search_catalog(monkeypatch, _CURVE_SPECS + [("app1", "other_e", "무관")])
    monkeypatch.setattr(gw, "_local_tools", lambda: [])
    monkeypatch.setattr(gw, "TOOL_SEARCH_EMBED_URL", "http://embedder.invalid/api/embed")
    monkeypatch.setattr(gw, "_TOOL_EMBED_BATCH", 2)
    _embed_fake(monkeypatch, {}, calls)
    asyncio.run(gw._tool_index_refresh())
    assert [len(t) for k, t in calls] == [2, 2, 1] and {k for k, _ in calls} == {"passage"}, "묶음으로 나눠 보낸다"
    assert all(t.startswith("App1 · ") for _, ts in calls for t in ts), "글은 '앱 라벨 · 이름: 설명' 이다"
    calls.clear()
    asyncio.run(gw._tool_index_refresh())
    assert calls == [], "바뀐 것이 없으면 임베더를 부르지 않는다"
    tools[0] = types.Tool(name="curve_a", description="설명을 고쳤다", inputSchema={"type": "object"})
    gw.exposed_tools[:] = tools
    asyncio.run(gw._tool_index_refresh())
    assert calls == [("passage", ["App1 · curve_a: 설명을 고쳤다"])] and len(gw._TOOL_VEC) == 5, "옛 글의 벡터는 버린다"
    calls.clear()
    gw.exposed_tools.pop()
    asyncio.run(gw._tool_index_refresh())
    assert calls == [] and len(gw._TOOL_VEC) == 4, "사라진 도구의 벡터도 버린다"


def test_색인을_채우는_중에_또_불리면_끝난_뒤_한_번_더_돈다(monkeypatch):
    """재집계가 잇따르면 갱신이 겹친다 — 둘이 함께 돌지 않고, 도는 중에 바뀐 카탈로그는 다음 바퀴가 마저 채운다."""
    _search_catalog(monkeypatch, _CURVE_SPECS)
    monkeypatch.setattr(gw, "_local_tools", lambda: [])
    monkeypatch.setattr(gw, "TOOL_SEARCH_EMBED_URL", "http://embedder.invalid/api/embed")

    async def scenario():
        started, release, n = asyncio.Event(), asyncio.Event(), {"calls": 0}

        async def slow(texts, kind, timeout_s):
            n["calls"] += 1
            started.set()
            await release.wait()
            return [[1.0, 0.0] for _ in texts], 0
        monkeypatch.setattr(gw, "_embed_texts", slow)
        first = asyncio.create_task(gw._tool_index_refresh())
        await started.wait()
        gw.exposed_tools.append(types.Tool(name="late", description="도는 중에 붙었다", inputSchema={"type": "object"}))
        await gw._tool_index_refresh()                                   # 곧바로 돌아온다 — 한 바퀴 더 돌라고만 남긴다
        assert n["calls"] == 1 and gw._TOOL_VEC_JOB == {"running": True, "again": True}
        release.set()
        await first
        return n["calls"]
    assert asyncio.run(scenario()) == 2
    assert all(gw._doc_key(gw._tool_doc(t)) in gw._TOOL_VEC for t in gw.exposed_tools) and len(gw._TOOL_VEC) == 5
    assert gw._TOOL_VEC_JOB == {"running": False, "again": False}


def test_색인이_실패해도_예외를_내지_않고_다음에_다시_건다(monkeypatch, caplog):
    _search_catalog(monkeypatch, _CURVE_SPECS)
    monkeypatch.setattr(gw, "_local_tools", lambda: [])
    monkeypatch.setattr(gw, "TOOL_SEARCH_EMBED_URL", "http://embedder.invalid/api/embed")

    async def down(texts, kind, timeout_s):
        raise httpx.ConnectError("connection refused")
    monkeypatch.setattr(gw, "_embed_texts", down)
    with caplog.at_level(logging.WARNING, logger="hwax-mcp-gateway"):
        asyncio.run(gw._tool_index_refresh())
    assert gw._TOOL_VEC == {} and gw._TOOL_VEC_JOB["running"] is False, "다음 검색이 다시 걸 수 있어야 한다"
    assert any("의미 색인을 채우지 못했다" in r.getMessage() for r in caplog.records)


def test_임베더_차원이_바뀌면_색인을_버리고_다시_채운다(monkeypatch):
    search = _fused_kit(monkeypatch, _CURVE_SPECS, {})
    _embed_fake(monkeypatch, {}, dim=3)                                   # 모델이 바뀌어 질의 벡터 길이가 달라졌다
    out = search("곡선")
    assert out["mode"] == "substring" and "차원" in out["mode_reason"]
    assert gw._TOOL_VEC == {}


def test_임베더_요청은_접두_없이_kind_로_보내고_꼴이_틀린_답은_예외다(monkeypatch):
    """e5 의 `query: `·`passage: ` 접두는 AIDataHub 가 kind 를 보고 붙인다 — 게이트웨이가 붙이면 두 번 붙는다."""
    seen, answer = [], {}

    def handler(request):
        seen.append(json.loads(request.content))
        return httpx.Response(answer.get("status", 200), json=answer.get("body"))
    real = httpx.AsyncClient
    monkeypatch.setattr(gw.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr(gw, "TOOL_SEARCH_EMBED_URL", "http://embedder.invalid/api/embed")
    answer["body"] = {"vectors": [[0.6, 0.8]], "dim": 2, "over_limit": [0]}
    vecs, over = asyncio.run(gw._embed_texts(["휨 불량"], "query", 1.0))
    assert seen == [{"texts": ["휨 불량"], "kind": "query"}] and vecs == [[0.6, 0.8]] and over == 1
    for status, body in ((500, {"detail": "encode failed"}), (200, {"vectors": []}), (200, {"vectors": [["x"]]}),
                         (200, {"vectors": [[0.1, 0.2], [0.3]]})):
        answer.update(status=status, body=body)
        texts = ["a", "b"] if len(body.get("vectors") or []) == 2 else ["a"]
        with pytest.raises((httpx.HTTPStatusError, ValueError)):
            asyncio.run(gw._embed_texts(texts, "passage", 1.0))


def test_재집계는_켜져_있을_때만_색인_갱신을_뒤에서_건다(monkeypatch):
    class _TG:
        def __init__(self):
            self.started = []

        def start_soon(self, fn, *a):
            self.started.append(fn)
    tg = _TG()
    monkeypatch.setattr(gw, "_task_group_holder", {"tg": tg})
    _aggregate_with(monkeypatch, {"signalforge": ["search_voc"]})
    assert tg.started == [], "꺼져 있으면 아무것도 걸지 않는다"
    monkeypatch.setattr(gw, "TOOL_SEARCH_EMBED_URL", "http://embedder.invalid/api/embed")
    _aggregate_with(monkeypatch, {"signalforge": ["search_voc"]})
    assert tg.started == [gw._tool_index_refresh]


_EMBED_PROBE = "import gateway as gw; print(repr(gw.TOOL_SEARCH_EMBED_URL)); print(gw.TOOL_SEARCH_EMBED_TIMEOUT_S)"


def test_의미_순위_손잡이는_env_에서_읽고_기본은_꺼짐이다(tmp_path):
    """상수를 monkeypatch 하는 시험은 env 를 읽는 줄이 사라져도 통과한다 — 실제로 import 해 본다. 0 이하의 한도는 다른 시간 한도와
    같은 규칙으로 따르지 않는다. 켠 주소의 호스트는 NO_PROXY 에 든다(사내 프록시로 나가지 않는다)."""
    (tmp_path / "cfg.json").write_text(json.dumps({"_gateway": {"token": "gw-test-token"}}), encoding="utf-8")

    def probe(**env):
        full = {k: v for k, v in os.environ.items() if not k.startswith(("GATEWAY_", "REST_PROXY_", "NO_PROXY", "no_proxy"))}
        full.update(GATEWAY_CONFIG=str(tmp_path / "cfg.json"), GATEWAY_AUDIT=str(tmp_path / "audit.jsonl"),
                    PYTHONDONTWRITEBYTECODE="1", **env)
        run = subprocess.run([sys.executable, "-c", _EMBED_PROBE], cwd=os.path.dirname(os.path.abspath(gw.__file__)),
                             env=full, capture_output=True, text=True, timeout=120)
        assert run.returncode == 0, run.stderr[-2000:]
        return run.stdout.split("\n")[:2], run.stderr
    assert probe()[0] == ["''", "2.0"], "기본은 꺼짐 · 질의 한도 2초"
    (url, timeout), log_ = probe(GATEWAY_TOOL_SEARCH_EMBED_URL=" http://embedder.corp.example:8001/api/embed ",
                                 GATEWAY_TOOL_SEARCH_EMBED_TIMEOUT="0.5")
    assert (url, timeout) == ("'http://embedder.corp.example:8001/api/embed'", "0.5")
    assert "embedder.corp.example" in log_.split("NO_PROXY 에 내부 목적지", 1)[1].split("\n", 1)[0]
    (_, timeout), log_ = probe(GATEWAY_TOOL_SEARCH_EMBED_TIMEOUT="0")
    assert timeout == "2.0" and "GATEWAY_TOOL_SEARCH_EMBED_TIMEOUT=0 " in log_


_LOG_PROBE = ("import logging, gateway as gw; r = logging.getLogger(); "
              "print(type(r.handlers[0].formatter).__name__ if r.handlers else '-'); "
              "print(logging.getLogger('httpx').getEffectiveLevel(), logging.getLogger('httpcore').getEffectiveLevel()); "
              "logging.getLogger('httpx').warning('HTTP Request: POST http://odb.example:8000/mcp?token=s3cr3t-Value')")


def test_로그는_쿼리의_비밀을_가리고_httpx_요청_줄은_찍지_않는다(tmp_path):
    """ODB 는 토큰을 주소 쿼리로 받는다 — httpx 의 INFO 요청 줄이 그 주소를 통째로 찍어 cae00 gateway.log 에 26,275줄이
    남았다(10-17 리뷰 G1). 요청 줄은 끄고, 예외 문구 · 트레이스백으로 찍히는 주소도 형식기가 가린다. 기동 꼴은 새 프로세스로 본다 —
    pytest 는 루트 로거에 먼저 처리기를 달아 import 시 basicConfig 가 아무것도 하지 않는다."""
    import logging
    import sys as _sys

    (tmp_path / "cfg.json").write_text(json.dumps({"_gateway": {"token": "gw-test-token"}}), encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("GATEWAY_")}
    env.update(GATEWAY_CONFIG=str(tmp_path / "cfg.json"), GATEWAY_AUDIT=str(tmp_path / "audit.jsonl"), PYTHONDONTWRITEBYTECODE="1")
    run = subprocess.run([sys.executable, "-c", _LOG_PROBE], cwd=os.path.dirname(os.path.abspath(gw.__file__)),
                         env=env, capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stderr[-2000:]
    kind, levels = run.stdout.split("\n")[:2]
    assert kind == "_MaskSecretsFormatter", kind
    assert all(int(x) >= logging.WARNING for x in levels.split()), levels
    assert "s3cr3t-Value" not in run.stderr and "?token=***" in run.stderr, run.stderr[-500:]

    fmt = gw._MaskSecretsFormatter("%(message)s")
    rec = logging.LogRecord("hwax-mcp-gateway", logging.WARNING, __file__, 1,
                            "연결 실패 %s", ("http://odb.example:8000/mcp?token=s3cr3t-Value&x=1",), None)
    out = fmt.format(rec)
    assert "s3cr3t-Value" not in out and "?token=***&x=1" in out
    try:
        raise RuntimeError("Client error for url 'http://odb.example:8000/mcp?api_key=abc123'")
    except RuntimeError:
        rec = logging.LogRecord("httpx", logging.ERROR, __file__, 1, "실패", (), _sys.exc_info())
    out = fmt.format(rec)
    assert "abc123" not in out and "api_key=***" in out, out
    # 비밀이 아닌 쿼리(email · groups)는 그대로다 — 가리는 범위를 넓히면 진단이 어려워진다.
    rec = logging.LogRecord("x", logging.INFO, __file__, 1, "GET /internal/access/entitlements?email=a@b.c", (), None)
    assert "email=a@b.c" in fmt.format(rec)


# ── 읽기 전용 포털 PAT(결정 5, 10-18) ─────────────────────────────────────────────
# 포털 PAT 의 scopes 가 read 만이면(read 있고 write 없음) 허용 목록(read_tools.json) · 앱이 단 readOnlyHint · 게이트웨이 자체 조회만.
# 챗 · 절차 PAT 의 ["chat"] 은 읽기 전용이 아니다. 표지는 게이트웨이가 PAT 분기에서만 싣고 클라이언트 사본은 두 분기 모두 버린다.
def test_읽기_전용_판정은_read_있고_write_없을_때만():
    from rest_proxy import is_read_only
    assert is_read_only({"scopes": ["read"]}) and is_read_only({"scopes": [" READ "]})
    assert not is_read_only({"scopes": ["read", "write"]}), "포털 기본 범위"
    assert not is_read_only({"scopes": ["chat"]}), "챗 · 절차 PAT — 'write 가 없으면 읽기' 로 보면 웹 챗이 막힌다"
    assert not is_read_only({}) and not is_read_only({"scopes": "read"}), "칸이 없거나 꼴이 틀리면 옛 기본(읽기 · 쓰기)"


def test_읽기_전용_표지는_PAT_분기에서만_싣고_위조는_버린다(monkeypatch):
    import asyncio
    seen = {}

    async def app(scope, receive, send):
        seen["h"] = {k.decode().lower(): v.decode() for k, v in scope["headers"]}

    async def no_portal(email, base, **_kw):
        return None
    monkeypatch.setattr(gw, "_portal_access", no_portal)
    monkeypatch.setattr(gw, "GW_TOKEN", "gw-secret")

    class _V:
        def __init__(self, claims): self.claims = claims
        async def verify(self, token, aud): return self.claims

    def run(auth, claims):
        seen.clear()
        hdrs = [(b"authorization", auth), (gw.READONLY_HEADER.encode(), b"1")]
        asyncio.run(gw._bearer_gate(app, _V(claims))({"type": "http", "path": "/mcp", "headers": hdrs}, None, None))
        return seen.get("h", {})
    assert run(b"Bearer ro", {"email": "u@x.io", "groups": [], "scopes": ["read"]})[gw.READONLY_HEADER] == "1"
    assert gw.READONLY_HEADER not in run(b"Bearer rw", {"email": "u@x.io", "groups": [], "scopes": ["read", "write"]}), \
        "읽기 · 쓰기 PAT 는 위조 표지가 살아남지 않는다"
    assert gw.READONLY_HEADER not in run(b"Bearer gw-secret", None), "GW_TOKEN 길도 클라이언트 사본을 버린다"


def _ro_setup(monkeypatch, headers):
    import asyncio
    hinted = types.Tool(name="get_hinted", description="", inputSchema={"type": "object"},
                        annotations=types.ToolAnnotations(readOnlyHint=True))
    b = _CallB(["list_parts", "export_step"])
    b.session._t.append(hinted)                                       # 재집계가 readOnlyHint 를 줍는지까지 본다
    monkeypatch.setattr(gw, "backends", {"heax-step_forge": b})
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "route", {})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "tool_readonly_hint", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "READ_TOOLS", frozenset({"heax-step_forge:list_parts"}))
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    asyncio.run(gw._aggregate())
    _set_request_headers(monkeypatch, headers)
    return b


def test_읽기_전용_토큰은_허용_목록_표시_자체_조회만(monkeypatch):
    _ro_setup(monkeypatch, {gw.READONLY_HEADER: "1"})
    assert gw.tool_readonly_hint[("heax-step_forge", "get_hinted")] is True, "재집계가 앱의 readOnlyHint 를 담는다"
    assert gw._readonly_denial("list_parts", {}) == "", "허용 목록"
    assert gw._readonly_denial("heaxstep_forge_list_parts", {}) == "", "별칭도 원래 이름으로 푼다"
    assert gw._readonly_denial("get_hinted", {}) == "", "앱이 단 readOnlyHint"
    why = gw._readonly_denial("export_step", {})
    assert why.startswith("read_only:") and "heax-step_forge:export_step" in why and "read_tools.json" in why, why
    for local in ("search_tools", "list_tool_apps", "rest_catalog", "search_conversations", "verify_answer"):
        assert gw._readonly_denial(local, {}) == "", local
    assert gw._readonly_denial("save_conversation", {}).startswith("read_only: save_conversation")
    assert gw._readonly_denial("rest_call", {"method": "get"}) == "" and gw._readonly_denial("rest_call", {}) == ""
    assert gw._readonly_denial("rest_call", {"method": "POST"}).startswith("read_only: rest_call POST")
    assert gw._readonly_denial("no_such_tool", {}) == "", "없는 도구는 'unknown tool' 로 끝난다"


def test_읽기_전용이면_call_tool_이_백엔드로_보내지_않고_감사에_남긴다(monkeypatch):
    import asyncio
    b = _ro_setup(monkeypatch, {gw.READONLY_HEADER: "1"})
    r = asyncio.run(gw._call_tool("export_step", {}))
    assert r.isError and r.content[0].text.startswith("read_only:")
    r2 = asyncio.run(gw._call_tool("invoke_tool", {"name": "heaxstep_forge_export_step", "arguments": {}}))
    assert r2.isError and r2.content[0].text.startswith("read_only:"), "invoke_tool 은 안쪽 도구로 본다"
    assert b.session.calls == [], f"막힌 호출이 백엔드까지 갔다: {b.session.calls}"
    assert not asyncio.run(gw._call_tool("list_parts", {})).isError and b.session.calls == ["list_parts"]
    lines = [json.loads(x) for x in open(gw.AUDIT_PATH, encoding="utf-8")]
    assert sum(1 for x in lines if x.get("error") == "read-only" or x.get("note") == "read-only") >= 2, lines[-3:]
    _set_request_headers(monkeypatch, {})                              # 읽기 · 쓰기 토큰이면 종전 그대로
    assert not asyncio.run(gw._call_tool("export_step", {})).isError and b.session.calls[-1] == "export_step"


def test_read_tools_파일이_온전하고_리스크_앱_도구를_담는다():
    data = json.load(open(gw.Path(gw.__file__).with_name("read_tools.json"), encoding="utf-8"))
    tools = data["tools"]
    assert tools == sorted(set(tools)) and all(t.count(":") == 1 and all(t.split(":")) for t in tools)
    for need in ("heax-step_forge:job_status", "heax-kooremapper_mcp:inspect_file", "signalforge:get_top_issues",
                 "ai-data-hub:recommend_agents", "heax-step_forge:system_status"):
        assert need in tools, need
    assert gw.READ_TOOLS == frozenset(tools)


def test_REST_다리도_읽기_전용_PAT_는_GET_HEAD_만(monkeypatch):
    """`/api/<site>/` 는 MCP 를 거치지 않는다 — 같은 규칙을 다리가 따로 건다(rest_proxy.is_read_only)."""
    import asyncio
    from starlette.requests import Request
    from rest_proxy import RestProxy

    async def allow(site, groups, email):
        return True

    async def no_revoked():
        return set()
    p = RestProxy({"s": {"base": "http://upstream.invalid", "methods": ["GET", "HEAD", "POST"]}}, {"audience_ok": ["s"]},
                  gw._audit, allow=allow)
    p._verify = lambda token, site: {"sub": "S", "email": "u@x.io", "jti": "j", "groups": [], "scopes": ["read"]}
    p._revoked_set = no_revoked
    resp = asyncio.run(p.handle(Request({
        "type": "http", "method": "POST", "path": "/api/s/x", "headers": [(b"authorization", b"Bearer t")],
        "query_string": b"", "path_params": {"site": "s", "path": "x"}, "client": ("127.0.0.1", 0)})))
    assert resp.status_code == 403 and b"read-only token" in resp.body
    rows = [json.loads(x) for x in open(gw.AUDIT_PATH, encoding="utf-8")]
    assert rows[-1]["error"] == "read-only" and rows[-1]["via"] == "pat"


def test_신원_전달_심의_호출에_포털의_지금_소속을_싣는다(monkeypatch):
    """심의 백엔드의 같은 소속 열람(결정 6, 10-18)이 이 값과 잡을 열 때 적은 소속을 견준다. 못 읽으면(빈 값) 싣지 않는다 — 빈 소속은
    누구와도 같은 소속이 아니다(열리지 않는 쪽)."""
    res, b, shots, row = _recon_kit(monkeypatch, "hwax-deliberation", session="none")
    assert not res.isError and shots[0].get(gw.AFF_FWD_HEADER) == "CAEG"
    res, b, shots, row = _recon_kit(monkeypatch, "hwax-deliberation", session="none", aff="")
    assert gw.AFF_FWD_HEADER not in shots[0], "소속을 모르면 싣지 않는다"


# ── search_tools 실사용 질의 모으기(HWAXPortal docs/followups-1017 결정 21 — 30일) ─────────────────────────────────────
# 평가셋에 실사용 질의가 없었다(감사 원장은 search_tools 를 남기지 않는다). 이름 · 주소 없이 날짜 · 질의 · 방식 · 상위 다섯만,
# 첫 줄 날짜부터 30일이 지나면 저절로 멈춘다. 시험 질의는 autouse `_no_prod_audit` 가 tmp 로 돌린다.
def _qlog_kit(monkeypatch):
    tools = [_tool("report_digest"), _tool("report_list")]
    monkeypatch.setattr(gw, "exposed_tools", tools)
    monkeypatch.setattr(gw, "route", {"report_digest": ("signalforge", "digest"), "report_list": ("signalforge", "list")})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    monkeypatch.setattr(gw, "_request_muted", lambda: set())
    monkeypatch.setattr(gw, "_request_user", lambda: "someone@example.com")


def _qlog_lines():
    return [r for r in gw._qlog_read() if "q" in r]


def _qlog_outcomes():
    return [r for r in gw._qlog_read() if "o" in r]


def test_search_tools_질의를_이름_없이_날짜_파일에_남긴다(monkeypatch):
    _qlog_kit(monkeypatch)
    out = json.loads(asyncio.run(gw._search_tools({"query": "Report 요약"})).content[0].text)
    assert out["ranked"][0] == "report_digest"
    [line] = _qlog_lines()
    assert set(line) <= {"d", "ts", "id", "q", "mode", "top", "fp", "via", "boost_only"}, "이름 · 주소 · 결과 전문은 남기지 않는다"
    assert line["q"] == "Report 요약", "질의는 원문(대소문자 그대로 — 임베딩에 주는 글)"
    assert line["mode"] == "substring" and line["top"][0] == "signalforge:digest", "정답은 평가셋 꼴(앱키:원래 이름)"
    today = gw.datetime.now(gw._KST).date().isoformat()
    assert line["d"] == today and (gw.TOOL_QUERY_LOG_DIR / f"queries-{today}.local.jsonl").exists()
    assert line["fp"] == gw._tuning()["fingerprint"], "어느 손잡이로 잰 질의인가"
    assert "someone@example.com" not in json.dumps(gw._qlog_read(), ensure_ascii=False)
    asyncio.run(gw._search_tools({"query": "x"}))                      # 2자 미만은 검색 오류 — 남기지 않는다
    assert len(_qlog_lines()) == 1


def test_search_tools_질의_기록은_굴러가는_창이다(monkeypatch):
    """10-18 결정 '30일' 을 일회성에서 굴러가는 창으로(E-9 ① — 고리는 cae00 에서 닫힌다). 날이 바뀔 때 창 밖의 날짜 파일을 지운다."""
    _qlog_kit(monkeypatch)
    gw.TOOL_QUERY_LOG_DIR.mkdir(parents=True)
    today = gw.datetime.now(gw._KST).date()
    for age in (gw.TOOL_QUERY_LOG_DAYS - 1, gw.TOOL_QUERY_LOG_DAYS):
        d = (today - gw.timedelta(days=age)).isoformat()
        (gw.TOOL_QUERY_LOG_DIR / f"queries-{d}.local.jsonl").write_text(json.dumps({"d": d, "q": f"옛 {age}", "top": []}) + "\n")
    gw.TOOL_QUERY_LOG.write_text(json.dumps({"d": "2026-01-01", "q": "옛 일회성", "top": []}) + "\n")
    asyncio.run(gw._search_tools({"query": "report"}))
    qs = [r["q"] for r in _qlog_lines()]
    assert qs == ["옛 일회성", f"옛 {gw.TOOL_QUERY_LOG_DAYS - 1}", "report"], qs
    assert gw.TOOL_QUERY_LOG.exists(), "옛 일회성 파일은 읽기만 한다(지우지 않는다)"
    assert [r["q"] for r in gw._qlog_read(days=1)] == ["report"], "days 를 주면 그날 수 안의 것만"


def test_search_tools_질의_모으기는_끌_수_있고_못_남겨도_검색은_답한다(monkeypatch, tmp_path):
    _qlog_kit(monkeypatch)
    monkeypatch.setattr(gw, "TOOL_QUERY_LOG_ON", False)
    asyncio.run(gw._search_tools({"query": "report"}))
    assert not gw.TOOL_QUERY_LOG_DIR.exists(), "GATEWAY_TOOL_QUERY_LOG=0"
    monkeypatch.setattr(gw, "TOOL_QUERY_LOG_ON", True)
    (tmp_path / "file").write_text("x")
    monkeypatch.setattr(gw, "TOOL_QUERY_LOG_DIR", tmp_path / "file" / "qlog")    # 파일 아래라 만들기가 실패한다
    out = json.loads(asyncio.run(gw._search_tools({"query": "report"})).content[0].text)
    assert out["ranked"], "남기기 실패가 검색을 막지 않는다"


def test_search_tools_귀속은_보정_덕에만_든_결과를_가린다(monkeypatch):
    """'요약' 은 도구 이름 · 설명에 없고 손 동의어(요약 → digest)로만 report_digest 에 닿는다 — boost_only. 'report' 는 이름에 그대로 있다."""
    _qlog_kit(monkeypatch)
    asyncio.run(gw._search_tools({"query": "요약"}))
    asyncio.run(gw._search_tools({"query": "report"}))
    a, b = _qlog_lines()
    assert a["top"][0] == "signalforge:digest" and a["via"]["signalforge:digest"] == ["syn:요약"], a
    assert a["boost_only"] == ["signalforge:digest"], "보정을 빼면 0점이다"
    assert "via" not in b and "boost_only" not in b, b


def test_search_tools_찾기_뒤의_호출은_결과_줄로_남는다(monkeypatch):
    """같은 호출자가 600초 안에 부른 백엔드 도구 — 순위 · 성공. 찾기 하나 · 도구 하나에 한 번이고, 결과에 없던 도구는 r 이 null 이다(E-9 ①)."""
    _qlog_kit(monkeypatch)
    monkeypatch.setattr(gw, "backends", {"signalforge": object()})
    monkeypatch.setattr(gw, "alias_route", {"signalforge_list": ("signalforge", "list")})
    asyncio.run(gw._search_tools({"query": "report digest"}))
    [q] = _qlog_lines()
    gw._audit("report_list", "signalforge", True, None, 5, caller="someone@example.com")
    gw._audit("report_list", "signalforge", True, None, 5, caller="someone@example.com")       # 같은 도구 — 한 번만
    gw._audit("signalforge_list", "signalforge", False, "boom", 5, caller="someone@example.com")  # 별칭도 같은 도구다
    gw._audit("report_list", "signalforge", True, None, 5, caller="other@example.com")          # 다른 호출자
    gw._audit("rest_call GET /x", "signalforge", True, None, 5, caller="someone@example.com")    # 도구가 아니다
    [o] = _qlog_outcomes()
    assert o["o"] == q["id"] and o["t"] == "signalforge:list" and o["r"] == q["top"].index("signalforge:list") + 1 and o["ok"] is True, o
    assert "caller" not in o and "someone" not in json.dumps(o)
    gw._RECENT_SEARCH["someone@example.com"] = (q["id"], gw.time.monotonic() - gw.SEARCH_OUTCOME_WINDOW_S - 1, {}, set())
    gw._audit("report_digest", "signalforge", True, None, 5, caller="someone@example.com")
    assert len(_qlog_outcomes()) == 1, "창(600초) 밖의 호출은 그 찾기의 결과가 아니다"
    asyncio.run(gw._search_tools({"query": "report digest"}))
    monkeypatch.setattr(gw, "route", {**gw.route, "elsewhere": ("signalforge", "elsewhere")})
    gw._audit("elsewhere", "signalforge", True, None, 5, caller="someone@example.com")
    assert _qlog_outcomes()[-1]["r"] is None, "결과에 없던 도구를 불렀다 — 찾기에서 못 보였다(설명 문제의 신호)"


# ── 검색 손잡이 파일 · 박스 덧씌우기(HWAXPortal docs/request-1029 E-7 · 설계 2.5 ①) ──────────────────────────────────────
def _tune(monkeypatch, tmp_path, overlay):
    p = tmp_path / "search_tuning.local.json"
    if overlay is None:
        p.unlink(missing_ok=True)
    else:
        p.write_text(overlay if isinstance(overlay, str) else json.dumps(overlay, ensure_ascii=False), encoding="utf-8")
        st = p.stat()
        gw.os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
    monkeypatch.setattr(gw, "SEARCH_TUNING_LOCAL_PATH", p)
    return gw._tuning()


def test_검색_손잡이_기본값은_옮기기_전_코드_상수와_같다():
    """기본값은 지금 순위와 바이트까지 같다(_SEARCH_TOOLS_MASTER 가 응답을 본다) — 여기서는 옮긴 값 자체를 본다."""
    d = gw._tuning()
    # 옮기기 전(10-29) 게이트웨이 코드 상수 그대로 — 기본값을 일부러 바꾸면 이 값을 함께 고친다(순위 기준 사본도 다시 뜬다)
    assert d["delib_ask"] == ('심의', '토의', '회의')
    assert d["quality_words"] == ('불량', '시장', '원인', '대책', '사례') and d["quality_areas"] == ("quality", "voc")
    assert d["write_intent"] == ('등록', '생성', '만들', '추가', '수정', '고치', '고쳐', '바꾸', '바꿔', '변경', '삭제', '지우', '지워', '저장', '올리', '올려', '업로드', '반입', '가져오', '실행', '돌리', '돌려', '제출', '시작', '걸어', '적용', '반영', '보내', '발행', '게시', '취소', '중지', '멈추', '멈춰', '학습', '이어서', '다시 돌', '채워', '채우', '넣어', '넣고', '남기', '남겨', '붙여', '붙이', '기각', '승인', '심의', '토의', '심사', '회의', 'create', 'add ', 'update', 'edit', 'modify', 'delete', 'remove', 'save', 'register', 'upload', 'import', 'run ', 'execute', 'submit', 'start', 'launch', 'apply', 'publish', 'send', 'cancel', 'stop', 'train', 'rename')
    assert d["weights"] == {"name": 4, "desc_cap": 3, "app": 1, "coverage": 1, "write_penalty": 0.5, "quality_per_word": 2}
    assert all(d["switches"].values()) and len(d["synonyms"]) == 73 and d["synonyms"]["요약"] == ("digest", "summary")
    assert d["fingerprint"] == d["base_fingerprint"] and gw._tuning_health()["overlay"] == {"present": False}


def test_검색_손잡이_덧씌우기는_merge_patch_로_얹고_재기동_없이_읽는다(monkeypatch, tmp_path):
    _qlog_kit(monkeypatch)
    base = gw._tuning()
    d = _tune(monkeypatch, tmp_path, {"switches": {"synonyms": False}, "synonyms": {"요약": None, "다이제스트": {"to": ["digest"]}},
                                      "weights": {"name": 5}})
    assert d["switches"]["synonyms"] is False and "요약" not in d["synonyms"] and d["synonyms"]["다이제스트"] == ("digest",)
    assert d["weights"]["name"] == 5 and d["weights"]["app"] == 1, "객체는 합치고 그 밖은 바꾼다"
    assert d["fingerprint"] != base["fingerprint"] and d["base_fingerprint"] == base["base_fingerprint"]
    h = gw._tuning_health()
    assert h["switches_off"] == ["synonyms"] and h["overlay"]["present"] is True and h["overlay"]["fingerprint"]
    assert set(h["overlay"]["changed"]) == {"switches.synonyms", "synonyms.요약", "synonyms.다이제스트", "weights.name"}, h
    out = json.loads(asyncio.run(gw._search_tools({"query": "요약"})).content[0].text)
    assert "report_digest" not in out["ranked"], "손 동의어를 끄면 '요약' 은 report_digest(이름 · 설명에 그 낱말이 없다)에 안 닿는다"
    _tune(monkeypatch, tmp_path, None)
    out = json.loads(asyncio.run(gw._search_tools({"query": "요약"})).content[0].text)
    assert out["ranked"][0] == "report_digest", "덧씌우기를 지우면 기본값으로 돌아온다"


def test_검색_손잡이_덧씌우기가_깨지면_버리고_기본값으로_돈다(monkeypatch, tmp_path):
    base = gw._tuning()
    for bad in ("{깨진", "[]", json.dumps({"weights": {"name": "넷"}}), json.dumps({"synonyms": {"x": {"to": "y"}}})):
        d = _tune(monkeypatch, tmp_path, bad)
        assert d["fingerprint"] == base["fingerprint"], bad
        assert "덧씌우기를 버렸다" in gw._tuning_health()["overlay"]["error"], bad


def test_검색_손잡이_묶음별로_끈다(monkeypatch, tmp_path):
    """품질 가중 · 쓰기 감점 · 사본 접기를 하나씩 끄면 그것만 빠진다."""
    _search_catalog(monkeypatch)
    _no_embed(monkeypatch)
    q = "시장 불량 원인 대책"
    on = json.loads(asyncio.run(gw._search_tools({"query": q, "limit": 20})).content[0].text)["ranked"]
    _tune(monkeypatch, tmp_path, {"switches": {"quality": False}})
    off = json.loads(asyncio.run(gw._search_tools({"query": q, "limit": 20})).content[0].text)["ranked"]
    assert on.index("search_voc") < off.index("search_voc"), (on, off)
    _tune(monkeypatch, tmp_path, {"switches": {"write_penalty": False}})
    w = json.loads(asyncio.run(gw._search_tools({"query": "회의", "limit": 20})).content[0].text)["ranked"]
    assert w.index("meeting_start") <= on.index("meeting_start") if "meeting_start" in on else True


def test_평가_러너는_실사용_질의_파일에_쓰지_않는다():
    src = (gw.Path(gw.__file__).parent / "tool_search_eval" / "run.py").read_text(encoding="utf-8")
    i = src.index("def _import_gateway")
    body = src[i:src.index("import gateway as gw", i)]
    assert 'os.environ["GATEWAY_TOOL_QUERY_LOG"] = "0"' in body, "142쌍 평가 질의가 실사용 질의에 섞인다"


def test_검토_표시를_평가셋에_되돌린다(tmp_path):
    """검토 화면(결정 21)의 표시 — 맞음은 reviewed, 고침은 정답 · 질의를 바꾸고 reviewed, 빼기는 줄을 지운다. 틀린 꼴은 건너뛰고 센다."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("apply_review", gw.Path(gw.__file__).parent / "tool_search_eval" / "apply_review.py")
    ar = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ar)
    pairs = [{"id": f"p{i}", "query": f"질의{i}", "gold": [f"app:t{i}"], "source": "auto", "reviewed": False} for i in range(6)]
    marks_dir = tmp_path / "marks"
    marks_dir.mkdir()
    docs = {
        "p0": {"verdict": "ok", "memo": "  맞다  "},
        "p1": {"id": "p1", "data": {"verdict": "fix", "gold": ["app:t1", "app:x", "app:x"], "query": "고친 질의"}, "version": 3},
        "p2": {"verdict": "drop"},
        "p3": {"verdict": "fix", "gold": ["이름만"]},
        "p4": {"verdict": "maybe"},
        "zz": {"verdict": "ok"},
    }
    for k, v in docs.items():
        (marks_dir / f"{k}.json").write_text(json.dumps(v, ensure_ascii=False), encoding="utf-8")
    new, rep = ar.apply(pairs, ar.load_marks(marks_dir))
    by = {p["id"]: p for p in new}
    assert [p["id"] for p in new] == ["p0", "p1", "p3", "p4", "p5"], "빼기는 줄을 지운다"
    assert by["p0"]["reviewed"] is True and by["p0"]["review_memo"] == "맞다"
    assert by["p1"] == {**pairs[1], "query": "고친 질의", "gold": ["app:t1", "app:x"], "reviewed": True}, "내려받은 꼴 {id, data, version}"
    assert by["p3"] == pairs[3] and by["p4"] == pairs[4] and by["p5"] == pairs[5], "틀린 고침 · 모르는 표시 · 표시 없음은 그대로"
    assert sorted(pid for pid, _ in rep["skipped"]) == ["p3", "p4", "zz"], "건너뛴 것을 센다(평가셋에 없는 id 포함)"
    assert pairs[1]["reviewed"] is False, "원래 목록은 바꾸지 않는다"


# ── 외부 연결 선언(HWAXPortal docs/ext-connect) — 포털 박스 권한표의 connect: 로 토큰 등록 플랫폼을 코드 없이 붙인다 ───────────────
import hashlib  # noqa: E402
import stat  # noqa: E402

import anyio  # noqa: E402


@pytest.fixture(autouse=True)
def _no_conn_state(monkeypatch, tmp_path):
    """선언 상태는 프로세스 전역이다 — 시험마다 새것으로 둔다. 맞추기가 PORTAL_CONN_* 를 고치므로 사본으로 바꿔 끼우고, 선언 캐시는 tmp 에,
    재활 잠금도 새것이다(앞 시험이 쥔 채 끝나도 다음 시험이 매달리지 않게)."""
    monkeypatch.setattr(gw, "_CONN_REG", {})
    monkeypatch.setattr(gw, "_CONN_ACTIVE", set())
    monkeypatch.setattr(gw, "_CONN_STATUS", {})
    monkeypatch.setattr(gw, "_CONN_SINCE", {})
    monkeypatch.setattr(gw, "_CONN_NOLIST_BACKOFF", {})
    monkeypatch.setattr(gw, "_CONN_TOKEN_MASK", None)
    monkeypatch.setattr(gw, "_CONN_CACHE_FILE", tmp_path / "conn_registry_cache.json")
    monkeypatch.setattr(gw, "PORTAL_CONN_BACKENDS", dict(gw.PORTAL_CONN_BACKENDS))
    monkeypatch.setattr(gw, "PORTAL_CONN_META", {k: dict(v) for k, v in gw.PORTAL_CONN_META.items()})
    monkeypatch.setattr(gw, "_REVIVE_LOCK", anyio.Lock())


# 포털 `gateway_connections()` 가 내는 꼴 그대로(주소는 예시 도메인).
_MNX = {"platform": "matnexus", "label": "MatNexus", "desc": "물성 DB", "hint": "mnx_pat_…", "prefix": "mnx_pat_",
        "mcp_url": "http://mnx.example:8012/mcp", "list_auth": "open", "read_tools": [], "workspace_header": ""}
_FMEA = {**_MNX, "platform": "fmea", "label": "FMEA Agent", "desc": "FMEA", "hint": "fmea_…", "prefix": "fmea_",
         "mcp_url": "http://fmea.example:5190/mcp", "list_auth": "registered:list@corp.com"}
_ROWS = {"matnexus": ["plat:matnexus"], "fmea": ["plat:fmea"]}


def _conn_kit(monkeypatch, *, lookup=None):
    """실제 `_Backend` · `_conn_reconcile` · `_revive_once` · `_aggregate` 를 돌릴 판 — 전송 계층과 목록 계정의 연결 조회만 막는다.
    상주 세션이 열릴 때 받은 헤더와 그때의 NO_PROXY 를 남긴다(돌려주는 opened). 조회는 `lookup`(없으면 목록 토큰 하나)."""
    opened: list = []

    class _Sess:
        def __init__(self, url): self.url = url

        async def initialize(self): return None

        async def list_tools(self):
            app = "mnx" if "mnx." in self.url else "fmea"
            return _Res([_tool("get_material" if app == "mnx" else "get_fmea"), _tool(f"list_{app}")])

        async def call_tool(self, *a, **k):
            raise AssertionError("목록 전용 세션으로 도구를 불렀다")

    def fake_stream(url, headers=None, **_kw):
        opened.append((url, dict(headers or {}), os.environ.get("NO_PROXY", "")))
        return _StubCM((url, None, "sid"))

    seen: list = []

    async def fake_lookup(service, email):
        seen.append((service, email))
        if lookup is not None:
            return await lookup(service, email)
        return {"token": "fmea_list0tok1", "workspace": ""}
    monkeypatch.setattr(gw, "streamablehttp_client", fake_stream)
    monkeypatch.setattr(gw, "ClientSession", lambda read, write: _StubCM(_Sess(read)))
    monkeypatch.setattr(gw, "_portal_connection", fake_lookup)
    monkeypatch.setattr(gw, "LIVENESS_TIMEOUT_S", 1.0)
    monkeypatch.setattr(gw, "HEAX", {})
    for name in ("backends", "route", "alias_route", "_FP", "_LAST_TOOLS", "_LIVENESS_MISS", "DISCOVERED_META", "POLICY",
                 "_REAGG", "tool_readonly_hint"):
        monkeypatch.setattr(gw, name, {})
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "_ACCESS_POLICY", dict(_ROWS))
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")
    return opened, seen


def _in_tg(fn):
    """fn(tg) 를 태스크 그룹 안에서 돌리고, 끝나면 세션 태스크를 거둔다."""
    async def go():
        async with anyio.create_task_group() as tg:
            try:
                return await fn(tg)
            finally:
                for b in list(gw.backends.values()):
                    if getattr(b, "_stop", None) is not None:
                        b._stop.set()
                tg.cancel_scope.cancel()
    return asyncio.run(asyncio.wait_for(go(), 10))


def _declare(key, spec):
    """맞추기를 거치지 않고 선언 하나를 붙은 상태로 둔다(호출 경로만 보는 시험)."""
    got, why = gw._conn_validate(key, dict(spec), {key: [f"plat:{key}"]})
    assert why == "ok", why
    gw._CONN_REG[key] = got
    gw._CONN_ACTIVE.add(key)
    gw._conn_meta_set(key, got)
    return got


def test_선언_하나로_목록_전용_백엔드가_생기고_목록_토큰은_목록_세션에만_실린다(monkeypatch):
    opened, seen = _conn_kit(monkeypatch)
    assert gw._conn_registry_set({"matnexus": dict(_MNX), "fmea": dict(_FMEA)}, _ROWS) is True

    async def go(tg):
        changed = await gw._conn_reconcile(tg)
        return changed, {k: (type(b) is gw._Backend, b.headers, b.list_headers, b.list_only, b.session is not None)
                         for k, b in gw.backends.items()}
    changed, made = _in_tg(go)
    assert changed is True
    assert made == {"matnexus": (True, {}, {}, True, True),
                    "fmea": (True, {}, {"Authorization": "Bearer fmea_list0tok1"}, True, True)}, \
        "바탕 헤더는 비어 있다 — 사람별 단발 세션이 목록 자격을 물려받을 수 없게"
    by = {u: (h, np) for u, h, np in opened}
    assert not any(k.lower() == "authorization" for k in by[_MNX["mcp_url"]][0]), "open 은 자격 없이 연다"
    assert by[_FMEA["mcp_url"]][0]["Authorization"] == "Bearer fmea_list0tok1"
    assert "mnx.example" in by[_MNX["mcp_url"]][1] and "fmea.example" in by[_FMEA["mcp_url"]][1], "세션을 열기 전에 프록시에서 뺀다"
    assert seen == [("fmea", "list@corp.com")], "목록 계정의 등록만 묻는다(open 은 묻지 않는다)"
    assert gw.PORTAL_CONN_BACKENDS["fmea"] == "fmea" and gw.PORTAL_CONN_META["fmea"]["label"] == "FMEA Agent"
    assert gw.DISCOVERED_META["matnexus"] == {"label": "MatNexus", "description": "물성 DB"}, "앱 이름이 'Matnexus' 가 되지 않게"
    assert gw._CONN_STATUS == {"matnexus": "ok", "fmea": "ok"} and gw._CONN_ACTIVE == {"matnexus", "fmea"}


def test_목록_계정이_등록하지_않았으면_백엔드를_만들지_않고_포털을_못_물으면_건드리지_않는다(monkeypatch):
    async def none(service, email):
        return None
    _conn_kit(monkeypatch, lookup=none)
    gw._conn_registry_set({"fmea": dict(_FMEA)}, _ROWS)
    assert _in_tg(gw._conn_reconcile) is False
    assert gw.backends == {} and gw._CONN_STATUS == {"fmea": "no-list-token"}

    async def down(service, email):
        raise gw._ConnLookupError("503")
    _conn_kit(monkeypatch, lookup=down)
    gw._CONN_STATUS.clear()
    assert _in_tg(gw._conn_reconcile) is False
    assert gw.backends == {} and gw._CONN_STATUS == {}, "모름은 '없음' 이 아니다 — 이번 패스에는 그 키를 건드리지 않는다"


def test_HG09_목록_계정이_등록하지_않은_동안은_묻는_간격을_두_배씩_10분까지_늘리고_상태가_바뀔_때만_남긴다(monkeypatch, caplog):
    """10-25 stepforge-prod 'no-list-token' — 재활 주기(60초)마다 포털에 물어 그 404 가 포털 로그에 하루 약 1,400줄이었다
    (HWAXPortal docs/request-1027 HG-09). 시계를 갈아 끼워 패스 스무 번(20분)을 돌린다."""
    import logging
    state = {"token": None}

    async def lookup(service, email):
        return None if state["token"] is None else {"token": state["token"], "workspace": ""}
    _opened, seen = _conn_kit(monkeypatch, lookup=lookup)
    clk = _Clock()
    monkeypatch.setattr(gw, "time", clk)
    gw._conn_registry_set({"fmea": dict(_FMEA)}, _ROWS)

    async def passes(tg, n):
        for _ in range(n):
            await gw._conn_reconcile(tg)
            clk.now += gw.REVIVE_INTERVAL_S
    with caplog.at_level(logging.INFO, logger=gw.log.name):
        _in_tg(lambda tg: passes(tg, 20))
    asked_at = len(seen)
    assert asked_at == 5, f"60 · 120 · 240 · 480 · 600 간격이면 20분에 다섯 번이다: {asked_at}"
    assert gw._CONN_STATUS["fmea"] == "no-list-token" and gw._CONN_SINCE["fmea"].endswith("+00:00")
    assert [r.message for r in caplog.records if "외부 연결 fmea:" in r.message] == ["외부 연결 fmea: (처음) → no-list-token"], \
        "같은 상태를 패스마다 찍지 않는다"
    # 목록 계정이 등록했다 — 포털이 /conn-invalidate 를 부르면(또는 /refresh) 다음 패스가 바로 다시 묻고 붙는다
    state["token"] = "fmea_list0tok1"
    gw._CONN_NOLIST_BACKOFF.clear()            # /conn-invalidate · /refresh 가 하는 일(아래 시험이 두 길을 본다)
    _in_tg(lambda tg: passes(tg, 1))
    assert len(seen) == asked_at + 1 and gw._CONN_STATUS["fmea"] == "ok" and "fmea" not in gw._CONN_NOLIST_BACKOFF


def test_HG09_conn_invalidate_와_refresh_가_백오프를_비우고_health_는_since_를_따로_싣는다(monkeypatch):
    import asyncio
    monkeypatch.setattr(gw, "GW_TOKEN", "gw-secret")
    gw._CONN_NOLIST_BACKOFF["fmea"] = (1e12, 600.0)
    sent = []

    async def recv():
        return {"type": "http.request", "body": b""}

    async def send(m):
        sent.append(m)

    async def app(scope, receive, send_):
        raise AssertionError("게이트가 처리할 길이다")
    gate = gw._bearer_gate(app)
    asyncio.run(gate({"type": "http", "path": "/conn-invalidate", "method": "POST", "query_string": b"email=list%40corp.com",
                      "headers": [(b"authorization", b"Bearer gw-secret")]}, recv, send))
    assert sent[0]["status"] == 200 and gw._CONN_NOLIST_BACKOFF == {}
    # 손으로 부른 /refresh 도 비운다 — 운영자가 목록 계정 등록 뒤 바로 붙이려고 부른다
    gw._CONN_NOLIST_BACKOFF["fmea"] = (1e12, 600.0)
    monkeypatch.setattr(gw, "_task_group_holder", {"tg": object()})
    monkeypatch.setattr(gw, "_refresh_access_policy", _noop_async(True))
    monkeypatch.setattr(gw, "_revive_once", _noop_async(False))
    sent.clear()
    asyncio.run(gate({"type": "http", "path": "/refresh", "method": "POST", "query_string": b"",
                      "headers": [(b"authorization", b"Bearer gw-secret")]}, recv, send))
    assert sent[0]["status"] == 200 and gw._CONN_NOLIST_BACKOFF == {}
    gw._CONN_STATUS.update({"fmea": "no-list-token", "matnexus": "ok"})
    gw._CONN_SINCE.update({"fmea": "2026-10-28T01:02:03+00:00", "gone": "2026-10-01T00:00:00+00:00"})
    sent.clear()
    asyncio.run(gate({"type": "http", "path": "/health", "method": "GET", "query_string": b"", "headers": []}, recv, send))
    body = json.loads(b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body"))
    assert body["conn_platforms"]["fmea"] == "no-list-token", "상태 칸은 종전 꼴(글자) 그대로 — update-all · mcp-smoke 가 읽는다"
    assert body["conn_since"] == {"fmea": "2026-10-28T01:02:03+00:00"}, "지금 상태가 있는 키만"


def test_목록_토큰이_바뀌면_그_세션만_갈아_끼우고_목록_계정이_지우면_뗀다(monkeypatch):
    tokens = {"t": "fmea_list0tok1"}

    async def lookup(service, email):
        return None if tokens["t"] is None else {"token": tokens["t"], "workspace": ""}
    _conn_kit(monkeypatch, lookup=lookup)
    gw._conn_registry_set({"matnexus": dict(_MNX), "fmea": dict(_FMEA)}, _ROWS)

    async def go(tg):
        await gw._conn_reconcile(tg)
        mnx, f1 = gw.backends["matnexus"], gw.backends["fmea"]
        same = await gw._conn_reconcile(tg)
        tokens["t"] = "fmea_list0tok2"                      # 목록 계정이 카드에서 다시 등록했다(포털이 /conn-invalidate 를 부른다)
        swapped = await gw._conn_reconcile(tg)
        f2 = gw.backends["fmea"]
        out = (same, swapped, mnx is gw.backends["matnexus"], f1 is not f2, f1._stop.is_set(), dict(f2.list_headers))
        tokens["t"] = None                                  # 목록 계정이 토큰을 지웠다 — 지운 토큰으로 목록을 계속 받지 않는다
        gone = await gw._conn_reconcile(tg)
        return (*out, gone, f2._stop.is_set(), "fmea" in gw.backends, gw._CONN_STATUS.get("fmea"))
    same, swapped, mnx_kept, replaced, old_stopped, lh, gone, new_stopped, left, status = _in_tg(go)
    assert same is False and swapped is True and mnx_kept and replaced and old_stopped
    assert lh == {"Authorization": "Bearer fmea_list0tok2"}
    assert gone is True and new_stopped and not left and status == "no-list-token"


def test_재활_패스_둘이_겹치지_않는다_한_패스가_백엔드를_도는_사이에_다른_패스가_선언_백엔드를_넣지_않는다(monkeypatch):
    """주기 루프와 POST /refresh 가 같은 함수를 부른다. 한 패스가 재연결 루프에서 `backends` 를 돌며 기다리는 사이 다른 패스가 선언
    백엔드를 넣으면 `dictionary changed size during iteration` 으로 패스가 죽는다 — heax 합류에도 있던 위험이다(HWAXPortal docs/ext-connect
    GW6). 잠금이 있으면 뒤 패스가 기다렸다가 돌고, 백엔드는 한 번만 생긴다."""
    _conn_kit(monkeypatch)
    made: list = []
    real = gw._Backend

    class _Counting(real):
        def __init__(self, *a, **k):
            made.append(a[0])
            super().__init__(*a, **k)

    class _SlowB(_CallB):
        """세션이 죽어 재연결 루프가 기다리는 백엔드."""
        def __init__(self):
            super().__init__(["slow_tool"])
            self.session = None

        async def reconnect(self, tg, seen_gen=None):
            await asyncio.sleep(0.1)
            self.session = _CallSess([_tool("slow_tool")])
    monkeypatch.setattr(gw, "_Backend", _Counting)
    gw.backends["slow"] = _SlowB()

    async def go(tg):
        first = asyncio.ensure_future(gw._revive_once(tg))         # 주기 패스 — 재연결 루프에서 기다린다
        await asyncio.sleep(0.02)
        gw._conn_registry_set({"matnexus": dict(_MNX)}, _ROWS)      # 그 사이 정책 루프가 새 선언을 받았다
        second = asyncio.ensure_future(gw._revive_once(tg))        # POST /refresh
        await asyncio.gather(first, second)
        return sorted(gw.backends), sorted(gw.route)
    keys, tools = _in_tg(go)
    assert made == ["matnexus"] and keys == ["matnexus", "slow"]
    assert tools == ["get_material", "list_mnx", "slow_tool"]


def test_선언을_지우면_다음_패스에_세션과_경로가_사라지고_집계_뒤에야_지킴이_풀린다(monkeypatch):
    _conn_kit(monkeypatch)
    gw._conn_registry_set({"matnexus": dict(_MNX)}, _ROWS)

    async def go(tg):
        await gw._revive_once(tg)
        b = gw.backends["matnexus"]
        before = (sorted(gw.route), set(gw._CONN_ACTIVE), gw._deny_reason("matnexus", ["plat:matnexus"]))
        gw._conn_registry_set({}, _ROWS)                    # 박스 파일에서 connect: 를 지웠다 — 행은 남아 있다(추적 행이 되살아남)
        mid = gw._deny_reason("matnexus", ["plat:matnexus"]), gw._deny_reason("matnexus", [gw.SERVICE_GROUP])
        changed = await gw._revive_once(tg)
        return before, mid, changed, b._stop.is_set(), sorted(gw.route), set(gw._CONN_ACTIVE), set(gw.backends)
    before, mid, changed, stopped, route_after, active, keys = _in_tg(go)
    assert before == (["get_material", "list_mnx"], {"matnexus"}, None)
    assert mid == ("gateway_group", "gateway_group"), "패스 전에도 닫힌다 — 내부 서비스 호출에도"
    assert changed is True and stopped and route_after == [] and active == set() and keys == set()
    assert set(gw.PORTAL_CONN_BACKENDS) == {"reportarchive", "testscope"} and "matnexus" not in gw._CONN_STATUS


def test_선언만_바뀌면_세션은_두고_재집계해_읽기_도구가_바로_선다(monkeypatch):
    opened, _ = _conn_kit(monkeypatch)
    gw._conn_registry_set({"matnexus": dict(_MNX)}, _ROWS)

    async def go(tg):
        await gw._revive_once(tg)
        b = gw.backends["matnexus"]
        h0 = gw.tool_readonly_hint.get(("matnexus", "get_material"))
        gw._conn_registry_set({"matnexus": {**_MNX, "read_tools": ["get_material"], "label": "MatNexus DB"}}, _ROWS)
        changed = await gw._revive_once(tg)
        return (h0, changed, b is gw.backends["matnexus"], b._stop.is_set(),
                gw.tool_readonly_hint.get(("matnexus", "get_material")), len(opened), gw.DISCOVERED_META["matnexus"]["label"])
    h0, changed, same, stopped, h1, n_open, label = _in_tg(go)
    assert h0 is False and changed is True and same and not stopped and n_open == 1, "세션을 갈지 않는다"
    assert h1 is True and label == "MatNexus DB"


def test_선언이_아닌_백엔드가_쓰는_키는_맞추기가_덮지_않는다(monkeypatch):
    opened, _ = _conn_kit(monkeypatch)
    other = _B([_tool("x")])
    gw.backends["matnexus"] = other                         # 선언이 아닌 길로 이미 표에 있다
    gw._CONN_REG["matnexus"] = gw._conn_validate("matnexus", dict(_MNX), _ROWS)[0]
    assert _in_tg(gw._conn_reconcile) is False
    assert gw.backends["matnexus"] is other and opened == [] and gw._CONN_STATUS["matnexus"] == "collision"
    assert "matnexus" not in gw._CONN_ACTIVE and "matnexus" not in gw.PORTAL_CONN_BACKENDS


@pytest.mark.parametrize("key", ["signalforge", "heax-step_forge", "testscope", "reportarchive", "newapp", "hwax-deliberation"])
def test_정적_heax_내장_위임_신원전달_키와_겹치는_선언은_collision(monkeypatch, key):
    """위임 키와 겹치면 위임 분기(if/elif)가 먼저 타 신원 없는 호출을 상주 세션까지 내린다 — 목록 토큰으로 부르게 된다(요청서 1-4 ⑤)."""
    _conn_kit(monkeypatch)
    monkeypatch.setattr(gw, "BACKENDS", {"signalforge": {"url": "http://sf.example/mcp"}})
    monkeypatch.setattr(gw, "PER_USER_SSO", {"newapp": {"sso_url": "http://newapp.example/sso", "secret": "s"}})
    monkeypatch.setattr(gw, "IDENTITY_FWD", {"hwax-deliberation"})
    gw._conn_registry_set({key: dict(_MNX)}, {key: ["plat:x"]})
    assert gw._CONN_REG == {} and gw._CONN_STATUS == {key: "collision"}
    assert _in_tg(gw._conn_reconcile) is False and gw.backends == {}


_BAD_CONN = {
    "u-at": {"mcp_url": "http://u@mnx.example/mcp"},
    "u-query": {"mcp_url": "http://mnx.example/mcp?token=x"},
    "u-frag": {"mcp_url": "http://mnx.example/mcp#f"},
    "u-scheme": {"mcp_url": "ftp://mnx.example/mcp"},
    "u-zone": {"mcp_url": "http://[fe80::1%25eth0]:8012/mcp"},     # NO_PROXY 에 적을 수 없는 호스트
    "u-port": {"mcp_url": "http://mnx.example:99999/mcp"},
    "u-none": {"mcp_url": None},
    "la-email": {"list_auth": "registered:nobody"},
    "la-kind": {"list_auth": "token:abc"},
    "wh-auth": {"workspace_header": "Authorization"},
    "wh-hwax": {"workspace_header": "X-Hwax-User"},
    "wh-mcp": {"workspace_header": "Mcp-Session-Id"},
    "wh-shape": {"workspace_header": "X Slug"},
    "rt-str": {"read_tools": "get_a"},
    "rt-shape": {"read_tools": ["get a"]},
    "label-type": {"label": 3},
}


@pytest.mark.parametrize("key", sorted(_BAD_CONN))
def test_꼴이_틀린_선언은_invalid_이고_나머지는_받는다(monkeypatch, key):
    _conn_kit(monkeypatch)
    rows = {key: ["plat:x"], "fmea": ["plat:fmea"]}
    gw._conn_registry_set({key: {**_MNX, **_BAD_CONN[key]}, "fmea": dict(_FMEA)}, rows)
    assert set(gw._CONN_REG) == {"fmea"} and gw._CONN_STATUS == {key: "invalid"}


def test_권한_행이_없는_선언과_틀린_키는_받지_않고_다시_받으면_옛_사유를_지운다(monkeypatch):
    _conn_kit(monkeypatch)
    gw._conn_registry_set({"fmea": dict(_FMEA), "Bad_Key": dict(_MNX)}, {"Bad_Key": ["plat:x"]})
    assert gw._CONN_REG == {} and gw._CONN_STATUS == {"fmea": "no-policy-row", "Bad_Key": "invalid"}
    gw._conn_registry_set({"fmea": dict(_FMEA)}, _ROWS)
    assert set(gw._CONN_REG) == {"fmea"} and gw._CONN_STATUS == {}, "선언에서 빠진 키 · 이제 받는 키의 옛 사유는 남기지 않는다"


def test_정책_갱신이_선언을_같은_응답에서_읽고_캐시는_0600_이며_옛_포털이면_선언이_빈다(monkeypatch, tmp_path):
    monkeypatch.setattr(gw, "_ACCESS_CACHE_FILE", tmp_path / "ap.json")
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    # 응답만 바꿔 끼운다 — _mock_http 를 두 번 걸면 가짜 클라이언트가 겹친다.
    answer = {"status": 200, "json": {"backends": _ROWS, "connections": {"matnexus": _MNX, "fmea": _FMEA}}}
    _mock_http(monkeypatch, lambda req: httpx.Response(answer["status"], json=answer["json"]))
    assert asyncio.run(gw._refresh_access_policy()) is True
    assert set(gw._CONN_REG) == {"matnexus", "fmea"} and gw._CONN_REG["fmea"]["list_auth"] == "registered:list@corp.com"
    f = gw._CONN_CACHE_FILE
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert set(json.loads(f.read_text(encoding="utf-8"))) == {"matnexus", "fmea"}
    assert "Bearer" not in f.read_text(encoding="utf-8"), "캐시에는 선언만 — 토큰은 없다"
    answer.update(status=503, json={})
    assert asyncio.run(gw._refresh_access_policy()) is False and set(gw._CONN_REG) == {"matnexus", "fmea"}, "못 받으면 직전 선언"
    answer.update(status=200, json={"backends": _ROWS})        # connections 를 모르는 옛 포털
    assert asyncio.run(gw._refresh_access_policy()) is True and gw._CONN_REG == {} and gw._ACCESS_POLICY == _ROWS


def test_부팅은_두_캐시로_open_선언을_첫_카탈로그에_넣고_registered_는_포털이_답한_뒤에_붙인다(monkeypatch, tmp_path):
    real_load = gw._load_access_cache
    _boot_kit(monkeypatch, set())
    monkeypatch.setattr(gw, "_load_access_cache", real_load)
    monkeypatch.setattr(gw, "BACKENDS", {})
    monkeypatch.setattr(gw, "HEAX", {})
    monkeypatch.setattr(gw, "tool_readonly_hint", {})

    async def nothing():
        return {}
    monkeypatch.setattr(gw, "_discover_heax", nothing)
    monkeypatch.setattr(gw, "_ACCESS_CACHE_FILE", tmp_path / "ap.json")
    (tmp_path / "ap.json").write_text(json.dumps(_ROWS), encoding="utf-8")
    gw._CONN_CACHE_FILE.write_text(json.dumps({"matnexus": _MNX, "fmea": _FMEA}), encoding="utf-8")
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", False)
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")
    _portal(monkeypatch, 503)                               # 포털이 아직 안 떴다 — registered 의 목록 계정을 못 묻는다

    async def go():
        async with gw._backends_lifespan():
            first = sorted({bk for bk, _o in gw.route.values()})
            _Portal.status, _Portal.payload = 200, {"token": "fmea_list0tok1", "workspace": ""}
            gw._CONN_CACHE.clear()
            await gw._revive_once(gw._task_group_holder["tg"])
            return first, sorted({bk for bk, _o in gw.route.values()}), dict(gw._CONN_STATUS)
    first, second, status = asyncio.run(asyncio.wait_for(go(), 10))
    assert first == ["matnexus"], "open 선언은 포털 없이도 첫 카탈로그에 든다"
    assert second == ["fmea", "matnexus"] and status == {"matnexus": "ok", "fmea": "ok"}


def test_사람_호출에는_그_사람의_Bearer_하나만_나가고_감사에_토큰_지문이_남는다(monkeypatch):
    res, svc, one, row = _decl_call_kit(monkeypatch, base_headers={"authorization": "Bearer someone_put_this", "X-Keep": "1"})
    assert not res.isError and svc == [], "목록 세션으로 부르지 않는다"
    auth = [(k, v) for k, v in one["headers"].items() if k.lower() == "authorization"]
    assert auth == [("Authorization", "Bearer fmea_user0tok9")], "그 사람의 Bearer 하나만 — 목록 토큰 · 바탕 헤더는 섞이지 않는다"
    assert one["headers"]["X-Keep"] == "1" and one["tool"] == "get_fmea"
    assert _Portal.seen[0][0].endswith("/internal/connections/fmea") and _Portal.seen[0][1] == {"email": "u@corp.com"}
    assert row["mode"] == "as-conn" and row["caller"] == "u@corp.com"
    assert row["note"] == "tok:" + hashlib.sha256(b"fmea_user0tok9").hexdigest()[:10]
    text = open(gw.AUDIT_PATH, encoding="utf-8").read()
    assert "fmea_user0tok9" not in text and "fmea_list0tok1" not in text


def _decl_call_kit(monkeypatch, *, user="u@corp.com", base_headers=None, conn=None, tool="get_fmea"):
    """선언 백엔드 하나로 `_call_tool` 을 실제로 태운다(`_call_as_user` 는 진짜, 전송 계층만 막는다). 상주(목록) 세션은 받은 호출을 남긴다."""
    b = _CallB([tool])
    b.headers = dict(base_headers or {})
    b.list_headers, b.list_only = {"Authorization": "Bearer fmea_list0tok1"}, True
    one: dict = {}

    class _Sess:
        async def initialize(self): return None

        async def call_tool(self, original, arguments, read_timeout_seconds=None):
            one["tool"] = original
            return types.CallToolResult(content=[types.TextContent(type="text", text="{}")], isError=False)

    def fake_stream(url, headers=None, **_kw):
        one["headers"] = dict(headers or {})
        return _StubCM((None, None, "sid"))
    monkeypatch.setattr(gw, "streamablehttp_client", fake_stream)
    monkeypatch.setattr(gw, "ClientSession", lambda read, write: _StubCM(_Sess()))
    gw._RESP_CACHE.clear()
    monkeypatch.setattr(gw, "backends", {"fmea": b})
    monkeypatch.setattr(gw, "route", {tool: ("fmea", tool)})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {"fmea": ["plat:fmea"]})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setattr(gw, "_request_user", lambda: user)
    monkeypatch.setattr(gw, "_request_groups", lambda: ["plat:fmea"] if user else [gw.SERVICE_GROUP])
    _declare("fmea", _FMEA)
    _portal(monkeypatch, **(conn or {"status": 200, "payload": {"token": "fmea_user0tok9", "workspace": ""}}))
    res = asyncio.run(gw._call_tool(tool, {}))
    return res, b.session.calls, one, _rows()[-1]


def test_신원_없는_선언_호출은_서비스_세션으로_내리지_않고_거절한다(monkeypatch):
    res, svc, one, row = _decl_call_kit(monkeypatch, user="")
    text = res.content[0].text
    assert res.isError and "FMEA Agent" in text and "사람 신원이 없는 호출은 받지 않는다" in text
    assert svc == [] and one == {} and _Portal.seen == []
    assert row["mode"] == "refused" and row["note"] == "no-identity" and row["ok"] is False


def test_미등록_사람의_선언_호출은_등록을_안내하고_RA_사정은_말하지_않는다(monkeypatch):
    res, svc, one, row = _decl_call_kit(monkeypatch, conn={"status": 404})
    text = res.content[0].text
    assert res.isError and svc == [] and one == {}
    assert "FMEA Agent 토큰이 포털에 등록되어 있지 않습니다" in text and "fmea_…" in text and "/tokens?tab=connect" in text
    assert "공용 계정" not in text
    assert row["mode"] == "refused" and row["note"] == "no-connection"
    res, svc, one, row = _decl_call_kit(monkeypatch, conn={"status": 503})
    assert res.isError and one == {} and row["note"] == "conn-lookup-error", "포털을 못 물으면 다른 자격으로 대신 부르지 않는다"


def test_내장_RA_의_감사_줄과_거절_문구는_그대로다(monkeypatch):
    _res, _svc, _user, row = _ra_kit(monkeypatch, "get_report", status=200, payload={"token": "rat_u", "workspace": "dept"})
    assert row["mode"] == "as-conn" and "note" not in row, "tok: 지문은 선언 키에만"
    res, *_ = _ra_kit(monkeypatch, "get_report", status=404)
    assert "공용 계정으로 대신 부르면" in res.content[0].text


def test_목록_전용_세션으로는_어떤_길로도_도구를_부르지_않는다(monkeypatch):
    b = _ReconB(["get_fmea"])
    b.list_only = True
    res = asyncio.run(gw._call_shared(b, "fmea", "get_fmea", {}))
    assert res.isError and "목록 전용" in res.content[0].text
    assert b.session.calls == [] and b.reconnects == 0, "던지지 않으니 재연결 재시도도 없다"
    # 선언 아닌 키에 붙은 목록 전용 세션도 일반 호출 길에서 같은 답이다
    monkeypatch.setattr(gw, "backends", {"x": b})
    monkeypatch.setattr(gw, "route", {"get_fmea": ("x", "get_fmea")})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setattr(gw, "_request_user", lambda: "")
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    gw._RESP_CACHE.clear()
    res = asyncio.run(gw._call_tool("get_fmea", {}))
    assert res.isError and b.session.calls == [] and b.reconnects == 0


def test_백엔드를_뗀_뒤_경로만_남은_순간의_호출은_정돈된_오류다(monkeypatch):
    monkeypatch.setattr(gw, "backends", {})
    monkeypatch.setattr(gw, "route", {"get_fmea": ("fmea", "get_fmea")})
    monkeypatch.setattr(gw, "alias_route", {})
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {"fmea": ["plat:fmea"]})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setattr(gw, "_request_user", lambda: "u@corp.com")
    monkeypatch.setattr(gw, "_request_groups", lambda: ["plat:fmea"])
    gw._CONN_REG["fmea"] = gw._conn_validate("fmea", dict(_FMEA), _ROWS)[0]
    gw._CONN_ACTIVE.add("fmea")
    res = asyncio.run(gw._call_tool("get_fmea", {}))
    assert res.isError and "방금 게이트웨이에서 빠졌다" in res.content[0].text
    assert _rows()[-1]["error"] == "backend removed"


def test_선언_백엔드는_행이_없거나_선언이_지워지면_내부_서비스에도_닫힌다(monkeypatch):
    monkeypatch.setattr(gw, "POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    gw._CONN_ACTIVE.add("fmea")
    gw._CONN_REG["fmea"] = gw._conn_validate("fmea", dict(_FMEA), _ROWS)[0]
    svc, person = [gw.SERVICE_GROUP], ["plat:fmea"]
    assert gw._deny_reason("fmea", svc) == "gateway_group", "표에 없는 백엔드는 전체 공개라 — 행 없는 순간을 운영 순서에 맡기지 않는다"
    gw._ACCESS_POLICY["fmea"] = ["plat:fmea"]
    assert gw._deny_reason("fmea", svc) is None and gw._deny_reason("fmea", person) is None
    assert gw._deny_reason("fmea", ["feat:chat"]) == "portal_access"
    gw._CONN_REG.clear()                                    # 선언을 지웠다 — 다음 패스 전
    assert gw._deny_reason("fmea", svc) == "gateway_group" and gw._deny_reason("fmea", person) == "gateway_group"
    assert "잠시 뒤" not in gw._deny_text("fmea", person), "지운 플랫폼에 '잠시 뒤 다시 부르라' 고 말하지 않는다"
    assert gw._deny_reason("free", []) is None, "선언 아닌 백엔드는 종전대로"


def test_이름이_겹치면_선언_쪽_도구만_접두가_붙고_기존_맨_이름은_그대로_불린다(monkeypatch):
    """둘 다 바꾸던 규칙이면 MatNexus 가 붙는 순간 MaterialTwin · SignalForge 의 맨 이름이 사라져 그 이름을 부르던 절차 · 핀 ·
    클라이언트가 unknown tool 이 된다(요청서 0절 실측)."""
    monkeypatch.setattr(gw, "tool_readonly_hint", {})
    gw._CONN_ACTIVE.add("matnexus")
    _aggregate_with(monkeypatch, {"heax-materialtwin": ["get_material", "how_to_measure"],
                                  "signalforge": ["get_ontology"],
                                  "matnexus": ["get_material", "get_ontology", "list_samples"]})
    assert gw.route["get_material"] == ("heax-materialtwin", "get_material")
    assert gw.route["get_ontology"] == ("signalforge", "get_ontology")
    assert gw.route["how_to_measure"] == ("heax-materialtwin", "how_to_measure")
    assert gw.route["matnexus_get_material"] == ("matnexus", "get_material")
    assert gw.route["matnexus_get_ontology"] == ("matnexus", "get_ontology")
    assert gw.route["list_samples"] == ("matnexus", "list_samples"), "겹치지 않으면 맨 이름"
    assert {t.name for t in gw.exposed_tools} == set(gw.route)


def test_선언의_read_tools_가_읽기_힌트와_노출_표지를_세우고_앱이_False_를_적으면_앱이_이긴다(monkeypatch):
    _declare("fmea", {**_FMEA, "read_tools": ["get_a", "put_b"]})
    monkeypatch.setattr(gw, "tool_readonly_hint", {})
    tools = [_tool("get_a"),
             types.Tool(name="put_b", description="", inputSchema={"type": "object"},
                        annotations=types.ToolAnnotations(readOnlyHint=False, title="쓰기")),
             _tool("list_c")]
    monkeypatch.setattr(gw, "backends", {"fmea": _B(tools), "heax-x": _B([_tool("list_y")])})
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "route", {})
    monkeypatch.setattr(gw, "alias_route", {})
    asyncio.run(gw._aggregate())
    h = gw.tool_readonly_hint
    assert (h[("fmea", "get_a")], h[("fmea", "put_b")], h[("fmea", "list_c")]) == (True, False, False)
    ann = {t.name: t.annotations for t in gw.exposed_tools}
    assert ann["get_a"].readOnlyHint is True and ann["put_b"].readOnlyHint is False and ann["put_b"].title == "쓰기"
    assert ann.get("list_c") is None
    assert gw._readonly_denial("get_a", {}) == "" and gw._readonly_denial("list_c", {}).startswith("read_only")
    monkeypatch.setattr(gw, "READ_TOOLS", frozenset({"fmea:list_c"}))
    assert gw._readonly_denial("list_c", {}) == "", "read_tools.json 항목도 그대로 통과한다(더하기)"
    monkeypatch.setattr(gw, "_request_user", lambda: "u@corp.com")
    monkeypatch.setattr(gw, "_request_groups", lambda: [])
    assert gw._cache_key("fmea", "list_c", {}) is None, "선언 백엔드는 이름 접두로 캐시하지 않는다 — 같은 이름의 쓰기가 무음으로 버려진다"
    assert gw._cache_key("fmea", "put_b", {}) is None
    assert gw._cache_key("fmea", "get_a", {}) is not None
    assert gw._cache_key("heax-x", "list_y", {}) is not None, "선언 아닌 백엔드는 종전대로"


def test_refresh_는_정책과_선언을_먼저_받고_재활_패스를_돈다(monkeypatch):
    order: list = []

    async def pol():
        order.append("policy")
        return True

    async def rev(tg):
        order.append("revive")
        return False
    monkeypatch.setattr(gw, "_refresh_access_policy", pol)
    monkeypatch.setattr(gw, "_revive_once", rev)
    monkeypatch.setattr(gw, "GW_TOKEN", "gw-secret")
    monkeypatch.setattr(gw, "_task_group_holder", {"tg": object()})
    sent: list = []

    async def send(m): sent.append(m)
    asyncio.run(gw._bearer_gate(None, None)({"type": "http", "path": "/refresh", "method": "POST", "query_string": b"",
                                             "headers": [(b"authorization", b"Bearer gw-secret")]}, None, send))
    assert sent[0]["status"] == 200 and order == ["policy", "revive"]


def test_health_의_conn_platforms_는_키와_상태만_싣는다(monkeypatch):
    down = _B([])
    down.session = None
    monkeypatch.setattr(gw, "backends", {"matnexus": _B([]), "fmea": down, "signalforge": _B([])})
    _declare("matnexus", _MNX)
    _declare("fmea", _FMEA)
    gw._CONN_STATUS.update({"matnexus": "ok", "fmea": "ok", "newapp": "collision", "old": "no-list-token"})
    sent: list = []

    async def send(m): sent.append(m)
    asyncio.run(gw._bearer_gate(None, None)({"type": "http", "path": "/health", "method": "GET", "query_string": b"",
                                             "headers": []}, None, send))
    raw = sent[1]["body"].decode()
    assert json.loads(raw)["conn_platforms"] == {"fmea": "down", "matnexus": "ok", "newapp": "collision", "old": "no-list-token"}
    assert "mnx.example" not in raw and "list@corp.com" not in raw, "무인증 응답에 주소 · 이메일을 싣지 않는다"


def test_health_의_no_proxy_는_보정_결과를_수로만_싣는다(monkeypatch):
    """HWAXPortal docs/request-1027 HG-18 · HP-22 — 포털 출구 점검이 게이트웨이 목적지를 이 결과로 판정한다(게이트웨이는 제가 부르는
    호스트를 스스로 더하므로 포털 셸의 NO_PROXY 로 재면 거짓 경보다). 무인증 응답이라 주소는 싣지 않는다."""
    _proxy_env(monkeypatch)
    monkeypatch.setattr(gw, "_NO_PROXY_ADDED", set())
    monkeypatch.setattr(gw, "_NO_PROXY_UNWRITABLE", set())
    monkeypatch.setattr(gw, "backends", {})
    gw._bypass_proxy_for(["http://ra.corp.test:3002/mcp", "http://[fe80::1%25eth0]:9/x"])
    gw._bypass_proxy_for(["http://ra.corp.test:3002/mcp"])          # 다시 불러도 두 번 세지 않는다
    sent: list = []

    async def send(m): sent.append(m)
    asyncio.run(gw._bearer_gate(None, None)({"type": "http", "path": "/health", "method": "GET", "query_string": b"",
                                             "headers": []}, None, send))
    raw = sent[1]["body"].decode()
    assert json.loads(raw)["no_proxy"] == {"auto": True, "added": 4, "unwritable": 1, "all": False, "proxy": True}
    assert "ra.corp.test" not in raw and "fe80" not in raw, "무인증 응답에 주소를 싣지 않는다"
    monkeypatch.setenv("no_proxy", "*")
    assert gw._no_proxy_health()["all"] is True


def test_로그는_선언_접두의_토큰을_가리고_도구_이름은_그대로_둔다():
    gw._conn_registry_set({"fmea": dict(_FMEA), "matnexus": dict(_MNX)}, _ROWS, persist=False)
    fmt = gw._MaskSecretsFormatter("%(message)s")
    rec = logging.LogRecord("x", logging.INFO, __file__, 1,
                            "tok fmea_9f8e7d6c5b4a / Bearer mnx_pat_ab12cd34ef — fmea_list_projects · fmea_ab1", None, None)
    assert fmt.format(rec) == "tok fmea_*** / Bearer mnx_pat_*** — fmea_list_projects · fmea_ab1"
    gw._conn_registry_set({}, _ROWS, persist=False)
    assert gw._CONN_TOKEN_MASK is None, "선언이 없으면 가릴 접두도 없다"


# ── MCP 리소스 중계 — ui:// 패널(HWAXPortal docs/request-1027 HG-07) ─────────────────────────────────────────
# 집계가 도구 `_meta` 를 버리고 resources 처리기가 없어 게이트웨이(/mcp-gw/mcp)에 붙은 Claude Desktop 에서 SimFlow · ARP 패널이 뜨지 않았다.
_PANEL_HTML = "<!doctype html><title>workflow</title>"


class _PanelSess:
    """패널 도구 · ui:// 리소스를 내는 백엔드 세션 — 받은 읽기를 남긴다. `fail_list` 면 리소스 목록이 터진다."""
    def __init__(self, tools, resources, templates=(), *, fail_list=False):
        self._t, self._r, self._tm, self.fail_list, self.reads = tools, resources, list(templates), fail_list, []

    async def list_tools(self):
        return _Res(self._t)

    async def list_resources(self):
        if self.fail_list:
            raise RuntimeError("list_resources down")
        return types.ListResourcesResult(resources=self._r)

    async def list_resource_templates(self):
        return types.ListResourceTemplatesResult(resourceTemplates=self._tm)

    async def read_resource(self, uri):
        self.reads.append(str(uri))
        return types.ReadResourceResult(contents=[types.TextResourceContents(
            uri=uri, text=_PANEL_HTML, mimeType="text/html;profile=mcp-app", _meta={"ui": {"prefersBorder": True}})],
            _meta={"served": "backend"})


def _panel_tool(name, uri, *, old_key=False, extra_meta=None):
    meta = {"ui/resourceUri": uri} if old_key else {"ui": {"resourceUri": uri}}
    return types.Tool(name=name, description="패널을 연다", inputSchema={"type": "object"}, _meta={**meta, **(extra_meta or {})})


def _panel_kit(monkeypatch, sessions: dict, *, policy=None, groups=(), user=""):
    import asyncio
    bs = {}
    for key, sess in sessions.items():
        b = _CallB([])
        b.session = sess
        bs[key] = b
    monkeypatch.setattr(gw, "backends", bs)
    for name in ("route", "alias_route", "_FP", "_LAST_TOOLS", "_LIVENESS_MISS", "_REAGG", "tool_readonly_hint", "_LAST_UI_RES",
                 "_UI_RESOURCES"):
        monkeypatch.setattr(gw, name, {})
    monkeypatch.setattr(gw, "_UI_TEMPLATES", [])
    monkeypatch.setattr(gw, "exposed_tools", [])
    monkeypatch.setattr(gw, "POLICY", policy or {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY", {})
    monkeypatch.setattr(gw, "_ACCESS_POLICY_READY", True)
    monkeypatch.setattr(gw, "_request_groups", lambda: list(groups))
    monkeypatch.setattr(gw, "_request_muted", lambda: set())
    monkeypatch.setattr(gw, "_request_user", lambda: user)
    asyncio.run(gw._aggregate())
    return bs


def _read(uri):
    import asyncio
    req = types.ReadResourceRequest(method="resources/read", params=types.ReadResourceRequestParams(uri=uri))
    return asyncio.run(gw._read_ui_resource(req))


def test_HG07_집계가_패널_표지를_옮기고_이름을_바꿔도_resourceUri_는_그대로다(monkeypatch):
    sf = _PanelSess([_panel_tool("open_workflow_panel", "ui://simflow/workflow", extra_meta={"internal": "x"}),
                     _panel_tool("status", "ui://simflow/status", old_key=True)],
                    [types.Resource(uri="ui://simflow/workflow", name="workflow"), types.Resource(uri="ui://simflow/status", name="s"),
                     types.Resource(uri="file:///secret.txt", name="secret")])
    other = _PanelSess([_tool("status")], [])
    _panel_kit(monkeypatch, {"simflow": sf, "arp": other})
    by = {t.name: t for t in gw.exposed_tools}
    assert by["open_workflow_panel"].meta == {"ui": {"resourceUri": "ui://simflow/workflow"}}, "ui 만 옮긴다 — 다른 칸(internal)은 아니다"
    assert by["simflow_status"].meta == {"ui/resourceUri": "ui://simflow/status"}, "충돌 접두로 이름이 바뀌어도 주소는 그대로다"
    assert by["arp_status"].meta is None
    dumped = by["open_workflow_panel"].model_dump(by_alias=True, exclude_none=True)
    assert dumped["_meta"]["ui"]["resourceUri"] == "ui://simflow/workflow", "클라이언트로 나가는 꼴(_meta)에 실린다"
    assert sorted(gw._UI_RESOURCES) == ["ui://simflow/status", "ui://simflow/workflow"], "ui:// 만 중계한다"


def test_HG07_리소스_목록은_도구와_같은_규칙으로_거르고_권한_없는_주소는_없는_주소와_같은_오류다(monkeypatch):
    import asyncio
    sf = _PanelSess([_panel_tool("open_workflow_panel", "ui://simflow/workflow")], [types.Resource(uri="ui://simflow/workflow", name="w")],
                    [types.ResourceTemplate(uriTemplate="ui://simflow/run/{id}", name="run")])
    arp = _PanelSess([_panel_tool("open_arp_panel", "ui://arp/board")], [types.Resource(uri="ui://arp/board", name="b")])
    _panel_kit(monkeypatch, {"simflow": sf, "arp": arp}, policy={"arp": ["arp-users"]})
    assert [str(r.uri) for r in asyncio.run(gw._list_resources())] == ["ui://simflow/workflow"]
    assert [t.uriTemplate for t in asyncio.run(gw._list_resource_templates())] == ["ui://simflow/run/{id}"]
    errs = []
    for uri in ("ui://arp/board", "ui://nope/x"):
        with pytest.raises(gw.McpError) as ei:
            _read(uri)
        errs.append((ei.value.error.code, ei.value.error.message.replace(uri, "<uri>")))
    assert errs[0] == errs[1] == (-32002, "Resource not found: <uri>"), "있다는 사실을 흘리지 않는다"
    assert arp.reads == []


def test_HG07_읽기는_백엔드_답을_그대로_돌려주고_감사에_남긴다(monkeypatch):
    sf = _PanelSess([_panel_tool("open_workflow_panel", "ui://simflow/workflow")], [types.Resource(uri="ui://simflow/workflow", name="w")])
    _panel_kit(monkeypatch, {"simflow": sf})
    out = _read("ui://simflow/workflow")
    res = out.root
    assert res.contents[0].text == _PANEL_HTML and res.contents[0].mimeType == "text/html;profile=mcp-app"
    assert res.contents[0].meta == {"ui": {"prefersBorder": True}} and res.meta == {"served": "backend"}, "내용 · 결과의 _meta 를 고치지 않는다"
    row = [r for r in _rows() if r["tool"].startswith("resources/read")][-1]
    assert (row["ok"], row["backend"], row["mode"]) == (True, "simflow", "service")


def test_HG07_사람별_위임_백엔드는_그_사람_토큰의_단발_세션으로_읽는다(monkeypatch):
    sf = _PanelSess([_panel_tool("open_workflow_panel", "ui://simflow/workflow")], [types.Resource(uri="ui://simflow/workflow", name="w")])
    bs = _panel_kit(monkeypatch, {"simflow": sf}, user="u@corp.com")
    bs["simflow"].headers = {"Authorization": "Bearer svc"}
    seen = {}

    class _One:
        async def initialize(self): return None

        async def read_resource(self, uri):
            seen["uri"] = str(uri)
            return types.ReadResourceResult(contents=[types.TextResourceContents(uri=uri, text="per-user", mimeType="text/html")])

    def fake_stream(url, headers=None, **_kw):
        seen["headers"] = dict(headers or {})
        return _StubCM((None, None, "sid"))
    monkeypatch.setattr(gw, "streamablehttp_client", fake_stream)
    monkeypatch.setattr(gw, "ClientSession", lambda read, write: _StubCM(_One()))
    monkeypatch.setattr(gw, "PER_USER_SSO", {"simflow": {"sso_url": "http://x", "secret": "s"}})

    async def fake_pat(app_id, email, *, stale=None, notes=None):
        return "sf_user_tok"
    monkeypatch.setattr(gw, "_user_pat", fake_pat)
    out = _read("ui://simflow/workflow")
    assert out.root.contents[0].text == "per-user" and seen["uri"] == "ui://simflow/workflow"
    assert seen["headers"]["Authorization"] == "Bearer sf_user_tok" and sf.reads == [], "상주(서비스) 세션으로 읽지 않는다"
    assert [r for r in _rows() if r["tool"].startswith("resources/read")][-1]["mode"] == "as-user-pat"


def test_HG07_목록을_못_받으면_직전_목록을_두고_겹치는_주소는_먼저_붙은_쪽으로_크면_거절한다(monkeypatch):
    import asyncio
    sf = _PanelSess([_panel_tool("open_workflow_panel", "ui://simflow/workflow")], [types.Resource(uri="ui://simflow/workflow", name="w")])
    _panel_kit(monkeypatch, {"simflow": sf})
    sf.fail_list = True
    asyncio.run(gw._aggregate())
    assert list(gw._UI_RESOURCES) == ["ui://simflow/workflow"], "한 번 못 받았다고 표를 비우지 않는다"
    dup = _PanelSess([_panel_tool("open_dup", "ui://simflow/workflow")], [types.Resource(uri="ui://simflow/workflow", name="dup")])
    _panel_kit(monkeypatch, {"zz-copy": dup, "simflow": _PanelSess(sf._t, sf._r)})
    assert gw._UI_RESOURCES["ui://simflow/workflow"][0] == "simflow", "키 순으로 먼저인 쪽"
    monkeypatch.setattr(gw, "RESOURCE_MAX_BYTES", 10)
    with pytest.raises(gw.McpError) as ei:
        _read("ui://simflow/workflow")
    assert "GATEWAY_RESOURCE_MAX_BYTES" in ei.value.error.message


def test_HG07_지침이_패널_도구는_직접_부르라고_하고_서버가_resources_를_광고한다():
    from mcp.server.lowlevel.server import NotificationOptions
    assert "패널 도구" in gw._INSTRUCTIONS and "직접 불러라" in gw._INSTRUCTIONS
    assert gw._low.request_handlers[types.ReadResourceRequest] is gw._read_ui_resource, "FastMCP 기본 처리기가 이기면 중계가 안 된다"
    assert gw._low.get_capabilities(NotificationOptions(), {}).resources is not None


def test_HG07_진짜_클라이언트가_resources_list_read_와_도구의_meta_를_받는다(monkeypatch):
    """처리기를 바로 부르는 시험만으로는 등록 · 직렬화(`_meta` 별칭)가 빠져도 초록이다 — 메모리 전송으로 진짜 ClientSession 을 붙인다."""
    import asyncio
    from mcp.shared.memory import create_connected_server_and_client_session
    sf = _PanelSess([_panel_tool("open_workflow_panel", "ui://simflow/workflow")], [types.Resource(uri="ui://simflow/workflow", name="w")])
    _panel_kit(monkeypatch, {"simflow": sf})
    monkeypatch.setattr(gw, "_local_tools", lambda: [])

    async def go():
        async with create_connected_server_and_client_session(gw._low) as client:
            tools = (await client.list_tools()).tools
            res = (await client.list_resources()).resources
            got = await client.read_resource("ui://simflow/workflow")
            try:
                await client.read_resource("ui://nope/x")
                missing = None
            except gw.McpError as exc:
                missing = exc.error.code
            return tools, res, got, missing
    tools, res, got, missing = asyncio.run(go())
    assert tools[0].meta == {"ui": {"resourceUri": "ui://simflow/workflow"}}
    assert [str(r.uri) for r in res] == ["ui://simflow/workflow"]
    assert got.contents[0].text == _PANEL_HTML and got.meta == {"served": "backend"}
    assert missing == -32002


# ── 나가는 응답의 개인정보 가림(HWAXPortal docs/request-1027 HG-20 · 사용자 결정 D-2 — 기본으로 가린다) ─────────────────────────
_VOC_ROW = ('{\n  "items": [\n    {"id": 7, "author_name": "Kim Minsu", "handle": "minsu.bsky.social", "text": "배터리 광탈 — IMEI 352099001761481 기기", '
            '"serial": 3},\n    {"id": 8, "author": "", "detected_by": "홍길동", "serial_number": "R58N12ABCDE", "imei": 352099001761481,\n'
            '     "score": 0.91}\n  ],\n  "count": 2\n}')


def test_HG20_백엔드_결과의_작성자_계정_IMEI_일련번호를_가리고_서식은_그대로다(monkeypatch):
    _result_kit(monkeypatch, _VOC_ROW)
    res = asyncio.run(gw._call_tool("get_big", {}))
    out = res.content[0].text
    for leak in ("Kim Minsu", "minsu.bsky.social", "352099001761481", "홍길동", "R58N12ABCDE"):
        assert leak not in out, leak
    assert '"author_name": "[가림:이름]"' in out and '"handle": "[가림:계정]"' in out and '"detected_by": "[가림:이름]"' in out
    assert '"serial_number": "[가림:일련번호]"' in out and '"imei": "[가림:IMEI]"' in out and "IMEI [가림:IMEI] 기기" in out
    assert '"serial": 3' in out and '"author": ""' in out, "차례 번호 · 빈 값은 그대로 둔다"
    assert out.replace("[가림:이름]", "X").count("\n") == _VOC_ROW.count("\n") and json.loads(out)["count"] == 2, "서식 · 나머지 값은 그대로"
    again = asyncio.run(gw._call_tool("get_big", {}))
    assert again.content[0].text == out, "캐시에서 와도 가린 판이다"


def test_HG20_가릴_것이_없으면_결과를_바이트까지_그대로_두고_끄면_원문이다(monkeypatch):
    plain = '{"rows": [{"part": "BRKT-01", "stress": 352.1, "count": 123456789012345}]}'     # Luhn 을 통과 못 하는 15자리
    _result_kit(monkeypatch, plain)
    assert asyncio.run(gw._call_tool("get_big", {})).content[0].text == plain
    monkeypatch.setattr(gw, "PII_MASK_ON", False)
    _result_kit(monkeypatch, _VOC_ROW)
    assert asyncio.run(gw._call_tool("get_big", {})).content[0].text == _VOC_ROW, "GATEWAY_PII_MASK=0 이면 원문"


def test_HG20_구조화_본문과_rest_call_도_가리고_health_는_수만_싣는다(monkeypatch):
    res = types.CallToolResult(content=[types.TextContent(type="text", text="ok")],
                               structuredContent={"rows": [{"nickname": "철수", "note": "IMEI 35-209900-176148-1 교체"}]})
    out = gw._pii_mask(res)
    assert out.structuredContent == {"rows": [{"nickname": "[가림:이름]", "note": "IMEI [가림:IMEI] 교체"}]}
    assert res.structuredContent["rows"][0]["nickname"] == "철수", "원본 객체는 건드리지 않는다(캐시 · 근거 원장이 쥔다)"
    src = open(gw.__file__, encoding="utf-8").read()
    assert 'return _evid_keep("rest_call", _pii_mask(_rest_text(payload)))' in src
    assert src.count("_cache_put(ckey, _evid_keep(name, _pii_mask(res)))") == 5, "백엔드 결과를 돌려주는 자리 다섯이 모두 가린다"
    assert gw._luhn_ok("352099001761481") and not gw._luhn_ok("352099001761482")
    sent = []

    async def recv():
        return {"type": "http.request", "body": b""}

    async def send(m):
        sent.append(m)
    asyncio.run(gw._bearer_gate(lambda *a: None)({"type": "http", "path": "/health", "method": "GET", "query_string": b"",
                                                  "headers": []}, recv, send))
    health = json.loads(b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body"))
    assert health["pii_mask"]["on"] is True and isinstance(health["pii_mask"]["masked"], int) and health["pii_mask"]["masked"] >= 2



# ── 재기동 때 비우기(HWAXPortal docs/request-1027 HG-11) ─────────────────────────────────────────────────────────
# 10-25 재기동에 열린 스트림 98건이 응답 없이 끊겼다. 리스너 먼저 → 새 세션 503 → 진행 중인 CallTool 이 0 이 될 때까지(상한) → 나머지.
class _FakeListener:
    def __init__(self, ev): self.ev = ev

    def close(self): self.ev.append("listener-closed")


def _graceful(monkeypatch, inflight_for: float, drain_s: float = 5.0):
    """진짜 `_GracefulServer.shutdown` 을 돌린다 — 위 단계(uvicorn 의 종료)만 기록으로 바꾼다. 도구 호출 하나가 `inflight_for` 초 걸린다."""
    import uvicorn as _uv
    ev: list = []

    async def fake_super(self, sockets=None):
        ev.append(("uvicorn-shutdown", gw._INFLIGHT_CALLS["n"]))
    monkeypatch.setattr(_uv.Server, "shutdown", fake_super)
    monkeypatch.setattr(gw, "DRAIN_TIMEOUT_S", drain_s)
    monkeypatch.setattr(gw, "_DRAIN", {"on": False})
    monkeypatch.setattr(gw, "_INFLIGHT_CALLS", {"n": 0})

    async def slow_body(name, arguments):
        ev.append(("call-start", gw._DRAIN["on"]))
        await asyncio.sleep(inflight_for)
        ev.append("call-done")
        return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])
    monkeypatch.setattr(gw, "_call_tool_body", slow_body)
    import time
    srv = gw._GracefulServer.__new__(gw._GracefulServer)
    srv.servers, srv.force_exit = [_FakeListener(ev)], False

    async def go():
        call = asyncio.ensure_future(gw._call_tool("x", {}))
        await asyncio.sleep(0.05)
        t0 = time.monotonic()
        await srv.shutdown()
        took = time.monotonic() - t0
        await call
        return took
    took = asyncio.run(go())
    return ev, took


def test_HG11_재기동은_리스너를_먼저_닫고_진행_중인_도구_호출이_끝난_뒤에_내린다(monkeypatch):
    ev, took = _graceful(monkeypatch, inflight_for=0.6)
    assert ev == [("call-start", False), "listener-closed", "call-done", ("uvicorn-shutdown", 0)], ev
    assert 0.4 < took < 3, took
    assert gw._DRAIN["on"] is True and gw._INFLIGHT_CALLS["n"] == 0


def test_HG11_기다림에는_상한이_있다(monkeypatch):
    ev, took = _graceful(monkeypatch, inflight_for=3.0, drain_s=0.5)
    assert ev[:3] == [("call-start", False), "listener-closed", ("uvicorn-shutdown", 1)], ev
    assert took < 2, "상한(GATEWAY_DRAIN_TIMEOUT) 뒤에는 남은 호출을 두고 내린다"


def test_HG11_비우는_동안_새_세션은_503_이고_열린_세션의_요청은_지나간다(monkeypatch):
    monkeypatch.setattr(gw, "_DRAIN", {"on": True})
    passed = []

    async def app(scope, receive, send):
        passed.append(dict(scope["headers"]).get(b"mcp-session-id"))
        await send({"type": "http.response.start", "status": 202, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def recv():
        return {"type": "http.request", "body": b""}

    def run(headers):
        sent = []

        async def send(m):
            sent.append(m)
        monkeypatch.setattr(gw, "GW_TOKEN", "gw-secret")
        asyncio.run(gw._bearer_gate(app)({"type": "http", "path": "/mcp", "method": "POST", "query_string": b"",
                                          "headers": [(b"authorization", b"Bearer gw-secret"), *headers]}, recv, send))
        return sent[0]["status"], dict(sent[0]["headers"])
    status, hdrs = run([])
    assert status == 503 and hdrs[b"retry-after"] == b"1" and passed == []
    status, _h = run([(b"mcp-session-id", b"s-1")])
    assert status == 202 and passed == [b"s-1"], "열린 세션의 호출은 끝까지 간다"


def test_HG11_기동이_비우기_서버와_대기_스트림_한도로_뜬다():
    src = open(gw.__file__, encoding="utf-8").read()
    main = src[src.index("\ndef main():"):]
    assert "_GracefulServer(uvicorn.Config(app, host=HOST, port=PORT" in main and "timeout_graceful_shutdown=SHUTDOWN_TAIL_S" in main
    assert "uvicorn.run(" not in main, "uvicorn.run 은 기본(한없이 기다리다 두 번째 신호에 전부 끊는다)으로 돌아간다"


def test_HG11_start_sh_stop_은_리스너를_닫고_비우는_옛_프로세스를_kill_9_하지_않는다(tmp_path):
    """update-sites 의 재기동은 down(start.sh stop) → 리스너가 답하지 않을 때까지 → up 이다(HWAXPortal docs/request-1027 HP-25). stop 이
    포트가 풀리면 바로 돌아오고 옛 프로세스를 끝까지 비우게 두어야 HG-11 이 뜻이 있다 — '프로세스가 끝날 때까지 기다렸다 kill -9' 로
    바뀌면 비우기가 통째로 꺼진다. 진짜 프로세스 · 진짜 신호로 본다(빈 높은 포트 — 떠 있는 9110 은 건드리지 않는다)."""
    import shutil
    import socket
    import subprocess
    import sys
    import time
    from pathlib import Path
    if not shutil.which("ss"):
        pytest.skip("ss 없음")
    d = tmp_path / "gw"
    d.mkdir()
    shutil.copy(Path(gw.__file__).with_name("start.sh"), d / "start.sh")
    (d / "gateway.py").write_text(
        "import signal, socket, sys, time\n"
        "s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "s.bind(('127.0.0.1', int(sys.argv[1]))); s.listen()\n"
        "st = {'t': None}\n"
        "def term(*_):\n    st['t'] = time.monotonic(); s.close()\n"
        "signal.signal(signal.SIGTERM, term)\n"
        "while st['t'] is None or time.monotonic() - st['t'] < 1.5:\n    time.sleep(0.05)\n"
        "open(sys.argv[2], 'w').write('drained')\n", encoding="utf-8")
    with socket.socket() as so:
        so.bind(("127.0.0.1", 0))
        port = so.getsockname()[1]
    done = tmp_path / "done.txt"
    fake = subprocess.Popen([sys.executable, str(d / "gateway.py"), str(port), str(done)])
    try:
        for _ in range(100):
            if subprocess.run(["ss", "-tlnH", f"sport = :{port}"], capture_output=True, text=True).stdout.strip():
                break
            time.sleep(0.05)
        t0 = time.monotonic()
        r = subprocess.run(["bash", str(d / "start.sh"), "stop"], capture_output=True, text=True, timeout=30,
                           env={"PATH": os.environ["PATH"], "GATEWAY_PORT": str(port), "GATEWAY_CONFIG": str(tmp_path / "none.json")})
        took = time.monotonic() - t0
        assert r.returncode == 0 and took < 1.2, (r.returncode, took, r.stdout, r.stderr)
        assert fake.poll() is None, "stop 이 돌아온 때 옛 프로세스는 아직 비우고 있어야 한다"
        assert fake.wait(timeout=10) == 0 and done.read_text() == "drained", "kill -9 없이 스스로 끝났다"
    finally:
        if fake.poll() is None:
            fake.kill()


def test_health_에_검색_손잡이_지문이_실린다():
    """/health 의 search_tuning — 무인증 칸이다(지문 · 꺼 둔 묶음 · 덧씌우기 여부만, 경로 · 낱말은 없다)."""
    import inspect
    src = inspect.getsource(gw)
    i = src.index('if scope.get("path") == "/health":')
    assert '"search_tuning": _tuning_health(),' in src[i:src.index('if scope.get("path") == "/tools-map":', i)]
    h = gw._tuning_health()
    assert set(h) <= {"fingerprint", "base", "switches_off", "synonyms", "overlay", "error"} and len(h["fingerprint"]) == 12


def test_코어_어휘표_박스_덧씌우기는_merge_patch_로_얹는다(monkeypatch, tmp_path):
    """core_vocab.local.json — 코어 낱말 · 정본 · 앱 역할을 cae00 에서 커밋 없이 고친다. 깨지면 버리고 기본 표로 돈다(E-7 ②)."""
    monkeypatch.setattr(gw, "CORE_VOCAB_PATH", _REAL_CORE_VOCAB)
    loc = tmp_path / "core_vocab.local.json"
    monkeypatch.setattr(gw, "CORE_VOCAB_LOCAL_PATH", loc)
    base = gw._core_vocab()
    assert base["fingerprint"] == base["base_fingerprint"] and gw._core_vocab_health()["overlay"] == {"present": False}
    loc.write_text(json.dumps({"apps": {"stepforge-prod": None}, "search": [{"words": ["메인 PBA"], "tools": ["object_resolve"]}]},
                              ensure_ascii=False), encoding="utf-8")
    d = gw._core_vocab()
    assert "stepforge-prod" not in d["staging"] and "dynaforge-prod" in d["staging"], "객체는 합치고 null 은 지운다"
    assert [s for s in d["syn"] if s[0] == "메인pba"] and len(d["syn"]) < len(base["syn"]), "목록은 통째로 바뀐다"
    h = gw._core_vocab_health()
    assert h["fingerprint"] != h["base"] and h["overlay"]["present"] and set(h["overlay"]["changed"]) == {"apps.stepforge-prod", "search"}
    loc.write_text("{깨진", encoding="utf-8")
    st = loc.stat()
    gw.os.utime(loc, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
    d = gw._core_vocab()
    assert d["fingerprint"] == base["fingerprint"] and "덧씌우기를 버렸다" in gw._core_vocab_health()["overlay"]["error"]


# ── E-9 ② ③ — 검색 고리 창구(/search-log · /search-review · /search-eval) ─────────────────────────────────────────────
def _gate_call(monkeypatch, path, method="GET", qs=b"", body=None, token="gw-secret"):
    monkeypatch.setattr(gw, "GW_TOKEN", "gw-secret")
    sent = []

    async def send(m):
        sent.append(m)

    async def receive():
        return {"type": "http.request", "body": json.dumps(body, ensure_ascii=False).encode() if body is not None else b"",
                "more_body": False}
    mw = gw._bearer_gate(None, None)
    asyncio.run(mw({"type": "http", "path": path, "method": method, "query_string": qs,
                    "headers": [(b"authorization", f"Bearer {token}".encode())]}, receive, send))
    return sent[0]["status"], json.loads(sent[1]["body"])


def test_E9_검색_고리_창구는_공유_비밀을_요구한다(monkeypatch):
    for path, method in (("/search-log", "GET"), ("/search-review", "POST"), ("/search-eval", "POST")):
        st, body = _gate_call(monkeypatch, path, method, body={}, token="wrong")
        assert st == 401, path


def test_E9_검색_기록_보기는_새것_먼저_뒤이은_호출과_박스_표시를_싣는다(monkeypatch):
    _qlog_kit(monkeypatch)
    monkeypatch.setattr(gw, "backends", {"signalforge": object()})
    asyncio.run(gw._search_tools({"query": "report digest"}))
    gw._audit("report_list", "signalforge", True, None, 5, caller="someone@example.com")
    asyncio.run(gw._search_tools({"query": "요약"}))
    st, body = _gate_call(monkeypatch, "/search-review", "POST", body={"q": "요약", "verdict": "ok", "gold": ["signalforge:digest"]})
    assert st == 200 and body["ok"] and body["pairs"] == 1
    st, body = _gate_call(monkeypatch, "/search-log", qs=b"days=3&limit=10")
    assert st == 200 and [r["q"] for r in body["searches"]] == ["요약", "report digest"], "새것 먼저"
    first, second = body["searches"]
    assert first["mark"]["gold"] == ["signalforge:digest"] and first["boost_only"] == ["signalforge:digest"]
    assert second["outcomes"] == [{"t": "signalforge:list", "r": 2, "ok": True}] and "mark" not in second
    st, body = _gate_call(monkeypatch, "/search-log", qs=b"q=DIGEST")
    assert [r["q"] for r in body["searches"]] == ["report digest"], "q 는 대소문자 없이 부분 일치로 거른다"


def test_E9_사람_표시는_박스_정답쌍에_두고_같은_질의는_바꿔_쓰고_remove_는_지운다(monkeypatch):
    for gold in (["signalforge:digest"], ["signalforge:list", "signalforge:digest"]):
        st, body = _gate_call(monkeypatch, "/search-review", "POST", body={"q": " 요약 ", "verdict": "gold", "gold": gold, "memo": "m"})
        assert st == 200
    [p] = gw._read_jsonl(gw.SEARCH_PAIRS_LOCAL_PATH)
    assert p["query"] == "요약" and p["gold"] == ["signalforge:list", "signalforge:digest"] and p["source"] == "box", p
    assert p["id"] == gw._box_pair_id("요약") and p["reviewed"] is True and p["memo"] == "m"
    st, body = _gate_call(monkeypatch, "/search-review", "POST", body={"q": "요약", "verdict": "remove"})
    assert st == 200 and body["removed"] and gw._read_jsonl(gw.SEARCH_PAIRS_LOCAL_PATH) == []
    for bad in ({"q": "", "verdict": "ok", "gold": ["a:b"]}, {"q": "x", "verdict": "maybe", "gold": ["a:b"]},
                {"q": "x", "verdict": "ok", "gold": []}, {"q": "x", "verdict": "ok", "gold": ["앱키만"]}):
        st, body = _gate_call(monkeypatch, "/search-review", "POST", body=bad)
        assert st == 400, bad


def test_E9_평가는_떠_있는_카탈로그로_판마다_재고_기록을_남기지_않는다(monkeypatch, tmp_path):
    _search_catalog(monkeypatch)
    _no_embed(monkeypatch)
    pairs = tmp_path / "pairs.jsonl"
    pairs.write_text("\n".join(json.dumps(p, ensure_ascii=False) for p in (
        {"id": "doc-x", "query": "물성 조회", "gold": ["heax-materialtwin_web:get_material_properties"], "source": "doc"},
        {"id": "doc-y", "query": "없는 도구", "gold": ["nowhere:none"], "source": "doc"})) + "\n", encoding="utf-8")
    monkeypatch.setattr(gw, "SEARCH_PAIRS_PATH", pairs)
    _gate_call(monkeypatch, "/search-review", "POST", body={"q": "응력 곡선 그림", "verdict": "gold",
                                                            "gold": ["heax-materialtwin_web:plot_curve"]})
    st, body = _gate_call(monkeypatch, "/search-eval", "POST", body={})
    assert st == 200, body
    assert body["pairs"]["total"] == 3 and body["pairs"]["measured"] == 2 and body["pairs"]["missing_gold"] == 1
    assert body["pairs"]["box"] == 1 and body["pairs"]["doc"] == 1
    assert set(body["variants"]) == {"effective", "base", "off", *[f"-{k}" for k in gw._TUNING_SWITCHES]}
    assert body["variants"]["effective"]["전체"]["n"] == 2 and body["variants"]["effective"]["box"]["hit@5"] == 1.0
    assert body["fingerprint"] == gw._tuning()["fingerprint"]
    assert not [r for r in gw._qlog_read() if "q" in r], "평가 질의는 실사용 질의 기록에 섞이지 않는다"
    monkeypatch.setattr(gw, "_SEARCH_EVAL_LOCK", {"busy": True})
    st, _ = _gate_call(monkeypatch, "/search-eval", "POST", body={})
    assert st == 409, "평가는 한 번에 하나"


def test_E9_run_py_live_는_떠_있는_창구를_불러_판마다_표로_찍는다(monkeypatch, tmp_path, capsys):
    # CLI → httpx → 실제 미들웨어 → _search_eval_run 을 한 줄로 — 가짜 응답이 아니라 창구가 내는 꼴 그대로 표를 찍는지 본다
    import argparse
    import importlib.util
    _search_catalog(monkeypatch)
    _no_embed(monkeypatch)
    monkeypatch.setattr(gw, "GW_TOKEN", "gw-secret")
    pairs = tmp_path / "pairs.jsonl"
    pairs.write_text(json.dumps({"id": "doc-x", "query": "물성 조회", "gold": ["heax-materialtwin_web:get_material_properties"],
                                 "source": "doc"}, ensure_ascii=False) + "\n", encoding="utf-8")
    monkeypatch.setattr(gw, "SEARCH_PAIRS_PATH", pairs)
    spec = importlib.util.spec_from_file_location("tse_run", gw.Path(gw.__file__).with_name("tool_search_eval") / "run.py")
    run = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(run)
    real = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient",
                        lambda **kw: real(transport=httpx.ASGITransport(app=gw._bearer_gate(None, None)), **kw))
    for token, want_ok in (("gw-secret", True), ("wrong", False)):
        cfg = tmp_path / f"cfg-{token}.json"
        cfg.write_text(json.dumps({"_gateway": {"token": token}}), encoding="utf-8")
        args = argparse.Namespace(gateway="http://gw", config=str(cfg), timeout=30.0, detail=True)
        if not want_ok:
            with pytest.raises(SystemExit, match="/search-eval 401"):
                asyncio.run(run._live(args))
            continue
        asyncio.run(run._live(args))
        out = capsys.readouterr().out
        assert "(덧씌우기 없음)" in out and "정답쌍 — 1쌍 중 1쌍을 잰다" in out and "doc 1" in out, out
        rows = [ln.split() for ln in out.splitlines() if ln.startswith(("effective ", "base ", "off "))]
        assert {r[0] for r in rows} == {"effective", "base", "off"} and all(r[1] in ("전체", "doc") for r in rows), out


# ── E-8 — 플랫폼별 피드백 보고서가 게이트웨이가 남긴 기록을 그대로 읽는다(가짜가 아니라 진짜 꼴) ──────────────────────────────
def test_E8_피드백_보고서는_게이트웨이가_남긴_질의_기록과_감사를_그대로_읽는다(monkeypatch, tmp_path):
    import platform_feedback_report as pfr
    _qlog_kit(monkeypatch)
    # 실제 꼴 — 노출 이름은 원래 이름이거나 '<백엔드 키에서 하이픈 뺀 것>_<원래 이름>' 이다(_aggregate). _qlog_kit 의 route 는 그 꼴이 아니다
    monkeypatch.setattr(gw, "route", {"report_digest": ("signalforge", "report_digest"), "report_list": ("signalforge", "report_list")})
    monkeypatch.setattr(gw, "backends", {"signalforge": object()})
    asyncio.run(gw._search_tools({"query": "요약"}))                      # 손 동의어로만 report_digest 에 닿는다 — boost_only
    big = types.CallToolResult(content=[types.TextContent(type="text", text="가" * 60_000)])
    gw._audit("report_list", "signalforge", True, None, 5, caller="someone@example.com", res=big)
    gw._audit("report_digest", "signalforge", False, "refused: no-connection", 5, caller="someone@example.com")
    tmap = tmp_path / "map.json"
    tmap.write_text(json.dumps({"map": {"report_digest": "signalforge", "report_list": "signalforge"},
                                "apps": [{"app": "signalforge", "label": "SignalForge"}]}), encoding="utf-8")
    out = tmp_path / "r.md"
    assert pfr.main(["--tools-map", str(tmap), "--audit", gw.AUDIT_PATH, "--qlog-dir", str(gw.TOOL_QUERY_LOG_DIR),
                     "--tuning", str(gw.SEARCH_TUNING_PATH), "--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "질의 1개 · 결과 줄 2개" in text and f"질의 때의 지문 `{gw._tuning()['fingerprint']}` 1개" in text, text[:600]
    row = next(ln for ln in text.splitlines() if ln.startswith("| 손 동의어 '요약'"))
    assert "`report_digest`(1)" in row and "「요약」" in row, row
    row = next(ln for ln in text.splitlines() if ln.startswith("| `report_list` | 1 |") and ln.endswith("| 1 |"))
    assert "60,000" in row, "감사 chars(진짜 _res_chars)로 큰 응답을 잰다"
    assert "게이트웨이 · 권한에서 막힌 호출 1건은 실패에서 뺐다" in text
    assert "someone" not in text


def test_E8_피드백_보고서의_손잡이_읽기는_게이트웨이와_지문이_같다(monkeypatch):
    import platform_feedback_report as pfr
    local = gw.SEARCH_TUNING_LOCAL_PATH                                  # autouse 가 tmp 로 건 자리
    cases = [None, {"synonyms": {"요약": {"owner": "signalforge", "source_fix": "digest 설명에 '요약'"}, "보고서": None},
                    "switches": {"quality": False}},
             {"weights": {"name": "넷"}}, "{깨진", [1, 2]]
    for overlay in cases:
        if overlay is None:
            local.unlink(missing_ok=True)
        else:
            local.write_text(overlay if isinstance(overlay, str) else json.dumps(overlay, ensure_ascii=False), encoding="utf-8")
        monkeypatch.setattr(gw, "_TUNING", {"key": None, "data": None, "error": None, "overlay": None})
        mine, theirs = pfr.load_tuning(gw.SEARCH_TUNING_PATH, local), gw._tuning()
        assert mine["fingerprint"] == theirs["fingerprint"] and mine["base_fingerprint"] == theirs["base_fingerprint"], overlay
        assert {k: (e["owner"], e["source_fix"]) for k, e in mine["synonyms"].items()} == \
               {k: (e["owner"], e["source_fix"]) for k, e in theirs["owners"].items()}, overlay


# ── 분석 루틴(HWAXPortal docs/analysis-routines R2) — 로컬 도구 여섯 · 단계 울타리 · 원장 · RA 초안 ────────────────────────────
_RT_PLAN = {"run": {"id": "r1", "state": "running", "calls": 0},          # 포털 run_view 꼴 — allowed 는 {백엔드: [원래 이름]}
            "steps": [{"id": "voc", "state": "running", "backends": ["signalforge"],
                       "allowed": {"signalforge": ["search_voc", "defect_profile"]}, "budget": {"calls": 3}, "calls": 0},
                      {"id": "delib", "state": "pending", "backends": ["hwax-deliberation"],
                       "allowed": {"hwax-deliberation": ["deliberate_start"]}, "budget": {"calls": 3}, "calls": 0},
                      {"id": "old", "state": "ok", "backends": ["signalforge"], "allowed": {"signalforge": ["search_voc"]},
                       "budget": {"calls": 3}, "calls": 1},
                      {"id": "two", "state": "pending", "backends": ["signalforge", "failuretrace"],
                       "allowed": {"signalforge": ["search_voc"], "failuretrace": ["search_voc"]}, "budget": {"calls": 3}, "calls": 0}]}


def _rt_kit(monkeypatch, plan=None, result_text='{"rows": [1, 2]}', is_error=False, extra=None):
    """포털(/routines-api)은 가짜(부른 것을 적는다), 안쪽 도구 호출(_call_tool_body)도 가짜다 — 이름 · 인자 · 그때의 corr 를 적는다.
    노출 이름은 실제 꼴이다(겹침 별칭은 '<백엔드에서 하이픈 뺀 것>_<원래 이름>')."""
    seen, inner = [], []
    replies = {("GET", "/runs/r1"): plan or _RT_PLAN, ("POST", "/runs/r1/calls"): {"call_id": "voc.c1"},
               ("GET", "/runs/r1/evidence"): {"evidence": [{"source": "signalforge:search_voc", "key": "voc.c1"}]},
               ("POST", "/runs/r1/ra"): {"ok": True}, **(extra or {})}

    async def portal(method, path, *, body=None, params=None, timeout=None):
        seen.append((method, path, body, params))
        if (method, path) not in replies:
            raise AssertionError(f"뜻밖의 포털 호출 {method} {path}")
        v = replies[(method, path)]
        if isinstance(v, Exception):
            raise v
        return v
    monkeypatch.setattr(gw, "_routine_portal", portal)
    monkeypatch.setattr(gw, "route", {"search_voc": ("signalforge", "search_voc"),
                                      "signalforge_defect_profile": ("signalforge", "defect_profile"),
                                      "submit_job": ("signalforge", "submit_job"),
                                      "create_report_draft": ("reportarchive", "create_report_draft"),
                                      "deliberate_start": ("hwax-deliberation", "deliberate_start")})
    monkeypatch.setattr(gw, "alias_route", {})

    async def body(name, args):
        inner.append((name, args, gw._request_corr()))
        return types.CallToolResult(content=[types.TextContent(type="text", text=result_text)], isError=is_error)
    monkeypatch.setattr(gw, "_call_tool_body", body)
    return seen, inner


def _rt_run(name, args):
    res = asyncio.run(gw._routine_dispatch(name, args))
    return res, res.content[0].text


def test_루틴_도구_여섯은_로컬_목록에_있고_읽기_전용_PAT_는_목록_계획만(monkeypatch):
    names = [t.name for t in gw._local_tools()]
    assert {t.name for t in gw.ROUTINE_TOOLS} <= set(names) and len(gw.ROUTINE_TOOLS) == 6
    for t in gw.ROUTINE_TOOLS:
        props = t.inputSchema.get("properties") or {}
        assert all((p.get("description") or "").strip() for p in props.values()), f"{t.name} 인자 설명(점수판)"
    assert {n for n in gw._LOCAL_READ if n.startswith("routine_")} == {"routine_list", "routine_get"}
    for n in ("routine_run_start", "routine_call", "routine_step_done", "routine_report_submit"):
        assert gw._readonly_denial(n, {}).startswith("read_only:"), n
    assert gw._readonly_denial("routine_list", {}) == "" and gw._readonly_denial("routine_get", {}) == ""
    st, body = _gate_call(monkeypatch, "/tools-map")
    assert st == 200 and all(body["map"].get(t.name) == "_gateway" for t in gw.ROUTINE_TOOLS), "도구 지도 · list_tool_apps 의 수가 맞는다"


def test_routine_call_은_단계_울타리_밖을_거절한다(monkeypatch):
    seen, inner = _rt_kit(monkeypatch)
    for name, step, why in (("search_reports", "voc", "울타리 밖"), ("submit_job", "voc", "울타리 밖"),
                            ("search_voc", "old", "이미 닫혔다"), ("search_voc", "nope", "단계 'nope' 가 없다")):
        res, text = _rt_run("routine_call", {"run_id": "r1", "step": step, "name": name})
        assert res.isError and text.startswith("ROUTINE_ERROR:") and why in text, (name, text)
    assert inner == [], "울타리 밖은 안쪽 도구를 부르지 않는다"
    plan = {**_RT_PLAN, "run": {**_RT_PLAN["run"], "state": "cancelled"}}
    _rt_kit(monkeypatch, plan=plan)
    _, text = _rt_run("routine_call", {"run_id": "r1", "step": "voc", "name": "search_voc"})
    assert "cancelled 상태" in text
    steps = [dict(_RT_PLAN["steps"][0], calls=3)] + _RT_PLAN["steps"][1:]
    _rt_kit(monkeypatch, plan={**_RT_PLAN, "steps": steps})
    _, text = _rt_run("routine_call", {"run_id": "r1", "step": "voc", "name": "search_voc"})
    assert "호출 예산(3번)을 다 썼다" in text
    _rt_kit(monkeypatch, plan={**_RT_PLAN, "run": {**_RT_PLAN["run"], "limit_reached": "시간 60분"}})
    _, text = _rt_run("routine_call", {"run_id": "r1", "step": "voc", "name": "search_voc"})
    assert "실행 상한에 닿았다(시간 60분)" in text


def test_routine_call_은_원래_이름을_풀고_corr_를_달아_부른_뒤_원장에_남긴다(monkeypatch):
    seen, inner = _rt_kit(monkeypatch)
    res, text = _rt_run("routine_call", {"run_id": "r1", "step": "voc", "name": "defect_profile", "arguments": {"product": "X"}})
    assert not res.isError, text
    [(exposed, args, corr)] = inner
    assert exposed == "signalforge_defect_profile" and args == {"product": "X"}, "원래 이름 → 이 게이트웨이의 노출 이름"
    assert corr == "routine:r1:voc" and gw._request_corr() == "", "안쪽 호출 동안만 그 실행 · 단계가 corr 다"
    post = next(b for m, p, b, _ in seen if (m, p) == ("POST", "/runs/r1/calls"))
    assert post == {"step": "voc", "backend": "signalforge", "tool": "defect_profile", "args": {"product": "X"}, "ok": True,
                    "ms": post["ms"], "result": '{"rows": [1, 2]}', "truncated": False}
    head = json.loads(text)
    assert head == {"routine_call": "voc.c1", "step": "voc", "tool": "signalforge:defect_profile", "ok": True, "chars": 16}
    assert res.content[1].text == '{"rows": [1, 2]}', "작은 결과는 원래 블록 그대로"


def test_두_백엔드에_같은_이름이면_백엔드_이름으로_부른다(monkeypatch):
    seen, inner = _rt_kit(monkeypatch)
    monkeypatch.setattr(gw, "route", {**gw.route, "failuretrace_search_voc": ("failuretrace", "search_voc")})
    _, text = _rt_run("routine_call", {"run_id": "r1", "step": "two", "name": "search_voc"})
    assert "signalforge, failuretrace 에 다 있다" in text, "노출 이름 search_voc 는 signalforge 것이다 — 고르지 않고 묻는다"
    res, text = _rt_run("routine_call", {"run_id": "r1", "step": "two", "name": "failuretrace:search_voc"})
    assert not res.isError and inner[-1][0] == "failuretrace_search_voc"
    post = [b for m, p, b, _ in seen if (m, p) == ("POST", "/runs/r1/calls")][-1]
    assert (post["backend"], post["tool"]) == ("failuretrace", "search_voc")
    _, text = _rt_run("routine_call", {"run_id": "r1", "step": "two", "name": "nope:search_voc"})
    assert "울타리 밖" in text


def test_routine_call_큰_결과는_원장에_다_두고_응답은_첫_쪽만(monkeypatch):
    seen, _ = _rt_kit(monkeypatch, result_text="가" * 150_000)
    res, text = _rt_run("routine_call", {"run_id": "r1", "step": "voc", "name": "search_voc"})
    head = json.loads(text)
    assert head["pages"] == 3 and "page=2" in head["next"] and len(res.content[1].text) == gw.ROUTINE_PAGE_CHARS
    post = next(b for m, p, b, _ in seen if (m, p) == ("POST", "/runs/r1/calls"))
    assert len(post["result"]) == 150_000 and post["truncated"] is False


def test_routine_call_오류_결과도_원장에_남기고_isError_를_잇는다(monkeypatch):
    seen, _ = _rt_kit(monkeypatch, result_text="backend down", is_error=True)
    res, _ = _rt_run("routine_call", {"run_id": "r1", "step": "voc", "name": "search_voc"})
    assert res.isError
    post = next(b for m, p, b, _ in seen if (m, p) == ("POST", "/runs/r1/calls"))
    assert post["ok"] is False and post["result"] == "backend down"


def test_심의_단계는_evidence_를_비우면_원장에서_채운다(monkeypatch):
    seen, inner = _rt_kit(monkeypatch)
    _rt_run("routine_call", {"run_id": "r1", "step": "delib", "name": "deliberate_start", "arguments": {"question": "왜"}})
    assert inner[-1][1] == {"question": "왜", "evidence": [{"source": "signalforge:search_voc", "key": "voc.c1"}]}
    assert ("GET", "/runs/r1/evidence", None, {"step": "delib"}) in seen
    seen.clear()
    _rt_run("routine_call", {"run_id": "r1", "step": "delib", "name": "deliberate_start",
                             "arguments": {"question": "왜", "evidence": [{"source": "직접"}]}})
    assert inner[-1][1]["evidence"] == [{"source": "직접"}] and not any(p.endswith("/evidence") for _, p, _, _ in seen)


def test_보고서는_저절로면_그_사람_이름으로_RA_초안을_만들고_결과를_원장에_돌려준다(monkeypatch):
    rendered = {"report_md": "# 보고서", "coverage": {"ok": 2, "skipped": 1}, "warnings": ["w"],
                "ra": {"upload": "auto", "title": "S26 스웰링", "blocks": {"background": ["b"]}, "tags": ["분석 루틴"]}}
    seen, inner = _rt_kit(monkeypatch, result_text='{"report_id": 58, "title": "S26"}',
                          extra={("POST", "/runs/r1/report"): rendered})
    res, text = _rt_run("routine_report_submit", {"run_id": "r1", "sections": {"insight": "근거 [voc.c1]"}})
    out = json.loads(text)
    assert out["ra_report_id"] == "58" and out["coverage"] == {"ok": 2, "skipped": 1} and out["report_chars"] == len("# 보고서")
    [(exposed, args, corr)] = inner
    assert exposed == "create_report_draft" and args == {"template_id": "deliberation", "template_version": 1, "title": "S26 스웰링",
                                                         "blocks": {"background": ["b"]}, "tags": ["분석 루틴"]}
    assert corr == "routine:r1:report"
    assert ("POST", "/runs/r1/ra", {"report_id": "58"}, None) in seen
    assert ("POST", "/runs/r1/report", {"sections": {"insight": "근거 [voc.c1]"}}, None) in seen


def test_RA_토큰이_없으면_건너뛰고_까닭을_원장에(monkeypatch):
    rendered = {"report_md": "x", "ra": {"upload": "auto", "title": "t", "blocks": {}, "tags": []}}
    seen, _ = _rt_kit(monkeypatch, result_text="Report Archive 토큰을 등록하세요(/tokens?tab=connect)", is_error=True,
                      extra={("POST", "/runs/r1/report"): rendered})
    _, text = _rt_run("routine_report_submit", {"run_id": "r1"})
    out = json.loads(text)
    assert "토큰을 등록" in out["ra_error"] and "ra_report_id" not in out
    assert any((m, p) == ("POST", "/runs/r1/ra") and "토큰을 등록" in b["error"] for m, p, b, _ in seen)


def test_끝에_묻기_루틴은_upload_true_일_때만_올리고_안_올림은_안_올린다(monkeypatch):
    for mode, upload, called in (("ask", None, False), ("ask", True, True), ("off", True, False)):
        rendered = {"report_md": "x", "ra": {"upload": mode, "title": "t", "blocks": {}, "tags": []}}
        _, inner = _rt_kit(monkeypatch, result_text='{"report_id": 7}', extra={("POST", "/runs/r1/report"): rendered})
        _, text = _rt_run("routine_report_submit", {"run_id": "r1", **({"upload": upload} if upload else {})})
        assert bool(inner) is called, (mode, upload)
        if mode == "ask" and not upload:
            assert "upload=true" in json.loads(text)["ra_next"]
    _rt_kit(monkeypatch, extra={("POST", "/runs/r1/report"): {"ra": {"upload": "auto"}}})
    monkeypatch.setattr(gw, "route", {})
    _, text = _rt_run("routine_report_submit", {"run_id": "r1"})
    assert json.loads(text)["ra_error"] == "이 박스 게이트웨이에 Report Archive 가 없다"


def test_실행_시작은_자격으로_실행자를_가린다(monkeypatch):
    seen, _ = _rt_kit(monkeypatch, extra={("POST", "/runs"): {"run_id": "r9"}})
    _set_request_headers(monkeypatch, {gw.VIA_HEADER: "chat"})
    _rt_run("routine_run_start", {"routine_id": "x", "inputs": {"model": "S26"}, "version": 2})
    _set_request_headers(monkeypatch, {gw.VIA_HEADER: "pat"})
    _rt_run("routine_run_start", {"routine_id": "x"})
    bodies = [b for m, p, b, _ in seen if (m, p) == ("POST", "/runs")]
    assert bodies == [{"routine_id": "x", "inputs": {"model": "S26"}, "executor": "chat", "version": 2},
                      {"routine_id": "x", "inputs": {}, "executor": "mcp"}]


def test_포털_창구는_호출자_PAT_를_넘기고_낡은_포털을_말한다(monkeypatch):
    import re
    sent = []
    reply = {"r": httpx.Response(200, json={"routines": []})}

    def handler(req):
        sent.append(req)
        return reply["r"]
    real = httpx.AsyncClient
    monkeypatch.setattr(gw.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr(gw, "PORTAL", {"api_base": "http://portal.test"})
    _set_request_headers(monkeypatch, {"authorization": "Bearer pat-person"})
    got = asyncio.run(gw._routine_portal("GET", "/routines", params={"q": "x"}))
    assert got == {"routines": []} and sent[0].headers["authorization"] == "Bearer pat-person"
    assert str(sent[0].url) == "http://portal.test/routines-api/routines?q=x"
    cases = [(httpx.Response(200, text="<html>SPA</html>", headers={"content-type": "text/html"}), "포털이 이 게이트웨이보다 낡았다"),
             (httpx.Response(404, json={"detail": "Not Found"}), "포털이 이 게이트웨이보다 낡았다"),
             (httpx.Response(404, json={"detail": "루틴을 찾을 수 없습니다"}), "루틴을 찾을 수 없습니다"),
             (httpx.Response(401, json={"detail": "x"}), "토큰을 받지 않았다"),
             (httpx.Response(403, json={"detail": "권한이 없습니다(feat:routines)"}), "feat:routines")]
    for resp, why in cases:
        reply["r"] = resp
        with pytest.raises(gw._RoutineError, match=re.escape(why)):
            asyncio.run(gw._routine_portal("GET", "/routines"))
    monkeypatch.setattr(gw, "GW_TOKEN", "gw-secret")
    _set_request_headers(monkeypatch, {"authorization": "Bearer gw-secret"})
    with pytest.raises(gw._RoutineError, match="사람 PAT 로만"):
        asyncio.run(gw._routine_portal("GET", "/routines"))


def test_루틴_도구는_정상_호출_경로에서_디스패치되고_읽기_전용은_실행을_못_한다(monkeypatch):
    real = gw._call_tool_body
    seen, _ = _rt_kit(monkeypatch, extra={("GET", "/routines"): {"count": 0, "routines": []}})
    monkeypatch.setattr(gw, "_call_tool_body", real)              # 안쪽 호출은 가짜로 두지 않는다 — 진짜 디스패치를 탄다
    _set_request_headers(monkeypatch, {})
    res = asyncio.run(real("routine_list", {"q": "x" * 300}))
    assert not res.isError and json.loads(res.content[0].text) == {"count": 0, "routines": []}
    assert seen[-1] == ("GET", "/routines", None, {"q": "x" * 200}), "q 는 200자까지"
    _set_request_headers(monkeypatch, {gw.READONLY_HEADER: "1"})
    res = asyncio.run(real("routine_call", {"run_id": "r1", "step": "voc", "name": "search_voc"}))
    assert res.isError and res.content[0].text.startswith("read_only: routine_call"), res.content[0].text
    res = asyncio.run(real("routine_list", {}))
    assert not res.isError, "목록은 읽기 전용 토큰도 본다"
