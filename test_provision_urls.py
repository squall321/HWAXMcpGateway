# 백엔드 주소 결정 — 형제 서비스의 `.env` 포트가 정본이고, 한 번 박힌 기본값을 물려받지 않는다
import json
import re
import subprocess
import sys
from pathlib import Path

import provision_urls as pu

HERE = Path(__file__).resolve().parent


def _sibling(tmp_path, body: str) -> Path:
    root = tmp_path / "siblings"
    (root / "SignalForge").mkdir(parents=True)
    (root / "SignalForge" / ".env").write_text(body, encoding="utf-8")
    return root


# ── cae00 에서 실제로 난 것 ─────────────────────────────────────────────────
def test_한_번_박힌_기본값을_물려받지_않는다(tmp_path):
    """cae00: SignalForge 는 8008 인데 `.bak` 이 8013 을 들고 있었다 → 09-18 부터 signalforge: false.
    형제 `.env` 가 선언한 포트가 직전 config(로컬 주소)보다 이긴다."""
    root = _sibling(tmp_path, "API_PORT=18000\nMCP_PORT=8008\n")
    url, why = pu.resolve("signalforge", env_url=None, prev_url="http://127.0.0.1:8013/mcp",
                          sibling_root=str(root), default="http://127.0.0.1:8013/mcp")
    assert url == "http://127.0.0.1:8008/mcp", url
    assert "SignalForge/.env" in why and "8008" in why


def test_dev_처럼_선언과_같으면_그대로다(tmp_path):
    root = _sibling(tmp_path, "MCP_PORT=8013\n")
    url, _ = pu.resolve("signalforge", env_url=None, prev_url="http://127.0.0.1:8013/mcp",
                        sibling_root=str(root), default="x")
    assert url == "http://127.0.0.1:8013/mcp"


def test_사람이_명시한_env_가_이긴다(tmp_path):
    root = _sibling(tmp_path, "MCP_PORT=8008\n")
    url, why = pu.resolve("signalforge", env_url="http://10.0.0.5:9000/mcp",
                          prev_url="http://127.0.0.1:8013/mcp", sibling_root=str(root), default="x")
    assert url == "http://10.0.0.5:9000/mcp" and why == "env"


def test_원격으로_옮긴_주소는_존중한다(tmp_path):
    """`.bak` 은 사람이 손으로 바꾼 주소를 지키려고 있다 — 원격이면 사람이 서비스를 옮긴 것이다.
    이 박스의 형제 `.env` 로 그걸 덮으면 옮긴 서비스를 다시 로컬로 끌어온다."""
    root = _sibling(tmp_path, "MCP_PORT=8008\n")
    url, why = pu.resolve("signalforge", env_url=None, prev_url="http://sf.internal:8008/mcp",
                          sibling_root=str(root), default="x")
    assert url == "http://sf.internal:8008/mcp" and "원격" in why


def test_선언이_없으면_짐작하지_않는다(tmp_path):
    """형제 `.env` 가 없거나 포트를 선언하지 않았으면 예전 순서(직전 → 기본값) 그대로다."""
    url, why = pu.resolve("signalforge", env_url=None, prev_url="http://127.0.0.1:8013/mcp",
                          sibling_root=str(tmp_path / "없음"), default="d")
    assert (url, why) == ("http://127.0.0.1:8013/mcp", "직전 config")
    url, why = pu.resolve("signalforge", env_url=None, prev_url=None,
                          sibling_root=str(tmp_path / "없음"), default="d")
    assert (url, why) == ("d", "기본값")
    # 형제 선언이 없는 백엔드는 형제를 보지 않는다
    root = _sibling(tmp_path, "MCP_PORT=8008\n")
    url, _ = pu.resolve("ai-data-hub", env_url=None, prev_url="http://127.0.0.1:8001/mcp/",
                        sibling_root=str(root), default="d")
    assert url == "http://127.0.0.1:8001/mcp/"


def test_env_파일_모양(tmp_path):
    f = tmp_path / ".env"
    f.write_text('# 주석\nexport MCP_PORT="8008"  \nOTHER=1\n', encoding="utf-8")
    assert pu.dotenv_get(str(f), "MCP_PORT") == "8008"
    f.write_text("MCP_PORT=8008 # 운영 포트\n", encoding="utf-8")
    assert pu.dotenv_get(str(f), "MCP_PORT") == "8008"
    f.write_text("MCP_PORT=\n", encoding="utf-8")
    assert pu.dotenv_get(str(f), "MCP_PORT") is None
    root = _sibling(tmp_path, "MCP_PORT=abc\n")
    url, _ = pu.resolve("signalforge", env_url=None, prev_url=None, sibling_root=str(root), default="d")
    assert url == "d", "숫자가 아닌 포트로 주소를 지어내지 않는다"


# ── update-all 이 쓰는 드리프트 판정 ────────────────────────────────────────
def _cfg(tmp_path, url: str) -> Path:
    p = tmp_path / "gateway_config.json"
    p.write_text(json.dumps({"signalforge": {"url": url, "headers": {"Authorization": "Bearer secret"}}}),
                 encoding="utf-8")
    return p


def test_드리프트는_로컬_주소가_선언과_다를_때만(tmp_path):
    root = _sibling(tmp_path, "MCP_PORT=8008\n")
    assert pu.drift(str(_cfg(tmp_path, "http://127.0.0.1:8013/mcp")), str(root)) == [
        ("signalforge", "http://127.0.0.1:8013/mcp", "http://127.0.0.1:8008/mcp")]
    assert pu.drift(str(_cfg(tmp_path, "http://127.0.0.1:8008/mcp")), str(root)) == []
    assert pu.drift(str(_cfg(tmp_path, "http://sf.internal:8013/mcp")), str(root)) == [], "원격은 사람 몫"
    assert pu.drift(str(_cfg(tmp_path, "http://127.0.0.1:8013/mcp")), str(tmp_path / "없음")) == []


def test_드리프트_CLI_는_주소만_찍는다(tmp_path):
    """update-all 이 부른다. 토큰(headers)이 출력에 새면 운영 로그에 비밀이 남는다."""
    root = _sibling(tmp_path, "MCP_PORT=8008\n")
    out = subprocess.run([sys.executable, str(HERE / "provision_urls.py"), "drift",
                          str(_cfg(tmp_path, "http://127.0.0.1:8013/mcp")), str(root)],
                         capture_output=True, text=True, check=True).stdout
    assert out == "signalforge\thttp://127.0.0.1:8013/mcp\thttp://127.0.0.1:8008/mcp\n"
    assert "secret" not in out


def test_프로비저너가_signalforge_주소를_이_판정으로_정한다():
    """배선이 끊기면 위 시험이 전부 초록인 채 운영은 옛 기본값으로 돈다 — 소스에서 건다."""
    src = (HERE / "provision-config.sh").read_text(encoding="utf-8")
    assert re.search(r'provision_urls\.resolve\(\s*"signalforge"', src), "signalforge 가 resolve 를 안 탄다"
    assert 'cfg["signalforge"] = {"url": _sf_url' in src
    assert '_url("SF_MCP_URL", "signalforge"' not in src, "옛 경로(.bak 물려받기)가 남아 있다"
    assert 'SIBLING_ROOT="$PARENT"' in src, "형제 리포 루트를 파이썬 블록에 안 넘긴다"


# ── REST 다리 사이트 확장 ────────────────────────────────────────────────────
# provision-config.sh 의 파이썬 블록을 **그대로 떼어 돌린다.** 로직을 시험 안에 베껴 쓰면
# 스크립트가 바뀌어도 시험은 계속 통과한다 — 그러면 시험이 아니라 사본이다.
def _run_provision(tmp_path, env: dict) -> dict:
    body = re.search(r"python3 - <<'PYEOF'\n(.*?)\nPYEOF\n",
                     (HERE / "provision-config.sh").read_text(encoding="utf-8"), re.S).group(1)
    script = tmp_path / "block.py"
    script.write_text(body, encoding="utf-8")
    cfg = tmp_path / "gateway_config.json"
    full = {"CFG": str(cfg), "AGENT_DIR": str(tmp_path / "noagent"), "HERE": str(HERE),
            "SIBLING_ROOT": str(tmp_path / "siblings"), "GW_TOKEN": "gw", **env}
    r = subprocess.run([sys.executable, str(script)], env=full, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(cfg.read_text(encoding="utf-8"))


def test_rest_사이트는_본인_명의로_갈_수_있으면_그렇게_간다(tmp_path):
    out = _run_provision(tmp_path, {
        "HEAX_MCP_TOKEN": "heax-svc", "KOORM_SSO_SECRET": "s1", "STE_SSO_SECRET": "s2",
        "STE_SSO_URL": "http://10.0.0.9:15810/api/auth/sso",
    })
    rest = out["rest"]
    # ste·DynaForge 는 사용자 위임이 있으니 주입 없이 per_user 로 간다 → 쓰기가 막히지 않는다.
    assert rest["ste"] == {"base": "http://10.0.0.9:15810", "per_user": "ste"}
    assert rest["dyna-forge"]["per_user"] == "kooremapper_mcp"
    assert "inject" not in rest["ste"] and "inject" not in rest["dyna-forge"]
    import rest_proxy
    assert rest_proxy.allowed_methods(rest["ste"]) is None
    # StepForge 는 서비스 토큰뿐이다 → 읽기전용으로 묶인다(마스터 키로 쓰지 못하게).
    assert rest["step-forge"]["base"].endswith("/apps/step_forge")
    assert rest_proxy.allowed_methods(rest["step-forge"]) == ["GET", "HEAD"]
    # 사이트를 늘렸으면 허용 청중도 같이 늘어야 한다 — 안 그러면 프록시가 404 로 답한다.
    assert set(out["portal"]["audience_ok"]) == set(rest)


def test_위임_시크릿이_없으면_그_사이트를_아예_안_만든다(tmp_path):
    """자격 없이 사이트만 만들면 '있는데 401' 이 된다 — 없는 것보다 나쁘다."""
    out = _run_provision(tmp_path, {"HEAX_MCP_TOKEN": "heax-svc"})
    assert "ste" not in out["rest"] and "dyna-forge" not in out["rest"]
    assert "step-forge" in out["rest"]
    out2 = _run_provision(tmp_path, {})           # heax 토큰도 없으면 StepForge 도 빠진다
    assert set(out2["rest"]) == {"ai-data-hub"}
    assert set(out2["portal"]["audience_ok"]) == {"ai-data-hub"}
    # 자격이 아무것도 없는 사이트도 읽기전용이다 — 상류(AIDataHub)가 무인증 200 이라
    # 이 프록시가 유일한 관문이고, rest_call 로 LLM 이 부를 수 있게 된 뒤로는 더 그렇다.
    import rest_proxy
    assert rest_proxy.allowed_methods(out2["rest"]["ai-data-hub"]) == ["GET", "HEAD"]


def test_손으로_바꾼_rest_base_는_재생성에서_보존된다(tmp_path):
    env = {"HEAX_MCP_TOKEN": "heax-svc", "STE_SSO_SECRET": "s2",
           "STE_SSO_URL": "http://10.0.0.9:15810/api/auth/sso"}
    _run_provision(tmp_path, env)
    cfg = tmp_path / "gateway_config.json"
    (tmp_path / "gateway_config.json.bak").write_text(
        json.dumps({"rest": {"ste": {"base": "http://192.168.130.10:15810"}}}), encoding="utf-8")
    cfg.unlink()
    out = _run_provision(tmp_path, env)
    assert out["rest"]["ste"]["base"] == "http://192.168.130.10:15810"   # sso_url 유도보다 앞선다


def test_ste_sso_url_은_env_가_없으면_직전_config_를_보존한다(tmp_path):
    """MCP url 은 `_url()` 이 직전값을 지키는데 sso_url 만 env → 기본값이었다. 그래서
    STE_SSO_URL 없이 --force 를 돌리면 VM 주소가 127.0.0.1 로 **덮였다**(dev 실측 2026-09-24)."""
    (tmp_path / "gateway_config.json.bak").write_text(json.dumps({
        "heax_registry": {"per_user_sso": {"ste": {
            "sso_url": "http://192.168.130.10:15810/api/auth/sso", "secret": "old", "client": "gateway"}}},
    }), encoding="utf-8")
    out = _run_provision(tmp_path, {"HEAX_MCP_TOKEN": "heax-svc", "STE_SSO_SECRET": "s2"})   # STE_SSO_URL 없음
    assert out["heax_registry"]["per_user_sso"]["ste"]["sso_url"] == "http://192.168.130.10:15810/api/auth/sso"
    # env 가 있으면 그것이 이긴다
    out = _run_provision(tmp_path, {"HEAX_MCP_TOKEN": "heax-svc", "STE_SSO_SECRET": "s2",
                                    "STE_SSO_URL": "http://10.0.0.9:15810/api/auth/sso"})
    assert out["heax_registry"]["per_user_sso"]["ste"]["sso_url"] == "http://10.0.0.9:15810/api/auth/sso"
    # 직전값도 env 도 없을 때만 기본값
    (tmp_path / "gateway_config.json.bak").unlink()
    (tmp_path / "gateway_config.json").unlink(missing_ok=True)
    out = _run_provision(tmp_path, {"HEAX_MCP_TOKEN": "heax-svc", "STE_SSO_SECRET": "s2"})
    assert out["heax_registry"]["per_user_sso"]["ste"]["sso_url"] == "http://127.0.0.1:15810/api/auth/sso"


def test_포털_api_base_는_재생성에서_사라지지_않는다(tmp_path):
    """--force 가 portal 블록을 api_base 없이 다시 써서 사용자별 RA 위임이 조용히 꺼졌다(2026-09-29).
    기본값이 있고, 손으로 바꾼 값은 이어받는다."""
    out = _run_provision(tmp_path, {})
    assert out["portal"]["api_base"] == "http://127.0.0.1:8723"
    assert out["portal"]["jwks_url"].startswith(out["portal"]["api_base"] + "/")
    (tmp_path / "gateway_config.json.bak").write_text(
        json.dumps({"portal": {"api_base": "http://10.0.0.7:8723"}}), encoding="utf-8")
    (tmp_path / "gateway_config.json").unlink()
    assert _run_provision(tmp_path, {})["portal"]["api_base"] == "http://10.0.0.7:8723"


def test_ste_위임은_heax_토큰이_없어도_생긴다(tmp_path):
    """heax 토큰 자동 발급이 실패한 박스에서 ste 위임까지 사라져 게이트웨이가 ste 를 토큰 없이(서비스 신분) 불렀다 —
    REST 가 401 → "Error executing tool …"(HWAXPortal docs/ste-cae00 D-30). 위임은 heax 앱 탐지와 무관하다."""
    out = _run_provision(tmp_path, {"STE_SSO_SECRET": "s2", "STE_SSO_URL": "http://127.0.0.1:15810/api/auth/sso"})
    reg = out["heax_registry"]
    assert reg["per_user_sso"]["ste"] == {"sso_url": "http://127.0.0.1:15810/api/auth/sso", "secret": "s2",
                                         "client": "gateway"}
    assert "servers_url" not in reg and "token" not in reg, "heax 앱 자동탐지는 토큰이 있을 때만 켠다"
    assert out["rest"]["ste"]["per_user"] == "ste", "REST 다리도 같은 위임으로 산다"


# ── RA 사람별 위임(ste 방식) · TestScope 등록 토큰 방식(HWAXPortal docs/sso-delegation) ──────────
def test_RA_위임은_env_로_생기고_부서_헤더를_뺀다(tmp_path):
    out = _run_provision(tmp_path, {"RA_SSO_SECRET": "ra-s", "RA_SSO_URL": "http://10.0.0.3:3000/api/auth/sso"})
    assert out["heax_registry"]["per_user_sso"]["reportarchive"] == {
        "sso_url": "http://10.0.0.3:3000/api/auth/sso", "secret": "ra-s", "client": "gateway",
        "strip_headers": ["X-Workspace-Slug"]}
    # 주소를 안 주면 직전 config, 그것도 없으면 같은 박스 기본값
    (tmp_path / "gateway_config.json").unlink()
    out = _run_provision(tmp_path, {"RA_SSO_SECRET": "ra-s"})
    assert out["heax_registry"]["per_user_sso"]["reportarchive"]["sso_url"] == "http://127.0.0.1:3000/api/auth/sso"


def test_RA_위임은_비밀이_없는_실행에도_지워지지_않는다(tmp_path):
    """비밀을 못 읽은 실행(.env 미반영 등)이 멀쩡하던 위임을 끄면 RA 호출이 조용히 등록 토큰 방식으로 돌아간다."""
    prev = {"sso_url": "http://10.0.0.3:3000/api/auth/sso", "secret": "old", "client": "gateway",
            "strip_headers": ["X-Workspace-Slug"]}
    (tmp_path / "gateway_config.json.bak").write_text(json.dumps({
        "heax_registry": {"per_user_sso": {"reportarchive": prev}}}), encoding="utf-8")
    out = _run_provision(tmp_path, {})
    assert out["heax_registry"]["per_user_sso"]["reportarchive"] == prev
    # 비밀만 새로 주면 주소는 직전 값을 지킨다(ste 와 같은 규칙)
    out = _run_provision(tmp_path, {"RA_SSO_SECRET": "new"})
    got = out["heax_registry"]["per_user_sso"]["reportarchive"]
    assert got["sso_url"] == "http://10.0.0.3:3000/api/auth/sso" and got["secret"] == "new"


def test_RA_위임이_서비스_백엔드를_바꾸지_않는다(tmp_path):
    """도구 목록은 서비스 세션(RAT_TOKEN)으로 모은다 — 위임을 켜도 서비스 항목은 종전 그대로."""
    base = _run_provision(tmp_path, {"RAT_TOKEN": "rat_svc"})
    (tmp_path / "gateway_config.json").unlink()
    out = _run_provision(tmp_path, {"RAT_TOKEN": "rat_svc", "RA_SSO_SECRET": "ra-s"})
    assert out["reportarchive"] == base["reportarchive"]
    assert out["reportarchive"]["headers"] == {"Authorization": "Bearer rat_svc", "X-Workspace-Slug": "dev"}


def test_TestScope_백엔드는_MCP_주소만으로_생기고_위임은_만들지_않는다(tmp_path):
    """다른 조직의 포털이라 RA 처럼 사람이 등록한 토큰으로 부른다(2026-10-03) — 우리가 발급하는 위임은 없다."""
    out = _run_provision(tmp_path, {"TESTSCOPE_MCP_URL": "http://testscope.example:8022/mcp"})
    # 서비스 Authorization 이 없다 — TestScope tools/list 는 토큰 없이 되고, 사람별 호출은 등록 토큰을 싣는다.
    assert out["testscope"] == {"url": "http://testscope.example:8022/mcp", "transport": "streamable_http"}
    assert "testscope" not in (out.get("heax_registry") or {}).get("per_user_sso", {})
    # 옛 손잡이가 env 에 남아 있어도 위임을 만들지 않는다 — 만들면 게이트웨이에서 등록 토큰보다 먼저 탄다.
    (tmp_path / "gateway_config.json").unlink()
    out = _run_provision(tmp_path, {"TESTSCOPE_MCP_URL": "http://testscope.example:8022/mcp",
                                    "TESTSCOPE_SSO_SECRET": "ts-s",
                                    "TESTSCOPE_SSO_URL": "http://testscope.example:8020/api/auth/sso"})
    assert "testscope" not in (out.get("heax_registry") or {}).get("per_user_sso", {})
    assert out["testscope"]["url"] == "http://testscope.example:8022/mcp"


def test_TestScope_는_주소를_모르면_만들지_않는다(tmp_path):
    """기본 호스트가 없다 — 127.0.0.1 로 지어내면 없는 서비스를 가리킨다."""
    out = _run_provision(tmp_path, {})
    assert "testscope" not in out
    out = _run_provision(tmp_path, {"TESTSCOPE_SSO_SECRET": "ts-s",
                                    "TESTSCOPE_SSO_URL": "http://testscope.example:8020/api/auth/sso"})
    assert "testscope" not in out, "MCP 주소가 없으면 백엔드는 없다"


def test_TestScope_는_env_가_없는_실행에도_이어받는다(tmp_path):
    """손으로 붙인 필드(allowed_groups 등)까지 산다 — testscope 는 프로비저너가 만드는(MANAGED) 키다."""
    (tmp_path / "gateway_config.json.bak").write_text(json.dumps({
        "testscope": {"url": "http://testscope.example:8022/mcp", "transport": "streamable_http",
                      "allowed_groups": ["plat:testscope"]},
    }), encoding="utf-8")
    out = _run_provision(tmp_path, {})
    assert out["testscope"] == {"url": "http://testscope.example:8022/mcp", "transport": "streamable_http",
                                "allowed_groups": ["plat:testscope"]}
    # env 주소가 이기고 손으로 붙인 필드는 남는다
    out = _run_provision(tmp_path, {"TESTSCOPE_MCP_URL": "http://testscope2.example:8022/mcp"})
    assert out["testscope"]["url"] == "http://testscope2.example:8022/mcp"
    assert out["testscope"]["allowed_groups"] == ["plat:testscope"]


def test_직전_config_의_TestScope_위임은_조용히_지우지_않는다(tmp_path):
    """만들지는 않지만 사람이 넣어 둔 것일 수 있다 — 지우는 대신 실행 로그에 경고한다."""
    prev = {"sso_url": "http://testscope.example:8020/api/auth/sso", "secret": "old", "client": "gateway"}
    (tmp_path / "gateway_config.json.bak").write_text(json.dumps({
        "heax_registry": {"per_user_sso": {"testscope": prev}}}), encoding="utf-8")
    assert _run_provision(tmp_path, {})["heax_registry"]["per_user_sso"]["testscope"] == prev


def test_RA_위임과_TestScope_가_ste_hwax_risk_를_건드리지_않는다(tmp_path):
    env = {"STE_SSO_SECRET": "s2", "STE_SSO_URL": "http://127.0.0.1:15810/api/auth/sso",
           "HWAXRISK_SSO_SECRET": "hr", "HEAX_MCP_TOKEN": "heax-svc"}
    base = _run_provision(tmp_path, env)["heax_registry"]["per_user_sso"]
    (tmp_path / "gateway_config.json").unlink()
    out = _run_provision(tmp_path, {**env, "RA_SSO_SECRET": "ra-s",
                                    "TESTSCOPE_MCP_URL": "http://testscope.example:8022/mcp"})
    pu_ = out["heax_registry"]["per_user_sso"]
    assert pu_["ste"] == base["ste"] and pu_["hwax_risk"] == base["hwax_risk"]
    assert set(pu_) == {"ste", "hwax_risk", "reportarchive"}
    assert out["rest"]["ste"]["per_user"] == "ste"
    assert "reportarchive" not in out["rest"] and "testscope" not in out["rest"], "REST 다리는 이번 범위가 아니다"
