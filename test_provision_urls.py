# 백엔드 주소 결정 — 형제 서비스의 `.env` 포트가 정본이고, 한 번 박힌 기본값을 물려받지 않는다
import json
import os
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
def _run_provision(tmp_path, env: dict, log: list | None = None) -> dict:
    """`log` 를 주면 그 실행의 표준출력(운영 로그에 남는 줄)을 덧붙인다."""
    body = re.search(r"python3 - <<'PYEOF'\n(.*?)\nPYEOF\n",
                     (HERE / "provision-config.sh").read_text(encoding="utf-8"), re.S).group(1)
    script = tmp_path / "block.py"
    script.write_text(body, encoding="utf-8")
    cfg = tmp_path / "gateway_config.json"
    full = {"CFG": str(cfg), "AGENT_DIR": str(tmp_path / "noagent"), "HERE": str(HERE),
            "SIBLING_ROOT": str(tmp_path / "siblings"), "GW_TOKEN": "gw", **env}
    r = subprocess.run([sys.executable, str(script)], env=full, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    if log is not None:
        log.append(r.stdout)
    return json.loads(cfg.read_text(encoding="utf-8"))


def _force_backup(tmp_path) -> None:
    """`--force` 가 파이썬 블록 **앞에서** 하는 백업을 스크립트에서 그대로 떼어 돌린다 — 라이브 config 가 `.bak` 을 덮는다.
    `_run_provision` 은 블록만 돌려 이것을 하지 않는다. 그래서 연속 실행을 흉내 낸 시험이 첫 실행 전의 `.bak` 을 계속 읽어,
    스크립트가 만들 수 없는 순서(항목이 빠진 **다음** 실행에 직전 주소로 선다)를 통과시켰다. 연속 실행을 볼 때만 사이에 부른다 —
    `.bak` 을 한 번 심어 놓고 독립된 경우를 여럿 돌리는 시험에는 맞지 않는다."""
    block = re.search(r'\nif \[ -f "\$CFG" \]; then\n  cp -f "\$CFG" "\$CFG\.bak"\n.*?\nfi\n',
                      (HERE / "provision-config.sh").read_text(encoding="utf-8"), re.S).group(0)
    r = subprocess.run(["bash", "-c", block], env={"CFG": str(tmp_path / "gateway_config.json"), "PATH": os.environ["PATH"]},
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


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


# ── RA·TestScope 두 방식 — 비밀이 있으면 ste 방식 위임, 없으면 등록 토큰(HWAXPortal docs/sso-delegation) ──────────
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


def test_TestScope_백엔드는_MCP_주소만으로_생기고_비밀이_없으면_등록_토큰_방식이다(tmp_path):
    """기본은 사람이 포털에 등록한 TestScope 토큰(PORTAL_CONN) — 위임 항목이 없어야 게이트웨이가 그 길로 간다."""
    log: list = []
    out = _run_provision(tmp_path, {"TESTSCOPE_MCP_URL": "http://testscope.example:8022/mcp"}, log)
    # 서비스 Authorization 이 없다 — TestScope tools/list 는 토큰 없이 되고, 사람별 호출은 등록 토큰을 싣는다.
    assert out["testscope"] == {"url": "http://testscope.example:8022/mcp", "transport": "streamable_http"}
    assert "testscope" not in (out.get("heax_registry") or {}).get("per_user_sso", {})
    assert "포털에 등록한 TestScope 토큰으로" in log[0]


def test_TestScope_위임은_비밀과_주소로_생기고_백엔드_모양은_같다(tmp_path):
    """RA 와 같은 ste 방식(2026-10-03) — 다만 부서 헤더가 없어 strip_headers 가 없다. 비밀은 로그에 안 나온다."""
    base = _run_provision(tmp_path, {"TESTSCOPE_MCP_URL": "http://testscope.example:8022/mcp"})["testscope"]
    (tmp_path / "gateway_config.json").unlink()
    log: list = []
    out = _run_provision(tmp_path, {"TESTSCOPE_MCP_URL": "http://testscope.example:8022/mcp",
                                    "TESTSCOPE_SSO_SECRET": "ts-secret-xyz",
                                    "TESTSCOPE_SSO_URL": "http://testscope.example:8020/api/auth/sso"}, log)
    assert out["heax_registry"]["per_user_sso"]["testscope"] == {
        "sso_url": "http://testscope.example:8020/api/auth/sso", "secret": "ts-secret-xyz", "client": "gateway"}
    assert out["testscope"] == base, "백엔드는 방식과 무관하다 — 사람별 자격만 바뀐다"
    assert "testscope" not in out["rest"], "REST 다리는 이번 범위가 아니다"
    assert "TestScope 사람별 위임 — http://testscope.example:8020/api/auth/sso" in log[0]
    assert "위임 토큰으로" in log[0] and "ts-secret-xyz" not in log[0]


def test_TestScope_위임은_주소를_모르면_만들지_않고_그렇다고_말한다(tmp_path):
    """기본 호스트가 없다 — 지어내면 없는 서비스에 비밀을 보낸다. 생략은 로그에 남긴다(조용히 빠지지 않게)."""
    log: list = []
    out = _run_provision(tmp_path, {"TESTSCOPE_SSO_SECRET": "ts-secret-xyz",
                                    "TESTSCOPE_MCP_URL": "http://testscope.example:8022/mcp"}, log)
    assert "testscope" not in (out.get("heax_registry") or {}).get("per_user_sso", {})
    assert "TESTSCOPE_SSO_SECRET 은 있는데 주소가 없다" in log[0] and "ts-secret-xyz" not in log[0]
    assert out["testscope"]["url"] == "http://testscope.example:8022/mcp", "백엔드는 등록 토큰 방식으로 그대로 선다"


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


def test_TestScope_위임은_비밀이_없는_실행에도_지워지지_않는다(tmp_path):
    """RA 와 같은 규칙 — 비밀을 못 읽은 실행이 멀쩡하던 위임을 끄면 TestScope 호출이 조용히 등록 토큰 방식으로 돌아간다."""
    prev = {"sso_url": "http://testscope.example:8020/api/auth/sso", "secret": "old", "client": "gateway"}
    (tmp_path / "gateway_config.json.bak").write_text(json.dumps({
        "heax_registry": {"per_user_sso": {"testscope": prev}}}), encoding="utf-8")
    assert _run_provision(tmp_path, {})["heax_registry"]["per_user_sso"]["testscope"] == prev
    # 비밀만 새로 주면 주소는 직전 값을 지킨다
    got = _run_provision(tmp_path, {"TESTSCOPE_SSO_SECRET": "new"})["heax_registry"]["per_user_sso"]["testscope"]
    assert got == {**prev, "secret": "new"}


def test_update_all_이_끄라고_하면_그_위임만_지운다(tmp_path):
    """되돌리기 — infra/.env 에서 비밀을 비우면 update-all 이 PER_USER_SSO_OFF 로 넘긴다. 이어받기는 비밀을 못 읽은 실행용이라
    이 신호 없이는 위임이 남아 포털은 '토큰 등록' 인데 게이트웨이만 위임으로 부르고 거부했다."""
    ste = {"sso_url": "http://127.0.0.1:15810/api/auth/sso", "secret": "s2", "client": "gateway"}
    ra = {"sso_url": "http://ra.example:3000/api/auth/sso", "secret": "ra-old", "client": "gateway",
          "strip_headers": ["X-Workspace-Slug"]}
    ts = {"sso_url": "http://testscope.example:8020/api/auth/sso", "secret": "ts-old", "client": "gateway"}
    (tmp_path / "gateway_config.json.bak").write_text(json.dumps({
        "heax_registry": {"per_user_sso": {"ste": ste, "reportarchive": ra, "testscope": ts}}}), encoding="utf-8")
    log: list = []
    pu_ = _run_provision(tmp_path, {"PER_USER_SSO_OFF": "testscope"}, log)["heax_registry"]["per_user_sso"]
    assert pu_ == {"ste": ste, "reportarchive": ra}
    assert "TestScope 사람별 위임 끔" in log[0] and "ts-old" not in log[0]
    # 둘 다 끄면 둘 다 — 다른 서비스(ste)는 이 손잡이로 지워지지 않는다
    pu_ = _run_provision(tmp_path, {"PER_USER_SSO_OFF": "reportarchive testscope ste"})["heax_registry"]["per_user_sso"]
    assert pu_ == {"ste": ste}
    # 비밀이 같이 오면 끄지 않는다(켜는 쪽이 이긴다)
    pu_ = _run_provision(tmp_path, {"PER_USER_SSO_OFF": "reportarchive", "RA_SSO_SECRET": "ra-new"}
                         )["heax_registry"]["per_user_sso"]
    assert pu_["reportarchive"] == {**ra, "secret": "ra-new"}


def test_마지막_위임을_끄면_per_user_sso_가_비어_남지_않는다(tmp_path):
    (tmp_path / "gateway_config.json.bak").write_text(json.dumps({"heax_registry": {"per_user_sso": {
        "reportarchive": {"sso_url": "http://ra.example:3000/api/auth/sso", "secret": "x", "client": "gateway"}}}}),
        encoding="utf-8")
    out = _run_provision(tmp_path, {"PER_USER_SSO_OFF": "reportarchive"})
    assert "reportarchive" not in ((out.get("heax_registry") or {}).get("per_user_sso") or {})


def test_RA_위임과_TestScope_가_ste_hwax_risk_를_건드리지_않는다(tmp_path):
    env = {"STE_SSO_SECRET": "s2", "STE_SSO_URL": "http://127.0.0.1:15810/api/auth/sso",
           "HWAXRISK_SSO_SECRET": "hr", "HEAX_MCP_TOKEN": "heax-svc"}
    base = _run_provision(tmp_path, env)["heax_registry"]["per_user_sso"]
    (tmp_path / "gateway_config.json").unlink()
    out = _run_provision(tmp_path, {**env, "RA_SSO_SECRET": "ra-s", "TESTSCOPE_SSO_SECRET": "ts-s",
                                    "TESTSCOPE_SSO_URL": "http://testscope.example:8020/api/auth/sso",
                                    "TESTSCOPE_MCP_URL": "http://testscope.example:8022/mcp"})
    pu_ = out["heax_registry"]["per_user_sso"]
    assert pu_["ste"] == base["ste"] and pu_["hwax_risk"] == base["hwax_risk"]
    assert set(pu_) == {"ste", "hwax_risk", "reportarchive", "testscope"}
    assert out["rest"]["ste"]["per_user"] == "ste"
    assert "reportarchive" not in out["rest"] and "testscope" not in out["rest"], "REST 다리는 이번 범위가 아니다"


# ── 일반 앱 위임(PER_USER_SSO_APPS) — 여섯 번째 앱부터 provision-config.sh 를 고치지 않는다(change-request-8-10 #8) ──
def test_일반_앱_위임은_PER_USER_SSO_APPS_로_생긴다(tmp_path):
    """앱별 분기가 3개에서 5개로 늘었다 — 모양이 {sso_url, secret, client} 인 앱은 env 만으로 붙는다."""
    log: list = []
    out = _run_provision(tmp_path, {"PER_USER_SSO_APPS": "newapp:NEWAPP other-app:OTHER",
                                    "NEWAPP_SSO_SECRET": "na-secret-xyz",
                                    "NEWAPP_SSO_URL": "http://newapp.example:9000/api/auth/sso",
                                    "OTHER_SSO_SECRET": "ot-secret-xyz",
                                    "OTHER_SSO_URL": "http://other.example:9100/api/auth/sso"}, log)
    pu_ = out["heax_registry"]["per_user_sso"]
    assert pu_ == {
        "newapp": {"sso_url": "http://newapp.example:9000/api/auth/sso", "secret": "na-secret-xyz", "client": "gateway"},
        "other-app": {"sso_url": "http://other.example:9100/api/auth/sso", "secret": "ot-secret-xyz",
                      "client": "gateway"}}
    assert "newapp 사람별 위임 — http://newapp.example:9000/api/auth/sso" in log[0]
    assert "na-secret-xyz" not in log[0] and "ot-secret-xyz" not in log[0]
    # 목록에 없는 접두의 비밀은 아무것도 만들지 않는다 — 이름을 적어야 붙는다
    (tmp_path / "gateway_config.json").unlink()
    out = _run_provision(tmp_path, {"NEWAPP_SSO_SECRET": "na-secret-xyz",
                                    "NEWAPP_SSO_URL": "http://newapp.example:9000/api/auth/sso"})
    assert "newapp" not in ((out.get("heax_registry") or {}).get("per_user_sso") or {})


def test_일반_앱_위임은_주소를_모르면_만들지_않고_그렇다고_말한다(tmp_path):
    """TestScope 와 같다 — 기본 호스트가 없다. 지어내면 없는 서비스에 비밀을 보낸다."""
    log: list = []
    out = _run_provision(tmp_path, {"PER_USER_SSO_APPS": "newapp:NEWAPP", "NEWAPP_SSO_SECRET": "na-secret-xyz"}, log)
    assert "newapp" not in ((out.get("heax_registry") or {}).get("per_user_sso") or {})
    assert "NEWAPP_SSO_SECRET 은 있는데 주소가 없다" in log[0] and "na-secret-xyz" not in log[0]


def test_일반_앱_위임은_비밀이_없는_실행에도_지워지지_않는다(tmp_path):
    """RA·TestScope 와 같은 규칙 — env > 직전 config 주소, 비밀을 못 읽은 실행은 직전 항목을 이어받는다.
    손으로 붙여 둔 필드(strip_headers 등)는 비밀을 새로 줘도 남는다."""
    prev = {"sso_url": "http://newapp.example:9000/api/auth/sso", "secret": "old", "client": "gateway",
            "strip_headers": ["X-Team"]}
    (tmp_path / "gateway_config.json.bak").write_text(json.dumps({
        "heax_registry": {"per_user_sso": {"newapp": prev}}}), encoding="utf-8")
    # 목록도 비밀도 없는 실행
    assert _run_provision(tmp_path, {})["heax_registry"]["per_user_sso"]["newapp"] == prev
    # 목록만 있고 비밀이 없는 실행
    got = _run_provision(tmp_path, {"PER_USER_SSO_APPS": "newapp:NEWAPP"})["heax_registry"]["per_user_sso"]["newapp"]
    assert got == prev
    # 비밀만 새로 주면 주소는 직전 값을 지킨다
    got = _run_provision(tmp_path, {"PER_USER_SSO_APPS": "newapp:NEWAPP", "NEWAPP_SSO_SECRET": "new"}
                         )["heax_registry"]["per_user_sso"]["newapp"]
    assert got == {**prev, "secret": "new"}
    # env 주소가 직전 값을 이긴다
    got = _run_provision(tmp_path, {"PER_USER_SSO_APPS": "newapp:NEWAPP", "NEWAPP_SSO_SECRET": "new",
                                    "NEWAPP_SSO_URL": "http://newapp2.example:9000/api/auth/sso"}
                         )["heax_registry"]["per_user_sso"]["newapp"]
    assert got == {**prev, "secret": "new", "sso_url": "http://newapp2.example:9000/api/auth/sso"}


def test_일반_순회로_기존_다섯_앱의_위임을_덮지_못한다(tmp_path):
    """다섯 앱은 모양이 제각각이다(auth·token_header·strip_headers·client) — 순회가 덮으면 그 앱의 위임이
    다른 주소·비밀·모양으로 조용히 바뀐다. 건너뛰되 말한다."""
    ste = {"sso_url": "http://127.0.0.1:15810/api/auth/sso", "secret": "s2", "client": "gateway"}
    ra = {"sso_url": "http://ra.example:3000/api/auth/sso", "secret": "ra-old", "client": "gateway",
          "strip_headers": ["X-Workspace-Slug"]}
    ts = {"sso_url": "http://testscope.example:8020/api/auth/sso", "secret": "ts-old", "client": "gateway"}
    koorm = {"sso_url": "http://127.0.0.1:8700/api/v1/auth/sso", "secret": "k", "client": "deliberation"}
    risk = {"sso_url": "http://127.0.0.1:4180/apps/hwax_risk/api/auth/sso", "secret": "hr", "client": "deliberation",
            "auth": "heax", "token_header": "X-Heax-Sso-Assertion"}
    before = {"ste": ste, "reportarchive": ra, "testscope": ts, "kooremapper_mcp": koorm, "hwax_risk": risk}
    (tmp_path / "gateway_config.json.bak").write_text(json.dumps({
        "heax_registry": {"per_user_sso": before}}), encoding="utf-8")
    log: list = []
    out = _run_provision(tmp_path, {
        "PER_USER_SSO_APPS": "ste:EVIL reportarchive:EVIL testscope:EVIL kooremapper_mcp:EVIL hwax_risk:EVIL",
        "EVIL_SSO_SECRET": "evil-secret", "EVIL_SSO_URL": "http://evil.example/api/auth/sso"}, log)
    assert out["heax_registry"]["per_user_sso"] == before
    assert "evil" not in json.dumps(out)
    for k in before:
        assert f"PER_USER_SSO_APPS: {k} " in log[0], f"{k} 를 건너뛴 사실이 로그에 없다"
    # 이 손잡이로 기존 앱을 끌 수도 없다 — 끄는 표에 EVIL 이름으로 올라가지 않는다
    out = _run_provision(tmp_path, {"PER_USER_SSO_APPS": "ste:EVIL hwax_risk:EVIL",
                                    "PER_USER_SSO_OFF": "ste hwax_risk"})
    assert out["heax_registry"]["per_user_sso"] == before


def test_일반_앱_위임도_PER_USER_SSO_OFF_로_끈다(tmp_path):
    prev = {"sso_url": "http://newapp.example:9000/api/auth/sso", "secret": "old", "client": "gateway"}
    ste = {"sso_url": "http://127.0.0.1:15810/api/auth/sso", "secret": "s2", "client": "gateway"}
    (tmp_path / "gateway_config.json.bak").write_text(json.dumps({
        "heax_registry": {"per_user_sso": {"newapp": prev, "ste": ste}}}), encoding="utf-8")
    log: list = []
    pu_ = _run_provision(tmp_path, {"PER_USER_SSO_APPS": "newapp:NEWAPP", "PER_USER_SSO_OFF": "newapp"}, log
                         )["heax_registry"]["per_user_sso"]
    assert pu_ == {"ste": ste}
    assert "newapp 사람별 위임 끔(NEWAPP_SSO_SECRET 비어 있음)" in log[0] and "old" not in log[0]
    # 비밀이 같이 오면 끄지 않는다(켜는 쪽이 이긴다) — RA·TestScope 와 같다
    pu_ = _run_provision(tmp_path, {"PER_USER_SSO_APPS": "newapp:NEWAPP", "PER_USER_SSO_OFF": "newapp",
                                    "NEWAPP_SSO_SECRET": "new"})["heax_registry"]["per_user_sso"]
    assert pu_["newapp"] == {**prev, "secret": "new"}
    # 목록에 없는 이름은 끄지 않는다 — 어느 env 가 그 앱의 비밀인지 모르면 '비밀이 비었다' 를 판정할 수 없다
    pu_ = _run_provision(tmp_path, {"PER_USER_SSO_OFF": "newapp"})["heax_registry"]["per_user_sso"]
    assert pu_["newapp"] == prev


def test_PER_USER_SSO_APPS_의_못_읽은_쌍은_건너뛰되_말한다(tmp_path):
    """조용히 건너뛰면 '적었는데 왜 위임이 안 켜지나' 를 로그에서 찾을 수 없다. 멀쩡한 쌍은 그대로 붙는다."""
    log: list = []
    out = _run_provision(tmp_path, {
        "PER_USER_SSO_APPS": "nocolon :NOKEY noprefix: dash:NEW-APP digit:1APP two:A:B good:GOOD",
        "GOOD_SSO_SECRET": "g-secret-xyz", "GOOD_SSO_URL": "http://good.example/api/auth/sso",
        # 잘못된 접두가 우연히 env 이름과 맞아도 붙지 않는다
        "NEW-APP_SSO_SECRET": "x", "NEW-APP_SSO_URL": "http://x.example/sso",
        "A:B_SSO_SECRET": "x", "A:B_SSO_URL": "http://x.example/sso"}, log)
    assert set(out["heax_registry"]["per_user_sso"]) == {"good"}
    bad = [l for l in log[0].splitlines() if "PER_USER_SSO_APPS" in l and "읽지 못했다" in l]
    assert len(bad) == 6, log[0]
    for i, k in ((3, "noprefix"), (4, "dash"), (5, "digit"), (6, "two")):
        assert any(f"{i}번째 쌍('{k}:…')" in l for l in bad), f"{k} 쌍을 건너뛴 사실이 로그에 없다"
    assert any("2번째 쌍(':…')" in l for l in bad)
    # 콜론 없는 낱말과 콜론 뒤는 찍지 않는다 — 비밀을 잘못 적었을 수 있고 이 출력은 운영 로그에 남는다
    assert any("1번째 쌍(콜론 없음)" in l for l in bad)
    for leak in ("nocolon", "NOKEY", "NEW-APP", "1APP", "A:B", "g-secret-xyz"):
        assert leak not in log[0], f"{leak} 가 로그에 샜다"


# ── arp — 주소와 토큰이 둘 다 있을 때만 등재한다(change-request-8-10 #10 · D-5) ──────────────────────────
# ARP 는 2026-10-01 부터 인증을 켰다. 토큰 없이 등재하면 401 → /health 의 arp 가 영영 false(가짜 DOWN)였다.
ARP_BASE = "http://arp.example:3001"


def test_arp_는_주소와_토큰이_둘_다_있으면_토큰을_실어_등재한다(tmp_path):
    log: list = []
    out = _run_provision(tmp_path, {"ARP_BASE": ARP_BASE + "/", "ARP_TOKEN": "arp-secret-xyz"}, log)
    assert out["arp"] == {"url": ARP_BASE + "/mcp", "transport": "streamable_http",
                          "headers": {"Authorization": "Bearer arp-secret-xyz"}}
    assert "arp-secret-xyz" not in log[0], "토큰이 운영 로그에 남는다"


def test_arp_는_토큰이_없으면_등재하지_않고_켜는_법을_말한다(tmp_path):
    log: list = []
    out = _run_provision(tmp_path, {"ARP_BASE": ARP_BASE}, log)
    assert "arp" not in out
    line = [l for l in log[0].splitlines() if "arp 생략" in l]
    assert len(line) == 1 and "켜려면" in line[0] and "ARP_TOKEN=" in line[0] and "provision.env" in line[0], log[0]
    assert "ARP_BASE=" not in line[0], "주소를 env 로 받은 실행이다 — 주소는 사라지지 않으니 적으라고 하지 않는다"
    # 주소도 토큰도 없는 박스(dev)는 예전처럼 조용하다 — 쓰지 않는 박스에 '생략' 을 매번 찍지 않는다
    (tmp_path / "gateway_config.json").unlink()
    log = []
    out = _run_provision(tmp_path, {}, log)
    assert "arp" not in out and "arp 생략" not in log[0]
    # 토큰만 있고 주소를 모르면 지어내지 않는다
    (tmp_path / "gateway_config.json").unlink()
    assert "arp" not in _run_provision(tmp_path, {"ARP_TOKEN": "arp-secret-xyz"})


def test_arp_무토큰_항목이_직전_config_에_남아_있어도_이어받지_않는다(tmp_path):
    """cae00 의 모양 — 옛 프로비저너가 토큰 없이 등재해 둔 항목이 라이브 config 와 .bak 에 있다.
    주소는 이어받되 토큰이 없으니 빠져야 한다(arp 는 프로비저너가 만드는 키라 '보존' 으로 되살아나지도 않는다)."""
    old = {"arp": {"url": ARP_BASE + "/mcp", "transport": "streamable_http"},
           "knox-bridge": {"url": "http://127.0.0.1:9120/mcp", "transport": "streamable_http"}}
    (tmp_path / "gateway_config.json").write_text(json.dumps(old), encoding="utf-8")
    (tmp_path / "gateway_config.json.bak").write_text(json.dumps(old), encoding="utf-8")
    log: list = []
    out = _run_provision(tmp_path, {}, log)
    assert "arp" not in out
    assert "knox-bridge" in out, "손으로 붙인 백엔드는 그대로 보존한다"
    assert any("arp 생략" in l and "ARP_TOKEN=" in l for l in log[0].splitlines()), log[0]
    # 무토큰 항목이 **아직 config 에 있는** 실행에 토큰을 주면 그 주소로 선다(빠진 다음 실행은 아래 시험이 본다)
    (tmp_path / "gateway_config.json").write_text(json.dumps(old), encoding="utf-8")
    out = _run_provision(tmp_path, {"ARP_TOKEN": "arp-secret-xyz"})
    assert out["arp"] == {"url": ARP_BASE + "/mcp", "transport": "streamable_http",
                          "headers": {"Authorization": "Bearer arp-secret-xyz"}}


def test_arp_가_토큰이_없어_빠질_때_주소도_함께_사라진다고_말하고_다음_실행도_조용하지_않다(tmp_path):
    """주소가 게이트웨이 config 에만 있던 박스(이 실행이 ARP_BASE 를 받지 못했다) — 항목이 빠지면 주소도 함께 사라진다.
    안내는 'ARP_TOKEN 을 적어라' 뿐이었고, 그대로 따른 다음 실행은 주소를 몰라 arp 를 만들지 않으면서 **아무 말도 없었다**.
    `--force` 는 블록 앞에서 라이브 config 로 `.bak` 을 덮으므로 빠진 다음 실행에는 이어받을 주소가 없다."""
    (tmp_path / "gateway_config.json").write_text(json.dumps({
        "arp": {"url": ARP_BASE + "/mcp", "transport": "streamable_http"}}), encoding="utf-8")
    _force_backup(tmp_path)
    log: list = []
    assert "arp" not in _run_provision(tmp_path, {}, log)
    drop = [l for l in log[0].splitlines() if "arp 생략" in l]
    assert len(drop) == 1 and "ARP_TOKEN=" in drop[0] and f"ARP_BASE={ARP_BASE}" in drop[0], log[0]
    # 안내의 절반(토큰)만 따른 다음 실행 — 주소를 지어내지 않고, 왜 서지 않는지와 켜는 법을 말한다
    _force_backup(tmp_path)
    log = []
    assert "arp" not in _run_provision(tmp_path, {"ARP_TOKEN": "arp-secret-xyz"}, log)
    drop = [l for l in log[0].splitlines() if "arp 생략" in l]
    assert len(drop) == 1 and "켜려면" in drop[0] and "ARP_BASE=" in drop[0] and "ARP_HOST" in drop[0], log[0]
    assert ARP_BASE not in log[0], "모르는 주소를 지어내 찍으면 안 된다"
    assert "arp-secret-xyz" not in log[0], "토큰이 운영 로그에 남는다"
    # 둘 다 주면 선다
    _force_backup(tmp_path)
    out = _run_provision(tmp_path, {"ARP_TOKEN": "arp-secret-xyz", "ARP_BASE": ARP_BASE})
    assert out["arp"] == {"url": ARP_BASE + "/mcp", "transport": "streamable_http",
                          "headers": {"Authorization": "Bearer arp-secret-xyz"}}


def test_arp_토큰은_env_가_없는_실행에_직전_config_에서_이어받는다(tmp_path):
    """다른 토큰(RAT·ODB)과 같다 — env 를 못 읽은 실행(손으로 돌린 --force)이 돌고 있던 백엔드를 지우면 안 된다."""
    (tmp_path / "gateway_config.json.bak").write_text(json.dumps({
        "arp": {"url": ARP_BASE + "/mcp", "transport": "streamable_http",
                "headers": {"Authorization": "Bearer arp-old-token"}}}), encoding="utf-8")
    log: list = []
    out = _run_provision(tmp_path, {}, log)
    assert out["arp"] == {"url": ARP_BASE + "/mcp", "transport": "streamable_http",
                          "headers": {"Authorization": "Bearer arp-old-token"}}
    assert "ARP_TOKEN: env 없음" in log[0] and "arp-old-token" not in log[0]
    assert "arp 생략" not in log[0]


def test_arp_env_토큰과_주소가_직전_config_를_이긴다(tmp_path):
    """토큰을 바꿔 적었는데 .bak 의 옛 토큰이 되살아나면 재발급이 반영되지 않는다(odb-hub 가 그랬다)."""
    (tmp_path / "gateway_config.json.bak").write_text(json.dumps({
        "arp": {"url": ARP_BASE + "/mcp", "transport": "streamable_http",
                "headers": {"Authorization": "Bearer arp-old-token"}}}), encoding="utf-8")
    out = _run_provision(tmp_path, {"ARP_TOKEN": "arp-new-token"})
    assert out["arp"]["headers"] == {"Authorization": "Bearer arp-new-token"}
    assert out["arp"]["url"] == ARP_BASE + "/mcp", "주소는 직전 값을 지킨다"
    out = _run_provision(tmp_path, {"ARP_TOKEN": "arp-new-token", "ARP_BASE": "http://arp2.example:3001"})
    assert out["arp"]["url"] == "http://arp2.example:3001/mcp"
    assert "arp-old-token" not in json.dumps(out)


# ── smart-twin-mcp — 주소가 설정된 박스에서만 등재한다(change-request-8-10 #11 · D-4) ───────────────────────
# 예전엔 기본값(같은 박스 :5013)으로 무조건 등재했다 — 띄운 적 없는 cae00 에서 가짜 DOWN 이 영구히 남았다.
# 없어진 서비스는 아니다(dev 는 그 주소에서 듣고 도구 18종을 낸다) — 그래서 지우지 않고 조건부로 바꿨다.
ST_DEFAULT = "http://127.0.0.1:5013/mcp"


def _st_skip(log: list) -> list:
    return [l for l in log[0].splitlines() if "smart-twin-mcp 생략" in l]


def test_smart_twin_mcp_는_주소를_적은_박스에서만_등재한다(tmp_path):
    log: list = []
    out = _run_provision(tmp_path, {}, log)
    assert "smart-twin-mcp" not in out, "기본값으로 지어내면 서비스가 없는 박스에 가짜 DOWN 이 선다"
    skip = _st_skip(log)
    assert len(skip) == 1 and "켜려면" in skip[0] and "provision.env" in skip[0] and "SMARTTWIN_MCP_URL=" in skip[0], log[0]
    # dev 의 모양 — 같은 박스 기본 주소에서 듣고 있고, 그 주소를 env 로 적었다
    (tmp_path / "gateway_config.json").unlink()
    log = []
    out = _run_provision(tmp_path, {"SMARTTWIN_MCP_URL": ST_DEFAULT}, log)
    assert out["smart-twin-mcp"] == {"url": ST_DEFAULT, "transport": "streamable_http"}
    assert _st_skip(log) == []


def test_smart_twin_mcp_직전_config_의_옛_기본값은_이어받지_않는다(tmp_path):
    """cae00 의 모양 — 예전 프로비저너가 박은 기본 주소가 라이브 config 와 .bak 에 남아 있다. 이어받으면 반영 뒤에도
    가짜 DOWN 이 그대로다. 관리 키라 '보존' 으로 되살아나지도 않아야 한다 — 빠진 사실은 켜는 법과 함께 말한다."""
    old = {"smart-twin-mcp": {"url": ST_DEFAULT, "transport": "streamable_http"},
           "smart-twin-cluster": {"url": "http://127.0.0.1:5012/mcp", "transport": "streamable_http"}}
    (tmp_path / "gateway_config.json").write_text(json.dumps(old), encoding="utf-8")
    (tmp_path / "gateway_config.json.bak").write_text(json.dumps(old), encoding="utf-8")
    log: list = []
    out = _run_provision(tmp_path, {}, log)
    assert "smart-twin-mcp" not in out
    assert out["smart-twin-cluster"] == old["smart-twin-cluster"], "손으로 붙인 별개 서버는 그대로 보존한다"
    skip = _st_skip(log)
    assert len(skip) == 1 and "옛 기본값" in skip[0] and "켜려면" in skip[0] and "SMARTTWIN_MCP_URL=" in skip[0], log[0]
    # 그 박스가 실제로 쓰는 곳이면(dev) env 한 줄로 그 주소 그대로 선다
    out = _run_provision(tmp_path, {"SMARTTWIN_MCP_URL": ST_DEFAULT})
    assert out["smart-twin-mcp"] == {"url": ST_DEFAULT, "transport": "streamable_http"}


def test_smart_twin_mcp_사람이_옮겨_적은_주소는_이어받는다(tmp_path):
    """기본값이 아닌 주소는 '설정' 이다 — env 가 없는 실행(손으로 돌린 --force)이 그것을 지우면 도구가 통째로 사라진다."""
    moved = "http://smarttwin.example:5013/mcp"
    (tmp_path / "gateway_config.json.bak").write_text(json.dumps({
        "smart-twin-mcp": {"url": moved, "transport": "streamable_http"}}), encoding="utf-8")
    log: list = []
    out = _run_provision(tmp_path, {}, log)
    assert out["smart-twin-mcp"] == {"url": moved, "transport": "streamable_http"}
    assert _st_skip(log) == []
    # env 가 직전 값을 이긴다
    out = _run_provision(tmp_path, {"SMARTTWIN_MCP_URL": "http://smarttwin2.example:5013/mcp"})
    assert out["smart-twin-mcp"]["url"] == "http://smarttwin2.example:5013/mcp"
