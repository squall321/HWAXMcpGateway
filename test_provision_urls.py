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
