# 게이트웨이 백엔드 주소를 **형제 서비스가 선언한 포트**에서 정한다 — provision-config.sh 와 update-all 이 함께 쓴다
"""백엔드 MCP 주소 결정.

⚠ 전에는 `env > 직전 config(.bak) > 하드코딩 기본값` 이었다. 처음 한 번 기본값이 박히면 이후
`--force` 재생성이 `.bak` 에서 **그 틀린 값을 영원히 물려받았다.** 실제로 cae00 에서 SignalForge
MCP 는 8008 인데(SignalForge/.env `MCP_PORT`) 게이트웨이는 8013 을 들고 있었고, `/health` 가
`signalforge: false` 로 09-18 부터 떠 있었다. dev 는 우연히 `.env` 가 8013 이라 멀쩡했다 —
**포트는 박스마다 다르고 정본은 그 서비스의 `.env` 다.**

순서(위가 이긴다):
  1. env(사람이 명시한 주소)
  2. 직전 config 가 **원격 호스트**를 가리키면 그대로 — 사람이 서비스를 다른 서버로 옮긴 것이다
  3. 형제 리포 `.env` 가 선언한 포트 → `http://127.0.0.1:<port><path>`
  4. 직전 config(로컬 주소)
  5. 기본값
"""
from __future__ import annotations

import json
import os
import sys
from urllib.parse import urlparse

# 자기 `.env` 에 MCP 포트를 선언하는 형제 서비스. 선언이 있는 곳만 넣는다(없는 곳을 짐작하지 않는다).
# 키: 게이트웨이 백엔드 키 → (형제 리포 이름, 포트 변수, MCP 경로, 오버라이드 env 이름)
SIBLING_PORTS = {
    "signalforge": ("SignalForge", "MCP_PORT", "/mcp", "SF_MCP_URL"),
}

_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


def dotenv_get(path: str, key: str) -> str | None:
    """`.env` 의 한 값. 파일이 없거나 키가 없으면 None — 추측하지 않는다."""
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#") or "=" not in s:
                    continue
                k, v = s.split("=", 1)
                if k.strip().removeprefix("export ").strip() != key:
                    continue
                v = v.strip()
                if v[:1] in ('"', "'") and v[-1:] == v[:1]:
                    v = v[1:-1]
                else:
                    v = v.split(" #", 1)[0].strip()
                return v or None
    except OSError:
        return None
    return None


def is_local(url: str | None) -> bool:
    return bool(url) and (urlparse(url).hostname or "").lower() in _LOCAL_HOSTS


def resolve(key: str, *, env_url: str | None, prev_url: str | None, sibling_root: str | None,
            default: str) -> tuple[str, str]:
    """(주소, 근거). 근거는 사람이 읽는 한 줄 — 프로비저닝 출력에 그대로 찍는다."""
    if env_url:
        return env_url, "env"
    if prev_url and not is_local(prev_url):
        return prev_url, "직전 config(원격 — 사람이 옮긴 주소)"
    spec = SIBLING_PORTS.get(key)
    if spec and sibling_root:
        repo, var, path, _ = spec
        env_file = os.path.join(sibling_root, repo, ".env")
        port = dotenv_get(env_file, var)
        if port and port.isdigit():
            return f"http://127.0.0.1:{port}{path}", f"{repo}/.env {var}={port}"
    if prev_url:
        return prev_url, "직전 config"
    return default, "기본값"


def drift(config_path: str, sibling_root: str) -> list[tuple[str, str, str]]:
    """config 가 든 로컬 주소가 형제 서비스의 선언과 다른 백엔드 — (키, 지금, 선언).

    update-all 이 이걸로 재프로비저닝 여부를 정한다. 원격 주소·env 오버라이드는 사람이 정한
    것이라 드리프트로 보지 않는다(여기서는 env 를 모르므로 원격만 거른다).
    """
    try:
        with open(config_path, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return []
    out = []
    for key, (repo, var, path, _) in SIBLING_PORTS.items():
        cur = (cfg.get(key) or {}).get("url")
        if not cur or not is_local(cur):
            continue
        port = dotenv_get(os.path.join(sibling_root, repo, ".env"), var)
        if not (port and port.isdigit()):
            continue
        want = f"http://127.0.0.1:{port}{path}"
        if cur.rstrip("/") != want.rstrip("/"):
            out.append((key, cur, want))
    return out


if __name__ == "__main__":
    # update-all 용: `python3 provision_urls.py drift <gateway_config.json> <형제 리포 루트>`
    # 한 줄에 하나 `<키>\t<지금>\t<선언>` — 없으면 아무것도 안 찍는다. 주소만 찍고 토큰은 안 읽는다.
    if len(sys.argv) == 4 and sys.argv[1] == "drift":
        for row in drift(sys.argv[2], sys.argv[3]):
            print("\t".join(row))
        raise SystemExit(0)
    print("usage: provision_urls.py drift <gateway_config.json> <sibling_root>", file=sys.stderr)
    raise SystemExit(2)
