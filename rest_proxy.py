# 포털 PAT(RS256, scope=api)를 JWKS로 검증하고 하위 사이트 REST API로 프록시하는 게이트웨이 확장
"""REST proxy surface for the HWAX gateway.

Mirrors the MCP fan-out (one caller token → per-backend native token) for plain REST:
a caller presents ONE portal-issued PAT (`Authorization: Bearer <jwt>`); the gateway
verifies it against the portal JWKS (RS256, scope="api", aud contains the target site,
not in the published revoked-jti denylist), then forwards `/api/<site>/<path>` to that
site's REST base injecting the site's OWN service credential. Sub-sites are never changed.
"""

import logging
import time

import httpx
import jwt
from jwt import PyJWKClient
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

# hop-by-hop headers not forwarded verbatim (+ host/authorization which we rewrite)
_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
        "trailers", "transfer-encoding", "upgrade", "host", "content-length", "authorization"}



log = logging.getLogger("hwax-mcp-gateway")


def credential_mode(conf: dict) -> str:
    """이 사이트를 **누구 명의로** 부르는가. `per_user` | `inject` | `none`.

    **정본은 여기 하나다** — REST 프록시와 게이트웨이의 MCP 다리가 같은 답을 봐야 한다.
    `per_user` 가 `inject` 를 이긴다. 사용자 위임이 가능한 사이트를 서비스 자격으로 부르면
    잡 소유자가 한 명으로 뭉치고 감사 원장에는 그 한 명이 전부 한 것으로 남는다.
    """
    if conf.get("per_user"):
        return "per_user"
    return "inject" if conf.get("inject") else "none"


def allowed_methods(conf: dict) -> list[str] | None:
    """이 사이트에서 허용되는 HTTP 메서드. None = 제한 없음.

    **정본은 여기 하나다.** 게이트웨이의 MCP 다리(`gateway._rest_call`)도 이것을 부른다 —
    같은 규칙을 두 군데 적어 두면 MCP 로는 통하고 REST 로는 막히는(또는 그 반대) 두 얼굴이 된다.
    """
    if conf.get("methods"):
        return list(conf["methods"])        # 사이트가 명시했으면 그대로
    # **쓰기의 기본은 닫힘이다.** 여는 길은 둘뿐 —
    #   · `per_user` : 호출자 본인의 토큰으로 가므로 권한 상승이 없다. 그 사이트가 자기
    #     사용자에게 허용하는 만큼만 되고, 누가 했는지도 상류 원장에 남는다.
    #   · `methods`  : 사람이 그 사이트에 대해 명시적으로 열었다.
    #
    # ⚠ `inject` 는 그 사이트의 **마스터 키**라 당연히 묶이지만, 자격이 **아무것도 없는**
    # 사이트(`none`)도 똑같이 묶는다. 예전엔 "주입이 없으니 권한 상승도 없다" 고 보고 열어
    # 뒀는데, 그 전제가 틀렸다 — 상류가 무인증 200 이면(ai-data-hub 실측) 이 프록시가
    # **유일한 관문**이라 '권한 상승이 없다' 가 아니라 '아무 통제도 없다' 였다. 게다가 이제
    # `rest_call` 로 LLM 이 부를 수 있어서, 전문가챗 허가만 있는 사람(feat:expert-chat 이
    # plat:aidatahub 를 함의한다)이 변경 op 를 그대로 부를 수 있었다.
    return None if credential_mode(conf) == "per_user" else ["GET", "HEAD"]

class PortalPatVerifier:
    """포털 PAT 검증(JWKS RS256, scope=api, aud, 폐기목록 60s 캐시). /mcp 게이트와 REST 프록시가 공유.
    verify(token, audience) → 성공 시 claims dict, 실패 시 None(모든 오류를 None 으로 흡수)."""

    def __init__(self, portal_conf: dict):
        jwks_url = portal_conf.get("jwks_url")
        self.jwks = PyJWKClient(jwks_url, cache_keys=True) if jwks_url else None
        self._revoked_url = portal_conf.get("revoked_url")
        self._revoked: set[str] = set()
        self._revoked_at = 0.0
        self._client = httpx.AsyncClient(timeout=10.0)

    async def _revoked_set(self) -> set[str]:
        now = time.monotonic()
        if not self._revoked_url or (self._revoked_at and now - self._revoked_at < 60):
            return self._revoked
        try:
            r = await self._client.get(self._revoked_url, timeout=5)
            r.raise_for_status()
            body = r.json()
            # ⚠ 'revoked' 키가 없으면 빈 목록으로 받아들이면 안 된다. 포털 재기동 중
            # 앞단이 200 으로 {"detail": …} 같은 것을 돌려주면 폐기가 통째로 꺼지고,
            # _revoked_at 도장까지 찍혀 60초 동안 재조회조차 안 한다. 토큰이 무기한으로
            # 발급될 수 있는 지금 이것이 마지막 방어선이라 조용히 비우면 안 된다.
            if not isinstance(body, dict) or "revoked" not in body:
                raise ValueError(f"revoked 목록 형식이 아니다: {str(body)[:120]}")
            self._revoked = set(body["revoked"])
            self._revoked_at = now
        except Exception as exc:  # noqa: BLE001 — 직전 목록 유지(fail-closed 는 더 위험)
            # 조용히 넘기지 않는다. 이 목록은 무기한 토큰의 유일한 차단 수단이라,
            # 갱신 실패가 이어지면 폐기가 반영 안 된 채 계속 도는 것이므로 보여야 한다.
            log.warning("폐기목록 갱신 실패 — 직전 목록(%d건) 유지: %r", len(self._revoked), exc)
        return self._revoked

    async def verify(self, token: str, audience: str) -> dict | None:
        if not self.jwks or not token:
            return None
        try:
            key = self.jwks.get_signing_key_from_jwt(token).key
            claims = jwt.decode(token, key, algorithms=["RS256"], audience=audience,
                                options={"require": ["exp", "aud", "sub", "jti"], "leeway": 30})
            if claims.get("scope") != "api":
                return None
            if claims["jti"] in await self._revoked_set():
                return None
            return claims
        except Exception:  # noqa: BLE001 — any failure = not a valid PAT
            return None


class RestProxy:
    def __init__(self, rest_conf: dict, portal_conf: dict, audit, allow=None, mint=None):
        # ⚠ `allow(site, groups)` 는 **MCP 경로와 같은 규칙**이다(`gateway._backend_allowed`).
        # 없이 두면 이 프록시는 자격 체계를 통째로 우회한다 — 아래 handle() 참조.
        self.allow = allow
        # `mint(app_id, email) -> token` — per_user 사이트를 **호출자 본인 명의로** 부를 때 쓴다.
        # 게이트웨이가 쥔 기계(`_user_pat`)를 주입받는다. 없으면 per_user 사이트는 막는다.
        self.mint = mint
        self.rest = rest_conf or {}
        self.audience_ok = set(portal_conf.get("audience_ok", list(self.rest)))
        self.audit = audit
        jwks_url = portal_conf.get("jwks_url")
        self.jwks = PyJWKClient(jwks_url, cache_keys=True) if jwks_url else None
        self._revoked_url = portal_conf.get("revoked_url")
        self._revoked: set[str] = set()
        self._revoked_at = 0.0
        self._client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)

    async def _revoked_set(self) -> set[str]:
        """Portal-published revoked-jti denylist, cached 60s. Fail-open (keep last-known)."""
        now = time.monotonic()
        if not self._revoked_url or (self._revoked_at and now - self._revoked_at < 60):
            return self._revoked
        try:
            r = await self._client.get(self._revoked_url, timeout=5)
            r.raise_for_status()
            body = r.json()
            # ⚠ 'revoked' 키가 없으면 빈 목록으로 받아들이면 안 된다. 포털 재기동 중
            # 앞단이 200 으로 {"detail": …} 같은 것을 돌려주면 폐기가 통째로 꺼지고,
            # _revoked_at 도장까지 찍혀 60초 동안 재조회조차 안 한다. 토큰이 무기한으로
            # 발급될 수 있는 지금 이것이 마지막 방어선이라 조용히 비우면 안 된다.
            if not isinstance(body, dict) or "revoked" not in body:
                raise ValueError(f"revoked 목록 형식이 아니다: {str(body)[:120]}")
            self._revoked = set(body["revoked"])
            self._revoked_at = now
        except Exception as exc:  # noqa: BLE001 — 직전 목록 유지(fail-closed 는 더 위험)
            # 조용히 넘기지 않는다. 이 목록은 무기한 토큰의 유일한 차단 수단이라,
            # 갱신 실패가 이어지면 폐기가 반영 안 된 채 계속 도는 것이므로 보여야 한다.
            log.warning("폐기목록 갱신 실패 — 직전 목록(%d건) 유지: %r", len(self._revoked), exc)
        return self._revoked

    def _verify(self, token: str, site: str) -> dict:
        if not self.jwks:
            raise ValueError("portal jwks not configured")
        key = self.jwks.get_signing_key_from_jwt(token).key  # cached by kid after first fetch
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=site,
                            options={"require": ["exp", "aud", "sub", "jti"], "leeway": 30})
        if claims.get("scope") != "api":
            raise ValueError("token is not scope=api")
        return claims

    async def handle(self, request: Request):
        site = request.path_params["site"]
        path = request.path_params["path"]
        conf = self.rest.get(site)
        t0 = time.monotonic()
        if not conf or site not in self.audience_ok:
            return JSONResponse({"error": f"unknown site: {site}"}, status_code=404)
        auth = request.headers.get("authorization", "")
        token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
        if not token:
            return JSONResponse({"error": "missing bearer PAT"}, status_code=401)
        try:
            claims = self._verify(token, site)
            if claims["jti"] in await self._revoked_set():
                raise ValueError("token revoked")
        except Exception as e:  # noqa: BLE001
            self.audit(f"{request.method} /{path}", site, False, f"pat: {e!r}", 0)
            return JSONResponse({"error": "invalid PAT", "detail": str(e)}, status_code=401)

        # ⚠ 서비스 자격증명을 주입하는 사이트는 기본적으로 읽기만 허용한다.
        # 아래 inject 는 "그 사이트의 마스터 키" 다. PAT 검증은 서명·aud·scope=="api"·폐기목록
        # 까지고 groups 도 PAT 의 scopes 도 경로도 보지 않으므로, 포털에 로그인한 최저 권한
        # 사용자가 aud 만 맞는 PAT(ttl_days=0 이면 100년)를 스스로 찍어 공개 오리진
        # /mcp-gw/api/<site>/... 로 그 마스터 키 권한을 그대로 쓸 수 있었다. 아무도 실수하지
        # 않아도 그렇게 된다 — 허용 audience 목록이 사용자·그룹과 무관한 전역 설정이기 때문이다.
        # 쓰기를 열려면 사이트 설정에 methods 를 명시하게 한다(감사로그 기준 이 프록시는
        # 아직 호출 0건이라, 닫아도 깨지는 사용처가 없다).
        # inject 가 없는 사이트는 권한 상승이 없으므로 종전대로 둔다.
        allowed = allowed_methods(conf)
        if allowed is not None and request.method.upper() not in {m.upper() for m in allowed}:
            self.audit(f"{request.method} /{path}", site, False, "method not allowed", 0,
                       caller=claims.get("sub"))
            return JSONResponse(
                {"error": "method not allowed for this site",
                 "detail": f"{site} 는 {'/'.join(allowed)} 만 허용한다. 쓰기가 필요하면 "
                           f"게이트웨이 설정의 rest.{site}.methods 에 명시하라."},
                status_code=405)

        # ⚠ **자격을 MCP 와 같은 규칙으로 본다.** 여태 PAT 서명·aud·scope·폐기목록까지만
        # 보고 **groups 를 안 봤다** — 그래서 자격 0개인 사람이 MCP 로는 `forbidden:` 을
        # 받는 백엔드를 이 경로로는 200 으로 읽었다(실측). `inject` 없는 사이트는 권한
        # 상승이 없다고 봤는데, 상류 AIDataHub 가 **인증 없이 200** 이라 이 프록시가
        # 유일한 관문이었다(6차 감사). 규칙은 게이트웨이에서 주입받는다 — 여기서 다시
        # 만들면 두 경로가 어긋난다.
        if self.allow is not None:
            groups = [str(g) for g in (claims.get("groups") or [])]
            if not await self.allow(site, groups, str(claims.get("email") or "")):
                self.audit(f"{request.method} /{path}", site, False, "forbidden", 0,
                           caller=claims.get("sub"))
                return JSONResponse(
                    {"error": f"forbidden: {site}",
                     "detail": "이 백엔드를 쓸 권한이 없습니다 — 포털 '내 권한' 에서 요청하세요."},
                    status_code=403)

        url = conf["base"].rstrip("/") + "/" + path.lstrip("/")
        headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP}
        email = str(claims.get("email") or "").strip().lower()
        mode = credential_mode(conf)                       # per_user | inject | none
        if mode == "per_user":
            # 서비스 자격으로 조용히 강등하지 않는다 — 그러면 남의 시야로 200 을 돌려주고,
            # 실패가 정상 응답과 구분되지 않는다(MCP 경로와 같은 자세).
            if not self.mint:
                return JSONResponse({"error": "per-user credential minting not wired",
                                     "detail": f"{site} 는 본인 명의로만 부른다."}, status_code=503)
            if not email:
                return JSONResponse({"error": "PAT 에 이메일이 없다",
                                     "detail": f"{site} 는 본인 명의로만 부른다."}, status_code=401)
            try:
                tok, tok_header = await self.mint(str(conf["per_user"]), email)
            except Exception as e:  # noqa: BLE001
                self.audit(f"{request.method} /{path}", site, False, f"per-user: {e!r}", 0,
                           caller=claims.get("sub"))
                return JSONResponse({"error": f"{email} 자격증명을 받지 못했다",
                                     "detail": str(e)[:300]}, status_code=502)
            if tok_header:
                headers[tok_header] = tok
            else:
                headers["Authorization"] = f"Bearer {tok}"
        elif mode == "inject":
            headers[conf["inject"]["header"]] = conf["inject"]["value"]  # the site's OWN service credential
        headers["x-forwarded-user"] = email                # identity hint (site may ignore)
        # ⚠ **요청도 응답도 버퍼링하지 않는다.** 종전엔 `await request.body()` 가 업로드 전량을 메모리에 받았고
        #   응답도 `up.content` 로 통째였다 — 2GB k파일이 이 경로로 못 가던 확정 원인이고(2026-09-24 적대 검토),
        #   result.zip 을 받으면 게이트웨이가 그만큼 부풀었다. 요청은 request.stream() 을 그대로 흘리고,
        #   응답은 StreamingResponse 로 흘린다. 스트림 자체는 이 프록시가 만들지 않으므로 상한을 두지 않는다 —
        #   받는 쪽(브라우저·curl)이 바이트를 감당한다. 모델에 보이는 rest_call 만 상한이 있다.
        async def _body():
            async for chunk in request.stream():
                yield chunk
        try:
            req = self._client.build_request(request.method, url, params=dict(request.query_params),
                                             content=_body(), headers=headers)
            up = await self._client.send(req, stream=True)
        except Exception as e:  # noqa: BLE001
            self.audit(f"{request.method} /{path}", site, False, f"upstream: {e!r}",
                       round((time.monotonic() - t0) * 1000), caller=claims.get("sub"))
            return JSONResponse({"error": "upstream unreachable", "detail": str(e)}, status_code=502)
        self.audit(f"{request.method} /{path}", site, up.status_code < 400, None,
                   round((time.monotonic() - t0) * 1000), caller=claims.get("sub"))
        out_headers = {k: v for k, v in up.headers.items() if k.lower() not in _HOP}

        async def _out():
            try:
                async for chunk in up.aiter_raw():
                    yield chunk
            finally:
                await up.aclose()
        return StreamingResponse(_out(), status_code=up.status_code, headers=out_headers)

    def routes(self) -> list[Route]:
        return [Route("/api/{site}/{path:path}", self.handle,
                      methods=["GET", "POST", "PUT", "PATCH", "DELETE"])]
