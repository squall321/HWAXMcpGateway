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
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

# hop-by-hop headers not forwarded verbatim (+ host/authorization which we rewrite)
_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
        "trailers", "transfer-encoding", "upgrade", "host", "content-length", "authorization"}



log = logging.getLogger("hwax-mcp-gateway")

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
    def __init__(self, rest_conf: dict, portal_conf: dict, audit):
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
        allowed = conf.get("methods") or (["GET", "HEAD"] if conf.get("inject") else None)
        if allowed is not None and request.method.upper() not in {m.upper() for m in allowed}:
            self.audit(f"{request.method} /{path}", site, False, "method not allowed", 0,
                       caller=claims.get("sub"))
            return JSONResponse(
                {"error": "method not allowed for this site",
                 "detail": f"{site} 는 {'/'.join(allowed)} 만 허용한다. 쓰기가 필요하면 "
                           f"게이트웨이 설정의 rest.{site}.methods 에 명시하라."},
                status_code=405)

        url = conf["base"].rstrip("/") + "/" + path.lstrip("/")
        headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP}
        inj = conf.get("inject")                           # optional (a site may allow anonymous)
        if inj:
            headers[inj["header"]] = inj["value"]          # the site's OWN service credential
        headers["x-forwarded-user"] = claims.get("email", "")  # identity hint (site may ignore)
        body = await request.body()
        try:
            up = await self._client.request(
                request.method, url, params=dict(request.query_params),
                content=body, headers=headers,
            )
        except Exception as e:  # noqa: BLE001
            self.audit(f"{request.method} /{path}", site, False, f"upstream: {e!r}",
                       round((time.monotonic() - t0) * 1000), caller=claims.get("sub"))
            return JSONResponse({"error": "upstream unreachable", "detail": str(e)}, status_code=502)
        self.audit(f"{request.method} /{path}", site, up.status_code < 400, None,
                   round((time.monotonic() - t0) * 1000), caller=claims.get("sub"))
        out_headers = {k: v for k, v in up.headers.items() if k.lower() not in _HOP}
        return Response(content=up.content, status_code=up.status_code, headers=out_headers)

    def routes(self) -> list[Route]:
        return [Route("/api/{site}/{path:path}", self.handle,
                      methods=["GET", "POST", "PUT", "PATCH", "DELETE"])]
