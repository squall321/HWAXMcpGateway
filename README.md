# HWAX MCP Gateway

HWAX 페더레이션의 **중앙 MCP 게이트웨이**. 채팅 에이전트(HWAXAgentServer)가 서버별 MCP를 직접 들고 fan-out하던 것을, 이 게이트웨이 1개 엔드포인트로 모았다. 게이트웨이가 3개 백엔드 MCP를 집계해 도구를 재노출하고, 각 백엔드로 호출을 포워딩할 때 **해당 서버의 토큰을 중앙에서 주입**한다(토큰이 에이전트 설정에서 게이트웨이로 이동).

## 구조
- `gateway.py` — FastMCP 저수준 Server(`fm._mcp_server`)에 `@list_tools`/`@call_tool(validate_input=False)`을 달아 집계 재노출. 전송은 `fm.streamable_http_app()`(StreamableHTTPSessionManager, 경로 `/mcp`)을 그대로 쓰고, SignalForge식 순수 ASGI `_bearer_gate`로 감싸 인바운드 `Authorization: Bearer <GW_TOKEN>` 인증.
- 기동 lifespan에서 백엔드별 `streamablehttp_client` + `ClientSession.initialize()` + `list_tools()`를 1회 수행해 원본 `types.Tool`을 무손실 수집. 이름 충돌(현재 `extract_pptx_images` 2건)만 `backend_` 프리픽스로 rename → 정확히 46개 고유 도구.
- `call_tool`은 route 맵으로 백엔드를 찾아 raw `ClientSession.call_tool`의 `CallToolResult`를 그대로 반환(langchain 이중변환 회피, image/structuredContent 충실도 보존). 세션이 죽으면 1회 재연결하고, 재시도는 첫 시도와 **같은 자격**으로 나간다 — 신원 전달 백엔드(`IDENTITY_FWD_BACKENDS`, 기본 `hwax-deliberation`)는 신원 헤더를 실은 단발 세션으로 부르므로 상주 세션이 죽어 있어도 재연결을 기다리지 않는다.
- 백엔드 1개가 기동 시 다운이면 그 도구만 빠지고 나머지는 정상 노출(전체 실패 아님).

## 인가 — 그룹 기반 도구 필터 (계획서 §4)
백엔드별 가시성을 caller의 `groups`로 건다. 에이전트가 매 요청 `X-HWAX-Groups`(콤마구분)에 사용자 그룹을 실어 보내면, 게이트웨이가:
- **`tools/list`** 를 필터 — 백엔드 `allowed_groups`가 caller groups와 교집합이 있는 도구만 노출(보이지 않는 도구는 LLM이 존재조차 모름).
- **`tools/call`** 을 가드 — list에서 숨겼어도 직접 호출을 시도하면 `forbidden`(이중 방어).

포털 PAT 로 들어온 호출은 PAT 에 박힌 발급 때 값이 아니라 포털의 **지금** 답(`GET /internal/access/entitlements`)을 쓴다 — 권한 키(`feat:`·`plat:`)는 응답의 `keys` 로 바꾸고, 관리자 표지(`portal-admin`)는 PAT 에 박힌 것을 떼고 응답이 `"is_admin": true` 일 때만 붙인다. 이 그룹은 신원 전달 백엔드까지 내려가므로, 떼지 않으면 관리자 해제가 하위에서 먹지 않는다. 칸이 없으면(옛 포털) 붙이지 않는다 — 이 표지를 읽는 백엔드·`allowed_groups` 규칙이 없어 아무도 막히지 않는다(2026-10-07 dev 대조). 포털에 물을 때는 토큰의 로그인 그룹을 그대로 준다(누가 관리자인지는 포털이 정한다). PAT 의 그룹을 읽는 길은 둘이고 **둘 다** 이렇게 한다 — `/mcp` 는 인증 미들웨어가, REST 프록시(`/api/<site>/`)는 `_rest_groups` 가. 한쪽만 떼면 같은 토큰이 `/mcp` 에서는 막히고 `/api` 에서는 통한다.

규칙: 백엔드 `allowed_groups`가 **비었거나 없으면 전체 공개**(기존 동작 보존), 있으면 교집합 필요. 헤더가 없거나 그룹이 비면 제한 백엔드는 숨김(**fail-closed**). 어느 도구가 어느 백엔드인지는 게이트웨이의 `route` 맵만 알기에(에이전트엔 평탄화되어 도착) 필터는 여기서만 가능하다. 헤더는 `_low.request_context.request.headers`로 읽는다(streamable-http가 Starlette Request를 핸들러까지 전달).

## 읽기 전용 포털 PAT — 조회만(HWAXPortal docs/followups-1017 결정 5)

포털 PAT 의 `scopes` 가 `read` 만이면(**`read` 가 있고 `write` 가 없을 때** — 챗 · 절차 PAT 의 `["chat"]` 은 해당 없음, 칸이 없는 옛 PAT 은
포털 기본 읽기 · 쓰기) 다음만 부른다. 막으면 `read_only: …` 로 까닭과 여는 법을 답하고 감사 원장에 `read-only` 를 남긴다.

- 백엔드 도구 — **`read_tools.json`(추적)의 `백엔드키:원래 이름`**(별칭 · 접두 노출 이름도 원래 이름으로 푼다) 또는 **앱이 그 도구에 단
  `readOnlyHint`**(재집계마다 다시 읽는다). 처음 목록은 리스크 앱이 읽기 토큰으로 부르는 26종(10-18 대조).
- 게이트웨이 자체 도구 — 조회(search_tools · list_tool_apps · rest_catalog · search_conversations · browse_experts · use_experts ·
  verify_answer)는 열고 `save_conversation` 은 막는다. `rest_call` 과 REST 다리(`/api/<site>/`)는 GET · HEAD 만. `invoke_tool` 은 안쪽 도구로 본다.
- 표지 `x-hwax-readonly` 는 PAT 분기에서만 싣고 클라이언트 사본은 두 분기(GW_TOKEN · PAT) 모두 버린다.
- 판정 밖 — 읽기 PAT 로 포털 `/agent/chat` · 카드 대조를 부르면 포털이 챗 PAT 를 새로 찍어 심의(RA 초안 저장)가 돈다. 리스크 앱 패널의
  길이라 그대로 둔다(결정 FU-D17).

## 설정 — `gateway_config.json` (gitignore, 시크릿)
**전체 스키마·플레이스홀더는 커밋된 `gateway_config.example.json` 참고** — fresh 배포 시 이걸 복사해 실토큰만 채운다. `gateway_config.json` 자체는 gitignore(600).
현 `mcp_servers.json`과 동일 JSON 스키마 + 최상위 `_gateway` 블록. 백엔드에 선택적 `allowed_groups`(미지정 = 전체 공개).
```json
{
  "_gateway": { "host": "127.0.0.1", "port": 9110, "token": "<GW_TOKEN>" },
  "reportarchive":  { "url": "http://127.0.0.1:3002/mcp", "headers": { "Authorization": "Bearer rat_…",  "X-Workspace-Slug": "dev" }, "allowed_groups": ["report-users"] },
  "signalforge":    { "url": "http://127.0.0.1:8013/mcp", "headers": { "Authorization": "Bearer sfmcp_…" } },
  "mx-white-paper": { "url": "http://127.0.0.1:8765/mcp", "headers": { "Authorization": "Bearer mxwp_…" } }
}
```

## 내부 목적지는 사내 프록시를 거치지 않는다 — `NO_PROXY` 자동 유도
httpx 는 환경의 `HTTP(S)_PROXY` 를 따른다(`trust_env` 기본값). 사내 프록시가 걸린 박스에서는 내부 백엔드 호출까지 프록시로 나가고, 상대가 IP 허용목록으로 거절한다(RA 사람별 위임 403). 게이트웨이는 **설정을 읽은 직후**(클라이언트를 하나도 만들기 전에) 자기가 부르는 주소의 호스트를 `NO_PROXY`·`no_proxy` 에 더한다 — 운영자가 셸에 따로 적지 않아도 된다.

- 모으는 곳 — 백엔드 `url` · `heax_registry.per_user_sso.*.sso_url`·`portal_pat_url` · `rest.*.base` · `portal.api_base`·`jwks_url`·`revoked_url` · `heax_registry.servers_url`·`base`. 레지스트리로 뒤늦게 발견되는 앱은 발견할 때 같은 함수로 더한다. `127.0.0.1`·`localhost`·`::1` 은 늘 넣는다.
- 있던 값은 지우지 않는다. 한쪽 철자에만 있으면 다른 쪽이 그 값을 이어받고(파이썬은 소문자를 먼저 본다), 둘 다 있으면 각자 제 값 뒤에 붙인다. 값이 `*` 하나면 그대로 둔다.
- 호스트만 적는다(포트·계정·쿼리는 뺀다). CIDR 이나 `.example.com` 항목이 이미 있어도 주소를 따로 더한다 — httpx 는 CIDR 을 대역으로 읽지 않고, 점으로 시작하는 항목은 하위 도메인만 덮는다.
- 무엇을 더했는지는 기동 로그에 호스트 이름으로 남는다(`NO_PROXY 에 내부 목적지 N곳을 더했다`). IP·평범한 DNS 이름이 아닌 호스트는 적지 않고 경고를 남긴다.
- 설정에 적힌 주소는 전부 프록시 밖으로 나간다. 프록시를 **거쳐야만** 닿는 주소를 백엔드로 두는 구성과는 맞지 않는다(지금 그런 백엔드는 없다).

## REST 프록시 — 포털 PAT 하나로 하위 사이트 REST API (`rest_proxy.py`)
MCP fan-out과 같은 패턴("호출자 토큰 1개 → 백엔드별 네이티브 토큰 주입")을 **일반 REST**로 확장. 클라이언트가 **포털이 발급한 PAT 하나**(`Authorization: Bearer <JWT>`)로 `/api/<site>/<path>`를 치면, 게이트웨이가:
1. 포털 **JWKS로 PAT 검증**(RS256, `scope=api`, `aud`에 대상 site 포함, exp, 그리고 `portal.revoked_url` 폐기목록에 없을 것 — 60s 캐시).
2. `rest.<site>.base` 로 라우팅하며 **그 사이트의 서비스 토큰을 주입**(`inject.header/value`) 후 httpx 포워드. 호출자 신원은 `X-Forwarded-User` 헤더 + 게이트웨이 audit(`caller`=이메일·`ip`·`via`)에 남는다.
- **하위 사이트 코드는 무변경** — 각 사이트는 자기 서비스 토큰만 본다.
- `/mcp`(GW_TOKEN)와 인증 분리 — `/api/*`는 GW_TOKEN 게이트를 우회하고 라우트가 자체 PAT 검증.
- **graceful**: config에 `rest`/`portal`이 없으면 REST 표면 off, MCP만 정상 기동(옛 config 서버에 새 코드 배포해도 안 깨짐).

### 사이트별 서비스 토큰 조달 (`rest.<site>.inject`)
| site | base | 주입 | 토큰 조달 |
|---|---|---|---|
| mx-white-paper | :8800 | `Authorization: Bearer` | `mxwp_` read+write 토큰 발급 — 인증된 사용자로 `POST /api/v1/me/api-tokens {"scopes":["read","write"]}` (또는 api_tokens 테이블 직접 INSERT: `hash_password(token)`). |
| signalforge | :17370 | `X-API-Key` | 그 서비스의 `settings.API_KEY`(SignalForge `.env`) 그대로. |
| ai-data-hub | :8001 | (없음) | `auth_required=false` → 익명 허용이라 inject 불필요. 잠글 땐 api_keys에 서비스 키 생성 후 `X-API-Key` inject. |

포털 PAT는 `POST /auth/pat`(세션+CSRF, `audiences`는 config `portal.audience_ok` 내에서), 폐기는 `DELETE /auth/pat/{jti}` → `/auth/pat/revoked.json`에 등장(게이트웨이가 폴링).

## ste 방식 사람별 위임 — `heax_registry.per_user_sso`
게이트웨이가 서비스의 `POST /api/auth/sso` 에 공유 비밀(`X-Heax-Gateway-Secret`)과 호출자 이메일을 보내 **그 사람 토큰**을 받아 그 명의로 부른다. 토큰은 12시간 캐시하되 응답의 `expires_in` 이 더 짧으면 그보다 2분 먼저 버린다. 그 2분은 위임 백엔드의 도구가 짧거나 토큰을 요청이 도착할 때만 본다는 전제이고, **발급자가 주는 수명은 호출 한도(`GATEWAY_CALL_TIMEOUT`, 600초)보다 길어야 한다**(hwax_risk `HWAXRISK_SSO_TTL_S` 900초) — 길지 않으면 발급 때 경고를 남긴다. 백엔드가 401 이면 한 번 다시 받고, 받지 못하면 거부한다(서비스 계정으로 강등하지 않는다). 포털은 토큰을 쥐지 않는다.

- 항목 `{sso_url, secret, client, strip_headers?}` — `strip_headers` 는 서비스 계정 설정에만 맞는 헤더를 사람별 호출에서 뺀다(RA 의 `X-Workspace-Slug`: 서비스 부서가 남으면 남의 부서로 읽고 쓴다).
- 발급 요청은 호출자를 `X-Heax-User-Email` 과 `X-Hwax-Delegate-Email` 둘에 싣는다. Caddy 경로로 발급받는 앱(`auth: heax` — hwax_risk)은 forward_auth 가 앞의 것을 지우고 서비스 토큰 주인(heax 첫 관리자)으로 다시 실으므로, 앱은 뒤의 것(Caddy 가 건드리지 않는다)을 먼저 읽는다. 값은 게이트웨이가 확인한 신원뿐이다 — 클라이언트가 보낸 같은 이름 헤더는 `/mcp`(인증 미들웨어)와 `/api/`(REST 프록시) 모두 버린다. 받은 단언이 리스크 앱 꼴(`rrsso_`)이면 그 이메일이 보낸 사람인지 본다. 다를 때(위임이 접혔다) 거부하는 것은 **앱이 위임을 아는 판일 때뿐이다** — 그 앱은 위임 헤더로 발급한 단언에만 표지 `d` 를 싣는다(HWAXRisk 2eecb36). `d` 가 있는데 남의 이메일이면 위임 헤더가 앱에 닿기 전에 바뀐 것이라 발급 실패로 거부한다. `d` 가 없으면(위임 헤더를 모르는 옛 앱 — HWAXRisk main) 종전 동작대로 그 단언으로 부르고, 발급 때 경고 로그 한 줄과 MCP 도구 호출마다 감사 `note=folded-old-app` 만 남긴다(REST 다리 길은 경고 로그뿐이다). 접힌 신원의 쓰기는 위임을 아는 앱이 `d` 없는 단언을 받지 않아 스스로 막는다. 그래서 게이트웨이를 앱보다 먼저 내도 hwax_risk 사람별 호출이 거부되지 않는다(종전처럼 접힌 신원으로 돈다) — 옛 앱이 남은 동안 감사에 `folded-old-app` 이 보이면 HWAXRisk 새 판 배포가 필요하다는 뜻이다.
- `portal_pat_url`(선택 — 지금은 hwax_risk) — 발급 응답에 `portal_pat_wanted`(앱이 그 사람의 포털 PAT 가 없거나 곧 끝난다고 보는 것)가 실리면, 게이트웨이가 호출자 본인의 포털 PAT 로 포털 `POST /auth/pat/exchange` 를 불러 같은 사람의 더 좁은 PAT 를 받고 이 주소로 넘긴다 — 성공이면 `{pat}`, 교환 실패면 `{error, message}`, 헤더는 발급과 같다(HWAXPortal `docs/risk-credentials` §4.2). `provision-config.sh` 가 `sso_url` 끝의 `/api/auth/sso` 를 `/api/auth/portal-pat` 로 바꿔 적는다(`HWAXRISK_PORTAL_PAT_URL` 로 덮는다, 유도하지 못하면 생략을 로그에 남긴다).
  - `portal_pat_spec`(이 칸이 있어야 건넨다) — 교환 본문의 상한 `{name, audiences, scopes, max_ttl_days}` 이다. 본문은 이 명세 안에서만 만든다 — `name` 은 명세의 것(바란 이름은 버린다), `audiences` 는 바람 ∩ 명세 ∩ 호출자 PAT 의 aud, `scopes` 는 바람 ∩ 명세, `ttl_days` 는 바람과 `max_ttl_days` 중 짧은 것(바람이 없거나 꼴이 틀리면 `max_ttl_days`), `min_remaining_s` 는 바람의 값이 0 이상 정수일 때만 싣는다. 바람의 다른 칸(`reason`·`require_audiences` 등)은 포털로 보내지 않는다. 바람의 `require_audiences`(앱이 '이 청중 때문에' 바란 것 — 예: 등록된 PAT 에 `step-forge` 가 없다) 가운데 하나라도 그 본문의 청중에 들지 못하면(호출자 PAT 에 없거나 명세가 뺐거나 호출자 청중을 못 읽었다) `skipped-aud-unavailable` 로 포털을 부르지 않는다 — 받아도 앱은 여전히 모자라다고 보고 단언마다 다시 바란다. 명세가 없으면 `skipped-no-spec`, 꼴이 틀리면 `skipped-bad-spec`, 청중·범위 겹침이 비면 `skipped-no-audience`·`skipped-no-scope` 이고 포털도 앱도 부르지 않는다. `provision-config.sh` 가 hwax_risk 에 `{"name":"hwax-risk","audiences":["mcp-gateway","step-forge"],"scopes":["read"],"max_ttl_days":90}` 를 적는다(`portal_pat_url` 처럼 `--force` 재생성에서도, 비밀 없이 이어받는 실행에서도 남는다).
  - **포털 PAT 로 들어온 호출(`via=pat`)에만** 한다 — GW_TOKEN(에이전트 서버)·웹 챗·절차 PAT·요청 문맥 밖의 발급(REST 다리)은 건너뛴다. 교환으로 받은 자식 PAT(포털이 `par` = 원 jti 를 찍는다 — 원이 될 수 없다)로 들어온 호출도 포털·앱을 부르지 않고 `skipped-child` 로 건너뛴다 — 대개 앱 자신이 그 사람 자격으로 게이트웨이를 다시 부른 것이고, 교환하면 거절이 앱에 가 앱이 실패 쉼에 든다.
  - 발급 직후, 그 도구 호출을 앱에 보내기 전에 같은 잠금 안에서 하고, 전체 8초를 넘기지 않으며 실패해도 도구 호출은 그대로 간다. 한 번 건넨 (앱, 사람)은 5분 동안 다시 하지 않는다(401 뒤 강제 재발급이 또 교환하지 않게).
  - 앱은 바람을 **발급 응답에만** 싣는다. 그 발급의 호출이 건넬 수 없었으면(포털 PAT 가 아닌 호출·교환 자식·5분 쉼 안) 또는 잠깐 실패했으면(교환·등록의 시간 초과·닿지 않음·5xx) 그 바람을 (앱, 사람)마다 남겨 두고, 캐시된 단언으로 가는 같은 사람의 다음 호출에서 다시 건넨다 — 단언이 캐시에 사는 동안(hwax_risk 900초 − 2분) 포털 PAT 로 온 호출도 발급을 거치지 않아 건네지 못하던 것을 막는다. 5분 쉼은 그대로 지키고, 캐시 길에서 바람이 그대로 남는 건너뜀은 감사 note 로 적지 않는다(호출마다 같은 줄이 붙는다). 등록되거나, 거절·설정 탓으로 끝났거나, 다음 발급이 바람을 싣지 않으면 지운다. 메모리에 상한(1024)을 두고 넘치면 가장 오래 손대지 않은 것부터 버린다(버려도 다음 발급이 다시 싣는다).
  - 교환은 됐는데 앱 등록이 실패하면(200 이 아님·시간 초과·닿지 않음) 새 PAT 를 그 PAT 스스로 폐기한다 — 포털 `POST /auth/pat/revoke-self` 에 `Authorization: Bearer <새 PAT>`. 같은 8초 안에서 하는 최선 노력이고(교환 + 등록은 그 4분의 3 안에서 끝내 폐기 몫을 남긴다), 결과는 `portal-pat:revoked-unused` 또는 `portal-pat:revoke-failed` 로 앞 note 에 `+` 로 붙는다. 등록 시간 초과는 앱이 실은 받았을 수도 있지만, 그러면 앱이 다음 단언에서 폐기된 PAT 를 보고 다시 바란다 — 주인 없는 토큰을 최대 90일 남기는 것보다 낫다.
  - 결과는 그 호출의 감사 `note` 에 접힌다 — `portal-pat:registered` · `portal-pat:exchange-<code>` · `portal-pat:register-<status>`(시간 초과는 `-timeout`) · `portal-pat:revoked-unused`·`revoke-failed` · `portal-pat:skipped-<까닭>`. 토큰 값은 로그·감사 어디에도 적지 않고, 호출자의 원 PAT 는 포털에만 간다.
- `per_user_sso` 가 포털 등록 연결(`PORTAL_CONN_BACKENDS`, 포털 '개인 토큰 › 외부 연결' 의 RA·TestScope 토큰)보다 **먼저**다 — 위임이 켜진 서비스는 등록 토큰을 쓰지 않는다.
- `provision-config.sh` 가 env 로 만든다. 순서는 env > 직전 config > 기본값이고, 비밀이 없는 실행은 직전 항목을 지우지 않고 이어받는다. 운영에서는 update-all 이 포털 `infra/.env` 에서 읽어 넘긴다(HWAXPortal `docs/sso-delegation`).

| env | 만드는 것 |
|---|---|
| `STE_SSO_SECRET` · `STE_SSO_URL` | `per_user_sso.ste` |
| `RA_SSO_SECRET` · `RA_SSO_URL`(기본 `http://127.0.0.1:3000/api/auth/sso`) | `per_user_sso.reportarchive` + `strip_headers: ["X-Workspace-Slug"]`. 서비스 백엔드(`RAT_TOKEN`)는 그대로 — 도구 목록은 그 세션으로 모은다 |
| `TESTSCOPE_SSO_SECRET` · `TESTSCOPE_SSO_URL`(기본 없음 — 운영에서는 포털이 `TESTSCOPE_BASE_URL` 에서 유도해 넘긴다) | `per_user_sso.testscope`(부서 헤더가 없어 `strip_headers` 없음). 주소를 모르면 만들지 않고 생략을 로그에 남긴다 |
| `PER_USER_SSO_APPS`(공백 구분 `<per_user 키>:<ENV 접두>`, 예 `newapp:NEWAPP`) + `<접두>_SSO_SECRET` · `<접두>_SSO_URL`(기본 없음) | `per_user_sso.<키>` = `{sso_url, secret, client: "gateway", managed_by: "PER_USER_SSO_APPS"}` — 이 모양의 앱은 `provision-config.sh` 를 고치지 않고 붙는다. `managed_by` 는 이 순회가 쓴 항목이라는 표지다(게이트웨이는 읽지 않는다 — 목록에서 뺀 앱을 끌 때 가린다). 규칙은 TestScope 와 같고(env > 직전 config 주소, 주소를 모르면 만들지 않고 로그에 남긴다, 비밀 없는 실행은 이어받는다), 손으로 붙여 둔 필드(`strip_headers` 등)는 남는다. 스크립트가 직접 만드는 다섯 키(`kooremapper_mcp`·`hwax_risk`·`ste`·`reportarchive`·`testscope`)와 못 읽은 쌍은 건너뛰고 그 사실을 로그에 남긴다. 한 키를 두 번 적으면 **먼저 적힌 쌍만** 쓰고 뒤 쌍은 경고와 함께 건너뛴다(HWAXPortal update-all 과 같은 읽기 — 끄기 판정도 먼저 적힌 쌍의 비밀을 본다) |
| `PER_USER_SSO_OFF`(공백 구분 `reportarchive`·`testscope` — HWAXPortal update-all 이 infra/.env 의 빈 비밀을 보고 넘긴다 — 와 일반 앱의 키) | 그 위임 항목을 지운다(토큰 등록으로 되돌리기 — 일반 앱은 등록 토큰 길이 없어 서비스 계정으로 나간다). 비밀 없는 손 실행은 직전 값을 이어받으므로 끄는 길은 이것뿐이다. 비밀이 같이 오면 끄지 않는다. 일반 앱은 두 경우에 꺼진다 — 그 실행의 `PER_USER_SSO_APPS` 에 쌍이 있고 비밀이 비었을 때, 또는 쌍째 빠졌고 항목에 `managed_by` 표지가 있을 때(앱을 걷으며 줄을 지운 경우). 어느 쪽이든 이름이 와야 한다 — 목록이 비었다고 스크립트가 스스로 지우지는 않는다(손 실행에는 목록이 없다). 넘기는 쪽은 provision.env 를 읽은 호출자다(update-all, 손으로는 `PER_USER_SSO_OFF=<키>` 를 주고 `--force`). 표지 없는 항목(손으로 붙인 위임, `ste`·`hwax_risk` 등)은 이름이 와도 지우지 않는다 |

## 등록 토큰 방식 — `PORTAL_CONN_BACKENDS`(RA·TestScope)
사람이 그 서비스에서 직접 받은 개인 토큰을 포털 '개인 토큰 › 외부 연결'(`/tokens?tab=connect`)에 등록하면, 게이트웨이가 호출 때 포털 `GET /internal/connections/<service>?email=`(GW_TOKEN)로 그 토큰을 읽어 그 사람 명의로 부른다. 신원이 있는데 등록이 없거나 포털에 묻지 못하면 **거부**하고 등록을 안내한다(서비스 계정으로 대신 부르지 않는다). 신원 없는 내부 호출만 서비스 세션으로 간다.

| 백엔드 | 토큰 | 부서 헤더 |
|---|---|---|
| `reportarchive` | `rat_…` | 등록한 워크스페이스를 `X-Workspace-Slug` 로(비면 서비스 값을 지운다) |
| `testscope` | `tsc_pat_…`(TestScope 에서 발급, `/api/auth/me` 를 부르려면 `read` 범위) | 싣지 않는다 |

위 둘은 **내장**이다. 그 밖의 토큰 등록 플랫폼(FMEA · MatNexus 등)은 **선언**으로 붙는다 — 포털 박스 권한표(`backend/config/access.local.yaml`)의 그 플랫폼 항목에 `connect:` 블록을 적으면, 게이트웨이가 포털 `/internal/access/policy` 의 `connections`(권한 행과 한 응답)를 받아 같은 길에 넣고 백엔드를 스스로 붙이고 뗀다(코드 · 빌드 · 재기동 없음, HWAXPortal `docs/ext-connect`). 상주 세션은 **목록 전용**이다(`list_auth: open` 이면 자격 없이, `registered:<포털 이메일>` 이면 그 계정이 등록한 토큰을 목록 세션에만 싣는다). 호출은 언제나 부르는 사람의 등록 토큰으로 가고, 신원 없는 호출은 거절하며(서비스 계정 없음), 권한 행이 없거나 선언이 지워지면 내부 서비스 호출에도 닫힌다. 이름이 겹치면 선언 쪽 도구만 `<키>_` 접두가 붙는다. 선언의 `read_tools` 는 `read_tools.json` 에 더해지는 읽기 목록이다(앱이 `readOnlyHint=False` 를 적었으면 앱이 이긴다). 감사 줄에 `tok:<토큰 sha256 앞 10자>` 를 남기고, 상태는 `/health` 의 `conn_platforms`(키 → ok · down · no-list-token · collision · no-policy-row · invalid)로 본다. 정적 · heax · 내장 · 위임(`per_user_sso`) · 신원 전달 키와 겹치는 선언은 collision 으로 받지 않는다 — 토큰 등록 앱이면 `PER_USER_SSO_APPS` 에서 뺀다. 선언 캐시는 `.conn_registry_cache.json`(0600, 토큰 없음)이다.

TestScope 는 다른 조직의 포털(제 주소로 노출)이라 RA 처럼 두 방식 중 하나로 붙는다 — TestScope 코드는 여기서 손대지 않는다. **기본(`TESTSCOPE_SSO_SECRET` 없음)** 은 이 등록 토큰 길이고, **비밀이 있으면** `per_user_sso.testscope` 가 생겨 위 우선순위대로 그쪽이 먼저 탄다(등록할 것 없음). 위임은 TestScope 가 `POST /api/auth/sso`(위 계약)를 갖춘 뒤에만 켠다 — 그 전에 비밀이 생기면 발급이 실패해 신원 있는 TestScope 호출이 전부 거부되고 등록 토큰으로 돌아가지 않는다. 그래서 비밀은 자동으로 만들지 않고 사람이 넣는다. 백엔드는 두 방식이 같다 — `provision-config.sh` 가 `TESTSCOPE_MCP_URL`(> 직전 config 주소)로 만든다(`streamable_http`, 서비스 `Authorization` 없음 — tools/list 는 토큰 없이 된다). 기본 호스트가 없어 주소를 모르면 만들지 않는다.

## 시간 한도 — 손잡이는 프로세스 env, 기본값은 코드
게이트웨이는 `.env` 를 읽지 않고 HWAXPortal `infra/services.yaml` 의 `mcp-gateway` 항목도 env 를 넘기지 않는다 — **`gateway.py` 의 기본값이 곧 운영값**이다. 바꾸려면 `start.sh` 를 부르는 환경에 export 한다(값은 초). 닿았는지는 기동 로그의 한 줄(`시간 한도(초) — GATEWAY_CALL_TIMEOUT=600 · …`)로 본다 — 이 프로세스에 실제로 걸린 값이다.

원칙은 셋이다. ① 안쪽 한도가 그것을 감싸는 한도보다 작다. ② 느린 도구(시간 초과)와 죽은 상대(연결 실패)를 가른다 — 시간 초과는 **한 번으로 끝내고**(재시도·세션 교체·토큰 재발급 없음) 연결 실패만 한 번 다시 건다. ③ 만료 문구는 몇 초였고 어느 손잡이인지 말한다.

| env | 기본 | 무엇을 재나 | 걸리면 |
|---|---|---|---|
| `GATEWAY_CALL_TIMEOUT` | 600 | 백엔드 도구 호출 1건(상주 세션·사람별·등록 토큰·신원 전달 네 길 공통) | `backend <키>: <도구> 이 600초 안에 답하지 않았다(GATEWAY_CALL_TIMEOUT)…` — 도구는 한 번만 불렸고 세션은 그대로다. 백엔드는 아직 일하고 있을 수 있다 |
| `GATEWAY_RECONNECT_TIMEOUT` | 30 | 죽은 상대 — 단발 세션의 핸드셰이크(connect + initialize)와, 연결 실패 뒤 상주 세션이 돌아오기를 기다리는 시간 | `backend <키> unavailable: 30초 안에 세션을 열지 못했다(GATEWAY_RECONNECT_TIMEOUT)` · `… unavailable: 30초 안에 돌아오지 않았다(…)` — 죽은 상대라 머리에 `unavailable:` 를 남긴다(포털 절차 판정기가 이 머리로 '불통' 을 가른다). 느린 도구의 문구에는 붙이지 않는다 |
| `GATEWAY_BACKEND_READ_TIMEOUT` | 호출 한도 + 60 | 백엔드 세션 아래 HTTP read 침묵(MCP SDK 의 숨은 300초에 이름을 붙였다) | 호출 한도가 먼저 걸리므로 위 문구가 나온다. 호출 한도보다 크지 않게 적으면 따르지 않고 기본값을 쓴다(기동 로그에 경고) — 이것이 먼저 걸리면 세션째 끊긴다 |
| `GATEWAY_BACKEND_HTTP_TIMEOUT` | 30 | 같은 세션의 connect·write·pool | 연결 실패로 다뤄진다(한 번 다시 건다) |
| `GATEWAY_LIVENESS_TIMEOUT` | 10 | 생사 탐침 — 재활 패스(`GATEWAY_REVIVE_INTERVAL`, 60초)마다 연결된 백엔드에 보내는 `list_tools` 한 번. 부팅·재활 패스가 백엔드에 거는 핸드셰이크(첫 연결·재연결)도 이 값이다 | 탐침은 아래 횟수만큼 **연속으로** 놓치면 세션을 간다. 핸드셰이크는 놓고 가서 다음 패스가 다시 건다(`backend <키> 첫 연결 10초 초과 — 다음 패스에서 다시 시도(GATEWAY_LIVENESS_TIMEOUT)`) — 매달린 백엔드 하나가 부팅이나 다른 백엔드의 탐침·재연결·카탈로그 갱신을 세우지 않는다 |
| `GATEWAY_LIVENESS_STRIKES` | 2 | 탐침 무응답을 몇 번 연속 놓쳐야 세션을 가는가. 한 번으로 갈면 이벤트 루프가 잠깐 바쁜 건강한 백엔드의 진행 중인 답을 버린다. 예외로 실패한 탐침(세션 종료·연결 거부)은 종전대로 한 번에 간다 | 세션을 갈 때 그 세션에 걸린 진행 중 호출을 곧바로 실패로 돌려준다 — `backend <키> 가 탐침에 2회 연속 답하지 않아 세션을 갈았다(GATEWAY_LIVENESS_TIMEOUT × GATEWAY_LIVENESS_STRIKES) — <도구> 의 실행 여부는 모른다`. 죽은 백엔드는 약 2분 안에 호출자를 놓아 준다(단발 세션의 호출은 건드리지 않는다) |
| `GATEWAY_AGG_STALE_ROUNDS` · `GATEWAY_HEAX_MISS_DROP` | 10 · 10 | 닿지 않는 백엔드(또는 레지스트리에서 빠진 앱)의 도구를 몇 패스 뒤에 카탈로그에서 빼는가 — 약 10분(종전 3패스) | 남아 있는 동안은 `backend <키> unavailable: … backend session down`, 빠진 뒤에는 `unknown tool`. 수 시간짜리 심의 도중의 앱 재배포가 '도구가 없다' 로 읽히지 않게 길게 둔다 |
| `GATEWAY_PORTAL_SAVE_TIMEOUT` | 120 | `save_conversation` — 심의 전사 전체를 포털에 올리는 POST 의 답(연결은 8초) | `CONV_UNAVAILABLE: 포털이 120초 안에 저장을 확인하지 않았다(GATEWAY_PORTAL_SAVE_TIMEOUT) — 저장됐을 수 있으니 다시 보내기 전에 대화 목록을 확인하라` |
| `GATEWAY_REST_CALL_TIMEOUT` | 호출 한도 | `rest_call` 한 건 — read 침묵과 전체 기한 둘 다(연결은 10초). 전용 도구가 없을 때의 다리라 도구 호출과 같은 단위다 | `<사이트> 가 600초 안에 답하지 않았다(GATEWAY_REST_CALL_TIMEOUT)` — 느린 것이다. 연결 시간 초과·거부는 종전대로 `upstream unreachable` |
| `REST_PROXY_UPSTREAM_TIMEOUT_S` | 110 | REST 프록시(`/api/<site>/`)가 상류를 기다리는 시간 — read 침묵·write·pool 각각이고 전체 기한이 아니다(2GB 업로드·결과 스트림은 상류가 이만큼 말이 없을 때만 끊긴다). 연결은 30초 그대로. 가장 짧은 바깥이 리스크 앱의 원천 호출 120초(HWAXRisk `DEFAULT_SOURCE_CALL_TIMEOUT_S` — 위임 캡처가 `/api/step-forge` 로 큰 트리를 읽는다)라 그 밑이다. `GATEWAY_REST_CALL_TIMEOUT` 은 `rest_call` 의 전체 기한이고 기본 600 이라 이 길에 쓰지 않는다 | 504 `{"error": "upstream timeout", "detail": "<사이트> 가 110초 안에 답하지 않았다(REST_PROXY_UPSTREAM_TIMEOUT_S)"}`(종전 30초에 502 `upstream unreachable`). 연결 실패는 그대로 502 |
| `GATEWAY_JWKS_TIMEOUT` | 5 | 호출자 토큰(포털 PAT)을 검증할 때의 포털 서명 키 조회 — `/mcp` 와 `/api/<site>/` 둘 다. 스레드에서 돈다(동기 urllib 가 이벤트 루프를 붙잡지 않게) | 검증 실패로 다뤄져 401 `unauthorized`(감사 `unverified-token`). 포털이 매달려도 진행 중인 호출과 ping 은 멈추지 않는다 |

**0 은 '끔' 이 아니다.** 이 표에 0 을 '끔'·'없음' 으로 읽는 손잡이는 없다 — 기한 0 은 상대에 닿기도 전에 걸린다. 엔진의 `MCP_CALL_TIMEOUT_S`·`DELIB_TIMEOUT_S` 가 0=없음이라 같은 뜻으로 적기 쉽다. `GATEWAY_CALL_TIMEOUT` 과 `GATEWAY_RECONNECT_TIMEOUT` 은 0 이하를 **받지 않는다** — 따르면 모든 도구 호출(재연결 한도는 단발 세션의 호출)이 곧바로 실패하므로, 기본값(600 · 30)으로 돌고 기동 로그에 `GATEWAY_CALL_TIMEOUT=0 는 따르지 않는다 …` 를 남긴다. 호출 한도는 끌 수 없다(아래 '층'). 나머지 초 단위 손잡이는 적은 값을 그대로 쓰므로 0 을 적지 않는다 — 그 길이 곧바로 실패한다(`GATEWAY_BACKEND_READ_TIMEOUT` 만 호출 한도보다 크지 않으면 스스로 바로잡는다).

층 — 핸드셰이크·재연결 30 < 호출 600 < 전송 read·단발 세션 바깥 기한 660(= 30 + 600 + 30) < 엔진 `MCP_CALL_TIMEOUT_S` 900 < nginx `/mcp-gw/` 3600. 포털 절차 워밍업(690)도 660 바깥이다. **`GATEWAY_CALL_TIMEOUT` 을 올리면 엔진·포털 워밍업·nginx 셋을 같은 폭으로 올린다**(전송 read 와 단발 세션 바깥 기한은 스스로 따라 오른다). 안쪽(백엔드 자신의 한도 — KooRemapper MCP→REST 240, AIDataHub 풀 60 + 검색 90 등)은 600 보다 작아야 한다. HWAXPortal 절차 시험(`test_procedures_census`)이 `gateway.py` 의 기본값을 읽어 30~600 으로 묶으므로 600 을 넘기려면 그 상한부터 고친다. 600 으로도 모자란 도구는 한도를 올리지 말고 잡 도구(제출 + 상태 조회)로 돌린다 — 이 값이 호출 중 죽은 무상태 백엔드에서 호출자를 풀어 주는 마지막 값이다.

그대로 둔 값 — 느린 일을 재지 않고 죽은 상대·신선도를 재는 값이라 짧게 둔다.

| env | 기본 | 무엇 |
|---|---|---|
| `GATEWAY_REVIVE_INTERVAL` | 60 | 재활 패스 주기(탐침·재연결·레지스트리 폴·카탈로그 갱신) |
| `GATEWAY_USER_PAT_TTL` | 43200 | 사람별 위임 토큰 캐시. 응답의 `expires_in` − 120초가 더 짧으면 그것 |
| `GATEWAY_AFF_PROOF_TTL` | 120 | 소속 증명의 재전송 창(앱은 요청이 도착할 때 본다) |
| `GATEWAY_CONN_TTL` | 300 | 포털 등록 토큰 캐시(조회 실패·미등록은 30초) |
| `GATEWAY_ACCESS_POLICY_TTL` · `GATEWAY_ACCESS_ENT_TTL` | 60 · 60 | 포털 권한 정책 갱신 주기 · 사람별 권한 캐시(포털이 불통이면 직전 값) |
| `GATEWAY_CACHE_TTL` | 300 | 읽기 전용 응답 캐시. 상태·잡·`deliberate_*`·`risk_*` 는 캐시하지 않아 폴링이 실제 상태를 본다 |
| `EVID_TTL_S` | 1800 | `verify_answer` 의 조회 기록. 지나면 `조회 기록이 만료됐다 … (EVID_TTL_S)` |
| `ORG_TAX_TTL_S` | 600 | 조직도 라벨 캐시 |

손잡이 없이 리터럴로 남은 것도 있다 — 죽은 상대를 재는 포털 조회 8초(등록 토큰·권한·정책·조직도) · REST 사이트의 OpenAPI 조회 8초 · 사람별 토큰 발급 15초 · 레지스트리 폴 10초 · 폐기 목록 5초, 그리고 심의가 쓰지 않는 길의 `search_conversations` 120초 · REST 스트리밍 프록시(`/api/<site>/`)의 연결 30초(상류 침묵은 위 `REST_PROXY_UPSTREAM_TIMEOUT_S`).

**만료된 호출자 토큰**은 틀린 토큰과 다르게 답한다 — 401 본문 `{"error": "expired", "detail": "토큰 수명이 끝났다(포털 CHAT_PAT_TTL_S 또는 PAT 만료)"}`, 감사 줄은 `/mcp` 가 `unauthorized: expired`, `/api/` 가 `pat: expired` 다. 서명이 틀린 토큰은 `exp` 가 지났어도 만료로 치지 않는다(주장일 뿐이다). 수 시간짜리 심의에서 시작할 때 받은 챗 토큰이 도중에 끝나면 여기서 거절되고, 엔진은 그것을 보고 서비스 계정으로 넘긴다.

진행 중인 도구 호출은 끝날 때까지 감사 줄도 진행 알림도 없다(호출자에게는 15초마다 SSE ping 만 흐른다). 살아 있음은 호출자 쪽(엔진의 ping·상태줄)이 보인다. `/mcp` 세션에는 idle 한도를 두지 않는다 — 수 시간짜리 `deliberate_status` 폴링이 여기서 끊기지 않는 이유다.

그 **15초 ping** 은 sse-starlette 의 기본값이다(MCP SDK 는 간격을 따로 주지 않는다). 호출자들의 한도가 이 수에 기대어 있다 — 게이트웨이를 부르는 쪽의 httpx 침묵 한도는 15초보다 크면 죽은 게이트웨이만 잡고(포털 `upload.mcp_call` 의 timeout·절차 실행기 `CLIENT_TIMEOUT`, 리스크 앱 `HWAXRISK_SOURCE_CALL_TIMEOUT_S`·`ra_client.DEFAULT_TIMEOUT` — 값은 각 리포가 정본이라 여기 적지 않는다), 15초보다 작으면 그것이 실제 호출 상한이다(리스크 앱의 필드 근거 조회 `field_source.FIELD_TIMEOUT_S` 가 그 경우다). 15초를 넘는 '상한' 은 벽시계 기한으로 구현해야 걸린다. 게이트웨이는 에이전트 venv 로 뜨므로 그쪽 라이브러리를 올릴 때 이 전제를 다시 확인한다(시험이 건다).

## 크기 — 게이트웨이는 도구 결과를 자르지 않는다

운영 모델의 창은 1,048,576 토큰(GLM-5.2)이다. Claude 사용자는 이 게이트웨이를 거쳐 받은 결과로 심의하므로 여기서 잘리면 잘린 근거로 심의한다. 그래서 게이트웨이는 **생산자로서 자르지 않고**, 작은 창이 필요한 소비자(에이전트 서버의 웹 챗)가 자기 쪽에서 자른다(`TOOL_RESULT_MAX`).

- 백엔드 도구 결과(직접 호출·`invoke_tool`·캐시 적중)는 본문을 그대로 준다. 감사 줄의 `chars` 가 돌려준 결과의 글자 수다.
- `search_tools` 는 찾은 도구의 설명 전문과 인자 스키마 전부(`$defs` 포함)를, `list_tool_apps` 는 도구·앱 설명 전문을, `use_experts` 는 역할 문서 전문을, `rest_catalog` 는 경로의 인자(`params`)·본문(`body`) 스키마를 준다. `rest_call` 은 JSON 이 아닌 본문도 통째로 준다.
- 순위·목록은 이름을 먼저 싣는다 — `search_tools` 의 `ranked`(그다음 `truncated`·`note`, 전문 `matches` 는 맨 뒤), `list_tool_apps(app=)` 의 `tool_names`. 작은 창의 소비자가 앞에서부터 글자로 잘라도(dev 웹 챗 6,000자) 뒤 순위 도구가 '없다' 로 읽히지 않는다.
- `save_conversation` 은 포털 입력 한도(발언 20,000자·한 번에 200건 — 포털 `ConvMessageIn`·`ConvCreate` 가 정본, 시험이 대조한다)를 넘는 것을 버리지 않는다. 긴 발언은 `(긴 발언 나눔 k/N)` 로 이어 싣고, 200건 넘는 것은 덧붙이기로 보낸다. 도중에 멈추면 `CONV_PARTIAL:` 이다.

남는 상한 — 창이 아닌 까닭이 있는 것만 두고, 넘으면 말한다.

| 무엇 | 값 | 까닭 · 넘으면 |
|---|---|---|
| `GATEWAY_REST_CALL_MAX_BYTES` | 1,048,576 바이트 | 메모리 보호(120MB 응답에 피크 521MB 실측). 자르지 않고 **거부**하며 바이트·손잡이·좁히는 법을 말한다 |
| `GATEWAY_CACHE_ITEM_MAX_BYTES` · `GATEWAY_CACHE_MAX_BYTES` | 1,048,576 · 67,108,864 바이트 | 응답 캐시(300초)의 메모리 보호 — 결과는 자르지 않는다. 한 건이 앞의 값을 넘으면 그대로 돌려주되 캐시에 담지 않고(`/health` 의 `cache.too_big`), 담은 것의 합(`cache.bytes`)이 뒤의 값을 넘으면 오래된 것부터 버린다 |
| `EVID_MAX_CHARS` | 1,048,576 | `verify_answer` 근거 원장의 호출자 한 칸(원문이 아니라 숫자 줄기). 메모리 보호. 넘치면 오래된 조회부터 버리고 `evidence_trimmed` 로 말한다 |
| `EVID_MAX_CALLS` | 없음(0) | 적으면 건수 천장이다 — 낮출 때만 쓴다 |
| 결과 건수 `search_tools`·`browse_experts`·`rest_catalog` | 8(≤20)·40(≤200)·40(≤200) | 순위·목록이다. 넘으면 `truncated` 가 말한다 |
| `use_experts` 5명·앱 3·입구 도구 12 | — | 포털 `pinned_agents`·에이전트 서버 `_persona_meta` 와 같은 제품 규칙. 넘긴 것은 `dropped_keys`·`*_omitted` |
| 감사 `corr`·`note`·`error` | 120·120·200자 | 무기한 보존·한 호출 한 줄. 잘렸으면 `…(원문 N자)` 가 붙는다 |
| 대화 저장의 이름·제목 | 120·200자 | 포털 입력 한도. 응답 `clipped` 와 감사 `note` 에 남는다 |

## 인자 설명 점수판 — `/tools-map` 의 `arg_scores`

도구 인자에 설명이 거의 없다(2026-09-15 실측 — 468종의 인자 1,348개 중 15개, HWAXPortal `docs/procedures/gaps/hub-arg-descriptions.yaml`). 게이트웨이는 재집계마다 앱별로 세어 무인증 `/tools-map` 에 `arg_scores` 를 덧붙인다(있던 칸은 그대로다). **보고만 한다** — 막지도 숨기지도 않는다. 기준 모델은 LaminateAnalyzerMCP 의 '각 필드 description 에 단위와 유효 범위' 다.

- 인자는 `inputSchema.properties` 의 맨 위 키다. 객체 속성·배열 항목 안으로 내려가지 않는다(실측과 같은 눈금). 설명 있음은 그 속성의 `description` 이 공백 아닌 글일 때다(`title` 은 세지 않는다).
- 단위·범위 있음은 설명이 있고, 그 글에 단위(`mm`·`MPa`·`Hz`·`%`·`°`, 숫자 뒤의 `N`·`s`·`초`·`분` 등)나 범위(`범위`·`이상`·`이하`·`최소`·`최대`·`min`·`max`·`between`·`default`, 숫자에 붙은 부등호·`1~10`)가 들었거나 스키마가 `enum`·숫자 경계(`minimum`·`maximum`·`exclusive*`)를 가질 때다. 낱말의 정본은 `gateway.py` 의 `_ARG_UNIT_RANGE_RE` 다. 설명 없는 인자는 세지 않으므로 이 수는 설명 있음을 넘지 않는다.
- 게이트웨이 로컬 도구는 `_gateway` 앱으로 센다 — tools/list 가 붙이는 목록(`_local_tools`) 그대로라 REST 다리 둘은 사이트가 있을 때만 들어간다.
- 모양은 `{threshold, total: {apps, tools, args, described, unit_or_range, described_ratio, unit_or_range_ratio}, apps: [{app, tools, args, described, unit_or_range, described_ratio, unit_or_range_ratio, worst: [{tool, args, described}]}]}` 다. 앱은 설명 비율이 낮은 순(같으면 설명 없는 인자가 많은 순)이고 인자가 없는 앱(비율 `null`)은 맨 뒤다. `worst` 는 앱마다 최대 다섯 — 설명 없는 인자가 많은 순(같으면 인자가 많은 순)이고 설명이 다 있는 도구는 싣지 않는다. 수만 싣는다(인자 이름·설명·값은 없다).
- 기준은 `GATEWAY_ARG_DESC_WARN_RATIO`(기본 0.3, **미만**이면 부족 · 0 이면 끈다)다. 기동(첫 재집계) 때는 기준 미만 앱 수를 요약 한 줄(`인자 설명 부족 — 기동 때 붙은 앱 N개 가운데 M개가 …`)로만 남긴다 — 거의 모든 앱이 기준 아래라 앱마다 한 줄이면 기동마다 열댓 줄이 쌓인다. 기동 뒤 새로 붙는 앱은 붙을 때 한 줄(`인자 설명 부족 — <앱> 의 …`, 앱 이름·비율·가장 나쁜 도구)이다. 앱마다 프로세스당 한 번이고, 재프로비저닝은 게이트웨이를 다시 띄우므로 그때 다시 본다.

## search_tools 의미 순위 — 선택, 기본 꺼짐

`search_tools` 의 부분문자열 순위에 AIDataHub 임베딩 순위를 RRF(k=60)로 **더한다**(갈아 끼우지 않는다 — 한국어 업무어는 부분문자열이 이기는 사례가 있다). 켤지는 평가 결과를 보고 정한다 — 평가셋·러너·숫자는 `tool_search_eval/README.md`.

| 손잡이 | 기본 | 뜻 |
|---|---|---|
| `GATEWAY_TOOL_SEARCH_EMBED_URL` | 비어 있음(꺼짐) | AIDataHub `/api/embed` 의 주소(예 `http://127.0.0.1:8001/api/embed`). 비면 `search_tools` 의 답은 종전과 바이트 단위로 같고 임베더를 부르지 않는다 |
| `GATEWAY_TOOL_SEARCH_EMBED_TIMEOUT` | 2 | 질의 한 건의 임베딩 한도(초). 넘거나 임베더가 오류면 그 호출은 부분문자열 순위로 답한다. 0 이하는 따르지 않는다(끄려면 주소를 비운다) |

- 켜면 결과에 `mode` 가 붙는다 — `rrf`, 또는 못 섞었을 때 `substring` 과 까닭 `mode_reason`(색인이 덜 참 · 임베더 오류 · 시간 초과 · 차원이 바뀜).
- 색인은 도구마다 '앱 라벨 · 이름: 설명' 글의 해시로 두고 재집계 뒤 뒤에서 새 글만 임베딩한다(기동 직후 첫 색인 동안은 부분문자열로 답한다). 순위만 쓰고 코사인 값으로 거르지 않는다.
- 게이트웨이는 `.env` 를 읽지 않는다 — 띄우는 프로세스의 env 에 있어야 하고, 기동 로그의 `search_tools 의미 순위 켬` 줄로 닿았는지 본다.
- 실사용 질의 모으기(10-18 결정 21) — `search_tools` 질의를 이름 없이 `tool_search_eval/queries.local.jsonl` 에 30일 동안 남긴다(첫 줄 날짜부터, 그 뒤 저절로 멈춤). 끄기는 `GATEWAY_TOOL_QUERY_LOG=0`. 꼴과 쓰는 법은 `tool_search_eval/README.md` '실사용 질의'.

## 실행
```bash
./start.sh          # 에이전트 venv 파이썬으로 gateway.py 기동 (streamable-http :9110/mcp)
```
HWAXPortal `infra/services.yaml`에 `mcp-gateway`(tier 16)로 등록되어 오케스트레이터/재부팅이 관리한다(tier15 MCP들 다음, tier20 에이전트 이전). 에이전트는 `mcp_servers.json`에 게이트웨이 단일 엔트리(`{"gateway": {"url": "http://127.0.0.1:9110/mcp", "headers": {"Authorization": "Bearer <GW_TOKEN>"}}}`)만 둔다.

## 검증
```bash
# 게이트웨이 경유 도구 수 = 46 (RA 13 + SF 16 + MX 17), 무토큰/오토큰 401
curl -s http://127.0.0.1:9009/health | python3 -c "import sys,json;print(len(json.load(sys.stdin)['tools']))"
```
