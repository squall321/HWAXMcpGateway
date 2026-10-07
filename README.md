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

- 모으는 곳 — 백엔드 `url` · `heax_registry.per_user_sso.*.sso_url` · `rest.*.base` · `portal.api_base`·`jwks_url`·`revoked_url` · `heax_registry.servers_url`·`base`. 레지스트리로 뒤늦게 발견되는 앱은 발견할 때 같은 함수로 더한다. `127.0.0.1`·`localhost`·`::1` 은 늘 넣는다.
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
게이트웨이가 서비스의 `POST /api/auth/sso` 에 공유 비밀(`X-Heax-Gateway-Secret`)과 호출자 이메일을 보내 **그 사람 토큰**을 받아 그 명의로 부른다. 토큰은 12시간 캐시하되 응답의 `expires_in` 이 더 짧으면 그보다 2분 먼저 버린다. 백엔드가 401 이면 한 번 다시 받고, 받지 못하면 거부한다(서비스 계정으로 강등하지 않는다). 포털은 토큰을 쥐지 않는다.

- 항목 `{sso_url, secret, client, strip_headers?}` — `strip_headers` 는 서비스 계정 설정에만 맞는 헤더를 사람별 호출에서 뺀다(RA 의 `X-Workspace-Slug`: 서비스 부서가 남으면 남의 부서로 읽고 쓴다).
- `per_user_sso` 가 포털 등록 연결(`PORTAL_CONN_BACKENDS`, 포털 '개인 토큰 › 외부 연결' 의 RA·TestScope 토큰)보다 **먼저**다 — 위임이 켜진 서비스는 등록 토큰을 쓰지 않는다.
- `provision-config.sh` 가 env 로 만든다. 순서는 env > 직전 config > 기본값이고, 비밀이 없는 실행은 직전 항목을 지우지 않고 이어받는다. 운영에서는 update-all 이 포털 `infra/.env` 에서 읽어 넘긴다(HWAXPortal `docs/sso-delegation`).

| env | 만드는 것 |
|---|---|
| `STE_SSO_SECRET` · `STE_SSO_URL` | `per_user_sso.ste` |
| `RA_SSO_SECRET` · `RA_SSO_URL`(기본 `http://127.0.0.1:3000/api/auth/sso`) | `per_user_sso.reportarchive` + `strip_headers: ["X-Workspace-Slug"]`. 서비스 백엔드(`RAT_TOKEN`)는 그대로 — 도구 목록은 그 세션으로 모은다 |
| `TESTSCOPE_SSO_SECRET` · `TESTSCOPE_SSO_URL`(기본 없음 — 운영에서는 포털이 `TESTSCOPE_BASE_URL` 에서 유도해 넘긴다) | `per_user_sso.testscope`(부서 헤더가 없어 `strip_headers` 없음). 주소를 모르면 만들지 않고 생략을 로그에 남긴다 |
| `PER_USER_SSO_APPS`(공백 구분 `<per_user 키>:<ENV 접두>`, 예 `newapp:NEWAPP`) + `<접두>_SSO_SECRET` · `<접두>_SSO_URL`(기본 없음) | `per_user_sso.<키>` = `{sso_url, secret, client: "gateway", managed_by: "PER_USER_SSO_APPS"}` — 이 모양의 앱은 `provision-config.sh` 를 고치지 않고 붙는다. `managed_by` 는 이 순회가 쓴 항목이라는 표지다(게이트웨이는 읽지 않는다 — 목록에서 뺀 앱을 끌 때 가린다). 규칙은 TestScope 와 같고(env > 직전 config 주소, 주소를 모르면 만들지 않고 로그에 남긴다, 비밀 없는 실행은 이어받는다), 손으로 붙여 둔 필드(`strip_headers` 등)는 남는다. 스크립트가 직접 만드는 다섯 키(`kooremapper_mcp`·`hwax_risk`·`ste`·`reportarchive`·`testscope`)와 못 읽은 쌍은 건너뛰고 그 사실을 로그에 남긴다 |
| `PER_USER_SSO_OFF`(공백 구분 `reportarchive`·`testscope` — HWAXPortal update-all 이 infra/.env 의 빈 비밀을 보고 넘긴다 — 와 일반 앱의 키) | 그 위임 항목을 지운다(토큰 등록으로 되돌리기 — 일반 앱은 등록 토큰 길이 없어 서비스 계정으로 나간다). 비밀 없는 손 실행은 직전 값을 이어받으므로 끄는 길은 이것뿐이다. 비밀이 같이 오면 끄지 않는다. 일반 앱은 두 경우에 꺼진다 — 그 실행의 `PER_USER_SSO_APPS` 에 쌍이 있고 비밀이 비었을 때, 또는 쌍째 빠졌고 항목에 `managed_by` 표지가 있을 때(앱을 걷으며 줄을 지운 경우). 어느 쪽이든 이름이 와야 한다 — 목록이 비었다고 스크립트가 스스로 지우지는 않는다(손 실행에는 목록이 없다). 넘기는 쪽은 provision.env 를 읽은 호출자다(update-all, 손으로는 `PER_USER_SSO_OFF=<키>` 를 주고 `--force`). 표지 없는 항목(손으로 붙인 위임, `ste`·`hwax_risk` 등)은 이름이 와도 지우지 않는다 |

## 등록 토큰 방식 — `PORTAL_CONN_BACKENDS`(RA·TestScope)
사람이 그 서비스에서 직접 받은 개인 토큰을 포털 '개인 토큰 › 외부 연결'(`/tokens?tab=connect`)에 등록하면, 게이트웨이가 호출 때 포털 `GET /internal/connections/<service>?email=`(GW_TOKEN)로 그 토큰을 읽어 그 사람 명의로 부른다. 신원이 있는데 등록이 없거나 포털에 묻지 못하면 **거부**하고 등록을 안내한다(서비스 계정으로 대신 부르지 않는다). 신원 없는 내부 호출만 서비스 세션으로 간다.

| 백엔드 | 토큰 | 부서 헤더 |
|---|---|---|
| `reportarchive` | `rat_…` | 등록한 워크스페이스를 `X-Workspace-Slug` 로(비면 서비스 값을 지운다) |
| `testscope` | `tsc_pat_…`(TestScope 에서 발급, `/api/auth/me` 를 부르려면 `read` 범위) | 싣지 않는다 |

TestScope 는 다른 조직의 포털(제 주소로 노출)이라 RA 처럼 두 방식 중 하나로 붙는다 — TestScope 코드는 여기서 손대지 않는다. **기본(`TESTSCOPE_SSO_SECRET` 없음)** 은 이 등록 토큰 길이고, **비밀이 있으면** `per_user_sso.testscope` 가 생겨 위 우선순위대로 그쪽이 먼저 탄다(등록할 것 없음). 위임은 TestScope 가 `POST /api/auth/sso`(위 계약)를 갖춘 뒤에만 켠다 — 그 전에 비밀이 생기면 발급이 실패해 신원 있는 TestScope 호출이 전부 거부되고 등록 토큰으로 돌아가지 않는다. 그래서 비밀은 자동으로 만들지 않고 사람이 넣는다. 백엔드는 두 방식이 같다 — `provision-config.sh` 가 `TESTSCOPE_MCP_URL`(> 직전 config 주소)로 만든다(`streamable_http`, 서비스 `Authorization` 없음 — tools/list 는 토큰 없이 된다). 기본 호스트가 없어 주소를 모르면 만들지 않는다.

## 시간 한도 — 손잡이는 전부 프로세스 env, 기본값은 코드
게이트웨이는 `.env` 를 읽지 않고 HWAXPortal `infra/services.yaml` 의 `mcp-gateway` 항목도 env 를 넘기지 않는다 — **`gateway.py` 의 기본값이 곧 운영값**이다. 바꾸려면 `start.sh` 를 부르는 환경에 export 한다(값은 초).

원칙은 셋이다. ① 안쪽 한도가 그것을 감싸는 한도보다 작다. ② 느린 도구(시간 초과)와 죽은 상대(연결 실패)를 가른다 — 시간 초과는 **한 번으로 끝내고**(재시도·세션 교체·토큰 재발급 없음) 연결 실패만 한 번 다시 건다. ③ 만료 문구는 몇 초였고 어느 손잡이인지 말한다.

| env | 기본 | 무엇을 재나 | 걸리면 |
|---|---|---|---|
| `GATEWAY_CALL_TIMEOUT` | 600 | 백엔드 도구 호출 1건(상주 세션·사람별·등록 토큰·신원 전달 네 길 공통) | `backend <키>: <도구> 이 600초 안에 답하지 않았다(GATEWAY_CALL_TIMEOUT)…` — 도구는 한 번만 불렸고 세션은 그대로다. 백엔드는 아직 일하고 있을 수 있다 |
| `GATEWAY_RECONNECT_TIMEOUT` | 30 | 죽은 상대 — 단발 세션의 핸드셰이크(connect + initialize)와, 연결 실패 뒤 상주 세션이 돌아오기를 기다리는 시간 | `backend <키> unavailable: 30초 안에 세션을 열지 못했다(GATEWAY_RECONNECT_TIMEOUT)` · `… unavailable: 30초 안에 돌아오지 않았다(…)` — 죽은 상대라 머리에 `unavailable:` 를 남긴다(포털 절차 판정기가 이 머리로 '불통' 을 가른다). 느린 도구의 문구에는 붙이지 않는다 |
| `GATEWAY_BACKEND_READ_TIMEOUT` | 호출 한도 + 60 | 백엔드 세션 아래 HTTP read 침묵(MCP SDK 의 숨은 300초에 이름을 붙였다) | 호출 한도가 먼저 걸리므로 위 문구가 나온다. 호출 한도보다 크지 않게 적으면 따르지 않고 기본값을 쓴다(기동 로그에 경고) — 이것이 먼저 걸리면 세션째 끊긴다 |
| `GATEWAY_BACKEND_HTTP_TIMEOUT` | 30 | 같은 세션의 connect·write·pool | 연결 실패로 다뤄진다(한 번 다시 건다) |
| `GATEWAY_LIVENESS_TIMEOUT` | 10 | 생사 탐침 — 재활 패스(`GATEWAY_REVIVE_INTERVAL`, 60초)마다 연결된 백엔드에 보내는 `list_tools` 한 번 | 아래 횟수만큼 **연속으로** 놓치면 세션을 간다 |
| `GATEWAY_LIVENESS_STRIKES` | 2 | 탐침 무응답을 몇 번 연속 놓쳐야 세션을 가는가. 한 번으로 갈면 이벤트 루프가 잠깐 바쁜 건강한 백엔드의 진행 중인 답을 버린다. 예외로 실패한 탐침(세션 종료·연결 거부)은 종전대로 한 번에 간다 | 세션을 갈 때 그 세션에 걸린 진행 중 호출을 곧바로 실패로 돌려준다 — `backend <키> 가 탐침에 2회 연속 답하지 않아 세션을 갈았다(GATEWAY_LIVENESS_TIMEOUT × GATEWAY_LIVENESS_STRIKES) — <도구> 의 실행 여부는 모른다`. 죽은 백엔드는 약 2분 안에 호출자를 놓아 준다(단발 세션의 호출은 건드리지 않는다) |

층 — 핸드셰이크·재연결 30 < 호출 600 < 전송 read·단발 세션 바깥 기한 660(= 30 + 600 + 30) < 엔진 `MCP_CALL_TIMEOUT_S` 900 < nginx `/mcp-gw/` 3600. 포털 절차 워밍업(690)도 660 바깥이다. **`GATEWAY_CALL_TIMEOUT` 을 올리면 엔진·포털 워밍업·nginx 셋을 같은 폭으로 올린다**(전송 read 와 단발 세션 바깥 기한은 스스로 따라 오른다). 안쪽(백엔드 자신의 한도 — KooRemapper MCP→REST 240, AIDataHub 풀 60 + 검색 90 등)은 600 보다 작아야 한다. HWAXPortal 절차 시험(`test_procedures_census`)이 `gateway.py` 의 기본값을 읽어 30~600 으로 묶으므로 600 을 넘기려면 그 상한부터 고친다. 600 으로도 모자란 도구는 한도를 올리지 말고 잡 도구(제출 + 상태 조회)로 돌린다 — 이 값이 호출 중 죽은 무상태 백엔드에서 호출자를 풀어 주는 마지막 값이다.

진행 중인 도구 호출은 끝날 때까지 감사 줄도 진행 알림도 없다(호출자에게는 15초마다 SSE ping 만 흐른다). 살아 있음은 호출자 쪽(엔진의 ping·상태줄)이 보인다.

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
