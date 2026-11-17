<!-- 게이트웨이에 도구를 붙이거나 고칠 때 보는 도구 등록 점검표(HWAXPortal docs/request-1117 GW-04) -->
# 도구 등록 점검표

HWAXPortal `docs/request-1117` GW-04 — 사용자 결정은 **점검표 문서 + 읽기만 하는 훑기**다(관리자 도구 · 저장 없음). 훑기는 리포 루트의
`tool_registration_scan.py` 다.

## 배치 원칙

- **데이터를 가진 플랫폼이 함수를 갖는다.** 조회 · 계산 · 저장 · 보고의 함수는 그 데이터의 정본을 가진 앱에 둔다.
- **포털 · 게이트웨이는 노출 · 연결만 한다** — 찾기 · 부르기 · 권한 · 감사 · 카탈로그(도구 목록 · REST 표 · 적재 경로 공개). 계산하지 않고, 남의 데이터를
  저장하지 않고, 업로드를 받지도 나르지도 않는다(GW-01 사용자 결정 C3).
- **보고만 하는 함수는 데이터를 가진 플랫폼으로 돌려보낸다.** 다른 플랫폼의 데이터를 가져다 요약 · 표 · 그림 · 문서로 꼴만 바꿔 내는 함수는, 그
  데이터의 주인이 같은 함수를 갖고 게이트웨이는 그것을 노출만 한다. 두 곳에 같은 일이 있으면 숫자가 갈리고 어느 쪽이 맞는지 아무도 모른다.

## 점검 항목

새 도구를 붙이거나 바꿀 때 하나씩 본다. 걸리면 그 도구가 사는 앱의 세션에 요청한다(포털 · 게이트웨이에서 대신 짓지 않는다).

- [ ] **데이터 주인** — 이 도구가 읽고 쓰는 데이터의 정본이 이 앱인가. 아니면 주인 앱에 같은 함수를 요청하고, 이 도구는 걷거나 그 앱 도구를 부르게 한다.
- [ ] **보고만 하는 함수** — 다른 플랫폼의 데이터를 가져다 꼴만 바꿔 내는가. 그렇다면 주인 플랫폼으로 돌려보낸다.
- [ ] **게이트웨이 · 포털 자체 도구** — 노출 · 연결만인가(계산 · 저장 · 업로드 받기 없음).
- [ ] **읽기 · 쓰기 표지** — 앱이 `readOnlyHint` · `destructiveHint` 를 단다. 못 달면 게이트웨이 `read_tools.json`(박스는 `read_tools.local.json` —
  재기동 없이 먹는다, GW-02)에 읽기를 확인한 것만 더한다.
- [ ] **인자 설명** — 모든 인자에 설명(단위 · 범위). `/tools-map` 의 `arg_scores` 로 본다.
- [ ] **이름 · 앱 키** — 다른 앱과 겹치지 않게. 앱 키를 바꾸면 옛 키를 `app_keys.json` 의 `retired` 에 남긴다(옛 이름으로 부르면 새 이름을 안내한다 — GW-05).
- [ ] **환경** — 박스가 `app_keys.local.json` 에 그 앱의 `env`(`dev` · `prod` 둘뿐 — 사용자 결정 D5)를 적었나. 시험 사본이면 `canonical: false`.
- [ ] **큰 파일** — MCP 로 나르지 않는다. 앱이 적재 경로(바깥 경로 · 메서드 · 받는 자격 종류 · 크기 상한 · 포털 로그인 문)를 공식으로 밝히고,
  게이트웨이 `ingest_routes.json` 에 그 답을 싣는다(GW-01 — 짐작으로 채우지 않는다).
- [ ] **검색** — 그 데이터를 묻는 질의에서 주인 앱의 도구가 먼저 오는가. 아니면 먼저 그 앱의 도구 설명을 고친다(원천 고침). 박스 덧씌우기
  `search_tuning.local.json` 은 그다음이고, 고리는 cae00 에서 닫는다(잰 그 자리에서 고친다).
- [ ] **D1 — 낙하 · 부분 충격 해석 결과의 저장 · 조회는 DynaForge 만**(사용자 결정 D1, 11-17). Report Archive 의 분석 실행 도구
  `list_analysis_runs` · `get_analysis_summary` · `get_analysis_peaks` · `compare_analysis_runs` 는 '전각도 낙하 결과' · '낙하 해석 결과' · '부분 충격
  결과' 같은 질의에서 **1위가 아니어야 한다.** 훑기가 이 넷을 짚는다(질의 점검 D1). 게이트웨이의 기본 검색 순위(`search_tuning.json` 기본값)는 이 일로
  바꾸지 않는다.

## D1 — 박스 덧씌우기 제안(기본값은 그대로)

고칠 곳의 차례는 ① Report Archive 의 그 넷 도구 설명에 '낙하 · 부분 충격 해석 결과는 DynaForge 가 정본이다' 를 밝히고(그 리포 세션 몫) ② 그래도 cae00
에서 순위가 뒤집히지 않으면 박스 덧씌우기로 DynaForge 리포트 도구 쪽 낱말을 더한다. 예 — 값은 cae00 에서 `search_tools` 로 잰 뒤에 정한다.

```json
{
 "synonyms": {
  "낙하 결과": {"to": ["report_worst_cases", "report_summary", "sphere"], "owner": "heax-kooremapper_mcp", "source_fix": "Report Archive 분석 실행 도구 설명 — D1"},
  "부분 충격": {"to": ["impact", "report_part_risk"], "owner": "heax-kooremapper_mcp", "source_fix": "Report Archive 분석 실행 도구 설명 — D1"}
 }
}
```

추적 `search_tuning.json` 에는 이미 `낙하`(drop · impact · sphere) · `충격`(impact) · `전각도`(sphere · angle)가 DynaForge 몫으로 있다 — 위 둘은 그
위에 얹는 박스 값이다. 덧씌우기는 바뀐 시각으로 재기동 없이 먹고 `/health` 의 `search_tuning` 이 지문 · 건드린 칸을 보인다.

## 훑기 — `tool_registration_scan.py`

읽기만 한다(파일 · 원장 · 게이트웨이에 아무것도 쓰지 않고 감사 원장도 읽지 않는다). 앱마다 표 하나 — 도구 · 원래 이름 · 데이터 주인(추정) · 보고만
의심 · 까닭. 끝에 질의 점검(D1)과 옛 키로 아직 붙어 있는 앱(GW-05).

```bash
python3 tool_registration_scan.py                                  # 이 박스 게이트웨이(127.0.0.1:9110)의 /tools-map — 박스 안에서 돌린다
python3 tool_registration_scan.py --tools-map map.json --snapshot tool_search_eval/catalog.local.json --flagged
python3 tool_registration_scan.py --app reportarchive --format json
```

- `/tools-map` 은 무인증이고 포털 nginx 는 밖에서 막는다 — 박스 안에서 돌리거나 저장한 파일을 준다.
- 설명까지 보려면 `tool_search_eval/run.py snapshot` 이 뜬 스냅숏(`--snapshot`)을 함께 준다. 없으면 도구 이름 낱말만 본다.
- 규칙 — 주인은 사용자 결정으로 굳은 것만 바꾼다(지금은 D1). '보고만 의심' 은 보고 · 형식 낱말(report · summary · export · figure · 그림 · 발표 …)이 든
  도구가 게이트웨이 자체이거나 데이터 주인이 다른 앱일 때다. 낱말 규칙은 울타리가 아니다 — 짚은 것은 사람이 판정한다.
- 순위는 돌리지 않는다. D1 질의의 실제 1위는 cae00 에서 `search_tools(query=…)` 의 `ranked[0]` 이나 `tool_search_eval/run.py live` 로 잰다.
