# Semaphore 트리거 방식: Integration 웹훅인가 Actions에서 API 호출인가

- 질문: [#620](https://github.com/ppzxc/infra-automation/issues/620), 상위 map [#618](https://github.com/ppzxc/infra-automation/issues/618). 이 문서는 근거만 모은다. 결정은 사람이 하고(#626이 이 질문에 막혀 있다), `firewall-policy`와 `idc-access`는 같은 방식을 쓴다.
- 조사일: 2026-11-20
- 대상 버전
  - Semaphore: 운영 중인 **v2.19.12** (컨트롤 플레인 compose의 이미지 태그). 원격 러너 서비스와 `USE_REMOTE_RUNNER` 설정은 없어서 태스크는 서버 안의 로컬 실행기로 돈다.
  - Forgejo: 운영 버전은 확인하지 않았다. 소스는 `forgejo` 브랜치(2026-11-19 커밋)를 읽었다. 웹훅 서명 헤더는 오래된 동작이라 버전 차이가 작다고 보지만 대조는 하지 않았다.
- 1차 출처
  - Semaphore 문서(Context7 `/semaphoreui/semaphore-docs`): [Integrations][s-int], [CI/CD integration][s-cicd], [API][s-api], [Schedules][s-sched], [Repositories(monorepo)][s-repo], [Task environment][s-taskenv], [Alerts][s-alerts]
  - Semaphore 소스 `semaphoreui/semaphore` 태그 `v2.19.12`: `api/integration.go`, `db/Integration.go`, `db/Task.go`, `db/TaskParams.go`, `api/projects/tasks.go`, `services/tasks/TaskPool.go`, `services/tasks/TaskRunner.go`, `services/tasks/local_executor.go`, `db_lib/CmdGitClient.go`, `db/APIToken.go`, `db/ProjectUser.go`, `db/Schedule.go`, `services/schedules/SchedulePool.go`, `services/tasks/alert.go`, `api-docs.yml`
  - Forgejo 문서(Context7 `/git_codeberg_org/forgejo_docs`): [Webhooks][f-hooks], [Actions reference][f-ref], [Actions basic concepts(자동 토큰)][f-basic]
  - Forgejo 소스 `forgejo/forgejo`: `services/webhook/shared/payloader.go`(서명 헤더), `modules/structs/hook.go`·`pull.go`(페이로드 필드)
  - 저장소: ADR-0016, 맵 #618

## 표기 규칙

| 태그 | 의미 |
|---|---|
| **출처** | 위 문서에 문장으로 적힌 내용 |
| **소스** | v2.19.12(Semaphore) 또는 Forgejo 소스 코드를 읽어 확인한 동작. 실행해 보지는 않았다 |
| **추론** | 출처와 소스에서 끌어낸 판단 |
| **권고** | 이 조사의 제안. 사람이 뒤집을 수 있다 |

## 핵심 답변

1. **두 방식 모두 Semaphore 공식 경로다.** 문서는 외부 CI에서 태스크를 시작하는 방법으로 Integrations와 REST API 두 가지를 나란히 적는다(출처 [s-cicd]).
2. **특정 커밋 고정은 (b) REST에서만 된다. 단, 문서에 없는 필드다.** `POST /api/project/{id}/tasks` 본문을 `db.Task` 구조체로 그대로 받으므로 `"commit_hash"`를 넣으면 저장되고, 실행기가 브랜치를 pull한 뒤 `git checkout <hash>`를 한다(소스). 이 필드는 `api-docs.yml`의 요청 스키마에 없고 UI의 "다시 실행" 기능용이다(소스). (a) Integration은 커밋을 고정할 수 없다. 추출 값은 extra vars나 `params`로만 들어가고 `TaskParams`에 커밋 필드가 없다(소스). ADR-0016 Consequences의 "Semaphore가 커밋 해시를 직접 체크아웃하는지 확인하지 못했다"에 대한 답은 "REST로는 되지만 비공식"이다.
3. **PR 번호·병합 커밋 전달은 둘 다 된다.** (a)는 값 추출기(JSON 경로)로, (b)는 요청 본문의 `environment`(JSON 문자열)로 넘긴다. 두 경로 모두 결국 **Ansible extra vars**(가장 높은 우선순위)가 된다(소스).
4. **결과를 Forgejo 커밋 상태로 되돌리는 기능은 Semaphore에 없다.** 알림 채널은 Telegram·Slack·Email·Teams·Rocket.Chat·DingTalk·Gotify뿐이다(출처 [s-alerts], 소스). (a)는 플레이북이 직접 Forgejo 상태 API를 호출해야 하고, (b)는 Actions 작업이 태스크를 폴링하면 그 작업의 성공·실패가 Forgejo에 그대로 표시된다(추론).
5. **토큰 범위는 (b)의 가장 큰 약점이다.** Semaphore API 토큰은 사용자 단위이고 만료일 외에 범위 제한이 없다. `task_runner` 역할만 줘도 프로젝트의 **모든 템플릿**을 실행할 수 있고, 템플릿 설정과 무관하게 `playbook`·`commit_hash`·extra vars를 바꿔 넣을 수 있다(소스). 그 토큰은 Forgejo Actions 시크릿에 들어가며, 포크가 아닌 같은 저장소의 브랜치·PR 워크플로에는 시크릿이 노출된다(출처 [f-ref]). (a)의 서명 비밀은 저장소 관리자만 보는 웹훅 설정에 있다.
6. **cron은 Semaphore가 직접 한다.** 표준 5필드 cron과 시간대, 한 번만 실행(`run_at`), 그리고 "저장소 브랜치 HEAD가 바뀌었을 때만 실행"하는 스케줄이 있다(출처 [s-sched], 소스). 마지막 것은 웹훅 없이 병합을 감지하는 세 번째 방법이 될 수 있다(§4).
7. **권고(사람 결정의 입력)**: ADR-0016 전제대로 **(a) Integration을 유지하되**, 커밋 고정은 ADR-0016의 대안(적용 직전 `main` HEAD와 웹훅 커밋 비교)으로 하고 결과 보고는 플레이북이 한다. (b)로 가려면 별도 Semaphore 프로젝트·전용 봇 사용자·`main` 전용 워크플로 보호가 전제다. 자세한 비교와 장단점은 §5에 있다.

## 1. (a) Forgejo 웹훅 → Semaphore Integration

### 1.1 동작 (v2.19.12)

| 항목 | 내용 | 태그 |
|---|---|---|
| 엔드포인트 | `/api/integrations/<alias>`, GET·POST. 프로젝트 alias 하나와 integration별 alias가 있다 | 출처 [s-int] |
| 인증 방식 | v2.19.12 상수는 `github`·`token`·`hmac`(SHA-256)·`bitbucket`·`basic`·없음. **문서가 말하는 `hmac-sha512`는 v2.19.12에 없다**(문서가 더 새 버전 기준) | 소스 `db/Integration.go` |
| `github` 방식 | `X-Hub-Signature-256` 헤더에서 `sha256=` 접두어를 떼고 본문의 HMAC-SHA256 hex와 비교한다. 비밀은 키 저장소 login/password 항목의 password | 소스 `api/integration.go` |
| `hmac` 방식 | 설정한 헤더 값(접두어 없음)을 HMAC-SHA256 hex와 비교한다 | 소스 |
| Forgejo가 보내는 서명 | 같은 HMAC-SHA256을 `X-Forgejo-Signature`·`X-Gitea-Signature`·`X-Gogs-Signature`(소문자 hex, 접두어 없음)와 `X-Hub-Signature-256`(`sha256=` 접두어)로 보낸다. SHA-1은 `X-Hub-Signature` | 소스 `payloader.go` |
| 호환 결론 | Forgejo 웹훅은 Semaphore의 `github` 방식으로도, `hmac` 방식 + `X-Forgejo-Signature` 헤더로도 검증된다 | 추론 |
| 매처 | 헤더 또는 본문(JSON 경로나 문자열 전체)을 `equals`·`unequals`·`contains`로 비교한다. 값은 `fmt.Sprintf("%v")` 문자열로 비교하므로 JSON `true`는 `"true"`, 정수는 `"12"`로 맞춘다 | 소스 |
| 매처 결합 | 여러 매처는 **AND**다. **프로젝트 alias에서 매처가 0개인 integration은 절대 실행되지 않는다**(`matched` 초기값이 false). **integration 전용 alias로 받으면 매처를 아예 평가하지 않는다** | 소스. 문서는 "전용 alias는 매처 없이 시작"까지만 적는다 [s-int] |
| 값 추출기 | 헤더 또는 본문(JSON 경로/문자열 전체)에서 값을 꺼낸다. 변수 종류 `environment`는 태스크 `Environment` JSON에, `task`는 태스크 `params` 맵에 들어간다 | 출처 [s-int] + 소스 |
| "environment"의 실제 의미 | 문서는 "environment variables"라고 쓰지만 소스에서는 태스크 `Environment` JSON이 변수 그룹의 JSON(extra vars)과 병합돼 **Ansible extra vars**가 된다. 셸 환경 변수가 아니다 | 소스 `TaskRunner.populateTaskEnvironment`, `local_executor.getEnvironmentExtraVars` |
| 고정 매개변수 | integration마다 `task_params`(브랜치·인벤토리·메시지·extra vars·params)를 고정할 수 있다. **커밋 필드는 없다** | 소스 `db/TaskParams.go` |
| 응답 | 인증 실패·매처 불일치·성공 모두 **HTTP 204**다. 태스크가 만들어졌을 때만 `X-Semaphore-Task-ID` 등 응답 헤더가 붙는다. Forgejo 전송 기록의 "성공"은 태스크 실행의 증거가 아니다 | 소스 |

### 1.2 Forgejo 쪽 페이로드

| 이벤트 | 쓸 만한 필드 | 태그 |
|---|---|---|
| push | `ref`(예: `refs/heads/main`), `after`(푸시 후 HEAD 커밋), `head_commit` | 소스 `modules/structs/hook.go` |
| pull_request | `action`(`closed` 등), `pull_request.number`, `pull_request.merged`(bool), `pull_request.merge_commit_sha` | 소스 `modules/structs/pull.go` |
| 헤더 | `X-Forgejo-Event`(`push`, `pull_request` 등), `X-Forgejo-Delivery` | 소스 + 출처 [f-hooks] |
| 웹훅 브랜치 필터 | 웹훅 설정에 `branch_filter`(glob)가 있어 `main`만 보내게 할 수 있다 | 소스 `hook.go` |

예시 구성(추론): pull_request 웹훅 하나 + 매처 3개(`X-Forgejo-Event` equals `pull_request`, `action` equals `closed`, `pull_request.merged` equals `true`) + 추출기 2개(`pull_request.number` → `pr_number`, `pull_request.merge_commit_sha` → `merge_commit`). 매처를 쓰려면 프로젝트 alias로 받아야 한다.

## 2. (b) Forgejo Actions → Semaphore REST API

| 항목 | 내용 | 태그 |
|---|---|---|
| 호출 | `POST /api/project/{project_id}/tasks`, `Authorization: Bearer <토큰>`, 본문 `{"template_id": N, "message": "..."}`. 응답(201)에 태스크 ID가 있고 `GET /api/project/{id}/tasks/{task_id}`의 `status`가 `success`·`error`·`stopped`가 될 때까지 폴링한다 | 출처 [s-cicd], [s-api] |
| 넘길 수 있는 필드 | 본문은 `db.Task`로 바인딩된다. `environment`(JSON 문자열 → extra vars), `message`, `git_branch`, `playbook`, `inventory_id`, `params`(limit·tags 등), 그리고 문서에 없는 `commit_hash` | 소스 `api/projects/tasks.go` `NewTaskMiddleware` |
| 커밋 고정 | `commit_hash`가 있으면 실행기가 브랜치를 pull한 뒤 `git checkout <hash>`를 한다. 없으면 브랜치 HEAD를 쓰고 그 해시를 태스크에 기록한다 | 소스 `local_executor.checkoutRepository` |
| 커밋 고정의 한계 | ① `api-docs.yml` 요청 스키마에 없어 업그레이드 때 깨질 수 있다. ② 같은 템플릿의 병렬 태스크는 작업 트리를 공유한다(소스 주석: "parallel tasks pinned to different commits still share the working tree"). 연속 병합이 겹치면 서로의 체크아웃을 덮을 수 있다. ③ monorepo 저장소 모드에서는 브랜치·커밋 선택이 막힌다고 문서가 적는다 | 소스 + 출처 [s-repo] |
| 브랜치 덮어쓰기 | `git_branch`는 템플릿의 `allow_override_branch_in_task`가 켜져 있을 때만 반영된다 | 소스 `resolveGitBranch` |
| 덮어쓰기 제한이 없는 필드 | `playbook`(저장소 밖 경로만 막음), `commit_hash`, `environment`(extra vars)는 템플릿 허용 설정과 무관하게 반영된다 | 소스 `getPlaybookArgs`, `ValidatePlaybookPath` |
| Forgejo Actions에서 호출 | `run:` 단계에서 `curl`로 호출하고 토큰은 `${{ secrets.X }}`로 읽는다. PR 번호는 `forgejo.event.pull_request.number`, 커밋은 `forgejo.sha` 등 컨텍스트로 얻는다 | 출처 [f-ref] |
| 결과 표시 | 워크플로 작업의 성공·실패가 Forgejo에 커밋 상태로 보인다. 태스크가 끝날 때까지 폴링하면 그 결과가 곧 상태가 된다. 대신 폴링하는 동안 러너 하나를 점유한다 | 추론 |

## 3. 비교 항목별 정리

| 비교 항목 | (a) Integration 웹훅 | (b) Actions → REST |
|---|---|---|
| PR 번호·병합 커밋 전달 | 추출기(JSON 경로)로 extra vars에. 고정 형태 필드만 추출한다(제목·브랜치 이름 같은 자유 문자열은 extra vars 주입 위험) | 본문 `environment`로 extra vars에. 워크플로가 값을 조립한다 |
| 특정 커밋 체크아웃 | **불가.** 브랜치 HEAD를 쓴다. ADR-0016의 대안(적용 직전 HEAD와 웹훅 커밋 비교, 다르면 중단)이 필요하다 | **가능하지만 비공식**(`commit_hash`, 문서 없음). 병렬 태스크 작업 트리 공유 주의 |
| 결과 → Forgejo 커밋 상태 | Semaphore 기능 없음. 플레이북이 시작·종료 시 Forgejo 상태 API(`POST /repos/{owner}/{repo}/statuses/{sha}`)를 직접 호출해야 한다. **플레이북 시작 전 실패(체크아웃·OpenBao 인증·인벤토리)는 보고되지 않는다** | 작업 결과가 그대로 상태가 된다. Semaphore 쪽 실패도 폴링 결과로 잡힌다 |
| 실패 가시성 | 웹훅 응답이 항상 204라 서명 불일치·매처 불일치를 Forgejo에서 알 수 없다. Semaphore 서버 로그에만 남는다 | HTTP 오류(401·400·500)가 작업 실패로 바로 보인다 |
| 정기 실행(cron) | Semaphore 스케줄(둘 다 같음) | Semaphore 스케줄. Actions의 `schedule`도 있지만 맵 #618은 스케줄을 Semaphore에 둔다 |
| 비밀 위치 | 웹훅 서명 비밀 1개(Forgejo 웹훅 설정 + Semaphore 키 저장소) | Semaphore API 토큰(Forgejo Actions 시크릿 + Semaphore 사용자) |
| 비밀이 주는 권한 | 그 integration이 가리키는 템플릿 하나를, 고정 매개변수 + 추출 값으로만 실행 | 토큰 사용자가 속한 프로젝트의 모든 템플릿을 임의 playbook·커밋·extra vars로 실행 |
| 비밀 노출면 | 저장소 관리 권한자만 웹훅 설정을 본다. `branch_filter`로 `main`만 보낼 수 있다 | 같은 저장소에 브랜치를 푸시할 수 있는 사람은 시크릿을 쓰는 워크플로를 PR로 바꿔 실행할 수 있다(포크만 차단). 리뷰 없는 실행 경로가 생긴다 |
| 추가 구성 요소 | 없음(Forgejo → Semaphore 네트워크 경로만) | Forgejo Runner 필요(운영 여부 미확인), 폴링 스크립트 |
| ADR-0016과의 관계 | 그대로 | ADR-0016 결정 2(흐름)를 개정해야 한다 |

## 4. 세 번째 후보: 저장소 변경 감시 스케줄

| 항목 | 내용 | 태그 |
|---|---|---|
| 기능 | 스케줄에 저장소를 지정하면, cron 시각마다 `git ls-remote`로 저장소 브랜치 HEAD를 보고 직전 실행 때와 **달라졌을 때만** 태스크를 만든다 | 소스 `SchedulePool.tryUpdateScheduleCommitHash` |
| cron 문법 | robfig/cron `ParseStandard`(5필드: 분 시 일 월 요일), 서버 시간대 적용. 한 번만 실행하는 `run_at` 유형도 있다 | 출처 [s-sched] + 소스 |
| 장점 | 들어오는 엔드포인트·비밀이 없다. Forgejo 쪽 설정이 없다 | 추론 |
| 한계 | 지연(최소 1분 주기), PR 번호를 모른다(커밋만), 감지한 해시로 태스크를 고정하지 않는다(실행 시점 HEAD를 다시 pull). 여러 병합이 한 주기 안에 겹치면 마지막 것만 실행한다 | 소스 + 추론 |
| 쓸 곳 | 트리거보다는 "웹훅이 유실돼도 결국 적용된다"는 보조 경로나 드리프트 보고 주기 실행 | 권고 |

## 5. 권고와 장단점 (사람 결정의 입력)

두 방식을 가르는 조건은 둘이다. **커밋 고정**은 (b)가 유리하고, **비밀 노출과 리뷰 우회**는 (a)가 유리하다.

**권고: (a) Integration 유지.** 이유:

1. ADR-0016의 전제("병합이 곧 운영 변경, `main` 보호와 병합 리뷰 필수")를 지키는 데 (a)가 더 맞다. (b)의 Semaphore 토큰은 범위를 좁힐 수 없고, 같은 저장소 브랜치의 워크플로가 시크릿을 쓸 수 있어 리뷰 없이 적용 템플릿을 부를 수 있다.
2. 커밋 고정은 ADR-0016이 정한 대안으로 충분하다. 웹훅의 `merge_commit_sha`(또는 push `after`)를 extra var로 받고, 플레이북 첫 태스크에서 체크아웃된 커밋(`semaphore_vars`의 `task_details.commit_hash`, 셸 앱은 `SEMAPHORE_TASK_DETAILS_COMMIT_HASH`, 출처 [s-taskenv])과 비교해 다르면 실패한다. 연속 병합 때 앞선 태스크가 실패하는 것은 의도된 동작(마지막 병합만 적용)으로 볼 수 있다.
3. 결과 보고는 플레이북의 `always` 블록에서 Forgejo 상태 API를 호출한다. 토큰은 OpenBao `secrets/`에 두고 계열 AppRole로 읽는다. 플레이북 시작 전 실패는 Semaphore 알림(이메일)과 보조 스케줄(§4)로 메운다.
4. 구성 요소가 적다. Forgejo Runner가 없어도 된다.

**(b)를 택한다면 필요한 전제**:

- idc-access·firewall-policy 전용 Semaphore 프로젝트를 따로 만들고, 그 프로젝트에만 `task_runner`인 봇 사용자와 만료일 있는 토큰을 쓴다.
- 토큰을 쓰는 워크플로는 `on: push: branches: [main]`만 쓰고, 브랜치 보호로 `main` 푸시를 병합으로만 제한한다. 그래도 PR 브랜치의 워크플로 수정으로 시크릿에 닿는 경로는 남는다(Forgejo는 포크만 차단).
- `commit_hash`가 비공식 필드라는 점을 업그레이드 점검 항목에 넣는다.
- ADR-0016 결정 2를 개정한다.

**혼합안**(참고): 트리거는 (a)로 하고, PR 단계의 검증·렌더링 diff는 Actions에서 Semaphore를 부르지 않고 저장소 안에서 끝낸다. 이 경우 Semaphore 토큰이 Actions에 들어가지 않는다.

## 6. 확인하지 못한 것

- 운영 Forgejo 버전과 Forgejo Runner 운영 여부.
- `commit_hash` 고정을 실제로 실행해 보지 않았다(소스만 읽음). 원격 러너 경로의 동작도 보지 않았다(운영은 로컬 실행기).
- 프로젝트 alias에서 `pull_request.merged` 같은 bool 값 매칭을 실제 Forgejo 페이로드로 시험하지 않았다(소스상 `"true"` 문자열 비교).
- Semaphore 업그레이드 시 `hmac-sha512` 등 문서에만 있는 기능이 들어오는 버전.

[s-int]: https://github.com/semaphoreui/semaphore-docs/blob/main/docs/user-guide/integrations.md
[s-cicd]: https://github.com/semaphoreui/semaphore-docs/blob/main/docs/admin-guide/cicd.md
[s-api]: https://github.com/semaphoreui/semaphore-docs/blob/main/docs/reference/api.md
[s-sched]: https://github.com/semaphoreui/semaphore-docs/blob/main/docs/user-guide/schedules.md
[s-repo]: https://github.com/semaphoreui/semaphore-docs/blob/main/docs/user-guide/repositories.md
[s-taskenv]: https://github.com/semaphoreui/semaphore-docs/blob/main/docs/reference/task-environment.md
[s-alerts]: https://github.com/semaphoreui/semaphore-docs/blob/main/docs/user-guide/alerts.md
[f-hooks]: https://codeberg.org/forgejo/docs/src/branch/next/docs/user/repository/webhooks.md
[f-ref]: https://codeberg.org/forgejo/docs/src/branch/next/docs/user/actions/reference.md
[f-basic]: https://codeberg.org/forgejo/docs/src/branch/next/docs/user/actions/basic-concepts.md
