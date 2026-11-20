# Forgejo로 계정 원장 흐름을 어디까지 할 수 있는가

- 질문: [#619](https://github.com/ppzxc/infra-automation/issues/619), 상위 map [#618](https://github.com/ppzxc/infra-automation/issues/618). 이 문서는 근거만 모은다. 설계 결정은 map의 다른 티켓이 내린다.
- 조사일: 2026-11-20
- 기준 버전: Forgejo v17.0(문서 `latest` = v17.0.2, 소스·swagger는 태그 `v17.0.0`). 운영 인스턴스의 버전·설정은 이 문서에 적지 않는다(공개 저장소 규칙).
- 1차 출처
  - Forgejo 문서(Context7 `/git_codeberg_org/forgejo_docs` + 원문): [config cheat sheet `[oauth2_client]`][fj-cheat], [CLI `admin auth`][fj-cli], [OIDC group mappings][fj-groupmap], [Token scope][fj-scope], [Actions reference][fj-act-ref], [Actions basic concepts — Secrets][fj-act-basic], [Actions security (사용자)][fj-act-sec-user], [Actions security (관리자)][fj-act-sec-admin], [Webhooks][fj-webhook], [AGit][fj-agit]
  - Forgejo 소스(태그 `v17.0.0`): [`templates/swagger/v1_json.tmpl`][fj-swagger], [`routers/private/hook_pre_receive.go`][fj-hook], [`routers/web/auth/oauth.go`][fj-oauth], [`routers/api/v1/admin/user.go`][fj-adminuser], [`routers/api/v1/user/key.go`][fj-key], [`services/auth/sync.go`][fj-sync], [`services/auth/source/oauth2/`][fj-oauth2src], [`options/locale/locale_en-US.ini`][fj-locale]
  - Forgejo 릴리스 노트(`release-notes-published/<버전>.md`, v10.0.0~v17.0.0)
  - Gitea CHANGELOG([1.18][gitea-118], [1.19][gitea-119]). Forgejo는 Gitea 1.18에서 갈라져 나왔으므로 그 전에 들어온 기능은 Forgejo 첫 버전부터 있다
  - Google: [OpenID Connect (ID token claims)][g-oidc]
  - [markbates/goth `providers/openidConnect`][goth] (Forgejo OAuth2 로그인이 쓰는 라이브러리)
  - 저장소: [ADR-0016](../adr/0016-firewall-policy-gitops-private-repository.md)(트리거 선례)

## 표기 규칙

| 태그 | 의미 |
|---|---|
| **출처** | 위 문서·소스에 문장이나 코드로 있는 내용 |
| **추론** | 출처에서 끌어낸 판단. 실제 인스턴스에서 돌려 보지 않았다 |
| **미확인** | 확인이 필요한 가정 |

버전 표기: "Gitea x.y"는 Forgejo가 상속한 상류 기능, "Forgejo vN"은 Forgejo에서 새로 생긴 기능이다.

## 핵심 답변

| # | 질문 | 답 | 필요 버전 |
|---|---|---|---|
| 1 | GWS 로그인·신원 묶기 | 된다. OIDC 인증 소스 + `--required-claim-name hd`로 회사 도메인만 허용. 직원 계정을 관리자 API로 미리 만들면서 `source_id`와 `login_name`=Google `sub`을 넣으면 첫 로그인이 그 계정에 바로 붙는다. **단 Google ID 토큰에는 groups 클레임이 없어** OIDC 그룹→팀 매핑은 못 쓰고, OAuth2 소스는 사용자 동기화(비활성화)를 하지 않는다 | OIDC 소스·required claim: Gitea 1.18 이전 / 그룹 매핑: Gitea 1.19(정적)·Forgejo v16(동적) |
| 2 | SSH 공개키 읽기 | 된다. `GET /users/{username}/keys`(지문 필터 가능), 사이트 관리자 토큰이면 소유자·종류 정보까지 붙는다. `GET /user/keys?fingerprint=`는 사용자 전체에서 지문으로 찾는다. 관리자용 GET 전용 경로는 없다(관리자 경로는 생성·삭제만) | Gitea 1.18 이전 |
| 3 | 조직·팀·사용자 API | 된다. 사용자 생성·수정(`prohibit_login`)·삭제(`purge`), 조직 생성, 팀 생성·멤버 추가/제거·저장소 연결이 모두 API에 있다. SCIM은 없다. 동기화는 우리 쪽(Semaphore)이 API를 호출해서 해야 한다 | Gitea 1.18 이전 |
| 4 | 브랜치 보호 | 필수 승인 수·승인자 제한·직접 push 허용 목록(사용자·팀·배포 키 전체)·필수 상태 검사·파일 패턴 보호가 있다. **그러나 "특정 계정은 특정 경로만 직접 push"는 없다.** 파일 패턴은 계정과 무관하게 적용되고, protected 패턴은 PR 병합까지 막는다. 봇을 push 허용 목록에 넣으면 봇은 브랜치 전체에 쓸 수 있다 | 승인·허용 목록: Gitea 1.5~1.7 / protected 패턴: Gitea 1.12 / unprotected 패턴: Gitea 1.16 |
| 5 | 커밋 상태 API | 된다. `POST /repos/{owner}/{repo}/statuses/{sha}`(상태 `pending`/`success`/`error`/`failure`/`warning`/`skipped`), 브랜치 보호의 필수 상태 검사(glob 패턴)와 연결된다 | Gitea 1.10(필수 상태 검사) 이전 |
| 6 | Actions 외부 HTTP·시크릿 | 잡 컨테이너가 외부로 나가는 것을 막는 Forgejo 설정은 없다(러너 네트워크 설정에 달림). 시크릿은 저장소·조직·사용자 단위, DB 암호화 저장, 로그 자동 가림, 포크 PR에는 비어 있음. Forgejo v15부터 Actions가 OIDC 토큰을 발급해 정적 시크릿 없이 외부에 신원을 증명할 수 있다. 선례(ADR-0016)는 Actions 대신 **서명 검증 웹훅**으로 Semaphore를 부른다 | Actions OIDC: Forgejo v15 / 저장소 한정 토큰: Forgejo v15 |

## 1. GWS(Google OIDC) 로그인과 신원 묶기

### 1.1 인증 소스

| 사실 | 태그 | 근거 |
|---|---|---|
| `forgejo admin auth add-oauth`로 OAuth2/OIDC 인증 소스를 추가한다. OIDC는 `--auto-discover-url`이 필요하다 | 출처 | [CLI][fj-cli] |
| `--required-claim-name`/`--required-claim-value`: "Claim name/value that has to be set to allow users to login with this source". 콜백에서 클레임이 없거나 값이 다르면 `ErrUserProhibitLogin` | 출처 | [CLI][fj-cli], [`oauth.go`][fj-oauth] `oAuth2UserLoginCallback` |
| Google ID 토큰의 `hd`는 "The domain associated with the Google Workspace or Cloud organization of the user", 없으면 Workspace 계정이 아니다 | 출처 | [Google OIDC][g-oidc] |
| goth OIDC 공급자는 ID 토큰 클레임 전체를 `RawData`에 넣는다(`RawData: claims`) | 출처 | [goth][goth] |
| 따라서 `--required-claim-name hd --required-claim-value <회사 도메인>`으로 회사 GWS 계정만 로그인시킬 수 있다 | 추론 | 위 세 줄 |
| `[oauth2_client]`: `ENABLE_AUTO_REGISTRATION`(기본 false), `USERNAME`(nickname/userid/email/preferred_username), `ACCOUNT_LINKING`(disabled/login/auto. auto는 같은 이름·이메일이면 기존 계정에 자동 연결한다는 경고가 있음) | 출처 | [cheat sheet][fj-cheat] |
| `--skip-local-2fa`로 이 소스 사용자에게 Forgejo 자체 2FA를 생략할 수 있다 | 출처 | [CLI][fj-cli] |

### 1.2 직원 Forgejo 계정을 GWS 신원에 묶는 방법

OAuth2 콜백은 사용자를 이 순서로 찾는다([`oauth.go`][fj-oauth] `oAuth2GothUserToUser`, 출처):

1. `user.LoginName == gothUser.UserID` 이고 `user.LoginSource == 소스 ID` 인 사용자
2. 없으면 `external_login_user` 표(계정 연결 기록)에서 `ExternalID == gothUser.UserID`
3. 둘 다 없으면 자동 가입(`ENABLE_AUTO_REGISTRATION`) 또는 계정 연결 화면(`ACCOUNT_LINKING`)

goth OIDC 공급자의 `UserID`는 `sub` 클레임이다(`UserIdClaims: []string{"sub"}`, [goth][goth], 출처). Google은 "Always use the `sub` field … unique to a Google Account even if the user changes their email address"라고 적는다([Google OIDC][g-oidc], 출처).

관리자 API `POST /admin/users`의 `CreateUserOption`에 `source_id`와 `login_name`이 있고, `source_id`를 주면 사용자의 `LoginType`·`LoginSource`가 그 소스로 정해진다([`admin/user.go`][fj-adminuser] `parseAuthSource`, 출처). `PATCH /admin/users/{username}`도 둘을 함께 받는다(하나만 주면 422).

그래서 가능한 묶기 방법은 둘이다.

| 방법 | 내용 | 평가 |
|---|---|---|
| A. 미리 만들기 | 동기화 작업이 GWS 직원마다 `POST /admin/users`로 `source_id=<OIDC 소스>`, `login_name=<Google sub>`를 넣어 계정을 만든다. 첫 로그인은 1번 경로로 이 계정에 붙는다 | **추론**: 이메일·이름이 바뀌어도 `sub`으로 고정된다. 원장이 Employee↔Forgejo 계정 대응을 결정적으로 갖는다. `GET /admin/users?source_id=&login_name=`로 역조회도 된다(출처: swagger) |
| B. 자동 가입 | `ENABLE_AUTO_REGISTRATION=true`, `USERNAME=email` 등. 계정은 첫 로그인 때 생긴다 | 로그인 전까지 계정이 없어 원장이 미리 팀·키를 걸 수 없다. `ACCOUNT_LINKING=auto`는 이름·이메일만으로 기존 계정에 붙여 위험하다고 문서가 경고한다 |

**미확인**: Google Directory API의 사용자 `id`가 OIDC `sub`과 같은 값인지. 같다면 방법 A의 `login_name`을 Directory API 스냅샷에서 바로 채울 수 있다. 다르면 첫 로그인 뒤 `sub`을 읽어 와야 한다. 구현 전에 테스트 계정 하나로 확인해야 한다.

### 1.3 그룹·팀 매핑과 동기화의 한계

| 사실 | 태그 | 근거 |
|---|---|---|
| 인증 소스에 groups 클레임 이름과 "그룹→조직/팀" 정적 매핑(JSON), 매핑 그룹에서 빠지면 팀에서 제거 옵션이 있다 | 출처 | [OIDC group mappings][fj-groupmap]. 기능은 Gitea 1.19 "Map OIDC groups to Orgs/Teams (#21441)" |
| 패턴(`{org}`/`{team}`) 기반 동적 매핑은 Forgejo v16에서 생겼다(PR 11656), v17에서 개선(PR 13056) | 출처 | 릴리스 노트 16.0.0·17.0.0 |
| **Google ID 토큰 클레임 목록에 groups가 없다** | 출처 | [Google OIDC][g-oidc] |
| 그래서 Google을 직접 OIDC로 붙이면 그룹→팀 매핑은 쓸 수 없다. 팀 소속은 API(3절)로 맞춰야 한다 | 추론 | 위 두 줄 |
| `cron.sync_external_users`는 `SynchronizableSource`를 구현한 소스만 돈다. LDAP 소스에는 `Sync`가 있고 OAuth2 소스(`services/auth/source/oauth2/`)에는 없다 | 출처 | [`sync.go`][fj-sync], [oauth2 소스][fj-oauth2src] |
| 따라서 **GWS에서 직원을 정지해도 Forgejo 계정은 그대로다.** 웹 재로그인만 막히고(Google이 거부), 이미 등록된 SSH 키·개인 토큰은 계속 쓸 수 있다. 퇴사자는 동기화 작업이 `PATCH /admin/users/{u}`의 `prohibit_login: true`나 `DELETE /admin/users/{u}`로 막아야 한다 | 추론 | 위 줄 + swagger |
| 기존 로그인 세션이 IdP 재검증으로 끊기는지는 보지 않았다(Forgejo v16 PR 12321 "persist OAuth2/OIDC sign-in via IdP re-validation") | 미확인 | 릴리스 노트 16.0.0 |
| Forgejo v11부터 OIDC 클레임에서 SSH 키를 동기화하는 옵션(`--attribute-ssh-public-key`)이 있다. Google 클레임에는 SSH 키가 없어 해당 없다 | 출처 | 릴리스 노트 11.0.0 PR 6232, [CLI][fj-cli] |

## 2. 사용자 SSH 공개키 읽기

| 사실 | 태그 | 근거 |
|---|---|---|
| `GET /users/{username}/keys`: 그 사용자의 공개키 목록. 쿼리 `fingerprint`, `page`, `limit` | 출처 | [swagger][fj-swagger] `userListKeys` |
| `GET /user/keys`: 토큰 주인의 키 목록. `fingerprint`만 주고 사용자 이름이 없으면 **전체 사용자**에서 그 지문을 찾는다(`OwnerID: 0 // Unrestricted`) | 출처 | [`user/key.go`][fj-key] `listPublicKeys` |
| 호출자가 사이트 관리자이거나 키 주인이면 응답에 `key_type`(user/deploy)·`owner`·`read_only`가 더해진다. 그 밖에는 키 본문·지문·제목 등 기본 필드만 | 출처 | [`user/key.go`][fj-key] `appendPrivateInformation` 조건 `ctx.IsUserSiteAdmin() \|\| ctx.Doer().ID == keys[i].OwnerID` |
| `PublicKey` 필드: `id`, `key`, `fingerprint`, `title`, `key_type`, `read_only`, `verified`, `created_at`, `updated_at`, `user` | 출처 | [swagger][fj-swagger] |
| 관리자 경로는 `POST /admin/users/{username}/keys`(대리 등록), `DELETE /admin/users/{username}/keys/{id}`만 있고 관리자 전용 GET은 없다 | 출처 | [swagger][fj-swagger] |
| `/users/*`는 토큰 범위 `read:user`가 필요하다. 범위 없는 토큰은 지원하지 않는다 | 출처 | [Token scope][fj-scope] |
| 원장 수집은 "사용자 목록(`GET /admin/users`) → 사용자별 `GET /users/{u}/keys`"로 하고, 호스트 `authorized_keys`에서 본 지문은 `GET /user/keys?fingerprint=`로 주인을 역조회할 수 있다 | 추론 | 위 줄들 |

`verified` 필드는 사용자가 키 소유를 서명으로 증명했는지를 나타낸다. 원장에 "검증된 키만 반영" 규칙을 둘 수 있다(추론).

## 3. 조직·팀·사용자를 API로 만들고 동기화

모두 v17 swagger에 있다(출처: [swagger][fj-swagger]).

| 대상 | 경로 | 비고 |
|---|---|---|
| 사용자 생성 | `POST /admin/users` | `source_id`·`login_name`·`restricted`·`visibility`·`must_change_password`·`send_notify` |
| 사용자 수정·잠금 | `PATCH /admin/users/{username}` | `prohibit_login`, `active`, `restricted`, `admin`, `source_id`+`login_name` |
| 사용자 삭제 | `DELETE /admin/users/{username}?purge=` | `purge`는 소유 저장소 등까지 지운다 |
| 사용자 검색 | `GET /admin/users` | `source_id`, `login_name`, `is_2fa_enabled`, `sort` 필터 |
| 이름 변경 | `POST /admin/users/{username}/rename` | |
| 조직 생성 | `POST /orgs`, `POST /admin/users/{username}/orgs` | `visibility`: public/limited/private |
| 팀 생성·수정·삭제 | `POST /orgs/{org}/teams`, `PATCH`/`DELETE /teams/{id}` | `permission`(read/write/admin), `units_map`, `includes_all_repositories` |
| 팀 멤버 | `GET /teams/{id}/members`, `PUT`/`DELETE /teams/{id}/members/{username}` | 조직 멤버십은 팀 소속으로 생긴다. `DELETE /orgs/{org}/members/{username}`로 조직에서 뺄 수 있다 |
| 팀↔저장소 | `PUT`/`DELETE /teams/{id}/repos/{org}/{repo}`, `PUT /repos/{owner}/{repo}/teams/{team}` | |

- swagger에 SCIM 경로가 없다(출처). GWS → Forgejo 동기화는 우리 쪽 작업이 위 API를 호출하는 "원하는 상태 맞추기"로 만들어야 한다(추론).
- 관리자 경로는 토큰 범위 `write:admin`, 조직·팀은 `write:organization`이 필요하다([Token scope][fj-scope], 출처).
- Forgejo v15부터 **저장소 한정 토큰**(특정 저장소만, `read`/`write:repository`·`issue` 범위만)이 있다. 커밋·상태 기록용 봇 토큰을 원장 저장소 하나로 좁힐 수 있다([Token scope][fj-scope], 릴리스 노트 15.0.0, 출처). 관리자 API를 부르는 동기화 토큰은 이것으로 좁힐 수 없다(관리자 권한이 제거됨, 릴리스 노트 15.0.0 "remove admin-level permissions from repo-specific … tokens").

## 4. 브랜치 보호

### 4.1 있는 기능

`BranchProtection` 필드(출처: [swagger][fj-swagger])와 UI 설명(출처: [locale][fj-locale]):

| 기능 | 필드 | 설명(locale 인용) |
|---|---|---|
| 규칙 이름 glob | `rule_name` | "Examples: main, release/\*\*" |
| 직접 push 끄기/켜기 | `enable_push` | 켜면 "Anyone with write access will be allowed to push … (but not force push)" |
| 직접 push 허용 목록 | `enable_push_whitelist`, `push_whitelist_usernames`, `push_whitelist_teams`, `push_whitelist_deploy_keys` | "Only whitelisted users or teams will be allowed to push to this branch". 배포 키는 **쓰기 권한 배포 키 전체**를 켜고 끄는 불리언이다 |
| 병합 허용 목록 | `enable_merge_whitelist`, `merge_whitelist_*` | |
| 필수 승인 수 | `required_approvals` | "Allow only to merge pull request with enough positive reviews" |
| 승인자 제한 | `enable_approvals_whitelist`, `approvals_whitelist_username`, `approvals_whitelist_teams` | "Only reviews from whitelisted users or teams will count" |
| 옛 승인 무효 | `dismiss_stale_approvals`, `ignore_stale_approvals` | |
| 병합 차단 | `block_on_rejected_reviews`, `block_on_official_review_requests`, `block_on_outdated_branch` | |
| 필수 상태 검사 | `enable_status_check`, `status_check_contexts`(줄마다 패턴) | |
| 서명 커밋 | `require_signed_commits` | |
| 파일 패턴 | `protected_file_patterns`, `unprotected_file_patterns`(`;` 구분 glob) | 아래 4.2 |
| 관리자에게도 적용 | `apply_to_admins` | |

도입 버전(상류 Gitea, 출처: [Gitea 1.18 CHANGELOG][gitea-118]): 허용 목록 1.3·병합 허용 목록 1.5, 리뷰 승인 1.6~1.7, 필수 상태 검사 1.10, protected 파일 패턴 1.12, unprotected 파일 패턴 1.16. 모두 Forgejo 첫 버전보다 앞선다.

### 4.2 경로별 보호의 실제 동작 (`hook_pre_receive.go`)

[`routers/private/hook_pre_receive.go`][fj-hook] `preReceiveBranch`(출처):

1. protected 파일 패턴에 걸리는 파일을 바꾸면 `changedProtectedfiles = true`.
2. 직접 push 가능 여부: 사용자는 `canPush = !changedProtectedfiles && protectBranch.CanUserPush(user)`, 배포 키는 `!changedProtectedfiles && CanPush && (!EnableWhitelist || WhitelistDeployKeys)`. 즉 **protected 패턴은 허용 목록에 있는 계정의 직접 push도 막는다.**
3. 직접 push가 안 되고 PR 병합도 아니면: protected 파일을 건드렸으면 거부, 아니면 **바뀐 파일이 모두 unprotected 패턴 안이면 허용**. 이 검사에는 계정 조건이 없다. 앞에서 저장소 쓰기 권한(`assertCanWriteCode`)만 확인한다.
4. PR 병합(UI/API)이면: 병합 권한 확인 → 사이트 관리자는 여기서 통과 → protected 파일을 건드렸으면 저장소 관리자(그리고 `apply_to_admins` 꺼짐)가 아닌 한 **병합도 거부** → 승인·상태 검사 확인.

여기서 나오는 결론(추론):

- **"특정 계정만 특정 경로에 직접 push"는 Forgejo 브랜치 보호로 표현할 수 없다.** 허용 목록은 계정 단위·브랜치 전체이고, 파일 패턴은 경로 단위·계정 무관이다.
- `unprotected_file_patterns = directory/**`로 두면 **쓰기 권한이 있는 누구나** `directory/`에 직접 push할 수 있다.
- `protected_file_patterns = grants/**`로 두면 Grant 변경 PR도 (저장소 관리자가 아닌 사람은) 병합할 수 없다. "Grant는 PR만"에 쓸 수 없다.

### 4.3 "봇은 `directory/`에 직접 커밋, Grant는 PR만"을 만드는 방법

| 안 | 설정 | 남는 틈 |
|---|---|---|
| A. 봇만 push 허용 | `main`에 `enable_push_whitelist` + `push_whitelist_usernames=[봇]`, `required_approvals=1`, `approvals_whitelist`=인프라 승인자, `enable_status_check`, `dismiss_stale_approvals` | 봇은 `main`의 **모든 경로**에 직접 쓸 수 있다. 봇이 `directory/` 밖을 건드리지 않는다는 보장은 Forgejo 밖에서 만들어야 한다: 봇 코드 자체, push 뒤 검사 워크플로가 "봇 커밋이 `directory/` 밖을 바꿨으면" 알람, 봇 토큰을 OpenBao에만 두기 |
| B. 쓰기 권한 최소화 + unprotected 패턴 | `enable_push=false`, `unprotected_file_patterns=directory/**`, 저장소 쓰기 권한은 봇과 승인자만. 요청자는 읽기 권한으로 포크 PR이나 AGit(`refs/for/main/<topic>`, 쓰기 권한 없이 PR 생성, [AGit][fj-agit])로 PR을 만든다 | 경로 제한은 생기지만 계정 제한은 아니다: 승인자도 `directory/`에 직접 push할 수 있다. 요청자가 쓰기 권한을 받으면 바로 틈이 생긴다. AGit을 읽기 권한만으로 쓸 수 있다는 것은 문서가 "no need for writing rights"라고만 적어 **미확인** |
| C. 저장소 분리 | GWS 스냅샷(`directory/`)을 별도 저장소나 별도 브랜치에 두고 봇만 쓰게 한다. Grant 저장소는 직접 push 금지 + PR 필수 | Forgejo 권한 모델과 그대로 맞는다. 대신 두 정본을 묶는 검증(Grant가 참조하는 Employee가 스냅샷에 있는지)이 저장소를 건너야 한다 |

- 사이트 관리자는 PR 병합 경로에서 승인·상태 검사 확인 전에 통과한다(4.2의 4번, `if ctx.user.IsAdmin { return }`). 이 분기가 UI 병합 버튼의 사전 검사와 어떻게 맞물리는지는 보지 않았다(**미확인**). 승인자를 사이트 관리자로 두지 않거나 `apply_to_admins`를 켜야 하는지 구현 때 확인해야 한다.
- 상태 검사 설명(locale `protect_check_status_contexts_desc`): "commits must first be pushed to another branch, then merged or pushed directly … after status checks have passed". 직접 push 허용 목록에 있는 봇이 필수 상태 검사를 어떻게 통과하는지는 별도 확인이 필요하다(**미확인**).

## 5. 커밋 상태(commit status) API

| 사실 | 태그 | 근거 |
|---|---|---|
| `POST /repos/{owner}/{repo}/statuses/{sha}` 본문 `state`, `context`, `description`, `target_url` | 출처 | [swagger][fj-swagger] `repoCreateStatus` |
| `state`: "pending", "success", "error", "failure", "warning", "skipped" | 출처 | [swagger][fj-swagger] `CommitStatusState` |
| 조회: `GET /repos/{owner}/{repo}/statuses/{sha}`, `GET …/commits/{ref}/statuses`, 합산 `GET …/commits/{ref}/status` | 출처 | [swagger][fj-swagger] |
| 브랜치 보호 `status_check_contexts` 패턴에 맞는 context가 성공해야 병합된다. 패턴이 하나도 안 맞으면 마지막 커밋 상태가 성공이어야 한다 | 출처 | [locale][fj-locale] `protect_check_status_contexts_desc` |
| Actions 잡은 자기 결과를 커밋 상태로 남긴다(context = 워크플로/잡 이름) | 출처 | Gitea 1.19.1 "Refactor commit status for Actions jobs", 릴리스 노트 10.0.0("The pull request workflow must always update the head SHA commit status") |
| 경로: `/repos/*` → 토큰 범위 `write:repository`. Forgejo v15 저장소 한정 토큰으로 원장 저장소 하나에 묶을 수 있다 | 출처 | [Token scope][fj-scope] |
| 따라서 Semaphore(Ansible) 검증 결과를 PR head 커밋 상태로 쓰고, 그 context를 필수 상태 검사로 걸 수 있다 | 추론 | 위 줄들 |

## 6. Actions의 외부 HTTP 호출과 시크릿

### 6.1 외부 HTTP

| 사실 | 태그 | 근거 |
|---|---|---|
| 러너 `container.network` 기본값 `""`은 잡마다 격리된 새 네트워크를 만든다. `host`/`bridge`/사용자 네트워크로 바꿀 수 있다 | 출처 | [Actions security (관리자)][fj-act-sec-admin] |
| 문서는 잡의 외부(인터넷) 통신을 막는다고 적지 않는다. 오히려 잡이 "local network resources"에 닿을 수 있다고 경고한다 | 출처 | 같은 문서 |
| Docker 기본 네트워크는 외부로 나가는 NAT가 열려 있으므로, 러너 호스트에서 막지 않는 한 잡은 외부 HTTP(예: Semaphore API, OpenBao)를 부를 수 있다 | 추론 | 위 줄 + Docker 기본 동작 |
| 잡에는 `FORGEJO_TOKEN`(`GITHUB_TOKEN` 별칭)이 자동으로 주어진다. 포크 PR에서는 읽기 전용, `pull_request_target`에서는 쓰기 | 출처 | [Actions reference][fj-act-ref] |
| Forgejo v15부터 워크플로에 `enable-openid-connect: true`를 두면 `ACTIONS_ID_TOKEN_REQUEST_URL`로 OIDC JWT를 받는다(PR 10481 "add OIDC workload identity federation support"). 워크플로에서 허용하지 않으면 발급을 막는 수정이 같은 버전에 있다 | 출처 | 릴리스 노트 15.0.0, [Authorized integrations 문서](https://forgejo.org/docs/latest/user/api/authorized-integrations/) |
| 이 JWT를 OpenBao의 JWT 인증이나 받는 쪽 서비스가 검증하면, Forgejo에 정적 토큰을 두지 않고 Actions가 자기 신원을 증명할 수 있다 | 추론(선택지) | 위 줄 |

### 6.2 시크릿

| 사실 | 태그 | 근거 |
|---|---|---|
| 저장소·사용자·조직이 시크릿을 가진다. "stored encrypted in the Forgejo database", `${{ secrets.KEY }}`로 노출. 한번 넣으면 값을 바꾸거나 볼 수 없다(UI) | 출처 | [Actions basic concepts][fj-act-basic] |
| "Forgejo Runner attempts to automatically redact secrets from the logs". 런타임 값은 `::add-mask::`로 가린다 | 출처 | [Actions security (사용자)][fj-act-sec-user], [Authorized integrations 문서](https://forgejo.org/docs/latest/user/api/authorized-integrations/) |
| `secrets` 컨텍스트는 포크 PR의 `pull_request` 이벤트에서 비어 있다. `pull_request_target`은 기본 저장소 시크릿을 받는다(신뢰할 수 없는 코드와 섞지 말라는 경고) | 출처 | [Actions reference][fj-act-ref] |
| API: `PUT`/`DELETE /repos/{owner}/{repo}/actions/secrets/{name}`, 조직·사용자 단위도 같은 꼴. 목록은 이름만 | 출처 | [swagger][fj-swagger] |

### 6.3 트리거 선례와의 관계

- ADR-0016(firewall-policy)은 "병합 → Forgejo 웹훅(서명 검증) → Semaphore 적용 템플릿"이다. map #618은 "트리거 방식은 firewall-policy와 통일"이라고 적었다.
- Forgejo 웹훅은 `X-Forgejo-Signature` 헤더에 본문 HMAC-SHA256을 싣고, Authorization 헤더를 보낼 수 있으며 그 값은 DB에 암호화 저장된다([Webhooks][fj-webhook], 출처).
- 그러니 Actions는 꼭 필요하지 않다. Actions를 쓰는 경우는 PR 단계 검사(문법·스키마)를 Forgejo 안에서 돌리고 싶을 때이고, 그때 외부 호출이 필요하면 6.1의 OIDC 토큰이 정적 시크릿을 피하는 선택지다(추론).

## 버전 요약

| 기능 | 처음 들어온 곳 |
|---|---|
| OAuth2/OIDC 인증 소스, required claim, 계정 연결 | Gitea 1.18 이전(Forgejo 첫 버전부터) |
| OIDC 그룹→팀 정적 매핑 | Gitea 1.19 (#21441) |
| OIDC 클레임 SSH 키 동기화 | Forgejo v11 (PR 6232) |
| Actions OIDC 토큰, 저장소 한정 토큰 | Forgejo v15 (PR 10481 등) |
| OIDC 동적 그룹 매핑 | Forgejo v16 (PR 11656), v17 개선 |
| 브랜치 보호(허용 목록·승인·상태 검사·파일 패턴), 커밋 상태 API, 키·사용자·조직·팀 API | Gitea 1.18 이전 |

## 열린 질문

- Google Directory API 사용자 `id`와 OIDC `sub`이 같은가(1.2).
- 직접 push 허용 목록의 봇이 필수 상태 검사와 어떻게 맞물리는가, 사이트 관리자 병합 경로가 승인 검사를 건너뛰는가(4.3).
- AGit이 읽기 권한만으로 동작하는가(4.3 B안).
- GWS 정지 뒤 기존 Forgejo 웹 세션이 언제 끊기는가(1.3).

[fj-cheat]: https://forgejo.org/docs/latest/admin/config-cheat-sheet/
[fj-cli]: https://forgejo.org/docs/latest/admin/command-line/
[fj-groupmap]: https://forgejo.org/docs/latest/admin/advanced/oidc-group-mappings/
[fj-scope]: https://forgejo.org/docs/latest/user/token-scope/
[fj-act-ref]: https://forgejo.org/docs/latest/user/actions/reference/
[fj-act-basic]: https://forgejo.org/docs/latest/user/actions/basic-concepts/
[fj-act-sec-user]: https://forgejo.org/docs/latest/user/actions/security/
[fj-act-sec-admin]: https://forgejo.org/docs/latest/admin/actions/security/
[fj-webhook]: https://forgejo.org/docs/latest/user/repository/webhooks/
[fj-agit]: https://forgejo.org/docs/latest/user/agit-support/
[fj-swagger]: https://codeberg.org/forgejo/forgejo/src/tag/v17.0.0/templates/swagger/v1_json.tmpl
[fj-hook]: https://codeberg.org/forgejo/forgejo/src/tag/v17.0.0/routers/private/hook_pre_receive.go
[fj-oauth]: https://codeberg.org/forgejo/forgejo/src/tag/v17.0.0/routers/web/auth/oauth.go
[fj-adminuser]: https://codeberg.org/forgejo/forgejo/src/tag/v17.0.0/routers/api/v1/admin/user.go
[fj-key]: https://codeberg.org/forgejo/forgejo/src/tag/v17.0.0/routers/api/v1/user/key.go
[fj-sync]: https://codeberg.org/forgejo/forgejo/src/tag/v17.0.0/services/auth/sync.go
[fj-oauth2src]: https://codeberg.org/forgejo/forgejo/src/tag/v17.0.0/services/auth/source/oauth2
[fj-locale]: https://codeberg.org/forgejo/forgejo/src/tag/v17.0.0/options/locale/locale_en-US.ini
[gitea-118]: https://github.com/go-gitea/gitea/blob/release/v1.18/CHANGELOG.md
[gitea-119]: https://github.com/go-gitea/gitea/blob/release/v1.19/CHANGELOG.md
[g-oidc]: https://developers.google.com/identity/openid-connect/openid-connect
[goth]: https://github.com/markbates/goth/blob/master/providers/openidConnect/openidConnect.go
