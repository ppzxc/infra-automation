# GWS Directory API로 직원·조직·그룹 읽기

- 질문: [#621](https://github.com/ppzxc/infra-automation/issues/621), 상위 map [#618](https://github.com/ppzxc/infra-automation/issues/618)(Host Account 원장). 이 문서는 근거만 모은다. 결정은 스펙·ADR이 내린다.
- 조사일: 2026-11-20
- 1차 출처: Google Admin SDK Directory API 공식 문서(REST reference·가이드), Cloud Identity Groups API 문서, Google Workspace 관리자 도움말, `google-auth` 레퍼런스. 각 주장 옆에 링크를 단다. Context7 `/websites/developers_google_workspace_admin`도 확인했지만 위임 예제가 옛 `oauth2client` 기반이라 원문을 우선했다.
- 실제 테넌트에는 호출하지 않았다. "(추론)", "(미확인)" 표시는 문서에 직접 쓰여 있지 않은 부분이다.

## 요약

- 동기화에 필요한 것은 **Directory API `users.list`·`orgunits.list`·`groups.list`·`members.list`** 네 가지이고 모두 읽기 전용 scope로 된다.
- 사용자 상태는 `suspended`(+`suspensionReason`), `archived`, 삭제는 `showDeleted=true`로 **최근 20일 안에 삭제된 사용자만** 보인다. 20일이 넘은 삭제자는 목록에서 사라지므로, 원장 쪽에서 "직전 스냅샷에 있었는데 이번에 없음"을 삭제로 판정해야 한다.
- **SSH 공개키와 리눅스 계정 정보는 커스텀 스키마 없이 내장 필드가 있다**: `sshPublicKeys[]`(key, expirationTimeUsec, 읽기 전용 SHA-256 fingerprint)와 `posixAccounts[]`(username, uid, gid, homeDirectory, shell, systemId, primary 등). 다른 속성이 필요하면 커스텀 스키마를 쓰고 `projection=full` 또는 `custom`+`customFieldMask`로 읽는다.
- 중첩 그룹: Directory API `members.list?includeDerivedMembership=true`가 간접 멤버까지 펼쳐 준다. Cloud Identity Groups API의 transitive 메서드는 **Enterprise Standard/Plus·Enterprise for Education·Cloud Identity Premium 전용**이라 에디션을 먼저 확인해야 한다.
- 최소 scope(도메인 전체 위임 시): `admin.directory.user.readonly`, `admin.directory.group.readonly`(멤버 포함), `admin.directory.orgunit.readonly`. 커스텀 스키마 정의까지 읽으려면 `admin.directory.userschema.readonly`를 더한다.
- 변경분 읽기: push(`watch`)는 **Users 리소스만** 지원하고, 공인 인증서가 있는 HTTPS 수신 주소가 필요하며 채널 자동 갱신이 없다. 사내 Semaphore 정기 실행에는 **매번 전체 목록을 읽고 직전 스냅샷과 비교**하는 쪽이 맞다(추론, 규모·한도 근거는 아래).
- 한도: 기본 사용자당 프로젝트당 분당 2,400 쿼리. 페이지 크기는 users 최대 500, groups·members 최대 200.
- 파이썬: `google-api-python-client` + `google-auth`(`service_account.Credentials`의 `subject=`/`with_subject()`), `build("admin", "directory_v1", ...)`.

## 1. 사용자 (`users.list`)

`GET https://admin.googleapis.com/admin/directory/v1/users` ([users.list][users-list])

| 파라미터 | 의미 |
|---|---|
| `customer=my_customer` | 자기 계정 전체. 다중 도메인이면 이쪽. `domain`은 한 도메인만 |
| `showDeleted=true` | 삭제된 사용자 목록 (기본 false) |
| `projection` | `BASIC`·`CUSTOM`·`FULL`. `CUSTOM`일 때만 `customFieldMask`(스키마 이름 쉼표 목록) |
| `viewType` | `admin_view`(관리자용) / `domain_public`(공개 프로필) |
| `query` | 검색식. 예: `isSuspended=true`, `isArchived=true`, `orgUnitPath=/...`, `schemaName.fieldName=...` |
| `maxResults`·`pageToken` | 페이지 크기 최대 500([limits][limits]), 토큰은 3일 유효 |
| `event` | watch 구독 이벤트(`ADD`·`DELETE`·`MAKE_ADMIN`·`UNDELETE`·`UPDATE`) |

scope: `admin.directory.user` 또는 `admin.directory.user.readonly`(또는 `cloud-platform`) ([users.list][users-list]).

**상태 필드** ([User 리소스][users-res]):

- `suspended`: "Indicates if user is suspended." `suspensionReason`은 `suspended=true`일 때만 온다(관리자 정지인지 Google 정지인지).
- `archived`: "Indicates if user is archived." (Archived User 라이선스 상태)
- `deletionTime`: 출력 전용, 삭제 시각. 삭제된 사용자는 `showDeleted=true`로만 보인다.
- `isAdmin`(슈퍼관리자), `isDelegatedAdmin`, `orgUnitPath`, `lastLoginTime`, `etag`, 불변 `id`, `primaryEmail`.

**삭제 보존 기간**: "retrieve all users deleted within the span of the last 20 days" ([manage-users][manage-users]). 원장에서 퇴사자를 놓치지 않으려면 동기화 주기가 20일보다 훨씬 짧아야 하고, 불변 `id`를 키로 직전 스냅샷과 비교해 사라진 사용자를 삭제로 본다(추론).

**검색식 주의** ([search-users][search-users]):

- `isSuspended`, `isArchived`, `isAdmin`, `isDelegatedAdmin`, `isEnrolledIn2Sv`는 불리언 `=` 검색이 된다.
- `orgUnitPath` 검색은 `viewType=admin_view`에서만 된다.
- 커스텀 필드 검색은 `schemaName.fieldName`이고 필드가 `indexed=true`여야 한다.
- **검색 인덱스 지연**: "it may take up to 36 hours for new data to be reflected in all search results"(대부분 1시간 안). 그래서 정지 판정은 `query=isSuspended=true`가 아니라 **전체 목록을 받아 `suspended` 필드를 직접 보는 것**이 안전하다(추론: 필드 값 자체와 검색 인덱스의 지연이 다르다는 근거는 이 문장 하나다).

**비관리자 읽기**: 일반 사용자도 `viewType=domain_public`으로 공개 프로필 일부를 읽을 수 있지만(연락처 공유가 켜진 경우), 정지·보관·OU·POSIX·SSH 같은 관리 필드는 `admin_view`가 필요하다 ([manage-users][manage-users]). 즉 위임 대상 주체는 관리자 권한이 있어야 한다(4절).

## 2. 내장 POSIX·SSH 필드와 커스텀 스키마

**내장 필드** ([User 리소스][users-res]) — 커스텀 스키마를 만들 필요가 없다:

- `posixAccounts[]`: `username`, `uid`, `gid`, `homeDirectory`, `shell`, `systemId`("System identifier for which account Username or Uid apply to"), `primary`(그 systemId 안의 주 계정 여부), `accountId`, `gecos`, `operatingSystemType`.
- `sshPublicKeys[]`: `key`, `expirationTimeUsec`(만료 시각, 마이크로초), `fingerprint`("A SHA-256 fingerprint of the SSH public key. (Read-only)").

`systemId`로 "이 원장용 리눅스 사용자명"을 다른 용도(예: 다른 시스템의 POSIX 계정)와 나눌 수 있다(추론). 값을 넣는 쪽(관리자 콘솔 UI에 이 필드가 있는지, API로만 넣는지)은 확인하지 못했다(미확인). 쓰기는 `admin.directory.user` scope가 필요하므로 동기화 봇이 아니라 사람이나 별도 도구가 넣는다.

`projection=BASIC`에 이 두 필드가 포함되는지는 문서에서 확인하지 못했다(미확인). 첫 구현은 `projection=FULL`로 읽어 실제 응답을 보고 정한다.

**커스텀 스키마** ([manage-schemas][manage-schemas], [schemas 리소스][schemas-res]):

- `schemas.insert`로 `schemaName`과 `fields[]`를 만든다. `fieldType`은 `BOOL`·`DATE`·`DOUBLE`·`EMAIL`·`INT64`·`PHONE`·`STRING`.
- `readAccessType`: `ADMINS_AND_SELF`(관리자와 본인만) 또는 `ALL_DOMAIN_USERS`. 바뀌는 데 최대 24시간.
- `multiValued`(단일→다중은 되고 반대는 안 됨, 타입 변경 불가), `indexed`(기본 true, 검색용).
- 한 계정에 스키마 100개·커스텀 필드 100개, 단일 값 문자열 500자. SSH 공개키(특히 RSA 4096)는 500자를 넘을 수 있으므로 **키는 내장 `sshPublicKeys`에 두는 편이 맞다**(추론).
- 사용자에서 읽기: `users.list`/`users.get`에 `projection=full` 또는 `projection=custom&customFieldMask=<schemaName>`. 결과는 `customSchemas.<schemaName>.<fieldName>`.
- 스키마 정의 자체(`schemas.list`)를 읽으려면 `admin.directory.userschema.readonly` ([authorizing][authorizing]). 사용자 값만 읽을 거면 필요 없다(추론).

## 3. 조직 단위와 그룹

**조직 단위** ([orgunits.list][orgunits-list]): `GET .../customer/{customerId}/orgunits`, `type=ALL`이면 하위 전체, `ALL_INCLUDING_PARENT`면 루트 포함(기본 `CHILDREN`). scope `admin.directory.orgunit.readonly`. 사용자 쪽에서는 `orgUnitPath`만으로도 소속은 알 수 있다.

**그룹 목록** ([groups.list][groups-list]): `customer=my_customer` 또는 `domain`, 페이지 최대 200. `userKey=<사용자>`로 그 사용자가 속한 그룹을 뽑을 수 있지만 `customer`와 같이 쓸 수 없고, 간접 소속을 포함하는지는 문서에 없다([manage-groups][manage-groups], 미확인). scope `admin.directory.group.readonly`.

**멤버** ([members.list][members-list], [Member 리소스][members-res]):

- `GET .../groups/{groupKey}/members`, 페이지 최대 200, `roles=OWNER,MANAGER,MEMBER` 필터.
- `includeDerivedMembership=true`: "Whether to list indirect memberships." — 중첩 그룹을 펼쳐 준다.
- 멤버 `type`: `USER`·`GROUP`·`CUSTOMER`(도메인 전체 사용자)·`EXTERNAL`(미사용). `status`, `role`, 불변 `id`.
- scope: `admin.directory.group.member.readonly` 또는 `admin.directory.group.readonly` 중 하나. **`group.readonly` 하나로 그룹과 멤버를 다 읽는다** ([authorizing][authorizing]: "read-only access to groups, aliases, and members").

**중첩 소속 확인** ([members.hasMember][has-member]): "Membership can be direct or nested, but if nested, the `memberKey` and `groupKey` must be entities in the same domain". 도메인 밖 엔터티가 끼면 Cloud Identity의 `checkTransitiveMembership()`을 쓰라고 한다.

**Cloud Identity Groups API** ([query-memberships][ci-query], [searchTransitiveGroups][ci-stg], [setup][ci-setup]):

- `searchTransitiveMemberships`(그룹의 직·간접 멤버, 각 멤버의 direct/indirect 구분), `searchTransitiveGroups`(멤버가 속한 모든 그룹), `checkTransitiveMembership`, `getMembershipGraph`.
- **에디션 제한**: "only available to Google Workspace Enterprise Standard, Enterprise Plus, and Enterprise for Education"(+Cloud Identity Premium). 아니면 403 `PERMISSION_DENIED`.
- scope `cloud-identity.groups.readonly`, Cloud Identity API를 GCP 프로젝트에서 켜야 한다.
- 호출자는 질의에 걸린 모든 그룹의 멤버십을 볼 권한이 있어야 한다.

정리: 그룹 수가 적은 사내 규모에서는 **Directory API로 그룹 전체와 각 그룹의 직접 멤버를 읽어 원장 쪽에서 그래프를 펼치는 것**이 에디션과 무관하게 동작한다(추론). `includeDerivedMembership=true`는 펼친 결과만 주고 경로는 안 주므로, 직접 멤버(`GROUP` 타입 포함)를 저장하면 펼침과 출처 둘 다 남는다.

## 4. 인증: 도메인 전체 위임(DWD)과 관리자 역할

### 4.1 DWD 절차 ([delegation][delegation], [create-credentials][create-cred])

1. GCP 콘솔 **IAM & Admin > Service Accounts**에서 서비스 계정 생성(GCP 역할은 필요 없음). 프로젝트에서 **Admin SDK API**를 켠다(Cloud Identity Groups를 쓰면 Cloud Identity API도).
2. **Keys > Add key > Create new key > JSON**. "the only copy of this key"이므로 OpenBao에만 보관.
3. 서비스 계정 상세의 **Show advanced settings**에서 Domain-wide delegation의 **Client ID** 복사.
4. 슈퍼관리자가 관리 콘솔 **Security > Access and data control > API controls > Manage Domain Wide Delegation > Add new**에 Client ID와 scope 목록(쉼표 구분)을 넣고 **Authorize**. "Changes can take up to 24 hours but typically happen more quickly."

이 원장용 최소 scope 목록:

```
https://www.googleapis.com/auth/admin.directory.user.readonly,
https://www.googleapis.com/auth/admin.directory.group.readonly,
https://www.googleapis.com/auth/admin.directory.orgunit.readonly
```

(커스텀 스키마 정의 조회 시 `admin.directory.userschema.readonly`, Cloud Identity transitive 메서드 사용 시 `cloud-identity.groups.readonly` 추가.)

### 4.2 위임 대상 주체(subject)에 필요한 관리자 역할

DWD는 "access user data on behalf of any user"([google-auth][google-auth])로, API 호출이 `subject` 사용자 권한으로 실행된다. Directory API 관리 필드(`admin_view`, 정지·OU 등)는 관리자만 읽으므로 subject는 **관리자 역할을 가진 사용자**여야 한다(추론: 공식 문서가 "subject에 어떤 권한이 필요한가"를 직접 적은 문장은 찾지 못했다. 근거는 [manage-users][manage-users]의 비관리자=`domain_public`뿐이라는 설명과 [search-users][search-users]의 `orgUnitPath`=`admin_view` 전용).

최소 권한으로 가려면 슈퍼관리자를 subject로 쓰지 말고 **커스텀 관리자 역할**을 만들어 Admin API 권한 중 **Users > Read, Groups > Read, Organizational Units > Read**만 준 전용 사용자를 subject로 둔다 ([admin privilege definitions][priv-defs]). 커스텀 필드를 읽는 데 Users > Read로 충분한지는 문서에 없다(미확인, 카나리에서 확인).

### 4.3 대안: 서비스 계정에 관리자 역할을 직접 부여 (DWD 없음)

- "You can assign any prebuilt or custom role except Super Admin to a service account." 관리 콘솔 **Account > Admin roles > (역할) > Assign admin > Assign service accounts**에 서비스 계정 이메일을 넣는다 ([assign-specific-admin-roles][assign-roles], [delegation][delegation]).
- Cloud Identity Groups 설정 문서는 이 방식을 명시한다: 그룹 관리자 역할을 서비스 계정에 주고 "Do not impersonate a user when generating credentials", 즉 `with_subject()`를 생략 ([ci-setup][ci-setup]).
- 장점: 사람 계정을 subject로 쓰지 않고, DWD처럼 "아무 사용자로나 행세"할 수 있는 권한을 만들지 않는다. GCP IAM 모범 사례도 다른 방법이 있으면 DWD를 피하라고 한다(검색 요약 근거, 원문 인용은 하지 않음).
- Directory API `users.list`가 이 방식(서비스 계정 자체에 Users > Read 커스텀 역할)으로 `admin_view`까지 되는지는 Directory API 문서에서 직접 확인하지 못했다(미확인). 첫 카나리에서 이 경로를 먼저 시도하고, 안 되면 4.1 DWD로 간다.

## 5. 변경분 읽기 (watch·etag·감사 로그)

**Push 알림** ([push][push]):

- "Currently, the Directory API supports notifications for changes to the Users resource." — 그룹·멤버·OU는 push가 없다.
- 이벤트: `add`, `delete`, `makeAdmin`, `undelete`, `update`.
- 수신 주소는 HTTPS이고 공인 인증서가 필요(자체 서명 불가).
- "there's no automatic way to renew a notification channel" — 만료 전에 새 채널을 다시 만들어야 한다.
- 알림 본문은 `kind`, `id`, `etag`, `primaryEmail`뿐이라 결국 `users.get`을 다시 불러야 한다.

**etag**: 사용자·멤버·목록 응답마다 `etag`가 있다([users-res][users-res], [members-list][members-list]). 조건부 요청(`If-None-Match`→304)을 Directory API가 지원한다는 문장은 찾지 못했다(미확인). 스냅샷 비교용 지문으로 쓰는 것은 가능하다(추론).

**Reports API 관리자 활동** ([admin user settings events][reports-user]): `applicationName=admin`, `type=USER_SETTINGS`에 `CREATE_USER`, `SUSPEND_USER`, `UNSUSPEND_USER`, `DELETE_USER`, `ARCHIVE_USER`, `MOVE_USER_TO_ORG_UNIT`, `CHANGE_USER_ORGANIZATION` 이벤트가 있다. "언제 누가 정지했는가" 같은 감사 근거가 필요할 때 보조로 쓸 수 있다. scope(`admin.reports.audit.readonly` 예상)는 이 페이지에서 확인하지 못했다(미확인).

**결론(추론)**: 이 원장은 Semaphore 정기 실행이고 사내망에서 공인 HTTPS 수신을 열 이유가 없으며 그룹 변경은 push가 없다. 그래서 **정기 전체 읽기 + 직전 스냅샷 비교**가 맞다. 수백 명 규모면 users 1~2페이지, 그룹 수 N이면 members 호출 N회 정도라 분당 2,400 한도에 한참 못 미친다.

## 6. 호출 한도 ([limits][limits])

- `403 userRateLimitExceeded`: 기본 "2,400 queries per minute per user per Google Cloud project". 콘솔 쿼터 화면에서 올릴 수 있다.
- `403 quotaExceeded`, `429 rateLimitExceeded`: 동시 요청 과다. 429는 "per Google Workspace account"이고 올릴 수 없다.
- 재시도: 지수 백오프 1·2·4·8·16초 + 최대 1,000ms 랜덤, n=5(약 32초)에서 포기.
- 페이지 크기: users 기본 100·최대 500, groups·members 최대 200.
- `members.list`는 60분에서 시간 초과 ([members-list][members-list]).

## 7. 파이썬 클라이언트

- 공식 quickstart: Python 3.10.7 이상, `google-api-python-client google-auth-httplib2 google-auth-oauthlib` ([python quickstart][py-quick]). 서비스 계정만 쓰면 `google-auth-oauthlib`(설치형 앱 OAuth 흐름)는 필요 없다(추론).
- `google.oauth2.service_account.Credentials.from_service_account_info(info, scopes=..., subject=...)` 또는 `.with_subject(...)`. `subject`는 "For domain-wide delegation, the email address of the user to for which to request delegated access" ([google-auth][google-auth]). 4.3 방식이면 `subject`를 생략한다.
- `googleapiclient.discovery.build("admin", "directory_v1", credentials=creds)`; 페이지는 `list_next(request, response)`로 넘긴다.
- Cloud Identity는 `build("cloudidentity", "v1", credentials=creds)` ([ci-setup][ci-setup]).
- Context7의 Directory 위임 예제(Reseller codelab)는 폐기된 `oauth2client`를 쓰므로 따르지 않는다.

```python
from google.oauth2 import service_account
from googleapiclient.discovery import build

SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
]
creds = service_account.Credentials.from_service_account_info(
    sa_info,            # OpenBao에서 읽은 JSON 키
    scopes=SCOPES,
    subject=SUBJECT,    # DWD일 때만. 4.3 방식이면 생략
)
svc = build("admin", "directory_v1", credentials=creds, cache_discovery=False)

req = svc.users().list(customer="my_customer", projection="full",
                       viewType="admin_view", maxResults=500)
while req is not None:
    resp = req.execute()
    for u in resp.get("users", []):
        ...  # id, primaryEmail, suspended, archived, orgUnitPath, posixAccounts, sshPublicKeys
    req = svc.users().list_next(req, resp)
```

## 미확인 목록 (카나리에서 확인)

1. 서비스 계정에 커스텀 관리자 역할을 직접 주는 방식(DWD 없음)으로 Directory API `admin_view`·`showDeleted`가 되는가.
2. DWD subject에 필요한 최소 관리자 권한(Users/Groups/OU Read로 충분한가, 커스텀 필드 포함).
3. `posixAccounts`·`sshPublicKeys`가 `projection=BASIC`에도 오는가, 관리 콘솔 UI에서 값을 넣을 수 있는가.
4. `groups.list?userKey=`가 간접 소속을 포함하는가.
5. Directory API의 `If-None-Match` 조건부 요청 지원 여부.
6. 우리 Workspace 에디션이 Cloud Identity transitive 메서드 대상인가(Enterprise 이상).

[users-res]: https://developers.google.com/workspace/admin/directory/reference/rest/v1/users
[users-list]: https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/list
[manage-users]: https://developers.google.com/workspace/admin/directory/v1/guides/manage-users
[search-users]: https://developers.google.com/workspace/admin/directory/v1/guides/search-users
[manage-schemas]: https://developers.google.com/workspace/admin/directory/v1/guides/manage-schemas
[schemas-res]: https://developers.google.com/workspace/admin/directory/reference/rest/v1/schemas
[orgunits-list]: https://developers.google.com/workspace/admin/directory/reference/rest/v1/orgunits/list
[groups-list]: https://developers.google.com/workspace/admin/directory/reference/rest/v1/groups/list
[manage-groups]: https://developers.google.com/workspace/admin/directory/v1/guides/manage-groups
[members-list]: https://developers.google.com/workspace/admin/directory/reference/rest/v1/members/list
[members-res]: https://developers.google.com/workspace/admin/directory/reference/rest/v1/members
[has-member]: https://developers.google.com/workspace/admin/directory/reference/rest/v1/members/hasMember
[authorizing]: https://developers.google.com/workspace/admin/directory/v1/guides/authorizing
[delegation]: https://developers.google.com/workspace/admin/directory/v1/guides/delegation
[create-cred]: https://developers.google.com/workspace/guides/create-credentials
[priv-defs]: https://knowledge.workspace.google.com/admin/users/administrator-privilege-definitions
[assign-roles]: https://knowledge.workspace.google.com/admin/users/assign-specific-admin-roles
[push]: https://developers.google.com/workspace/admin/directory/v1/guides/push
[limits]: https://developers.google.com/workspace/admin/directory/v1/limits
[reports-user]: https://developers.google.com/workspace/admin/reports/v1/appendix/activity/admin-user-settings
[ci-query]: https://docs.cloud.google.com/identity/docs/how-to/query-memberships
[ci-stg]: https://docs.cloud.google.com/identity/docs/reference/rest/v1/groups.memberships/searchTransitiveGroups
[ci-setup]: https://docs.cloud.google.com/identity/docs/how-to/setup
[google-auth]: https://googleapis.dev/python/google-auth/latest/reference/google.oauth2.service_account.html
[py-quick]: https://developers.google.com/workspace/admin/directory/v1/quickstart/python
