# wtmp·btmp 대조: auditd·secure가 로그인 성공·실패를 대신하는가 (2026-11-04)

> [Map #411 / Question] auditd·인증 로그가 wtmp·btmp를 대신하는가(#416)의 조사 결과다. ADR-0006 §2.3은 바이너리 로그(`wtmp`·`btmp`·`lastlog`)를 수집하지 않고 auditd `USER_LOGIN`·`USER_AUTH`와 `secure`/`auth.log`로 대신한다고 정했다. 이 문서는 그 전제를 실호스트에서 처음 대조한 기록이다. 공개 저장소라 호스트 이름·주소·계정은 적지 않고 대수와 OS 계열만 적는다. 호스트별 값과 대조 스크립트는 비공개 노트에 있다. 서버는 바꾸지 않았다(조회 명령만 실행).

## 결론

**대신한다.** 표본 4대에서 최근 7일 `wtmp` 163건과 `btmp` 10건, 그리고 CentOS 6 한 대의 31일치 `btmp` 6,075건을 대조했다. 그중 OpenObserve `security_logs`에 대응 기록이 없는 항목은 0건이었다. ADR-0006의 결정은 그대로 둔다.

다만 "기록이 있다"와 "지금 알림이 센다"는 다르다. 아래 [알림에 미치는 영향](#알림에-미치는-영향)의 두 사례는 `btmp`에는 실패로 남지만 현재 알림 집계에서는 빠진다.

## 조사 범위와 방법

| 계열 | 분류 | 대수 | 창 |
|---|---|---|---|
| Rocky 9.8 | 프로비저닝 대상 | 2대 | 7일 |
| CentOS 7.9 | 에이전트만 설치 | 1대 | 7일 |
| CentOS 6.9 | 에이전트만 설치 | 1대 | 7일, `btmp`는 압축 회전본까지 31일 |

- 호스트에서는 `last -F -w -x`와 `lastb -F -w`로 회전본까지 덤프했다. 압축 회전본은 임시 파일로 풀어 읽은 뒤 지웠다.
- OpenObserve에서는 같은 기간 `secure`/`auth.log`의 sshd·su·login 줄과 audit `USER_LOGIN`·`USER_AUTH`·`USER_ERR`·`USER_START`를 가져왔다.
- 짝짓기 규칙은 다음과 같다.
  - `wtmp`(성공): 사용자·출발지·tty가 같고 시각 차가 20초 이내인 `Accepted`·`session opened` 줄 또는 audit 기록(`terminal=/dev/pts/N`과 `addr` 일치, `res=success`).
  - `btmp`(실패): 사용자·출발지가 같고 시각 차가 20초 이내인 `Failed`·`Invalid user`·`authentication failure` 줄 또는 audit 기록(`res=failed`).
- `auth.log`를 쓰는 호스트(Debian/Ubuntu)는 7일간 0건이라 표본에 넣지 않았다. 지금은 해당 호스트가 없다.

## 결과

### 로그인 성공 (`wtmp` 163건, 누락 0)

- 163건 모두 같은 tty의 audit `USER_LOGIN`·`USER_START`가 있다.
- 104건은 `secure`의 `Accepted` 줄과도 바로 맞았다.
- 나머지 59건은 한 SSH 연결 안에서 tty를 여러 번 연 경우다(ControlMaster, Ansible `-tt`). `secure`는 연결마다 `Accepted`를 한 줄만 남기고 `wtmp`·audit은 tty마다 한 줄씩 남긴다. 59건 모두 같은 사용자·출발지의 `Accepted`가 1시간 안에 먼저 있었다.
- tty를 열지 않는 세션(명령 실행, scp, 대부분의 Ansible 작업)은 `wtmp`에 아예 남지 않는다. 반면 `secure`와 audit에는 남는다. 접속 증적으로는 로그 쪽이 `wtmp`보다 넓다.

### 로그인 실패 (`btmp` 6,084건, 누락 0)

- 7일 표본 10건과 CentOS 6 호스트의 31일치 6,075건이다(1건은 두 창에 겹친다). 31일치는 하루에 약 6천 건이 몰린 무차별 대입을 포함한다.
- 모두 `secure`(`Failed …`, `Invalid user …`)와 audit(`USER_LOGIN`/`USER_AUTH` `res=failed`) **양쪽**에 있다.
- 시각은 조금씩 어긋난다. `btmp`는 시도 시각을 남기고, audit은 존재하지 않는 계정이면 연결을 끊을 때 기록해 최대 18초 늦었다.
- 존재하지 않는 계정이면 audit은 시도한 이름을 남기지 않는다(`acct="(unknown)"`). 그 이름은 `secure`에만 있다. 두 소스는 서로 보완한다.

### su 실패 (1건, audit만)

- Rocky 9 호스트에서 `wheel` 그룹이 아닌 사용자가 `su`에 실패한 기록이 `btmp`에 있다(출발지 없는 `pts`).
- audit `USER_AUTH exe="/usr/bin/su" res=failed`(`grantors=?`)는 있었다. 같은 시각의 `secure`에는 호스트 원본 파일에도 줄이 없었다. `pam_wheel use_uid`가 `pam_unix`보다 먼저 거부해서 `pam_unix(su:auth): authentication failure` 줄이 생기지 않은 것으로 보인다.
- 결론: su 실패는 audit이 대신한다. `secure`만 보면 놓친다.
- CentOS 6의 `su`(coreutils)는 `btmp`를 쓰지 않으므로 그 계열에서는 대신할 `btmp` 기록이 없다. 표본 CentOS 6 호스트에서도 su 실패 `btmp`는 없었다.

### 재부팅·종료 기록 (로그인 질문 밖, 참고)

- `wtmp`의 `reboot`·`shutdown` 기록은 audit `SYSTEM_BOOT`·`SYSTEM_SHUTDOWN`에 대응한다. 프로비저닝 호스트 한 대의 재부팅에서 확인했다.
- 예외가 하나 있었다. SELinux autorelabel 부팅에서는 auditd가 뜨지 않아 audit 기록이 없다. 그 부팅은 `system_logs`의 커널 부팅 줄로만 보인다.

### 확인하지 못한 경로

- **콘솔(tty) 로그인**: 30일간 함대 전체에서 audit `USER_LOGIN terminal=tty…`가 0건이었고 표본 `wtmp`에도 없었다. PAM 표준상 `secure`의 `LOGIN ON tty…`와 audit `USER_LOGIN`이 남아야 하지만 실측하지 못했다.
- **Debian/Ubuntu(`auth.log`)**: 현재 해당 호스트가 없다.
- 수집 시작 전 기간: 일부 호스트는 수집 시작 시각이 `wtmp`·`btmp`보다 늦어 그 앞은 대조하지 않았다.

## 알림에 미치는 영향

두 사례는 기록은 있지만 현재 알림 집계(`event_outcome = 'failure'`)에서는 빠진다. 수집 결정과는 별개이며, 인증 영역 보충 알림을 정할 때 함께 다룬다(맵 #411).

1. **비밀번호를 시도하기 전에 끊긴 존재하지 않는 계정**: `btmp`에는 실패 1건으로 남는다. `secure`에는 `Invalid user`와 `Disconnected from invalid user … [preauth]`만 있다. `security_semantics` VRL은 `Invalid user` 줄에 `event_outcome`을 붙이지 않는다(같은 시도의 `Failed` 줄과 이중 집계를 막으려는 의도). 그래서 `Failed` 줄이 없는 이 경우는 실패로 세지 않는다. audit에는 `USER_LOGIN res=failed acct="(unknown)"`이 있다.
2. **`pam_wheel`이 거부한 su**: `secure`에 `pam_unix(su:auth)` 줄이 없어 VRL의 su 실패 해석이 동작하지 않는다. audit `USER_AUTH exe=…/su res=failed`에만 있다.

## 전제

- 대신하려면 수집이 끊기지 않아야 한다. 인증 로그 수집 중단은 별도 알림(#390)이 감시한다.
- audit 쪽 근거는 auditd가 떠 있어야 성립한다. 감시 규칙이 0개여도 PAM이 내는 `USER_*` 기록은 남는다. 규칙 적재 문제(#424)와 무관하다.
