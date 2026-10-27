# 탐지 복구 적용 런북 (무차별 대입 방어·감사 규칙·로그 영구 보존·중앙 수집)

> Spec #364 / #372. 방화벽 비관리 서버 두 대에 `security` 역할의 탐지 설정을 적용하고 검증하는 절차다. 공개 저장소라 IP·포트·출발지·시크릿 경로는 적지 않는다. 결과 원본과 실제 값은 비공개 경로에 둔다. 이슈에는 통과 여부만 적는다. 이 런북은 저장소 코드의 변경 내용을 설명할 뿐 서버를 바꾸지 않는다. 서버 적용은 항목별로 운영자 승인을 받은 뒤 한다.

## 무엇이 바뀌는가 (SPEC-ID는 docs/security.md)

| 항목 | 변경 | SPEC-ID |
|---|---|---|
| fail2ban | sshd jail 유지. 차단 동작(banaction)은 기본값(배포판 기본)을 유지하고, 이미 방화벽 연동으로 차단 중이지 않은 호스트에서만 운영자가 `dummy`를 명시한다 | `SEC-015` |
| auditd | 전체 execve 추적 제거. 인증·권한·sshd 설정·컨테이너 설정·시크릿 파일 접근만 기록. 로그 로테이션 상한(`max_log_file`·`num_logs`) | `SEC-012`, `SEC-055`, `SEC-056`, `SEC-081` |
| journald | `Storage=persistent` 드롭인과 `/var/log/journal`(그룹은 시스템 기본 `systemd-journal`) | `SEC-053`, `SEC-054`, `SEC-080` |
| 중앙 수집 | 기존 Host Agents(otelcol)가 `audit.log`·`fail2ban.log`·시스템 로그를 보낸다(수집 경로 변경 없음) | monitoring 역할 |

## 적용 전 전제 (운영자 승인 필요)

1. **방화벽 비관리 그룹**: 두 서버가 인벤토리 그룹 `firewall_unmanaged`에 있어야 한다. 없으면 방화벽 태스크도 실행된다(`fail2ban_banaction` 기본값은 그룹과 무관하게 비어 있어 배포판 기본 동작이다). Semaphore 인벤토리는 static이라 저장소가 아니라 Semaphore에서 확인한다.
2. **적용 방식(승인된 결정)**: 역할 적용(`provision_allowed` 임시 이동, `firewall_unmanaged` 등록)은 하지 않는다. 운영자가 승인한 대로 이 런북의 수동 절차(설정 파일 직접 편집)와 전후 스냅샷 diff로 증빙한다. 역할 코드는 Molecule과 신규 호스트용이다. 1번의 그룹 소속은 신규 호스트가 역할로 적용될 때의 전제이고, 수동 적용에서는 방화벽 구간 diff가 비어 있는지로 대신 확인한다.
3. **Host Agents 편입 상태**: 이미 편입되어 수집기가 동작하는 서버가 있다. 중앙 수집 도달은 5절의 읽기 전용 조회로 확인한다(서버에 접속해 바꾸지 않는다). 편입되지 않은 서버는 로컬 확인(검증 2~5)까지만 하고, 편입은 별도 승인·작업이다.
4. **시크릿 감시 경로**: `audit_watch_paths`에 시크릿 env·키 파일 경로를 Semaphore Environment 또는 인벤토리 변수로 넣는다(값은 비공개 경로에서 가져오고 저장소에 적지 않는다). 컨테이너 설정 위치가 `/etc/docker/` 밖이면 `audit_container_config_paths`에 추가한다.
5. **수동 편집 순서**: 설정 파일은 백업 복사본을 남기고 편집한 뒤 검증 명령(`sshd -T`가 아니라 해당 서비스의 설정 검사, 예: `fail2ban-client -t`, `augenrules --check`)을 통과하면 재시작한다. 재시작 뒤 별도 세션을 유지한 채 확인한다.

## 1. 적용 전 기준선 스냅샷

```bash
scripts/collect-security-baseline.sh --label <호스트A>-before-372 --ssh <user>@<host>
scripts/collect-security-baseline.sh --label <호스트B>-before-372 --ssh <user>@<host>
```

결과는 비공개 경로(`~/.local/share/infra-automation/...`)에 남는다. 형식은 `docs/runbooks/security-baseline.md`를 따른다. 스냅샷에 fail2ban·auditd 상태와 적재 규칙, 시스템 로그 저장 방식, 방화벽 구간이 들어 있다.

## 2. 롤백 절차 (적용 전에 확인)

| 대상 | 롤백 |
|---|---|
| auditd 규칙 | 이전 `/etc/audit/rules.d/overseer.rules`를 적용 전에 비공개 경로로 복사해 둔다. 되돌릴 때 복사본을 같은 경로에 두고 `augenrules --load`(RHEL) 또는 `service auditd restart` |
| fail2ban jail | `/etc/fail2ban/jail.d/sshd.local` 복사본 복원 후 `systemctl restart fail2ban` |
| journald | `/etc/systemd/journald.conf.d/50-persistent.conf` 삭제 후 `systemctl restart systemd-journald`. `/var/log/journal`은 지우지 않는다(이미 쌓인 로그 보존) |
| auditd 로테이션 | `auditd.conf`의 `max_log_file`·`num_logs`를 적용 전 값으로 되돌리고 `service auditd reload`(HUP). 적용 전 복사본을 비공개 경로에 둔다 |
| 방화벽 | 변경이 없어야 한다. 변경이 감지되면 적용을 중단하고 보고한다. 체인을 직접 조작하지 않는다 |

## 3. 적용 (항목별 운영자 승인 후)

승인 받은 항목 순서대로 한 호스트씩 적용한다: 1) journald 영구 저장, 2) fail2ban 차단 동작, 3) 감사 규칙. 각 항목 뒤 아래 검증을 한다. 한 항목이 실패하면 다음 항목으로 넘어가지 않고 해당 롤백을 한다.

## 4. 검증 (적용 후 같은 명령, 같은 비공개 경로)

1. **스냅샷 diff**: 적용 후 `collect-security-baseline.sh`를 같은 옵션(`--label`만 `-after-372`)으로 돌려 전후 `snapshot.txt`를 diff한다. 바뀌어야 하는 구간은 fail2ban·auditd 적재 규칙·시스템 로그 저장 방식뿐이고, **사람이 바꾸는 방화벽 설정 구간 diff는 비어 있어야 한다**(fail2ban 데몬이 런타임에 넣고 빼는 차단 규칙은 제외하고 읽는다). 그 밖의 방화벽 구간이 다르면 실패다.
2. **무차별 대입 방어 동작**: `fail2ban-client status sshd`에서 jail 활성과 감시 대상(로그 파일 또는 journal)을 확인한다. `fail2ban-client get sshd actions`가 의도한 banaction과 같은지 본다. 기본값(배포판 기본)을 유지한 호스트는 기존 방화벽 연동 액션이 그대로여야 하고, `dummy`를 명시한 호스트는 `dummy`뿐이어야 한다.
3. **감사 규칙 적재**: `auditctl -l`을 적용 전 목록과 diff한다. `execve` 규칙이 사라지고 `identity`·`auth_config`·`sudo_config`·`sshd_config`·`container_config`·`secret_access` 키가 보여야 한다. 규칙이 적재되지 않으면(`No rules`) `augenrules --load` 오류를 확인한다(없는 감시 경로가 있으면 실패한다).
4. **시험 이벤트(시크릿 파일 접근)**: 시크릿 감시 대상이 아닌 **시험용 파일**을 `audit_watch_paths`에 임시로 넣어(또는 승인된 시크릿 파일의 메타데이터만 읽는 `stat` 정도로) 접근한 뒤 `ausearch -k secret_access -ts recent`로 기록이 남는지 본다. 시크릿 파일의 내용은 읽지 않는다.
5. **재부팅 뒤 이전 부팅 로그**: 승인된 재부팅 창에서만 한다. 재부팅 전 `journalctl --list-boots`를 기록하고 재부팅 뒤 같은 명령에서 이전 부팅 항목이 보이는지 확인한다. 재부팅이 어려우면 `journalctl --header`/`ls /var/log/journal`로 영구 저장 상태까지만 확인하고 재부팅 항목은 남은 확인으로 기록한다.
6. **부정 시험**: 거부 시험 출발지는 "비공개 경로에 지정"한 값을 쓴다. 로그인 실패를 `maxretry`만큼 일으켜 fail2ban 로그에 탐지(`Found`/`Ban`)가 남는지 본다. `dummy`를 명시한 호스트는 실제 차단이 되지 않는다. 기본값을 유지한 호스트는 fail2ban 데몬이 런타임에 규칙을 넣고 빼므로 차단 건수가 늘 수 있다. 이는 역할이 체인을 조작한 것이 아니다(`docs/security.md`: 방화벽 체인을 직접 조작하지 않는 원칙은 Ansible 태스크에 대한 것이고, fail2ban의 런타임 규칙은 별개다). 스냅샷 방화벽 구간의 diff는 fail2ban이 만든 규칙과 사람이 바꾼 규칙을 구분해 읽는다. 접속 중인 운영 세션은 끊지 말고 별도 세션을 유지한다.

## 5. 중앙 수집 도달 확인 (편입된 서버)

이미 편입되어 수집기가 동작하는 서버는 아래 읽기 전용 조회로 도달을 확인한다. 편입되지 않은 서버는 이 절을 건너뛰고 로컬 확인(검증 2~5)까지만 한다.
Host Agents가 적용된 호스트에서 OpenObserve(SQL 모드)로 확인한다. 호스트 이름은 결과에서 읽는다.

```sql
SELECT host_name, count(*) AS records FROM "security_logs" GROUP BY host_name
```

- 감사 로그(`/var/log/audit/audit.log`)와 fail2ban 로그는 `security_logs` 스트림, 시스템 로그는 `system_logs`에 들어온다. 시험 이벤트(검증 4)와 같은 시각의 레코드가 해당 호스트로 보이면 통과다.
- 레코드가 없으면 Host Agents 적용 여부, otelcol 서비스 상태, 로그 파일 읽기 권한부터 확인한다. 편입 자체는 이 런북 범위 밖이다.
- 로그 보존·월간 점검은 `docs/runbooks/monthly-log-review.md`를 따른다.

## 6. Host Audit 연계

적용 뒤 Host Audit 드리프트 점검이 같은 인벤토리로 `security` 역할을 check 실행해 변경 없음(`ok`)을 확인한다. 드리프트가 보이면 이 런북의 설정이 바뀐 것이므로 원인을 확인하고 비공개 노트에 기록한다. fail2ban·감사 규칙·journald·수집 에이전트는 Host Audit 퇴행 점검 항목 `EXP-DET-1`~`EXP-DET-7`이 계속 확인한다([Host Audit 명세 16절](../host_audit.md), [적용 런북](host-audit-regression.md)).

## 7. 한계와 남은 일

- **`dummy`를 명시한 호스트는 fail2ban이 탐지만 한다.** 기본값(배포판 기본)을 유지하면 기존 방식의 차단이 그대로다. `dummy`일 때는 실제 차단은 하지 않고 실제 차단은 #371 sshd 출발지 제한([ssh-source-restriction.md](ssh-source-restriction.md))이 맡는다. 허용 출발지 안에서 오는 대입 시도는 탐지(로그)만 되고 차단되지 않는다. 필요하면 후속으로 sshd `MaxAuthTries` 같은 애플리케이션 수준 제한을 둔다.
- **덮어쓰기 한계**: 백업 호스트 키의 PutObject 덮어쓰기는 막지 못하고 중앙 check가 탐지한다([backup-host-key-scope.md](backup-host-key-scope.md)).
- **#375 순서**: 권한 정렬과 이미지 버전 목록은 먼저, 평문 정리·잔재 삭제는 #374 보관 완료 확인 뒤에 한다([secret-file-permissions.md](secret-file-permissions.md)).

## 8. 서버 적용에서 알게 된 점

- **감사 규칙 적재**: 규칙 파일을 바꾼 뒤에는 `augenrules --load`로 적재한다(`augenrules --check`는 변경 여부만 본다). 서비스 재시작은 systemd가 거부하므로 `service auditd reload`(HUP)나 `augenrules --load`를 쓴다.
- **로그 디렉터리 소유**: `/var/log/journal`의 시스템 기본은 `root:systemd-journal`(부팅 시 `systemd-tmpfiles`가 맞춘다). 손으로 만든 디렉터리가 다르면 `systemd-tmpfiles --create --prefix /var/log/journal`로 기본에 맞춘다.
- **fail2ban 설정이 서비스 시작 뒤에 생성된 경우**: jail 파일이 데몬 시작 뒤에 만들어지면 로드되지 않은 채 남는다. `fail2ban-client -t`로 검사한 뒤 `fail2ban-client reload`를 하고 `fail2ban-client status`에 jail이 보이는지 확인한다.
- **`ausearch -ts`가 0건일 때**: 기록이 없다는 뜻이 아닐 수 있다(시각 해석·로그 순환). 감사 로그 원본 파일에서 해당 키(`-k`)가 찍혔는지 직접 확인한 뒤 판정한다.
- **상위 디렉터리 권한으로 일반 계정이 존재를 확인할 수 없는 경로**(권한이 좁은 설정 디렉터리 등): `test -e`가 거짓으로 나올 수 있으므로 `sudo -n`으로 확인한다.
- **적용 전 롤백 복사본**은 서버에 남기지 말고(남겼다면 정리 대상 여부를 운영자가 정한다) 비공개 경로에 둔다.

## 9. 로그 로테이션과 보존 상한

- **auditd**: 변수 `audit_max_log_file`(MB, 기본 50)과 `audit_num_logs`(기본 10)가 `auditd.conf`에 반영된다(`SEC-081`). 합계(기본 약 500MB)가 감사 로그 상한이다. 수동 적용이면 같은 두 줄을 편집하고 `service auditd reload`로 읽힌다. 실제 순환은 로그가 한 번 이상 찼을 때 나타나므로 반영 직후에는 HUP 신호 로그만 확인하고, 순환 결과는 시간이 지난 뒤 `ls -l /var/log/audit/`로 본다.
- **journald**: 상한은 `common` 역할이 `/etc/systemd/journald.conf.d/99-retention.conf`로 정한다(`COMMON-017`, `journald_max_use`·`journald_max_retention`). 같은 이름을 재사용하고 이 역할에서 따로 만들지 않는다. `common`이 적용되지 않은 호스트에서 수동으로 둘 때만 같은 파일명으로 둔다.
- **rsyslog(`/var/log/messages` 계열)**: 이 저장소는 logrotate를 바꾸지 않는다. 한 파일이 폭주할 수 있는 호스트에는 logrotate에 `maxsize`를 두는 것을 권고한다(운영자가 항목별로 승인해 적용). 이미 쌓인 큰 파일은 중앙 수집본을 확인한 뒤 항목별 승인으로만 정리한다.

## 10. 기록

이슈에는 항목별 통과/실패만 적는다. 전후 스냅샷·`auditctl -l` 목록·시험 로그 원본은 비공개 경로에 둔다.
