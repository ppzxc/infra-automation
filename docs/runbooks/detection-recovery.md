# 탐지 복구 적용 런북 (무차별 대입 방어·감사 규칙·로그 영구 보존·중앙 수집)

> Spec #364 / #372. 방화벽 비관리 서버 두 대(ns0266, ns0331)에 `security` 역할의 탐지 설정을 적용하고 검증하는 절차다. 공개 저장소라 IP·포트·출발지·시크릿 경로는 적지 않는다. 결과 원본과 실제 값은 비공개 경로에 둔다. 이슈에는 통과 여부만 적는다. 이 런북은 저장소 코드의 변경 내용을 설명할 뿐 서버를 바꾸지 않는다. 서버 적용은 항목별로 운영자 승인을 받은 뒤 한다.

## 무엇이 바뀌는가 (SPEC-ID는 docs/security.md)

| 항목 | 변경 | SPEC-ID |
|---|---|---|
| fail2ban | sshd jail 유지, 차단 동작(banaction)을 `dummy`로 둬 방화벽 체인을 만들지 않는다(탐지·로그만) | `SEC-015` |
| auditd | 전체 execve 추적 제거. 인증·권한·sshd 설정·컨테이너 설정·시크릿 파일 접근만 기록 | `SEC-012`, `SEC-055`, `SEC-056` |
| journald | `Storage=persistent` 드롭인과 `/var/log/journal` | `SEC-053`, `SEC-054` |
| 중앙 수집 | 기존 Host Agents(otelcol)가 `audit.log`·`fail2ban.log`·시스템 로그를 보낸다(수집 경로 변경 없음) | monitoring 역할 |

## 적용 전 전제 (운영자 승인 필요)

1. **방화벽 비관리 그룹**: 두 서버가 인벤토리 그룹 `firewall_unmanaged`에 있어야 한다. 없으면 `fail2ban_banaction` 기본값이 비어 방화벽 동작이 남고 방화벽 태스크도 실행된다. Semaphore 인벤토리는 static이라 저장소가 아니라 Semaphore에서 확인한다.
2. **프로비저닝 게이트**: 두 서버는 `provision_excluded`에 있어 `provision_hosts.yml`이 접속 전에 거부한다. 적용하려면 한시적으로 `provision_allowed`로 옮기고 적용 뒤 원복한다(Semaphore 인벤토리 조작, 운영자 승인).
3. **Host Agents 편입(중앙 수집 전제)**: 감사·시스템 로그가 중앙에 도달하려면 두 서버에 Host Agents(otelcol)가 적용돼 있어야 한다. 에이전트가 없거나 `host_agents_excluded`면 중앙 수집 항목은 이 티켓에서 충족할 수 없다. 편입은 별도 승인·작업이며 여기서는 전제로만 둔다.
4. **시크릿 감시 경로**: `audit_watch_paths`에 시크릿 env·키 파일 경로를 Semaphore Environment 또는 인벤토리 변수로 넣는다(값은 비공개 경로에서 가져오고 저장소에 적지 않는다). 컨테이너 설정 위치가 `/etc/docker/` 밖이면 `audit_container_config_paths`에 추가한다.
5. **site 전체가 아니라 security 태스크만** 돌린다(`--tags` 또는 보안 전용 작업 템플릿이 없으면 `--check --diff`로 먼저 확인). `--check --diff`에서 방화벽 태스크가 하나도 나오지 않아야 한다.

## 1. 적용 전 기준선 스냅샷

```bash
scripts/collect-security-baseline.sh --label ns0266-before-372 --ssh <user>@<host>
scripts/collect-security-baseline.sh --label ns0331-before-372 --ssh <user>@<host>
```

결과는 비공개 경로(`~/.local/share/infra-automation/...`)에 남는다. 형식은 `docs/runbooks/security-baseline.md`를 따른다. 스냅샷에 fail2ban·auditd 상태와 적재 규칙, 시스템 로그 저장 방식, 방화벽 구간이 들어 있다.

## 2. 롤백 절차 (적용 전에 확인)

| 대상 | 롤백 |
|---|---|
| auditd 규칙 | 이전 `/etc/audit/rules.d/overseer.rules`를 적용 전에 비공개 경로로 복사해 둔다. 되돌릴 때 복사본을 같은 경로에 두고 `augenrules --load`(RHEL) 또는 `service auditd restart` |
| fail2ban jail | `/etc/fail2ban/jail.d/sshd.local` 복사본 복원 후 `systemctl restart fail2ban` |
| journald | `/etc/systemd/journald.conf.d/50-persistent.conf` 삭제 후 `systemctl restart systemd-journald`. `/var/log/journal`은 지우지 않는다(이미 쌓인 로그 보존) |
| 방화벽 | 변경이 없어야 한다. 변경이 감지되면 적용을 중단하고 보고한다. 체인을 직접 조작하지 않는다 |

## 3. 적용 (항목별 운영자 승인 후)

승인 받은 항목 순서대로 한 호스트씩 적용한다: 1) journald 영구 저장, 2) fail2ban 차단 동작, 3) 감사 규칙. 각 항목 뒤 아래 검증을 한다. 한 항목이 실패하면 다음 항목으로 넘어가지 않고 해당 롤백을 한다.

## 4. 검증 (적용 후 같은 명령, 같은 비공개 경로)

1. **스냅샷 diff**: 적용 후 `collect-security-baseline.sh`를 같은 옵션(`--label`만 `-after-372`)으로 돌려 전후 `snapshot.txt`를 diff한다. 바뀌어야 하는 구간은 fail2ban·auditd 적재 규칙·시스템 로그 저장 방식뿐이고, **방화벽 구간 diff는 비어 있어야 한다**. 방화벽 구간이 다르면 실패다.
2. **무차별 대입 방어 동작**: `fail2ban-client status sshd`에서 jail 활성과 감시 대상(로그 파일 또는 journal)을 확인한다. `fail2ban-client get sshd actions`에서 방화벽 액션이 없고 `dummy`뿐이어야 한다.
3. **감사 규칙 적재**: `auditctl -l`을 적용 전 목록과 diff한다. `execve` 규칙이 사라지고 `identity`·`auth_config`·`sudo_config`·`sshd_config`·`container_config`·`secret_access` 키가 보여야 한다. 규칙이 적재되지 않으면(`No rules`) `augenrules --load` 오류를 확인한다(없는 감시 경로가 있으면 실패한다).
4. **시험 이벤트(시크릿 파일 접근)**: 시크릿 감시 대상이 아닌 **시험용 파일**을 `audit_watch_paths`에 임시로 넣어(또는 승인된 시크릿 파일의 메타데이터만 읽는 `stat` 정도로) 접근한 뒤 `ausearch -k secret_access -ts recent`로 기록이 남는지 본다. 시크릿 파일의 내용은 읽지 않는다.
5. **재부팅 뒤 이전 부팅 로그**: 승인된 재부팅 창에서만 한다. 재부팅 전 `journalctl --list-boots`를 기록하고 재부팅 뒤 같은 명령에서 이전 부팅 항목이 보이는지 확인한다. 재부팅이 어려우면 `journalctl --header`/`ls /var/log/journal`로 영구 저장 상태까지만 확인하고 재부팅 항목은 남은 확인으로 기록한다.
6. **부정 시험**: 거부 시험 출발지는 "비공개 경로에 지정"한 값을 쓴다. 로그인 실패를 `maxretry`만큼 일으켜 fail2ban 로그에 탐지(`Found`/`Ban`)가 남는지 본다. `dummy`이므로 실제 차단은 되지 않는다. 방화벽 규칙이 늘지 않았는지(스냅샷 방화벽 구간) 함께 본다. 접속 중인 운영 세션은 끊지 말고 별도 세션을 유지한다.

## 5. 중앙 수집 도달 확인

Host Agents가 적용된 호스트에서 OpenObserve(SQL 모드)로 확인한다. 호스트 이름은 결과에서 읽는다.

```sql
SELECT host_name, count(*) AS records FROM "security_logs" GROUP BY host_name
```

- 감사 로그(`/var/log/audit/audit.log`)와 fail2ban 로그는 `security_logs` 스트림, 시스템 로그는 `system_logs`에 들어온다. 시험 이벤트(검증 4)와 같은 시각의 레코드가 해당 호스트로 보이면 통과다.
- 레코드가 없으면 Host Agents 적용 여부, otelcol 서비스 상태, 로그 파일 읽기 권한부터 확인한다. 편입 자체는 이 런북 범위 밖이다.
- 로그 보존·월간 점검은 `docs/runbooks/monthly-log-review.md`를 따른다.

## 6. Host Audit 연계

적용 뒤 Host Audit 드리프트 점검이 같은 인벤토리로 `security` 역할을 check 실행해 변경 없음(`ok`)을 확인한다. 드리프트가 보이면 이 런북의 설정이 바뀐 것이므로 원인을 확인하고 비공개 노트에 기록한다. 감사 규칙·journald 설정을 Host Audit 항목으로 추가하는 것은 #377에서 다룬다.

## 7. 기록

이슈에는 항목별 통과/실패만 적는다. 전후 스냅샷·`auditctl -l` 목록·시험 로그 원본은 비공개 경로에 둔다.
