# 보안 로그(`security_logs`) 알림: 업계 탐지 목록과 현재 `infra-` 알림 대조

- 질문: `security_logs`에 들어오는 로그 종류별로 업계가 표준·리더 제품에서 어떤 알림을 두는지 조사하고, 현재 `o2c_alerts`와 비교해 빈 곳을 찾는다.
- 조사일: 2026-11-04
- 범위: `secure`·`auth.log`(sshd·sudo·su), `audit.log`(auditd), `sudo.log`, `fail2ban.log`, `firewalld`, 포티게이트 syslog. 호스트 메트릭 알림은 [alert-conditions-industry-baseline.md](alert-conditions-industry-baseline.md)가 다룬다.
- 방법: 1차 목록은 GitHub 저장소 트리에서 직접 읽었다(아래 "근거"). 우리 쪽은 `roles/openobserve_config/defaults/main.yml`의 알림 이름과 `roles/security/templates/audit.rules.j2`를 읽었다. 운영 서버에 질의하거나 실행하지 않았다.
- 한계: 규칙 파일의 제목·설명·등급만 읽었고 탐지 로직과 임계값은 하나씩 검증하지 않았다. Elastic은 저장소 목록을 받지 못해 문서 검색 결과로만 확인했다.

## 요약

1. **Sigma(`rules/linux`)는 로그 소스별로 규칙을 나눈다.** auditd 53개(execve 28, syscall 9, path 9, 그 외), `builtin`(syslog·cron·sshd 등) 22개다. 사람이 읽는 `auth.log` 인증 규칙은 Sigma에 거의 없고(sshd 오류 1개, 특권 사용자 생성 1개), Splunk·Wazuh·Elastic은 이 영역을 임계값·상관 규칙으로 따로 둔다.
2. **Splunk Security Content는 `linux_*` 탐지 191개를 둔다(상당수가 auditd 기반).** 이 가운데 우리 감시 키와 겹치는 것은 sudoers·sshd_config·계정 추가·auditd 중지·cron 변경이다.
3. **우리 알림은 인증·계정·감사 설정 영역이 이미 두텁다(알림 20여 개).** 이전 답변에서 "sudo 실패가 비어 있다"고 한 것은 **틀렸다**. `infra-sudo-escalation-failure`와 `infra-sudo-risky-command`가 있다.
4. **진짜 빈 곳은 다섯 가지다.**
   - `fail2ban.log`와 `firewalld` 로그를 보는 알림이 하나도 없다.
   - auditd 감시 키 `auth_config`(`/etc/pam.d/`, `login.defs`), `container_config`, `secret_access`는 수집만 하고 알림이 없다.
   - auditd 설정·로깅 설정 파일(`/etc/audit/`, `/etc/rsyslog*`) 변경은 감시 규칙부터 없다. Sigma는 둘 다 `high`로 둔다.
   - `authorized_keys` 변경, 커널 모듈 적재, `setuid` 설정, sudoers `NOPASSWD` 추가는 감시 규칙이 없다. Splunk가 각각 별도 탐지로 둔다.
   - 방화벽 규칙 수정·`firewalld` 중지(Sigma `lnx_auditd_modify_system_firewall`, `disable_system_firewall`, Splunk `auditd_disable_or_modify_system_firewall`)를 잡을 수단이 없다.

## 1. 로그별 업계 탐지와 현재 알림

범례: ✅ 있음, ◐ 부분, ❌ 없음. 현재 알림은 `infra-` 접두어를 뗀 이름이다.

### 1.1 `secure` / `auth.log` (sshd·sudo·su)

| 업계 탐지 | 근거 | 현재 | 알림 |
|---|---|---|---|
| SSH 무차별 대입 (같은 출발지 N회/시간창) | Wazuh 5712(120초 6회, level 10)·5720 | ✅ | `ssh-login-failures-per-source`, `ssh-login-failures-per-host` |
| 실패 뒤 성공 | Splunk ES "Brute Force Access Behavior Detected" | ✅ | `ssh-bruteforce-success` |
| root 직접 로그인 | 일반 관행 | ✅ | `root-login-success`, `root-login-known` |
| 미등록 출발지 로그인 | 일반 관행(Elastic "이상 로그인"은 ML) | ✅ | `ssh-login-unregistered-source` |
| sudo 실패 | Wazuh 5401(level 5) | ✅ | `sudo-escalation-failure` |
| sudo 위험 명령 | Splunk `sudo_or_su_execution` | ✅ | `sudo-risky-command` |
| 계정 잠금 | Splunk `detect_excessive_user_account_lockouts` | ✅ | `account-lockout` |
| 특권 그룹에 사용자 추가 | Sigma `lnx_privileged_user_creation`(high) | ◐ | `account-change`(auditd 쪽에서 잡음, 그룹 종류는 구분 안 함) |
| sshd 치명 오류 | Sigma `lnx_sshd_susp_ssh`(medium) | ❌ | 없음 |
| 비밀번호 스프레이(한 출발지가 여러 계정 시도) | Splunk `detect_password_spray_attempts` | ◐ | 출발지별 실패 합계로만 잡는다. 계정 수는 보지 않는다 |
| 인증 로그 수집 중단 | 업계 공통(로그 소스 감시) | ✅ | `auth-silent-p1`·`p2` |

### 1.2 `audit.log` (auditd)

| 업계 탐지 | 근거 | 현재 | 알림 |
|---|---|---|---|
| 계정 생성·변경 | Splunk `auditd_add_user_account`, Sigma `lnx_auditd_create_account` | ✅ | `account-change` |
| sudoers·sshd_config·passwd 계열 수정 | Splunk `auditd_possible_access_to_sudoers_file`·`..._sshd_config_file` | ✅ | `audit-watch-change`(키 `identity`·`sudo_config`·`sshd_config`) |
| auditd 중지·중단 | Splunk `auditd_auditd_service_stop`·`daemon_abort`·`daemon_shutdown` | ✅ | `auditd-stopped` |
| PAM·로그인 정책 변경 | CIS 감사 규칙 관행 | ❌ | 키 `auth_config`는 수집만 한다 |
| 비밀 파일 접근 | 일반 관행 | ❌ | 키 `secret_access`는 수집만 한다 |
| 컨테이너 설정 변경 | 일반 관행 | ❌ | 키 `container_config`는 수집만 한다 |
| auditd 설정 변경 | Sigma `lnx_auditd_auditing_config_change`(high) | ❌ | 감시 규칙 없음 |
| syslog 설정 변경 | Sigma `lnx_auditd_logging_config_change`(high) | ❌ | 감시 규칙 없음 |
| sudoers `NOPASSWD` 추가 | Splunk `auditd_nopasswd_entry_in_sudoers_file` | ◐ | `audit-watch-change`가 파일 수정으로 잡음. 내용은 보지 않음 |
| `authorized_keys` 수정 | Splunk `ssh_authorized_keys_modification` | ❌ | 감시 규칙 없음 |
| 커널 모듈 적재·제거 | Splunk `insert/install_kernel_module...`, Sigma `lnx_auditd_load_module_insmod` | ❌ | 감시 규칙 없음 |
| `setuid` 설정(chmod·setcap) | Splunk `setuid_using_chmod_utility`·`setcap_utility` | ❌ | 감시 규칙 없음 |
| 방화벽 중지·수정 | Sigma `lnx_auditd_modify_system_firewall`, Splunk `auditd_disable_or_modify_system_firewall` | ❌ | 감시 규칙 없음 |
| `chattr -i` (immutable 제거) | Sigma `lnx_auditd_chattr_immutable_removal` | ❌ | 감시 규칙 없음 |
| cron 변경 | Sigma `lnx_cron_crontab_file_modification`, Splunk `edit_cron_table_parameter` | ◐ | `root-crontab-change`(root만, `system_logs`) |
| 로그 삭제·히스토리 삭제 | Sigma `lnx_clear_syslog`, `lnx_shell_clear_cmd_history` | ❌ | 없음 |

### 1.3 `sudo.log`

`secure`와 같은 사건이 겹쳐 남는다. 별도 알림은 두지 않고 1.1을 적용한다. 감시 키 `sudo_logs`는 sudo 사용마다 남아 알림 대상에서 뺐다(`docs/openobserve_config.md`).

### 1.4 `fail2ban.log`

Sigma·Splunk·Wazuh에서 fail2ban 전용 규칙은 찾지 못했다. 아래는 일반 관행이며 근거가 약하다.

| 후보 | 현재 |
|---|---|
| 짧은 시간 Ban 급증 | ❌ |
| fail2ban 서비스 중지·jail 오류 | ❌ |
| 차단된 출발지의 같은 대역 재시도 | ❌ |

우리 쪽 맥락: fail2ban 차단은 `ssh-login-failures-*`와 사건이 겹친다. 차단 급증 하나만 먼저 두고 나머지는 보류하는 것을 권한다.

### 1.5 `firewalld`

Sigma·Splunk에서 `firewalld` 로그를 직접 해석하는 규칙은 없다(수정·중지는 auditd 쪽, 1.2). 일반 관행 후보: 관리 포트 거부 급증, 한 출발지의 다수 포트 접근(포트 스캔), 허용 목록 밖 출발지의 관리 포트 접근. 현재 모두 ❌다.

### 1.6 포티게이트 syslog

| 업계 탐지 | 근거 | 현재 | 알림 |
|---|---|---|---|
| 관리자 로그인 실패 | Fortinet 커뮤니티(log ID 32002) | ✅ | `fortigate-admin-login-failures` |
| 관리자 로그인 새 출발지 | Elastic·Sigma | ✅ | `fortigate-admin-login-new-source` |
| 설정 변경 | Fortinet alert email 설정 | ✅ | `fortigate-change-unapproved`, `fortigate-change-approved` |
| HA 전환 | 일반 관행 | ✅ | `fortigate-ha-failover` |
| IPS·UTM 중대 탐지 | LogPoint·Datadog 통합 | ✅ | `fortigate-critical-detection` |
| 로그 수집 중단 | 업계 공통 | ✅ | `fortigate-syslog-silent` |
| VPN 실패 | LogPoint | ❌ | 없음 |
| 관리자 로그인 여러 IP | Elastic | ◐ | 새 출발지 알림이 대부분 덮는다 |

### 1.7 Elastic 규칙 대조 (저장소 트리 직접 확인, 2026-11-04)

`elastic/detection-rules`의 `rules/linux`에는 규칙 파일이 380개 있다. 이름만 읽었고 쿼리는 읽지 않았다. 우리 영역과 겹치는 것만 추렸다.

| Elastic 규칙(이름 요지) | 현재 |
|---|---|
| SSH 무차별 대입(내부·외부 출발지, 성공 포함), 로컬 계정 무차별 대입 | ✅ 출발지별·호스트별 실패, 실패 뒤 성공 |
| 처음 보는 IP·사용자의 SSH 성공, 처음 쓰는 공개키 인증 | ◐ 미등록 출발지는 있고, 공개키 첫 사용·사용자 첫 로그인은 없다 |
| 사용자·그룹 생성·삭제, 특권 그룹 추가, 백도어 사용자 생성, `shadow` 수정 | ◐ 계정 변경과 감시 키로 대응. 삭제와 특권 그룹은 구분하지 않는다 |
| `authorized_keys` 삭제, SSH 백도어 로그, SSH 바이너리 수정 | ❌ |
| auditd·syslog·방화벽 서비스 중지 시도 | ◐ auditd만 있다 |
| 방화벽 규칙 생성·수정 | ❌ |
| 로그 파일 삭제, `journalctl` 로그 삭제, 셸 히스토리 삭제 | ❌ |
| `chattr` immutable, `setuid`·`setgid`·`setcap` 설정 | ❌ |
| 커널 모듈 적재·제거 | ❌ |
| PAM 모듈 생성 | ❌ (`auth_config` 감시 키가 `/etc/pam.d/`만 본다) |
| 비밀번호 없는 sudo 탐색 | ❌ |

## 2. 권고 (우선순위순)

각 항목은 별도 스펙 이슈로 나누는 것을 전제로 한다. 감시 규칙(auditd) 추가는 호스트 변경이므로 프로비저닝 대상 호스트에만 적용한다.

1. **이미 수집 중인 키에 알림을 붙인다 (감시 규칙 변경 없음).** `auth_config`, `container_config`, `secret_access`를 `audit-watch-change`에 키로 더하거나 별도 알림으로 둔다. 가장 싸다.
2. **auditd 감시 규칙을 추가한다.** 우선순위는 `/etc/audit/`·`/etc/rsyslog*`(로그 은폐), `authorized_keys`, 방화벽 설정 순서다. 추가한 키는 1번과 같은 방식으로 알린다.
3. **`fail2ban` Ban 급증 알림 하나**를 둔다. 임계값은 실로그를 7일 이상 재서 정한다(기존 SQL 알림과 같은 방식, `docs/openobserve_config.md`의 "SQL은 실로그로 맞췄다" 참고).
4. **sshd 치명 오류**(Sigma 키워드 목록)는 오탐을 실로그로 먼저 본다.
5. 커널 모듈·`setuid`·`chattr -i`는 Host Audit(정기 점검) 쪽 항목으로 옮기는 것이 알림보다 맞을 수 있다. 사건이 드물고 정상 변경이 프로비저닝에서 생긴다.
6. `firewalld` 로그 알림은 로그량과 오탐을 실측한 뒤 판단한다. 근거 출처가 약하다.

## 2.1 기본 수집 외에 더 수집하는 로그가 있나 (자체 검토)

현재 표준 수집 목록은 ADR-0006이 정한다. 업계가 더 수집하는 것을 하나씩 "수집할 필요가 있는가"로 따져 봤다.

| 후보 | 업계 근거 | 우리 현황 | 판단 |
|---|---|---|---|
| `wtmp`·`btmp`·`lastlog` 내용 | Elastic Auditbeat login 데이터셋은 utmp 파일(`wtmp`=성공, `btmp`=실패)을 읽는다. Splunk Unix 애드온은 `last`·`lastlog`·`who`를 스크립트로 수집한다. Wazuh는 `last -n 20` 출력을 기본 수집한다 | 바이너리라 제외(ADR-0006). 접속 증적은 auditd `USER_LOGIN`·`USER_AUTH`와 `secure`·`auth.log`로 대신 | **수집하지 않는다.** 같은 사건이 텍스트 로그에 이미 있다. 다만 "대신한다"는 주장을 실호스트에서 한 번 대조해 확인하지 않았다(미확인) |
| `wtmp`·`btmp`·`utmp` **파일 변경 감시** | CIS auditd 규칙은 이 파일에 쓰기·속성 감시(`-k session`, `logins`)를 건다. 내용 수집이 아니라 **위·변조 탐지**다 | 감시 규칙 없음 | **추가를 검토한다.** 로그인 기록 삭제는 흔적 은폐 징후다 |
| `journald` | Wazuh는 systemd journal을 기본 수집한다. rsyslog가 없는 Debian 12+는 `auth.log`·`syslog`가 생기지 않는다 | rsyslog 없는 호스트에만 journald 수신기(`host_agents_journald`)를 켠다. **모든 항목이 `system_logs`로 가고 `service.name=journald`다** | **빈틈 의심.** 그런 호스트의 sshd·sudo 인증 기록이 `security_logs`로 가지 않으면 `security_logs` 기반 알림(SSH 무차별 대입 등)이 울리지 않고 `auth-silent`만 울릴 수 있다. 해당 호스트가 실제로 있는지 읽기 전용으로 확인해야 한다(미확인) |
| `mail.log` | 일반 관행 | 수집 안 함 | 불필요. MTA를 쓰는 호스트가 없다면 근거 없음(미확인) |
| `ufw` 로그 | 일반 관행 | 수집 안 함(`firewalld`를 쓴다) | 불필요 |
| `faillock` 상태 파일 | CIS가 파일 감시를 요구 | pam_faillock 잠금 문구는 `secure`로 이미 수집, `account-lockout`이 알림 | 상태 파일은 불필요. 감시만 위 `session` 묶음에 포함 검토 |
| 시간 변경·`mount`·커널 모듈 syscall | CIS auditd 규칙(`time-change`, `mounts`, `kernel_modules`) | 감시 규칙 없음 | `audit.log`로 이미 수집되는 경로이므로 **규칙만 추가**하면 된다. 알림 여부는 별도 판단 |
| 특권 명령(setuid)·파일 삭제 | CIS 감사 규칙. 특권 명령은 setuid·setgid 바이너리마다 `perm=x`, `auid>=1000`(미설정 제외), 키 `privileged` 규칙을 만든다. 파일 삭제는 `unlink`·`unlinkat`·`rename`·`renameat`, `auid>=UID_MIN`, 키 `delete`다(ComplianceAsCode, Tenable 감사 항목) | 감시 규칙 없음 | **규칙을 추가하려면 `audit.log` 증가량부터 잰다.** 두 규칙 모두 일반 사용자의 모든 실행·삭제를 남기므로 양이 크다. 알림 대상이 아니라 증적용이다 |
| 로그 소스 구분(NIST SP 800-92 §2.1.2) | OS 로그의 감사 기록은 인증 성공·실패, 파일 접근, 보안 정책 변경, 계정 변경, 권한 사용을 담는다고 정의한다 | `secure`·`audit.log`가 이 다섯 가지를 대부분 덮는다. 정책 변경과 파일 접근은 감시 키(`auth_config`·`secret_access` 등)로 남지만 알림이 없다 | 우리 수집 범위가 NIST의 분류와 어긋나지 않는다. 빈틈은 수집이 아니라 알림이다 |

정리하면 "수집하는 로그 파일을 늘릴" 근거가 가장 강한 곳은 없다. 업계가 더 하는 것은 대부분 **auditd 규칙을 늘려 `audit.log`에 사건을 더 남기는 것**이다. 단 하나, journald 호스트의 인증 기록 라우팅은 실제 빈틈일 수 있어 확인이 먼저다.

## 3. 근거

- Sigma: [SigmaHQ/sigma `rules/linux`](https://github.com/SigmaHQ/sigma/tree/master/rules/linux) — 저장소 트리 API로 목록을 받았고 5개 규칙의 제목·설명·등급을 읽었다.
- Splunk: [splunk/security_content `detections/endpoint`](https://github.com/splunk/security_content/tree/develop/detections/endpoint) — 저장소 트리 API로 `linux_*` 파일 이름을 받았다. 설명과 임계값은 읽지 않았다.
- Wazuh: [PCI DSS 로그 분석](https://documentation.wazuh.com/4.1/pci-dss/log-analysis.html) — 규칙 5712·5720·5401·5402. 4.1 문서라 현재 버전의 ID·등급은 다를 수 있다.
- Elastic: [Unusual Sudo Activity](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/ml/privilege_escalation_ml_linux_anomalous_sudo_activity), [Unusual Login Activity](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/ml/credential_access_ml_suspicious_login_activity), [Spike in Failed Logon Events](https://www.elastic.co/guide/en/security/current/spike-in-failed-logon-events.html), [FortiGate Administrator Login from Multiple IP Addresses](https://www.elastic.co/guide/en/security/8.19/prebuilt-rule-8-19-21-fortigate-administrator-login-from-multiple-ip-addresses.html) — 검색 결과 요약만 확인했다.
- Fortinet: [관리자 로그인 실패 확인](https://community.fortinet.com/fortigate-3/technical-tip-how-to-check-failed-admin-logins-from-the-gui-and-cli-176715), [방화벽 인증 실패](https://community.fortinet.com/t5/FortiGate/Technical-Tip-Difference-between-firewall-authentication-failure/ta-p/253223).
- LogPoint: [FortiGate 통합](https://docs.logpoint.com/integrations-1/fortigate). Palo Alto: [알람 설정](https://docs.paloaltonetworks.com/ngfw/help/11-1/device/device-log-settings/define-alarm-settings).
- CIS Controls v8 8.11(감사 로그 검토): 인증 실패·특권 사용을 필수 이벤트로 명시한 출처는 찾지 못했다.
- 추가 수집(§2.1): [Wazuh 5.0-rc 로그 수집 기본값](https://documentation.wazuh.com/5.0-rc/user-manual/capabilities/log-data-collection/configuring-log-collection/configuration.html), [Elastic Auditbeat login 데이터셋](https://www.elastic.co/guide/en/beats/auditbeat/7.9/auditbeat-dataset-system-login.html), [Splunk Add-on for Unix and Linux 수집 데이터](https://docs.splunk.com/Documentation/UnixAddOn/latest/User/Whatdataarecollected), [CIS 세션 시작 정보 감사 규칙(Tenable 감사 항목)](https://tenable.com/audits/items/CIS_Ubuntu_12.04_LTS_Server_v1.0.0_L2.audit:ec35fab8cae816dee14174eb4f8045e0), [Debian 12 rsyslog 미설치 시 로그 위치](https://allthings.how/read-system-logs-without-rsyslog-on-debian-12). Wazuh 문서 페이지는 `auth.log`·`secure` 기본 수집 여부를 밝히지 않는다.
- 후속 확인(2026-11-04): [Wazuh `syslog-logs` 템플릿](https://github.com/wazuh/wazuh/blob/master/etc/templates/config/generic/localfile-logs/syslog-logs.template)은 `messages`·`auth.log`·`secure`·`syslog`·`kern.log`·`mail.log`·`dpkg.log`를 후보로 두고 `[!journald]` 표시를 붙인다(journald를 쓰지 않을 때만 파일을 본다). `audit.log`는 별도 템플릿이다. 다만 5.0-rc 문서는 `syslog`·`messages`·`audit.log`를 기본 수집이 아니라고 적어 둘이 어긋난다. 어느 쪽이 실제 기본값인지는 확정하지 못했다. 우리가 journald 호스트에서만 journald를 켜는 방식은 Wazuh와 같은 구조다.
- 후속 확인: [Red Hat CIS 문서](https://access.redhat.com/articles/7146814)는 RHEL 9·10이 `systemd-journald`와 `rsyslog`를 함께 실행한다고 적는다(그 문서는 `/var/log/secure` 경로를 말하지 않는다). 저널은 기본적으로 영속 저장하지 않는다. 우리 호스트가 RHEL 계열 기본 설치인지는 별개로 확인해야 한다.
- 후속 확인: [NIST SP 800-92 원문](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf) §2.1.2 "Audit Records"를 직접 읽었다(PDF 텍스트를 직접 추출). 위 표의 NIST 행이 그 내용이다.
- 후속 확인: Elastic 규칙 목록은 [저장소 트리](https://github.com/elastic/detection-rules/tree/main/rules/linux)에서 이름을 받았다(§1.7). CIS 특권 명령·파일 삭제는 [ComplianceAsCode PR](https://github.com/ComplianceAsCode/content/pull/10326)과 [Tenable 감사 항목](https://www.tenable.com/audits/items/CIS_Rocky_Linux_9_v2.0.0_L2_Server.audit:3f35fd82e20045d0a4ba1e95d253fbb7)의 규칙 형태로 확인했다. CIS 벤치마크 PDF 원문은 로그인이 필요해 보지 못했다.
- 우리 쪽: `roles/openobserve_config/defaults/main.yml`, `roles/security/templates/audit.rules.j2`, `docs/openobserve_config.md`.
