# OpenObserve 알림 런북

> OpenObserve 알림(`roles/openobserve_config/defaults/main.yml`의 `o2c_alerts`)을 받았을 때의 대응 절차다. 네이버웍스 알림 메시지의 `▶ 런북` 링크가 이 문서의 각 절로 연결된다.
> 알림 정의와 전송 구조는 [openobserve_config.md](../openobserve_config.md), 로그 필드는 [ADR-0008](../adr/0008-log-structuring-edge-envelope-central-semantics.md)을 본다.

## 심각도

| 심각도 | 의미 | 응답 목표 |
|---|---|---|
| 🔴 P1 긴급 | 장애·데이터 손실·침해가 진행 중이거나 수 시간 내 임박 | 즉시 확인 (업무 시간 외 포함) |
| 🟠 P2 경고 | 방치하면 하루~며칠 내 P1이 된다 | 당일 확인 |
| 🟡 P3 주의 | 탐지·수집 품질 문제. 직접 피해는 없다 | 업무 시간에 처리 |

### 재통지 원칙 (Event Alert / State Alert)

- **Event Alert**: 사건이 일어났다는 알림. silence가 조회 구간과 같아 구간마다 1번만 온다.
- **State Alert**: 어떤 상태가 계속된다는 알림. 상태가 이어지는 동안 P1은 60분, P2·P3은 1440분(하루 1번)마다 다시 온다. 복구 통지는 없다(통지가 멈추면 복구).
- 이중 등급 알림(디스크·inode·메모리)은 P2가 "P2 이상 P1 미만" 구간만 잡아 같은 대상에 P1·P2가 동시에 오지 않는다. CPU 사용률(P2 90% 이상 / P3 80~90%)과 디스크 고갈 전망(P1 4시간 / P2 24시간)도 같다.
- **지속 조건(#318)**: "N분 지속"이라고 적힌 알림은 조건이 처음 맞은 뒤 N분 동안 평가마다 계속 맞아야 울린다(알림의 `pending_period_sec`, Prometheus `for:`와 같은 뜻). 한 번이라도 안 맞으면 처음부터 다시 센다. PromQL 알림의 평가 한 번은 조회 구간 안의 한 점만 넘어도 맞는 것으로 치므로, "내내"는 조회 구간이 아니라 이 대기로 만든다.

## 공통 절차

1. 메시지의 `▶ 로그 보기`로 OpenObserve에서 알림 조건에 맞는 원문 로그(최근 1일, 최신순 200줄)를 바로 연다. 같은 메시지의 `▶ 상세 보기`는 알림 화면(집계 결과)이다. `▶ 로그 보기`가 알림 화면으로 열리는 알림(원문 조건을 만들 수 없는 알림)과 메트릭 알림(`▶ 상세 보기`만 있음)은 알림 화면에서 이어 조회한다. 원문 링크는 열 때부터 1일 전까지를 보므로 오래된 알림은 `⏱ 발생` 시각이 구간 밖일 수 있다. `⏱ 발생` 시각은 알림이 평가된 시각이며 **UTC**다(KST는 +9시간, 예: `13:31` = KST 22:31). `■ 대상 N건`은 조건에 걸린 전체 건수이고 행은 20줄까지만 실린다.
2. `■ 대상`의 호스트·출발지·사용자를 작업 일정, 배포 기록(Semaphore Task 이력)과 대조한다. Semaphore와 사무실에서 시작된 접속은 대부분 운영 작업이다(정상 출발지 목록은 OpenBao `normal_sources`).
3. 대응하면 결과(원인, 조치, 담당자)를 기록한다. ISMS 2.11.5(사고 대응) 증적이 된다.
4. 같은 알림이 반복되고 원인이 정상 작업이면 임계값이나 예외 조건을 고치는 PR을 낸다. 알림을 끄지 않는다.

---

<a id="root-login-success"></a>
## 🔴 root 계정 원격 로그인 성공 — 외부 출발지 (`infra-root-login-success`)

**조건**: `security_logs`에서 `user_name = 'root'`인 SSH 로그인 성공이 5분 안에 1건 이상이고, 출발지가 **정상 출발지 목록에도 사설 대역에도 없을 때**(진짜 외부 출발지). 목록의 출발지(kind 무관)와 미등록 사설 대역은 아래 P2(알고 있는 출발지)로 간다. 출발지 값이 없는 로그인은 알 수 없는 출발지라 이 P1이다.

**정상 출발지 목록**: OpenBao `agents/openobserve`의 `normal_sources`(`[{"address": "<IP>", "kind": "semaphore|office"}]`)에만 둔다. 저장소에는 주소를 두지 않는다. 바꾼 뒤 `OpenObserve — Config`를 다시 실행하면 반영된다. `kind`는 구분용 표시이고 판정은 같다(semaphore·office 모두 P1에서 빠지고 P2로 간다). 사설 대역은 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16이다. 목록이 비어 있으면 모든 공인 출발지 root 로그인이 이 P1로 오고 사설 대역은 P2로 간다. SSH 로그인 실패 급증 알림에는 이 목록을 적용하지 않는다(정상 출발지의 실패 급증도 신호다).

**왜 중요한가**: root 직접 접속은 누가 접속했는지 식별할 수 없고, 프로비저닝 이후에는 막혀야 한다(`PermitRootLogin`, KISA U-01). 등록되지도 사내도 아닌 곳의 성공 기록은 침해이거나 설정이 우회된 것이다.

**확인**
```bash
# 대상 서버에서
sudo grep -E "Accepted .* for root" /var/log/secure | tail      # Debian 계열: /var/log/auth.log
sudo sshd -T | grep -i permitrootlogin
last -i root | head
```

**대응**
- 출발지가 새로 편입된 Semaphore·사무실 주소로 확인되면 `normal_sources`에 추가하고 Config를 다시 실행한다. 부트스트랩 모드(아직 site.yml로 프로비저닝되지 않은 호스트)에서는 root 접속이 정상이지만 출발지는 보통 Semaphore 목록에 있다.
- 확인되지 않은 접속이면: 해당 세션 종료(`pkill -KILL -t <tty>`), root 비밀번호 변경, OpenBao 값 갱신, 보안 담당에게 보고한다.
- `PermitRootLogin`이 `yes`로 되어 있으면 site.yml(`security` 역할)을 다시 적용한다.

**격상**: 출발지가 외부 IP이고 작업자가 확인되지 않으면 즉시 침해 대응으로 전환한다.

---

<a id="root-login-known"></a>
## 🟠 root 계정 원격 로그인 성공 — 알고 있는 출발지 (`infra-root-login-known`)

**조건**: `user_name = 'root'`인 SSH 로그인 성공이 5분 안에 1건 이상이고, 출발지가 `normal_sources`에 있거나(kind 무관: semaphore·office) 목록에 없는 사설 대역(10/8, 172.16/12, 192.168/16, 127/8, 169.254/16)일 때. 재통지 간격은 기본 60분이고 역할 변수 `o2c_root_known_silence_minutes`로 바꾼다. 이전의 하루 요약 알림(`infra-root-login-office-daily`, P3)을 대체하며 기존 알림은 기본 폐기 목록(`o2c_retired_alerts`)에 있어 반영 때 삭제된다.

**왜 중요한가**: 알고 있는 출발지여도 정책상 금지된 root 직접 접속(`PermitRootLogin`)이 일어났다는 뜻이다. 등록된 출발지면 작업·배포일 가능성이 높고, 미등록 사설 출발지면 내부 이동(횡적 이동) 가능성을 확인해야 한다.

**대응**
- 등록된 출발지면 작업·배포 일정과 대조하고, 일반 계정 + sudo로 전환하도록 안내한다. 배포 자동화가 root로 접속하면 접속 계정을 바꾸는 PR을 낸다.
- 미등록 사설 출발지면 그 장비의 소유자와 접속 경위를 확인한다. 정상 출발지로 확정되면 `normal_sources`에 추가하고 Config를 다시 실행한다.
- 확인되지 않으면 세션 종료, root 비밀번호 변경 후 위 P1 절차(외부 출발지)로 격상한다.

---

<a id="oom-kill"></a>
## 🟠 OOM kill로 프로세스 강제 종료 (`infra-oom-kill`)

**조건**: `system_logs`에 `Killed process`, `Out of memory: Kill process`, `invoked oom-killer`가 대소문자와 상관없이 5분 안에 1건 이상. 컨테이너 cgroup OOM(`Memory cgroup out of memory: Killed process`)과 CentOS 6/7 형식을 포함한다. 같은 상태는 조회 구간(5분)마다 다시 통지된다(Event Alert).

**왜 중요한가**: 서비스 프로세스가 강제 종료됐다는 뜻이다. 반복되면 다른 서비스와 서버 전체로 번진다.

**확인**
```bash
sudo dmesg -T | grep -iE "out of memory|killed process|oom-killer" | tail
free -h; ps aux --sort=-%mem | head -5
docker stats --no-stream        # 컨테이너 한도(cgroup) OOM이면
```

**대응**
- `■ 대상`의 종료된 프로세스가 서비스면 재기동 상태를 확인한다.
- 메모리 상위 프로세스와 한도(JVM 힙, 컨테이너 limit)를 점검하고, 반복되면 증설이나 한도 조정을 계획한다.

**격상**: 같은 호스트에서 OOM이 반복되며 핵심 서비스가 계속 죽으면 P1로 다룬다.

---

<a id="disk-fs-errors"></a>
## 🔴 디스크 I/O·파일시스템 오류 발생 (`infra-disk-fs-errors`)

**조건**: `system_logs`에 `I/O error`, `EXT4-fs error`, `XFS ... Corruption`, `blk_update_request`, `Buffer I/O error`가 대소문자와 상관없이 5분 안에 1건 이상(Event Alert).

**왜 중요한가**: 디스크 고장이나 데이터 손상의 전조다. 프로세스 종료(OOM)와 달리 데이터 손실 위험이 있어 P1로 따로 통지한다.

**확인**
```bash
sudo dmesg -T | grep -iE "i/o error|ext4-fs error|xfs|blk_update_request" | tail
sudo smartctl -H /dev/sdX; df -h; mount | grep "ro,"
```

**대응**
- 먼저 백업 상태를 확인한다(RustFS snapshot, `restic snapshots`).
- 파일시스템이 읽기 전용으로 바뀌었으면 서비스 영향을 판단하고 디스크 교체·fsck 일정을 잡는다.

**격상**: 파일시스템이 읽기 전용으로 바뀌었거나 같은 디스크 오류가 반복되면 하드웨어 장애로 IDC에 연락한다.

---

<a id="keepalived-script-disabled"></a>
## 🔴 keepalived 헬스 체크·알림 스크립트가 비활성화됨 (`infra-keepalived-script-disabled`)

**조건**: `app_logs`에서 컨테이너 `vrrp-keepalived-1`의 로그에 `Unsafe permissions found for script` 또는 `Disabling track script`가 5분 안에 1건 이상(Event Alert). keepalived는 레벨이 없는 로그라 문구로 잡는다.

**왜 중요한가**: keepalived는 `enable_script_security`가 켜져 있으면 스크립트와 그 디렉터리를 root가 아닌 그룹이 쓸 수 있을 때 스크립트를 **조용히 비활성화**한다. 헬스 체크(`check.sh`)가 꺼지면 funa가 내려가도 FAULT 전환과 VIP 페일오버가 없고, 알림(`notify.sh`)이 꺼지면 상태가 바뀌어도 봇에 알림이 가지 않는다. 권한은 keepalived가 **시작할 때만** 검사하므로 이 줄은 재시작 직후 한 번만 남는다.

**확인**
```bash
ls -ld /opt/services/vrrp/config /opt/services/vrrp/config/*.sh   # 목표: 디렉터리 root:root 0755, 스크립트 root:root 0755
docker logs vrrp-keepalived-1 2>&1 | grep -iE "unsafe permissions|disabling track|VRRP_Script"
```

**대응**
- Semaphore에서 `Host Provisioning`(대상 호스트를 `target_hosts`로)을 실행하면 `funa_env`(FUNA-011~014)가 권한을 `root:root 0755`/`0644`로 맞춘다. 급하면 `sudo chown root:root`와 `sudo chmod 0755`로 직접 고쳐도 된다.
- 권한은 시작 시에만 검사하므로 고친 뒤 keepalived 컨테이너를 **재생성**해야 반영된다(VIP가 잠깐 이동하고 상태 전이 알림이 온다). 시작 로그에 `Unsafe permissions`가 없고 `VRRP_Script(check) succeeded`가 보이면 정상이다.

**격상**: 같은 노드에서 반복되거나 여러 노드에서 동시에 나오면 `/opt/services`의 SGID·기본 ACL 상속(DOC-016/017)과 운영자 umask(DOC-018) 때문에 누가 스크립트를 새로 만들었는지 확인한다.

---

<a id="app-log-errors"></a>
## 🟠 컨테이너 로그에 ERROR 이상 기록 (`infra-app-log-errors`)

**조건**: `app_logs`에서 수집기가 올린 `severity`가 error 이상(`error`·`err`·`severe`·`fatal`·`critical`·`panic`·`dpanic`, 대소문자 무시)인 줄이 호스트·컨테이너별로 5분 안에 1건 이상(Event Alert).

**레벨이 올라오는 형식**: JSON 한 줄 로그의 `level` 또는 `log.level`(앱·Caddy), valkey 텍스트 로그의 레벨 문자. keepalived처럼 레벨이 없는 로그와 JSON이 아닌 줄(스택 트레이스 이어지는 줄 등)은 알림 대상이 아니다(키워드로 추정하지 않는다). WARN은 알리지 않고 검색용으로만 남는다.

**왜 중요한가**: 앱 장애, 요청 실패, DB·큐·캐시 연결 문제의 첫 신호일 수 있다.

**확인**
```bash
# OpenObserve에서: app_logs, host_name=<행의 호스트>, container_name=<행의 컨테이너>, severity가 error 이상
# 노드에서 직접 볼 때
docker logs --since 10m <컨테이너 이름> 2>&1 | grep -iE '"level":"(error|fatal)"' | tail
```

**대응**
- ERROR 원문과 직전 줄로 원인을 좁힌다(DB·RabbitMQ·valkey 연결, 설정 오류).
- 같은 시각의 VIP 전환, valkey 알림, Silent Host가 있는지 대조한다.
- 서비스 영향이 있으면 해당 노드를 서비스에서 뺀다(valkey 수동 페일오버 → keepalived 정지).

**격상**: 여러 노드에서 동시에 오거나 앱 헬스가 DOWN이면 서비스 장애로 처리한다.

---

<a id="ssh-login-failures-per-source"></a>
## 🟠 한 출발지에서 SSH 로그인 실패 급증 (`infra-ssh-login-failures-per-source`)

**조건**: 같은 `source_address`에서 5분 동안 SSH 로그인 실패 10회 이상.

**왜 중요한가**: 무차별 대입 공격의 전형적인 형태다. fail2ban이 동작하면 이 정도로 쌓이기 전에 차단돼야 한다.

**확인**
```bash
sudo fail2ban-client status sshd
sudo grep "<출발지IP>" /var/log/secure | tail
```

**대응**
- 사내·작업자 IP면 해당 자동화(Semaphore 작업 등)의 자격증명을 확인한다. 오늘 사례처럼 OpenBao 비밀번호가 실제와 다르면 같은 실패가 반복된다.
- 외부 IP면 fail2ban이 차단했는지 확인하고, 안 됐으면 방화벽에서 차단한다.

**격상**: 같은 출발지에서 로그인 **성공** 기록이 있으면 P1로 다룬다.

---

<a id="ssh-login-failures-per-host"></a>
## 🟠 한 서버에 SSH 로그인 실패 급증 (`infra-ssh-login-failures-per-host`)

**조건**: 한 서버에서 5분 동안 SSH 로그인 실패 50회 이상(출발지 무관).

**왜 중요한가**: 여러 출발지에서 오는 분산 공격이라 출발지별 알림과 fail2ban에 잡히지 않을 수 있다.

**대응**
- `▶ 로그 보기`에서 출발지 분포를 본다. 출발지가 많고 외부면 SSH 포트를 인터넷에 노출할 필요가 있는지 검토하고, 방화벽 허용 범위를 줄인다.
- 한두 개 내부 출발지면 자격증명이 틀린 자동화 작업이다. 해당 작업을 멈추고 자격증명을 고친다.

---

<a id="sudo-escalation-failure"></a>
## 🟠 sudo/su 권한 상승 실패 (`infra-sudo-escalation-failure`)

**조건**: sudo/su 인증 실패 또는 `NOT in sudoers` 기록이 5분 안에 1건 이상. 성공은 알리지 않고 기록만 한다.

**왜 중요한가**: 탈취한 일반 계정으로 권한 상승을 시도하는 단계일 수 있다. 단순 비밀번호 오입력도 같은 기록을 남긴다.

**확인**
```bash
sudo grep -E "(sudo|su)(\[[0-9]+\])?: .*(authentication failure|NOT in sudoers|FAILED SU)" /var/log/secure | tail
last -i <사용자> | head
```

**대응**
- 해당 사용자에게 시도 여부를 확인한다.
- 본인이 아니면 계정을 잠그고(`usermod -L`), 비밀번호를 바꾸고, 그 계정의 접속 출발지를 추적한다.

---

<a id="ssh-bruteforce-success"></a>
## 🔴 SSH 무차별 대입 뒤 로그인 성공 (`infra-ssh-bruteforce-success`)

**조건**: 같은 `source_address`가 15분(`o2c_ssh_bruteforce_window_minutes`) 안에 한 서버에서 SSH 로그인에 10회(`o2c_ssh_bruteforce_min_failures`) 이상 실패하고 1번 이상 성공(재통지 15분). 사용자 이름은 따지지 않는다. Elastic "Potential Successful Linux SSH Brute Force"와 같은 생각이고, 실패 임계는 출발지별 실패 급증 알림(P2)과 같다. 이 알림이 생기기 전 그 알림의 "성공 기록이 있으면 P1로 격상" 절차를 자동으로 하는 것이다.

**왜 중요한가**: 무차별 대입이 성공했을 수 있다. 계정이 탈취됐다면 공격자는 이미 서버 안에 있다.

**확인**
```bash
sudo grep "<출발지IP>" /var/log/secure | grep -E "Accepted|Failed" | tail -30
last -i | grep "<출발지IP>"
```

**대응**
- 출발지가 사무실·Semaphore면 비밀번호를 여러 번 틀린 작업자일 가능성이 크다. 작업자에게 확인하고 기록을 남긴다.
- 확인되지 않으면 성공한 계정의 비밀번호를 바꾸고 세션을 끊는다(`pkill -u <계정>`). 출발지를 방화벽에서 막고 보안 담당에게 보고한다. 성공 뒤 그 계정의 sudo·계정 변경 기록(아래 알림들)을 본다.

**한계**: 수집 함수(`security_semantics`)는 프로그램 이름이 `sshd`인 줄만 해석한다. OpenSSH 9.8 이후의 `sshd-session` 줄(2026-10-22 기준 5개 호스트)은 `event_action`이 비어 이 알림과 다른 SSH 알림에 잡히지 않는다. 함수를 고치기 전까지 그 호스트들은 감시 공백이다.

---

<a id="account-change"></a>
## 🟠 계정·그룹 변경 (`infra-account-change`)

**조건**: auditd 계정 관리 기록(`ADD_USER`·`DEL_USER`·`ADD_GROUP`·`DEL_GROUP`·`USER_MGMT`·`GRP_MGMT`·`USER_CHAUTHTOK`·`GRP_CHAUTHTOK`·`CHUSER_ID`·`CHGRP_ID`·`ACCT_LOCK`·`ACCT_UNLOCK`)이 5분 안에 1건 이상(재통지 5분). 행은 호스트·종류·실행 계정(auditd `AUID`)으로 묶인다. 종류는 특권 그룹 변경(`o2c_privileged_groups`: wheel·sudo·docker·root), 비밀번호 변경, 계정·그룹 추가, 계정·그룹 삭제, 계정·그룹 속성 변경이다. shadow-utils의 syslog 줄(`useradd[…]: new user: …`)은 같은 사건의 중복이라 세지 않는다. `usermod --help` 같은 실행 기록(`exec_log` EXECVE)도 세지 않는다.

**왜 중요한가**: 계정 추가와 특권 그룹 가입은 침입자가 발판을 남기는 전형적인 수법이다. 다만 Semaphore 프로비저닝도 같은 기록을 남긴다(7일 표본의 변경은 모두 프로비저닝이었다). 그래서 P2로 두고 특권 그룹 변경은 행에서 구분한다.

**확인**
```bash
sudo ausearch -m ADD_USER,DEL_USER,USER_MGMT,GRP_MGMT,USER_CHAUTHTOK -ts recent -i
getent group wheel sudo docker
```

**대응**
- 실행 계정과 시각을 Semaphore 작업 이력과 대조한다. 프로비저닝이면 끝이다.
- 계획에 없던 변경이면 대상 계정을 잠그고(`usermod -L`) 특권 그룹에서 뺀 뒤(`gpasswd -d <계정> <그룹>`) 보안 담당에게 보고한다.

---

<a id="sudo-risky-command"></a>
## 🔴 sudo로 위험 명령 실행 (`infra-sudo-risky-command`)

**조건**: 성공한 sudo 기록의 명령 줄(`process_command_line`, 소문자)에 위험 명령 문구가 붙은 그대로 들어 있음(재통지 5분). 문구는 역할 변수 `o2c_sudo_risky_commands`(SELinux 해제 `setenforce 0`, 방화벽 규칙 초기화 `iptables -F`·`nft flush ruleset`·`firewall-cmd --panic-on`, 감사 규칙 끄기·삭제 `auditctl -e 0`·`auditctl -D`, 계정 삭제 `userdel`, 명령 기록 삭제 `history -c`, 불변 속성 해제 `chattr -i`)와 `o2c_sudo_protected_services`(auditd·rsyslog·systemd-journald·firewalld·otelcol-contrib)를 `systemctl stop|disable|mask|kill`, `service … stop`하는 명령이다. `restart`는 세지 않는다. 통지 행에는 명령 원문 대신 종류만 싣는다(명령 줄에 비밀값이 섞인 사례가 있다).

**왜 중요한가**: 흔적을 지우거나 방어를 끄는 단계에서 쓰는 명령이다. 계획된 작업이 아니면 침해가 진행 중일 수 있다.

**확인**
```bash
sudo grep "COMMAND=" /var/log/secure | tail -20     # 또는 /var/log/sudo.log
getenforce; sudo systemctl is-active auditd rsyslog firewalld otelcol-contrib
```

**대응**
- 사용자에게 작업 여부를 묻고 작업 일정과 대조한다.
- 확인되지 않으면 그 계정의 세션을 끊고 비밀번호를 바꾼다. 꺼진 기능(SELinux, 방화벽, auditd, rsyslog)을 즉시 복구하고 보안 담당에게 보고한다.

**한계**: Ansible(Semaphore)의 become 작업은 `sudo … COMMAND=/bin/sh -c echo BECOME-SUCCESS-…; python3 …`로만 남아 실제 명령이 보이지 않는다. 이 알림은 사람이 직접 친 sudo 명령만 잡는다.

---

<a id="auditd-stopped"></a>
## 🔴 감사 데몬(auditd) 종료 또는 감사 비활성화 (`infra-auditd-stopped`)

**조건**: auditd 기록(`security_logs`, `service_name=audit`)에서 종료(`DAEMON_END`·`DAEMON_ABORT`)나 감사 끄기(`CONFIG_CHANGE … audit_enabled=0`)의 마지막 시각이 시작(`DAEMON_START`, `audit_enabled=1`)의 마지막 시각보다 늦은 상태가 2분(`pending_minutes`) 이어짐(조회 10분, 재통지 10분). 재시작은 시작 기록이 곧 따라와 풀린다.

**왜 이렇게 판정하나**: 정상 종료 순서에서 수집기(otelcol-contrib)가 auditd보다 먼저 멈춘다. 그래서 재부팅 때의 `DAEMON_END`는 부팅 뒤에 늦게 들어와 조회 구간(이벤트 시각 기준) 밖에 놓이고 울리지 않는다(실측: ns0338 재부팅에서 수집기 정지가 `DAEMON_END`보다 2초 빨랐다). rsyslog·journald의 `SERVICE_STOP`은 재부팅 중 수집기가 아직 살아 있을 때 들어와 오탐이 나므로 이 알림에서 뺐다. 그 서비스를 sudo로 멈추는 명령은 위 위험 명령 알림이 잡는다.

**왜 중요한가**: auditd가 멈추면 그 뒤의 명령 실행·계정 변경·설정 파일 접근 기록이 남지 않는다. 침입자가 먼저 끄는 대상이다.

**확인**
```bash
sudo systemctl status auditd
sudo auditctl -s        # enabled 1이어야 한다
```

**대응**: 멈춰 있으면 즉시 `sudo service auditd start`, `sudo auditctl -e 1`로 복구한다. 직전 sudo·로그인 기록으로 누가 멈췄는지 확인하고, 계획에 없던 중단이면 보안 담당에게 보고한다.

---

<a id="account-lockout"></a>
## 🟠 로그인 실패 누적으로 계정 잠김 (`infra-account-lockout`)

**조건**: 계정 잠금 기록이 5분 안에 1건 이상(재통지 5분). pam_faillock syslog `Consecutive login failures for user <계정> account temporarily locked`, auditd `RESP_ACCT_LOCK` 또는 `ANOM_LOGIN_FAILURES`(`op=pam_faillock`), EL7 이하 pam_tally2 `tally N, deny M`. 로그인 성공 기록의 `grantors=pam_faillock`은 잠금이 아니라 세지 않는다. **잠금 문구는 linux-pam 소스에서 가져왔고 7일·30일 실로그에 잠금 기록이 없어 합성 줄로만 검증했다.** 실제 잠금이 처음 생기면 원문을 보고 패턴을 확인한다.

**왜 중요한가**: 특정 계정을 노린 비밀번호 추측이거나 자격증명이 바뀐 자동화 작업의 반복 실패다. 잠긴 동안 정상 사용자도 로그인하지 못한다.

**확인**
```bash
sudo faillock --user <계정>
sudo grep -E "faillock|pam_tally2" /var/log/secure | tail
```

**대응**: 직전 실패의 출발지가 외부면 방화벽에서 막는다. 내부 자동화면 자격증명을 고친다. 본인 확인 뒤 `sudo faillock --user <계정> --reset`으로 잠금을 푼다.

---

<a id="log-parse-errors"></a>
## 🟡 로그 해석 실패율 상승 (`infra-log-parse-errors-security-logs`, `infra-log-parse-errors-system-logs`)

**조건**: 30분 동안 20줄 이상 들어온 서버에서 `log_parse_error = true` 비율이 10% 이상.

**왜 중요한가**: 해석되지 않은 로그에는 `event_action`, `user_name`, `source_address` 같은 필드가 없어서 위 보안·장애 알림에 잡히지 않는다. 탐지 공백이다.

**대응**
- 해당 서버에서 최근 패키지 업데이트(openssh, sudo, rsyslog)로 로그 형식이 바뀌었는지 확인한다.
- OpenObserve에서 `log_parse_error = true`인 원문을 몇 줄 뽑아, 수집기 설정(`roles/monitoring/templates/otelcol-contrib.yaml.j2`)이나 VRL 함수(`roles/openobserve_config/files/vrl/`)를 고치는 PR을 낸다.

---

<a id="openobserve-health"></a>
## 🔴 OpenObserve 응답 없음 (ns0266 `openobserve-health.timer`)

**조건**: ns0266이 5분마다 OpenObserve `/healthz`를 확인해, 실패하면 OpenObserve를 거치지 않고 네이버웍스 webhook으로 직접 P1을 보낸다. 같은 장애는 60분마다만 다시 통지하고 복구 통지는 없다(통지가 멈추면 복구). ns0266·ns0331 동시 장애는 감수한다.

**왜 중요한가**: OpenObserve가 죽으면 이 문서의 모든 알림이 동작하지 않는다.

**확인**
```bash
# ns0331
systemctl status openobserve; df -h; free -m
# ns0266 (확인 쪽)
systemctl list-timers openobserve-health.timer
journalctl -u openobserve-health.service -n 20
```

**대응**: ns0331의 OpenObserve 서비스·디스크·메모리를 복구한다. 복구 뒤 Silent Host 알림이 남아 있으면 수집 재개를 확인한다. ns0266에서 타이머 자체가 안 돌면 `Host Agents — Config All`를 다시 실행한다.

**수동 검증 절차** (배포 후 한 번, 또는 webhook 값을 바꾼 뒤): ns0266에서 대상 URL을 틀린 값으로 한 번 실행해 통지가 도착하는지 본다.
```bash
sudo rm -f /var/lib/openobserve-health/notified
sudo O2_HEALTH_URL_OVERRIDE=http://127.0.0.1:1/healthz /usr/local/sbin/openobserve-health-check
```
네이버웍스에 `[P1 긴급] OpenObserve 응답 없음`이 도착하면 정상이다(종료코드 0). 통지 뒤 60분 동안은 같은 장애로 보고 재통지하지 않으므로, 이 시험 뒤에는 위 첫 줄처럼 상태 파일을 지운다(실제 장애가 아니므로 상태가 남지 않게 한다).

<a id="silent-host"></a>
## 🟠/🔴 Silent Host — 메트릭 하트비트 끊김 (`infra-silent-host-p2`, `infra-silent-host-p1`)

수집 로스터 호스트(인벤토리 `servers` − Host Agents Exclusion − Host Agents Backup Only, ns0266·ns0331 포함)에서 `system_memory_usage` 하트비트가 15분 넘게 끊기면 P2(3시간 미만), 3시간 넘게 끊기면 P1이다. 같은 호스트에 P2와 P1이 동시에 오지 않는다. 서버가 내려가도(서버 응답 없음) 수집기가 멈춰도 같이 걸린다.

**왜 중요한가**: OpenObserve는 약 5시간보다 오래된 로그를 받지 않는다. 이 시간이 지나면 이 구간 로그는 OpenObserve로 복구되지 않음 — ISMS 로그 증거가 중앙에서 영구히 빠진다(2026-10 CentOS 6 수집기 중단 사고, #161).

**확인**
1. 같은 호스트의 서버 응답 없음(Unreachable Host) 알림이 있으면 그쪽이 원인이다. 서버·네트워크부터 복구한다.
2. 서버가 살아 있으면 호스트에서 `systemctl status otelcol-contrib`(CentOS 6은 `service otelcol-contrib status`)와 최근 로그를 본다.

**대응**: 수집기를 재기동하고 하트비트가 돌아오는지 본다. P1이면 끊긴 구간 로그가 5시간 한도 안에 들어오는지 확인하고, 넘었다면 호스트의 원본 로그를 보존한다. 며칠 이상 계획 정지하는 호스트는 OpenBao `silent_host_exceptions`에 만료일과 함께 등록하고 `OpenObserve — Config`를 다시 실행한다. 호스트를 편입·폐기했다면 같은 Config 재실행이 필요하다.

---

<a id="app-telemetry-silent"></a>
## 🟠 앱 텔레메트리 무소식 — funa JVM 메트릭 끊김 (`infra-app-telemetry-silent`)

OpenBao `hosts/<host>/agents`의 `otel_app_telemetry`가 켜진 호스트에서 funa JVM 메트릭(`jvm_memory_used`, `service_name=funa`)이 15분 넘게 오지 않으면 온다. 스위치가 꺼진 호스트는 대상이 아니다. 대상 목록은 `OpenObserve — Config`를 실행할 때 만들어지므로 스위치를 바꾸면 Config를 다시 실행한다.

**왜 중요한가**: 2026-10-01처럼 앱 텔레메트리(트레이스, 앱 메트릭)가 알림 없이 버려질 수 있다.

**확인**
1. 같은 호스트의 Silent Host 알림이 있으면 수집기 전체가 원인이다. 그쪽부터 복구한다.
2. 호스트에서 `systemctl status otelcol-contrib`와 OTLP 수신기 설정(스위치가 렌더링에 반영됐는지)을 본다.
3. funa 컨테이너가 떠 있는지, OTLP exporter 환경 변수가 맞는지 본다.

**대응**: 원인을 고치고 메트릭이 돌아오는지 본다. 의도적으로 끈 것이면 `otel_app_telemetry`를 끄고 Config를 다시 실행한다.

---

<a id="unreachable-host"></a>
## 🔴 서버 응답 없음 — Unreachable Host (`infra-unreachable-host`)

Semaphore 호스트(ns0266)의 수집기가 `servers` 전체(Host Agents Backup Only 포함)의 SSH 포트에 60초마다 접속을 시도하고, `tcpcheck.status`가 5분 연속 0(접속 실패)이면 P1이다. 통지 행에 대상 `<주소>:<포트>`가 나온다. P1이라 해소될 때까지 60분마다 다시 온다.

**왜 중요한가**: 서버·네트워크가 내려갔을 가능성이 크다. 접속이 된다고 OS가 건강하다는 뜻은 아니며 이 알림은 도달성만 본다.

**Silent Host와의 구분**
| 알림 | 의미 | 보는 곳 |
|---|---|---|
| 서버 응답 없음 | 서버의 SSH 포트에 접속이 안 됨(서버·네트워크 다운) | ns0266이 외부에서 확인 |
| Silent Host | 서버가 보내던 메트릭 하트비트가 끊김(수집기 중단 또는 서버 다운) | 서버 안의 수집기가 보냄 |

서버가 다운이면 두 알림이 같은 호스트에 함께 올 수 있다(수집 로스터 호스트). 이때는 서버 응답 없음이 원인이므로 서버·네트워크부터 복구하고, 복구되면 수집기도 돌아와 Silent Host가 멈춘다. Backup Only 호스트는 로그를 보내지 않아 Silent Host 대상이 아니며 이 알림으로만 감시된다. 서버 응답 없음 없이 Silent Host만 오면 서버는 살아 있고 수집기만 멈춘 것이다.

**확인**
```bash
# ns0266에서 해당 주소·포트로 직접
nc -vz -w 5 <주소> <포트>
```
1. 접속이 안 되면 서버 전원·콘솔·네트워크 경로를 확인한다. 서버가 계획 정지라면 그대로 둔다(정지 중에는 계속 온다).
2. 접속이 되는데 알림이 온다면 ns0266 수집기(`otelcol-contrib`) 상태, ns0266에서 대상까지의 방화벽 경로, OpenBao `hosts/<호스트>`의 `ansible_port`·`public_ip`가 실제 SSH 포트·주소와 같은지 본다(대상은 OpenBao 값으로 만든다).
3. ns0266이 죽으면 `tcpcheck` 메트릭 전체가 끊긴다. 이는 ns0266의 Silent Host 알림으로 잡힌다.

**편입·폐기**: 대상 목록은 검사하는 쪽이 Host Agents 실행 때마다 `servers` 전체의 OpenBao `hosts/<호스트>`(주소 `public_ip`, 비표준 SSH 포트 `ansible_port`)에서 만든다. 실행 범위(`target_hosts`)와 무관하다. 호스트를 편입·폐기하면 `Host Agents — Deploy All`(또는 Config)를 ns0266에 다시 반영해야 한다.
**제외**: 검사하는 쪽에서 도달할 수 없는 것이 정상인 서버는 Semaphore 인벤토리(`hosts`)의 `tcpcheck_excluded` 그룹에 넣는다(`host_agents_excluded`와 같은 방식). 현재 `ns0229`·`ns0246`이 들어 있다: 순수 내부 IP(10.10.10.x)만 할당된 서버라 공인 `218.234.206.79`의 포트 2002·2001 포워딩으로만 접근하고, ns0266에서는 이 경로가 막혀 있다(`connect: no route to host`). 그래서 서버 도달성 감시의 사각지대다. 접속 못 하는 이유가 없어지면 그룹에서 뺀다. 목록에서 빠진 서버는 도달성 알림을 받지 못한다. Extra variables `host_agents_tcpcheck_excluded`로도 지정할 수 있다. 저장소의 `inventory/group_vars`는 Semaphore에서 읽히지 않으니 거기에 두지 않는다.
<a id="backup-failure"></a>
## 🟠 백업 실패 (`infra-backup-failure`)

`backup_logs`에서 `job=backup`, `success=false` 이벤트가 오면 발생 즉시 P2로 한 번 알린다(Event Alert). 호스트는 `host` 필드다.

**왜 중요한가**: 복구 지점이 늘지 않는다. 방치하면 26시간 뒤 백업 누락으로 이어진다.

**확인**: 행의 호스트에서 `tail -1 /var/log/host-agents/backup.jsonl`의 `error`, 저장소(RustFS) 접속·자격증명·디스크 여유.

**대응**: 원인을 고친 뒤 호스트에서 백업을 수동 실행해 성공을 확인한다.

<a id="integrity-check-failure"></a>
## 🟠 백업 저장소 무결성 검사 실패 (`infra-integrity-check-failure`)

Repo Maintenance의 `job=maintenance`, `command=check`, `success=false` 이벤트를 즉시 P2로 알린다(Event Alert).

**왜 중요한가**: 저장소 손상 가능성이 있고, 실패한 호스트는 prune이 차단된다.

**확인·대응**: Semaphore Repo Maintenance 실행 로그에서 해당 호스트의 check 오류를 보고 `restic check`로 손상 범위를 확인한다. 손상이면 복구·재초기화와 백업 재실행을 계획한다.

<a id="backup-missing"></a>
## 🟠 백업 누락 (`infra-backup-missing`)

수집 로스터 호스트(Backup Only 제외, ns0266·ns0331 포함)의 마지막 성공 `job=backup`이 26시간을 넘으면 하루 1번 P2로 알린다(State Alert). 배포만 되고 한 번도 백업하지 않은 호스트도 걸린다.

**확인**
1. **같은 호스트의 Silent Host 알림이 있는지 먼저 확인한다.** 수집기가 멈췄다면 백업은 돌았어도 이벤트만 빠진 것일 수 있다.
2. 호스트의 `/etc/cron.d/host-agents-backup`(또는 systemd timer)과 `/var/log/host-agents/backup.jsonl` 마지막 줄을 본다. 놓친 실행은 보정되지 않는다.
3. 신규 편입 호스트면 Host Agents Deploy가 실행됐는지 확인한다.

**구분**: 서버 다운은 Unreachable Host(서버 응답 없음), 수집기 중단은 Silent Host, 백업 이벤트만 없는 것이 백업 누락이다.

<a id="maintenance-missing"></a>
## 🟠 유지보수 누락 (`infra-maintenance-missing`)

유지보수 로스터(Backup Only 포함) 호스트의 마지막 `command=check`가 8일을 넘으면 하루 1번 P2로 알린다(State Alert). Backup Only 호스트는 백업 이벤트를 보내지 않으므로 백업 누락이 아니라 이 알림과 무결성 검사 실패로만 감시된다.

**확인·대응**: Semaphore Repo Maintenance 템플릿의 최근 실행과 스케줄, 해당 호스트가 제외·접속 실패로 건너뛰어졌는지 확인한 뒤 수동으로 Repo Maintenance를 실행한다.

---

## 스위치 syslog 알림 (Spec #277)

스위치 syslog는 수신 서버(#276)를 거쳐 `system_logs`에 `service_name=switch-syslog`로 들어오고, `switch_syslog_semantics` 함수가 로그 한 줄에 장비와 Cisco 메시지 필드를 붙인다. `host_name`은 스위치가 아니라 로그를 받는 서버이고 `severity`는 항상 0이므로, 스위치로 거를 때는 아래 필드를 쓴다. 원문 `body`는 바뀌지 않는다.

| 필드 | 뜻 |
|---|---|
| `device_id` | 관리번호(`ns0347`). 장비 이름 앞부분의 `ns` + 숫자이며 인벤토리 호스트명과 같다. 이름에 없으면 필드가 없다 |
| `device_name` | 원문의 장비 이름을 소문자로 바꾸고 도메인을 뗀 값(`ns0347-3560x`). 알림은 `device_id`가 없으면 이 값으로 장비를 센다 |
| `cisco_facility`, `cisco_mnemonic` | `%SW_MATM-4-MACFLAP_NOTIF`의 `SW_MATM`, `MACFLAP_NOTIF` |
| `event_name` | 메시지 코드 전체(`SW_MATM-4-MACFLAP_NOTIF`, `%` 제외). 잡음·알림 목록은 이 값으로 적는다 |
| `log_syslog_severity_code`, `log_syslog_severity_name` | 메시지 코드의 심각도 0~7과 이름(emergency, alert, critical, error, warning, notice, informational, debug) |

**한계**: 장비 시각은 연도가 없고 시간대가 장비 설정에 달려 있어 `_timestamp`(수신 시각)가 기준이다. 장비 시각은 원문에 그대로 있다. 알림은 일부 메시지에만 생기는 필드를 쓰지 않고 `body`에서 뽑는다(그 메시지가 한 번도 오지 않은 동안 컬럼이 없어 알림이 `unknown field`로 오류가 나지 않게).

**목록 갱신 절차**: 아래 목록은 모두 역할 기본 변수(`roles/openobserve_config/defaults/main.yml`)이며 Semaphore의 `OpenObserve — Config` 템플릿 Environment(`-e`)나 저장소 기본값을 고쳐 반영한다. 고친 뒤 **`OpenObserve — Config`를 다시 실행**해야 알림 SQL이 바뀐다.
- `o2c_switch_syslog_roster`(수신 중단 감시 장비, 관리번호 목록): 새 스위치에 syslog 전송을 설정하고 로그가 `switch-syslog`로 도착하는 것을 확인한 **뒤에** 추가한다. 철거·교체한 장비는 뺀다. 전송을 설정하지 않은 장비를 넣으면 허위 알림이 온다.
- `o2c_switch_uplinks`(업링크 포트 다운 감시, `[{device: ns0250, port: Gi1/0/49}]`): 포트는 약어(`Gi1/0/49`)와 전체 이름(`GigabitEthernet1/0/49`) 어느 쪽이든 쓴다(링크 다운 메시지는 전체 이름, MAC 플랩 메시지는 약어로 찍힌다). **목록이 비어 있으면 규칙 자체가 만들어지지 않는다.** 링크 다운은 심각도 3이라 미사용 포트 다운까지 전부 알림이 되므로 핵심 연결만 넣는다. 용어 `Watched Port`(CONTEXT.md)는 SNMP 감시(#175)의 라벨 기반 개념이며 이 로그 기반 목록과 별개다.
- `o2c_switch_noise_events`(잡음 메시지 코드): 반복되는 의미 없는 메시지를 `FACILITY-SEVERITY-MNEMONIC`로 추가한다. 기본값은 ARP 해소 실패(`ADJ-3-RESOLVE_REQ`)다. 잡음으로 뺀 줄도 검색은 그대로 되고 수신 중단 판단에는 수신으로 센다. 설정 변경·로그인 실패·MAC 플랩 메시지 코드를 잡음에 넣으면 그 알림도 꺼지므로 넣지 않는다.
- 임계값: `o2c_switch_login_fail_threshold`(기본 5회/5분), `o2c_switch_macflap_threshold`(기본 2회/10분), `o2c_switch_severity_max`(기본 2), `o2c_switch_silent_hours`(기본 24시간).

**수신 중단 판정**: `device_id` 필드가 있거나 원문에 장비 이름(관리번호)이 있으면 수신 중으로 센다. 파이프라인을 반영한 직후에도, 새 장비를 목록에 더한 직후에도 이전 로그 때문에 오탐이 나지 않는다. 원문에서 찾으므로 다른 장비 메시지가 이 장비 이름을 본문에 언급하면 조용한 장비를 놓칠 수 있다(관리번호는 보통 본문에 나오지 않는다).

**수신 중단 알림의 한계**: 스위치 syslog는 이벤트가 있을 때만 전송되므로 조용한 장비와 고장난 전송을 구분하지 못한다. 그래서 기준 시간을 24시간으로 길게 두었다. 2주 관찰한 뒤 오탐이 있으면 `o2c_switch_silent_hours`를 늘리고, 놓치는 것이 있으면 줄인다. 장비 자체가 내려간 것은 이 알림이 아니라 SNMP 알림(#175)이 맡는다.

<a id="switch-config-change"></a>
### 🟠 스위치 설정 변경 감지 (`infra-switch-config-change`)

**조건**: `SYS-5-CONFIG_I`(설정 모드를 마칠 때 장비가 남기는 메시지) 1건부터 5분 구간마다 한 번(Event Alert). 대상 행에 장비와 원문의 변경 주체(`Configured from console by <사용자> on vty0 (<주소>)`)가 나온다.

**왜 중요한가**: 승인되지 않은 설정 변경은 장애나 침해의 시작이다. 변경 이력은 ISMS 변경 관리 증적이다.

**확인**: 행의 사용자·접속 방식·주소를 작업 일정(Semaphore 이력, 작업 요청)과 대조한다. 로그 보기에서 같은 장비의 직전 로그인 기록을 본다. Cisco Backup의 직전 설정과 비교하면 바뀐 줄을 알 수 있다.

**대응**: 승인되지 않은 변경이면 해당 계정·접속 경로를 막고 직전 설정으로 되돌린 뒤 보안 담당에게 보고한다. 승인된 작업이면 작업 기록에 남긴다.

<a id="fortigate-config-change"></a>
### 🟠 포티게이트 설정 변경 감지 (`fortigate_backup` 역할)

**조건**: 포티게이트 설정 백업(매일 03:30)이 같은 대상의 직전 백업과 다를 때 한 번(Event Alert). 이 알림은 OpenObserve가 아니라 백업 역할이 같은 webhook으로 직접 보낸다. 헤더 줄(빌드·사용자·시각)만 다르면 오지 않고, 첫 백업에도 오지 않는다. 같은 변경은 다시 오지 않는다. 대상 행에 장비(관리번호), 응답 멤버, 바뀐 섹션·항목 이름과 설정 키 이름만 나온다(값 없음).

**왜 중요한가**: 승인되지 않은 방화벽 정책·관리자·VPN 변경은 접근 통제 약화나 침해의 시작이다. 변경 이력은 ISMS 변경 관리 증적이다.

**확인**: 변경 시각 전후(전날 백업~이번 백업)의 작업 요청·변경 기록과 대조한다. 바뀐 값은 알림에 없으므로 컨트롤러의 백업 디렉터리에서 직전 파일과 이번 파일을 `diff`로 비교한다(두 파일명은 알림의 직전 백업 이름과 같은 대상의 최신 파일). 출력에 VPN 키·관리자 해시가 들어 있으니 화면·채팅·이슈에 붙이지 않는다. 같은 시간대의 방화벽 관리자 로그인 기록(`security_logs`, `fortigate-syslog`)에서 변경 주체를 찾는다.

**대응**: 승인되지 않은 변경이면 해당 관리자 계정·접속 경로를 막고 직전 백업으로 되돌린 뒤 보안 담당에게 보고한다. 승인된 작업이면 변경 기록에 남긴다. 알림에 멤버 변경 비교라고 되어 있으면 장애 전환이 있었던 것이니 멤버 고유 설정은 변경으로 세지 않았음을 감안한다.

**알림이 오지 않을 때**: Semaphore 백업 작업이 `FORTIGATE-ALERT`로 실패했다면 변경은 감지했으나 webhook이 없거나 전송이 실패한 것이다. 같은 변경은 다시 알리지 않으므로 작업 로그의 변경 항목을 직접 확인하고 webhook(`fortigate_backup_alert_webhook_url`) 설정을 고친다.

<a id="switch-login-failures"></a>
### 🟠 스위치 로그인 실패 반복 (`infra-switch-login-failures`)

**조건**: 한 장비에서 `SEC_LOGIN-4-LOGIN_FAILED`가 5분 안에 5회 이상(Event Alert, 기본값은 `o2c_switch_login_fail_threshold`).

**확인**: 로그 보기에서 실패 줄의 `[user: ...] [Source: ...]`를 본다. 출발지가 사내(작업자·Semaphore)인지 외부인지 구분한다.

**대응**: 외부·미확인 출발지면 스위치의 관리 접속 ACL과 방화벽을 점검해 막는다. 작업자의 반복 오입력이면 기록만 남긴다. 같은 출발지의 로그인 성공이 이어졌으면 설정 변경 알림도 함께 확인한다.

<a id="switch-severity-critical"></a>
### 🔴 스위치 중요 장애 메시지 (`infra-switch-severity-critical`)

**조건**: 메시지 코드의 심각도가 0~2(emergency·alert·critical)인 줄이 5분 안에 1건 이상(Event Alert). 잡음 목록의 코드는 제외한다.

**왜 중요한가**: 하드웨어·전원·스택·메모리 같은 중대한 장애이며 그 스위치 아래 서버가 함께 끊길 수 있다.

**확인**: 행의 `event_name`과 로그 보기의 원문을 읽는다. 장비 콘솔 또는 다른 경로로 `show logging`, `show environment`, `show switch`(스택)를 본다.

**대응**: 하드웨어 문제면 이중화 경로로 서비스를 옮기고 교체 일정을 잡는다. 이미 알려진 무해한 반복 메시지면 `o2c_switch_noise_events`에 추가하는 PR을 낸다.

<a id="switch-uplink-down"></a>
### 🔴 스위치 업링크 포트 다운 (`infra-switch-uplink-down`)

**조건**: `o2c_switch_uplinks`에 적은 (장비, 포트)에 대해 `LINK-3-UPDOWN`·`LINEPROTO-5-UPDOWN`·`LINK-5-CHANGED`가 `down` 또는 `administratively down`으로 바뀐 줄이 5분 안에 1건 이상(Event Alert). **목록이 비어 있으면 이 알림은 없다.**

**확인**: 행의 장비·포트와 반대편 장비의 포트 상태, 케이블·광모듈을 확인한다. `administratively down`이면 누군가 shutdown한 것이므로 설정 변경 알림과 대조한다.

**대응**: 복구되지 않으면 우회 경로를 확보하고 회선·장비 담당에게 연락한다. 이중화로 이미 우회되고 있으면 복구 일정을 잡는다.

<a id="switch-mac-flap"></a>
### 🟠 스위치 MAC 플랩 감지 (`infra-switch-mac-flap`)

**조건**: 한 장비에서 `SW_MATM-4-MACFLAP_NOTIF`가 10분 안에 2회 이상(기본값은 `o2c_switch_macflap_threshold`). 플랩이 계속되면 60분(`o2c_switch_macflap_silence_minutes`)마다 다시 온다.

**왜 중요한가**: 같은 MAC이 두 포트 사이를 오가는 것은 L2 루프나 장비 이동·이중 연결의 신호다. 방치하면 VLAN 통신이 불안정해진다.

**확인**: 로그 보기에서 원문의 MAC, VLAN, 두 포트(`Gi0/13`, `Gi0/14`)를 읽는다. 그 두 포트에 무엇이 연결됐는지 본다(서버 이중화 본딩, 가상 스위치, 루프 케이블, 무선 AP).

**대응**: 서버의 이중화 구성이면 본딩 모드(active-backup/LACP)와 스위치 쪽 EtherChannel 설정이 맞는지 본다. 루프면 케이블을 분리한다. 의도된 구성이라면 스위치 설정을 고치거나 임계값을 조정한다.

<a id="switch-syslog-silent"></a>
### 🟠 스위치 syslog 수신 중단 (`infra-switch-syslog-silent`)

**조건**: `o2c_switch_syslog_roster`의 스위치가 24시간(`o2c_switch_silent_hours`) 넘게 `switch-syslog` 로그를 보내지 않음(State Alert, 하루 1번 재통지). 목록에 없는 장비는 보지 않는다.

**왜 중요한가**: 전송 설정이나 수신 경로가 끊기면 그동안의 설정 변경·로그인 이력이 중앙에 남지 않는다. 스위치는 이벤트가 있을 때만 보내므로 오래 조용한 정상 장비일 수도 있다.

**확인**: 스위치에서 `show running-config | include logging`으로 `logging host`와 `logging trap` 수준을 본다. 수신 서버의 방화벽과 수신 서비스 상태(#276)를 본다. 해당 장비의 `ns` 번호와 `device_id`가 같은지 로그 보기에서 확인한다.

**대응**: 설정이 사라졌으면 복구한다. 원래 조용한 장비면 기준 시간을 늘린다. 철거·교체한 장비면 목록에서 뺀다.

---

## 방화벽(포티게이트) 알림 (Spec #282 / Ticket-3)

방화벽 syslog는 [수신 경로](fortigate-syslog.md)를 거쳐 `security_logs`에 `service_name=fortigate-syslog`로 들어온다. 알림 6개는 스위치 알림과 같은 통지 경로·메시지 형식(등급, 무슨 일, 왜 중요, 대상, 조치, 런북 링크)을 쓴다.

> **실로그 샘플로 검증됨**(검증 범위: 관리자 로그인 성공/실패, 정책·로그 설정 변경(GUI·jsconsole·ha_daemon), 로컬·포워드 트래픽(정책 0 포함), IPsec 터널 통계, UTM(ips·virus·dlp·anomaly), HA 인터페이스 실패, FSSO, 엔드포인트. 검증되지 않은 종류: HA 전환(상태 변경) 실제 줄, SSL VPN 사용자 로그인/로그아웃·로그인 실패 줄, 실제 장비가 만든 웹필터·앱제어 줄, IPv6 주소). 실장비 줄을 가짜 값으로 치환한 `tests/fixtures/fortigate_real_lines.tsv`(합성이 아닌 실장비 모양)를 알림 SQL에 넣어 발화·미발화를 확인한다. 실측으로 고친 점: 실제 바이러스 로그에는 `severity` 키가 없어 `subtype=virus`·`eventtype=infected`를 중대 탐지로 함께 센다. 로그 전송 설정 변경(`log.syslogd.*`, `log.setting`)은 기본 감시 대상이 아니다(`o2c_fortigate_policy_cfgpaths`에 더하면 알린다). 검증되지 않은 종류의 줄이 처음 들어오면 `subtype`/`action`/`status`, `cfgpath`·`user`·`time`, `logdesc`, `severity`·`attack`, `devname`을 샘플과 다시 대조하고, 다르면 알림 SQL(`roles/openobserve_config/defaults/main.yml`)과 검증 레코드(`files/alert_fixtures.yml`)를 함께 고친다.

| 알림 | 등급 | 조건 (기본값) | 재통지 |
|---|---|---|---|
| `infra-fortigate-admin-login-failures` | 🟠 P2 | 한 출발지에서 관리자 로그인 실패가 5분 안에 5회 이상 | 30분 |
| `infra-fortigate-change-unapproved` | 🔴 P1 | 정책·계정 변경이 승인 시간(기본 9~18시) 밖 | 5분(구간과 같음) |
| `infra-fortigate-change-approved` | 🟡 P3 | 정책·계정 변경이 승인 시간 안, 하루 1번 요약 | 하루 |
| `infra-fortigate-ha-failover` | 🟠 P2 | HA 로그(`subtype=ha`) 1건부터 | 30분 |
| `infra-fortigate-critical-detection` | 🔴 P1 | UTM 탐지(`type=utm`) 중 `severity=critical` 또는 바이러스 감염(`subtype=virus`·`eventtype=infected`) 1건부터 | 60분 |
| `infra-fortigate-syslog-silent` | 🟠 P2 | 감시 목록의 방화벽이 120분 넘게 로그 없음 | 하루 |

**중복 알림 방지**: 모든 알림이 재통지 간격(silence)을 가진다. 같은 공격·같은 HA 전환 반복은 위 간격마다 한 번만 알리고, 변경 알림은 조회 구간(5분)과 같아 같은 줄을 두 번 알리지 않는다. 승인 시간 안의 변경은 하루 1번 요약으로만 가므로 정상 작업이 P1을 만들지 않는다.

**공통 한계**: 알림 SQL은 `service_name`과 원문 `body`의 `key=value`만 읽는다. `security_logs`에는 첫 방화벽 줄이 들어오기 전까지 방화벽 필드(`device_id` 등) 컬럼이 없어서, 그 컬럼을 참조하면 알림 평가가 매번 오류가 나고 Config 실행(`O2C-036`)이 막히기 때문이다. 필드 추출([OpenObserve 구성](../openobserve_config.md), #285)과 별개로 동작한다. 따옴표 있는 값(`subtype="ha"`)과 없는 값(`subtype=ha`)을 모두 받는다.

**목록 갱신 절차**: 아래 값은 모두 역할 기본 변수(`roles/openobserve_config/defaults/main.yml`)이며 Semaphore의 `OpenObserve — Config` 템플릿 Environment(`-e`)나 저장소 기본값을 고친 뒤 **`OpenObserve — Config`를 다시 실행**해야 반영된다. 잘못된 형식(장비 이름, 경로 문자, 승인 시간)은 요청 전에 실패한다.
- `o2c_fortigate_syslog_roster`(수신 중단 감시 장비): **기본값은 비어 있다.** 전송을 시작하기 전 장비(`ns0380`, `ns0381`, `ns0399`)를 넣으면 허위 알림이 계속 오기 때문이다. 장비가 로그를 보내기 시작하고 `security_logs`에 도착하는 것을 확인한 **뒤에** 관리번호를 더한다(사무실 `ns0399`가 먼저). IDC HA 쌍은 대기 멤버가 평소 조용하고 장애 전환 뒤에는 반대가 되므로 `ns0380+ns0381`처럼 `+`로 묶어 한 항목으로 쓴다(어느 한 멤버라도 보내면 수신 중). **hostname을 관리번호로 바꾸지 못한 장비는 관리번호가 아닌 원래 이름(`devname` 그대로, 대소문자 무관)으로도 목록에 넣을 수 있다**(예: `Example_Branch_FW`). 이 장비의 `device_id`(관리번호)를 채우려면 `o2c_fortigate_device_aliases`에 `{example_branch_fw: ns0000}`처럼 소문자 정규화한 이름 → 관리번호를 넣는다(표에 없으면 `ns`+숫자 추출). 공개 저장소라 실제 이름과 값은 저장소에 쓰지 않고 Semaphore `OpenObserve — Config` 템플릿의 Environment(Extra variables)로 넣는다. 목록에 없는 장비는 로그가 없어도 알리지 않는다. 목록이 비면 규칙은 있지만 행을 돌려주지 않는다.
- `o2c_fortigate_approved_start_hour`, `o2c_fortigate_approved_end_hour`(승인 시간, 기본 9, 18, 끝 미포함): 변경 로그 원문의 `time=`(장비 시계)을 읽는다. **장비 시간대가 운영 시간대(KST)여야 한다.** 시각이 없는 줄은 승인 시간 밖으로 본다. 요일은 구분하지 않는다.
- `o2c_fortigate_policy_cfgpaths`, `o2c_fortigate_account_cfgpaths`(변경을 알릴 `cfgpath`): 기본은 정책(`firewall.policy`, `firewall.policy6`, `firewall.proxy-policy`)과 계정(`system.admin`, `system.accprofile`, `system.api-user`, `user.local`, `user.group`)이다.
- `o2c_fortigate_detection_severities`(기본 `critical`), `o2c_fortigate_login_fail_threshold`(기본 5), `o2c_fortigate_silent_minutes`(기본 120, 스위치 24시간보다 짧다. 방화벽은 로그가 계속 나오므로), 재통지 간격 `o2c_fortigate_*_silence_minutes`.

<a id="fortigate-admin-login-failures"></a>
### 🟠 방화벽 관리자 로그인 연속 실패 (`infra-fortigate-admin-login-failures`)

**조건**: `subtype=system`, `action=login`, `status=failed`인 줄이 같은 출발지에서 5분 안에 5회 이상(`o2c_fortigate_login_fail_threshold`). VPN 사용자 로그인 실패는 관리자 로그인이 아니라 대상이 아니다.

**왜 중요한가**: 방화벽 관리자 계정이 뚫리면 모든 통신 정책을 바꿀 수 있다(무차별 대입의 전형).

**확인**: 행의 출발지가 사내 작업자·Semaphore인지 본다. 로그 보기에서 실패한 계정과 접속 방식(`ui`: GUI/ssh)을 읽는다. 같은 출발지의 로그인 성공이 이어졌는지 본다.

**대응**: 외부·미확인 출발지면 관리 접속 허용 주소(trusted host)와 관리 인터페이스 노출 범위를 점검해 막는다. 성공이 이어졌으면 계정 변경 알림(아래)과 함께 보고 계정을 잠근다. 작업자의 오입력이면 기록만 남긴다.

<a id="fortigate-change-unapproved"></a>
### 🔴 방화벽 정책·계정 변경, 승인 시간 밖 (`infra-fortigate-change-unapproved`)

**조건**: `cfgpath`가 정책·계정 목록에 있는 변경이 승인 시간(장비 시계 기준 9~18시) 밖에 기록됨. 시각을 읽을 수 없는 줄도 포함한다. 행에 장비, 변경 대상(`cfgpath`), 관리자가 나온다.

**왜 중요한가**: 승인되지 않은 정책·계정 변경은 차단 해제나 백도어 계정 생성일 수 있다. 변경 이력은 ISMS 변경 관리 증적이다.

**확인**: 행의 관리자와 `cfgpath`를 작업 요청·Semaphore 이력과 대조한다. 로그 보기에서 `cfgattr`(바뀐 값)과 접속 방식·출발지(`ui`)를 읽는다. 직전 [FortiGate Backup](../fortigate_backup.md)과 비교하면 바뀐 설정을 알 수 있다.

**대응**: 승인된 긴급 작업이 아니면 해당 관리자 계정을 잠그고 직전 설정으로 되돌리며 보안 담당에게 보고한다. 승인된 작업이면 작업 기록에 남긴다.

<a id="fortigate-change-approved"></a>
### 🟡 방화벽 정책·계정 변경, 승인 시간 안 하루 요약 (`infra-fortigate-change-approved`)

**조건**: 위와 같은 변경이 승인 시간 안에 기록됨. 하루에 한 번 요약한다.

**왜 중요한가**: 정상 작업이 대부분이지만 변경 관리 증적으로 그날의 작업 요청과 대조해야 한다. 대응 작업이 없는 변경은 계정 도용일 수 있다.

**확인·대응**: 행의 관리자·변경 대상을 그날의 작업 요청과 대조해 결과를 작업 기록에 남긴다. 대응 작업이 없는 변경이면 승인 시간 밖 변경 절차(P1)로 격상한다.

<a id="fortigate-ha-failover"></a>
### 🟠 방화벽 HA 전환·이상 (`infra-fortigate-ha-failover`)

**조건**: `subtype=ha` 로그 1건부터. 행에 장비 이름과 `logdesc`(HA 이벤트 종류)가 나온다. 정보성 동기화 로그(secondary가 주기적으로 남기는 동기화 상태 줄, logid `0108037903`)는 제외한다. 제외 목록은 변수 `o2c_fortigate_ha_ignored_logids`(숫자 문자열 목록, 빈 목록이면 HA 로그 전부)로 조정한다. 실장비에서 다른 정보성 줄이 알림을 일으키면 그 logid를 목록에 더한다(실제 HA 전환 줄은 아직 검증되지 않았다).

**왜 중요한가**: 통신은 이어지더라도 이중화가 깨져 다음 장애에서 서비스가 끊길 수 있다. 전환이 반복되면 세션이 끊긴다.

**확인**: 장비 이름으로 지금 주 장비가 어느 멤버인지 본다(IDC 쌍은 멤버마다 장비 이름이 다르다). 전환 직전의 인터페이스·전원·하트비트 로그를 본다. **IDC 쌍은 secondary가 직접 로그를 보내지 못하는 수용 위험이 있으므로**([수신 런북](fortigate-syslog.md) 2절) 대기 멤버 쪽 사정은 장비 접속이나 다른 경로로 확인해야 한다.

**대응**: 멤버가 복구되지 않으면 교체·점검 일정을 잡는다. 계획된 작업(재부팅, 펌웨어)이면 작업 기록에 남긴다.

<a id="fortigate-critical-detection"></a>
### 🔴 방화벽 중대 보안 탐지 (`infra-fortigate-critical-detection`)

**조건**: `type=utm` 로그 중 `severity`가 `critical`(`o2c_fortigate_detection_severities`)인 것 1건부터. 행에 장비와 탐지 이름(`attack`)이 나온다.

**왜 중요한가**: 알려진 취약점 공격이나 악성코드가 방화벽을 지나가려 했다. 차단됐더라도 공격 대상에 이미 닿았는지 확인해야 한다.

**확인**: 로그 보기에서 출발지·목적지·조치(`action`: 차단 `dropped`/`blocked`, 통과 `pass`/`monitor`)를 본다. 출발지가 내부 호스트인지 본다.

**대응**: 통과였거나 내부 호스트가 출발지면 그 호스트를 격리하고 점검한다. 외부의 반복 공격이면 차단 정책 추가를 검토한다. 결과를 사고 기록(ISMS 2.11.5)에 남긴다.

<a id="fortigate-syslog-silent"></a>
### 🟠 방화벽 syslog 수신 중단 (`infra-fortigate-syslog-silent`)

**조건**: `o2c_fortigate_syslog_roster`의 방화벽이 120분(`o2c_fortigate_silent_minutes`) 넘게 `fortigate-syslog` 로그를 보내지 않음(State Alert, 하루 1번 재통지). 목록이 기본값(빈 목록)이면 어떤 장비도 보지 않는다. 장비 이름은 원문의 `devname`으로 찾는다.

**왜 중요한가**: 전송 설정이나 수신 경로가 끊기면 그동안의 관리자 접속·정책 변경 이력이 중앙에 남지 않는다(ISMS 로그 1년 보관의 공백).

**확인**: 장비의 로그 전송 설정(대상, 형식, 출발지 고정)이 그대로인지 본다. 수신 서버의 허용 목록과 syslog-ng 상태를 [수신 런북 3절](fortigate-syslog.md)대로 확인한다. HA 쌍은 장애 전환 뒤 새 primary 이름으로 이어지는지 본다.

**대응**: 설정이 사라졌으면 복구한다. 철거·교체한 장비면 목록에서 뺀다. 로그가 원래 적은 장비(정책별 로그를 최소화)면 기준 시간을 늘린다. IDC 쌍에서 secondary가 조용한 것은 정상이다(쌍을 `+`로 묶어 감시).

---

## 리소스 알림 (디스크·inode·메모리)

사용률은 `_timestamp`별로 묶은 값의 **조회 구간 최솟값**으로 판정한다(구간 내내 높아야 발화). 디스크·inode는 15분, 메모리는 10분. 90% 이상 95% 미만은 P2(재통지 1440분), 95% 이상은 P1(재통지 60분). 통지 행에 호스트·마운트·사용률이 나온다. squashfs·iso9660·tmpfs·devtmpfs·overlay는 감시하지 않고 `/boot`·`/boot/efi`는 감시한다. 항상 높게 쓰는 볼륨은 OpenBao `agents/openobserve`의 `alert_resource_exclusions`(호스트·마운트 예외)나 `alert_resource_thresholds`(임계값 덮어쓰기)에 넣고 `OpenObserve — Config`를 다시 실행한다.

<a id="disk-usage"></a>
### 🟠/🔴 디스크 사용률 (`infra-disk-usage-p2`, `infra-disk-usage-p1`)

**왜 중요한가**: 가득 차면 로그·DB·백업 쓰기가 실패한다.

**확인**
```bash
df -hT <마운트>
sudo du -xh <마운트> --max-depth=2 | sort -h | tail -20
docker system df   # Docker 사용 호스트
```

**대응**: 큰 파일·오래된 로그·Docker 이미지/볼륨을 정리하거나 증설한다. 원래 가득 차게 쓰는 볼륨이면 OpenBao 예외를 등록한다.

<a id="inode-usage"></a>
### 🟠/🔴 inode 사용률 (`infra-inode-usage-p2`, `infra-inode-usage-p1`)

**왜 중요한가**: 용량이 남아도 inode가 다하면 파일을 만들 수 없다(작은 파일 폭증).

**확인**
```bash
df -i <마운트>
sudo du -x --inodes <마운트> --max-depth=3 | sort -n | tail -20
```

**대응**: 작은 파일이 몰린 디렉터리(세션·캐시·메일 큐 등)를 정리하고 원인 프로세스를 고친다.

<a id="memory-usage"></a>
### 🟠/🔴 메모리 사용률 (`infra-memory-usage-p2`, `infra-memory-usage-p1`)

사용률 = `1 − system.linux.memory.available / system.memory.limit`(`system_linux_memory_available`·`system_memory_limit`). 회수 가능한 캐시·버퍼는 사용량에 들어가지 않는다.

**확인**
```bash
free -m
ps aux --sort=-%mem | head
docker stats --no-stream   # Docker 사용 호스트
```

**대응**: 메모리를 많이 쓰는 프로세스·컨테이너의 누수와 한도를 점검하고 재기동하거나 증설한다. OOM kill이 이미 있었는지 시스템 로그에서 확인한다.

**알림 정의가 바뀌어 `OpenObserve — Config` 계획에 `recreate alert infra-memory-usage-p1 (stream changed)`가 나오면**: 서버 알림의 스트림이 정의와 달라 삭제 후 재생성하는 것이다(PUT은 스트림을 못 바꾼다). 반영 중 생성이 실패하면 알림이 서버에 없는 채로 남으므로 원인(새 스트림에 데이터 없음 등)을 고친 뒤 Config를 다시 실행한다.

---

## 메트릭(PromQL) 알림

`metrics` 스트림을 PromQL로 평가하는 알림 17개다(Spec #282, #318에서 업계 기준으로 정비). 통지에는 `▶ 상세 보기` 링크가 나오고, `■ 대상`의 값은 PromQL 결과의 `value`(정수로 반올림)다. 모두 호스트 수집기(OTel hostmetrics·Caddy)의 메트릭이며 호스트 이름은 `host_name` 레이블이다. 알림 정의는 `o2c_alerts`의 `promql` 항목이고 합성 레코드 검증(O2C-030~034)은 적용하지 않는다(평가 오류는 O2C-036이 본다). 모두 State Alert이며 재통지는 P1 60분, 그 밖은 정의의 `silence`(60분 또는 1440분)다.

**평가 방식(#318)**: OpenObserve는 평가 한 번에 조회 구간(period) 안의 **한 점만** 조건을 넘어도 일치로 본다. 그래서 조회 구간을 늘리면 오히려 더 잘 울린다. "N분 지속"은 알림의 대기(`pending_minutes` → `pending_period_sec`)로 만들고, 조회 구간은 평가 주기와 같게(5분/5분) 둔다. 기준은 node-mixin 규칙의 `for`(15분~1시간)다. 근거와 전수 비교는 [조사 문서](../research/alert-conditions-industry-baseline.md)에 있다.

<a id="cpu-usage-p1"></a>
### 🟠 CPU 사용률 매우 높음 (`infra-cpu-usage-p1`)

**조건**: 호스트 CPU 사용률(1 − idle − iowait − steal)이 90% 이상, 5분마다 평가해 15분 지속(재통지 60분). 이름은 그대로지만 등급은 **P2**다(#318).

**이유(업계 관행)**: node-mixin `NodeCPUHighUsage`는 같은 90%를 `for: 15m`, 등급 `info`로 둔다. 단일 호스트 리소스 경보는 호출(page) 대상이 아니다. iowait와 steal은 CPU가 일하는 시간이 아니라 아래 별도 알림이 본다(kubernetes-mixin도 사용률에서 뺀다).

**왜 중요한가**: CPU가 포화되면 서비스 응답과 관리 접속, 수집기까지 밀린다.

**확인**
```bash
top -b -n1 -o %CPU | head -20
docker stats --no-stream   # Docker 사용 호스트
```

**대응**: 폭주한 프로세스·컨테이너의 원인(배포, 배치, 공격 트래픽)을 조치한다. 지속되면 증설이나 부하 분산을 검토한다.

<a id="cpu-usage-p2"></a>
### 🟡 CPU 사용률 높음 (`infra-cpu-usage-p2`)

**조건**: 같은 지표가 80% 이상 90% 미만, 5분마다 평가해 15분 지속(재통지 1440분). 등급은 **P3**다(#318). 90% 이상은 위 P2만 울려 같은 호스트에 동시에 오지 않는다.

**왜 중요한가**: 방치하면 90%를 넘어 위 알림으로 올라간다.

**확인**: 위 P1과 같다. 일시적인 배치·배포인지 상시 부하인지 시각을 본다.

**대응**: 상시 부하면 증설 계획을 세우고, 서비스 설정(스레드 수, 배치 주기)을 점검한다.

<a id="caddy-5xx-error-rate"></a>
### 🔴 Caddy 5xx 오류 비율 (`infra-caddy-5xx-error-rate`)

**조건**: Caddy가 10분 동안 처리한 요청 중 5xx 비율이 5% 이상이고 같은 구간 요청이 10건 이상일 때(재통지 60분). 요청이 적은 호스트의 오탐을 막는 최소 건수다.

**왜 중요한가**: 업스트림이 오류를 내 사용자 요청이 실패하고 있다.

**확인**: 호스트의 Caddy 로그(`docker logs` 또는 로그 파일)에서 5xx 경로와 업스트림을 본다. 업스트림 컨테이너 상태를 본다.

**대응**: 업스트림을 재기동하거나 직전 배포를 되돌린다. 원인을 찾으면 결과를 기록한다.

<a id="caddy-4xx-error-rate"></a>
### 🟡 Caddy 4xx 오류 비율 (`infra-caddy-4xx-error-rate`)

**조건**: 401·499를 뺀 4xx 응답 비율이 10분 동안 5% 이상이고 같은 구간 요청이 **100건 이상**일 때(재통지 1440분). 최소 요청 수는 저트래픽 호스트에서 404 몇 건으로 비율이 넘는 오탐을 막으려고 10건에서 100건으로 올렸다(Q13).

**왜 중요한가**: 잘못된 경로, 설정 불일치, 스캐너 접근, 클라이언트 오류가 늘었다는 신호다. 직접 장애는 아니다.

**확인**: Caddy 로그에서 4xx가 나는 경로와 출발지를 본다.

**대응**: 정상 경로가 404면 라우팅·배포를 확인한다. 외부 스캐너면 방화벽·접근 제한을 검토한다.

<a id="disk-fill-24h"></a>
### 🟠 디스크 24시간 내 가득 참 전망 (`infra-disk-fill-24h`)

**조건**: 최근 6시간 여유 공간의 감소 추세(`deriv`)로 계산한 소진 시간이 24시간 미만이고 사용률이 60% 이상인 파일시스템(ext4·xfs·ext3·btrfs, 읽기·쓰기 마운트)이 1시간 지속(30분마다 평가, 재통지 1440분). node-mixin `NodeFilesystemSpaceFillingUp`(warning, `for: 1h`)과 같다. 아래 4시간 P1 조건(사용률 80% 이상, 4시간 미만)에 걸린 파일시스템은 이 알림에서 뺀다. 행에 호스트·마운트·남은 시간(시간)이 나온다.

**왜 중요한가**: 사용률 알림(90%·95%)보다 먼저 급증하는 쓰기를 알려 준다.

**확인**
```bash
df -h <마운트>
sudo du -xh <마운트> --max-depth=2 | sort -h | tail -20
```

**대응**: 급증한 로그·덤프·Docker 데이터를 정리하거나 로테이션을 조정한다. 정상 증가면 증설을 계획한다.

<a id="disk-fill-4h"></a>
### 🔴 디스크 4시간 내 가득 참 전망 (`infra-disk-fill-4h`)

**조건**: 사용률 80% 이상(여유 20% 미만)인 파일시스템이 최근 6시간 감소 추세대로면 4시간 안에 가득 차는 상태가 1시간 지속(10분마다 평가, 재통지 60분). node-mixin `NodeFilesystemSpaceFillingUp`(critical, `for: 1h`)과 같다. 같은 파일시스템에는 위 24시간 P2가 오지 않는다.

**왜 중요한가**: 몇 시간 안에 디스크가 가득 차 서비스·DB·로그 기록이 멈춘다. 업무 시간 외라도 지금 조치한다.

**확인**: 위 24시간 알림과 같다. `ls -lt`로 최근 커지는 파일, `lsof +L1`로 지웠지만 열려 있는 파일을 본다.

**대응**: 폭주하는 로그·덤프를 정리하거나 원인 프로세스를 멈춘다. 정리할 수 없으면 볼륨을 늘린다.

<a id="network-errors"></a>
### 🟠 네트워크 인터페이스 오류 (`infra-network-errors`)

**조건**: 물리 인터페이스(`lo`·veth·docker·br-·virbr·cni·flannel·cali 제외)의 5분 오류/패킷 비율이 1% 초과이고 같은 5분 오류가 10건 이상인 상태가 1시간 지속(5분마다 평가, 재통지 60분). node-mixin `NodeNetworkReceiveErrs`·`TransmitErrs`(비율 1%, `for: 1h`)와 같다. 예전의 절대 건수(10분 10건)는 트래픽이 많은 인터페이스에서는 아주 낮은 비율에도 울렸다. 비율 비교는 반올림 전에 PromQL 안에서 한다. 행에 호스트·인터페이스·방향·오류 비율(%)이 나온다.

**왜 중요한가**: 케이블, NIC, 스위치 포트, 드라이버 문제의 신호이며 패킷 손실로 이어진다.

**확인**
```bash
ip -s link show <인터페이스>
ethtool <인터페이스>   # 속도·duplex 협상
```

**대응**: 케이블·SFP·스위치 포트 오류를 확인하고 반복되면 포트나 NIC 교체를 검토한다.

<a id="cpu-load-saturation"></a>
### 🟠 CPU 부하 포화 (`infra-cpu-load-saturation`)

**조건**: 1분 load average를 논리 코어 수로 나눈 값이 2 초과, 5분마다 평가해 15분 지속(재통지 60분). node-mixin `NodeSystemSaturation`과 같다. 비교는 반올림 전에 PromQL 안에서 한다(예전에는 반올림 때문에 실제로 2.5부터 울렸다).

**왜 중요한가**: 실행 대기 작업이 코어 수의 2배를 넘어 응답이 지연된다.

**확인**: `uptime`과 `top`으로 load와 대기 프로세스를 본다. CPU 사용률이 낮은데 load가 높으면 디스크 I/O 대기(아래 iowait)를 본다.

**대응**: 원인 프로세스·배치를 줄이거나 증설을 검토한다.

<a id="cpu-iowait"></a>
### 🟡 CPU iowait 높음 (`infra-cpu-iowait`)

**조건**: 호스트 평균 iowait 비율이 10% 초과, 5분마다 평가해 15분 지속(재통지 1440분). 등급은 **P3**다(#318). iowait는 증상이 아니라 원인 지표이고 디스크 지연·포화 알림과 겹친다.

**왜 중요한가**: 디스크가 느리거나 포화되어 서비스 지연과 load 상승을 일으킨다.

**확인**: `iostat -x 1 5`, `iotop -o`로 I/O가 많은 장치와 프로세스를 본다. 아래 디스크 지연·I/O 포화 알림이 함께 왔는지 본다.

**대응**: 백업·배치가 원인이면 시간대를 조정한다. 디스크 이상이면 교체를 검토한다.

<a id="cpu-steal"></a>
### 🟡 CPU steal 높음 (`infra-cpu-steal`)

**조건**: 호스트 평균 steal 비율이 10% 초과, 5분마다 평가해 30분 지속(재통지 1440분). 등급은 **P3**다(#318). 조치가 하이퍼바이저 쪽이라 당일 대응 대상이 아니다.

**왜 중요한가**: 같은 물리 서버의 다른 가상 머신(noisy neighbor) 때문에 이 서버의 성능이 떨어진다.

**확인**: `top`의 `st` 값이 계속되는지 본다.

**대응**: 가상화 관리자에게 물리 서버 과할당 여부를 묻고, 반복되면 다른 물리 서버로 이전하거나 자원 예약을 검토한다.

<a id="disk-io-saturation"></a>
### 🟠 디스크 I/O 포화 (`infra-disk-io-saturation`)

**조건**: 디스크 장치별 평균 I/O 큐 깊이(`system_disk_weighted_io_time`의 5분 증가율)가 10 초과, 5분마다 평가해 30분 지속(재통지 60분). node-mixin `NodeDiskIOSaturation`(`for: 30m`)과 같다. 장치는 `^(sd[a-z]+|nvme[0-9]+n[0-9]+|vd[a-z]+|xvd[a-z]+|dm-[0-9]+|md[0-9]+)$`만 본다(파티션 `sda3` 등 중복 제외). OpenObserve 정규식은 앞뒤가 고정되지 않아 `^(…)$`가 필요하다. LVM 호스트는 물리 장치(`sda`)와 `dm-0`이 따로 잡힐 수 있다. 행에 호스트·장치·큐 깊이가 나온다.

**왜 중요한가**: 요청이 처리 속도보다 빨리 쌓여 읽기·쓰기 지연이 커진다.

**확인**: `iostat -x 1 5`로 사용률과 대기 시간을, `iotop -o`로 I/O가 많은 프로세스를 본다.

**대응**: 백업·DB·로그 등 원인 프로세스를 조정한다. 지속되면 디스크 성능 증설이나 부하 분산을 검토한다.

<a id="disk-read-latency"></a>
### 🟠 디스크 읽기 지연 (`infra-disk-read-latency`)

**조건**: 디스크 장치별 **30분 평균** 읽기 지연(처리 시간 ÷ 요청 수)이 100ms 초과이고 같은 30분의 읽기 요청이 초당 5건 이상(`o2c_disk_latency_min_iops`)인 상태가 30분 지속(5분마다 평가, 재통지 60분). 장치 필터는 위 I/O 포화와 같다(파티션 중복 제외). 요청 하한은 입출력이 거의 없을 때 느린 요청 한두 건이 평균을 올리는 오탐을 막는다.

**이유(#318)**: 예전 정의(5분 증가율, 조회 10분)는 "10분 내내"라고 적었지만 실제로는 10분 안의 한 점만 넘어도 울렸다. 그래서 2분짜리 쓰기 몰림(ns0338, 2026-10-22)에도 울렸다. 조회 구간을 늘리면 한 점이 걸릴 기회가 늘어 오히려 더 잘 울린다. 지금은 평균 창을 30분으로 늘리고 30분 대기를 더했다. 업계 기준도 "지속되는" 지연을 본다(Microsoft 10~15ms "consistently", VMware 10ms "sustained"). 임계 100ms는 HDD·쓰기 캐시 없는 RAID를 고려한 값이다.

**왜 중요한가**: 읽기 위주 서비스의 응답이 지연되고 디스크 고장이나 RAID 컨트롤러 캐시 이상의 신호일 수 있다.

**확인**: `iostat -x 1 5`로 읽기 지연을 보고 `dmesg`·SMART(`smartctl -a <장치>`)로 디스크 오류를, HP 서버는 `ssacli ctrl all show status`로 컨트롤러 캐시·배터리 상태를 본다.

**대응**: 오류가 있으면 디스크 교체를 계획하고, 부하 문제면 I/O를 분산한다.

<a id="disk-write-latency"></a>
### 🟠 디스크 쓰기 지연 (`infra-disk-write-latency`)

**조건**: 디스크 장치별 30분 평균 쓰기 지연이 100ms 초과이고 같은 30분의 쓰기 요청이 초당 5건 이상(`o2c_disk_latency_min_iops`)인 상태가 30분 지속(5분마다 평가, 재통지 60분). 읽기 지연과 같은 이유다.

**실서버 점검(2026-10-22, 이 정의로 지난 24시간을 5분 단위로 계산)**: ns0288(쓰기 캐시 영구 비활성)은 30분 평균이 계속 100ms를 넘어 최장 약 11시간 이어졌고, ns0272·ns0273도 30분 이상 이어진 구간이 각각 5번 있었다(만성). ns0338의 2분 몰림은 30분 평균 최대 97ms라 걸리지 않았다.

**왜 중요한가**: 쓰기 위주 서비스(DB 커밋, 로그 기록, 백업)가 지연된다. RAID 컨트롤러 쓰기 캐시가 꺼졌거나(배터리 고장·미장착) 디스크 고장의 신호일 수 있다.

**확인**: 위 읽기 지연과 같다. 백업이나 대량 쓰기가 같은 시각에 있었는지도 본다.

**대응**: 오류가 있으면 디스크를 교체하고, 컨트롤러 캐시가 꺼져 있으면 배터리·캐시 모듈을 점검한다. 부하 문제면 쓰기를 분산하거나 시간대를 옮긴다. 원인이 분명한 만성 호스트(캐시 비활성)는 하드웨어 조치 전까지 매일 울리므로 조치 일정을 티켓으로 추적한다.

<a id="inode-fill-24h"></a>
### 🟠 inode 24시간 내 고갈 전망 (`infra-inode-fill-24h`)

**조건**: 여유 inode가 40% 미만이고 최근 6시간 여유 inode의 감소 추세로 계산한 소진 시간이 24시간 미만인 파일시스템이 1시간 지속(30분마다 평가, 재통지 1440분). node-mixin `NodeFilesystemFilesFillingUp`(warning)과 같다. 예전의 1시간 추세는 임시 파일 생성 폭주에 흔들렸다. 행에 호스트·마운트·남은 시간이 나온다.

**왜 중요한가**: 용량이 남아도 inode가 다하면 파일을 만들 수 없다.

**확인**
```bash
df -i <마운트>
sudo du -x --inodes <마운트> --max-depth=3 | sort -n | tail -20
```

**대응**: 작은 파일이 몰린 디렉터리(세션·캐시·메일 큐 등)를 정리하고 원인 프로세스를 고친다.

<a id="conntrack-limit"></a>
### 🟠 conntrack 테이블 사용률 (`infra-conntrack-limit`)

**조건**: conntrack 사용 수 ÷ 최대 수가 80% 초과(5분 구간, 재통지 60분).

**왜 중요한가**: 테이블이 가득 차면 새 연결의 패킷이 버려져 간헐적인 접속 실패가 생긴다.

**확인**
```bash
sudo conntrack -C
sysctl net.netfilter.nf_conntrack_max
sudo conntrack -L | awk '{print $5}' | sort | uniq -c | sort -rn | head   # 연결이 많은 출발지
```

**대응**: 연결을 많이 만드는 프로세스나 출발지(스캔, DDoS)를 조치한다. 정상 트래픽이면 `nf_conntrack_max` 상향을 검토한다.

<a id="swap-usage"></a>
### 🟡 스왑 사용률 높음 (`infra-swap-usage`)

**조건**: 스왑 사용률이 80% 초과이면서 같은 호스트의 사용 가능 메모리(`system_linux_memory_available` ÷ `system_memory_limit`)가 10% 미만인 상태가 10분 구간 지속(재통지 1440분). 심각도는 P3(주의)다. 행에 호스트·스왑 장치·사용률이 나온다.

**이유(업계 관행)**: 스왑 사용률은 원인 지표라 단독으로는 오탐이 많다(오래된 페이지가 밀려난 정상 상태도 100%가 될 수 있다). 그래서 낮은 등급으로 두고 메모리 부족을 함께 요구한다. node-mixin은 메모리 압박 신호를 major fault 비율로 옮겼고, GitLab 런북은 available < 5%와 높은 major fault를 함께 요구한다.

**왜 중요한가**: 스왑이 가득 찬 데다 여유 메모리까지 부족해 메모리가 모자란 상태로, 서비스가 느려지고 OOM kill로 이어질 수 있다.

**확인**
```bash
free -m
swapon --show
ps aux --sort=-%mem | head
```

**대응**: 누수·한도 초과 프로세스를 재기동하거나 한도를 조정한다. 상시 부족이면 메모리를 증설한다.

<a id="memory-pressure"></a>
### 🟠 메모리 압박 — 주요 페이지 폴트 (`infra-memory-pressure`)

**조건**: 주요(major) 페이지 폴트가 초당 1000건 초과이면서 같은 호스트의 사용 가능 메모리가 전체의 10% 미만인 상태가 15분 지속(5분마다 평가, 재통지 60분). node-mixin `NodeMemoryMajorPagesFaults`(`for: 15m`)와 같은 지속 조건이다.

**이유**: 여유 메모리가 충분한 DB 호스트가 디스크에서 데이터를 읽는 정상 패턴(mysqld 등)은 major fault가 많아도 메모리 압박이 아니다. 사용 가능 메모리 조건을 AND로 더해 이를 거른다.

**왜 중요한가**: 필요한 페이지를 디스크에서 읽어 오는데 여유 메모리도 없어 서비스가 크게 느려진다.

**확인**: `vmstat 1 5`, `free -m`으로 스왑·메모리 상태를 보고 메모리 상위 프로세스와 한도(JVM 힙, 컨테이너 limit)를 점검한다.

**대응**: 반복되면 메모리를 증설하거나 한도를 조정한다. OOM kill이 이미 있었는지 시스템 로그에서 확인한다.
