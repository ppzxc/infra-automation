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
- 이중 등급 알림(디스크·inode·메모리)은 P2가 "P2 이상 P1 미만" 구간만 잡아 같은 대상에 P1·P2가 동시에 오지 않는다.

## 공통 절차

1. 메시지의 `▶ 로그 보기`로 OpenObserve에서 원문 로그를 연다. 시각은 UTC다(KST = UTC+9).
2. `■ 대상`의 호스트·출발지·사용자를 작업 일정, 배포 기록(Semaphore Task 이력)과 대조한다. Semaphore와 사무실에서 시작된 접속은 대부분 운영 작업이다(정상 출발지 목록은 OpenBao `normal_sources`).
3. 대응하면 결과(원인, 조치, 담당자)를 기록한다. ISMS 2.11.5(사고 대응) 증적이 된다.
4. 같은 알림이 반복되고 원인이 정상 작업이면 임계값이나 예외 조건을 고치는 PR을 낸다. 알림을 끄지 않는다.

---

<a id="root-login-success"></a>
## 🔴 root 계정 원격 로그인 성공 — 외부 출발지 (`infra-root-login-success`)

**조건**: `security_logs`에서 `user_name = 'root'`인 SSH 로그인 성공이 5분 안에 1건 이상이고, 출발지가 **정상 출발지 목록에 없을 때**. 목록의 Semaphore 종류 출발지는 이 알림에 걸리지 않고, 사무실 종류 출발지는 아래 P3 하루 요약으로 간다.

**정상 출발지 목록**: OpenBao `agents/openobserve`의 `normal_sources`(`[{"address": "<IP>", "kind": "semaphore|office"}]`)에만 둔다. 저장소에는 주소를 두지 않는다. 바꾼 뒤 `OpenObserve — Config`를 다시 실행하면 반영된다. 목록이 비어 있으면 모든 root 로그인이 이 P1로 온다. SSH 로그인 실패 급증 알림에는 이 목록을 적용하지 않는다(정상 출발지의 실패 급증도 신호다).

**왜 중요한가**: root 직접 접속은 누가 접속했는지 식별할 수 없고, 프로비저닝 이후에는 막혀야 한다(`PermitRootLogin`, KISA U-01). 정상 출발지가 아닌 곳의 성공 기록은 침해이거나 설정이 우회된 것이다.

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

<a id="root-login-office-daily"></a>
## 🟡 사무실·S2S 출발지 root 로그인 — 하루 요약 (`infra-root-login-office-daily`)

**조건**: `normal_sources`에서 `kind=office`인 출발지의 root SSH 로그인 성공. 조회 구간·재통지 모두 1440분이라 하루에 한 번 요약으로 온다.

**왜 중요한가**: 사내 출발지라 침해 가능성은 낮지만 root 직접 접속은 정책 위반이다. 기록으로 남기고 습관을 바로잡는다.

**대응**
- 작업자와 작업 내용을 확인하고 일반 계정 + sudo로 전환하도록 안내한다.
- 사무실 주소가 아닌 것으로 밝혀지거나 작업자가 확인되지 않으면 위 P1 절차(외부 출발지)로 격상한다.

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

**조건**: ns0266이 5분마다 OpenObserve `/healthz`를 확인해, 실패하면 OpenObserve를 거치지 않고 네이버웍스 webhook으로 직접 P1을 보낸다. 같은 장애는 60분마다만 다시 통지하고 복구 통지는 없다(통지가 멈추면 복구). ns0266·ns0332 동시 장애는 감수한다.

**왜 중요한가**: OpenObserve가 죽으면 이 문서의 모든 알림이 동작하지 않는다.

**확인**
```bash
# ns0332
systemctl status openobserve; df -h; free -m
# ns0266 (확인 쪽)
systemctl list-timers openobserve-health.timer
journalctl -u openobserve-health.service -n 20
```

**대응**: ns0332의 OpenObserve 서비스·디스크·메모리를 복구한다. 복구 뒤 Silent Host 알림이 남아 있으면 수집 재개를 확인한다. ns0266에서 타이머 자체가 안 돌면 `Host Agents — Config`를 다시 실행한다.

**수동 검증 절차** (배포 후 한 번, 또는 webhook 값을 바꾼 뒤): ns0266에서 대상 URL을 틀린 값으로 한 번 실행해 통지가 도착하는지 본다.
```bash
sudo rm -f /var/lib/openobserve-health/notified
sudo O2_HEALTH_URL_OVERRIDE=http://127.0.0.1:1/healthz /usr/local/sbin/openobserve-health-check
```
네이버웍스에 `[P1 긴급] OpenObserve 응답 없음`이 도착하면 정상이다(종료코드 0). 통지 뒤 60분 동안은 같은 장애로 보고 재통지하지 않으므로, 이 시험 뒤에는 위 첫 줄처럼 상태 파일을 지운다(실제 장애가 아니므로 상태가 남지 않게 한다).

<a id="silent-host"></a>
## 🟠/🔴 Silent Host — 메트릭 하트비트 끊김 (`infra-silent-host-p2`, `infra-silent-host-p1`)

수집 로스터 호스트(인벤토리 `servers` − Host Agents Exclusion − Host Agents Backup Only, ns0266·ns0332 포함)에서 `system_memory_usage` 하트비트가 15분 넘게 끊기면 P2(3시간 미만), 3시간 넘게 끊기면 P1이다. 같은 호스트에 P2와 P1이 동시에 오지 않는다. 서버가 내려가도(서버 응답 없음) 수집기가 멈춰도 같이 걸린다.

**왜 중요한가**: OpenObserve는 약 5시간보다 오래된 로그를 받지 않는다. 이 시간이 지나면 이 구간 로그는 OpenObserve로 복구되지 않음 — ISMS 로그 증거가 중앙에서 영구히 빠진다(2026-10 CentOS 6 수집기 중단 사고, #161).

**확인**
1. 같은 호스트의 서버 응답 없음(Unreachable Host) 알림이 있으면 그쪽이 원인이다. 서버·네트워크부터 복구한다.
2. 서버가 살아 있으면 호스트에서 `systemctl status otelcol-contrib`(CentOS 6은 `service otelcol-contrib status`)와 최근 로그를 본다.

**대응**: 수집기를 재기동하고 하트비트가 돌아오는지 본다. P1이면 끊긴 구간 로그가 5시간 한도 안에 들어오는지 확인하고, 넘었다면 호스트의 원본 로그를 보존한다. 며칠 이상 계획 정지하는 호스트는 OpenBao `silent_host_exceptions`에 만료일과 함께 등록하고 `OpenObserve — Config`를 다시 실행한다. 호스트를 편입·폐기했다면 같은 Config 재실행이 필요하다.

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

**편입·폐기**: 대상 목록은 검사하는 쪽이 Host Agents 실행 때마다 `servers` 전체의 OpenBao `hosts/<호스트>`(주소 `public_ip`, 비표준 SSH 포트 `ansible_port`)에서 만든다. 실행 범위(`target_hosts`)와 무관하다. 호스트를 편입·폐기하면 `Host Agents — Deploy`(또는 Config)를 ns0266에 다시 반영해야 한다.
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

수집 로스터 호스트(Backup Only 제외, ns0266·ns0332 포함)의 마지막 성공 `job=backup`이 26시간을 넘으면 하루 1번 P2로 알린다(State Alert). 배포만 되고 한 번도 백업하지 않은 호스트도 걸린다.

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
