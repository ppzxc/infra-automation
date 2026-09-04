# Cisco IOS Switch Configuration Backup Role Task Specification

`cisco_backup` 역할은 온프레미스 IDC 인프라의 Cisco IOS 네트워크 스위치 장비의 러닝 컨피그(`show running-config`)를 수집하고, 안전한 로컬/원격 스토리지에 아카이빙하며, 보관 주기(Retention)를 초과한 백업을 자동 정리하는 네트워크 백업 자동화 모듈입니다.

---

## 1. 개요 및 구현 기능 (What)

- **Ansible Native Network CLI 통합**: Netmiko 스크립트 의존성 없이 Ansible 공식 `cisco.ios` 컬렉션을 활용하여 장비에 안전하게 접속 및 명령 실행.
- **러닝 컨피그 자동 수집**: `show running-config` 명령을 실행하여 최신 장비 설정을 실시간 수집.
- **백업 파일 무결성 및 오류 검증**: 명령어 출력값 내 `% Invalid input detected` 등 CLI 에러 패턴을 검증하여 손상되거나 비정상적인 백업 파일 생성 방지.
- **안전한 권한 보관 및 타임스탬프 네이밍**: 디렉토리(`0700`), 백업 파일(`0600`) 최소 권한을 부여하고 `<장비명>_YYYYMMDDTHHMMSS.txt` 형식으로 저장.
- **보관 주기(Retention) 자동 관리**: 지정된 보관 주기(`cisco_backup_retention_days`, 기본 90일)를 초과한 백업 파일을 자동 검색하여 만료 파일 제거.
- **Semaphore UI 기반 스케줄링**: 기존의 리눅스 `systemd` 타이머 대신 Semaphore UI의 Cron Schedule 기능을 활용하여 중앙 집중식 예약 실행 및 결과 알림(Slack/Webhook) 연동.

---

## 2. 왜 구현해야 하는가? (Why)

1. **단일 오케스트레이션 툴체인 일원화**:
   - 서버 호스트 관리와 네트워크 스위치 설정을 동일한 Ansible / Semaphore UI 툴체인으로 통합 관리하여 운영 파편화를 방지합니다.
2. **비밀번호 및 자격증명 보안 강화**:
   - 평문 설정 파일 대신 Semaphore UI의 Key Store 또는 OpenBao(Vault)를 통해 스위치 접속 계정 및 `enable` 비밀번호를 안전하게 주입합니다.
3. **네트워크 장애 시 신속한 복구력 확보**:
   - 정기적인 형상 백업을 통해 장비 교체, 장애 발생, 설정 실수 시 최신 백업본을 통해 즉각적인 복구가 가능합니다.

---

## 3. 태스크 매트릭스 (Task Matrix)

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `CISCO-001` | `Ensure local backup destination directory exists` | `ansible.builtin.file` | Controller / Localhost | 디렉토리 상태 및 권한(`0700`) 일치 시 `ok` |
| `CISCO-002` | `Collect running configuration from Cisco IOS switch` | `cisco.ios.ios_command` | Cisco IOS | 장비로부터 `show running-config` 실행 후 출력 등록 |
| `CISCO-004` | `Verify configuration output validity` | `ansible.builtin.assert` | Controller / Localhost | 출력값 검증 및 CLI 에러 패턴 미포함 확인 |
| `CISCO-003` | `Save running configuration to backup destination` | `ansible.builtin.copy` | Controller / Localhost | 백업 파일 생성 및 권한(`0600`) 부여 |
| `CISCO-005` | `Clean up old backup archives exceeding retention period` | `ansible.builtin.find` | Controller / Localhost | 만료 백업 파일 검색 및 삭제 수행 |
| `CISCO-006` | `Collect running configuration via Telnet` | `ansible.builtin.command` | Controller / Localhost | Telnet 소켓 세션 통해 설정 수집 |
| `CISCO-007` | `Collect running configuration via Bastion jump session` | `ansible.builtin.command` | Controller / Localhost | Bastion 대화형 쉘 점프 통해 설정 수집 |

---

## 4. 플레이북 실행 및 Semaphore UI 연동

### CLI 직접 실행
```bash
# 전체 스위치 백업 실행
./docker-run.sh playbooks/backup_cisco.yml

# 특정 스위치만 선별 실행
./docker-run.sh playbooks/backup_cisco.yml --limit sw-core-01.idc.internal
```

### Semaphore UI 예약 작업 구성
1. **Task Template 생성**:
   - Playbook: `playbooks/backup_cisco.yml`
   - Inventory: `inventory/hosts.yml`
   - Environment: `cisco_switches` 접속 자격증명 주입
2. **Cron Schedule 설정**:
   - 매일 새벽 03:00 정기 실행: `0 3 * * *`
   - 작업 완료 후 Semaphore 기본 Webhook/알림 채널(Slack, Teams 등)로 자동 결과 전달
