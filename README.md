# Overseer Ansible Provisioning & Automation

**Overseer Ansible**은 Overseer 중앙 컨트롤 플레인 호스트(Docker CE, OpenBao, Boundary, Postgres)와 온프레미스 대상 서버(Node Exporter, OTEL Collector, OpenBao SSH CA, Boundary Target)의 프로비저닝, 보안 하드닝 및 형상 관리를 자동화하는 툴체인입니다.

---

## 1. 인벤토리 구조 (`overseer` vs `servers`)

| 인벤토리 그룹 | 정의 경로 | 대상 호스트 역할 | 적용 Playbook |
|---|---|---|---|
| **`overseer`** | `inventory/group_vars/overseer.yml` | OpenBao, Boundary, Postgres 컨트롤 플레인 구동 호스트 | `playbooks/provision_overseer.yml` |
| **`servers`** | `inventory/group_vars/servers.yml` | 온프레미스 IDC 일반 서버 노드 (타겟 서버) | `playbooks/provision_servers.yml` |
| **`loadbalancers`**| `inventory/group_vars/loadbalancers.yml` | HAProxy, Keepalived, VIP 로드밸런서 노드 (L4 포워딩 & ARP Flux 방지) | `playbooks/provision_servers.yml` |

---

## 2. 역할(Roles) 카탈로그

1. **`docker_engine`**:
   - Podman 및 레거시 패키지 충돌 완벽 정리 (`DOC-001 ~ DOC-002`)
   - 공식 Docker CE 최신판 & Docker Compose 플러그인 설치 (`DOC-003 ~ DOC-009`)
   - 운영 하드닝 `daemon.json` 배포 (`DOC-010 ~ DOC-013`: `json-file` log rotation, `live-restore: true`, `metrics-addr: 127.0.0.1:9323`)
2. **`overseer_control_plane`**:
   - 컨트롤 플레인 커널 파라미터(`vm.swappiness=1`, `fs.file-max`) 및 `memlock` 제한 해제 (`CP-001 ~ CP-002`)
   - 영구 데이터 디렉토리 생성 및 권한 설정 (`CP-003`)
   - Docker Compose 자동 오케스트레이션 Systemd 서비스 배포 (`CP-004 ~ CP-005`: `overseer.service`)
3. **`common`**:
   - 타임존(`Asia/Seoul`), Chrony NTP Standard UTC 동기화, 기본 패키지, 커널 튜닝, 관리자 계정 생성 (`COMMON-001 ~ COMMON-017`)
4. **`security`**:
   - SSH 보안 하드닝, 방화벽(UFW/Firewalld/iptables), SELinux(permissive), Auditd, Fail2ban (`SEC-001 ~ SEC-015`)
5. **`openbao_ssh_ca`**:
   - OpenBao SSH CA 공개키 배포 및 단기 SSH 인증서 신뢰 설정 (`BAO-001 ~ BAO-007`)
6. **`boundary_target`**:
   - HashiCorp Boundary Zero-Trust 타겟 노드 메타데이터 등록 (`BND-001 ~ BND-003`)
7. **`monitoring`**:
   - OpenTelemetry Collector Contrib(`otelcol-contrib`) 바이너리/서비스 배포 및 원격 OTEL 백엔드로 OTLP 아웃바운드 푸시 (`MON-001 ~ MON-006`)
   - `hostmetrics` receiver를 통한 호스트 CPU, Memory, Disk, Network 등 저수준 시스템 메트릭 직접 수집
   - 레거시 `node_exporter` 데몬/바이너리/유저 자동 정리 (`MON-CLEANUP-001 ~ MON-CLEANUP-005`)


---

## 3. 플레이북 실행 가이드

### 0. 인벤토리 준비 (Git 격리 및 템플릿 복사)
```bash
# 템플릿 파일로부터 실제 hosts.yml 생성 (hosts.yml은 .gitignore 처리됨)
cp inventory/hosts.yml.example inventory/hosts.yml
```

### 1. 플레이북 실행
#### Option A: Semaphore Web UI를 통한 실행 (권장)
- 브라우저 접속: `http://<호스트IP>:3000` (초기 계정: `admin` / `semaphoreadmin`)
- UI에서 **Playbook Template** 선택 후 버튼 클릭으로 간편 실행 및 실시간 모니터링

#### Option B: CLI 스크립트 직접 실행
```bash
# 1. Overseer 컨트롤 플레인 전용 호스트 프로비저닝 (Docker CE + Podman 제거 + 하드닝)
./docker-run.sh playbooks/provision_overseer.yml

# 2. 온프레미스 대상 서버 프로비저닝 (SSH CA + Boundary + OTEL Agent)
./docker-run.sh playbooks/provision_servers.yml

# 3. 전체 인프라 일괄 프로비저닝
./docker-run.sh playbooks/provision.yml

# 4. Dry-Run (Check & Diff) 시뮬레이션
./docker-run.sh playbooks/provision.yml --check --diff

# 5. 특정 타겟 호스트만 선택 실행
./docker-run.sh playbooks/provision_servers.yml --limit ns0333.nanoit.kr

# 6. 정기 유지보수 및 보안 패치
./docker-run.sh playbooks/maintenance.yml
```
