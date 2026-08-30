# Ansible 테스팅 및 멱등성 검증 표준 가이드라인 (Testing Guideline)

본 문서는 **Overseer** 프로젝트의 Ansible 역할(Roles)과 플레이북(Playbooks)을 안전하게 개발, 검증, 배포하기 위한 **4단계 테스팅 피라미드**와 **Molecule 기반 컨테이너 테스트 표준 절차**를 정의합니다.

---

## 1. 테스팅 피라미드 아키텍처 (4-Layer Testing Pyramid)

```
             ▲
            / \       [Layer 4] 실서버 카나리 배포 (Canary Deployment)
           /   \      [Layer 3] Molecule 격리 통합 테스트 & 멱등성 검증
          /     \     [Layer 2] 사전 시뮬레이션 (Check Mode / Diff)
         /_______\    [Layer 1] 정적 분석 및 문법 검사 (ansible-lint / syntax-check)
```

| 계층 | 테스트 유형 | 주요 도구 | 검증 목적 | 실행 주기 |
|---|---|---|---|---|
| **Layer 1** | 정적 분석 & 문법 | `ansible-lint`, `--syntax-check` | 안티패턴, 보안 취약점, 문법 에러 즉시 탐지 | 코드 작성 시 상시 |
| **Layer 2** | 사전 시뮬레이션 | `ansible-playbook --check --diff` | 실제 서버 변경 없이 적용될 설정 라인 단위 사전 확인 | 운영 적용 직전 |
| **Layer 3** | 격리 통합 테스트 | **Molecule** (Docker/Systemd) | 다중 OS 환경에서 실제 적용, **멱등성(Idempotence)**, 상태 단언(Verify) | PR 생성 / 커밋 시 |
| **Layer 4** | 카나리 배포 | `--limit <single-node>` | 1개 실제 노드에 선배포하여 물리/네트워크 환경 검증 | 운영 배포 초기 |

---

## 2. Layer 1: 정적 분석 & 문법 검사 (Static Analysis)

코드 스타일과 모듈 사용 규칙을 검증합니다.

```bash
# 1. Ansible 문법 체크
./docker-run.sh playbooks/provision.yml --syntax-check

# 2. ansible-lint 정적 검사 (베스트 프랙티스 & 안티패턴 검사)
./docker-run.sh ansible-lint
```

---

## 3. Layer 2: 사전 시뮬레이션 (Dry-Run / Diff)

실제 서버에 접속하여 아무것도 변경하지 않고(Dry-Run), 변경될 설정 파일의 차이점(`diff`)을 사전에 점검합니다.

```bash
# 특정 대상 노드 대상 Dry-Run 시뮬레이션
./docker-run.sh playbooks/provision.yml -k -K --limit ns0333.nanoit.kr --check --diff
```

---

## 4. Layer 3: Molecule 격리 통합 테스트 (핵심 정석)

**Molecule**은 Ansible 공식 권장 통합 테스트 프레임워크로, 로컬 또는 CI 환경에서 **Rocky Linux 9 / Ubuntu 22.04 등 Systemd 컨테이너**를 자동으로 띄워 전체 라이프사이클을 검증합니다.

### 1) Molecule 테스트 라이프사이클 (`molecule test`)

```
┌──────────┐     ┌───────────┐     ┌─────────────┐     ┌──────────┐     ┌───────────┐
│  Create  │ ──> │ Converge  │ ──> │ Idempotence │ ──> │  Verify  │ ──> │  Destroy  │
└──────────┘     └───────────┘     └─────────────┘     └──────────┘     └───────────┘
 컨테이너 기동       Role 1차 적용        멱등성 검증(2차실행)    상태 단언 검증      테스트환경 정리
```

1. **`Create`**: `molecule.yml`에 정의된 대상 OS 컨테이너(Rocky, Ubuntu 등)를 Docker로 기동
2. **`Converge`**: `converge.yml` 플레이북을 실행하여 전체 Role을 컨테이너에 실제 설치/설정
3. **`Idempotence (멱등성 검증)`**: 동일한 Role을 **한 번 더 연속 실행**하여 `changed=0` (변경 없음)인지 검증
   - *만약 2번째 실행에서 변경점이 발생하면 테스트 실패 (멱등성 버그)*
4. **`Verify (상태 검증)`**: `verify.yml`을 실행하여 파일 권한, 사용자 생성, 서비스 유닛, 바이너리 실행 여부를 단언(`assert`)
5. **`Destroy`**: 테스트가 완료되면 테스트용 컨테이너를 안전하게 삭제

---

### 2) Molecule 실행 명령어

```bash
cd /home/ppzxc/projects/overseer/ansible

# ① 전체 풀 라이프사이클 테스트 실행 (Create -> Converge -> Idempotence -> Verify -> Destroy)
./docker-run.sh molecule test

# ② 단계별 디버깅 실행 (컨테이너를 유지하면서 작업할 때)
# 1) 컨테이너 기동
./docker-run.sh molecule create

# 2) Role 적용 (수정 후 반복 실행 가능)
./docker-run.sh molecule converge

# 3) 멱등성만 별도 검증
./docker-run.sh molecule idempotence

# 4) 상태 단언(Verify) 태스크만 실행
./docker-run.sh molecule verify

# 5) 테스트 컨테이너 내부 쉘 접속 (디버깅)
./docker-run.sh molecule login --host test-rockylinux9

# 6) 테스트 컨테이너 정리 및 종료
./docker-run.sh molecule destroy
```

---

### 3) Molecule 시나리오 구성 파일

- [`molecule/default/molecule.yml`](file:///home/ppzxc/projects/node-provisioner/molecule/default/molecule.yml): 테스트 대상 OS(Rocky Linux, Ubuntu) 및 Docker 드라이버 설정
- [`molecule/default/converge.yml`](file:///home/ppzxc/projects/node-provisioner/molecule/default/converge.yml): 테스트 실행할 엔트리포인트 플레이북
- [`molecule/default/verify.yml`](file:///home/ppzxc/projects/node-provisioner/molecule/default/verify.yml): 시스템 상태 단언(Assert) 검증 태스크

---

## 5. 멱등성(Idempotency) 디버깅 및 작성 규칙

Molecule 테스트 중 `Idempotence` 단계가 실패하는 주된 원인과 해결 방법:

1. **`shell` / `command` 모듈 사용 시**:
   - `changed_when` 조건을 명시하지 않으면 실행될 때마다 무조건 changed가 발생하여 멱등성이 깨집니다.
   - **올바른 작성 예**:
     ```yaml
     - name: Check version
       ansible.builtin.command: /usr/local/bin/otelcol-contrib --version
       register: result
       changed_when: false
     ```
2. **파일 다운로드/생성 시**:
   - `creates` 파라미터 또는 파일 존재 여부 검사(`stat`)를 함께 사용하여 중복 작업을 방지합니다.

---

## 6. Layer 4: 실서버 카나리(Canary) 배포 절차

실제 운영 IDC 서버에 적용할 때는 항상 단일 노드에 선적용한 뒤 점진적으로 확장합니다.

1. **1단계 (단일 카나리 노드 적용)**:
   ```bash
   ./docker-run.sh playbooks/provision.yml -k -K --limit ns0333.nanoit.kr
   ```
2. **2단계 (실서버 접속 및 동작 검증)**:
   - 신규 관리자 계정 로그인 테스트: `ssh infra-admin@<IP>`
   - OTel 에이전트 서비스 상태 점검: `systemctl status otelcol-contrib`
   - 타임 동기화 상태 점검: `chronyc sources -v`

3. **3단계 (전체 그룹 롤링 배포)**:
   - 카나리 노드 검증 완료 후 전체 그룹으로 확장 (`--limit compute_nodes` 등)
