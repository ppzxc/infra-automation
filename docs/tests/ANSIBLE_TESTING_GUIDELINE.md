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
./docker-run.sh playbooks/site.yml --syntax-check

# 2. ansible-lint 정적 검사 (베스트 프랙티스 & 안티패턴 검사)
./docker-run.sh ansible-lint
```

---

## 3. Layer 2: 사전 시뮬레이션 (Dry-Run / Diff)

실제 서버에 접속하여 아무것도 변경하지 않고(Dry-Run), 변경될 설정 파일의 차이점(`diff`)을 사전에 점검합니다.

```bash
# 특정 대상 노드 대상 Dry-Run 시뮬레이션
./docker-run.sh playbooks/site.yml -k -K --limit ns0333.nanoit.kr --check --diff
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

### 2) Molecule 실행 명령어 (3개 티어, ADR-0007)

| 티어 | 명령 | 범위 | 언제 |
|---|---|---|---|
| **Fast Scenario** | `make test-fast` | `common`(Base Layer) + `security` + `access_security`, Rocky 9 (`roles/security`·`roles/common` 변경 시 Rocky 8 추가), idempotence 포함 | pre-push |
| **Slow Scenario** | `make test-slow` | `docker_engine` + `monitoring` 실제 설치, 3개 OS | 수동/CI |
| **Full Matrix** | `make test-full` | fast + slow, 3개 OS | **릴리스 전 필수** |
| 단일 role | `make test-role ROLE=security` | 해당 role + `common`, Rocky 9 | 개발 중 |

```bash
make test-images                          # 테스트 이미지 빌드/갱신 (Dockerfile 해시가 바뀔 때만 재빌드, FORCE=1 강제)
make test-role ROLE=security              # 개발 루프
MOLECULE_SKIP_IDEMPOTENCE=1 make test-role ROLE=security   # 더 빠른 반복(멱등성 검증 생략, 명시적 opt-in)

# 단계별 디버깅 (컨테이너 유지). 시나리오는 -s fast | slow, 인스턴스는 <시나리오>-<OS>
molecule create   -s fast -p fast-rockylinux9
molecule converge -s fast
molecule idempotence -s fast
molecule verify   -s fast
molecule login    -s fast --host fast-rockylinux9
molecule destroy  -s fast
```

- 실행 시간은 `ansible.posix.profile_tasks`로 태스크별 기록됩니다(`molecule.yml`의 `ANSIBLE_CALLBACKS_ENABLED`).
- 고정 인스턴스 이름(`fast-*`, `slow-*`)은 시나리오별로 분리되어 있어 동시에 띄워도 충돌하지 않습니다.
- 패키지 캐시는 named volume(`infra-test-cache-*`)에 유지됩니다. 초기화: `docker volume rm $(docker volume ls -q -f name=infra-test-cache)`.

---

### 3) Molecule 시나리오 구성 파일

- `molecule/fast/`, `molecule/slow/`: 시나리오별 `molecule.yml`(플랫폼·역할 목록)과 `verify.yml`(단언).
- `molecule/shared/`: 두 시나리오가 공유하는 `converge.yml`(Base Layer 선적용 + `MOLECULE_ROLES` 선택), `prepare.yml`(매 실행마다 새로 필요한 상태만), `group_vars/all.yml`(fixture), `files/collect_facts.py`.
- `molecule/images/*.Dockerfile`: Test Image. 실행마다 반복되던 준비(openssh-server, 호스트 키, Rocky 8의 python3.11)만 굽습니다. **role이 설치하는 패키지와 [PREPARE-004]의 삭제 시나리오 시드는 굽지 않습니다** (설치 경로와 COMMON-013/023 검증을 보존하기 위해).
- `verify.yml`은 `collect_facts.py`로 사실을 **한 번의 원격 실행**으로 수집하고 `assert`는 컨트롤러에서 평가합니다. `[VERIFY-*]` ID는 유지되며 3-Way 검증기는 `molecule/*/verify.yml` 합집합을 검사합니다.

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
   ./docker-run.sh playbooks/site.yml -k -K --limit ns0333.nanoit.kr
   ```
2. **2단계 (실서버 접속 및 동작 검증)**:
   - 신규 관리자 계정 로그인 테스트: `ssh infra-admin@<IP>`
   - OTel 에이전트 서비스 상태 점검: `systemctl status otelcol-contrib`
   - 타임 동기화 상태 점검: `chronyc sources -v`

3. **3단계 (전체 그룹 롤링 배포)**:
   - 카나리 노드 검증 완료 후 전체 그룹으로 확장 (`--limit compute_nodes` 등)
