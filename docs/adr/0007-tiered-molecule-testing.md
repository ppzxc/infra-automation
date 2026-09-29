# 7. Molecule 테스트를 3개 티어로 분리 (Fast / Slow / Full Matrix)

- **Status**: Accepted (구현 완료)
- **Date**: 2026-09-29

`molecule test` 한 번이 14분 걸려 pre-push가 사실상 개발 루프에서 쓸 수 없는 게이트였다. 원인은 시나리오 하나가 3개 플랫폼에 5개 role 전부를 적용하고(idempotence로 2회), 네트워크 의존 태스크(`docker_engine`, `monitoring`)와 매 실행 반복되는 컨테이너 준비(`prepare.yml`)를 매번 포함하기 때문이다. pre-push의 검증 범위를 좁히고 나머지는 Full Matrix로 옮기되, 멱등성 검증은 어떤 게이트에서도 빼지 않기로 했다.

## Decision

| 티어 | 범위 | 실행 위치 | 실측 시간 |
|---|---|---|---|
| **Fast Scenario** | `common`(Base Layer) + `security` + `access_security`, Representative Platform(Rocky 9), **idempotence 포함** | pre-push | **약 150초** (기준선 845초) |
| **Fast Scenario (넓은 실행)** | 위와 같되 `roles/security`·`roles/common` 변경 시 Rocky 8·9, Ubuntu 22.04를 **한 번의 실행**으로 | pre-push | **약 240초** |
| **Slow Scenario** | `docker_engine` + `monitoring` 실제 설치, 3개 OS, idempotence 포함 | 수동/CI | 약 300초 |
| **Full Matrix** | fast + slow, 3개 OS | 수동/릴리스 전 | fast 240 + slow 300 |
| 개발 루프 | `make test-role ROLE=…` (기본은 idempotence 포함, Rocky 9). `MOLECULE_SKIP_IDEMPOTENCE=1`이면 `dev` 시나리오로 멱등성 검증 생략 | 개발 중 | 기본 약 100초 / 생략 시 약 95초 |

- **멱등성은 어떤 게이트에서도 포기하지 않는다.** pre-push, Slow, Full Matrix 모두 idempotence 단계를 유지한다. 생략은 개발 루프에서 명시적으로 opt-in할 때만 가능하고 게이트가 될 수 없다.
- `common`은 항상 먼저 적용하고 나머지 role만 `MOLECULE_ROLES`로 선택한다(운영 적용 순서와 동일).
- 컨테이너 준비(SSH 서버, 호스트 키, Rocky 8의 python3.11)는 파생 **Test Image**(`molecule/images/`)에 굽고 Dockerfile 해시가 바뀔 때만 재빌드한다. role이 설치하는 패키지와 `[PREPARE-004]`(삭제 시나리오 시드)는 굽지 않는다. 굽는 순간 설치 경로와 `VERIFY-COMMON-013/023`이 아무것도 검증하지 않게 된다.
- 패키지 캐시는 named volume에 유지하고, molecule에 `ANSIBLE_PIPELINING`과 인터프리터 고정을 준다(프로젝트 `ansible.cfg`는 molecule이 상속하지 않는다).
- `verify.yml`은 `collect_facts.py`로 사실을 한 번의 원격 실행으로 수집하고 `assert`는 컨트롤러에서 평가한다(verify 65초 → 약 2~4초). `[VERIFY-*]` ID와 단언 의미는 그대로다.
- 넓은 실행 규칙: 변경 파일이 `roles/security/**` 또는 `roles/common/**`이면 pre-push가 3개 OS를 한 번에 돌린다. hosts가 lockstep으로 실행되어 Rocky 9 + Rocky 8을 순차로 돌리는 것(약 316초)보다 빠르고(약 240초) Ubuntu까지 덮는다.
- molecule 전에 `ansible-playbook --syntax-check`와 `ansible-lint`(설치된 경우)를 먼저 실행한다.
- `scripts/validate-ansible-specs.py`와 pytest는 `molecule/*/verify.yml` 합집합을 읽는다. 분할 전후 VERIFIED/INTEGRATED 분류가 동일함을 diff로 확인했다.
- 진입점: `make test-fast`, `test-slow`, `test-full`, `test-role ROLE=…`, `test-images`. CI는 이번 범위에서 도입하지 않았다.

## Consequences

- pre-push는 평소 Rocky 9만 검증하므로(`security`·`common` 변경 시에만 3개 OS) Ubuntu·Rocky 8 전용 분기 회귀와 Docker/otelcol 설치 회귀는 Full Matrix를 돌리기 전까지 잡히지 않을 수 있다. 릴리스 전 체크리스트에 `make test-full`을 명시해 커버리지가 조용히 사라지는 것을 막는다.
- Test Image는 로컬 빌드가 필요하고 낡을 수 있다. 해시 기반 자동 재빌드로 완화한다.
- **Docker Desktop(Windows)이 지속적인 `docker exec` 부하에서 멈춘다.** 이 저장소를 개발한 환경(WSL2 + Docker Desktop 4.87~4.93)에서 90초~10분 안에 백엔드가 정지하는 것을 재현했다. Defender, 버전(4.87.0에서도 발생), Resource Saver, 테스트 코드는 원인이 아니었고 근본 원인은 규명하지 못했다. molecule은 호스트 수 × 태스크 수만큼 `docker exec`를 보내므로 호스트 3대 실행이 가장 위험했다. 멈추면 `molecule destroy`를 포함한 모든 docker 호출이 응답하지 않아 pre-push가 최대 `RUN_TIMEOUT`(30분) 동안 막힌다. 그래서 `scripts/docker-guard.sh`가 실행 중 데몬을 주기적으로 확인하고, 연속 실패하면 프로세스 그룹을 종료한 뒤 종료 코드 125로 끝낸다(정리는 다음 실행의 초기 destroy가 맡는다). 원인 해결이 아니라 피해 제한이다.

## Considered Options

- **설치 태스크를 스텁으로 대체**: "실제로 설치되고 기동되는가"라는 핵심 회귀를 잃어 폐기.
- **로컬 미러/캐시 프록시**: 관리할 인프라가 하나 늘어 폐기.
- **현행 유지**: 14분 게이트가 개발 루프를 막아 폐기.
- **role당 시나리오 5개**: `access_security`가 `common`의 계정에 의존해 유지 비용이 커서 폐기. 대신 2개 시나리오 + role 선택.
