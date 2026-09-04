# Node Provisioner Project Rules & Guidelines

이 문서는 `node-provisioner` 프로젝트의 프로덕션 운영 표준, 아키텍처 원칙, 멱등성 및 보안 규칙을 정의합니다. Antigravity 및 모든 작업자는 다음 가이드라인을 엄격히 준수해야 합니다.

---

## 1. 표준 디렉터리 아키텍처
Ansible과 Semaphore UI는 저장소 루트(`cwd`)를 기준으로 동작하므로 계층적 격리를 유지합니다:
- `ansible.cfg`: 전역 런타임 최적화 (`roles_path`, `collections_path`, fact caching 등).
- `requirements.yml`: Ansible Galaxy 외부 롤 및 컬렉션 의존성 정의.
- `inventory/`: 환경별 인벤토리 및 `group_vars/`, `host_vars/` 분리.
- `playbooks/`: 목적별 오케스트레이션 진입점 (`site.yml`, `provision_hosts.yml`, `maintenance.yml` 등).
- `roles/`: 단일 책임 원칙(SRP) 기반 모듈화.

## 2. 역할(Role) 구성 및 변수 우선순위 표준
- `defaults/main.yml`: [우선순위 낮음] 사용자가 덮어쓸 수 있는 가변 기본값 (버전, 포트, 옵션 등).
- `vars/main.yml`: [우선순위 높음] 외부 변경을 금지하는 내부 고정 상수 (OS별 패키지 종속성, 아키텍처 매핑 등).
- `handlers/main.yml`: 데몬 재기동은 작업마다 `systemd` 모듈을 직접 호출하지 않고 반드시 `notify: Restart <service>` 핸들러로 위임하여 불필요한 다중 재기동을 방지.

## 3. 멱등성(Idempotency) 및 코드 작성 규칙
1. **FQCN (Fully Qualified Collection Name) 강제**
   - 모든 태스크 모듈은 완전한 네임스페이스를 명시합니다 (예: `ansible.builtin.copy`, `ansible.posix.sysctl`, `community.docker.docker_image`).
2. **`shell` / `command` 모듈 제어 조건 필수**
   - 전용 모듈(`get_url`, `unarchive` 등)을 우선 사용하고, `shell`/`command` 사용 시 반드시 `creates`, `removes`, `changed_when`, `failed_when` 중 적절한 제어 조건을 선언하여 멱등성을 보장합니다.
3. **명시적 권한 설정 (mode, owner, group)**
   - 파일 및 디렉터리 생성/복사 시 시스템 umask에 의존하지 않고 4자리 8진수(`mode: '0644'`, `mode: '0755'`, `mode: '0600'`)로 명시합니다.

## 4. 보안 및 시크릿(Secret) 관리
1. **Git 무결성 및 평문 시크릿 커밋 금지**
   - Private Key, Passwords, S3 Secret Key, Tokens(OpenBao/Vault/GitHub)는 절대로 Git에 커밋하지 않습니다.
   - 시크릿은 Semaphore UI의 Environment(-e) 주입 또는 OpenBao/Vault lookup 플러그인을 활용합니다.
2. **권한 최소화**
   - 민감한 설정/키 파일은 반드시 `mode: '0600'` 이하로 제한합니다.

## 5. 품질 검증 및 린팅 (CI & Pre-Commit)
1. **Git Pre-Commit Hook 필수 준수**
   - 커밋 전 시크릿 유출 검사, 3-Way Spec 검증(`scripts/validate-ansible-specs.py`), 단위 테스트(`pytest tests/`)를 통과해야 합니다.
2. **3-Way 명세 추적성 유지**
   - 신규 태스크나 역할 변경 시 `docs/*.md` 스펙 테이블과 `roles/*/tasks/main.yml`의 `[SPEC-ID]`, `molecule/default/verify.yml` 검증 테스트를 항상 1:1로 일치시킵니다.
