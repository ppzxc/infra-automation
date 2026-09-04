# 4. Evaluation and Adoption Strategy for Security Hardening Frameworks (`dev-sec` & `ansible-lockdown`)

- **Status**: Accepted
- **Date**: 2026-09-03
- **Deciders**: Overseer Engineering Team & User
- **Context**: On-Premise Target Server Security Baseline & CIS Compliance Strategy

---

## 1. Context & Problem Statement

`node-provisioner` 환경에서 대상 서버(Target Nodes)의 보안 강화를 위해 오픈소스 보안 하드닝 프레임워크인 **`dev-sec/ansible-collection-hardening`** 및 **`ansible-lockdown`**의 도입 타당성을 검토하였습니다.

현재 인프라 환경은 다음과 같은 특수한 기술적 제약과 아키텍처 요구사항을 가지고 있습니다:
1. **다세대 OS 지원 및 EOL 레거시 호환성**:
   - CentOS 6 레거시부터 CentOS 7, Rocky Linux 8/9/10, Ubuntu/Debian까지 광범위한 리눅스 배포판을 프로비저닝.
2. **Zero-Trust 컨트롤 플레인 연동 (`access_security`)**:
   - OpenBao SSH CA 기반 단기 인증서 신뢰(`TrustedUserCAKeys`), `AuthorizedPrincipalsFile`, HashiCorp Boundary Target 메타데이터 통합.
3. **엄격한 3-Way 명세 추적 체계 (`validate-ansible-specs.py`)**:
   - `docs/*.md` 스펙 테이블, `roles/*/tasks/main.yml`의 `[SPEC-ID]`, `molecule/default/verify.yml` 간의 1:1 일관성 및 무결성 강제.
4. **서비스 무중단 및 Docker 브리지 네트워크 보존**:
   - 무분별한 방화벽 초기화나 SELinux Enforcing 강제 시 Docker 컨테이너 패킷 포워딩 및 자동화 파이프라인 차단 위험 존재.

---

## 2. Framework Comparison & Evaluation

| 평가 항목 | `dev-sec/ansible-collection-hardening` | `ansible-lockdown` (MindPoint Group) |
|---|---|---|
| **표준 룰셋** | DevSec Security Baseline (범용 리눅스) | 공식 CIS Benchmark / DISA STIG (OS별 1:1) |
| **태스크 규모** | 20 ~ 50개 (모듈식 경량화) | 200 ~ 500개 (극도로 엄격한 벤치마크) |
| **CentOS 6 지원** | 불가 (Python 3/최신 문법 의존) | 불가 (RHEL 7/8/9/10, Ubuntu 등으로 분리) |
| **감사 전용 모드** | 지원 미흡 (즉시 Remediation 적용) | **완벽 지원 (`*_cis_audit_only: true`)** |
| **OpenSSH 통합** | 전체 템플릿 덮어쓰기로 SSH CA와 충돌 | 세부 룰 단위 비활성화 스위치 제공 |
| **평가 결과** | **전체 도입 비권장 (우수 룰 선별 흡수)** | **Rocky 9 한정 Audit-only 파일럿 도입 채택** |

---

## 3. Decision Outcomes (결정 사항)

1. **독립적 CIS 감사 파일럿 채택 (`ansible-lockdown.rhel9_cis`)**:
   - Rocky Linux 9 노드를 대상으로 시스템 변경 없이 취약점을 진단하는 **감사 전용 모드(`rhel9_cis_audit_only: true`)** 플레이북(`playbooks/audit_rhel9_cis.yml`)을 구성합니다.
   - 기존 무인 프로비저닝 메인 플로우(`playbooks/provision_hosts.yml`, `site.yml`)와 철저히 분리하여 운영 안정성을 보장합니다.

2. **기존 역할(Security, Common) 중심의 우수 룰 내재화**:
   - `dev-sec` 및 CIS 벤치마크 중 운영 영향도가 없고 보안성을 증대시키는 안전한 커널 파라미터(`fs.protected_hardlinks`, `fs.protected_symlinks`, `kernel.randomize_va_space`)를 `roles/common/defaults/main.yml`에 선별 반영합니다.
   - 3-Way Spec 추적 체계(`validate-ansible-specs.py`)를 준수하여 자체 보안 역할을 고도화합니다.

3. **향후 점진적 치유 (Remediation) 로드맵**:
   - Phase 1: Rocky 9 대상 `ansible-lockdown` Audit 리포트 수집 및 갭(Gap) 분석.
   - Phase 2: 안전성이 확인된 항목을 화이트리스트화하여 선별 Remediation 태그 실행.
