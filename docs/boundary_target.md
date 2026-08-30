# Boundary Target Role Task Specification

`boundary_target` 역할은 HashiCorp Boundary Zero-Trust 접근 제어 환경에서 타겟 노드의 메타데이터 및 연결 환경을 구성합니다.

---

## 1. 개요 및 구현 기능 (What)

- **타겟 메타데이터 디렉토리 생성**: `/etc/boundary-target` 경로 생성 및 권한 설정.
- **노드 식별 정보(Node Info) 등록**: 호스트명, 관리 IP, 서비스 태그, 노드 역할을 JSON 메타데이터(`/etc/boundary-target/node_info.json`)로 기록하여 관리.
- **조건부 활성화 제어**: `boundary_target_enabled` 변수 플래그를 통해 Boundary 타겟 등록 여부를 노드별/그룹별로 유연하게 제어.

---

## 2. 왜 구현해야 하는가? (Why)

1. **경계선 없는 Zero-Trust 네트워크 접근 (ZTNA)**:
   - 엔지니어에게 온프레미스 인프라의 실제 IP나 서브넷을 VPN 형태로 직접 노출하지 않고, Boundary 프록시 세션을 통해서만 접근을 허용합니다.
2. **동적 인벤토리 및 타겟 상태 식별**:
   - 노드 내부에 표준화된 메타데이터를 유지함으로써, 중앙 컨트롤 플레인 또는 자동화 도구가 노드의 역할과 연결 속성을 일관되게 인식할 수 있습니다.
3. **접근 세션 격리 및 감사**:
   - 신원(IAM) 기반 세션 인가를 거친 사용자만 타겟에 접속할 수 있도록 보장합니다.

---

## 3. 무엇을 변경하는가? (What Changes)

- 📁 **설정 파일 및 디렉토리**:
  - `/etc/boundary-target/` : 메타데이터 디렉토리
  - `/etc/boundary-target/node_info.json` : 노드 식별자, 호스트명, IP, 태그 정보 파일

---

## 4. 태스크 매트릭스 (Task Matrix)

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `BND-001` | `Skip Boundary Target if disabled` | `ansible.builtin.debug` | All | `when` 조건부 스킵 |
| `BND-002` | `Create Boundary target metadata directory` | `ansible.builtin.file` | All | 디렉토리 존재 시 `ok` |
| `BND-003` | `Write Boundary Target Node Info` | `ansible.builtin.copy` | All | 메타데이터 파일 생성 및 갱신 |
