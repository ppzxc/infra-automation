# OpenBao & Semaphore UI Secret Management Integration Guide

본 문서는 **Semaphore UI** 최신 버전과 **OpenBao**(HashiCorp Vault 호환 Secret Manager)를 연동하여 대상 노드 프로비저닝 시크릿을 안전하게 주입하고 관리하는 표준 아키텍처 및 설정 가이드입니다.

---

## 1. 아키텍처 개요 (Architecture Overview)

```mermaid
flowchart TD
    subgraph ExecutionContext["실행 환경 (Execution Context)"]
        Local["🖥️ 로컬 실행 (ansible-playbook CLI)"]
        Semaphore["🚀 Semaphore UI Task Runner"]
    end

    subgraph SecretSources["시크릿 저장소"]
        LocalYAML["📄 로컬 Git 미추적 YAML (host_vars / group_vars)"]
        OpenBaoKV["🔐 OpenBao KV v2 (secret/data/...)"]
    end

    subgraph AnsibleResolution["Ansible 런타임 변수 해석 (Hybrid Fallback)"]
        Priority1["1순위: 로컬 명시 변수 (_local_*)"]
        Priority2["2순위: OpenBao KV v2 (community.hashi_vault lookup)"]
        Priority3["3순위: Defaults / omit 안전 폴백"]
    end

    subgraph Targets["대상 노드 및 파이프라인"]
        SSHConn["🔑 SSH 연결 (ansible_user / ansible_password / ansible_become_password)"]
        Services["🛡️ 서비스 토큰 (otel_auth_header / openbao_ssh_ca_public_key)"]
    end

    Local -->|로컬 파일 우선| LocalYAML --> Priority1 --> Targets
    Semaphore -->|VAULT_ADDR / VAULT_TOKEN 주입| OpenBaoKV --> Priority2 --> Targets
    Priority1 -.->|미정의 시| Priority2
    Priority2 -.->|미정의 시| Priority3
```

---

## 2. OpenBao KV v2 Secret Path 표준 명세

OpenBao의 `secret/` (KV v2) 마운트 아래에 다음과 같이 경로와 키를 배치합니다:

### (1) 노드별 개별 접속 자격증명
* **경로**: `secret/data/nodes/<inventory_hostname>` (예: `secret/data/nodes/web-01.idc.internal`, `secret/data/nodes/ns0278`)
* **서버 노드 필드 (Key-Value)**:
  ```json
  {
    "ansible_user": "ppzxc",
    "ansible_password": "HostSpecificSecretPassword123!",
    "ansible_become_password": "SudoPasswordIfDifferentOrSame",
    "ansible_port": 22
  }
  ```
### (2) Cisco 스위치별 접속 정보 및 자격증명
* **경로**: `secret/data/switches/<inventory_hostname>` (예: `secret/data/switches/ns0000`, `secret/data/switches/ns0278`)
* **변수 해석 우선순위**: OpenBao KV v2 최우선 ➔ 인벤토리/로컬 변수 폴백 ➔ 시스템 기본값
* **필드 (Key-Value) - SSH 스위치**:
  ```json
  {
    "ansible_host": "211.210.44.182",
    "ansible_port": 22,
    "ansible_user": "ansible-backup",
    "ansible_password": "SwitchSecretPassword123!",
    "connection_type": "ssh",
    "fqdn": "ns0278.nanoit.kr"
  }
  ```
* **필드 (Key-Value) - Telnet 스위치 (예: `ns0000`, 무암호 허용)**:
  ```json
  {
    "ansible_host": "218.54.219.82",
    "ansible_port": "23",
    "ansible_user": "ansible-backup",
    "ansible_password": "",
    "connection_type": "telnet",
    "fqdn": "ns0065.nanoit.kr"
  }
  ```
* **Bastion 경유 장비 필드 추가 (예: `ns0279`)**:
  ```json
  {
    "ansible_host": "10.10.200.4",
    "ansible_port": 22,
    "ansible_user": "ansible-backup",
    "ansible_password": "SwitchSecretPassword123!",
    "connection_type": "jump_ssh",
    "bastion_host": "ns0278",
    "fqdn": "ns0279.nanoit.kr"
  }
  ```


### (3) 전역 인프라 서비스 시크릿
* **경로**: `secret/data/global/services`
* **필드 (Key-Value)**:

  ```json
  {
    "openbao_ssh_ca_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... openbao-ca@internal",
    "otel_auth_header": "Bearer gls_secret_otlp_token_here",
    "boundary_token": "s.boundary_worker_auth_token"
  }
  ```

---

## 3. Semaphore UI 최신 버전 연동 가이드

Semaphore UI 최신 버전은 **OpenBao** 및 **HashiCorp Vault**를 일급 시민(First-Class) 스토리지 백엔드로 지원합니다.

### 1단계: Semaphore Settings에서 OpenBao Storage 설정
1. Semaphore UI 대시보드 진입 ➔ **Settings** ➔ **Secrets / Key Store**
2. **Storage Type**을 `OpenBao` 또는 `HashiCorp Vault`로 지정
3. OpenBao Server URL (`https://openbao.internal:8200`), Mount Path (`secret`), Token 또는 Vault Agent 토큰 파일 경로(`/var/run/openbao/token`) 설정

### 2단계: Key Store 등록
* **Type**: `OpenBao`
* **Path**: `secret/data/semaphore/ssh_key` 또는 `secret/data/semaphore/sudo_pass`
* Semaphore가 태스크 실행 시 OpenBao로부터 인증서를 실시간으로 취득하여 Runner에 주입합니다.

### 3단계: Environment (Variable Group) 구성
Semaphore UI의 **Environment**에 Ansible 및 `community.hashi_vault` lookup을 위한 환경변수를 등록합니다:

```json
{
  "VAULT_ADDR": "https://openbao.internal:8200",
  "VAULT_SKIP_VERIFY": "false",
  "VAULT_AUTH_METHOD": "token",
  "VAULT_TOKEN": "{{ vault_runner_token }}"
}
```

---

## 4. 로컬 및 CI 하이브리드 지원 동작 원리

`inventory/group_vars/all.yml`에 다음과 같은 3중 안전 폴백이 구성되어 있습니다:

```yaml
# 1. 로컬 환경: _local_* 변수 또는 로컬 git 미추적 yml에 변수가 있으면 로컬 값 사용
# 2. Semaphore 환경: 로컬 변수가 없고 VAULT_ADDR가 주입되어 있으면 OpenBao 조회
# 3. 개발/테스트 환경: OpenBao가 없거나 미설정 시에도 에러 없이 기본값(default/omit)으로 안전 폴백
```

이 설계를 통해 개발자는 로컬 머신에서 별도의 Vault 서버 없이도 작업을 진행할 수 있으며, Semaphore UI에서는 완전한 중앙 집중식 시크릿 격리가 이루어집니다.
