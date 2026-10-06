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

### (1) 호스트별 개별 접속 정보
* **원칙**: 정적 인벤토리(Semaphore UI 및 `inventory/hosts.yml`)에는 관리번호(호스트명, 예: `ns0332`)만 전달되며, 실제 연결 대상 IP(`ansible_host`) 및 SSH 포트(`ansible_port`)는 OpenBao KV에서 동적으로 로딩하여 바인딩합니다.
* **네임스페이스**: `infra/prod/host/` (Semaphore UI `VAULT_NAMESPACE` 주입)
* **경로**: `secret/data/hosts/<inventory_hostname>` (예: `secret/data/hosts/ns0266`, `secret/data/hosts/ns0332`)
* **필드 (Key-Value)** (플랫 오브젝트, 호스트명 키 중첩, 또는 배열 포맷 지원):
  ```json
  {
    "ansible_host": "39.116.31.40",
    "ansible_port": 22,
    "ansible_python_interpreter": "auto_silent"
  }
  ```
  또는 `public_ip` (IDC 기본 호스트 메타데이터 포맷) / `ip` 필드 사용:
  ```json
  {
    "hostname": "ns0332",
    "domain": "nanoit.kr",
    "fqdn": "ns0332.nanoit.kr",
    "public_ip": "39.116.31.40",
    "ssh_user": "ppzxc"
  }
  ```
  > `ssh_user`는 IDC 메타데이터 필드로 **플레이북이 읽지 않습니다**(기존 호스트의 동작이 바뀌지 않도록 의도적으로 무시). 접속 계정을 바꾸려면 아래 `admin_users`를 사용하세요.

  **관리 IP (`ip` 변수)**: Host Agents가 로그·메트릭의 `host.ip`로 쓰는 값입니다(ADR-0006 §2.3). 우선순위는 **인벤토리 `ip` > 호스트 KV `ip` > 호스트 KV `public_ip`** 이며, 접속 주소(`ansible_host`)와 별개로 관리 IP를 따로 선언하려면 KV `ip`를 쓰세요. 셋 다 없거나 IP 형식이 아니면 `host.ip`만 생략하고 WARN(`MON-038`)합니다.

  **호스트별 접속 사용자 선택 (선택 필드)**: 해당 호스트에서만 실행 변수를 덮어씁니다. 필드가 없으면 기존 동작(실행 변수 `target_admin_users` / `bootstrap_user`, 기본값 `root`)을 그대로 따릅니다.
  ```json
  {
    "ansible_host": "39.116.31.40",
    "admin_users": ["svcadm", "ppzxc"],
    "bootstrap_user": "centos"
  }
  ```
  * `admin_users`: 이 호스트의 관리자 목록(문자열 1개도 허용). **첫 번째 항목이 SSH 접속 계정**이 되며, 목록 전체가 `common` 역할의 `accounts`로 프로비저닝됩니다. 각 사용자의 자격증명은 `users/<user>`에서 조회합니다.
  * `bootstrap_user`: 이 호스트의 부트스트랩(최초 접속) 계정.
  * 우선순위: **호스트 KV > 실행 변수 > 기본값**. 어느 쪽에서도 관리자를 결정할 수 없으면 해당 호스트만 실패합니다.

  또는 호스트명 키 래핑 사용:
  ```json
  {
    "ns0332": {
      "ip": "39.116.31.40",
      "port": 22
    }
  }
  ```

  **호스트별 사용자 자격증명 재정의 (선택 필드, #26)**: `hosts/<hostname>` 자체가 아니라
  `secret/data/hosts/<inventory_hostname>/users/<username>`에 **평면(flat) 오브젝트**로 둡니다
  (`(2) 사용자 계정 자격증명`의 배열 포맷과 다릅니다). 인식하는 필드는 두 그룹으로 나뉩니다:
  - **자격증명 4개** (`ssh_private_key`, `ssh_passphrase`, `password`, `ssh_public_key`): **존재하는
    키만** 전역 `users/<username>` 값 위에 덮어씁니다 — 값이 비어 있어도 "존재"로 취급되므로,
    예를 들어 호스트가 평문 키로 교체되어 `ssh_passphrase: ""`를 명시하면 상속된 전역 passphrase를
    지우는 것으로 처리됩니다(전역 키를 잘못된 passphrase로 복호화 시도하지 않음). 전역
    `users/<username>` 자체가 없는(404) 신규 계정이라도 호스트 재정의만으로 적용됩니다.
  - **`revoked_keys`** (별도 취급, 아래 참고): 전역 값과 **항상 합집합**이며 존재 기준 덮어쓰기가
    아닙니다.
  ```json
  {
    "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
    "ssh_passphrase": "",
    "password": "HostSpecificPassword123!",
    "ssh_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...",
    "revoked_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... old@laptop"]
  }
  ```
  * 부트스트랩 계정(`bootstrap_user`)의 접속 비밀번호에도 같은 재정의가 적용됩니다. 단, 조회 대상은
    `admin_users`로 해석된 사용자이므로 부트스트랩 계정이 `admin_users`에 없으면 재정의는 조회되지 않습니다.
  * `common` 역할은 접속(primary) 사용자에게만 `ssh_private_key`/`ssh_passphrase`/`password`를
    실제로 사용합니다(SSH 연결·sudo 자격증명). `accounts`로만 프로비저닝되는 나머지 사용자는
    로컬 계정 자체에 비밀번호를 두지 않으므로, 의미 있게 반영되는 필드는 `ssh_public_key`와
    `revoked_keys`뿐입니다 — 그 외 사용자에 대한 `ssh_private_key`/`ssh_passphrase`/`password`
    재정의는 저장은 되지만 아무 곳에도 쓰이지 않습니다.
  * 조회는 `admin_users`로 해석된 사용자 전원(접속 계정 + `accounts`로 프로비저닝되는 나머지)에 대해
    호스트마다 반복되므로, OpenBao 조회 횟수가 호스트 × 사용자 수만큼 늘어납니다(허용된 비용).
  * `secret/` 폴백 없이 404는 정상(해당 호스트에 재정의가 없음)으로 처리합니다. AppRole/Token
    정책에 `hosts/+/users/*` 읽기 권한이 없어 403이 발생하면, 해당 사용자의 호스트별 재정의와
    `revoked_keys`가 조용히 적용되지 않으므로 플레이북 출력의 `[WARN]` 메시지로 확인하세요.
  * `revoked_keys`는 예외적으로 **항상 전역 값과 합집합**입니다(호스트가 이 필드로 전역 폐기를
    되살릴 수 없음). 실제로 배포하지 않는 판정(키가 `revoked_keys`와 겹치면 배포 생략)은
    `common` 역할(COMMON-015) 한 곳에서만 이뤄집니다.

  **명시적 계정 삭제 및 키 폐기 (선택 필드, #26, ISMS 2.5.1 증적)**:
  ```json
  {
    "removed_users": ["legacy-hand-made-account"]
  }
  ```
  * `removed_users`: 이 호스트에서 `common` 역할이 `state: absent`로 제거할 계정 목록(문자열
    1개도 허용). 실행 변수 `target_removed_users`(문자열/리스트/JSON 문자열 배열 모두 허용)와
    **합집합**으로 통합되며, `admin_users`에서 자동으로 빠지는 계정은 없습니다(삭제는 항상 명시).
    지원 형태는 문자열(콤마로 여러 개 구분 가능)과 리스트/JSON 배열 문자열뿐입니다. mapping(객체)
    형태로 오면 전부 무시되고 `[WARN]` 메시지가 남습니다(키 이름이 계정명으로 오인되는 것을
    막기 위함이며, 리스트 안의 문자열이 아닌 원소도 조용히 걸러집니다).
  * **안전장치**: `removed_users`가 접속 계정, 부트스트랩 계정(호스트별 override 포함), 또는
    이번 실행에서 선언된 `admin_users`와 겹치면 SSH 프로브 성공 여부와 무관하게 그 호스트만
    결정적으로 실패합니다(`REMOVED-USER-CONFLICT`).
  * **증적**: 매 실행마다 호스트 KV/실행 변수 각각에서 온 목록과 최종 합집합을 debug로 남깁니다
    (`Log accounts resolved for removal (ISMS 2.5.1 evidence)`).
  * `accounts[].revoked_keys`(전역 `users/<user>` 또는 호스트별 재정의에서 합집합)에 나열된
    공개키는 `common` 역할이 `authorized_key: state: absent`로 제거합니다(`exclusive`는 사용하지
    않으므로 수동으로 추가된 다른 키는 보존됩니다). 배포하려는 키와 폐기 목록이 겹치면 배포되지
    않습니다(타입+본문 비교, 주석/개행 차이는 무시).

### (2) 사용자 계정 자격증명 (Users)
* **경로**: `secret/data/users/<username>` (예: `secret/data/users/ppzxc`, `secret/data/users/root`)
* **SSH 자격증명 포맷 (JSON Array)**:
  ```json
  [
    {
      "ssh_passphrase": "",
      "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
      "ssh_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...",
      "type": "SSH",
      "username": "ppzxc"
    }
  ]
  ```
* **패스워드 자격증명 포맷 (JSON Array, root 등 부트스트랩 계정)**:
  ```json
  [
    {
      "password": "InitialRootPassword123!",
      "type": "PASSWORD",
      "username": "root"
    }
  ]
  ```

### (3) 부트스트랩 접속 및 관리자 자동 폴백 메커니즘
* `target_admin_users`와 `bootstrap_user`는 실행 단위 기본값입니다. 호스트 KV(`hosts/<hostname>`)의 `admin_users` / `bootstrap_user`가 있으면 그 호스트에서는 KV 값이 우선합니다 ([(1) 호스트별 개별 접속 정보](#1-호스트별-개별-접속-정보) 참고). `target_admin_users`는 모든 대상 호스트의 KV에 `admin_users`가 있을 때만 생략할 수 있습니다.
* **1차 시도 (관리자 접속)**: OpenBao `users/<target_admin_user>`의 SSH Private Key로 타겟 호스트 접속을 시도합니다. 성공 시 이미 프로비저닝된 상태로 판단하여 해당 키로 플레이북을 실행합니다.
* **2차 시도 (부트스트랩 폴백)**: 관리자 SSH 연결 실패 시 신규 호스트로 판단, OpenBao `users/<bootstrap_user>`에서 패스워드/키를 취득하여 `ansible_user=bootstrap_user`로 자동 폴백 접속 후 프로비저닝을 수행합니다. 프로비저닝이 완료되면 `root` 원격 접속은 차단되고 등록된 관리자 계정만 유지됩니다.

### (4) Cisco 스위치별 접속 정보 및 자격증명
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


### (5) 전역 인프라 서비스 시크릿
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
Semaphore UI의 **Environment / Variable Groups**에 Ansible 및 `community.hashi_vault` lookup을 위한 환경변수와 Extra Variables를 등록합니다:

* **Environment variables (환경 변수)**:
  ```json
  {
    "VAULT_ADDR": "https://openbao.internal:8200",
    "VAULT_NAMESPACE": "root",
    "OPENBAO_CISCO_PREFIX": "switches/",
    "VAULT_SKIP_VERIFY": "false"
  }
  ```
* **Extra variables (추가 변수)**:
  ```json
  {
    "cisco_backup_dir": "/opt/backups/cisco",
    "openbao_cisco_prefix": "switches/"
  }
  ```
* **Secrets (보안 변수 - AppRole 인증 시)**:
  - `VAULT_ROLE_ID`: OpenBao AppRole Role ID
  - `VAULT_SECRET_ID`: OpenBao AppRole Secret ID

---

## 4. 로컬 및 CI 하이브리드 지원 동작 원리

`inventory/group_vars/all.yml`에 다음과 같은 3중 안전 폴백이 구성되어 있습니다:

```yaml
# 1. 로컬 환경: _local_* 변수 또는 로컬 git 미추적 yml에 변수가 있으면 로컬 값 사용
# 2. Semaphore 환경: 로컬 변수가 없고 VAULT_ADDR가 주입되어 있으면 OpenBao 조회
# 3. 개발/테스트 환경: OpenBao가 없거나 미설정 시에도 에러 없이 기본값(default/omit)으로 안전 폴백
```

이 설계를 통해 개발자는 로컬 머신에서 별도의 Vault 서버 없이도 작업을 진행할 수 있으며, Semaphore UI에서는 완전한 중앙 집중식 시크릿 격리가 이루어집니다.

---

## 5. 신규 플레이북 작성을 위한 재사용 연결 모듈 (`common/resolve_connection.yml`)

모든 신규 플레이북에서 복잡한 OpenBao 자격증명 조회, SSH 키 복호화, 지능형 접속 진단(Probe), 부트스트랩 폴백 로직을 중복 구현할 필요 없이 `playbooks/common/` 모듈을 `ansible.builtin.import_playbook`으로 재사용할 수 있습니다.

### (1) 제공되는 공통 모듈
1. `playbooks/common/resolve_connection.yml`:
   - OpenBao AppRole / Token 자동 인증 및 Health 체크
   - 대상 호스트 IP / Port KV 메타데이터 자동 바인딩
   - 관리자 SSH Private Key 복호화(Passphrase 해제) 및 임시 파일화
   - 대상 호스트 SSH 사전 진단(Probe) 및 미프로비저닝 시 부트스트랩 자동 폴백
   - 원격 Python 인터프리터 자동 탐색 (`ansible_python_interpreter: auto_silent`) 강제
2. `playbooks/common/cleanup_connection.yml`:
   - 컨트롤러에 임시 생성된 SSH 키 파일 안전 제거

### (2) 신규 플레이북 작성 표준 템플릿 (참고 예제: `playbooks/example_task.yml`)

저장소 내 [playbooks/example_task.yml](file:///home/ppzxc/projects/infra-automation/playbooks/example_task.yml) 파일이 바로 복사/참고하여 사용할 수 있는 공식 템플릿입니다.

```yaml
---
# 1. OpenBao 자격증명 및 서버 접속 연결 사전 해결
- name: Resolve OpenBao Connection and Credentials
  ansible.builtin.import_playbook: common/resolve_connection.yml

# 2. 본 작업 플레이 (임의의 작업 수행)
- name: Execute Custom Host Tasks
  hosts: "{{ target_hosts | default('servers:loadbalancers') }}"
  become: true
  gather_facts: true
  tasks:
    - name: Run custom commands or maintenance tasks
      ansible.builtin.command: uname -a
      register: _result
      changed_when: false

    - name: Print host status
      ansible.builtin.debug:
        msg: "Connected successfully to {{ inventory_hostname }}: {{ _result.stdout }}"

# 3. 컨트롤러 임시 키 정리
- name: Cleanup Controller Temporary Credentials
  ansible.builtin.import_playbook: common/cleanup_connection.yml
```

### (3) 특정 호스트만 지정하여 실행 (Semaphore Task Template)
Semaphore UI 또는 CLI 실행 시 Extra Variable로 `target_hosts`를 지정하여 특정 단일 호스트 또는 그룹만 필터링하여 실행할 수 있습니다:
```bash
ansible-playbook -i inventory/hosts.yml playbooks/example_task.yml -e "target_hosts=ns0332"
```

