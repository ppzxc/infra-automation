# 2. On-Premise Docker Infrastructure Account, Directory Layout, and Permission Inheritance Standard

- **Status**: Accepted
- **Date**: 2026-08-27
- **Deciders**: Overseer Engineering Team & User
- **Context**: IDC On-Premise Docker Infrastructure Provisioning (Rocky Linux, Ubuntu/Debian)

---

## 1. Context & Problem Statement

IDC 온프레미스 인프라 환경에서 Docker 및 Compose 기반의 서비스(LibreNMS, OpenBao, PowerDNS, OpenObserve 등)를 운영할 때 다음과 같은 보안 및 운영상 문제점이 지속적으로 발생했습니다:

1. **권한 충돌 및 접근 통제 미흡**:
   - 컨테이너가 생성한 볼륨 데이터(DB, 로그, RRD 등)의 소유권이 `root` 또는 컨테이너 내부 임의 UID로 설정되어, 일반 운영 엔지니어가 `sudo` 없이 설정/로그/백업을 다룰 수 없거나 권한 오류(Permission Denied)가 발생함.
2. **UID/GID 충돌 및 FHS 비표준화**:
   - OS 설치 시 자동 생성되는 일반 유저(UID 1000)와 컨테이너 데몬 실행 전용 계정의 UID가 충돌하는 문제.
   - 설정 코드(Git 형상)와 가변 대용량 데이터(DB/RRD/스토리지), 백업 디렉터리가 무분별하게 혼재되는 문제.
3. **다양한 컨테이너 이미지의 권한 처리 파편화**:
   - LinuxServer 계열(`PUID`/`PGID` 환경변수 지원)과 공식 오픈소스 이미지(MariaDB, Postgres, Redis, OpenBao 등 고정 내부 UID `999`/`100` 사용) 간의 일관된 볼륨 공유 표준 부재.

---

## 2. Decision Outcomes (결정 사항)

### 2.1 계정 및 그룹 분리 아키텍처 (Least Privilege & System Reserved UID)

OS 기본 계정 충돌을 방지하기 위해 컨테이너 데몬 계정은 **시스템 예약 대역(System UID/GID)**을 사용하고, 운영 엔지니어는 **일반 유저 대역(UID >= 1000)**을 할당합니다.

| 구분 | 계정/그룹명 | UID / GID | 소속 그룹 | 역할 및 권한 범위 |
|---|---|---|---|---|
| **공유 관리 그룹** | `dockermgmt` | **GID: 2000** | - | `/opt/services`, `/data`, `/backup` 파일시스템 공동 접근 그룹 |
| **컨테이너 서비스 계정** | `dockersvc` | **UID: 998** (시스템 예약) | 주 그룹: `dockermgmt` | 컨테이너 프로세스 실행 소유자(PUID), 대화형 로그인 차단 (`/sbin/nologin`, 홈 없음) |
| **기본 운영자 계정** | `ppzxc` (확장 가능) | **UID: 1001** (또는 1000+) | 보조: `dockermgmt`, `docker`, `wheel`/`sudo` | SSH 로그인 엔지니어 (sudo 및 docker CLI 제어 권한, 홈에 심볼릭 링크 구성) |
| **도커 엔진 그룹** | `docker` | 기본 GID | - | `/var/run/docker.sock` 접근 및 도커 CLI 명령어 실행 권한 |

> **추가 운영자 지원**: 신규 엔지니어 추가 시 `ansible/inventory/group_vars/all.yml`의 `docker_operators` 목록에 계정을 등록하면 자동으로 `dockermgmt`, `docker`, `wheel`/`sudo` 그룹 및 홈 심볼릭 링크가 구성됩니다.

---

### 2.2 FHS 표준 디렉터리 레이아웃

리눅스 파일시스템 계층 표준(FHS)에 따라 **독립형 소프트웨어/설정 코드(`/opt/services`)**, **가변 영구 데이터(`/data`)**, **백업 아카이브(`/backup`)**를 물리적/논리적으로 명확히 분리합니다.

```text
/opt/services/                      # [설정 및 코드] Git 형상관리 대상 (용량 가벼움, 권한: 2775)
├── librenms/
│   ├── compose.yml
│   ├── .env                       # 시크릿 환경변수 (권한: 600)
│   └── config/                    # 커스텀 설정 파일 (syslog-ng.conf, custom.conf 등)
├── openbao/
│   └── compose.yml
└── powerdns/
    └── compose.yml

/data/                             # [영구 저장 데이터] DB, RRD, 스토리지 등 고속/대용량 영역 (권한: 2770)
├── librenms/
│   ├── db/                        # MariaDB/MySQL 데이터
│   └── core/                      # RRD 파일 및 플러그인
└── openbao/
    └── storage/

/backup/                           # [백업 영역] 별도 마운트 디스크 또는 NFS 경로 (권한: 2770)
├── db-dumps/                      # 일일 DB mysqldump/pg_dump 압축 파일
└── snapshots/                     # 볼륨 스냅샷 데이터
```

---

### 2.3 권한 상속 및 접근 제어 (SGID + POSIX Default ACL + Safe Umask)

컨테이너가 새로 생성하는 파일이나 운영자가 배포한 파일 모두 `dockermgmt` 그룹 쓰기 권한을 유지하도록 3단계 권한 상속을 표준화합니다:

1. **SGID (`2775` / `2770`)**: 하위 생성 파일/폴더에 `dockermgmt` 그룹 자동 상속.
2. **POSIX Default ACL**:
   ```bash
   setfacl -R -d -m g:dockermgmt:rwx /opt/services /data /backup
   setfacl -R -m g:dockermgmt:rwx /opt/services /data /backup
   ```
3. **운영자 전용 Umask (`/etc/profile.d/docker_mgmt.sh`)**:
   - 시스템 전역 umask(022)를 해치지 않으면서 `dockermgmt` 그룹 소속 사용자의 세션에서만 `umask 002`를 적용하여 ACL Mask 유실 방지:
   ```bash
   if id -nG "$USER" 2>/dev/null | grep -qw "dockermgmt"; then
       umask 002
   fi
   ```

---

### 2.4 컨테이너 이미지 유형별 권한 연동 표준

컨테이너 이미지의 특성에 따라 다음과 같이 이원화된 표준을 적용합니다:

1. **LinuxServer.io 및 PUID/PGID 지원 이미지**:
   - `.env`에 `PUID=998`, `PGID=2000` 주입하여 실행.
2. **공식 오픈소스 이미지 (MariaDB, PostgreSQL, OpenBao, Redis 등)**:
   - **원칙 1**: `user: "998:2000"`으로 안전하게 실행 가능한 이미지는 Compose에 `user` 파라미터 지정.
   - **원칙 2**: 내부 고정 UID(예: `mysql:999`, `postgres:999`, `vault:100`)로 실행해야 하는 공식 이미지는, 호스트의 해당 서비스 데이터 디렉터리에 POSIX ACL을 추가 부여하여 운영자 그룹(`dockermgmt`)과 컨테이너 데몬 간 읽기/쓰기를 양방향 보장:
     ```bash
     # 예: MariaDB(내부 UID 999)가 생성한 파일도 dockermgmt가 자유롭게 접근 가능하도록 ACL 설정
     setfacl -R -d -m u:999:rwx,g:2000:rwx /data/<service>/db
     setfacl -R -m u:999:rwx,g:2000:rwx /data/<service>/db
     ```

---

## 3. Architecture & Operational Flow

```mermaid
graph TD
    subgraph "Host OS Security & Filesystem"
        SvcUser["dockersvc (UID: 998, nologin)"]
        MgmtGroup["dockermgmt (GID: 2000)"]
        Operator["ppzxc / Operators (UID: 1001+, docker/dockermgmt)"]

        OptDir["/opt/services (2775, ACL g:dockermgmt:rwx)"]
        DataDir["/data (2770, ACL g:dockermgmt:rwx)"]
        BackupDir["/backup (2770, ACL g:dockermgmt:rwx)"]

        Operator -->|Symlink ~/services| OptDir
        Operator -->|Symlink ~/data| DataDir
        Operator -->|docker CLI (No Sudo)| DockerSock["/var/run/docker.sock"]
    end

    subgraph "Docker Compose Stacks"
        LSEnv["LinuxServer Stacks (PUID=998, PGID=2000)"]
        OfficialEnv["Official DB / Apps (UID: 999 / user: 998:2000)"]
    end

    LSEnv -->|Read / Write| OptDir
    LSEnv -->|Persistent Data| DataDir
    OfficialEnv -->|Persistent Data| DataDir
```

---

## 4. Consequences & Trade-offs

- **장점 (Pros)**:
  - **UID 충돌 제로**: 시스템 예약 대역(998)을 사용하여 OS 템플릿 설치 시 기본 생성되는 UID 1000과의 충돌 완전 제거.
  - **안전한 비루트 운영**: 운영 엔지니어는 `sudo` 없이도 `docker compose` 실행, 설정 수정, 볼륨 데이터/백업 조회 가능.
  - **감사 및 추적성**: 컨테이너 데몬과 개인 로그인 엔지니어의 계정이 물리적으로 분리되어 Audit 로그 추적 명확화.
  - **FHS 표준화**: 대용량 볼륨(`/data`)과 설정 코드(`/opt/services`)가 분리되어 백업 및 스토리지 마운트 용이.
- **사이드이펙트 방지 (Mitigations)**:
  - 전역 `/etc/profile`을 무조건 `umask 002`로 변경하지 않고 `dockermgmt` 소속 사용자 세션에만 선별 적용하여 시스템 데몬 보안성 유지.
