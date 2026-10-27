# Infra Automation Ansible Roles Index & Matrix

`infra-automation` 프로젝트는 단일 책임 원칙(SRP)에 따라 모듈화된 핵심 역할을 통해 온프레미스 대상 호스트의 라이프사이클을 관리하며, 본 디렉토리는 관련 스펙과 추적 매트릭스를 포함합니다.

---

## 1. 역할 목록 (Roles Index)

1. [Common Baseline (`common`)](common.md) - 시간 동기화(Chrony), 로케일, 관리자 계정, 커널 기본 튜닝
2. [Security Hardening (`security`)](security.md) - SSH 하드닝, 방화벽(UFW/Firewalld/iptables), SELinux, Auditd, firewalld-docker CLI
3. [Access Security (`access_security`)](access_security.md) - OpenBao SSH CA 단기 인증서 신뢰 및 HashiCorp Boundary 접속 메타데이터 통합
4. [Docker Engine (`docker_engine`)](docker_engine.md) - Podman 충돌 제거, 최신 Docker CE 설치 및 하드닝
5. [Monitoring & Observability (`monitoring`)](monitoring.md) - OpenTelemetry Collector (`otelcol-contrib`) 호스트 메트릭 및 시스템 로그 수집 파이프라인
6. [Host Backup (`backup`)](backup.md) - restic + resticprofile 기반 호스트 설정 백업(RustFS S3), ISMS 2.9.3 표준, 중앙 Repo Maintenance 포함
7. [Cisco IOS Switch Backup (`cisco_backup`)](cisco_backup.md) - Cisco 네트워크 스위치 `show running-config` 수집, 무결성 검증, 보관 주기 자동화 및 Semaphore UI 연동
8. [FortiGate Backup (`fortigate_backup`)](fortigate_backup.md) - FortiGate IDC 클러스터·사무실 장비별 설정 백업(접속 대상 단위, 응답 멤버를 파일명에), 파일명 `<장비>_<멤버>_<시각>`, 90일 보관, 원격 보관·암호화 결정 (#284), 직전 백업 대비 설정 변경 감지·알림 (#286)
9. [OpenObserve Config (`openobserve_config`)](openobserve_config.md) - 컨트롤러 전용. OpenObserve VRL ingest function(sshd/sudo 해석)·파이프라인·통지 webhook·알림 규칙(서버·스위치·방화벽 로그 알림, 방화벽은 #287, 대응 절차는 [알림 런북](runbooks/alerts.md))을 코드로 관리하고 API로 반영 (ADR-0008)
10. [FUNA Env (`funa_env`)](funa_env.md) - FUNA Cluster 환경 값을 OpenBao에서 읽어 `/etc/funa-cluster/`의 비시크릿 파일과 소비자별 시크릿 파일(0640 root:dockermgmt)로 렌더링 (#222)

---

## 2. 통합 아키텍처 및 시크릿 관리 (Integrations & Secrets)

* [OpenBao & Semaphore UI Secret Management Integration](openbao_integration.md) - OpenBao KV v2 동적 시크릿 및 Semaphore UI 최신 연동 가이드
* [Host Agents (otelcol + resticprofile) ADR-0006](adr/0006-host-agents-otelcol-resticprofile.md) - Host Agents 설치·재구성, ISMS 수집/백업 표준, OpenBao KV 스키마, CentOS 6/7 분기
* [Semaphore 셋업 가이드](semaphore-setup.md) - Key Store·Repository·Inventory·Variable Group·Host Agents/OpenObserve 템플릿·스케줄(UTC/KST) 등록 절차와 자주 겪는 문제
* Host Agents — Deploy All 배포 내역서: [Simple](host-agents-deploy-inventory-simple.md) · [Full](host-agents-deploy-inventory-full.md) - otelcol-contrib·restic·resticprofile 버전/SHA256, 호스트 변경 파일, 기본 수집 로그, 기본 백업 대상
* [Log Structuring ADR-0008](adr/0008-log-structuring-edge-envelope-central-semantics.md) - 엣지 Envelope Parsing + 중앙(OpenObserve VRL·알림) 의미 해석
* [스위치 syslog 수신 경로 런북](runbooks/switch-syslog.md) - 스위치 syslog → syslog-ng → 파일 보관 → otelcol → OpenObserve 경로, 설정 위치와 점검 절차(#276)
* [포티게이트 방화벽 로그 수신 런북](runbooks/fortigate-syslog.md) - 방화벽 syslog → `security_logs`(`fortigate-syslog`) 경로, 장비 쪽 로그 거름 기준, HA 멤버 구성, 점검·편입 절차(#283)
* [HP Smart Array 관리 도구(ssacli) 설치·점검 런북](runbooks/hp-raid-tool.md) - RAID 상태 수집기가 쓰는 도구의 설치 절차·버전·설치 기록(#334, #335)
* [월간 로그 점검 런북](runbooks/monthly-log-review.md) - 월 1회 로그 점검 절차(쿼리), 기록 양식, 아직 도착하지 않은 로그 종류의 관찰 목록. 실제 기록은 비공개 노트(#322, #333)
* [서버 시각 동기 현황 조사 (2026-10-26)](research/time-sync-host-survey-2026-10-26.md) - CentOS 6은 ntpd 없이 하루 한 번 rdate, CentOS 7·Rocky 9은 chrony 동기. 수집기·`infra-time-unsynced`에 미치는 영향과 열린 결정(#336)
* [Host Audit ADR-0009](adr/0009-host-audit-read-only-inspection.md) - 읽기 전용 정기 점검(Asset Inventory·Drift·KISA-2026·Trivy)과 A4 통합 보고서 메일
* [Host Audit 태스크 명세](host_audit.md) - 실행 흐름, 호스트별 JSON 구조(schema_version 1), 변수, AUD-xxx 태스크 매트릭스
* [Security Hardening Frameworks Evaluation ADR-0004](adr/0004-hardening-framework-evaluation.md) - dev-sec 및 ansible-lockdown 도입 검토 (CIS 감사 파일럿은 ADR-0009로 대체·제거)
* [Compose 프로젝트·서비스 이름 규칙 ADR-0011](adr/0011-compose-project-and-service-naming.md) - 수동 관리 docker compose의 `name:` 명시, 구성요소 서비스명, `<프로젝트>-<서비스>` 식별자 (FUNA Cluster 편입)
* [컨테이너 앱 텔레메트리 수집 경로 ADR-0012](adr/0012-container-app-telemetry-via-host-otelcol.md) - 노드 otelcol OTLP HTTP 수신기(`0.0.0.0`, host-gateway), `otel_app_telemetry` 스위치, `app_traces` 스트림
* [로그·트랩 수신 접점 출발지 제한 런북](runbooks/receiver-source-restriction.md) - 방화벽 체인 변경 없이 syslog·트랩 수신기를 애플리케이션 수준에서 제한, 실현성 보고 양식·수신기 관측 출발지 수집(`scripts/collect-receiver-sources.sh`)·롤백·부정 시험(#370)
