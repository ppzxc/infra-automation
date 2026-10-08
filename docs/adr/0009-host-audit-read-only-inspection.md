---
status: accepted
date: 2026-10-08
---

# 9. Host Audit: 읽기 전용 정기 점검과 A4 통합 보고서

관리 호스트의 현재 상태를 ISMS 증적으로 낼 수단이 없었고, 감사용으로 들인 CIS 파일럿(ADR-0004)은 변수 이름이 role 2.4.0과 맞지 않아 실제로는 교정을 실행했다. 그래서 **Host Audit**을 둔다. servers·loadbalancers·overseer 전체(Host Agents 미적용·CentOS 6/7 포함)를 **읽기 전용**으로 월 1회 점검해 Asset Inventory, Configuration Drift, Configuration Vulnerability, Package Vulnerability를 A4 인쇄용 HTML 보고서 1부로 만들고 RustFS에 3년 보관하며 메일로 보낸다. 고치지는 않는다. 근거와 경과는 [Map #100](https://github.com/ppzxc/infra-automation/issues/100), 구현은 [스펙 #115](https://github.com/ppzxc/infra-automation/issues/115).

1. **읽기 전용 = 관리 상태 불변.** 설정 파일, 패키지와 그 캐시, 저장소 정의, 서비스, 계정, 커널 설정을 바꾸지 않는다. 접속·권한 사용의 감사 흔적(인증·sudo·audit 로그, 로그인 기록)과 같은 실행 안에서 만들고 지우는 임시 파일은 허용한다. 점검 스크립트는 `raw`로 `sh -s`에 stdin으로 넣는다. check 모드에서도 호스트를 바꾸던 `DOC-004`/`DOC-004-CACHE`를 먼저 고치고, 모든 `check_mode: false` 태스크가 조회 전용인지 pytest로, 실행 전후 관리 영역 체크섬을 molecule로 확인한다.
2. **Configuration Vulnerability 기준은 KISA-2026 Unix 항목**(U-01~U-67)이고 CIS는 참조 열만 둔다. 항목은 판본을 붙여(`KISA-2026:U-NN`) 쓴다. 2021판과 번호가 전면 재배열됐기 때문이다. 점검은 자체 POSIX sh다.
3. **Package Vulnerability는 Trivy(SBOM 입력)**다. 호스트는 패키지 목록만 내주고 러너가 SBOM으로 바꿔 판정한다. Trivy는 사람이 검토한 고정 버전과 Git의 sha256으로만 받는다.
4. **Configuration Drift는 Git 선언 대비 차이**이고, 러너가 `site.yml`·Host Agents Config를 `--check --diff`로 하위 실행해 JSON 콜백 결과를 읽는다. Raw Provisioning Path 호스트는 raw 태스크가 check 모드에서 스킵되므로(ADR-0005) 점검불가로 보고한다.
5. **Audit Baseline은 직전 정기 실행**이다. 수시 실행은 보관하되 기준선이 되지 않는다. 발견은 신규·지속·해소·재발로 표시하며, 재발은 지난 12개월 정기 실행에서 해소됐던 항목이 다시 나타난 것이다.
6. **보관은 RustFS 전용 버킷 3년**(보고서 HTML + 호스트별 JSON), Host Audit 전용 키는 Put·Get만 갖고 Delete는 없다. 메일 본문에 첨부의 SHA-256과 보관 경로를 적어 메일함과 RustFS가 서로를 검증하게 한다. 사람의 검토·결재는 인쇄본 마지막 쪽 서명란이 맡고, Host Audit은 조치를 추적하지 않는다.

## Considered Options

- **CIS 파일럿 고쳐 쓰기(ansible-lockdown audit)**: 감사 모드에서도 git·goss를 호스트에 설치하고, goss(Go 1.26 빌드)가 CentOS 6 커널에서 돌지 않는다. 읽기 전용과 레거시 커버리지를 둘 다 못 지킨다.
- **OpenSCAP(SSG 프로파일·OVAL)**: KISA 프로파일이 없고 `oscap-ssh`는 대상에 oscap 설치를 요구한다. RHEL 10 OVAL이 없고 Rocky OVAL은 2025-03 이후 멈췄다.
- **Vuls server 모드**: 리서치 1순위였으나 PoC에서 기각했다. CentOS 7에서 RHEL 7 ELS에만 수정본이 있는 CVE 69건(일부 HIGH)을 놓쳤고, server 모드는 EOL 경고를 내지 않으며, DB가 풀면 13.6GB이고 동시 요청 시 메모리 973MB로 러너 1024M 한도에 닿았다. 같은 입력에서 Trivy는 DB 1.4GB, 메모리 약 100MB였고 SBOM 변환기 81줄로 `trivy image`와 결과가 일치했다.
- **CMDB 제품(NetBox, iTop)**: 1.2.1이 요구하는 것은 최신 자산 목록과 정기 실사 내역이고, 월간 보고서가 그 자체로 실사 내역이 된다. 수집할 수 없는 항목(용도·부서·책임자 직책·보안등급)은 Git의 호스트 변수로 충분하다.
- **결과를 OpenObserve 스트림이나 Git에 보관**: Git에는 계정·포트·취약점이 남고, OpenObserve는 증적 보관소가 아니라 검색 대상이다. 즉시 알림이 필요해지면 그때 스트림 적재를 더한다.
- **보고서 PDF**: 러너에 CJK 폰트와 Chromium/WeasyPrint를 넣은 커스텀 이미지가 필요하다. `.html` 첨부가 차단되거나 쪽번호가 필수일 때만 재검토한다.

## Consequences

- CentOS 6/7은 Configuration Drift를 볼 수 없다. 대신 EOS OS로 2.10.8 결함 대상임을 보고서 요약이 경고한다. raw 프로브를 check 모드에서 돌리는 ADR-0005 개정은 후속 작업이다.
- CentOS 6/7 패키지 판정은 RHEL 권고 기준이라 "CentOS용 수정본 없음"과 Red Hat will-not-fix를 따로 분류하지 않으면 건수가 부풀어 보인다.
- 점검 계정은 Deploy와 같은 관리 계정이다. 이 계정의 로그인 기록은 매번 갱신되므로 장기 미사용 판정에서 뺀다. 최소 권한 감사 전용 계정은 후속 작업이다.
- 취약점 DB를 받지 못한 지 7일이 넘으면 Package Vulnerability 섹션이 통째로 점검불가가 된다. 러너의 아웃바운드가 끊기면 보고서가 비는 쪽으로 실패한다.
- 쪽번호는 Chrome·Edge 131+에서 인쇄할 때만 나온다.
- 메일은 Google Workspace SMTP relay(IP 인증, TLS 필수)를 쓰므로 overseer 공인 IP가 바뀌면 관리 콘솔 허용 목록도 바꿔야 한다. 수신자·발신자 주소는 Git에 두지 않고 OpenBao에서 주입한다.
- ADR-0004의 CIS 감사 파일럿은 이 결정으로 대체된다.
