# Host Audit: Vuls PoC (Package Vulnerability 도구 확정)

[#112](https://github.com/ppzxc/infra-automation/issues/112)의 PoC 결과입니다. 선행 조사는 [#101](https://github.com/ppzxc/infra-automation/issues/101)과 [host-audit-package-vulnerability-tooling.md](https://github.com/ppzxc/infra-automation/blob/research/host-audit-package-vulnerability-tooling/docs/research/host-audit-package-vulnerability-tooling.md)이고, 상위 맵은 [#100](https://github.com/ppzxc/infra-automation/issues/100)입니다.
실행일은 2026-10-08입니다. 용어는 `CONTEXT.md`의 **Host Audit**, **Package Vulnerability**, **Raw Provisioning Path**를 따릅니다.

모든 실행은 로컬 WSL2의 Docker 컨테이너 안에서 했습니다. 실제 운영 호스트, overseer, Semaphore에는 접속하지 않았습니다.

## 결론

**기각 (→ Trivy, SBOM 입력)** 입니다. Vuls server mode는 7개 OS를 모두 오프라인으로 판정했지만, #101의 권장 근거 가운데 두 가지가 실측에서 성립하지 않았습니다.

1. **CentOS 7에서 RHEL 7 ELS로만 고쳐진 CVE를 통째로 누락합니다.** Trivy는 CentOS vault 최종판보다 높은 버전(RHEL 7 ELS 전용)에서 고쳐진 CVE 69건을 보고했습니다. Vuls는 0건입니다. `X-Vuls-OS-Family: redhat`으로 보내도 마찬가지였습니다. 이것은 #101이 보고서에서 따로 표기하라고 한 바로 그 "CentOS용 수정본 없음" 분류이고, 2024~2026년의 HIGH 등급 glibc, openssl, libxml2, pam, bind 건이 포함됩니다.
2. **server mode는 EOL 경고를 내지 않습니다.** 7개 호스트 모두 `warnings: null`입니다. `CheckEOL()`은 `vuls scan` 경로(`scanner/scanner.go`)에서만 호출되고, server mode(`ViaHTTP`, `server/server.go`)에서는 호출되지 않습니다.
3. 자원 부담도 큽니다. `vuls.db`는 압축을 풀면 13.6 GB이고, 판정 중 메모리는 순차 판정에서도 약 400 MiB, 동시 7건에서는 973 MB까지 올라갔습니다. Trivy는 DB 1.4 GB, 메모리 최대 약 100 MB였습니다.

반대로 #101이 Trivy의 약점으로 든 "SBOM 변환기 부담"은 작았습니다. 81줄짜리 변환기로 만든 SBOM의 판정 결과는 `trivy image` 결과와 7개 OS 모두 (CVE, 패키지) 쌍 단위로 완전히 같았습니다(차이 0건). Trivy는 CentOS 6/7에 `EOSL: true`도 표시합니다.

Trivy 채택 조건은 [Trivy 채택 시 조건](#trivy-채택-시-조건)에 정리했습니다.

## #112 확인 항목 답

| 확인 항목 | 결과 |
|---|---|
| Rocky 10, Debian 13이 실제로 판정되는가 | **예.** Rocky 10.2는 82건, Debian 13은 72건입니다. Debian 13은 Trivy와 CVE 집합이 완전히 같고, Rocky 10은 80건이 겹칩니다(아래 표). |
| CentOS 6/7의 `raw` 수집 결과로 판정되는가 | **예.** CentOS 7은 709건, CentOS 6은 821건입니다. 다만 CentOS 7은 ELS 전용 수정 69건을 누락합니다. |
| EOL 경고가 나오는가 | **아니요.** server mode는 `CheckEOL()`을 호출하지 않아 모든 호스트에서 `warnings: null`입니다. |
| 오프라인 모드(`vuls.db` 반입 + `SkipUpdate`) | **예.** `--network none` 컨테이너에서 `SkipUpdate = true`로 7개 OS를 모두 판정했습니다. DB는 `:ro` 마운트로도 동작합니다. 크기와 반입 절차는 [오프라인 동작](#오프라인-동작)에 있습니다. |
| 같은 입력에 대한 Trivy(SBOM)와의 차이 | Rocky 8/9, Debian 13, Ubuntu 22.04는 거의 같습니다(차이 0~2건). Rocky 10은 Trivy에만 8건, Vuls에만 2건이 있습니다. CentOS 6/7은 Trivy가 436~450건 더 많습니다. 대부분은 정책 차이(Red Hat "Will not fix")이지만, CentOS 7의 ELS 전용 수정 69건은 Vuls의 누락입니다. |
| Semaphore 러너(Alpine, 1024M)에서 `vuls server`를 띄울 수 있는가 | **기동과 판정은 됩니다.** 정적 링크 바이너리라 `semaphoreui/semaphore` 이미지에서 그대로 실행됩니다. 하지만 메모리 여유가 거의 없습니다. 동시 7건에서 973 MB였고, 512 MiB 제한에서는 `GOMEMLIMIT` 없이 OOM kill됐습니다. |

## 방법

### 대상 컨테이너와 수집

업데이트를 하지 않은 공식 이미지를 그대로 썼습니다. 그래서 이미지 빌드 시점의 패키지 버전이 남아 있습니다. 수집은 `--network none` 컨테이너에서 POSIX `sh` 스크립트로 했습니다. Python은 쓰지 않았습니다. 이 스크립트는 Host Audit이 `ansible.builtin.raw`로 실행할 명령과 같습니다.

```sh
#!/bin/sh
# Host Audit raw collection (POSIX sh, no python)
echo "===RELEASE==="
if [ -f /etc/os-release ]; then cat /etc/os-release; fi
if [ -f /etc/redhat-release ]; then echo "REDHAT_RELEASE=$(cat /etc/redhat-release)"; fi
echo "===KERNEL==="
uname -r
echo "===PKGS==="
if command -v rpm >/dev/null 2>&1 && [ -f /etc/redhat-release ]; then
  major=$(sed -n 's/.*release \([0-9]*\).*/\1/p' /etc/redhat-release)
  if [ "$major" -ge 8 ]; then
    rpm -qa --queryformat "%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH} %{SOURCERPM} %{MODULARITYLABEL}\n"
  else
    rpm -qa --queryformat "%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH} %{SOURCERPM}\n"
  fi
else
  dpkg-query -W -f='${binary:Package},${db:Status-Abbrev},${Version},${Source},${source:Version}\n'
fi
```

| 호스트 | 이미지 (빌드일) | 릴리스 | 패키지 수 |
|---|---|---|---|
| rocky10 | `rockylinux/rockylinux:10` (2026-05-26) | Rocky Linux 10.2 | 138 |
| rocky9 | `rockylinux/rockylinux:9` (2026-05-25) | Rocky Linux 9.8 | 147 |
| rocky8 | `rockylinux/rockylinux:8` (2024-06-03) | Rocky Linux 8.10 | 148 |
| debian13 | `debian:13` (2026-10-05) | Debian 13 (trixie), `debian_version` 13.7 | 78 |
| ubuntu2204 | `ubuntu:22.04` (2026-09-24) | Ubuntu 22.04.5 LTS | 101 |
| centos7 | `centos:7` (2021-09-15) | CentOS Linux 7.9.2009 | 148 |
| centos6 | `centos:6` (2021-09-15) | CentOS 6.10 | 129 |

- `centos:6` 이미지는 Docker Hub에서 받을 수 있었습니다.
- 컨테이너의 `uname -r`은 모두 WSL 호스트 커널(`6.18.33.1-microsoft-standard-WSL2`)입니다. 컨테이너에는 kernel 패키지도 없습니다. 그래서 **커널 판정(`X-Vuls-Kernel-Release`, 재부팅 필요 판정)은 이 PoC에서 의미가 없고 검증하지 않았습니다.**
- 패키지 수가 적은 최소 이미지라 실제 서버보다 CVE 건수가 훨씬 적습니다. 도구 간 비교에는 충분합니다.

### 판정 측(러너)

| 항목 | 값 |
|---|---|
| Vuls | v0.41.0 (`vuls-0.41.0-f7331a92…`, 2026-09-30), `vuls_0.41.0_linux_amd64.tar.gz`. `checksums.txt` 일치, sigstore 번들 `cosign verify-blob` 통과(발급자 GitHub Actions, `future-architect/vuls`) |
| Vuls DB | `ghcr.io/vulsio/vuls-nightly-db:0`, manifest digest `sha256:c0f70d8f5972a58d2b51bf4e0e3e93958a5bf3c89375e687f4281d989f8a24d2`, 생성 2026-10-08T00:06:19Z |
| Trivy | v0.75.0 (2026-10-01), `trivy_0.75.0_Linux-64bit.tar.gz`. `checksums.txt` 일치, sigstore 번들 `cosign verify-blob` 통과(발급자 GitHub Actions, `aquasecurity/trivy` 워크플로) |
| Trivy DB | `trivy-db` v2, UpdatedAt 2026-10-07T07:38:55Z |
| 러너 이미지 | `semaphoreui/semaphore:latest` = `sha256:6d45ab59…` (Semaphore v2.18.31, Alpine 3.21.8, ansible-core 2.20.10, uid 1001) |
| 보조 도구 | oras v1.3.0(컨테이너), cosign v2.6.1(컨테이너), curl 8.16.0(컨테이너) |

Trivy 공급망 사고(GHSA-69fq-xp46-6x23)에서 악성 바이너리는 v0.69.4였습니다. v0.75.0은 그 뒤의 릴리스입니다. 같은 릴리스의 `checksums.txt`만으로는 자격증명 탈취를 막지 못하므로, sigstore 서명(Fulcio 인증서의 워크플로 신원)까지 확인했습니다.

### Vuls server 호출

`vuls server`를 `--network none` 컨테이너에서 띄웠습니다. 요청은 같은 네트워크 네임스페이스를 공유하는 curl 컨테이너(`--network container:<server>`)에서 보냈습니다. 외부 네트워크는 전혀 없습니다.

```toml
# config.toml
[vuls2]
Path = "/vuls/db/vuls.db"
SkipUpdate = true
```

```sh
vuls server -config /vuls/conf/config.toml -listen 127.0.0.1:5515 -to-localfile -results-dir /vuls/results

curl -X POST -H 'Content-Type: text/plain' \
  -H 'X-Vuls-OS-Family: centos' -H 'X-Vuls-OS-Release: 7.9.2009' \
  -H 'X-Vuls-Kernel-Release: <uname -r>' -H 'X-Vuls-Server-Name: centos7' \
  --data-binary @centos7.body http://127.0.0.1:5515/vuls
```

`X-Vuls-OS-Family`는 `rocky`, `centos`, `debian`, `ubuntu`를 썼습니다. 본문은 위 수집 결과의 `===PKGS===` 아래 줄 그대로입니다. 응답은 `ScanResult` JSON 배열이고, `-to-localfile`이면 결과 디렉터리에도 같은 JSON이 저장됩니다.

### Trivy 비교

두 가지로 돌렸습니다.

1. 기준값: `trivy image --scanners vuln --pkg-types os <이미지>`
2. Host Audit 경로: 수집 결과를 CycloneDX 1.5 SBOM으로 바꾼 뒤 `trivy sbom --skip-db-update --offline-scan`

변환기(`to_cdx.py`, 81줄)는 러너 쪽 Python입니다. 핵심은 다음과 같습니다.

- OS 컴포넌트 1개: `type: operating-system`, `name: rocky|centos|debian|ubuntu`, `version: 10.2` 등
- 패키지마다 purl: `pkg:rpm/<distro>/<name>@<ver>-<rel>?arch=..&epoch=..&distro=<distro>-<ver>`, `pkg:deb/<distro>/<name>@<ver>?arch=..&distro=..`
- 소스 패키지 정보는 `aquasecurity:trivy:SrcName/SrcVersion/SrcRelease/SrcEpoch` 속성으로 넣습니다(rpm은 `%{SOURCERPM}`, deb는 `${Source}`·`${source:Version}`).
- `dependencies`로 OS 컴포넌트가 모든 패키지를 가리키게 합니다.

**함정 하나**: 처음에 `metadata.component`의 type을 `operating-system`으로 두었습니다. 그러자 Trivy가 "Multiple OS components are not supported, taking the first one"을 경고하고 무작위로 그것을 OS로 골랐습니다. 그 결과 Rocky 9와 Debian 13이 **경고만 남기고 0건**으로 나왔습니다. `metadata.component`를 `application`으로 바꾸자 해결됐습니다. 운영에서는 "OS 인식 실패 = 0건"이 조용히 지나가지 않도록, 결과 JSON의 `Metadata.OS.Family`가 기대값과 같은지 검사해야 합니다.

수정 후 SBOM 경로와 `trivy image` 경로의 (CVE, 패키지) 쌍 집합은 7개 OS 모두 같았습니다(차이 0).

| 호스트 | `trivy image` 쌍 | `trivy sbom` 쌍 | 차이 |
|---|---|---|---|
| rocky10 | 104 | 104 | 0 |
| rocky9 | 176 | 176 | 0 |
| rocky8 | 233 | 233 | 0 |
| debian13 | 163 | 163 | 0 |
| ubuntu2204 | 31 | 31 | 0 |
| centos7 | 1661 | 1661 | 0 |
| centos6 | 1704 | 1704 | 0 |

## OS별 결과

CVE 수는 고유 CVE ID 기준입니다. 심각도 출처는 다음과 같습니다.

- **Vuls**: RHEL 계열은 Red Hat CVE 심각도(`redhat_api`, 없으면 `rocky`/`redhat` 항목), Ubuntu는 `ubuntu_api`, Debian은 Security Tracker에 등급이 없으면 NVD CVSS v3입니다. Critical/Important/Moderate/Low는 CRITICAL/HIGH/MEDIUM/LOW로 바꿨습니다. Vuls에는 단일 "판정 심각도" 필드가 없어서 이 우선순위는 이 PoC가 정한 것입니다.
- **Trivy**: Trivy 기본값(`Severity` 필드, 벤더 심각도 우선)입니다. 한 CVE가 여러 패키지에 걸치면 가장 높은 값을 썼습니다.

심각도 분포의 차이는 대부분 **출처 차이**입니다. 예를 들어 Rocky 10에서 Trivy HIGH 69건 대 Vuls HIGH 27건은, Vuls 집계가 Red Hat CVE 단위 심각도를 쓰는 반면, Trivy는 Rocky 권고(RLSA)의 권고 단위 심각도를 쓰는 것으로 보입니다(추정). 참고로 Vuls의 `rocky` 항목(NVD형 CVSS 등급)을 우선하면 Vuls Rocky 10은 1/38/39/4/0으로 바뀝니다. 검출 여부는 "겹침" 열로 비교하십시오.

| 호스트 | Vuls 판정 | Vuls CVE (C/H/M/L/?) | Vuls 수정 有/無 | EOL 경고 (Vuls / Trivy) | Trivy CVE (C/H/M/L/?) | Trivy 수정 有 | 겹침 | Vuls만 | Trivy만 |
|---|---|---|---|---|---|---|---|---|---|
| Rocky 10.2 | 예 | 82 (0/27/42/13/0) | 82 / 0 | 없음 / 없음 (Trivy: "not on the EOL list" 로그 경고) | 88 (0/69/17/2/0) | 88 | 80 | 2 | 8 |
| Rocky 9.8 | 예 | 129 (0/36/71/22/0) | 129 / 0 | 없음 / 없음 | 127 (0/84/40/3/0) | 127 | 127 | 2 | 0 |
| Rocky 8.10 | 예 | 179 (0/50/117/12/0) | 179 / 0 | 없음 / 없음 | 177 (0/80/90/7/0) | 177 | 177 | 2 | 0 |
| Debian 13 | 예 | 72 (1/12/20/35/4) | 0 / 72 | 없음 / 없음 | 72 (0/8/29/33/2) | 0 | 72 | 0 | 0 |
| Ubuntu 22.04 | 예 | 20 (0/1/7/12/0) | 6 / 14 | 없음 / 없음 | 20 (0/1/7/12/0) | 6 | 20 | 0 | 0 |
| CentOS 7.9 | 예 | 709 (1/50/365/293/0) | 67 / 642 | **없음** / `EOSL: true` | 1153 (1/81/557/514/0) | 137 | 703 | 6 | 450 |
| CentOS 6.10 | 예 | 821 (1/85/420/315/0) | 51 / 770 | **없음** / `EOSL: true` | 1231 (1/79/556/595/0) | 32 | 795 | 26 | 436 |

판정 방식(`confidences[].detectionMethod`)은 RHEL 계열이 `OvalMatch`, Debian이 `DebianSecurityTrackerMatch`, Ubuntu가 `UbuntuAPIMatch`였습니다. Rocky는 `rocky` 항목(Rocky errata)이 모든 CVE에 붙었습니다. CentOS는 `redhat`(Red Hat VEX, 세그먼트 `redhat:7`, 태그 `rhel-7-including-unpatched`)으로 판정됐습니다. #101에서 추론한 매핑(`centos` → `redhat:<major>`)과 같습니다.

### Rocky 10

- 판정됩니다. 공식 지원 OS 문서에는 없지만 DB에 Rocky 10 errata가 들어 있습니다.
- Trivy에만 있는 8건은 모두 `fixed` 상태입니다. curl/libcurl-minimal(`8.12.1-4.el10_2.6`에서 수정)과 libarchive(`3.7.7-11.el10_2`에서 수정)입니다. Vuls에만 있는 2건은 rpm-sequoia와 vim(`9.1.083-9.el10_2.22`에서 수정)입니다. 양쪽 모두 최근 권고라서 DB 반영 시점 차이로 추정하지만, 확인하지는 않았습니다.

### Debian 13 / Ubuntu 22.04

- 두 도구의 CVE 집합이 완전히 같습니다.
- Debian 13은 72건 전부 미수정입니다(`no-dsa: Minor issue`, `unfixed` 등). 이미지가 2026-10-05 빌드라 수정 가능한 건이 없습니다.
- Debian 본문에서 `${Source}`가 비어 있는 줄(소스 이름이 바이너리 이름과 같은 경우)도 Vuls가 문제없이 처리했습니다.

### CentOS 6/7: 수정 버전과 "CentOS용 수정본 없음"

두 도구가 낸 "수정 버전(fixed)"을 CentOS vault 최종판과 비교했습니다. vault 최종판은 `vault.centos.org/{7.9.2009,6.10}/{os,updates}/x86_64/Packages/` 목록에서 패키지별 최대 버전을 rpmvercmp로 구한 값입니다.

| 호스트 | 도구 | vault 최종판 이하에서 수정 (업데이트로 해소) | vault 최종판 초과 (RHEL ELS 전용 수정) |
|---|---|---|---|
| CentOS 7 | Vuls | 67 | **0** |
| CentOS 7 | Trivy | 68 | **69** |
| CentOS 6 | Vuls | 15 | 36 |
| CentOS 6 | Trivy | 15 | 17 |

- **CentOS 7에서 Vuls는 RHEL 7 ELS에서만 고쳐진 CVE를 보고하지 않습니다.** 미수정으로도 보고하지 않아 결과에서 아예 사라집니다. 예시는 다음과 같습니다.
  - CVE-2024-1737, CVE-2024-11187: bind-license (수정 `9.11.4-26.P2.el7_9.17`/`.18`, vault 최종 `.16`)
  - CVE-2024-33599: glibc (수정 `2.17-326.el7_9.3`, vault 최종 `2.17-326.el7_9`)
  - CVE-2025-49794 외 6건: libxml2 (수정 `2.9.1-6.el7_9.10`~`.14`, vault 최종 `el7_9.6`)
  - CVE-2025-6020 외 2건: pam, CVE-2026-45447: openssl-libs, CVE-2026-4519: python
- 같은 패키지 목록을 `X-Vuls-OS-Family: redhat`, `X-Vuls-OS-Release: 7.9`로 보내도 709건으로 같았고, 위 CVE들은 여전히 없었습니다. 그래서 CentOS 매핑 문제가 아니라, 현재 `vuls.db`가 RHEL 7의 ELS 스트림을 판정에 쓰지 않는 것으로 보입니다(추론, 원인은 코드에서 확인하지 않음).
- CentOS 6에서는 반대로 Vuls가 RHEL 6 ELS 수정 버전(예: bind `el6_10.17`, zlib `1.2.3-31.el6_10`)을 보고합니다. 즉 "RHEL 전용 수정 버전이 결과에 섞여 나온다"는 #101의 예상은 CentOS 6에서는 맞고, CentOS 7에서는 Vuls에서 해당 CVE 자체가 빠집니다.
- 어느 도구든 "업데이트로 해소 / CentOS용 수정본 없음" 구분은 보고서 단계에서 vault 최종판과 비교해 만들어야 합니다. 위 표가 그 계산이 가능하다는 것을 보여 줍니다.

### CentOS의 나머지 차이 (정책 차이)

- Trivy에만 있는 나머지(CentOS 7은 약 380건, CentOS 6은 436건 전부)는 Red Hat 상태가 `will_not_fix`(CentOS 7 556쌍, CentOS 6 592쌍)이거나 `under_investigation`인 건입니다. 패키지는 binutils, vim, libxml2, curl, glibc 순으로 많습니다. Vuls는 "Will not fix" 상태를 결과에 넣지 않고, Trivy는 넣습니다. 정책 차이이고, Trivy는 `--ignore-status will_not_fix`로 맞출 수 있습니다.
- Vuls에만 있는 건(CentOS 7 6건, CentOS 6 26건)은 `Out of support scope`, `Fix deferred`, `Affected` 상태입니다(예: CVE-2023-4039 libgcc, CVE-2021-3601 openssl-libs).
- Vuls의 CentOS 미수정 상태 분포(패키지 단위)는 CentOS 7이 `Out of support scope` 502, `Fix deferred` 328, `Affected` 91이고, CentOS 6이 각각 754, 236, 65입니다. Trivy는 CentOS 7에서 `end_of_life` 495쌍, `affected` 406쌍입니다.

## 오프라인 동작

| 시나리오 | 결과 |
|---|---|
| `SkipUpdate = true`, DB 있음, `--network none` | 7개 OS 모두 판정 (HTTP 200) |
| DB 디렉터리를 `:ro`로 마운트 | 동작함. bbolt를 `ReadOnly`로 엽니다. |
| `SkipUpdate = false`, DB 있음, `--network none` | 이번에는 판정됐습니다. 다만 DB가 6시간 이내로 새것이었기 때문입니다. `shouldDownload()`는 `LastModified + 6h`가 지나면 다운로드를 시도하므로, 폐쇄망에서는 **`SkipUpdate = true`가 필수**입니다. |
| `SkipUpdate = true`, DB 없음 | HTTP 503, `… vuls.db not found, cannot skip update` |
| 스키마 불일치 + `SkipUpdate = true` | 코드상 `vuls2 db schema version mismatch` 오류(실행 확인은 안 함). DB 태그(`:0`)와 Vuls 버전을 함께 고정해야 합니다. |

DB 반입 절차(실측):

```sh
oras pull ghcr.io/vulsio/vuls-nightly-db:0       # 287,572,489 B (vuls.db.zst), 31초
zstd -d vuls.db.zst -o vuls.db                    # 13,643,612,160 B (12.7 GiB), 9초
```

## 자원 측정

| 항목 | Vuls v0.41.0 | Trivy v0.75.0 |
|---|---|---|
| DB 배포 크기 | 287.6 MB (zstd) | 125.3 MB (tar+gzip) |
| DB 설치 크기 | **13.6 GB** (bbolt 단일 파일) | 1.4 GB (`trivy.db`) |
| 바이너리 | 93.5 MB (정적 링크) | 172.8 MB |
| 판정 시간 / 호스트 | 웜 상태 0.07~1.0초(CentOS가 가장 김), 첫 요청 0.4~3.1초. 7종 순차 반복 105건이 27초(평균 0.26초) | 0.09~0.24초(프로세스 기동과 DB 열기 포함) |
| 메모리, 순차 판정 (1024m 제한) | cgroup 최대 645 MB(첫 7건), 105건 반복 시 230~402 MiB를 오가며 406 MiB에서 평탄. 누수 증가는 없음 | cgroup 최대 약 100 MB (CentOS 6), 40 MB (Rocky 10) |
| 메모리, 동시 7건 (1024m 제한) | cgroup 최대 **973 MB** (anon 793 MB), VmHWM 1.15 GB. OOM 없음 | 측정 안 함(호스트마다 별도 프로세스) |
| 512m 제한, `GOMEMLIMIT` 없음 | 순차 7건 통과 후 동시 7건에서 **OOM kill** (exit 137) | 해당 없음 |
| 512m 제한, `GOMEMLIMIT=400MiB` | 순차와 동시 모두 통과(memory.max 도달 66회, OOM 0) | 해당 없음 |

Semaphore 러너 적합성:

- Vuls는 정적 링크 바이너리라 `semaphoreui/semaphore`(Alpine, uid 1001) 이미지에서 추가 패키지 없이 실행됩니다.
- 하지만 1024M 제한은 Semaphore 서버, ansible-playbook, fork 프로세스와 같이 쓰는 한도입니다. Vuls 하나가 동시 판정에서 973 MB를 쓰면 여유가 없습니다. 쓰려면 `GOMEMLIMIT` 설정, POST 직렬화(`throttle: 1`), 또는 러너 밖의 별도 컨테이너가 필요합니다.
- 러너 디스크에 13.6 GB DB가 상주해야 하고, 원자적으로 교체하려면 그 두 배가 필요합니다. 이 PoC에서도 12 GB tmpfs 작업 디렉터리에서 압축 해제 중 `No space left on device`가 나서 DB를 일반 디스크로 옮겼습니다.

## 겪은 문제

1. `vuls.db` 압축 해제 시 12 GB tmpfs에서 ENOSPC. DB는 일반 디스크에 두어야 합니다.
2. server mode에 EOL 경고가 없음(`CheckEOL()` 미호출). 문서와 #101의 기대와 다릅니다.
3. CentOS 7의 RHEL 7 ELS 전용 수정 CVE 69건 누락.
4. Trivy SBOM에서 `metadata.component` type을 `operating-system`으로 두면 OS 선택이 무작위가 되어 0건이 나옴. `application`으로 해결했습니다.
5. 컨테이너에서는 커널 판정을 검증할 수 없음(WSL 커널, kernel 패키지 없음).

## Trivy 채택 시 조건

1. **버전과 서명 고정**: 바이너리는 버전과 sha256으로 고정하고, 도입·갱신 때 sigstore 번들을 `cosign verify-blob --certificate-identity-regexp '^https://github.com/aquasecurity/trivy/.github/workflows/' --certificate-oidc-issuer https://token.actions.githubusercontent.com`으로 검증합니다. GHSA-69fq-xp46-6x23의 영향 버전(v0.69.4)은 쓰지 않습니다.
2. **DB 반입**: `ghcr.io/aquasecurity/trivy-db:2`를 사내 레지스트리나 RustFS로 미러링하고, 러너에서는 `--skip-db-update --offline-scan --skip-version-check`로 실행합니다. 보고서에 DB `UpdatedAt`을 찍습니다.
3. **SBOM 변환기 검증**: 결과의 `Metadata.OS.Family`/`Name`이 수집한 릴리스와 같은지 검사하고, 다르면 실패 처리합니다(0건이 조용히 통과하는 것을 막음). 변환기에는 OS별 고정 픽스처로 `trivy image` 결과와 같은지 보는 테스트를 둡니다.
4. **상태 정책 결정**: Red Hat `will_not_fix`를 포함할지(`--ignore-status`) 정합니다. 포함하면 CentOS 6/7 건수가 크게 늘어납니다.
5. **EOL**: CentOS는 `EOSL: true`가 나오지만 Rocky 10은 Trivy EOL 표에 없어 경고만 남습니다. 보고서의 EOL 표기는 Host Audit이 자체 표(OS, 메이저, 종료일)로 하는 것이 안전합니다.
6. **CentOS 6/7 구분**: "업데이트로 해소 / CentOS용 수정본 없음"은 vault 최종판과 비교해 보고서 단계에서 만듭니다(위 비교표 방식).

Vuls를 다시 검토할 조건: vuls2 DB가 RHEL 7 ELS 스트림을 판정에 포함하고, server mode가 EOL 경고를 내도록 바뀌면 재평가할 수 있습니다. 그때도 13.6 GB DB와 메모리 문제는 남습니다.

## 재현 메모

- 작업 스크립트(수집 `collect.sh`, POST `post_all.sh`, SBOM 변환 `to_cdx.py`, 비교 `analyze.py`/`diff.py`/`vaultcmp.py`, 메모리 `memtest.sh`/`soak.sh`)는 PoC 작업 디렉터리에만 두었고 저장소에는 넣지 않았습니다. 이 문서의 수치는 그 실행 결과입니다.
- 사용한 컨테이너와 DB 파일은 측정 후 삭제했습니다.

## 출처

- Vuls v0.41.0 소스: `server/server.go`(`ServeHTTP`, `CheckEOL` 호출 없음), `scanner/scanner.go`(`ViaHTTP`, 1001행 `r.CheckEOL()`은 scan 경로), `detector/vuls2/db.go`(`shouldDownload`: `SkipUpdate`, `LastModified + 6h`, 스키마 검사, bbolt `ReadOnly`) — [github.com/future-architect/vuls@v0.41.0](https://github.com/future-architect/vuls/tree/v0.41.0)
- [Vuls server mode 문서](https://vuls.io/docs/en/usage-server.html)
- Trivy: [SBOM/RPM 커버리지](https://github.com/aquasecurity/trivy/blob/main/docs/guide/coverage/others/rpm.md), [air-gap](https://github.com/aquasecurity/trivy/blob/main/docs/guide/advanced/air-gap.md), [GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
- CentOS vault 패키지 목록: `https://vault.centos.org/7.9.2009/{os,updates}/x86_64/Packages/`, `https://vault.centos.org/6.10/{os,updates}/x86_64/Packages/` (2026-10-08 조회)
