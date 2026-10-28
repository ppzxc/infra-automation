# HP Smart Array 관리 도구(ssacli) 설치·점검 런북

> RAID 상태 수집기(`docs/monitoring.md` §3-6, #335)는 호스트에 **이미 있는** HP 관리 도구만 쓴다. Host Agents는 도구를 설치하지 않는다(#322 결정: 패키지 설치는 사람이 하거나 프로비저닝 대상에서만 한다). 이 문서는 도구가 없는 HP 호스트에 사람이 설치할 때의 절차다(#334).

## 언제 필요한가

- `host_status_logs`에 `kind=tool_status`, `status=no_tool`이 남는데, 그 호스트에 HP Smart Array 컨트롤러가 있을 때.
- 컨트롤러가 있는지는 서버에서 `ls /sys/bus/pci/drivers/hpsa`(Gen9 이하의 `hpsa` 드라이버)나 `lspci -nn | grep -i 'smart array'`로 확인한다. 후지쯔·HP 일부 서버처럼 메인보드 SATA만 쓰는 호스트는 대상이 아니다.

## 무엇이 설치되나 (2026-10-22 RPM 직접 확인)

- 파일: `/opt/smartstorageadmin/ssacli`, `/usr/sbin/ssacli`, `/usr/sbin/ssascripting`, man 페이지. 데몬·서비스·커널 모듈·cron은 없다.
- 설치 전 스크립트는 실행 중인 ssacli가 있는지만 본다. 설치 후 스크립트는 예전 `cpqarray`·`cciss` 드라이버 버전 경고만 출력한다. 제거 스크립트는 설치 디렉터리만 지운다.
- 의존성은 glibc·libstdc++ 같은 기본 라이브러리뿐이다.
- HPE EULA상 재배포할 수 없으므로 RPM을 저장소·테스트 이미지에 넣지 않는다. 설치할 때마다 HPE에서 받는다.

## 버전 선택

| OS | 버전 | 출처(HPE MCP 저장소) | 비고 |
|---|---|---|---|
| Rocky 9 | `ssacli-6.60-8.0` | `https://downloads.linux.hpe.com/SDR/repo/mcp/rocky/9/x86_64/current/` | 릴리스 노트에 지원 컨트롤러 목록이 없지만 P440ar(Gen9)에서 동작 확인 |
| Rocky 10 | `ssacli-6.60-8.0` | `https://downloads.linux.hpe.com/SDR/repo/mcp/rocky/10/x86_64/current/` | Rocky 9 경로의 RPM과 SHA256이 같다(같은 바이너리). Rocky 10의 암호 정책이 HPE 키의 하위 키를 거부해 호스트의 `rpm -K`는 "간소화 서명 확인"만 낸다. 서명은 Rocky 9 호스트에서 임시 키링(`rpm --dbpath <임시> --import`)으로 검증하고, Rocky 10 호스트는 같은 SHA256일 때만 `rpm -i --nosignature`로 설치한다 |
| CentOS 7 | `ssacli-3.30-14.0` | `https://downloads.linux.hpe.com/SDR/repo/mcp/centos/7/x86_64/11.21/` | 같은 기종 CentOS 7 호스트들이 이미 쓰는 버전. 최신은 5.10-44.0 |
| CentOS 6 | (설치 사례 없음) | — | 기존 호스트는 `hpssacli` 2.x가 이미 있다 |

## 절차

1. **서명 검증(작업자 PC, 오프라인 컨테이너)**: RPM과 HPE 공개 키(`https://downloads.linux.hpe.com/SDR/hpePublicKey2048_key1.pub`, `_key2.pub`)를 받아 `rpm --import` 후 `rpm -K <rpm>`이 `digests signatures OK`인지 본다. 이때 SHA256을 적어 둔다.
2. **설치(호스트)**: 저장소는 추가하지 않는다. 호스트에서 같은 URL로 RPM을 `/var/tmp`에 받고, SHA256이 1단계 값과 같을 때만 `rpm -i`로 설치한 뒤 받은 파일을 지운다. DB 서버는 사용이 적은 시간에 한다.
3. **확인**: `timeout 120 ssacli ctrl all show status`가 컨트롤러 상태를 보여주는지 본다(보통 1초 안팎). 다음 수집(5분 안)부터 `host_status_logs`에 `tool_status=ok`와 `controller` 레코드가 들어온다.

설정을 바꾸는 명령(`modify`·`create`·`delete`)은 쓰지 않는다. 특히 `No-Battery Write Cache`를 켜지 않는다(정전 시 캐시의 쓰기가 사라진다).

## 설치 기록

| 날짜 | 호스트 | 버전 | 결과 |
|---|---|---|---|
| 2026-10-22 | ns0266·ns0325·ns0327·ns0338 (Rocky 9) | 6.60-8.0 | 정상. ns0325 캐시 영구 비활성(배터리 없음), ns0338 캐시 일시 비활성(케이블 오류) |
| 2026-10-22 | ns0334 (CentOS 7, DB) | 3.30-14.0 | 정상. 캐시 일시 비활성(케이블 오류) |
| 2026-10-28 | ns0331 (Rocky 10.2, 백업 저장소) | 6.60-8.0 | 정상. RAID 1+0, 1TB SATA 6개 모두 OK. 캐시 영구 비활성(백업 전원 없음) |
