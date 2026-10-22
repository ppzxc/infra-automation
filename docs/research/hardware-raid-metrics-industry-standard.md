# 하드웨어 RAID 상태 수집 지표: 공급사 도구별 필드, 선행 사례, 정규화 스키마, 알림 기준

- 질문: 이슈 #329(RAID·시각 동기 수집과 P2 알림)의 RAID 갈래를 설계하기 전에 다음을 1차 출처로 정리한다.
  - HPE Smart Array, Broadcom MegaRAID, Huawei, Fujitsu 컨트롤러의 관리 도구가 각각 무엇을 읽을 수 있는가
  - 업계 도구(node_exporter textfile, Nagios check_raid, Zabbix, OpenTelemetry semconv)는 무엇을 어떤 이름으로 보고 무엇에 알리는가
  - 우리 정규화 JSON 줄 형식, P2 알림 조건, 수집 주기를 어떻게 정할 것인가

  **결정과 변경은 하지 않는다.** 코드·서버는 그대로 두었다.
- 조사일: 2026-10-22
- 기준 버전(링크는 모두 이 커밋에 고정했다)
  - node-exporter-textfile-collector-scripts `642e365`
  - nagios-plugin-check_raid `316d946`
  - Zabbix `e54235d`
  - OTel semantic-conventions `0eb883b`
  - LibreNMS(CPQIDA-MIB 사본) `06080bb`
  - proliantutils(HPE 작성 OpenStack 라이브러리) `fe2f9c2`
  - HPE 저장소 목록은 2026-10-22에 직접 조회했다.
- 방법
  - 공급사 릴리스 노트·사용자 안내서, 소스 코드, 저장소 목록만 근거로 썼다.
  - **서버에서 도구를 실행해 보지는 않았다.** 출력 예시는 공급사 문서나 업스트림 테스트 fixture에서 가져왔다.
  - 1차 출처를 직접 읽지 못하고 검색 요약으로만 확인한 것은 그렇다고 적었다. 확인하지 못한 것은 §10에 모았다.
- 우리 쪽 문맥
  - [alert-conditions-industry-baseline.md](alert-conditions-industry-baseline.md) §5.3이 이 조사의 출발점이다. 거기서 제안한 5필드 스키마(`{host, controller, controller_status, cache_status, battery_status}`)를 이 문서 §6이 대체한다.
  - 실측 사례
    - ns0288: HP Smart Array P440, 쓰기 캐시 `Permanently Disabled`, `Cable Error`
    - ns0272·ns0273: DL120 Gen9인데 `ssacli`가 없다
  - 수집 경로는 `backup.jsonl`과 같다. filelog가 `json_parser`로 attributes에 풀고(`roles/monitoring/templates/otelcol-contrib.yaml.j2`의 `filelog/backup_logs`), OpenObserve가 평탄화한다([openobserve-otlp-traces-metrics-contract.md](openobserve-otlp-traces-metrics-contract.md) §3.1).

## 요약

1. **도구는 서버 제조사가 아니라 컨트롤러 칩 계열로 정해진다.** 우리 플릿에서는 세 계열이면 거의 다 덮는다.
   - HPE Smart Array(SR): `ssacli` ← `hpssacli` ← `hpacucli`. 세 도구는 명령 문법이 같다.
   - LSI/Broadcom MegaRAID: `storcli`/`storcli64`. 더 새 칩은 `storcli2`를 쓴다. 이 계열에는 다음이 들어간다.
     - HPE의 "MR" 컨트롤러
     - Huawei V5의 LSI SAS3108·SAS3408·SAS3508
     - Fujitsu PRAID EP4xx(SAS3108)
   - Huawei 자체 칩(SP686C): `hiraidadm`.
2. **기계가 읽을 수 있는 출력은 storcli JSON(`... J`)뿐이다.** ssacli·hpssacli·hpacucli·hiraidadm은 사람이 읽는 텍스트를 내므로 줄 단위로 파싱해야 한다. ssacli에 JSON 옵션이 있다는 1차 출처는 찾지 못했다.
3. **종료 코드는 어느 도구도 문서로 확인하지 못했다.** 성공·실패는 출력으로 판정해야 한다.
   - storcli: JSON의 `Command Status.Status`
   - ssacli: `Error:` 줄과 `No controllers detected`
   - hiraidadm: `Status Code = 0 / Status = Success` 머리말
4. **“쓰기 캐시 켜짐”은 한 필드로 표현할 수 없다.** “설정값”과 “실제 적용값”을 따로 담아야 한다.
   - storcli: VD의 `Write Cache(initial setting)`과 현재 `Cache`(예: `RWBD`)
   - hiraidadm: `WCache`와 `RealWCache`
   - ssacli: 컨트롤러 `Cache Status`(`Temporarily/Permanently Disabled`)와 LD `Caching`

   check_raid도 “현재 WT인데 기본값은 WT가 아닐 때”만 알린다.
5. **읽기 전용이어도 부작용은 있다.**
   - HPE는 ssacli·hpacucli가 “heavy array controller I/O” 중, 예를 들어 rebuild 중에 응답하지 않을 수 있다고 적는다. HP 드라이버 개발자는 hpacucli가 잠금을 과하게 잡는다며 감시에는 `cciss_vol_status`를 권했다(check_raid가 2012년 메일로 전한 말이다).
   - storcli는 기본으로 작업 디렉터리에 `storcli.log`를 쓰므로 `nolog`가 필요하다. Broadcom은 두 인스턴스를 동시에 돌리지 말라고 한다.
   - 그래서 **수집 주기는 5분, 호출마다 `timeout`, 전체를 감싸는 `flock` 하나**를 권고한다(§7).
6. **OTel hardware semconv는 아직 전부 Development 단계다.** 이름이 같아도 뜻이 다른 함정이 있다.
   - `hw.logical_disk.state`는 공간(used/free)을 뜻한다. 상태(health)가 아니다.
   - `hw.physical_disk.state`는 SSD 수명(remaining)을 뜻한다.
   - 상태는 `hw.state`(`ok|degraded|failed|predicted_failure|needs_cleaning`)에 담는다.

   OpenObserve는 `hw.state`를 `hw_state`로 평탄화하므로 처음부터 밑줄 이름을 쓰는 것을 권한다(§6).
7. **P2 알림은 다섯 가지다.** 근거는 §8에 있다.
   - 논리 드라이브 이상
   - 물리 드라이브 고장·예측 고장
   - 캐시 배터리 고장
   - 쓰기 캐시가 설정과 달리 꺼짐(충전·학습 중은 제외)
   - 컨트롤러 이상

   수집 실패·부재는 기존 부재 알림 방식으로 다룬다. 온도와 오류 카운터는 알림이 아니라 진단 자료로 둔다.
8. **라이선스.** HPE EULA는 복제·배포를 금지하고, Broadcom storcli 라이선스도 “Reproduction or redistribution prohibited”다. 따라서 바이너리는 저장소와 molecule 이미지 어디에도 넣을 수 없다. 테스트는 시리얼·WWN을 지운 출력 fixture와 가짜 실행 파일로 한다.

## 1. 도구 계보와 지원 범위

### 1.1 HPE Smart Array: hpacucli → hpssacli → ssacli

| 도구 | 확인한 릴리스 | 대상 컨트롤러(릴리스 노트 목록 기준) | 공식 지원 OS(릴리스 노트) | 비고 |
|---|---|---|---|---|
| `hpacucli` (HP Array Configuration Utility CLI) | 9.20-9.0 (2012-06) | Smart Array 5i·6i·P400·P410·P812부터 Gen8의 P220i·P420i·P822·B320i까지(Gen8까지) | RHEL 4·5·6(32비트). RHEL 6 x86_64는 “Compatibility Package”(32비트 라이브러리) 필요 | “You run hpacucli as root.” “may appear unresponsive during heavy array controller I/O conditions” [hpe-hpacucli920] |
| `hpssacli` (HP Smart Storage Administrator CLI) | 2.0-23.0 (2014-07) | P410i~P840, H240 등 Gen6~Gen9 | RHEL 5·6. x86_64는 32비트 호환 패키지 필요 | [hpe-hpssacli20] |
| `ssacli` (HPE SSA CLI) | 3.10-3.0 (2017-05) | B110i~P841(Gen6~Gen9) | RHEL 5·6·7(x86_64) | `/usr/sbin/ssacli`. “You run ssacli as root.” RHEL 7.1은 `sg` 드라이버를 부팅 때 올려야 컨트롤러를 찾는다. 같은 “unresponsive” 경고가 있다 [hpe-ssacli310] |

HPE Software Delivery Repository에 2026-10-22 현재 올라 있는 최신 패키지는 다음과 같다. 저장소 목록은 지원 선언이 아니라 “HPE가 그 OS용으로 올려 둔 것”일 뿐이다.

| 저장소 경로 | ssacli | storcli | storcli2 |
|---|---|---|---|
| `mcp/centos/6` | 3.40-3.0 | 없음 | 없음 |
| `spp/RHEL/6` | 3.40 … **5.10-44.0** | — | — |
| `mcp/centos/7`, `mcp/centos/8` | 5.10-44.0 | 007.1616 | 없음 |
| `mcp/rocky/9`, `mcp/rocky/10` | 6.60-8.0 | 007.3604 | 008.0016 |
| `mcp/pool/non-free` (Debian/Ubuntu) | 6.60-8.0 `.deb` | 007.3604 `.deb` | — |

출처: [hpe-mcp], [hpe-spp-el6]. CentOS 6용은 두 저장소가 서로 다르다(mcp는 3.40, spp는 5.10). EL6에서 5.10이 실제로 도는지는 확인하지 못했다.

- **명령 문법.** check_raid의 `ssacli`·`hpssacli` 플러그인은 `hpacucli` 플러그인을 그대로 상속하고 실행 파일 이름만 바꾼다. 셋이 같은 문법이라는 실증이다[cr-ssacli]. 감시에 쓰는 명령은 다음과 같다.
  - `controller all show status`: 컨트롤러·캐시·배터리 상태 3줄[cr-hpacucli]
  - `controller slot=N logicaldrive all show`: `logicaldrive 1 (68.3 GB, RAID 1, OK)` 형식[cr-hpacucli]
  - `controller all show config detail`: 전체 트리(컨트롤러 → 어레이 → LD → PD). HPE가 만든 proliantutils가 이 출력을 파싱한다. ssacli가 있으면 그것을, 없으면 hpssacli를 쓴다[pu-objects]. 출력 예시는 [pu-raid]의 `HPSSA_ONE_DRIVE`에 있다.
- **기계 판독 출력.** 세 도구 모두 JSON·XML 출력 옵션을 1차 출처에서 찾지 못했다(**미확인**). 업계 구현(check_raid, proliantutils, Sermo)은 모두 `키: 값` 텍스트를 파싱한다.
- **종료 코드.** 문서로는 확인하지 못했다. proliantutils는 실행 오류(`ProcessExecutionError`)의 메시지에서 `No controllers detected`를 찾는다[pu-objects]. 따라서 컨트롤러가 없으면 0이 아닌 코드로 끝난다고 **추정**한다. check_raid는 `Error:`로 시작하는 줄을 UNKNOWN으로 본다[cr-hpacucli].
- **잡음 줄.** 출력 앞에 `FIRMWARE UPGRADE REQUIRED: ...` 같은 권고문이 끼어들 수 있다. check_raid는 이것과 27칸 들여쓴 이어짐 줄을 건너뛴다[cr-hpacucli], [cr-irm].
- **HPE “MR” 컨트롤러는 ssacli가 아니라 storcli를 쓴다.** HPE QuickSpecs는 MR Gen10 Plus 컨트롤러(MR416i, MR216i)가 “CLI Management Tool called StorCLI”를 쓴다고 적는다[hpe-mr-qs]. 이 문구는 검색 요약으로 확인했고 페이지 본문은 직접 읽지 못했다. Gen10 `P824i-p MR`도 MegaRAID 기반이라는 커뮤니티 답변이 있지만 1차 문서로는 확인하지 못했다.
- **대안 `cciss_vol_status`.** check_raid는 hpsa·cciss 드라이버가 올라와 있으면 이 도구로 볼륨 상태를 읽는다(`/sys/module/hpsa/refcnt`, `/proc/driver/cciss`로 탐지)[cr-cciss]. 별도 패키지라 우리 호스트에 있을 가능성은 낮다(미확인).

### 1.2 Broadcom/LSI MegaRAID: storcli, storcli2, MegaCli, perccli

- **storcli (`storcli64`)**: 12Gb/s MegaRAID, IT HBA, Software RAID 컨트롤러를 지원한다[bc-ug108]. Broadcom 문서의 공식 미러는 Thomas-Krenn에 있는 *StorCLI 12Gb/s MegaRAID Tri-Mode User Guide v1.8*(MR-TM-StorCLI-UG108, 2022-03)이다. 이 안내서가 말하는 것은 다음과 같다.
  - JSON: “To get the output in JSON format, add J at the end of the command syntax.” 일부 로그 명령은 JSON을 내지 못한다고 명시돼 있다.
  - 동시 실행: “running two instances of the StorCLI tool in parallel (at the same time) is not recommended.”
  - 기본 로깅: `storcli.log`(최대 3MB × 4개)를 남긴다. “Use the nolog option to disable logging for any command.”
  - 지원 OS 표에는 RHEL 6.6~6.8과 7.0~7.5가 있다. 이 표가 오래돼서 RHEL 8 이상은 빠져 있다. **최신 storcli 007.3x가 EL6에서 도는지는 확인하지 못했다.** HPE 저장소도 EL6용 storcli는 올리지 않았다(§1.1 표).
  - 권한: Windows는 “administrator privileges”가 필요하다고 적혀 있다. Linux의 root 요구는 문서에서 찾지 못했다. 장치 노드 접근 때문에 사실상 root라고 **추정**한다.
  - 기본 설치 경로는 `/opt/MegaRAID/storcli/storcli64`다(storcli.py의 기본값[tf-storcli], Huawei 설치 안내[hw-v6-storcli]).
- **JSON 응답의 공통 머리.** `Controllers[].Command Status`에 `CLI Version`, `Status`(`Success`/`Failure`), `Description`이 있다. storcli.py는 `Status != "Success"`이면 실패로 끝낸다[tf-storcli], [tf-fixture]. 다만 오래된 storcli는 rebuild 중인 드라이브가 없을 때 `show rebuild`에도 실패 상태를 돌려준다는 구현 주석이 있다[sermo]. 이 경우를 수집 오류로 세면 안 된다.
- **storcli2**: MegaRAID 9600 계열(SAS4/“MegaRAID8”)용 별도 도구다. FreeBSD 포트 검토 기록이 9600 eHBA를 StorCLI2 대상으로 적는다[fbsd-storcli2]. HPE는 EL9·10 저장소에 008.0016을 올렸다. **`J` 지원 여부와 JSON 키가 storcli와 같은지는 확인하지 못했다.**
- **MegaCli (`MegaCli64`)**: 이전 세대 도구다. check_raid는 `-PDList -aALL -NoLog`, `-LdInfo -Lall -aALL -NoLog`, `-AdpBbuCmd -GetBbuStatus -aALL -NoLog`를 읽는다[cr-megacli]. 텍스트 출력이고 `Exit Code: 0x..` 줄이 있다. Broadcom의 단종 공지는 1차 출처로 확인하지 못했다.
- **perccli**: Dell PERC용으로 storcli를 다시 포장한 도구다. 우리 플릿 대상이 아니라 조사하지 않았다(미확인).

### 1.3 Huawei

- **V2~V6 서버의 LSI/Avago 카드.** Huawei 안내서 목차에 다음 카드가 각각 장으로 있다[hw-ch121], [hw-v3-3108]. 이 페이지들도 JS로 그려져 목차는 검색 요약으로 확인했다.
  - LSI SAS3108, Avago SAS3408iMR, Avago SAS3508
  - Avago MegaRAID 9440-8i, 9460-8i
  - SP686C

  Huawei V6 안내서의 “Downloading and Installing StorCLI”는 Broadcom 사이트에서 최신 StorCLI를 받아 rpm으로 깔면 `/opt/MegaRAID/storcli/`에 들어간다고 안내한다. 다만 이 페이지는 JS로 그려져 본문을 직접 읽지 못했고 검색 요약으로만 확인했다[hw-v6-storcli].
- **SP686C(Huawei 자체 칩) → `hiraidadm`.** Kunpeng 문서센터의 SP686C 사용자 안내서에 명령 레퍼런스가 있다. 장치는 `/dev/bsg/hiraid0`로 보인다[hk-allctrl]. 읽기 명령과 주요 필드는 다음과 같다.
  - `hiraidadm show allctrl`: Controller Id, Device Name, PCI Address[hk-allctrl]
  - `hiraidadm c0 show status`: `Tempature`(철자 그대로), `VD Degrade Number`, `VD Fault Number`, `Prefail Number`, `Fail Number`, `Cache Pinned`, `Board Error`, `Board Capacity Error`(전원 백업 커패시터 고장), `DDR UCE Count` 등[hk-status]
  - `hiraidadm c0 show vdlist`: `Status`, `WCache`, **`RealWCache`**(현재 실제 적용된 쓰기 정책), `RCache`[hk-vdlist]
  - `hiraidadm c0:vd0 show`: `RAID Level`, `Write Cache`, `Real Write Cache`, `Whether Dirty Cache`, `VD Initialize Progress`[hk-vd]
  - `hiraidadm c0:eE:sS show`: `Status`, `Is Hotspare Drive`, `Prefail`, `Media Error Count`, `Other Error Count`, `Drive Temperature`, `Firmware Version`, `Task Progress`[hk-pd]
  - `hiraidadm c0 show backupcap` / `show scaplearn`: `Backup Cap Cf`, `Learn Status`, `Super Cap Esr`[hk-cap]
  - 확인한 예시 출력은 모두 `Status Code = 0 / Status = Success / Description = None` 머리말로 시작한다.
  - **JSON 옵션은 문서에서 찾지 못했다.** `Status`의 정상값 `normal` 외 값 목록도 확인하지 못했다.
- xFusion(Huawei x86 서버 사업을 이어받은 회사)의 도구명·옵션은 조사하지 않았다(미확인).

### 1.4 Fujitsu PRIMERGY

- PRAID EP400i/EP420i는 Fujitsu 데이터시트가 “RAID Controller SAS 12Gbit/s ... based on LSI MegaRAID®”, 제품 페이지가 “Controller Silicon RoC LSI SAS3108”이라고 적는다[fj-ds], [fj-ep4xx]. 두 페이지는 현재 리디렉트·401로 막혀 있어 검색 요약으로 확인했다.
- EP540i는 SAS3516이라는 판매처 목록만 있다(2차 출처).
- Fujitsu가 안내하는 관리 도구는 ServerView RAID Manager다. **MegaRAID 칩이므로 storcli가 동작할 것으로 추정하지만, Fujitsu가 storcli를 공식 지원한다는 문서는 찾지 못했다.** 실제 서버 조사(이슈의 “다룰 계열은 실제 서버 조사 결과로 정한다”)에서 확인해야 한다.

### 1.5 탐지 순서 (권고)

서버 제조사(DMI)가 아니라 커널 드라이버와 장치 노드로 계열을 정하고, 계열마다 실행 파일을 순서대로 찾는다.

| 신호 | 계열 | 찾을 실행 파일(순서) | 근거 |
|---|---|---|---|
| `/sys/module/hpsa` 또는 `/proc/driver/cciss` | HPE Smart Array | `ssacli` → `hpssacli` → `hpacucli` (`/usr/sbin`, `/opt/hp/...`) | [cr-cciss], [pu-objects] |
| `/sys/module/megaraid_sas` | MegaRAID | `storcli64` → `storcli` (`/opt/MegaRAID/storcli/`) → `MegaCli64` | storcli.py는 `Driver Name`이 `megaraid_sas`인지로 분기한다[tf-storcli] |
| `/sys/module/mpt3sas` | LSI HBA(IT) | `storcli64`(정보만, RAID 없음) | storcli.py `handle_sas_controller`[tf-storcli] |
| `/dev/bsg/hiraid*` | Huawei SP686C | `hiraidadm` | [hk-allctrl] |
| `/sys/module/smartpqi` | HPE Gen10 이후 SR(**확인 필요**) | `ssacli` | 1차 출처 미확인 |

신호가 있는데 실행 파일이 없으면 `no_tool`이다. 신호도 없으면 `no_controller`다(§6.2).

## 2. 지표 전수 비교

`—`는 그 도구에서 해당 값을 찾지 못했다는 뜻이다(없다고 확정한 것은 아니다).

### 2.1 컨트롤러·캐시·배터리

| 정규화 필드 | ssacli `show config detail` | storcli JSON (`/cALL show all J`) | hiraidadm | 참고(SNMP CPQIDA-MIB 열거값) |
|---|---|---|---|---|
| 컨트롤러 상태 | `Controller Status: OK` | `Status."Controller Status"`: MegaRAID는 `Optimal`/`Degraded`/`Failed`, mpt3sas는 `OK` | `show status`의 `Board Error`·`Board Clock Error`·`Board Power Error`·`Board Flash Error`(0이 정상) | `cpqDaCntlrBoardStatus`: ok, generalFailure, **cableProblem**, poweredOff, cacheModuleMissing |
| 컨트롤러 온도 | `Controller Temperature (C)` | `HwCfg."ROC temperature(Degree Celsius)"`(옛 버전 `Celcius`, 센서 없으면 키 없음) | `Tempature` (`67c`) | — |
| 캐시 모듈 온도 | `Cache Module Temperature (C)` | — | — | — |
| 캐시 상태 | `Cache Status`: `OK` / `Temporarily Disabled` / `Permanently Disabled` / `Not Configured` | 컨트롤러 단일 필드 없음. `Status."Any Offline VD Cache Preserved"` | `Cache Pinned`, `show pinnedcache` | `cpqDaAccelStatus`: enabled, tmpDisabled, **permDisabled**, cacheModFlashMemNotAttached, cacheModDegradedFailsafeSpeed, cacheModCriticalFailure, cacheReadCacheNotMapped |
| 캐시 크기 | `Total Cache Size`, `Total Cache Memory Available` | `HwCfg."On Board Memory Size"` | `DDR Size` | — |
| 배터리 없을 때 쓰기 캐시 | `No-Battery Write Cache: Disabled` | `Defaults."Cache When BBU Bad": "Off"`. 이것은 **새 VD의 기본값**이다. 기존 VD마다의 실제 설정은 `AWB`(배터리 없어도 WB)와 `WB`의 구분으로 본다 | 미확인 | — |
| 백업 전원 종류·개수 | `Cache Backup Power Source: Capacitors\|Batteries`, `Battery/Capacitor Count` | `HwCfg.BBU`, `Cachevault_Info[]` 또는 `BBU_Info[]` 유무 | `show backupcap` | — |
| 백업 전원 상태 | `Battery/Capacitor Status`: `OK` / `Recharging` / `Failed` / … | `Status."BBU Status"`(숫자. 0 정상, 8 충전 중. storcli.py는 0·8·4096을 정상으로 본다), `Cachevault_Info[].State`: `Optimal`/`Degraded`/`Failed` | `Board Capacity Error`, `show scaplearn`의 `Learn Status`·`Learn Info` | `cpqDaAccelBattery`: ok, **recharging**, failed, degraded, notPresent, capacitorFailed |
| 백업 전원 온도 | `Capacitor Temperature  (C)`(공백 두 칸) | `Cachevault_Info[].Temp`(`"18C"`), `BBU_Info[].Temp` | — | — |
| 충전량 | — | `/cx/bbu show all`, `/cx/cv show all`에 있을 것으로 보이나 키 이름 미확인 | `Super Cap Cf` | — |
| 패트롤 리드·일관성 검사 일정 | `Surface Scan Mode`, `Surface Scan Delay` | `"Scheduled Tasks"."Patrol Read Reoccurrence"`, `"Consistency Check Reoccurrence"`, `"Next Battery Learn"` | `show patrolread`, `show ccheck`, `show bgtask` | — |
| 메모리 ECC | — | `Status."Memory Correctable Errors"`, `"Memory Uncorrectable Errors"` | `DDR CE Count`, `DDR UCE Count` | — |

출처: ssacli [pu-raid], [cr-pr193]. storcli [tf-fixture], [tf-storcli]. hiraidadm [hk-status], [hk-cap], [hk-pd]. MIB [cpqida].

CPQIDA-MIB 설명에 따르면 Battery `failed`는 “below the sufficient voltage level and has not recharged in 36 hours”이고, `recharging` 동안에는 write-back 캐시가 일시 중단된다([alert-conditions-industry-baseline.md](alert-conditions-industry-baseline.md) §5.3, [cpqida]).

### 2.2 논리 드라이브(LD/VD)

| 정규화 필드 | ssacli | storcli JSON | hiraidadm |
|---|---|---|---|
| 상태 | LD `Status`. check_raid가 아는 값: `OK`, `Disabled`, `Failed`, `Interim Recovery Mode`, `Rebuild`, `Recover`. 어레이 줄은 `array A (Failed)` | `"VD LIST"[].State`: `Optl`, `OfLn`, `Pdgd`(부분 저하), `Dgrd`, `Rec` | `vdlist`의 `Status`(`normal`) |
| RAID 레벨 | `Fault Tolerance: 1`(텍스트 요약 줄은 `RAID 1`) | `TYPE`: `RAID6` | `RAID Level` |
| 크기 | `Size: 558.9 GB` | `Size: "1.745 TB"`(사람용 단위) | `Capacity: 1.454TB` |
| 쓰기 캐시 **설정** | 컨트롤러 `Cache Ratio`, LD `Caching: Enabled`, `LD Acceleration Method: Controller Cache` | `/cx/vall show all J`의 `"Write Cache(initial setting)"` | `WCache` |
| 쓰기 캐시 **실제** | 별도 필드 없음. LD `Caching`과 컨트롤러 `Cache Status`를 조합해야 한다(추론) | `"VD LIST"[].Cache`: `R`/`NR` + `WB`/`AWB`/`WT` + `C`/`D` (예: `RWBD`) | `RealWCache` |
| 재구축·초기화 진행률 | 텍스트 형식 미확인 | `/call/eall/sall show rebuild J`의 `Progress%`(서드파티 구현에서 확인) | `VD Initialize Progress`, `show bgtask` |
| 일관성 | `Parity Initialization Status`(Sermo 파서 기준) | `Consist`(`Yes`/`No`), `sCC` | `show ccheck` |

storcli 약어의 뜻은 storcli 텍스트 출력 범례에 있다. 예: “Optl=Optimal|… WB=WriteBack|AWB=Always WriteBack|WT=WriteThrough|C=Cached IO|D=Direct IO”, “Rec=Recovery|OfLn=OffLine|Pdgd=Partially Degraded|dgrd=Degraded”[phpsysinfo]. `Write Cache(initial setting)` 키 이름은 서드파티 Go 구조체로 확인했다[scality].

ssacli LD의 `Status`는 OK·Failed 외에 `Interim Recovery Mode`[cr-irm]가 있다. 재구축 중의 정확한 문자열과 진행률 형식은 1차 출처에서 확인하지 못했다(check_raid는 `Rebuild`·`Recover`라는 값만 안다).

### 2.3 물리 드라이브(PD)

| 정규화 필드 | ssacli | storcli JSON (`/cALL/eALL/sALL show all J`) | hiraidadm |
|---|---|---|---|
| 위치 | `physicaldrive 5I:1:1`(port:box:bay) | `"PD LIST"[]."EID:Slt"` | `Enc`, `Slot` |
| 상태 | `Status: OK` | `"PD LIST"[].State`: `Onln`, `Offln`, `Rbld`, `UGood`, `UBad`, `GHS`, `DHS`, `JBOD` 등 | `Status` |
| 예측 고장 | `Status` 값으로 나타난다(정확한 문자열 미확인) | `"Drive … State"."Predictive Failure Count"` | `Prefail` |
| 매체 오류 | — | `"Media Error Count"` | `Media Error Count` |
| 기타 오류 | — | `"Other Error Count"` | `Other Error Count` |
| SMART 경보 | — | `"S.M.A.R.T alert flagged by drive"`: `Yes`/`No` | `show smart` |
| 온도 | `Current Temperature (C)`, `Maximum Temperature (C)` | `"Drive Temperature"`: `" 21C (69.80 F)"` | `Drive Temperature`: `32c` |
| 펌웨어·모델 | `Firmware Revision`, `Model` | `"Device attributes"."Firmware Revision"`, `Model` | `Firmware Version`, `Model` |
| 핫 스페어 | `Drive Type`(`Data Drive`/`Unassigned Drive`. 스페어 값은 미확인) | State `GHS`/`DHS`, `"Commissioned Spare"`, `"Emergency Spare"` | `Is Hotspare Drive` |
| SSD 수명 | 미확인 | `"Supported PD Operations"."Support SSD Wear Gauge"`만 확인 | `Residual Wearout` |
| 재구축 진행 | — | `show rebuild J` | `Task Progress`, `Task Remaining Time` |

MIB의 `cpqDaPhyDrvStatus` 열거값은 ok, failed, **predictiveFailure**, erasing, eraseDone, eraseQueued, **ssdWearOut**, notAuthenticated다. `cpqDaPhyDrvSmartStatus`는 ok, replaceDrive, replaceDriveSSDWearOut다[cpqida].

출처: [pu-raid], [tf-fixture-pd], [tf-storcli], [phpsysinfo], [hk-pd].

## 3. 선행 사례

| 사례 | 수집 방법 | 지표·판정 이름 | 알림·판정 규칙 |
|---|---|---|---|
| node_exporter textfile `storcli.py` | `storcli /cALL show all J nolog`, PD는 `/cALL/eALL/sALL show all J` | `megaraid_controller_info`, `megaraid_temperature`, `megaraid_healthy`/`degraded`/`failed`, `megaraid_battery_backup_healthy`, `megaraid_bbu_temperature`, `megaraid_cv_temperature`, `megaraid_cv_state{state}`, `megaraid_scheduled_patrol_read`, `megaraid_vd_info{cache,type,state}`, `megaraid_pd_media_errors`, `megaraid_pd_other_errors`, `megaraid_pd_predictive_errors`, `megaraid_pd_smart_alerted`, `megaraid_pd_shield_counter`, `megaraid_pd_temp_celsius`, `megaraid_pd_info{state,firmware,…}` | 규칙은 없다(지표만 낸다). `BBU Status ∈ {0, 8, 4096}`이면 healthy[tf-storcli] |
| 같은 저장소의 HP 스크립트 | — | **없다** | 저장소 최상위 목록에 Smart Array 스크립트가 없다[tf-repo] |
| Nagios check_raid | `hpacucli`/`hpssacli`/`ssacli`(공통 코드), `megacli`, `cciss_vol_status` 등 29개 플러그인 | 사람이 읽는 상태 문자열 | 아래 표 참고[cr-hpacucli], [cr-megacli], [cr-readme] |
| Zabbix “HPE ProLiant DL380 by SNMP” | CPQIDA-MIB | `hp.server.hw.diskarray.status`, `…cache.status`, `…cache.battery.status`, `hp.server.hw.virtualdisk.status`, `hp.server.hw.physicaldisk.status`, `…smart_status` | 아래 표 참고[z-dl380] |
| Zabbix “HPE iLO by HTTP” | Redfish | Storage·Controller·Drive·Volume 상태 | Drive failed / predicted to fail, Volume 상태 트리거[z-ilo] |
| OTel semconv hardware | (규약) | `hw.status`, `hw.errors`, `hw.temperature`, `hw.battery.charge` 등 | 규칙 없음(§4) |
| node-mixin(md 소프트웨어 RAID) | node_exporter mdadm | `node_md_disks` | `NodeRAIDDegraded` for 15m critical, `NodeRAIDDiskFailure` warning([alert-conditions-industry-baseline.md](alert-conditions-industry-baseline.md) §1.2) |

**check_raid 판정 규칙**

| 대상 | 판정 |
|---|---|
| HP LD | `OK`·`Disabled` → 정상. `Failed`·`Interim Recovery Mode` → CRITICAL. `Rebuild`·`Recover` → WARNING |
| HP 어레이 | `OK`가 아니면 CRITICAL |
| HP 컨트롤러 | `Controller Status`가 `OK`가 아니면 CRITICAL. `Cache Status`가 `OK`·`Not Configured`가 아니면 `cache_fail`. `Battery/Capacitor Status`가 그 둘이 아니면 `bbulearn` |
| megacli VD | `Optimal`이 아니면 CRITICAL. 현재 정책이 `WriteThrough`인데 기본 정책은 WT가 아니면 `cache_fail`(이슈 #65) |
| megacli PD | `Online`·`Hotspare`·`Unconfigured(good)`·`JBOD` → 정상. `Predictive` → WARNING. 그 밖 → CRITICAL |
| megacli BBU | 상태가 `Operational`/`Optimal`이 아니면 CRITICAL. 단, `Charging`/`Discharging`이면서 learn cycle 중이면 `bbulearn`. `missing`·`replacement_required`·`pack_will_fail`·온도·전압 이상 → CRITICAL |
| 옵션 기본값 | `--cache-fail`(캐시가 있는데 꺼짐)과 `--bbulearn`(학습 중)의 기본은 **WARNING**이다[cr-readme] |

**Zabbix DL380 SNMP 트리거 등급**

| 대상 | 조건 | 등급 |
|---|---|---|
| 배터리 | `failed`/`capacitorFailed` | AVERAGE |
| 배터리 | `degraded` | WARNING |
| 캐시 | `cacheModCriticalFailure` | (critical 트리거) |
| 캐시 | `enabled`·`invalid`가 아닌 모든 값(`tmpDisabled`·`permDisabled` 포함) | WARNING |
| 컨트롤러 | critical | HIGH |
| 컨트롤러 | warning | AVERAGE |
| 가상 디스크 | `failed` | HIGH |
| 가상 디스크 | `ok`가 아님 | WARNING |
| 물리 디스크 | `failed`, SMART `replaceDrive` | HIGH |
| 물리 디스크 | `predictiveFailure` | WARNING |
| 물리 디스크 | 시리얼 변경(교체 탐지) | 트리거 있음 |

발견 규칙의 주기는 1h이고, 개별 항목 프로토타입에는 `delay`를 적지 않았다[z-dl380].

Zabbix 공식 저장소 `templates/server`(`e54235d`)에는 **MegaRAID·LSI·storcli용 공식 템플릿이 없다.** HPE(SNMP·iLO)와 Dell(iDRAC·Redfish) 같은 BMC·SNMP 기반 템플릿만 있고, OS 안에서 RAID 도구를 실행하는 템플릿은 없다[z-tree].

## 4. OpenTelemetry hardware semconv와의 대응

모든 `hw.*` 이름과 속성은 **Development** 단계다[otel-common].

| 우리 레코드 | `hw.type` | 쓸 수 있는 지표·속성 | 주의 |
|---|---|---|---|
| controller | `disk_controller` | `hw.status{hw.state}`, `hw.id`, `hw.model`, `hw.vendor`, `hw.firmware_version`, `hw.driver_version`, `hw.serial_number` | 컨트롤러 온도는 `hw.temperature`(`hw.type=temperature`, `hw.parent=<컨트롤러 id>`, `hw.sensor_location`)로 표현한다[otel-temp] |
| logical_drive | `logical_disk` | `hw.status{hw.state}`, `hw.logical_disk.raid_level`(`RAID5` 등), `hw.logical_disk.limit`(크기 By), `hw.errors` | **`hw.logical_disk.state`는 `used`/`free`(공간)다. 상태에 쓰면 안 된다**[otel-ld] |
| physical_drive | `physical_disk` | `hw.status{hw.state=ok\|degraded\|failed\|predicted_failure}`, `hw.errors{error.type}`, `hw.physical_disk.smart`, `hw.physical_disk.endurance_utilization`, `hw.physical_disk.type`, `hw.firmware_version` | **`hw.physical_disk.state`는 수명 지표의 `remaining`이다. 상태가 아니다**[otel-pd] |
| cache_battery | `battery` | `hw.status`, `hw.battery.charge`(0~1), `hw.battery.state`(`charging`/`discharging`. 충전·방전 중에만 필수), `hw.battery.chemistry` | 슈퍼커패시터용 값은 따로 없다[otel-bat] |
| (캐시 자체) | 없음 | — | `hw.type`에 cache 값이 없다. 캐시 필드는 controller·logical_drive 레코드에 둔다 |

`hw.state`의 정해진 값은 `ok`, `degraded`, `failed`, `predicted_failure`, `needs_cleaning`이다. 해당하는 값이 없으면 사용자 정의 값을 써도 된다(“otherwise, a custom value MAY be used”)[otel-common], [otel-ctrl]. `hw.status`는 StateSet을 흉내 낸 UpDownCounter다. 상태마다 1/0 시리즈를 낸다[otel-pd].

우리는 지표가 아니라 로그 줄을 보내므로 이 형식을 그대로 따를 필요는 없다. **속성 이름과 상태 어휘만 맞춘다.**

## 5. 우리 파이프라인 제약

- `filelog/backup_logs`는 `json_parser`로 줄 전체를 attributes에 푼다. OpenObserve는 레코드를 `flatten_level`(ns0331은 3)까지 평탄화한다. 키는 소문자로 바꾸고 `[a-z0-9_]` 밖의 문자를 `_`로 바꾸며, 중첩은 `_`로 잇고, 배열은 JSON 문자열로 저장한다([openobserve-otlp-traces-metrics-contract.md](openobserve-otlp-traces-metrics-contract.md) §3.1).
  - 그래서 원문을 중첩 맵 `raw: {"ROC temperature(Degree Celsius)": 52, ...}`으로 보내면 `raw_roc_temperature_degree_celsius_` 같은 열이 공급사·버전마다 생긴다. **추정**으로는 storcli `show all` 하나에 키가 수백 개다([tf-fixture]의 `Supported Adapter Operations`만 60개 가까이 된다).
  - 따라서 **원문은 JSON 문자열 한 필드(`raw`)로 넣는 것을 권한다.** OpenObserve는 문자열 필드를 다시 파싱하지 않으므로 열이 하나로 유지된다.
- `hw.state`처럼 점이 든 키는 어차피 `hw_state`로 바뀐다. 처음부터 밑줄 이름을 쓰면 SQL과 문서의 이름이 같아진다.
- 저장소가 공개되어 있으므로 fixture에서는 시리얼·WWN·SAS 주소·Safe ID·`Board SN`을 지운다(이슈 #329 인수 조건).

## 6. 권고: 정규화 JSON 줄 스키마

> 아래는 권고안이다. 필드 이름과 값 어휘는 OTel `hw.*`를 따르되 밑줄로 썼다.

### 6.1 공통 필드 (모든 레코드)

| 필드 | 형식 | 설명 |
|---|---|---|
| `ts` | RFC 3339 | 수집 시각. `backup.jsonl`과 같은 `timestamp.parse_from` 규칙을 쓴다 |
| `schema` | 정수 | 스키마 판(1부터) |
| `run_id` | 문자열 | 한 번의 수집 실행을 묶는 값. 같은 실행의 레코드를 SQL로 모을 때 쓴다 |
| `kind` | `controller` \| `logical_drive` \| `physical_drive` \| `cache_battery` \| `tool_status` | 레코드 종류 |
| `tool` | `ssacli` \| `hpssacli` \| `hpacucli` \| `storcli` \| `storcli2` \| `hiraidadm` \| `none` | 실제로 쓴 실행 파일 |
| `tool_version` | 문자열 | 예: storcli `Command Status."CLI Version"`, hiraidadm `Version` |
| `hw_type` | `disk_controller` \| `logical_disk` \| `physical_disk` \| `battery` | OTel `hw.type` |
| `hw_id` | 문자열 | 호스트 안에서 유일한 값. 예: `ssa:slot=0`, `ssa:slot=0/ld1`, `ssa:slot=0/pd5I:1:1`, `mr:c0/v0`, `mr:c0/e252/s3`, `hi:c0/vd0` |
| `hw_parent` | 문자열 | 상위 컨트롤러의 `hw_id` |
| `hw_name` | 문자열 | 사람이 읽는 이름(예: `Smart Array P440 in Slot 1`) |
| `hw_state` | `ok` \| `degraded` \| `failed` \| `predicted_failure` \| `unknown` | 정규화한 상태. 매핑할 수 없으면 `unknown` |
| `operation` | `none` \| `rebuild` \| `init` \| `expand` \| `check` \| `learn` \| `charging` | 진행 중인 배경 작업. 알림 지속 조건에 쓴다 |
| `progress_pct` | 숫자 \| null | 작업 진행률 |
| `raw_state` | 문자열 | 도구가 낸 상태 문자열 그대로(예: `Interim Recovery Mode`, `Pdgd`) |
| `raw` | 문자열(JSON) | 이 구성 요소에 대해 도구가 낸 키·값 전체. **문자열로 직렬화한다**(§5) |

### 6.2 종류별 필드

| kind | 필드 |
|---|---|
| `controller` | `hw_model`, `hw_firmware_version`, `hw_driver_version`, `temperature_c`, `cache_present`(bool), `cache_status`(`ok`\|`temporarily_disabled`\|`permanently_disabled`\|`not_configured`\|`failed`\|`unknown`), `cache_size_mb`, `write_cache_without_battery`(bool), `backup_power`(`battery`\|`capacitor`\|`none`\|`unknown`), `backup_power_state`(같은 컨트롤러 배터리의 `hw_state` 복사), `backup_power_operation`(`none`\|`charging`\|`learn`) |
| `logical_drive` | `raid_level`(`RAID1`, `RAID10`, `RAID5`, `RAID6` 등. ssacli `Fault Tolerance: 1+0`는 `RAID10`으로 바꾼다), `size_bytes`, `write_cache_configured`(`wb`\|`awb`\|`wt`\|`unknown`), `write_cache_effective`(`wb`\|`wt`\|`unknown`), `backup_power_state`, `backup_power_operation`(컨트롤러 레코드와 같은 값을 복사), `os_device`(예: `/dev/sda`) |
| `physical_drive` | `slot`(`5I:1:1`, `252:3`), `hw_model`, `hw_firmware_version`, `media`(`hdd`\|`ssd`), `temperature_c`, `predictive_failure`(bool), `media_errors`, `other_errors`, `smart_alert`(bool), `hot_spare`(bool), `drive_role`(`data`\|`spare`\|`unassigned`\|`jbod`) |
| `cache_battery` | `backup_power`, `temperature_c`, `charge_ratio`(0~1, 있을 때만), `present`(bool) |
| `tool_status` | `status`(`ok`\|`no_controller`\|`no_tool`\|`timeout`\|`error`\|`locked`), `family`(`smartarray`\|`megaraid`\|`hiraid`\|`unknown`), `exit_code`, `duration_ms`, `message`(첫 줄 200자) |

`write_cache_*`를 채우는 규칙은 다음과 같다.

- storcli: `configured`는 `Write Cache(initial setting)`, `effective`는 `VD LIST[].Cache`의 `WB`/`AWB`/`WT` 부분에서 읽는다.
- hiraidadm: `configured`는 `WCache`, `effective`는 `RealWCache`에서 읽는다.
- ssacli: 실제 적용값을 직접 주는 필드가 없어 다음처럼 유도한다(추론).
  - LD `Caching: Enabled`이면 `configured=wb`, 아니면 `wt`.
  - 컨트롤러 `cache_status`가 `temporarily_disabled`, `permanently_disabled`, `failed` 중 하나이면 `effective=wt`.
  - 그 밖에는 `effective=configured`.

배터리 상태(`backup_power_state`·`backup_power_operation`)를 controller·logical_drive 레코드에 복사해 두는 것은 알림 SQL이 다른 레코드와 조인하지 않고 `WHERE` 한 줄로 판정하게 하려는 것이다(§8).

`tool_status`는 실행마다 **반드시 1줄** 남긴다. 정상일 때도 `status=ok`를 남긴다. 그래야 부재 알림과 “조용한 실패”를 구분할 수 있다.

### 6.3 상태 매핑 (권고)

| 도구 | `ok` | `degraded` | `failed` | `predicted_failure` | `operation` |
|---|---|---|---|---|---|
| ssacli 컨트롤러 | `Controller Status: OK` | — | `OK`가 아닌 값 | — | — |
| ssacli LD | `OK`. 확장·패리티 초기화 같은 계획된 작업도 `ok`로 보고 `operation`만 단다(CPQIDA도 `expanding`·`queuedForExpansion`·`rapidParityInit*`를 고장과 별개 상태로 둔다) | `Interim Recovery Mode`, `Recover`, `Rebuild`(check_raid 기준. 실제 ssacli 문자열은 미확인) | `Failed` | — | `rebuild`(Recover/Rebuild), `init`·`expand`(계획된 작업) |
| ssacli PD | `OK` | — | `Failed` | `Predictive Failure`(문자열 미확인) | — |
| ssacli 배터리 | `OK` | `Recharging`(→ `operation=charging`), `Degraded` | `Failed`, `Capacitor Failed` | — | `charging` |
| storcli 컨트롤러 | `Optimal`(mpt3sas는 `OK`) | `Degraded` | `Failed` | — | — |
| storcli VD | `Optl` | `Pdgd`, `Dgrd`, `Rec` | `OfLn` | — | `rebuild`(`Rec` 또는 `show rebuild` 진행 중) |
| storcli PD | `Onln`, `GHS`, `DHS`, `UGood`, `JBOD` | `Rbld` | `Offln`, `UBad`, `Failed`, `Msng` | `Predictive Failure Count > 0` 또는 `S.M.A.R.T alert = Yes` | `rebuild` |
| storcli CacheVault/BBU | CV `Optimal` / `BBU Status` 0 | CV `Degraded`, `BBU Status` 8(충전) | CV `Failed`, 그 밖의 `BBU Status` | — | `charging`/`learn` |
| hiraidadm VD·PD | `normal` | 미확인 | 미확인 | PD `Prefail` | `Task Progress` |

`Not Configured` 캐시는 결함이 아니다. SSD Smart Path나 Smart HBA에서 정상으로 나온다. check_raid도 `OK`와 함께 정상으로 친다[cr-hpacucli]. 따라서 `cache_status=not_configured`는 `hw_state`를 낮추지 않는다.

### 6.4 예시 줄

```json
{"ts":"2026-10-22T10:05:00+09:00","schema":1,"run_id":"r-1761095100","kind":"tool_status","tool":"ssacli","tool_version":"","family":"smartarray","status":"ok","exit_code":0,"duration_ms":4120,"message":""}
{"ts":"2026-10-22T10:05:00+09:00","schema":1,"run_id":"r-1761095100","kind":"controller","tool":"ssacli","hw_type":"disk_controller","hw_id":"ssa:slot=1","hw_name":"Smart Array P440 in Slot 1","hw_state":"ok","raw_state":"OK","cache_present":true,"cache_status":"permanently_disabled","write_cache_without_battery":false,"backup_power":"unknown","temperature_c":null,"operation":"none","progress_pct":null,"raw":"{\"Controller Status\":\"OK\",\"Cache Status\":\"Permanently Disabled\",...}"}
{"ts":"2026-10-22T10:05:00+09:00","schema":1,"run_id":"r-1761095100","kind":"logical_drive","tool":"storcli","hw_type":"logical_disk","hw_id":"mr:c0/v0","hw_parent":"mr:c0","hw_state":"ok","raw_state":"Optl","raid_level":"RAID6","write_cache_configured":"wb","write_cache_effective":"wt","operation":"none","progress_pct":null,"raw":"{...}"}
```

컨트롤러는 `hw_state=ok`인데 캐시는 `permanently_disabled`인 경우를 따로 표현할 수 있어야 한다(둘째 줄). ns0288의 실제 출력에서 `Cable Error`가 어느 필드에 나오는지는 아직 확인하지 않았으므로, 이 예시는 ns0288을 그대로 옮긴 것이 아니다.

## 7. 수집 주기와 호출 제한 (권고)

| 항목 | 권고 | 근거 |
|---|---|---|
| 주기 | **5분** | HPE 도구는 무거운 I/O 중 응답이 없을 수 있고, 잠금 부담을 경고한 전언도 있다[hpe-ssacli310], [cr-114]. 알림을 “2회 연속”으로 판정해도 10분 안에 결론이 나는 값이다 |
| 호출당 `timeout` | **60초**, 넘으면 `TERM` 뒤 10초 후 `KILL` | 공급사가 응답 시간 상한을 밝히지 않았다(미확인). rebuild 중 지연을 감안해 넉넉히 잡고, 주기(300초) 안에서 3~4개 호출이 끝나는 값이다. 실측으로 조정한다 |
| 실행 겹침 방지 | 스크립트 전체를 `flock -n` 하나로 감싼다. 잠금을 못 잡으면 `tool_status=locked` 한 줄을 남기고 끝낸다 | storcli 동시 실행 비권장[bc-ug108]. 도구별 잠금이 아니라 전체 잠금이어야 다른 공급사 도구와도 겹치지 않는다 |
| storcli 옵션 | 모든 호출에 `nolog`를 붙이고 `J`로 받는다. 작업 디렉터리는 쓰기 불가 경로로 둔다 | 기본 로깅이 `storcli.log`를 쓴다[bc-ug108] |
| storcli 호출 수 | `/cALL show all J`, `/cALL/vALL show all J`, `/cALL/eALL/sALL show all J`. rebuild가 있을 때만 `show rebuild J` | storcli.py와 Sermo의 조합[tf-storcli], [sermo] |
| ssacli 호출 수 | `ctrl all show config detail` 한 번(필요하면 `ctrl all show status`) | proliantutils와 Sermo가 config detail 한 번으로 전부 읽는다[pu-objects], [sermo] |
| 우선순위 | `nice -n 19`, 가능하면 `ionice -c3` | 추정. 도구가 컨트롤러 명령을 기다리는 동안 CPU·I/O를 덜 쓰게 하려는 것이다 |
| 원자적 쓰기 | 한 실행의 줄을 임시 파일에 모은 뒤 로그 파일에 한 번에 append한다 | textfile collector README도 `sponge`로 원자적 쓰기를 권한다[tf-readme]. filelog가 반쯤 쓴 줄을 읽지 않게 한다 |
| 실패 처리 | 어떤 경우에도 종료 코드 0. 결과는 `tool_status`로만 남긴다 | 이슈 #329 인수 조건 |

CentOS 6에서 `timeout`(coreutils)과 `flock`(util-linux-ng)을 쓸 수 있는지는 molecule CentOS 6 시험으로 확인해야 한다(**확인 필요**). 32비트 `hpacucli`/`hpssacli`는 x86_64 EL6에서 32비트 호환 라이브러리가 없으면 실행되지 않는다[hpe-hpacucli920], [hpe-hpssacli20]. 이 경우는 `tool_status=error`로 남는다.

## 8. 권고: P2 알림 기준

모두 OpenObserve SQL 로그 알림이다. “2회 연속”은 구간 안의 해당 레코드를 `run_id`별로 세어 판정한다. 기존 `o2c_resource_sql`의 `min()` 방식과 같은 발상이다([alert-conditions-industry-baseline.md](alert-conditions-industry-baseline.md) 요약 3).

| 알림 | 조건 | 지속 | 근거 |
|---|---|---|---|
| 논리 드라이브 고장 | `kind=logical_drive and hw_state='failed'` | 2회 연속(약 10분) | Zabbix VD failed HIGH, check_raid CRITICAL |
| 논리 드라이브 저하 | `hw_state='degraded'` (`operation=rebuild` 포함) | **15분** 연속 | node-mixin `NodeRAIDDegraded` for 15m. check_raid는 rebuild를 WARNING으로 본다. 재구축이 정상 진행 중이어도 이중화가 없는 상태이므로 업무 시간 대응 대상이다 |
| 물리 드라이브 고장·예측 고장 | `kind=physical_drive and hw_state in ('failed','predicted_failure')` | 2회 연속 | Zabbix PD failed·SMART replaceDrive HIGH, predictiveFailure WARNING. check_raid Predictive WARNING. 교체 부품 준비가 필요하므로 P2 |
| 캐시 배터리 고장 | `kind=cache_battery and hw_state='failed'`, 또는 `cache_present and backup_power='none'` | 2회 연속 | Zabbix battery failed/capacitorFailed AVERAGE. check_raid megacli `missing`/`replacement_required` CRITICAL |
| 쓰기 캐시 꺼짐 | (가) `kind=controller and cache_status in ('permanently_disabled','failed')`, (나) `kind=logical_drive and write_cache_configured in ('wb','awb') and write_cache_effective='wt' and backup_power_operation not in ('charging','learn')`. 레코드 하나로 판정한다(§6.2) | 2회 연속 | check_raid #65 규칙(설정과 실제가 다를 때만), Zabbix `permDisabled` WARNING. 충전·학습 중의 일시 중단은 정상 동작이다(CPQIDA `recharging`, check_raid `bbulearn`, fixture PR193). 36시간 넘게 충전되지 않으면 MIB 정의상 배터리가 `failed`가 되어 위 배터리 알림이 받는다 |
| 컨트롤러 이상 | `kind=controller and hw_state<>'ok'` | 2회 연속 | Zabbix 컨트롤러 critical HIGH, check_raid CRITICAL. MIB는 `cableProblem`을 컨트롤러 보드 상태로 둔다. ns0288의 `Cable Error`가 ssacli에서 어느 필드로 나오는지는 미확인이다 |
| 수집 중단 | `tool_status`가 30분 동안 0줄, 또는 `status in ('timeout','error')`가 3회 연속 | 30분 | [openobserve-metric-absence-alerts.md](openobserve-metric-absence-alerts.md)의 부재 알림 방식. Prometheus `NodeTextFileCollectorScrapeError`에 해당한다 |

알리지 않고 진단 자료로 두는 것은 다음과 같다.

- **`no_tool`·`no_controller`.** 설치는 프로비저닝 대상에서만 하므로(이슈 #329) 알림이 아니라 대시보드·월간 점검 목록에 올린다.
- **온도.** 공급사 임계값을 도구 출력에서 얻지 못했다. ssacli·storcli 어느 쪽도 임계를 내지 않는다(미확인). 고정 임계를 만들면 근거 없는 알림이 된다.
- **`media_errors`·`other_errors` 증가.** storcli.py는 값만 내고, check_raid는 판정에 쓰지 않는다. 드라이브 고장 판정은 컨트롤러가 내린 `predicted_failure`·`failed`에 맡긴다.

업계 도구는 위 항목을 HIGH/AVERAGE/WARNING으로 나눈다. 이슈 #329가 하드웨어 RAID 알림을 모두 “P2, 업무 시간 대응”으로 정했으므로 등급 차이는 지속 조건과 알림 문구로만 반영한다. 이중화가 남아 있는 저하·예측 고장은 즉시 데이터 손실로 이어지지 않으므로 P1이 아니다. node-mixin도 단일 노드 문제는 paging 대상이 아니라고 본다([alert-conditions-industry-baseline.md](alert-conditions-industry-baseline.md) §1.1).

## 9. 라이선스·재배포

| 도구 | 조건 | 우리에게 주는 뜻 |
|---|---|---|
| ssacli·hpssacli·hpacucli | HPE EULA: “internal purposes only”, “You may not make copies and distribute… to third parties”, “You may not copy software or make it available on a public or external distributed network.”[hpe-eula] | 공개 저장소·CI 이미지·molecule 이미지에 넣지 않는다. 호스트에 이미 있는 것만 실행한다 |
| storcli | FreeBSD 포트가 Broadcom 조건을 “Source recipient must acknowledge license. Reproduction or redistribution prohibited.”로 옮겨 적고 `no-dist-mirror no-pkg-mirror`로 표시한다[fbsd-storcli] | 위와 같다 |
| storcli2·hiraidadm·ServerView RAID Manager | 확인하지 못했다 | 같은 원칙(설치·재배포하지 않음)을 따른다 |
| 도구 **출력** fixture | 소프트웨어 사본이 아니다 | 시리얼·WWN·SAS 주소를 지운 뒤 커밋한다. 테스트는 fixture를 출력하는 가짜 실행 파일로 한다 |

## 10. 확인하지 못한 것

- ssacli·hpssacli·hpacucli의 JSON/XML 출력 옵션, 종료 코드 규약, LD 재구축 상태 문자열과 진행률 형식, PD 예측 고장 상태 문자열, 핫 스페어 `Drive Type` 값
- ssacli 5.x·6.x가 지원하는 컨트롤러 세대(Gen10·Gen10 Plus·Gen11 SR). 확인한 릴리스 노트는 3.10(Gen9까지)뿐이다
- ~~ns0288의 `Cable Error`가 ssacli 출력의 어느 필드에 나오는지~~ → 2026-10-22 실측: 컨트롤러 블록의 `Cache Status Details: Cable Error`에 나온다. hpssacli 2.40(ns0288)은 이 줄만 내고, ssacli 3.30·6.60(ns0334·ns0338)은 `Cache Disable Reason:` 줄에 원인 문장도 낸다. 같은 Cable Error라도 ns0288은 `Cache Status: Permanently Disabled`, ns0334·ns0338은 `Temporarily Disabled`다
- storcli의 종료 코드 규약, Linux root 요구, 최신 007.3x의 EL6 실행 여부, BBU·CacheVault 충전량 JSON 키
- storcli2의 `J` 지원과 JSON 키 호환성
- HPE Gen10 이후 SR 컨트롤러의 커널 모듈(`smartpqi` 추정), Gen10 `P824i-p MR`이 storcli 대상인지(1차 문서)
- Huawei V6 StorCLI 안내 페이지 본문(검색 요약만 확인), hiraidadm의 JSON 옵션과 `Status` 값 목록, xFusion 도구
- Fujitsu PRAID에서 storcli 공식 지원 여부(Fujitsu는 ServerView RAID Manager만 안내), EP540i 칩(판매처 정보만)
- `hpacucli`가 커널 잠금을 과하게 잡는다는 말의 1차 출처. check_raid가 옮긴 2012년 메일뿐이다
- 각 도구의 실제 응답 시간. 60초 타임아웃은 실측으로 조정해야 한다
- CentOS 6 기본 설치에서 `timeout`·`flock` 가용성(molecule로 확인). 우리 CentOS 6 호스트 14대에는 둘 다 있다(2026-10-22 실측)
- ssacli 6.60 릴리스 노트에는 지원 컨트롤러 목록이 없고 지원 OS도 RHEL 8까지만 적혀 있다. 다만 HPE가 `rocky/9` 저장소로 배포하며, Rocky 9의 P440ar(Gen9)에서 `ctrl all show status`가 정상 동작했다(2026-10-22, ns0266·0325·0327·0338)

## 출처

- HPE
  - [hpacucli 9.20 릴리스 노트][hpe-hpacucli920]
  - [hpssacli 2.0 릴리스 노트][hpe-hpssacli20]
  - [ssacli 3.10 릴리스 노트][hpe-ssacli310]
  - [HPE SDR mcp 저장소][hpe-mcp]
  - [HPE SDR spp RHEL 6][hpe-spp-el6]
  - [HPE EULA][hpe-eula]
  - [HPE MR Gen10 Plus QuickSpecs][hpe-mr-qs]
  - [proliantutils objects.py][pu-objects]
  - [proliantutils raid_constants.py][pu-raid]
- Broadcom
  - [StorCLI 12Gb/s MegaRAID Tri-Mode User Guide v1.8 (Thomas-Krenn 미러)][bc-ug108]
  - [Broadcom 문서 12352476(구 StorCLI 매뉴얼)][bc-12352476]
  - [FreeBSD sysutils/storcli Makefile][fbsd-storcli]
  - [FreeBSD storcli2 포트 검토][fbsd-storcli2]
- Huawei
  - [CH121 V5 RAID 안내서 SP686C 장][hw-ch121]
  - [V2·V3 RAID 안내서 LSI SAS3108][hw-v3-3108]
  - [V6 RAID 안내서 StorCLI 설치][hw-v6-storcli]
  - SP686C hiraidadm: [show allctrl][hk-allctrl], [show status][hk-status], [show vdlist][hk-vdlist], [vd show][hk-vd], [pd show][hk-pd], [backupcap·scaplearn][hk-cap]
- Fujitsu
  - [PRAID EP400i/EP420i 데이터시트][fj-ds]
  - [PRAID EP400i/EP420i 제품 페이지][fj-ep4xx]
- 선행 사례
  - [textfile storcli.py][tf-storcli]
  - [storcli 컨트롤러 fixture][tf-fixture]
  - [storcli PD fixture][tf-fixture-pd]
  - [textfile README][tf-readme]
  - [textfile 저장소 목록][tf-repo]
  - check_raid: [hpacucli.pm][cr-hpacucli], [ssacli.pm][cr-ssacli], [megacli.pm][cr-megacli], [cciss.pm][cr-cciss], [README][cr-readme], [#114 댓글][cr-114], [PR193 fixture][cr-pr193], [Interim Recovery fixture][cr-irm]
  - Zabbix: [HPE ProLiant DL380 by SNMP][z-dl380], [HPE iLO by HTTP][z-ilo], [templates/server 목록][z-tree]
  - [CPQIDA-MIB (LibreNMS 사본)][cpqida]
  - [phpsysinfo storcli 출력 샘플][phpsysinfo]
  - [scality raidmgmt storcli 구조체][scality]
  - [Sermo hardware_raid.go][sermo]
- OpenTelemetry semconv hardware: [common][otel-common], [disk-controller][otel-ctrl], [logical-disk][otel-ld], [physical-disk][otel-pd], [battery][otel-bat], [temperature][otel-temp]
- 저장소 내부
  - [alert-conditions-industry-baseline.md](alert-conditions-industry-baseline.md)
  - [openobserve-otlp-traces-metrics-contract.md](openobserve-otlp-traces-metrics-contract.md)
  - [openobserve-metric-absence-alerts.md](openobserve-metric-absence-alerts.md)
  - [host-agents-os-compat-matrix.md](host-agents-os-compat-matrix.md)

[hpe-hpacucli920]: https://downloads.linux.hpe.com/SDR/repo/spp/2012.06.0B_supspp_rhel6.3_i386/hpacucli-9.20-9.0.i386.txt
[hpe-hpssacli20]: https://downloads.linux.hpe.com/repo/spp/rhel/6/i686/2014.09.0_supspp_rhel6.6_i386/hpssacli-2.0-23.0.i386.txt
[hpe-ssacli310]: https://downloads.hpe.com/pub/softlib2/software1/pubsw-linux/p1857046646/v122802/ssacli-3.10-3.0.x86_64.txt
[hpe-mcp]: https://downloads.linux.hpe.com/SDR/repo/mcp/
[hpe-spp-el6]: https://downloads.linux.hpe.com/SDR/repo/spp/RHEL/6/x86_64/current/
[hpe-eula]: https://downloads.linux.hpe.com/SDR/repo/mcp/EULA.txt
[hpe-mr-qs]: https://www.hpe.com/us/en/collaterals/collateral.a50002563enw.html
[pu-objects]: https://opendev.org/x/proliantutils/src/commit/fe2f9c2950b283f6fa0018b2b6c85c1928e88276/proliantutils/hpssa/objects.py
[pu-raid]: https://opendev.org/x/proliantutils/src/commit/fe2f9c2950b283f6fa0018b2b6c85c1928e88276/proliantutils/tests/hpssa/raid_constants.py
[bc-ug108]: https://www.thomas-krenn.com/redx/tools/mb_download.php/mid.yb4c56128ef83f96a/Manual_MR-TM-StorCLI-UG108_20220610.pdf
[bc-12352476]: https://docs.broadcom.com/doc/12352476
[fbsd-storcli]: https://github.com/freebsd/freebsd-ports/blob/014c6e99f7f90853269139ff854f857191795c2c/sysutils/storcli/Makefile
[fbsd-storcli2]: https://reviews-dev.freebsd.org/R11:fa513a9caae46312547c2b30875cfb0e5489e130
[hw-ch121]: https://support.huawei.com/enterprise/en/doc/EDOC1000163569/5b0ae2de/sp686c
[hw-v3-3108]: https://support.huawei.com/enterprise/en/doc/EDOC1000004186/19736aaf/lsi-sas3108
[hw-v6-storcli]: https://support.huawei.com/enterprise/en/doc/EDOC1100173718/dbc19cc6/downloading-and-installing-storcli
[hk-allctrl]: https://www.hikunpeng.com/doc_center/source/zh/raid/ug/sp686cug/SP686C_raid_06_0123.html
[hk-status]: https://www.hikunpeng.com/doc_center/source/zh/raid/ug/sp686cug/SP686C_raid_06_0152.html
[hk-vdlist]: https://www.hikunpeng.com/doc_center/source/zh/raid/ug/sp686cug/SP686C_raid_06_0138.html
[hk-vd]: https://www.hikunpeng.com/doc_center/source/zh/raid/ug/sp686cug/SP686C_raid_06_0176.html
[hk-pd]: https://www.hikunpeng.com/doc_center/source/zh/raid/ug/sp686cug/SP686C_raid_06_0192.html
[hk-cap]: https://www.hikunpeng.com/doc_center/source/zh/raid/ug/sp686cug/SP686C_raid_06_0163.html
[fj-ds]: https://sp.ts.fujitsu.com/dmsp/Publications/public/ds-praid-ep400i-ep420i.pdf
[fj-ep4xx]: https://www.fujitsu.com/es/products/computing/servers/primergy/components/pmod-127485.html
[tf-storcli]: https://github.com/prometheus-community/node-exporter-textfile-collector-scripts/blob/642e365cd4e99a1f5cfe9b6b1756cfc27da066b8/storcli.py
[tf-fixture]: https://github.com/prometheus-community/node-exporter-textfile-collector-scripts/blob/642e365cd4e99a1f5cfe9b6b1756cfc27da066b8/mock/fixtures/storcli_-cALL_show_all.json
[tf-fixture-pd]: https://github.com/prometheus-community/node-exporter-textfile-collector-scripts/blob/642e365cd4e99a1f5cfe9b6b1756cfc27da066b8/mock/fixtures/storcli_-cALL-eALL-sALL_show_all.json
[tf-readme]: https://github.com/prometheus-community/node-exporter-textfile-collector-scripts/blob/642e365cd4e99a1f5cfe9b6b1756cfc27da066b8/README.md
[tf-repo]: https://github.com/prometheus-community/node-exporter-textfile-collector-scripts/tree/642e365cd4e99a1f5cfe9b6b1756cfc27da066b8
[cr-hpacucli]: https://github.com/glensc/nagios-plugin-check_raid/blob/316d94690e98b0029588b9c604de56999e2b5e9e/lib/App/Monitoring/Plugin/CheckRaid/Plugins/hpacucli.pm
[cr-ssacli]: https://github.com/glensc/nagios-plugin-check_raid/blob/316d94690e98b0029588b9c604de56999e2b5e9e/lib/App/Monitoring/Plugin/CheckRaid/Plugins/ssacli.pm
[cr-megacli]: https://github.com/glensc/nagios-plugin-check_raid/blob/316d94690e98b0029588b9c604de56999e2b5e9e/lib/App/Monitoring/Plugin/CheckRaid/Plugins/megacli.pm#L266-L335
[cr-cciss]: https://github.com/glensc/nagios-plugin-check_raid/blob/316d94690e98b0029588b9c604de56999e2b5e9e/lib/App/Monitoring/Plugin/CheckRaid/Plugins/cciss.pm
[cr-readme]: https://github.com/glensc/nagios-plugin-check_raid/blob/316d94690e98b0029588b9c604de56999e2b5e9e/README.md
[cr-114]: https://github.com/glensc/nagios-plugin-check_raid/issues/114#issuecomment-138866801
[cr-pr193]: https://github.com/glensc/nagios-plugin-check_raid/blob/316d94690e98b0029588b9c604de56999e2b5e9e/t/data/hpacucli/PR193/ctrl-status
[cr-irm]: https://github.com/glensc/nagios-plugin-check_raid/blob/316d94690e98b0029588b9c604de56999e2b5e9e/t/data/hpacucli/hpacucli.interim_recovery_mode.show
[z-dl380]: https://github.com/zabbix/zabbix/blob/e54235d8f7cefcdd2eec5d3e37b7212eb8ea59d4/templates/server/hp/hp_dl380_snmp/template_server_hp_dl380_snmp.yaml
[z-ilo]: https://github.com/zabbix/zabbix/blob/e54235d8f7cefcdd2eec5d3e37b7212eb8ea59d4/templates/server/hpe_ilo_http/template_server_hpe_ilo_http.yaml
[z-tree]: https://github.com/zabbix/zabbix/tree/e54235d8f7cefcdd2eec5d3e37b7212eb8ea59d4/templates/server
[cpqida]: https://github.com/librenms/librenms/blob/06080bb359079ad327957f6ccca5375275c211d7/mibs/hp/CPQIDA-MIB
[phpsysinfo]: https://github.com/phpsysinfo/phpsysinfo/blob/d7bfbb0eadaf8b3aa839d9e5d4da5ca155910bee/sample/plugin_raid/raidstorcli0.txt
[scality]: https://github.com/scality/raidmgmt/blob/edcad58e199daef3ca4bbc3210882040cdd8fdfd/pkg/implementation/raidcontroller/megaraid/structs.go
[sermo]: https://github.com/inode64/Sermo/blob/ff5a1354e1918e1919dea5e0c0c2045b0e8c6d48/internal/checks/hardware_raid.go#L199-L225
[otel-common]: https://github.com/open-telemetry/semantic-conventions/blob/0eb883be629282ae400a8063492626ff14dfb62f/docs/hardware/common.md
[otel-ctrl]: https://github.com/open-telemetry/semantic-conventions/blob/0eb883be629282ae400a8063492626ff14dfb62f/docs/hardware/disk-controller.md
[otel-ld]: https://github.com/open-telemetry/semantic-conventions/blob/0eb883be629282ae400a8063492626ff14dfb62f/docs/hardware/logical-disk.md
[otel-pd]: https://github.com/open-telemetry/semantic-conventions/blob/0eb883be629282ae400a8063492626ff14dfb62f/docs/hardware/physical-disk.md
[otel-bat]: https://github.com/open-telemetry/semantic-conventions/blob/0eb883be629282ae400a8063492626ff14dfb62f/docs/hardware/battery.md
[otel-temp]: https://github.com/open-telemetry/semantic-conventions/blob/0eb883be629282ae400a8063492626ff14dfb62f/docs/hardware/temperature.md
