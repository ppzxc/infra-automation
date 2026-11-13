# Cisco Catalyst SNMP OID 선정 결과

- 작성일: 2026-11-13
- 목적: LibreNMS에서 Telegraf + OpenObserve로 옮길 때 알림·대시보드·장애 분석에 쓰는 SNMP 데이터만 수집
- Telegraf: ns0266 Docker 배포에서 확인한 1.40.3 설정 문법 기준
- 근거: ns0266의 LibreNMS 컨테이너에서 각 장비에 SNMPv3 authPriv walk 실행. 자격 증명은 서버의 기존 Docker secret 파일로만 읽었으며 문서와 Git에는 기록하지 않음
- 범위: Catalyst 2960G/S/XR, 3750X, 3850. 현재 가동 중인 추가 3550/3560 계열은 이 설계의 지원 범위에 포함하지 않음

## 검증 결과

| 제품군 / 실제 응답 모델 | IOS 이미지·버전(응답 sysDescr) | 상태·CPU·메모리·IF-MIB | 64-bit 트래픽 카운터 | 센서·FRU | 결과 |
|---|---|---|---|---|---|
| 2960G — WS-C2960G-24TC-L | C2960 LANBASE, 12.2(55)SE10 | P0 모두 응답 | `ifHCInOctets`/`ifHCOutOctets` Counter64, 각 26행 | 온도·전원·팬 OID 미응답 | P0 사용 가능, 하드웨어 환경은 제외 |
| 2960S — WS-C2960S-48TS-S | C2960S UNIVERSALK9, 12.2(55)SE5 | P0 모두 응답 | Counter64, 각 54행 | 온도·전원·팬 OID 미응답 | P0 사용 가능, 하드웨어 환경은 제외 |
| 2960XR — WS-C2960XR-48TD-I (2대) | 확인 불가 | 장비가 down이라 walk timeout | 확인 불가 | 확인 불가 | 미검증. 장비가 응답할 때까지 설정에는 공통 P0만 사용하고 센서 설정은 붙이지 않음 |
| 3750X — WS-C3750X-24T-L | C3750E, 15.0(2)SE6 | P0 모두 응답 | Counter64, 각 46행 | 센서 5행, 전원 2행, 팬 2행 | P0 + 선택 P1 하드웨어 수집 가능 |
| 3850 — WS-C3850-24T | CAT3K_CAA, 03.07.04E | P0 모두 응답 | Counter64, 각 40행 | 센서 3행, 전원 2행, 팬 3행 | P0 + 선택 P1 하드웨어 수집 가능 |

실제 인터페이스 행 수는 모델별 ifIndex/ifName 테이블 행 수 기준이다. HC 카운터는 일부 가상/내부 인터페이스에서 빠질 수 있어 IF-MIB 전체 행 수와 다르다. 실제 ifType walk에서는 `ethernetCsmacd(6)`, `propVirtual(53)` Port-channel과 `other(1)`이 확인됐다. 이번 표본에서는 VLAN(135)과 Loopback(24) 행은 없었다.

CPU Rev 컬럼은 네 활성 모델 모두 응답했다. 2960G/2960S/3750X에서는 CPU 인덱스 suffix `.1`, 3850에서는 `.1000`이었다. 장비별 인덱스를 설정에 고정하지 않고 Telegraf 테이블의 행 인덱스로 수집한다. 구형 비-Rev 컬럼 `.3`도 2960G/2960S/3750X/3850에서 응답했지만 정상 경로에서는 추가 수집하지 않는다.

메모리 테이블의 suffix가 pool id다. 2960G/2960S/3750X에서는 `.1=Processor`, `.2=I/O`가 확인됐고, 3850에서는 `.1=Processor`, `.7=IOS Process stack`이 확인됐다. 일부 IOS는 작은 `Driver text` pool도 제공하지만 운영 메모리 알림에 쓰지 않아 설정에서 제외한다.

`ifHCInOctets`와 `ifHCOutOctets`는 네 활성 모델 모두 Counter64로 응답했다. `ifAdminStatus`, `ifOperStatus`, `ifLastChange`, 양방향 error/discard, ifName, ifAlias도 네 모델에서 응답했다. Core/Transit로 표시된 행 중에는 물리 포트와 Port-channel이 함께 있고, Port-channel 멤버에는 같은 설명이 반복되어 있다. 2960XR는 장비가 내려가 있어 모든 항목이 미검증이다.

대체 경로도 네 활성 모델에서 확인했다. legacy CPU 1분/5분 컬럼은 Gauge32, `ifInOctets`/`ifOutOctets`는 Counter32로 응답했다. `ifHighSpeed`도 네 모델에서 응답했다. 따라서 이 fallback OID들은 구성 파일에서 바로 선택할 수 있지만, primary OID와 함께 사용하지 않는다.

`sysName`, `sysObjectID`, `entPhysicalName`, `entPhysicalClass`, `entPhysicalModelName`, `entPhysicalSerialNum`도 네 활성 장비에서 응답했다. 3750X의 일부 entity 행은 model/serial 문자열이 비어 있으므로 실제 chassis 행의 non-empty 값만 정적 인벤토리로 사용한다. serial 값 자체는 이 문서에 남기지 않는다.

## P0 수집 OID

| 목적 | MIB 객체 | 숫자 OID | Telegraf 필드 / 의미 |
|---|---|---|---|
| 장비 이름 | SNMPv2-MIB::sysName.0 | `.1.3.6.1.2.1.1.5.0` | `sys_name`, 매일 정적 발견 |
| 장비 모델 식별자 | SNMPv2-MIB::sysObjectID.0 | `.1.3.6.1.2.1.1.2.0` | `sys_object_id`, 매일 정적 발견 |
| IOS·모델 설명 | SNMPv2-MIB::sysDescr.0 | `.1.3.6.1.2.1.1.1.0` | `sys_descr`, 매일 정적 발견 |
| 생존·재부팅 판별 | SNMPv2-MIB::sysUpTime.0 | `.1.3.6.1.2.1.1.3.0` | `sys_uptime_ticks`; 60초마다 성공 응답 marker이자 reset 판별 기준 |
| CPU 1분 | CISCO-PROCESS-MIB::cpmCPUTotal1minRev | `.1.3.6.1.4.1.9.9.109.1.1.1.1.8` | `cpu_1min_percent`, CPU 테이블 index 포함 |
| CPU 5분 | CISCO-PROCESS-MIB::cpmCPUTotal5minRev | `.1.3.6.1.4.1.9.9.109.1.1.1.1.9` | `cpu_5min_percent`, CPU 테이블 index 포함 |
| 메모리 pool 식별 | CISCO-MEMORY-POOL-MIB::ciscoMemoryPoolName | `.1.3.6.1.4.1.9.9.48.1.1.1.2` | `pool_name` tag, pool suffix/index와 함께 사용 |
| 메모리 사용량 | CISCO-MEMORY-POOL-MIB::ciscoMemoryPoolUsed | `.1.3.6.1.4.1.9.9.48.1.1.1.5` | `pool_used_bytes`, Gauge32 bytes |
| 메모리 여유 | CISCO-MEMORY-POOL-MIB::ciscoMemoryPoolFree | `.1.3.6.1.4.1.9.9.48.1.1.1.6` | `pool_free_bytes`, Gauge32 bytes |
| 인터페이스 index / type | IF-MIB::ifIndex / ifType | `.1.3.6.1.2.1.2.2.1.1` / `.1.3.6.1.2.1.2.2.1.3` | 테이블 행 suffix가 ifIndex이므로 Telegraf `index` tag로 보존, `if_type`은 분류 라벨 |
| 인터페이스 이름·설명 | IF-MIB::ifName / ifAlias | `.1.3.6.1.2.1.31.1.1.1.1` / `.1.3.6.1.2.1.31.1.1.1.18` | `if_name`, `if_alias` tags |
| 인터페이스 admin·oper | IF-MIB::ifAdminStatus / ifOperStatus | `.1.3.6.1.2.1.2.2.1.7` / `.1.3.6.1.2.1.2.2.1.8` | `if_admin_status`, `if_oper_status` enum 정수 |
| 인터페이스 마지막 변화 | IF-MIB::ifLastChange | `.1.3.6.1.2.1.2.2.1.9` | `if_last_change_ticks`, TimeTicks |
| 수신 discard·error | IF-MIB::ifInDiscards / ifInErrors | `.1.3.6.1.2.1.2.2.1.13` / `.1.3.6.1.2.1.2.2.1.14` | Counter32 원시값 |
| 송신 discard·error | IF-MIB::ifOutDiscards / ifOutErrors | `.1.3.6.1.2.1.2.2.1.19` / `.1.3.6.1.2.1.2.2.1.20` | Counter32 원시값 |

테이블 설정은 Telegraf의 `inputs.snmp.table`에 OID를 지정하지 않고 수집할 컬럼만 개별 열거한다. 이 방식은 Telegraf가 테이블의 모든 열을 기본 수집하는 동작을 피한다. `index` tag에는 각 컬럼 OID의 행 suffix가 들어가며 인터페이스 테이블에서는 ifIndex 그 자체다. 이를 별도 IF-MIB get으로 중복 수집하지 않는다.

## P1 / P2 OID

| 등급 | 목적 | MIB 객체 / 숫자 OID | 주기 | 정책 |
|---|---|---|---|---|
| P1 | 주요 링크 수신 bytes | IF-MIB::ifHCInOctets `.1.3.6.1.2.1.31.1.1.1.6` | 60초 | ifAlias가 `Core:` 또는 `Transit:`로 시작하는 행만 Telegraf에서 전달 |
| P1 | 주요 링크 송신 bytes | IF-MIB::ifHCOutOctets `.1.3.6.1.2.1.31.1.1.1.10` | 60초 | 위와 동일 |
| P1 | 주요 링크 용량 | IF-MIB::ifHighSpeed `.1.3.6.1.2.1.31.1.1.1.15` | 60초 | Mbps. 필드명 `if_high_speed_mbps` |
| P1 | 센서 값과 해석 정보 | CISCO-ENTITY-SENSOR-MIB `entSensorType/Scale/Precision/Value/Status`: `.1.3.6.1.4.1.9.9.91.1.1.1.1.{1,2,3,4,5}` | 300초 | 3750X/3850만 현재 확인. 인덱스는 entPhysicalIndex |
| P1 | FRU 전원 상태 | CISCO-ENTITY-FRU-CONTROL-MIB::cefcFRUPowerOperStatus `.1.3.6.1.4.1.9.9.117.1.1.2.1.2` | 300초 | 3750X/3850에서 확인, entPhysical index와 결합 |
| P1 | 팬 상태 | CISCO-ENTITY-FRU-CONTROL-MIB::cefcFanTrayOperStatus `.1.3.6.1.4.1.9.9.117.1.4.1.1.1` | 300초 | 3750X/3850에서 확인, entPhysical index와 결합 |
| P1 | 부품명·종류 | ENTITY-MIB::entPhysicalName / entPhysicalClass `.1.3.6.1.2.1.47.1.1.1.1.7` / `.1.3.6.1.2.1.47.1.1.1.1.5` | 300초 | 센서·FRU 행 해석에 필요한 행만 결합 |
| P2 | 일일 장비 정적 정보 | `sysName`, `sysObjectID`, `sysDescr` 위 OID | 24시간 | 별도 discovery를 도입하면 그때 대체 가능 |
| P2 | 모델·serial | ENTITY-MIB::entPhysicalModelName / entPhysicalSerialNum `.1.3.6.1.2.1.47.1.1.1.1.13` / `.1.3.6.1.2.1.47.1.1.1.1.11` | 24시간/Discovery | 네 활성 모델에서 컬럼 응답 확인. 값이 비어 있는 entity는 무시하고 chassis/부품 이름과 index로 식별 |
| P2 | 스택 부품 식별 | ENTITY-MIB `entPhysicalName`, `entPhysicalClass`, model, serial | 24시간/Discovery | 표준 물리 인벤토리 테이블에서 수집. 상태 변화/stack role 전용 Cisco MIB는 검증 전까지 설정하지 않음 |

P1 링크에 중복된 Core alias가 붙은 Port-channel과 그 멤버가 함께 존재한다. 설정은 해당 ifAlias를 모두 전달하고 `if_type`, `if_name`을 같이 보존한다. 링크 이용률 대시보드는 Port-channel(`ifType=53`) 또는 멤버 포트 중 한 계층만 선택해 이중 합산하지 않는다. 물리 Ethernet(`ifType=6`), VLAN(`135`), Loopback(`24`), 논리 Port-channel(`53`)을 쿼리에서 분리한다. Stack의 물리 멤버는 `ifName`과 ENTITY-MIB index로 식별하며 ifType 하나만으로 추측하지 않는다.

## Telegraf 설정과 OpenObserve 스키마

- 공통 P0, Watched Port 트래픽, 일일 정적 정보: [`configs/telegraf/cisco-catalyst-snmp.conf`](../../configs/telegraf/cisco-catalyst-snmp.conf)
- 지원이 확인된 3750X/3850의 선택 하드웨어 센서: [`configs/telegraf/cisco-catalyst-hardware-snmp.conf`](../../configs/telegraf/cisco-catalyst-hardware-snmp.conf)
- CPU 1분 fallback: [`configs/telegraf/cisco-catalyst-snmp-cpu-1min-legacy.conf`](../../configs/telegraf/cisco-catalyst-snmp-cpu-1min-legacy.conf)
- CPU 5분 fallback: [`configs/telegraf/cisco-catalyst-snmp-cpu-5min-legacy.conf`](../../configs/telegraf/cisco-catalyst-snmp-cpu-5min-legacy.conf)
- Watched Port 수신 HC fallback: [`configs/telegraf/cisco-catalyst-snmp-counter32-in.conf`](../../configs/telegraf/cisco-catalyst-snmp-counter32-in.conf)
- Watched Port 송신 HC fallback: [`configs/telegraf/cisco-catalyst-snmp-counter32-out.conf`](../../configs/telegraf/cisco-catalyst-snmp-counter32-out.conf)
- 설정은 장비 한 대마다 재사용한다. 배포 쪽에서 `SNMP_AGENT`와 `DEVICE_ID`만 장비별로 렌더링하고, SHA/AES 자격 증명은 `switch_snmp` Docker secret store에서 읽는다. 공유 Telegraf 설정의 `outputs.opentelemetry`는 기존 OpenObserve endpoint/auth를 사용한다.
- P0/traffic 인터페이스 테이블은 필요한 컬럼만 요청한다. MAC, ARP, VLAN, 전체 패킷 상세 카운터, trap, 사용처가 없는 센서 테이블은 설정하지 않는다.
- 스위치 syslog는 기존 OTel Collector 경로에서 `system_logs`로 계속 들어온다. 이 Telegraf 설정에는 syslog 수신기를 중복 추가하지 않으며 SNMP trap도 설정하지 않는다.

OpenTelemetry 출력은 일반 Telegraf measurement를 `measurement_field` 메트릭명으로 보낸다. OpenObserve는 메트릭명별 stream을 만들고 대소문자를 소문자로 정규화한다. 리소스·태그는 라벨로 저장된다. 대표 이름과 값 계약:

| OpenObserve stream | 값·라벨 |
|---|---|
| `cisco_device_sys_uptime_ticks` | Gauge: 1/100초 uptime; `device_id`, `source` |
| `cisco_device_cpu_1min_percent`, `cisco_device_cpu_5min_percent` | Gauge: percent; `device_id`, `source`, CPU row index |
| `cisco_memory_pool_used_bytes`, `cisco_memory_pool_free_bytes` | Gauge: bytes; `device_id`, `pool_name`, pool index |
| `cisco_device_if_admin_status`, `cisco_device_if_oper_status` | Gauge: IF-MIB enum 정수; `device_id`, `index`(ifIndex), `if_name`, `if_alias`, `if_type` 라벨 |
| `cisco_device_if_last_change_ticks` | Gauge: TimeTicks; 동일 인터페이스 라벨 |
| `cisco_device_if_in_errors`, `cisco_device_if_out_errors`, `cisco_device_if_in_discards`, `cisco_device_if_out_discards` | 원시 Counter32; 동일 인터페이스 라벨 |
| `cisco_watched_port_interface_if_hc_in_octets`, `cisco_watched_port_interface_if_hc_out_octets` | 원시 Counter64 bytes; `Core:`/`Transit:` alias Watched Port만, `if_type` 라벨 포함 |
| `cisco_watched_port_interface_if_high_speed_mbps` | Gauge: Mbps; Watched Port만 |
| `cisco_sensor_sensor_value_raw` | Gauge 원시값; `sensor_type`, `sensor_scale`, `sensor_precision`, `sensor_status`, `physical_name`, physical index. 스케일을 적용한 값만 온도/전력 단위로 해석 |
| `cisco_sensor_fru_power_oper_status`, `cisco_sensor_fan_tray_oper_status` | 상태 enum 정수; `physical_name`, `physical_class`, physical index |
| `cisco_device_info_inventory_poll_success` | Gauge marker; 함께 붙은 `sys_name`, `sys_object_id`, `sys_descr` 라벨로 일일 모델 정보 식별 |
| `cisco_device_info_physical_class` | Gauge: ENTITY-MIB class enum; `physical_name`, `model_name`, `serial_number`, physical index 라벨. 문자열이 비어 있는 모델/serial 태그는 검색 키로 쓰지 않음 |
| `cisco_device_legacy_cpu_1min_percent`, `cisco_device_legacy_cpu_5min_percent` | 각 Rev leaf가 없는 장비에 대응하는 legacy 설정만 선택. `cpu_oid_set=legacy` 라벨 |
| `cisco_watched_port_interface_legacy_if_in_octets`, `cisco_watched_port_interface_legacy_if_out_octets` | 각 HC 방향 leaf가 없는 경우에만 대응 Counter32 설정 선택. `counter_width=32` 라벨 |

SNMP 장비 poll 성공은 매 60초 수신되는 `sys_uptime_ticks` stream의 존재로 판단한다. timeout일 때 0 값을 보내지 않으며, OpenObserve 알림은 각 장비의 마지막 성공 sample이 2분 이상 오래된 경우 발화하도록 만든다. Telegraf 내부 `gather_errors`는 collector 장애 분석에 보조로 쓰고 장비 성공 marker를 대신하지 않는다.

Counter는 Telegraf에서 rate로 변환하지 않고 원시값을 보낸다. 쿼리에서 연속 샘플과 실제 elapsed time으로 delta/rate를 계산한다. 새 값이 작아졌을 때 sysUpTime이 함께 작아지면 장비 재부팅/카운터 reset으로 판단하고 해당 구간은 버린 뒤 기준값을 다시 잡는다. uptime reset 없이 Counter32가 감소하면 modulo `2^32`, Counter64가 감소하면 modulo `2^64` wrap으로 계산한다. 결측 구간을 60초로 가정하거나 reset을 0 traffic으로 처리하지 않는다. 첫 샘플과 reset 직후 샘플은 rate 대신 baseline으로 취급한다.

## Fallback 정책

1. CPU: 1분 Rev `.1.3.6.1.4.1.9.9.109.1.1.1.1.8`와 5분 Rev `.1.3.6.1.4.1.9.9.109.1.1.1.1.9`를 각각 검증한다. 한 leaf가 미지원이면 해당 primary input만 빼고 1분용 `cisco-catalyst-snmp-cpu-1min-legacy.conf` (`.3`) 또는 5분용 `cisco-catalyst-snmp-cpu-5min-legacy.conf` (`.4`)만 추가한다. 다른 주기와 uptime/interface/memory 입력은 계속 둔다. 이번 활성 Catalyst에서는 두 Rev 모두 확인돼 fallback은 꺼 둔다.
2. Memory: `ciscoMemoryPoolName/Used/Free`를 기본으로 한다. 이번 네 모델에서는 3개 컬럼 모두 지원됐다. 미지원 모델은 지원을 먼저 walk로 확인한다. HOST-RESOURCES-MIB는 네 모델에서 미응답이라 대체로 쓰지 않는다. 다른 Cisco memory MIB는 의미와 pool 기준을 확인한 후에만 추가한다.
3. Watched Port traffic: ifHC Counter64 방향별 leaf를 따로 검증한다. `ifHCInOctets`가 없으면 수신 primary input만 빼고 `cisco-catalyst-snmp-counter32-in.conf`의 `ifInOctets` `.1.3.6.1.2.1.2.2.1.10`을 사용한다. `ifHCOutOctets`가 없으면 송신 primary input만 빼고 `cisco-catalyst-snmp-counter32-out.conf`의 `ifOutOctets` `.1.3.6.1.2.1.2.2.1.16`을 사용한다. 둘 다 Counter32 modulo `2^32`로 계산하며 나머지 방향과 `ifHighSpeed`는 primary로 유지한다. CPU fallback과 독립적으로 선택한다.
4. Temperature/FRU: 실제 응답한 3750X/3850만 선택 설정을 포함한다. 2960에서 해당 컬럼이 없을 때 임의 vendor OID로 대체하지 않고 하드웨어 환경 메트릭을 비운다.
5. SNMP 미응답: 0으로 대체하지 않는다. 마지막 성공 uptime sample의 부재를 poll 장애로 알린다.
6. 2960XR: 장비가 online이 되면 위 P0 핵심 컬럼부터 짧은 개별 walk를 수행하고 이 표를 갱신한다. 확인 전에는 2960G/S 결과를 XR 지원 근거로 간주하지 않는다.

## 제외 목록

- MAC address table, ARP table, VLAN 구성의 주기적 전체 조회
- 미사용 포트의 HC traffic 및 모든 포트의 상세 패킷 통계
- SNMP trap
- 사용처를 정하지 않은 센서·통계와 Entity-MIB 전체 walk
- `Driver text` memory pool
- 이미 수집되는 syslog와 중복되는 메시지 수준 SNMP 통계

## 참고 자료

- [Cisco SNMP Object Navigator 도움말](https://www.cisco.com/c/en/us/support/web/tools/snmp/help/index.html): MIB 객체 의미와 소프트웨어 이미지별 지원 확인 절차
- [Cisco Catalyst 2960/2960-S 지원 MIB 목록](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960/software/release/12-2_53_se/configuration/guide/2960scg/swmibs.pdf)
- [Cisco CISCO-ENTITY-SENSOR-MIB 객체 안내](https://www.cisco.com/c/en/us/td/docs/ios_xr_sw/iosxr_r3-9-1/mib/guide/crs-gsr_mib3.pdf)
- [Telegraf SNMP input 설정](https://github.com/influxdata/telegraf/blob/master/plugins/inputs/snmp/README.md): table 컬럼을 생략하면 전체 열을 수집하므로 이 구성은 필요한 컬럼만 나열함
- [Telegraf OpenTelemetry output 스키마](https://github.com/influxdata/telegraf/blob/master/plugins/outputs/opentelemetry/README.md): measurement/field 이름과 tag 기반 속성 변환
- OpenObserve의 OTLP metrics 이름·라벨 계약: [`openobserve-otlp-traces-metrics-contract.md`](openobserve-otlp-traces-metrics-contract.md)
