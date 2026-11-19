# Host Audit 스위치 점검 — KISA-2026 N 항목 적용 표

Spec #568(Host Audit에 스위치 취약점 점검 포함)의 Ticket-1 산출물이다. KISA-2026 「주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」 V장(네트워크 장비) N-01~N-38 38개 항목 중 Cisco IOS 스위치(`cisco_switches` 인벤토리)에 무엇을 적용하고, 무엇이 "해당없음"·"점검불가"인지 항목마다 적는다. Ticket-3·4의 판정 함수는 이 표만 보고 짤 수 있어야 한다.

상태: **초안, 운영자 검수 전.** 검수 전에는 병합하지 않는다. 판단 근거는 가이드의 항목별 판단 기준·조치 방법(IOS 명령)을 요약한 것이며 원문을 옮기지 않는다. 이 저장소는 공개라 장비 IP·관리번호·모델별 취약 현황·점검 결과는 적지 않는다(결과는 보고서와 비공개 자료에만 둔다).

## 1. 판정 규칙

### 읽기 전용 명령

스위치에 보내는 명령은 `show running-config`와 `show version` 두 개뿐이다. 가이드가 확인용으로 드는 다른 조회 명령(상태·통계 조회류)은 쓰지 않고 running-config 줄로 대신 판정한다. 그래서 running-config에 드러나지 않는 정보는 "점검불가"가 된다. 설정을 바꾸는 명령과 `enable` 이후의 쓰기 동작은 없다.

### L2/L3 판정

장비 역할은 인벤토리 변수를 새로 두지 않고 `show running-config` 출력에서 판정한다.

- **L3**: `ip routing` 줄이 있거나(`no ip routing`이 아님), 라우팅 인터페이스가 하나라도 있으면 L3이다. 라우팅 인터페이스는 `ip address <주소> <마스크>` 줄이 있는 SVI(`interface Vlan*`), 라우티드 포트(`no switchport`), Loopback·Tunnel 인터페이스를 말하며, 모두 `ip address <주소> <마스크>` 줄이 있어야 센다. `no ip address`이거나 주소 줄이 없는 인터페이스는 세지 않는다.
- **L2**: 위 조건에 하나도 해당하지 않으면 L2이다.
- 표의 L2·L3 열은 그 역할일 때의 처리다. 한 장비는 둘 중 하나의 열만 따른다.
- "L3 인터페이스"라고 쓴 곳은 위 라우팅 인터페이스를 뜻한다.

### 상태 값

L2·L3 열은 `적용`, `해당없음`, `점검불가` 중 하나다.

- `적용`: 판정 함수가 양호/취약을 낸다. (예외(승인)는 Host Audit의 기존 예외 규칙이 처리한다.) 대상 구성요소가 장비에 없어 개별 장비에서 해당없음이 되는 경우(예: N-09의 AUX 포트 없는 기종)는 표 상태가 아니라 장비별 결과로 낸다.
- `해당없음`: 그 역할에는 의미 없는 항목이다. 사유 열에 한 줄로 적는다.
- `점검불가`: 허용된 두 명령으로는 알 수 없다. 사유 열에 한 줄로 적고 보고서에는 "점검불가(수동 확인)"로 올린다. 항목을 빼지 않는다.

### 공통 해석 규칙

running-config는 기본값 그대로인 기능을 줄로 보여 주지 않는다. 그래서 다음처럼 판정한다.

- 기본으로 켜져 있는 기능은 `no ...` 줄이 있어야 양호이고, 줄이 없으면 취약이다(예: `no ip source-route`, `no ip http server`).
- 기본으로 꺼져 있는 기능은 켜는 줄이 있으면 취약이고, 줄이 없으면 양호이다(예: `tftp-server`, `ip finger`).
- 기본값은 IOS 12.2 이상 기준이다. 가이드가 이전 버전에서 기본값이 다르다고 밝힌 항목(N-26, N-28, N-35)은 `show version`의 버전이 12.2보다 낮으면 줄 부재로 양호를 주지 않고 점검불가로 내린다.
- 값 판정이 필요한 줄(SNMP community 등)은 판정만 남기고 값 자체를 결과 JSON·보고서·로그에 쓰지 않는다.

### 항목별 고정 규칙

- **N-12(패치)**: 버전 문자열만 수집하고 판정은 "점검불가(수동 확인)"로 고정한다. 벤더 권고·EoL을 조회할 출처가 아직 정해지지 않았다.
- **N-08(VTY 안전한 프로토콜)**: 점검 수집 세션이 Telnet이었다면 설정과 무관하게 이 항목은 "취약"이다. Telnet 접속 자체가 원격 접속 암호화 위반이기 때문이다.
- **N-24(미사용 인터페이스)**: 포트가 쓰이는지는 링크 상태로만 알 수 있어 점검불가이다.

## 2. 적용 표

열: 중요도는 가이드의 (상)(중)(하) 표기다. 판정 근거는 판정에 읽는 줄 또는 출력이다. 사유는 해당없음·점검불가일 때만 적고, L2·L3 둘 다 적용이면 `-`이다. 취약 판정 조건은 어떤 줄이 있으면 또는 없으면 취약인지의 한 줄 요약이다. "블록"은 `line vty`·`line con`·`interface` 같은 설정 구역을 뜻하고, 가이드가 말하는 `login`·`transport` 등은 그 블록 안의 줄이다.

| 항목 코드 | 항목명 | 중요도 | 분류 | L2 | L3 | 판정 근거 | 사유 | 취약 판정 조건 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| N-01 | 비밀번호 설정 | 상 | 계정 | 적용 | 적용 | running-config의 enable secret·enable password 줄, line con·vty 블록의 login·login local·login authentication·no login 줄, aaa authentication login 줄 | - | enable secret·enable password가 둘 다 없음, 또는 line con·vty 블록에 no login이 있음, 또는 line con 블록에 login 계열 줄도 aaa authentication login 줄도 없음. 비밀번호 값이 출고 기본값인지는 설정에서 읽을 수 없어 판정에서 제외하고 한계로 보고서에 적음 |
| N-02 | 비밀번호 복잡성 설정 | 상 | 계정 | 적용 | 적용 | running-config의 security passwords min-length 줄 | - | security passwords min-length 줄이 없거나 값이 8 미만. 기준값 8은 기관 정책 미확정 상태의 잠정값이며 정책이 정해지면 상수 하나로 바꾼다 |
| N-03 | 암호화된 비밀번호 사용 | 상 | 계정 | 적용 | 적용 | running-config의 service password-encryption, enable secret·enable password, username ... secret·password 줄 | - | service password-encryption 줄이 없거나 no가 붙음, 또는 enable secret이 없음, 또는 enable secret·username 비밀번호가 평문 표기(유형 0 또는 유형 표기 없는 password) |
| N-04 | 계정 잠금 임계값 설정 | 상 | 계정 | 적용 | 적용 | running-config의 login block-for ... attempts N within ... 줄 | - | login block-for 줄이 없거나 attempts 값이 5 초과. 점검 계정이 잠기지 않게 login quiet-mode access-class로 관리 서버를 예외로 두는 것은 양호를 해치지 않음 |
| N-05 | 사용자·명령어별 권한 설정 | 중 | 계정 | 적용 | 적용 | running-config의 username ... privilege N 줄, aaa authorization exec 줄 | - | 로컬 계정이 둘 이상인데 전부 privilege 15(또는 권한 미지정으로 enable 공용)면 취약. 계정이 하나면 가이드 예외로 양호. 로컬 계정이 없고 aaa authorization exec도 없으면 취약 |
| N-06 | VTY 접근(ACL) 설정 | 상 | 접근 | 적용 | 적용 | running-config의 line vty 블록의 access-class ... in 줄과 그 ACL 정의 | - | line vty 블록 중 하나라도 access-class in이 없음, 또는 가리키는 ACL이 설정에 없음, 또는 ACL이 전체 허용(permit any 류). transport input none인 블록은 원격 접속이 없어 제외 |
| N-07 | Session Timeout 설정 | 상 | 접근 | 적용 | 적용 | running-config의 line con·vty(·aux) 블록의 exec-timeout 분 초 줄 | - | 블록에 exec-timeout 줄이 없음(기본값에 기대지 않고 명시를 요구), 또는 0 0, 또는 총 시간이 10분 초과 |
| N-08 | VTY 접속 시 안전한 프로토콜 사용 | 중 | 접근 | 적용 | 적용 | running-config의 line vty 블록의 transport input 줄, ip ssh version 줄, show version의 이미지 이름(k9 표기) | - | 수집 세션이 Telnet이었다면 설정과 무관하게 취약(Telnet 접속 자체), 또는 line vty 블록에 transport input 줄이 없거나 telnet·all이 포함됨, 또는 ip ssh version 2 줄이 없음. 이미지에 k9 표기가 없어 SSH를 쓸 수 없으면 취약 |
| N-09 | 불필요한 보조 입출력 포트 사용 금지 | 중 | 접근 | 적용 | 적용 | running-config의 line aux 블록의 transport input none·no exec·exec-timeout·no password 줄 | - | line aux 블록이 있는데 transport input none과 no exec 어느 쪽도 없음. line aux 블록이 아예 없으면 장비 판정은 해당없음(AUX 포트 없는 기종) |
| N-10 | 로그인 시 경고 메시지 설정 | 중 | 접근 | 적용 | 적용 | running-config의 banner login·motd·exec 블록 본문 | - | banner login·motd·exec 중 어느 것도 없음, 또는 본문에 호스트명·모델·IOS 버전 같은 시스템 정보를 쓰는 변수($(hostname) 등)나 문구가 있음 |
| N-11 | 원격로그 서버 사용 | 중 | 접근 | 적용 | 적용 | running-config의 logging host 줄(구형 표기 logging <주소>), logging on 줄 | - | logging host(또는 logging <주소>) 줄이 하나도 없음, 또는 no logging on |
| N-12 | 주기적 보안 패치 및 벤더 권고사항 적용 | 상 | 패치 | 점검불가 | 점검불가 | show version의 소프트웨어 버전 문자열(수집만 함) | 벤더 권고·EoL 조회 출처가 정해지지 않아 버전만 수집하고 판정은 점검불가(수동 확인)로 고정 | 판정하지 않음(항상 점검불가(수동 확인)). 버전 문자열만 결과에 남김 |
| N-13 | 로깅 버퍼 크기 설정 | 중 | 로그 | 적용 | 적용 | running-config의 logging buffered 크기 줄 | - | logging buffered 줄이 없거나 크기 미지정(기본값이 작음)이거나 16000 바이트 미만, 또는 no logging buffered |
| N-14 | 정책에 따른 로깅 설정 | 중 | 로그 | 적용 | 적용 | running-config의 logging on, logging trap·buffered 수준 줄 | - | no logging on, 또는 logging trap 수준이 informational보다 낮은 상세(emergencies~notifications), 또는 logging trap 줄이 있는데 그 수준이 잘못된 값. 기준 수준 informational은 기관 로그 정책이 없을 때의 가이드 예시값 |
| N-15 | NTP 및 시각 동기화 설정 | 중 | 로그 | 적용 | 적용 | running-config의 ntp server·ntp peer 줄, show version의 버전(12.2 미만 구분용) | - | ntp server·ntp peer 줄이 없음(버전과 무관하게 취약). ntp access-group은 버전이 12.2 미만일 때만 보며, 그때 ntp 줄은 있는데 ntp access-group이 없으면 점검불가이고 12.2 이상이면 ntp access-group은 묻지 않음 |
| N-16 | Timestamp 로그 설정 | 하 | 로그 | 적용 | 적용 | running-config의 service timestamps log 줄 | - | service timestamps log datetime 줄이 없음(uptime 방식이거나 no service timestamps log 포함). msec·localtime·show-timezone 옵션은 묻지 않음 |
| N-17 | SNMP 서비스 확인 | 상 | 기능 | 적용 | 적용 | running-config의 snmp-server community·user·group·host 줄 | - | snmp-server 관련 줄이 하나라도 있으면 취약. 운영상 사용이 승인된 장비는 Host Audit의 예외(승인) 규칙으로 양호 처리하며 판정 함수는 승인 여부를 알지 못함 |
| N-18 | SNMP Community String 복잡성 설정 | 상 | 기능 | 적용 | 적용 | running-config의 snmp-server community <문자열> 줄 | - | community 줄이 있고 문자열이 public·private이거나 대소문자·숫자·특수문자 중 3종 미만 또는 8자 미만. community 줄이 없으면 양호. 문자열 값은 결과에 남기지 않음 |
| N-19 | SNMP ACL 설정 | 상 | 기능 | 적용 | 적용 | running-config의 snmp-server community ... <ACL> 줄(또는 v3 group의 access 줄)과 그 ACL 정의 | - | community 줄 중 하나라도 ACL 번호·이름이 없음, 또는 가리키는 ACL이 설정에 없음, 또는 v3 group에 access가 없음. SNMP 줄이 하나도 없으면 양호 |
| N-20 | SNMP Community 권한 설정 | 상 | 기능 | 적용 | 적용 | running-config의 snmp-server community ... RO·RW 줄 | - | community 줄 중 하나라도 RW. RW가 없으면 양호(SNMP 줄이 없는 경우 포함) |
| N-21 | TFTP 서비스 차단 | 상 | 기능 | 적용 | 적용 | running-config의 tftp-server 줄 | - | tftp-server 줄이 있음. 단 줄 끝에 ACL이 붙어 있으면 가이드의 ACL 허용 범위로 양호 |
| N-22 | Spoofing 방지 필터링 적용 | 상 | 기능 | 해당없음 | 적용 | running-config의 L3 인터페이스 블록의 ip access-group ... in, 그 ACL의 특수 용도 대역(사설·루프백·링크 로컬·문서용·멀티캐스트) deny 항목, ip verify unicast source reachable-via 줄 | L2 해당없음: 경계 구간 인터페이스에 거는 필터라 IP를 전달하지 않는 L2 스위치에는 의미가 없음 | L3 인터페이스 중 어느 곳에도 특수 용도 대역을 deny하는 ACL(입력 방향)이나 uRPF 줄이 없음. 경계 구간이 아닌 장비는 Host Audit의 예외(승인) 규칙으로 처리 |
| N-23 | DDoS 공격 방어 설정 또는 DDoS 장비 사용 | 상 | 기능 | 해당없음 | 점검불가 | running-config의 rate-limit·police·ip tcp intercept 줄(참고용으로만 읽음) | L2 해당없음: 경계 라우터의 IP 전달 방어 설정이라 L2에는 의미가 없음. L3 점검불가: 경계 라우터 여부와 별도 DDoS 장비 운용은 설정으로 알 수 없음(수동 확인) | L3도 판정하지 않음(항상 점검불가(수동 확인)). 방어 설정 줄이 보이면 참고로만 남김 |
| N-24 | 사용하지 않는 인터페이스 비활성화 | 상 | 기능 | 점검불가 | 점검불가 | running-config의 interface 블록의 shutdown 줄(참고용) | 포트가 쓰이는지는 링크 상태와 연결 장비로만 알 수 있고 허용된 두 명령으로는 알 수 없어 수동 확인으로 둠 | 판정하지 않음(항상 점검불가(수동 확인)). shutdown이 없는 물리 포트 수는 참고 정보로만 남길 수 있음 |
| N-25 | TCP Keepalive 서비스 설정 | 중 | 기능 | 적용 | 적용 | running-config의 service tcp-keepalives-in·out 줄 | - | service tcp-keepalives-in 또는 service tcp-keepalives-out 줄이 없음 |
| N-26 | Finger 서비스 차단 | 중 | 기능 | 적용 | 적용 | running-config의 ip finger·service finger 줄, show version의 버전(12.2 미만 구분용) | - | ip finger 또는 service finger 줄이 있음(no가 붙은 줄은 양호). 버전이 12.2 미만이면 줄 부재로 양호를 주지 않고 점검불가 |
| N-27 | 웹 서비스 차단 | 중 | 기능 | 적용 | 적용 | running-config의 ip http server·ip http secure-server 줄과 ip http access-class 줄 | - | ip http server 또는 ip http secure-server 줄이 켜져 있고 ip http access-class로 접속 IP 제한도 없음. no ip http server와 no ip http secure-server 둘 다 있으면 양호 |
| N-28 | TCP/UDP small 서비스 차단 | 중 | 기능 | 적용 | 적용 | running-config의 service tcp-small-servers·udp-small-servers 줄, show version의 버전(12.2 미만 구분용) | - | service tcp-small-servers 또는 service udp-small-servers 줄이 켜져 있음(no가 붙은 줄은 양호). 버전이 12.2 미만이면 줄 부재로 양호를 주지 않고 점검불가 |
| N-29 | Bootp 서비스 차단 | 중 | 기능 | 적용 | 적용 | running-config의 no ip bootp server, ip dhcp bootp ignore 줄 | - | no ip bootp server 줄도 ip dhcp bootp ignore 줄도 없음(기본으로 켜져 있어 줄 부재가 취약) |
| N-30 | CDP 서비스 차단 | 중 | 기능 | 적용 | 적용 | running-config의 no cdp run 줄, interface 블록의 no cdp enable 줄 | - | no cdp run 줄이 없고, 있어도 cdp run이 켜진 채 일부 인터페이스에만 no cdp enable이 있는 경우. 음성(IP 전화기) 용도로 승인된 장비는 예외(승인) 규칙으로 처리 |
| N-31 | Directed-broadcast 차단 | 중 | 기능 | 해당없음 | 적용 | running-config의 L3 인터페이스 블록의 ip directed-broadcast 줄 | L2 해당없음: 서브넷 사이 IP 전달에서만 생기는 기능이라 라우팅하지 않는 L2에는 의미가 없음 | L3 인터페이스 블록에 ip directed-broadcast 줄이 있음(no가 붙은 줄이나 줄 부재는 양호) |
| N-32 | Source Routing 차단 | 중 | 기능 | 해당없음 | 적용 | running-config의 no ip source-route 줄 | L2 해당없음: IP 패킷을 전달하지 않는 L2에는 의미가 없음 | no ip source-route 줄이 없음(기본으로 켜져 있어 줄 부재가 취약) |
| N-33 | Proxy ARP 차단 | 중 | 기능 | 해당없음 | 적용 | running-config의 L3 인터페이스 블록의 no ip proxy-arp 줄 | L2 해당없음: 라우팅 인터페이스가 없으면 Proxy ARP 응답 주체가 아님 | L3 인터페이스 중 하나라도 no ip proxy-arp 줄이 없음(기본으로 켜져 있음) |
| N-34 | ICMP unreachable, redirect 차단 | 중 | 기능 | 해당없음 | 적용 | running-config의 L3 인터페이스 블록의 no ip unreachables·no ip redirects 줄 | L2 해당없음: 라우팅 인터페이스가 없으면 ICMP unreachable·redirect를 만들지 않음 | L3 인터페이스 중 하나라도 no ip unreachables 또는 no ip redirects 줄이 없음. Null 인터페이스는 no ip unreachables만 요구 |
| N-35 | identd 서비스 차단 | 중 | 기능 | 적용 | 적용 | running-config의 ip identd 줄, show version의 버전(12.2 미만 구분용) | - | ip identd 줄이 있음(no ip identd 표시는 없어도 정상). 버전이 12.2 미만이면 줄 부재로 양호를 주지 않고 점검불가 |
| N-36 | Domain Lookup 차단 | 중 | 기능 | 적용 | 적용 | running-config의 no ip domain-lookup·no ip domain lookup 줄 | - | 두 표기 중 어느 줄도 없음(기본으로 켜져 있어 줄 부재가 취약) |
| N-37 | pad 차단 | 중 | 기능 | 적용 | 적용 | running-config의 no service pad 줄 | - | no service pad 줄이 없음(기본으로 켜져 있어 줄 부재가 취약) |
| N-38 | mask-reply 차단 | 중 | 기능 | 해당없음 | 적용 | running-config의 L3 인터페이스 블록의 ip mask-reply 줄 | L2 해당없음: 서브넷마스크를 응답할 라우팅 인터페이스가 없음 | L3 인터페이스 블록에 ip mask-reply 줄이 있음(기본으로 꺼져 있어 줄 부재는 양호) |

## 3. 검수 때 확인할 판단

운영자가 표를 검수할 때 특히 봐야 하는 판단이다. 이 목록은 검수가 끝나면 지우거나 결정 결과로 바꾼다.

1. **L2 판정이 거의 없어질 수 있다.** 규칙대로면 관리용 SVI에 IP 하나만 있어도 L3이다. 순수 L2 스위치도 관리 주소가 SVI에 있으면 L3으로 분류돼 N-22, N-31~N-34, N-38이 적용된다. 관리용 SVI만 있는 장비를 L2로 볼지 정하려면 규칙을 고쳐야 한다.
2. **L2 해당없음 항목**: N-22(스푸핑 필터), N-23(DDoS), N-31(directed-broadcast), N-32(source routing), N-33(proxy ARP), N-34(ICMP unreachable·redirect), N-38(mask-reply). 근거는 모두 "L3 인터페이스에서 IP를 전달할 때만 생기는 기능"이다. 같은 이유로 N-29(bootp)는 L2에도 두었다(관리 IP가 있는 L2에서도 bootp 응답 가능).
3. **N-22 L3 적용**: 경계 구간 여부를 설정으로 알 수 없어 내부 L3 스위치는 대부분 취약이 나온다. 점검불가로 내릴지 예외(승인)로 처리할지 정해야 한다.
4. **N-17 SNMP**: SNMP가 켜져 있으면 일단 취약이고 승인은 예외 규칙으로 처리한다. 모니터링에 SNMP를 쓰는 장비가 많으면 예외가 많아진다.
5. **N-02 기준값 8, N-14 기준 수준 informational**: 기관 정책 값이 확인되지 않아 잠정값이다.
6. **N-01의 한계**: 비밀번호 값이 출고 기본값인지는 판정하지 않는다. 인증 설정 유무만 본다.
7. **N-24 점검불가**: 포트 사용 여부를 알 방법이 허용 명령에 없다.
8. **기본값 가정**: 줄 부재로 판정하는 항목은 IOS 12.2 이상 기본값을 기준으로 삼았다. 더 낮은 버전은 점검불가로 내리는 규칙(1절)이 합당한지 본다.
