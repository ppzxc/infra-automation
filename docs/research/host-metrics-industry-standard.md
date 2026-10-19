# 업계 표준 호스트 메트릭 수집 대상과 우리 hostmetrics에 더할 후보

- 질문: [#241](https://github.com/ppzxc/infra-automation/issues/241) (상위 map [#239](https://github.com/ppzxc/infra-automation/issues/239)). Host Agents의 otelcol은 hostmetrics 스크레이퍼 8종의 기본 메트릭만 수집한다. OTel semantic conventions와 주요 업체(Datadog Agent, node_exporter, Metricbeat, Google Cloud Ops Agent, New Relic Infrastructure)는 기본으로 무엇을 수집하나? 무엇을 더할지 메트릭 이름 단위로 후보를 고르고 가치와 비용을 적는다. **결정은 하지 않는다.**
- 조사일: 2026-10-19
- 확인한 버전
  - otelcol-contrib hostmetrics receiver: 태그 **v0.161.0**(modern·legacy_el7)과 **v0.119.0**(legacy_el6). 각 스크레이퍼의 `metadata.yaml`, `generated_config.go`, `*_linux.go`를 직접 읽었다. 배포판 구성은 opentelemetry-collector-releases의 같은 태그 `manifest.yaml`.
  - OTel semantic conventions: `main` @ `331541c` (최신 릴리스 v1.44.0 이후). Context7 `/open-telemetry/semantic-conventions`로 교차 확인.
  - node_exporter: v1.12.1 README와 `collector/*_linux.go`.
  - Datadog Agent: `DataDog/datadog-agent` `main` @ `aae41b0`의 `cmd/agent/dist/conf.d/*.d/conf.yaml.default`와 Go 코어 체크 소스, `DataDog/integrations-core`의 Python network 체크.
  - Metricbeat: `elastic/beats` `main` @ `1b199f6`의 `metricbeat/modules.d/system.yml`.
  - Google Cloud Ops Agent: `GoogleCloudPlatform/ops-agent` `master` @ `d6fa4ee`의 `apps/hostmetrics.go`, `confgenerator/built-in-config-linux.yaml`, 생성 결과 골든 파일. 사용률 계산은 `opentelemetry-operations-collector` @ `5faae1b`의 `agentmetricsprocessor`.
  - New Relic Infrastructure agent: `newrelic/infrastructure-agent` `master` @ `3bdc564`의 `pkg/metrics/**`, 공식 문서 "Default infrastructure monitoring data".
- 방법: 업스트림 소스와 공식 문서만 근거로 썼다. 운영 서버는 조회하지 않았다. 시계열 수는 소스의 속성 정의로 계산한 **추정치**이고 실측이 아니다.
- 우리 쪽 문맥: `roles/monitoring/defaults/main.yml`(`otel_hostmetrics_scrapers`, 간격 60s), `roles/monitoring/vars/main.yml`(버전 표), `roles/monitoring/templates/otelcol-contrib.yaml.j2`, `roles/monitoring/templates/otelcol-contrib.service.j2`, `roles/openobserve_config/defaults/main.yml`과 `filter_plugins/openobserve_config.py`(리소스 알림), ADR-0006 §2.3, [openobserve-metric-absence-alerts.md](openobserve-metric-absence-alerts.md), [host-agents-os-compat-matrix.md](host-agents-os-compat-matrix.md).

## TL;DR

1. **우리가 가진 8종은 업계 기본값의 "뼈대"와 같다.** CPU 시간, 메모리, 디스크 I/O, 파일시스템 용량·inode, load, NIC 트래픽·오류·드롭, 스왑, 프로세스 수는 다섯 업체가 모두 기본으로 수집하고, OTel semconv에서도 recommended다. 빠진 것은 크게 세 갈래다.
   - **값은 있는데 꺼 둔 것(hostmetrics 선택 메트릭)**: 업체 대부분이 기본으로 내는 **사용률(%) 게이지**(CPU·메모리·파일시스템·스왑), **부팅 이후 시간(`system.uptime`)**, **conntrack 테이블 사용량**.
   - **스크레이퍼를 꺼 둔 것**: 프로세스별 메트릭(`process`). Ops Agent는 기본으로 켜고, Metricbeat는 상위 N개만 켜며, New Relic·Datadog·node_exporter는 기본으로 끈다. 업계 기본값이 갈리는 유일한 항목이다.
   - **hostmetrics로는 아예 만들 수 없는 것**: TCP 재전송·listen 큐 넘침, 시스템 전체 파일 핸들, 시각 동기(NTP), PSI, RAID(mdadm)·하드웨어 센서. node_exporter와 Datadog은 기본으로 수집한다. 예전 node_exporter에서 otelcol로 옮기며 잃은 신호다(`cleanup_legacy_node_exporter`).
2. **싸고 가치가 큰 후보**는 다음 다섯이다. 모두 호스트당 1~10개 시계열이고 0.119.0과 0.161.0에 모두 있다.
   - `system.uptime`: `system` 스크레이퍼를 추가한다. 재부팅을 탐지한다.
   - `system.linux.memory.available`과 `system.memory.limit`: 메모리 알림의 분모와 분자를 버전과 무관하게 맞춘다.
   - `system.network.conntrack.count`/`.max`: Docker·NAT 호스트의 테이블 포화를 본다.
   - `system.cpu.utilization`: 0.161.0에서는 8개 시계열이다.
3. **비싼 후보는 `process` 스크레이퍼 하나다.** 프로세스 수 × 약 7개 시계열에 pid·command_line 리소스 속성이 붙는다. 프로세스가 바뀔 때마다 시계열도 바뀐다. modern 경로는 비root(`CAP_DAC_READ_SEARCH`만)로 돌기 때문에 다른 사용자 프로세스의 I/O와 exe를 읽지 못해 오류가 날 것으로 예상된다. 켜려면 이름 include 목록과 mute 플래그를 함께 써야 하고, ADR-0006 §2.3(`process` 비활성)도 개정해야 한다.
4. **조사 중 나온 부수 발견**은 이번 범위 밖이며 고치지 않았다. 각각 별도 이슈로 다룰 만하다.
   - **(a) 메모리 `used` 계산식이 경로마다 다르다.** 0.161.0은 feature gate `receiver.hostmetricsreceiver.UseLinuxMemAvailable`(beta, 기본 켜짐)에 따라 `used = Total − MemAvailable`로 계산한다. 0.119.0(EL6)은 `used = Total − Free − Buffers − Cached`로 계산한다. 0.161.0에서는 `state` 값들을 더해도 Total이 되지 않는다. 그래서 `infra-memory-usage-*` 알림의 분모(`state <> 'slab_unreclaimable'`의 합)가 MemTotal과 다르고, 그 차이도 경로마다 다르다(§4.1).
   - **(b) CPU 메트릭의 `cpu` 속성 기본값이 바뀌었다.** 0.161.0(v0.157.0부터)은 `system.cpu.time`·`system.cpu.utilization`이 기본으로 `cpu` 속성 없이 state별로 합산된다. 0.119.0은 CPU별로 낸다. 같은 스트림 안에서 EL6 호스트만 행 모양이 다르다.
   - **(c) `system.cpu.logical.count`는 이미 수집 중이다.** 0.161.0(v0.157.0부터)에서 기본으로 켜져 modern·EL7은 이미 이 메트릭을 보낸다. EL6은 보내지 않는다.
   - **(d) 리시버 타입 이름이 바뀌었다.** 0.161.0에서 리시버 타입은 `host_metrics`이고 우리 설정의 `hostmetrics`는 deprecated 별칭이다(v0.151.0부터).
   - **(e) semconv v1 이름으로 바꾸는 gate가 생겼다.** v0.160.0부터 alpha gate `receiver.hostmetrics.EmitV1SystemConventions`/`DontEmitV0SystemConventions`가 있다. 켜면 메트릭 이름이 바뀌어 OpenObserve 스트림이 갈라진다. EL6(0.119.0)은 영원히 옛 이름만 낸다.

## 1. 우리 현재 상태 (기준선)

`otel_hostmetrics_scrapers`는 `cpu, memory, disk, filesystem, load, network, paging, processes`를 모두 `{}`로 둔다. 그래서 각 스크레이퍼의 `enabled: true` 메트릭만 나온다. 수집 간격은 60s다. OpenObserve는 메트릭 이름마다 스트림을 하나 만든다(ADR-0006 §2.7). 따라서 **새 메트릭 이름 하나는 새 스트림 하나**다.

| 경로 | 버전 | 실행 권한 | 커널 |
|---|---|---|---|
| modern | 0.161.0 | 비root `otelcol` + `CAP_DAC_READ_SEARCH` (`otelcol-contrib.service.j2`) | 최신 |
| legacy_el7 | 0.161.0 | root | 3.10 |
| legacy_el6 | 0.119.0 | root (SysV init) | 2.6.32 |

`vars/main.yml`의 `host_agents_version_row`는 EL6만 0.119.0을 쓰고 EL7은 default 행(0.161.0)을 쓴다. 따라서 "0.119.0 대 0.161.0"과 "legacy 대 modern"은 같은 축이 아니다. 버전은 메트릭이 있는지를 결정하고, 권한은 `process` 스크레이퍼가 동작하는지를 결정한다.

기본 메트릭과 호스트당 시계열 수(추정)는 아래와 같다. C=논리 CPU 수, D=디스크 장치 수, M=마운트 수, I=NIC 수, S=스왑 장치 수.

| 스크레이퍼 | 기본 메트릭 | 시계열 (0.161.0) | 0.119.0과 차이 |
|---|---|---|---|
| cpu | `system.cpu.time`(state 8), `system.cpu.logical.count` | 8 + 1 | `time`이 C×8, `logical.count` 없음 |
| memory | `system.memory.usage`(Linux에서 state 6개 기록) | 6 | `used` 계산식 다름 (§4.1) |
| load | `system.cpu.load_average.{1m,5m,15m}` | 3 | 같음 |
| disk | `io`, `operations`, `merged`, `operation_time`(각 direction 2), `io_time`, `pending_operations`, `weighted_io_time` | 11×D | 같음 |
| filesystem | `usage`, `inodes.usage`(각 state 3) | 6×M | 같음 |
| network | `io`, `packets`, `errors`, `dropped`(각 direction 2), `connections`(tcp × 상태) | 8×I + 약 12 | 같음 |
| paging | `faults`(2), `operations`(4), `usage`(3×S) | 6 + 3×S | 같음 |
| processes | `system.processes.count`(status), `system.processes.created` | 수 개 | 같음 |

출처: [cpu v0.161.0][c161-cpu] / [v0.119.0][c119-cpu], [memory][c161-mem], [disk][c161-disk], [filesystem][c161-fs], [load][c161-load], [network][c161-net], [paging][c161-paging], [processes][c161-procs]; CPU 속성 기본값은 [cpu `generated_config.go` v0.161.0][c161-cpu-gencfg] (`SystemCPUTime` 기본 `EnabledAttributes: [state]`, `AggregationStrategy: sum`)와 [CHANGELOG v0.157.0 #49161, #49325][contrib-cl].

파일시스템 기본값(`include_virtual_filesystems: false`)은 gopsutil `Partitions(all=false)`를 거친다. 이 경로는 `/proc/filesystems`에서 `nodev` 표시가 있는 유형(tmpfs, overlay 등)을 걸러낸다([gopsutil `disk_linux.go`][gopsutil-disk]). 그래서 Docker overlay 마운트 때문에 M이 폭증하지는 않는다. node_exporter는 같은 문제를 정규식(`/var/lib/docker/.+`, `overlay` 등)으로 거른다([filesystem_linux.go][ne-fs]).

## 2. 업계 기본값 비교

### 2.1 OTel semantic conventions (system·process)

[`docs/system/system-metrics.md`][semconv-sys] 기준이다. 모든 system 메트릭의 stability는 **development**다. process 메트릭은 대부분 **release candidate**다([process-metrics.md][semconv-proc]).

| 영역 | recommended | opt-in |
|---|---|---|
| 일반 | `system.uptime` | |
| CPU | `system.cpu.time`, `system.cpu.logical.count`, `system.cpu.physical.count`, `system.cpu.frequency` | `system.cpu.utilization` |
| 메모리 | `system.memory.usage`, `system.memory.utilization`, `system.memory.linux.slab.usage` | `system.memory.limit`, `system.memory.linux.shared` |
| 스왑 | `system.paging.usage`, `.utilization`, `.faults`, `.operations` | |
| 디스크 | `system.disk.io`, `.operations`, `.io_time`, `.operation_time`, `.merged` | `system.disk.limit` |
| 파일시스템 | `system.filesystem.usage`, `system.filesystem.utilization` | `system.filesystem.limit` |
| 네트워크 | `system.network.io`, `.errors`, `.packet.count`, `.packet.dropped`, `.connection.count` | |
| 프로세스(집계) | `system.process.count`, `system.process.created`, `system.process.limit` | |
| 프로세스(개별) | `process.cpu.time`, `process.memory.usage`, `process.memory.virtual`, `process.disk.io`, `process.thread.count`, `process.unix.file_descriptor.count`, `process.context_switches`, `process.paging.faults`, `process.uptime` 등 | `process.cpu.utilization`, `process.memory.utilization` |

`system.memory.linux.available`에는 requirement level이 적혀 있지 않다. conntrack은 semconv에 **없다**. 따라서 conntrack은 업체 관행일 뿐 표준 이름이 없다.

semconv 이름은 hostmetrics 현재 이름과 일부 다르다. 대응은 hostmetrics → semconv 순서로 적는다.

- `system.network.packets` → `system.network.packet.count`
- `system.network.dropped` → `system.network.packet.dropped`
- `system.network.connections` → `system.network.connection.count`
- `system.processes.*` → `system.process.*`
- `system.linux.memory.available` → `system.memory.linux.available`

hostmetrics는 v0.160.0부터 이 이름으로 바꾸는 alpha gate를 두었다([hostmetrics `metadata.yaml` v0.161.0][c161-top]).

### 2.2 업체별 기본 수집 (Linux)

| 영역 | Datadog Agent | node_exporter v1.12 | Metricbeat `system` | Google Ops Agent | New Relic Infra |
|---|---|---|---|---|---|
| 기본 주기 | 체크 실행 주기 (값은 이번에 원문 확인 안 함) | 스크레이프 측 | 10s / 1m(fs) / 15m(uptime) | 60s | 5s(System) / 20s(Storage) / 10s(Network) |
| CPU | `system.cpu.{user,system,idle,iowait,...}` **%**, `num_cores` | `cpu` (초 단위 카운터) | `cpu` (% 기본) | `cpu/usage_time` + **`cpu/utilization`(파생)** | `cpuPercent`, `cpuUser/System/IOWait/StealPercent` |
| load | `system.load.{1,5,15}`, `load.norm.*` | `loadavg` | `load` | load 1/5/15 | `loadAverage{One,Five,Fifteen}Minute` |
| 메모리 | `system.mem.{total,used,free,usable,pct_usable,...}`, swap | `meminfo` (전 필드) | `memory` | usage + **utilization(파생)** | `memory{Used,Free}Bytes`, `memoryUsedPercent`, `memorySlabBytes`, swap |
| 디스크 I/O | `io` 체크: `system.io.{util,await,r_await,w_await,...}` | `diskstats` | **`diskio`는 주석 처리(기본 꺼짐)** | disk (`operation_time` 제외) | StorageSample `read/writeUtilizationPercent`, IOPS |
| 파일시스템 | `disk` 체크: `system.disk.{total,used,free,in_use}`, `system.fs.inodes.*` | `filesystem` | `filesystem`, `fsstat` (1m) | usage + **utilization(파생)**, inodes는 **제외** | StorageSample `diskUsedPercent`, `inodesUsedPercent` (xfs/ext/btrfs/zfs 등만) |
| 네트워크 | `system.net.{bytes,packets_in/out.*}`, TCP `retrans_segs`, `listen_overflows`, `listen_drops`, `backlog_drops`, UDP 오류 | `netdev`, `netstat`(TCP 재전송·listen·syncookie 등), `sockstat`, `softnet`, `udp_queues` | `network`, `socket_summary` | io, errors, packets, connections (`dropped` 제외) | NetworkSample bytes/packets/errors/dropped per sec |
| conntrack | **기본**: `/proc/sys/net/netfilter/nf_conntrack_*` 읽음 | **기본**: `conntrack` | 없음 | 없음 | 없음 |
| uptime | `uptime` 체크 `system.uptime` | `stat`(`node_boot_time_seconds`) | `uptime` (15m) | 없음(에이전트 uptime만) | 없음(호스트 속성) |
| 파일 핸들 | `file_handle` 체크 | `filefd` | 없음 | 없음 | 없음 |
| 시각 동기 | `ntp` 체크 (`ntp.offset`) | `timex` | 없음 | 없음 | 없음 |
| 프로세스별 | 꺼짐 (Process Agent 옵트인) | 없음 (`processes`는 집계, 기본 꺼짐) | **켜짐: CPU 상위 5 + 메모리 상위 5** | **켜짐: 모든 프로세스**(mute 플래그 3종) | **꺼짐**("Process metrics are not reported by default") |
| 기타 | `oom_kill`·`tcp_queue_length`는 conf.yaml.default가 있으나 system-probe(eBPF) 필요 | `pressure`(PSI), `vmstat`, `mdadm`, `edac`, `hwmon`, `entropy`, `os`, `uname` | | `system.network.dropped`, `inodes.usage`, `paging.faults`, `disk.operation_time`는 필터로 버림 | |

출처:
- Datadog: [`conf.d` 기본 목록][dd-confd] (`cpu`, `disk`, `file_handle`, `io`, `load`, `memory`, `network`, `ntp`, `uptime`, `oom_kill`, `tcp_queue_length`가 `conf.yaml.default`). [network 기본 설정][dd-net-default]은 `collect_connection_state: false`다. Go 디스크·네트워크 코어 체크가 Linux 기본이라는 근거는 [릴리스 노트][dd-v2-default]다. conntrack 파일 읽기는 [networkv2 `network_linux.go`][dd-netv2]에 있고, `conntrack -S` 경로는 기본값이 빈 문자열이라 꺼져 있다. 메트릭 이름은 [System 통합 문서][dd-system-doc].
- node_exporter: [README "Enabled by default"][ne-readme].
- Metricbeat: [`modules.d/system.yml`][mb-system].
- Ops Agent: [`built-in-config-linux.yaml`][gcp-builtin](60s), [`apps/hostmetrics.go`][gcp-hm](스크레이퍼, 프로세스 mute, 제외 필터), [골든 `otel.yaml`][gcp-golden]. 사용률 메트릭은 리시버가 아니라 `agentmetrics` 프로세서가 `system.cpu.time`·`memory.usage`·`filesystem.usage`·`paging.usage`에서 계산한다([`utils_calculate_utilizations.go`][gcp-util]).
- New Relic: [기본 데이터 문서][nr-default], 필드 이름은 [`pkg/metrics`][nr-metrics]의 JSON 태그.

정리하면 다음과 같다.
- **사용률(%) 값**: 5개 업체 중 4개(Datadog, Metricbeat, Ops Agent, NR)가 CPU·메모리·디스크 사용률을 퍼센트 값으로 바로 낸다. hostmetrics 기본값은 원시 값(초, 바이트)만 내므로 우리만 이 값이 없다.
- **conntrack**: Datadog과 node_exporter가 기본으로 수집한다.
- **uptime**: 3개 업체(Datadog, node_exporter, Metricbeat)가 기본으로 수집한다.
- **프로세스별**: 업체마다 갈린다. 켜는 쪽(Ops Agent 전체, Metricbeat 상위 N개)과 끄는 쪽(Datadog, NR, node_exporter)이 있다.

## 3. 후보 (메트릭 이름 단위)

"버전" 열의 의미는 다음과 같다. ✓는 해당 버전 hostmetrics에 있고 설정으로 켤 수 있다는 뜻이다. "기본"은 이미 켜져 있다는 뜻이다. ✗는 없다는 뜻이다. 비용은 호스트당 시계열 수와 새 스트림 수다. 행 수는 60s 간격 기준으로 분당 시계열 수와 같다.

### 3.1 싸고 가치가 큰 것

| 후보 | 켜는 법 | 가치 (어떤 장애를 보나) | 비용 | 0.119.0 (EL6) | 0.161.0 (EL7·modern) | 업계 |
|---|---|---|---|---|---|---|
| `system.uptime` | `scrapers.system: {}` 추가 | 계획되지 않은 재부팅(커널 패닉, 전원, 하이퍼바이저)을 잡는다. 값이 작아지면 재부팅이다. 지금은 Silent Host가 15분 넘게 비었을 때만 보이고, 짧은 재부팅은 보이지 않는다 | 1 시계열, 스트림 1 | ✓ (`system` 스크레이퍼 enabled 기본) | ✓ | semconv recommended; Datadog·node_exporter·Metricbeat 기본 |
| `system.linux.memory.available` | `memory.metrics.system.linux.memory.available.enabled: true` | 실제 메모리 압박을 본다(회수 가능한 캐시를 뺀 값). §4.1의 `used` 계산식 차이와 무관하게 세 경로에서 같은 뜻이다(커널 MemAvailable, 없으면 gopsutil 근사). OOM 직전 상태를 보고, `infra-oom-kill` 로그 알림의 선행 신호가 된다 | 1, 스트림 1 | ✓ | ✓ | semconv `system.memory.linux.available`(level 없음); NR `memoryFreeBytes`, Datadog `system.mem.usable`이 같은 개념 |
| `system.memory.limit` | `memory.metrics.system.memory.limit.enabled: true` | 메모리 알림의 분모(MemTotal)를 직접 준다. 지금은 state 합으로 분모를 추정하는데 그 합이 Total과 맞지 않는다(§4.1) | 1, 스트림 1 | ✓ | ✓ | semconv opt-in |
| `system.network.conntrack.count` / `.max` | `network.metrics.system.network.conntrack.{count,max}.enabled: true` | conntrack 테이블이 포화되면 커널이 새 연결을 버린다("nf_conntrack: table full, dropping packet"). Docker(NAT)·firewalld·VRRP 프록시 호스트에서 일어난다. count/max 비율로 미리 경보할 수 있다 | 2, 스트림 2 | ✓ | ✓ | node_exporter·Datadog 기본; semconv에 없음 |
| `system.cpu.utilization` | `cpu.metrics.system.cpu.utilization.enabled: true` | CPU 포화나 iowait·steal 과다(이웃 VM 간섭)를 **SQL 알림으로 바로** 판정한다. `system.cpu.time`은 누적 카운터라 SQL 알림에서는 rate를 직접 계산해야 하고 PromQL 알림이 필요하다([openobserve-metric-absence-alerts.md](openobserve-metric-absence-alerts.md) §1) | **0.161.0: 8** (state별 avg, `cpu` 속성 기본 제외) / **0.119.0: C×8** (재집계 기능 없음) | ✓ (CPU별만) | ✓ (집계 기본) | semconv opt-in; Datadog·Metricbeat·NR·Ops Agent는 % 값을 기본 수집 |
| `system.cpu.logical.count` (EL6만) | 0.119.0 행에서 `enabled: true` | load를 코어 수로 정규화한다(load/코어 > 1이면 포화) | 1 | ✓ (기본 꺼짐) | **이미 기본** | semconv recommended; Datadog `num_cores` |

conntrack에는 주의할 점이 있다. 두 버전 모두 gopsutil `FilterCountersWithContext`로 `/proc/sys/net/netfilter/nf_conntrack_{count,max}`를 읽는다([gopsutil `net_linux.go`][gopsutil-net]). `nf_conntrack` 모듈이 올라오지 않은 호스트에서는 파일이 없어 읽기가 실패하고, `network` 스크레이퍼가 매 60s **partial scrape error**를 낸다([network_scraper.go v0.161.0][c161-netscraper] `errors.AddPartial(conntrackMetricsLen, err)`). 다른 network 메트릭은 정상으로 나가지만 컬렉터 자체 로그에 오류가 쌓인다. node_exporter는 디렉터리가 없으면 "does nothing"이다. 그래서 다음 중 하나를 고르게 된다.
- 전체에 켜고 오류 로그를 감수한다.
- 모듈이 있는 호스트에만 켠다. 예를 들어 `otel_docker_metrics`처럼 `hosts/<host>/agents` 입력이나 그룹 파생 스위치를 둔다.
- 별도 `hostmetrics/conntrack` 리시버로 분리해 오류의 영향 범위를 줄인다.

EL6(2.6.32)에서 이 경로가 있는지는 실기로 확인하지 않았다.

### 3.2 중간 가치·중간 비용

| 후보 | 가치 | 비용 | 0.119.0 | 0.161.0 | 비고 |
|---|---|---|---|---|---|
| `system.memory.utilization` | 메모리 %를 SQL로 바로 쓴다. 다만 `used` 계산식은 `usage`와 같아서 §4.1의 경로 차이를 그대로 물려받는다. `available`/`limit` 조합이 더 일관된다 | 6, 스트림 1 | ✓ | ✓ | semconv recommended |
| `system.filesystem.utilization` | 디스크 %를 SQL로 바로 쓴다. 지금 알림은 `usage`의 used/(used+free)로 이미 계산하므로(`_RESOURCE['disk']`) **새로 생기는 장애 가시성은 없다**. 알림 SQL을 단순하게 만드는 효과만 있다. 이 값은 root 예약 블록을 분모에서 뺀다(`df`와 같음)는 점이 다를 수 있다(확인 안 함) | M, 스트림 1 | ✓ | ✓ | semconv recommended |
| `system.paging.utilization` | 스왑 고갈을 % 값으로 본다. `usage`로도 계산할 수 있다 | 3×S, 스트림 1 | ✓ | ✓ | semconv recommended |
| `system.cpu.utilization`의 `attributes: [cpu, state]` | 코어 하나만 100%인 단일 스레드 병목을 본다 | C×8 | (기본이 CPU별) | 옵트인 | Ops Agent는 `system.cpu.time`에 `[cpu, state]`를 다시 넣는다 |

### 3.3 비싼 것: `process` 스크레이퍼

| 항목 | 내용 |
|---|---|
| 기본 메트릭 | `process.cpu.time`(state 3), `process.memory.usage`, `process.memory.virtual`, `process.disk.io`(direction 2). 프로세스당 **7개 시계열**. 새 스트림 4개 |
| 리소스 속성 | `process.pid`, `parent_pid`, `executable.name`, `executable.path`, `command`, **`command_line`**, `owner`가 기본으로 켜진다([process `metadata.yaml`][c161-proc]). pid가 바뀌면 새 시계열이 되고(churn), command_line은 행마다 길게 붙는다 |
| 비용 추정 | 프로세스 200~400개인 호스트라면 1,400~2,800 시계열이다. 지금 호스트당 기준선(대략 100~200)보다 10배 이상 많다 |
| 권한 | modern은 비root + `CAP_DAC_READ_SEARCH`만 가진다. `/proc/<pid>/io`와 `/proc/<pid>/exe`는 ptrace 접근 검사(`PTRACE_MODE_READ_FSCREDS`)를 받는다([proc(5)][man-proc]). 그래서 다른 사용자 프로세스의 `disk.io`와 exe 경로 읽기는 실패할 것으로 **예상한다(실기 미확인)**. `mute_process_io_error`·`mute_process_exe_error`·`mute_process_user_error` 등으로 오류를 숨길 수 있고, 이 플래그는 0.119.0에도 있다([process config.go v0.119.0][c119-proc-cfg]). EL6·EL7은 root라 이 문제가 없다 |
| 줄이는 법 | `include.names` + `match_type`으로 관심 데몬만 고른다(예: dockerd, sshd, otelcol-contrib, java, caddy). Metricbeat의 상위 N개 같은 옵션은 hostmetrics에 **없다**([process config.go v0.161.0][c161-proc-cfg]). `process.command_line` 리소스 속성은 끌 수 있다 |
| 가치 | "누가 CPU·메모리를 먹었나"를 사후에 분석한다. 메모리 누수 데몬을 찾는다. 장애 시점 디스크 I/O를 일으킨 주체를 찾는다 |
| 버전 | 두 버전 모두 있다. 0.161.0에는 semconv v1 이름(`process.cpu.time@v1` 등, `cpu.mode` 속성)으로 바꾸는 gate가 별도로 있다 |
| 문서 | ADR-0006 §2.3에 "프로세스별 `process` 스크레이퍼 비활성"으로 결정돼 있다. 켜려면 ADR 개정이 필요하다 |

### 3.4 해당 없음 또는 낮음

- `nfs` 스크레이퍼: **0.161.0에만 있고**(0.119.0에는 디렉터리가 없다) stability는 development다. 기본 메트릭 16개가 대부분 NFS 연산·프로시저 이름별로 갈라져 카디널리티가 높다. NFS 클라이언트·서버가 없는 호스트에서는 의미가 없다. 우리 서버에 NFS가 있는지는 확인하지 않았다.
- `system.cpu.frequency`·`system.cpu.physical.count`: VM에서는 신호 가치가 낮다.
- `system.memory.linux.hugepages.*`·`system.linux.memory.dirty`·`system.memory.linux.shared`·`system.memory.page_size`: 0.161.0에만 있다. 일반 호스트에서는 가치가 낮다.
- `process.*` 선택 메트릭(`open_file_descriptors`, `threads`, `context_switches` 등): `process` 스크레이퍼를 켰을 때만 의미가 있다.

## 4. 부수 발견

### 4.1 메모리 `used`의 경로별 의미와 알림 분모

- 0.119.0([`memory_scraper_linux.go`][c119-memlinux])은 `used = memInfo.Used`다. gopsutil v4.24.12([`mem_linux.go`][gopsutil-mem])에서 `Used = Total − Free − Buffers − Cached`이고, `Cached`는 이미 `SReclaimable`을 더한 값이다. 그래서 `used + free + buffered + cached = Total`이 정확히 성립한다.
- 0.161.0([`memory_scraper_linux.go`][c161-memlinux])은 gate `receiver.hostmetricsreceiver.UseLinuxMemAvailable`(stage **beta**, 기본 켜짐, [metadata.yaml][c161-top])가 켜져 있으면 `used = Total − Available`다. 나머지 state(free, buffered, cached, slab_*)는 그대로다. 그래서 **state 합이 Total이 아니다**. 이 gate가 beta가 된 정확한 버전은 확인하지 않았다(gate는 v0.137.0에 추가, [CHANGELOG][contrib-cl]).
- 우리 알림 `infra-memory-usage-*`([`filter_plugins/openobserve_config.py`](../../filter_plugins/openobserve_config.py) `_RESOURCE['memory']`)은 분모를 `state <> 'slab_unreclaimable'`의 합(used+free+buffered+cached+slab_reclaimable)으로 계산한다. 이 분모는 두 경로 모두에서 MemTotal과 다르고, 그 차이도 경로마다 다르다. 0.119.0에서는 Total + SReclaimable이다(SReclaimable이 cached와 slab_reclaimable에 두 번 들어간다).
- 결과적으로 같은 임계값이라도 EL6과 그 밖의 호스트는 다른 양을 재고 있다. `system.memory.limit`(분모)와 `system.linux.memory.available`(분자 = limit − available)을 쓰면 세 경로에서 같은 정의가 된다. 고칠지는 이 조사의 범위 밖이다.

### 4.2 CPU 행 모양과 이미 켜진 메트릭

- 0.161.0은 `system.cpu.time`을 `cpu` 속성 없이 state별 합으로 낸다. 0.119.0은 CPU별로 낸다. 같은 `system_cpu_time` 스트림에 두 모양이 섞여 있다. 호스트 단위로 sum하는 쿼리는 둘 다 맞지만, `cpu` 열이 있다고 가정하는 쿼리는 modern에서 빈 결과를 낸다.
- `system.cpu.logical.count`는 0.161.0에서 이미 기본으로 수집 중이다. EL6만 없다.

### 4.3 리시버 타입 이름과 semconv v1 gate

- v0.151.0에서 `hostmetrics` 리시버가 `host_metrics`로 이름이 바뀌었고 `hostmetrics`는 deprecated 별칭으로 남았다([metadata.yaml][c161-top] `deprecated_type: hostmetrics`, [CHANGELOG #45449][contrib-cl]). 템플릿은 0.119.0과도 호환되어야 하므로 별칭을 유지할지, 버전 행별로 이름을 나눌지 정해야 한다(EL6 0.119.0은 `host_metrics`를 모른다).
- `receiver.hostmetrics.EmitV1SystemConventions`/`DontEmitV0SystemConventions`(alpha, v0.160.0~)를 나중에 켜면 network·processes 메트릭 이름이 semconv 이름으로 바뀐다(§2.1). OpenObserve에서는 스트림이 새로 생기고 EL6과 나머지가 다른 스트림에 쌓인다. 알림·대시보드를 둘 다 읽게 해야 한다.

## 5. hostmetrics로 만들 수 없는 업계 기본 신호 (공백)

| 신호 | 업계 기본 | 가치 | otelcol로 가능한 길 |
|---|---|---|---|
| TCP 재전송·listen 큐 넘침·SYN cookie | node_exporter `netstat`, Datadog network (`retrans_segs`, `listen_overflows`, `listen_drops`, `backlog_drops`) | 네트워크 품질 저하, accept 큐 포화(앱이 연결을 못 받음) | hostmetrics에 없다. 미조사 |
| 시스템 전체 파일 핸들 (`file-nr`) | node_exporter `filefd`, Datadog `file_handle` | "Too many open files" 고갈 | hostmetrics에 없다 |
| 시각 동기 (offset, 동기 상태) | node_exporter `timex`, Datadog `ntp` | 시각이 틀어져 로그 순서가 꼬이고 TLS·Kerberos 인증이 실패함. 감사 로그(ISMS)의 시각 신뢰도 | contrib `chronyreceiver`가 두 버전 배포판 모두에 있다([manifest v0.161.0][rel-161], [v0.119.0][rel-119]). chronyd 호스트에만 해당하고 EL6(ntpd)은 대상 밖 |
| PSI (CPU·메모리·I/O 압박) | node_exporter `pressure` | 포화를 사용률보다 정확히 본다 | hostmetrics에 없다. 커널 4.20+만 지원하므로 EL6·EL7은 어차피 불가 |
| OOM kill 횟수 | node_exporter `vmstat`(`oom_kill`), Datadog `oom_kill`(system-probe) | 메모리 고갈 사고 | 이미 `infra-oom-kill` 로그 알림이 있다 |
| RAID(mdadm)·EDAC·hwmon | node_exporter `mdadm`, `edac`, `hwmon` | IDC 물리 서버의 디스크 열화, 메모리 ECC 오류, 온도 | hostmetrics에 없다. 물리 서버 여부는 확인하지 않았다 |

## 6. 권고 (결정 아님)

1. **1순위 (싸고, 모든 경로에서 같고, 장애 가시성이 새로 생긴다)**: `system` 스크레이퍼(`system.uptime`), `system.linux.memory.available`, `system.memory.limit`. 합쳐서 호스트당 3개 시계열, 스트림 3개다. 메모리 알림 분모 정리(§4.1)와 함께 다루면 효과가 크다.
2. **2순위**: `system.cpu.utilization`. SQL로 CPU 알림을 만들 수 있다. 0.161.0은 8개, EL6은 C×8개 시계열이다. EL6의 비용이 걸리면 EL6 버전 행에서만 끄는 것도 선택지다.
3. **2순위, 조건부**: conntrack 2종. 모듈이 있는 호스트(Docker·방화벽·VRRP)에만 호스트 스위치로 켜는 형태를 권한다. 전체에 켜면 오류 로그 잡음이 생긴다.
4. **보류 권고**: `system.filesystem.utilization`, `system.memory.utilization`, `system.paging.utilization`은 이미 있는 `usage`로 계산할 수 있어 새 가시성이 없다. 알림 SQL을 단순하게 만들고 싶을 때만 고려한다.
5. **별도 결정 필요**: `process` 스크레이퍼. 전체에 켜는 것은 비용·권한 문제로 권하지 않는다. 필요하면 특정 호스트·이름 include 목록·mute 플래그·`command_line` 끄기를 묶은 옵트인으로 설계하고 ADR-0006 §2.3을 개정한다.
6. **공백(§5)**: 시각 동기는 `chronyreceiver`로 메울 수 있다. TCP·파일 핸들·RAID는 hostmetrics 밖이라 이번 갈래가 아니라 후속 조사 거리다.

## 7. 확인하지 못한 것

- 실제 호스트별 C·D·M·I와 프로세스 수. 시계열 수는 공식에서 낸 추정치다.
- EL6(2.6.32)에서 `/proc/sys/net/netfilter/nf_conntrack_*`와 `MemAvailable`이 있는지. gopsutil은 MemAvailable이 없으면 근사값을 계산한다.
- modern 경로에서 `process` 스크레이퍼를 비root로 돌렸을 때 실제로 어떤 오류가 나는지.
- `system.filesystem.utilization`이 root 예약 블록을 어떻게 다루는지.
- `UseLinuxMemAvailable` gate가 beta로 오른 버전. 0.161.0에서 beta(기본 켜짐)인 것만 확인했다.

<!-- 링크 -->
[c161-cpu]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/internal/scraper/cpuscraper/metadata.yaml
[c119-cpu]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.119.0/receiver/hostmetricsreceiver/internal/scraper/cpuscraper/metadata.yaml
[c161-cpu-gencfg]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/internal/scraper/cpuscraper/internal/metadata/generated_config.go
[c161-mem]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/internal/scraper/memoryscraper/metadata.yaml
[c161-memlinux]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/internal/scraper/memoryscraper/memory_scraper_linux.go
[c119-memlinux]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.119.0/receiver/hostmetricsreceiver/internal/scraper/memoryscraper/memory_scraper_linux.go
[c161-disk]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/internal/scraper/diskscraper/metadata.yaml
[c161-fs]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/internal/scraper/filesystemscraper/metadata.yaml
[c161-load]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/internal/scraper/loadscraper/metadata.yaml
[c161-net]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/internal/scraper/networkscraper/metadata.yaml
[c161-netscraper]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/internal/scraper/networkscraper/network_scraper.go
[c161-paging]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/internal/scraper/pagingscraper/metadata.yaml
[c161-procs]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/internal/scraper/processesscraper/metadata.yaml
[c161-proc]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/internal/scraper/processscraper/metadata.yaml
[c161-proc-cfg]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/internal/scraper/processscraper/config.go
[c119-proc-cfg]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.119.0/receiver/hostmetricsreceiver/internal/scraper/processscraper/config.go
[c161-top]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/metadata.yaml
[contrib-cl]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/CHANGELOG.md
[rel-161]: https://github.com/open-telemetry/opentelemetry-collector-releases/blob/v0.161.0/distributions/otelcol-contrib/manifest.yaml
[rel-119]: https://github.com/open-telemetry/opentelemetry-collector-releases/blob/v0.119.0/distributions/otelcol-contrib/manifest.yaml
[gopsutil-mem]: https://github.com/shirou/gopsutil/blob/v4.24.12/mem/mem_linux.go
[gopsutil-disk]: https://github.com/shirou/gopsutil/blob/779ae83d884fd24864dadcd5f41496c3564711a2/disk/disk_linux.go
[gopsutil-net]: https://github.com/shirou/gopsutil/blob/779ae83d884fd24864dadcd5f41496c3564711a2/net/net_linux.go
[semconv-sys]: https://github.com/open-telemetry/semantic-conventions/blob/331541c4057c53d133c32efadaa7b656636eda77/docs/system/system-metrics.md
[semconv-proc]: https://github.com/open-telemetry/semantic-conventions/blob/331541c4057c53d133c32efadaa7b656636eda77/docs/system/process-metrics.md
[ne-readme]: https://github.com/prometheus/node_exporter/blob/v1.12.1/README.md
[ne-fs]: https://github.com/prometheus/node_exporter/blob/v1.12.1/collector/filesystem_linux.go
[dd-confd]: https://github.com/DataDog/datadog-agent/tree/aae41b062ca325271c69d6333d3c3741f5564c1b/cmd/agent/dist/conf.d
[dd-net-default]: https://github.com/DataDog/datadog-agent/blob/aae41b062ca325271c69d6333d3c3741f5564c1b/cmd/agent/dist/conf.d/network.d/conf.yaml.default
[dd-netv2]: https://github.com/DataDog/datadog-agent/blob/aae41b062ca325271c69d6333d3c3741f5564c1b/pkg/collector/corechecks/net/networkv2/network_linux.go
[dd-v2-default]: https://github.com/DataDog/datadog-agent/blob/aae41b062ca325271c69d6333d3c3741f5564c1b/releasenotes/notes/enable-v2-checks-by-default-ff71cdcb4455bd43.yaml
[dd-system-doc]: https://docs.datadoghq.com/integrations/system/
[mb-system]: https://github.com/elastic/beats/blob/1b199f6b201807b2a7ae70ad3b598dba08ef650f/metricbeat/modules.d/system.yml
[gcp-builtin]: https://github.com/GoogleCloudPlatform/ops-agent/blob/d6fa4ee1a827ea1ee2eeb0a5c7b960715b4c60b9/confgenerator/built-in-config-linux.yaml
[gcp-hm]: https://github.com/GoogleCloudPlatform/ops-agent/blob/d6fa4ee1a827ea1ee2eeb0a5c7b960715b4c60b9/apps/hostmetrics.go
[gcp-golden]: https://github.com/GoogleCloudPlatform/ops-agent/blob/d6fa4ee1a827ea1ee2eeb0a5c7b960715b4c60b9/confgenerator/testdata/goldens/builtin/golden/linux/otel.yaml
[gcp-util]: https://github.com/GoogleCloudPlatform/opentelemetry-operations-collector/blob/5faae1b777dc6e3cf00798c12ee0969415371c21/components/otelopscol/processor/agentmetricsprocessor/utils_calculate_utilizations.go
[nr-default]: https://docs.newrelic.com/docs/infrastructure/manage-your-data/data-instrumentation/default-infrastructure-monitoring-data/
[nr-metrics]: https://github.com/newrelic/infrastructure-agent/tree/3bdc56490f4e7b36cb0db6056e9b00ea8b6e6de6/pkg/metrics
[man-proc]: https://man7.org/linux/man-pages/man5/proc.5.html
