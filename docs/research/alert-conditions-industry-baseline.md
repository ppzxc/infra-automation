# OpenObserve 알림 조건 전수 비교: 업계 표준(node-mixin·SRE·벤더 권장)과 OpenObserve 평가 방식

- 질문: `roles/openobserve_config/defaults/main.yml`의 `infra-` 알림 53개(기본 비활성 1개 포함)를 업계 표준 규칙과 하나씩 비교한다. 특히 OpenObserve PromQL 알림이 실제로 어떻게 평가되는지(“N분 내내” 조건이 성립하는지) 1차 출처로 확인한다. 알림마다 유지, 임계 조정, 조건 변경, 폐기 중 하나를 권고한다. **결정과 변경은 하지 않는다.** 코드·알림·서버는 그대로 두었다.
- 조사일: 2026-10-22
- 기준 커밋: 저장소 `8c28825` (#314). 알림 53개 중 `infra-switch-uplink-down`은 `o2c_switch_uplinks`가 비어 있어 기본으로 만들지 않으므로 활성 알림은 52개다. 자가 시험 `infra-alert-selftest`는 비교 대상에서 뺐다.
- 확인한 버전
  - OpenObserve: **v1.0.4** (commit `1e257e69ef0feb6029f3111d54697244a3f507db`). 운영 서버 ns0331이 이 커밋이라는 것은 [openobserve-metric-absence-alerts.md](openobserve-metric-absence-alerts.md)에서 확인했다. 아래 소스 링크는 모두 이 커밋을 가리킨다.
  - node_exporter node-mixin: `master` @ `b9e296a` (2026-10-22).
  - kube-prometheus: `f71fb6c`. kubernetes-mixin: `ea8e318`.
  - OTel semantic conventions: `0eb883b`. hostmetrics receiver: 우리가 배포하는 태그 v0.161.0(modern·EL7)과 v0.119.0(EL6). 메트릭 정의는 `main` @ `2863c04`과 대조했다.
- 방법: 업스트림 소스와 공식 문서만 근거로 썼다. OpenObserve 동작은 v1.0.4 소스를 읽어 확인했고, 이번 조사에서 운영 서버에 질의하거나 실행해 보지는 않았다. 사용자가 2026-10-22에 잰 결과(서브쿼리 무시, ns0338 발화)는 “우리 실측”으로 따로 적었다. 실측이 아니라 계산으로 낸 수치에는 **추정**이라고 붙였다.
- 우리 쪽 문맥: `roles/openobserve_config/defaults/main.yml`(`o2c_alerts`), `filter_plugins/openobserve_config.py`(`o2c_resource_sql`, 알림 본문 조립), `roles/monitoring/defaults/main.yml`(`otel_hostmetrics_scrapers`), `roles/monitoring/templates/otelcol-contrib.yaml.j2`, [런북](../runbooks/alerts.md), [openobserve_config.md](../openobserve_config.md), [openobserve-metric-absence-alerts.md](openobserve-metric-absence-alerts.md), [host-metrics-industry-standard.md](host-metrics-industry-standard.md). 알림 정비 이력은 #297~#307이다(#307에서 스왑·메모리 압박·디스크 지연을 복합 조건으로 바꿨다).

## 요약

1. **PromQL 알림 16개 가운데 “N분 내내”라고 적힌 것은 실제로는 “N분 안에 한 번이라도”다.** OpenObserve v1.0.4는 `(<promql>) <연산자> <값>`을 구간 `[end − period, end]`에 대해 range query로 돌린다. 비교 연산자는 조건을 넘지 못한 점을 지운다. 그 뒤 시리즈마다 남은 마지막 점을 읽는다. 그래서 **구간 안의 한 점만 넘어도 발화한다**(§2.2). 서브쿼리 `[10m:1m]`도 이 동작을 바꾸지 못한다(§2.3). ns0338의 2분짜리 쓰기 몰림이 “10분 내내”라고 적힌 `infra-disk-write-latency`를 울린 이유가 이것이다. 런북의 “평가 기간을 10분으로 늘려 한 번의 튐으로 울리지 않게 했다”는 설명은 거꾸로다. period를 늘리면 한 점이 걸릴 기회가 늘어 **더 잘** 울린다.
2. **v1.0.4에는 Prometheus `for:`에 해당하는 `pending_period_sec`가 있다**(Alert 최상위 필드, 기본 0). 우리 Config 역할은 이 값을 보내지 않는다. 지속 조건이 필요한 PromQL 알림에는 다음을 함께 쓰는 것이 가장 직접적인 해법이다(§2.4).
   - `pending_period_sec`를 설정한다.
   - `period`를 `frequency`와 같거나 그보다 짧게 둔다.
   - 단, 코드를 읽어 얻은 결론이라 실서버 검증이 먼저다.
3. **SQL 메트릭 알림(디스크·inode·메모리 사용률)은 정말로 “내내”를 구현한다.** `o2c_resource_sql`이 `_timestamp`별 사용률의 구간 최솟값(`min(pct)`)으로 판정하기 때문이다. 문제는 PromQL 알림에만 있다.
4. **바로 고칠 것 (우선순위순)**
   - ① `infra-cpu-usage-p1`은 P1에서 내린다. node-mixin `NodeCPUHighUsage`는 같은 90%를 `for: 15m`, **severity `info`**로 둔다. 우리 식은 iowait와 steal까지 사용률로 센다.
   - ② `infra-disk-read-latency`·`infra-disk-write-latency`에 지속 조건을 넣는다(`rate(...[30m])` 평균 + `pending_period_sec`). 런북 문구도 바로잡는다.
   - ③ `infra-disk-io-saturation`, `infra-cpu-load-saturation`, `infra-memory-pressure`, `infra-network-errors`, `infra-cpu-iowait`, `infra-cpu-steal`, `infra-disk-fill-24h`, `infra-inode-fill-24h`에 업스트림의 `for`(15분~1시간)를 맞춘다.
   - ④ `infra-network-errors`는 절대 건수(10분 10건)를 node-mixin처럼 오류/패킷 비율(1%)로 바꾼다.
   - ⑤ `infra-inode-fill-24h`는 추세 창을 1시간에서 6시간으로 늘리고 “여유 40% 미만” 조건을 더한다.
5. **디스크 지연 사례(§5)의 진짜 원인은 RAID 컨트롤러 쓰기 캐시다.** ns0288·ns0329는 쓰기 캐시가 영구 비활성이고, ns0272·ns0273은 상태를 확인할 도구가 없다. 지연 임계를 조정하는 것보다 **컨트롤러 캐시·배터리 상태를 직접 감시하는 알림**이 맞는 처방이다. HPE `ssacli`나 SNMP `CPQIDA-MIB`, iLO Redfish로 읽고, 우리 `backup.jsonl`처럼 JSON 줄 로그로 수집하면 지금 구조에 들어간다.
6. **추가 후보 1순위는 시각 동기(NTP)와 RAID 상태다.** hostmetrics로는 둘 다 만들 수 없어 수집을 더해야 한다. 지금 수집 범위로 바로 만들 수 있는 것도 있다: 재부팅 탐지(`system_uptime`), 파일시스템 4시간 내 고갈(P1), “실패 뒤 성공” SSH 무차별 대입(§4).

## 1. 비교 기준

### 1.1 알림 철학 (출처: Google SRE·Prometheus·node-mixin)

- **증상에 알리고, 원인은 진단 자료로 둔다.** SRE book은 “what's broken”(증상)과 “why”(원인)를 구분한다. 호출(page)마다 다음을 요구한다([SRE book ch.6][sre-ch6]).
  - “Every page should be actionable.”
  - “If a page merely merits a robotic response, it shouldn't be a page.”
  - Prometheus 공식 문서도 “keep alerting simple, alert on symptoms”, “avoid having pages where there is nothing to do”라고 쓴다([Prometheus alerting practices][prom-practice]).
- **용량은 예외다.** 같은 Prometheus 문서는 “being close to capacity often requires human intervention to avoid an outage in the near future”라고 해서, 디스크 고갈 예측 같은 용량 알림은 원인 지표여도 알림 대상으로 둔다([Prometheus alerting practices][prom-practice]).
- **배치 작업은 한 번 실패로 호출하지 않는다.** 같은 문서는 “a single failure should not require human intervention”이라고 하고, 최소 두 주기를 연속으로 성공하지 못했을 때 호출하라고 권한다.
- **단일 노드 리소스 경보는 호출 등급이 아니다.** node-mixin 설정 주석은 노드 하나의 임박한 장애도 “no reason to create a paging alert”라고 하며, 이 등급을 `nodeCriticalSeverity`로 조정하게 둔다([node-mixin config][nm-config]). 실제로 `NodeCPUHighUsage`는 `info`, 나머지 리소스 경보는 대부분 `warning`이다.
- **지속 조건.** Prometheus `for:`는 기본값 0s이며, 조건이 그 시간 동안 이어지기 전에는 “pending”이다([Prometheus alerting rules][prom-rules]). 평가 한 번만 조건이 깨져도 pending이 처음부터 다시 시작한다. AWS CloudWatch는 이와 다른 “N개 중 M개” 방식을 쓴다: “The breaching data points don't have to be consecutive, but they must all be within the last number of data points equal to Evaluation Period”([CloudWatch alarm evaluation][aws-eval]). Grafana는 Pending period와 Keep firing for로 같은 문제를 다룬다([Grafana alert rule evaluation][grafana-eval]).
- **SLO 소진율.** SRE workbook은 99.9% SLO 기준으로 다단 창 소진율을 권한다([SRE workbook, Alerting on SLOs][sre-slo]).
  - 1h/5m 창, 14.4배: 호출
  - 6h/30m 창, 6배: 호출
  - 3d/6h 창, 1배: 티켓

  우리는 SLO를 정의하지 않았으므로 이 기준은 Caddy 오류율 알림을 평가할 때만 참고한다.

### 1.2 node-mixin 규칙 (node_exporter `b9e296a`)

출처는 [`alerts.libsonnet`][nm-alerts]과 [`config.libsonnet`][nm-config]다. 아래 식에는 설정 기본값을 채워 넣었다. kube-prometheus는 같은 규칙을 쓰되 `fsSpaceFillingUp` 임계를 15/10으로 낮추고 디스크 장치 선택자를 `sd.+|nvme.+|vd.+|dm-.+|md.+` 등으로 좁힌다([kube-prometheus node-exporter.libsonnet][kp-ne]).

| 규칙 | 식 (기본값 대입) | for | severity |
|---|---|---|---|
| NodeFilesystemSpaceFillingUp | `avail/size*100 < 40 and predict_linear(avail[6h], 24h) < 0 and readonly == 0` | 1h | warning |
| NodeFilesystemSpaceFillingUp | `< 20`, `predict_linear(avail[6h], 4h) < 0` | 1h | critical |
| NodeFilesystemAlmostOutOfSpace | `avail/size*100 < 5` / `< 3`, `readonly == 0` | 30m | warning / critical |
| NodeFilesystemFilesFillingUp | `files_free/files*100 < 40 and predict_linear(files_free[6h], 24h) < 0` / `< 20`, 4h | 1h | warning / critical |
| NodeFilesystemAlmostOutOfFiles | `< 5` / `< 3` | 1h | warning / critical |
| NodeNetworkReceiveErrs / TransmitErrs | `rate(errs[2m]) / rate(packets[2m]) > 0.01` | 1h | warning |
| NodeHighNumberConntrackEntriesUsed | `entries / entries_limit > 0.75` | 없음 | warning |
| NodeTextFileCollectorScrapeError | `node_textfile_scrape_error == 1` | 없음 | warning |
| NodeClockSkewDetected | `offset > 0.05 and deriv(offset[5m]) >= 0` 또는 `offset < -0.05 and deriv <= 0` | 10m | warning |
| NodeClockNotSynchronising | `min_over_time(sync_status[5m]) == 0 and maxerror >= 16` | 10m | warning |
| NodeRAIDDegraded | `node_md_disks_required - ignoring(state) node_md_disks{state="active"} > 0` | 15m | critical |
| NodeRAIDDiskFailure | `node_md_disks{state="failed"} > 0` | 없음 | warning |
| NodeFileDescriptorLimit | `filefd_allocated*100/filefd_maximum > 70` / `> 90` | 15m | warning / critical |
| NodeCPUHighUsage | `sum without(mode)(avg without(cpu)(rate(node_cpu_seconds_total{mode!~"idle\|iowait"}[2m]))) * 100 > 90` | 15m | **info** |
| NodeSystemSaturation | `node_load1 / count(cpu) > 2` | 15m | warning |
| NodeMemoryMajorPagesFaults | `rate(node_vmstat_pgmajfault[5m]) > 500` | 15m | warning |
| NodeMemoryHighUtilization | `100 - MemAvailable/MemTotal*100 > 90` | 15m | warning |
| NodeDiskIOSaturation | `rate(node_disk_io_time_weighted_seconds_total[5m]) > 10` | 30m | warning |
| NodeSystemdServiceFailed | `node_systemd_unit_state{state="failed"} == 1` | 5m | warning |
| NodeSystemdServiceCrashlooping | `increase(node_systemd_service_restart_total[5m]) > 2` | 15m | warning |
| NodeBondingDegraded | `(node_bonding_slaves - node_bonding_active) != 0` | 5m | warning |

kube-prometheus는 여기에 다음 규칙을 더한다([kube-prometheus node.libsonnet][kp-node], [general.libsonnet][kp-general]).
- `NodeNetworkInterfaceFlapping`: `changes(node_network_up{device!~"veth.+"}[2m]) > 2`, for 2m, warning.
- `TargetDown`: 대상의 10% 넘게 `up == 0`, for 10m.
- `Watchdog`: `vector(1)`. 항상 울려서 알림 경로가 살아 있음을 증명한다.

kubernetes-mixin의 `node.rules`([kubernetes-mixin node.libsonnet][km-node])에는 recording rule만 있고 호스트 알림은 없다. CPU 사용률은 `mode!="idle",mode!="iowait",mode!="steal"`로 계산한다.

### 1.3 벤더 공식 권장값

- **Grafana Cloud Linux node 통합**: 프리빌트 알림 21종이며 node-mixin을 그대로 쓴다([Grafana Linux node integration][grafana-linux]).
- **Datadog**
  - 디스크 가이드는 여유 공간 10% 미만에서 알리라고 한다([Datadog disk space guide][dd-disk]).
  - NTP 체크의 기본 오프셋 임계는 소스 기준 60초다(`defaultOffsetThreshold := 60`, [datadog-agent ntp.go][dd-ntp]).
  - 메트릭 모니터는 평가 창이 데이터로 “filled”된 뒤에만 평가하는 옵션이 있다([Datadog metric monitor][dd-metric]).
  - CPU·메모리·네트워크 오류의 공식 권장 모니터는 확인하지 못했다.
- **AWS CloudWatch 권장 경보(EC2)**([AWS recommended alarms][aws-rec])
  - CPUUtilization: 80% 초과, 5분 주기 3개 중 3개(=15분 지속).
  - StatusCheckFailed: 5분 주기 2개 중 2개.
- **New Relic**
  - Host not reporting은 창을 5~60분에서 정한다([New Relic host not reporting][nr-hnr]).
  - “CPU 90% 5분” 같은 호스트 권장 임계는 공식 문서에서 찾지 못했다. 그래서 이 문서는 New Relic 권장 임계를 근거로 쓰지 않는다.
- **디스크 지연 절대값**
  - Microsoft는 SQL Server I/O 문제 진단 문서에서 Avg Disk sec/Transfer가 “consistently above 10-15 milliseconds”이면 조사하라고 한다([Microsoft Learn, SQL I/O][ms-io]). 같은 문서는 이 값이 “approximate threshold selected based on collective experience”라고 밝힌다. 파일 통계 등급은 16~100ms가 Poor, 100~500ms가 Bad다.
  - Broadcom(VMware) KB는 DAVG/KAVG/GAVG가 “should not exceed more than 10 milliseconds (ms) for sustained periods of time”이라고 한다([Broadcom KB 344099][vmw-kb]).
  - HDD와 SSD를 나눈 공식 임계는 찾지 못했다. Google Cloud와 Datadog의 공식 권장 디스크 지연 임계도 찾지 못했다.
- **로그(보안·커널) 규칙**
  - fail2ban 기본값은 `maxretry = 5`, `findtime = 10m`, `bantime = 10m`이다([fail2ban jail.conf][f2b]).
  - Elastic detection-rules의 SSH 무차별 대입 규칙은 같은 호스트·출발지·사용자의 실패 60회를 30초 안에 본다([Elastic external][el-ssh-ext]). 성공으로 끝난 무차별 대입은 실패 25회 뒤 성공을 15초 안에 본다([Elastic successful][el-ssh-ok]).
  - Wazuh 5712·5763은 같은 출발지에서 120초 안에 8회다([Wazuh sshd rules][wz-sshd]). 5108(`Out of Memory: `, level 12)과 5109(I/O error, level 4)는 [Wazuh syslog rules][wz-syslog]에 있다.
  - Sigma와 Elastic에는 OOM·EXT4/XFS·MCE 규칙이 없다([SigmaHQ linux builtin][sigma]).
  - syslog 심각도 0~2(emergency·alert·critical)의 의미는 [RFC 5424 §6.2.1][rfc5424]이 정의한다.

### 1.4 OTel 메트릭 단위 점검

우리 PromQL은 OTel 메트릭 이름을 그대로 쓴다. OpenObserve는 OTLP 메트릭 이름의 `.`을 `_`로 바꾸고 소문자로 만들 뿐이다. 단위 접미사(`_seconds`)와 `_total`은 붙이지 않는다(소스: [otlp.rs][oo-otlp], [schema.rs][oo-schema]). 그래서 `system_disk_operation_time`이 그대로 맞다. Prometheus exporter라면 `system_disk_operation_time_seconds_total`이 됐을 것이다. 단위는 [semconv][semconv]와 hostmetrics `metadata.yaml`([disk][hm-disk], [cpu][hm-cpu], [paging][hm-paging], [network][hm-net], [load][hm-load], [system][hm-system])로 확인했다.

| 우리 식에 쓰는 메트릭 | 종류·단위 | 우리 해석 | 판정 |
|---|---|---|---|
| `system_cpu_utilization{state}` | gauge, `1`(0~1) | ×100 해서 % | 맞다. 0.161.0은 `cpu` 속성 없이 state별 합산이고, 0.119.0(EL6)은 CPU별이라 `avg by(host_name)`이 필요하다(지금 식에 있다) |
| `system_disk_operation_time{direction}` | 누적 counter, `s` | `rate(time)/rate(ops)×1000` = 요청당 ms | 맞다. diskstats 필드 7·11이며 큐 대기 시간이 들어간다(iostat `r_await`/`w_await`와 같은 뜻) |
| `system_disk_weighted_io_time` | 누적 counter, `s`, Linux 전용 | `rate()` = 평균 큐 길이 | 맞다. node-mixin `NodeDiskIOSaturation`이 쓰는 `node_disk_io_time_weighted_seconds_total`과 같은 diskstats 필드 11이다. 지연이 아니라 큐 길이(iostat `aqu-sz`)다 |
| `system_cpu_load_average_1m` / `system_cpu_logical_count` | gauge `{thread}` / `{cpu}` | 코어당 load | 맞다. EL6은 `system.cpu.logical.count`를 따로 켠다(`otel_hostmetrics_scrapers_legacy_el6`) |
| `system_filesystem_usage{state}`·`system_filesystem_inodes_usage` | updown counter, `By`·`{inodes}` | `deriv()` = 초당 증감, `/3600` = 시간 | 맞다. state는 used·free·reserved다. 우리 사용률 `used/(used+free)`는 reserved를 빼므로 `df`의 Use%와 같은 방식이다(추정) |
| `system_paging_utilization{state}` | gauge, `1` | ×100 | 맞다. 스왑 장치마다 행이 하나씩 나온다 |
| `system_paging_faults{type}` | 누적 counter `{faults}` | `rate` = 초당 건수 | 맞다. node-mixin의 `rate(node_vmstat_pgmajfault)`에 해당한다 |
| `system_network_errors{direction}` | 누적 counter `{errors}` | `increase([10m])` = 10분 건수 | 맞다 |
| `system_network_conntrack_count`/`_max` | `{entries}`, 기본 꺼짐 | 비율 | 맞다. conntrack 호스트에서만 켠다(`otel_hostmetrics_scrapers_conntrack`) |
| `system_linux_memory_available`/`system_memory_limit` | `By`, 기본 꺼짐(우리는 켬) | `1 − available/limit` | 맞다. node-mixin `NodeMemoryHighUtilization`(MemAvailable/MemTotal)과 같은 정의다 |

참고: `system.cpu.load_average.*`, `system.network.conntrack.*`, `system.disk.weighted_io_time`, `system.disk.pending_operations`는 현재 semconv에 정의가 없고 hostmetrics만 낸다. hostmetrics가 semconv v1 이름으로 바꾸는 gate(`receiver.hostmetrics.EmitV1SystemConventions`, alpha)를 켜면 이름이 바뀌어 알림이 빈 결과가 된다. 이 내용은 [host-metrics-industry-standard.md](host-metrics-industry-standard.md) 요약 4(e)에 있다.

## 2. OpenObserve 알림 평가 방식과 제약

### 2.1 필드의 뜻 (v1.0.4 소스)

| 필드 | 뜻 | 출처 |
|---|---|---|
| `trigger_condition.period` | 조회 구간(분). 스케줄러는 매번 `[end − period, end]`를 평가한다 | [mod.rs L52-91][oo-meta], [handlers.rs L1843-1849][oo-h-range] |
| `trigger_condition.frequency` | 평가 주기. 내부 모델은 초 단위이고, v2 API 모델은 분(`frequency_minutes`)으로 받아 변환한다 | [meta mod.rs][oo-meta], [api models L254-258][oo-api] |
| `trigger_condition.threshold`/`operator` | **조건을 통과한 시리즈(PromQL)나 행(SQL)의 개수**를 비교하는 문턱이다. 우리는 `>= 1` | [aggregation_level.rs L146-178][oo-agg] |
| `trigger_condition.silence` | 발화 뒤 다음 평가를 `now + silence` 이후로 미룬다. 단일 등급의 비 multi 알림은 **silence 동안 평가 자체를 건너뛴다** | [handlers.rs L2081-2096][oo-h-silence] |
| `trigger_condition.tolerance_in_secs` | 다음 실행 시각에 0~N초 무작위 지연을 더한다. 조건의 허용 오차가 아니다 | [meta mod.rs][oo-meta] |
| `query_condition.promql_condition` | `{operator, value}`. `column`은 읽지 않는다 | [alerts/mod.rs L180-211][oo-eval] |
| `query_condition.promql_multi_alert` | 기본 false. true면 필터 없이 돌리고, 코드에서 시리즈마다 **마지막 값**을 비교한다 | [alerts/mod.rs L196-211][oo-eval] |
| `pending_period_sec` (Alert 최상위) | **Prometheus `for:`에 해당한다**. 기본 0(즉시 발화). 실시간 알림에는 쓸 수 없고 음수는 거부된다 | [alert.rs L134][oo-alert-model], [handlers.rs L2206-2300][oo-h-pending], [core alert.rs L663-669][oo-validate] |

공식 문서(Alerts, Scheduled alerts, Alert conditions)가 설명하는 것은 look-back window(=period), Check every(=frequency), Cooldown(=silence)뿐이다([OpenObserve alerts][oo-doc-alerts], [scheduled alerts][oo-doc-sched], [alert conditions][oo-doc-cond]). **PromQL 조건이 구간의 어느 점을 보는지와 pending period는 문서에 없다.** 이 절의 내용은 소스에서만 확인했다.

### 2.2 PromQL 알림은 구간 안의 한 점만 넘어도 발화한다

평가 순서는 다음과 같다([alerts/mod.rs L165-341][oo-eval]).

1. 단일 모드(`promql_multi_alert = false`, 우리 설정)에서는 쿼리 문자열을 `format!("({}) {} {}", promql, operator, value)`로 만든다. 임계 비교가 PromQL 안으로 들어간다.
2. 이 식을 range query로 돌린다. 범위는 `[end − period, end]`, step은 `max(1s, period / 256)`이다([promql lib.rs L45-47][oo-promql-lib]). 10분 구간이면 약 2.3초마다 한 점이다. 순간 선택자는 각 step에서 최대 5분(`DEFAULT_LOOKBACK = 300s`) 전까지의 마지막 원시 샘플을 쓴다. 그래서 **실제로 보는 범위는 period보다 최대 5분 길다.**
3. PromQL 비교 연산자는 조건을 넘지 못한 step의 점을 지우고, 점이 하나도 남지 않은 시리즈는 버린다([vector_operations.rs L74-120][oo-vecop]).
4. 남은 시리즈마다 `v.samples.last()`, 즉 **조건을 통과한 점 중 마지막 점**을 행으로 만든다(L266). 행 수가 `threshold`(1) 이상이면 발화한다.

결론: **구간 안에서 한 step이라도 조건을 넘은 시리즈는 발화한다.** period는 Prometheus의 `for:`와 정반대로 작동해서, 사실상 “구간 최댓값이 임계를 넘는가”를 묻는다. 이전 조사([openobserve-metric-absence-alerts.md](openobserve-metric-absence-alerts.md) §1)가 “`samples.last()`는 끝 시각 값이 아니라 마지막으로 있는 점”이라고 적은 것은 이 동작의 절반이다. 그 앞에서 비교 필터가 점을 지운다는 점까지 합쳐야 “한 점 발화”가 설명된다.

우리 실측과의 대응:
- 2026-10-22 `infra-disk-write-latency`가 ns0338의 17:17~17:19 2분 쓰기 몰림으로 발화했다. 문구는 “10분 내내”이지만 식은 period 10분 안에서 `rate([5m])` 기반 평균이 100ms를 한 번 넘으면 된다.
- 더구나 `rate([5m])`는 2분 몰림을 5분 동안 끌고 다니고, lookback 5분이 창을 늘린다. 그래서 몰림 뒤 최대 15분 남짓 동안 평가할 때마다 걸릴 수 있다(추정).

### 2.3 서브쿼리는 지속 조건을 만들지 못한다

엔진은 `expr[10m:1m]`을 오류 없이 받는다([engine.rs L290-314][oo-engine-sub]). 그러나 Prometheus와 다르게 동작한다.

- 서브쿼리 step(`:1m`)은 무시된다. 안쪽 식은 바깥 쿼리의 step 시각(알림에서는 period/256)에서 계산된다.
- 쿼리 시작 시각을 서브쿼리 범위만큼 앞당기지 않는다. step 시각은 `start`부터 만든다([value.rs L434-443][oo-ts]). 원시 선택자만 `start` 이전 데이터를 더 읽는다.
- 그래서 `min_over_time(x[10m:1m])`는 각 step에서 `[start, 그 step]` 안의 안쪽 점만 본다. **구간의 첫 step에서는 점이 하나뿐이라 순간값과 같다.** 비교 필터가 step마다 적용되므로, 이 첫 step(또는 그 근처)의 순간값이 임계를 넘으면 발화한다.
- 우리 실측 “서브쿼리를 오류 없이 무시하고 순간값을 돌려준다”는 instant query(`start = end`)에서 창에 점이 하나만 남는 경우와 같다. 소스 해석과 실측이 모순되지 않는다. 다만 위 동작은 코드를 읽어 얻은 결론이고 알림 경로에서 실행해 보지는 않았다.

영향받는 정의:
- `infra-cpu-usage-p1`·`p2`는 `min_over_time((...)[10m:1m])`로 “10분 내내”를 흉내 내려 했지만 실제로는 한 점 판정이다.
- `defaults/main.yml`의 기존 주석 “sum by() 결과를 서브쿼리로 감싸면 빈 결과가 나온다”는 안쪽 식이 matrix가 아닐 때 `NotImplemented`가 나는 경로와 관련 있어 보인다(미검증).

### 2.4 지속 조건을 만드는 방법 (실서버 검증 전 제안)

| 방법 | 내용 | 장점 | 제약 |
|---|---|---|---|
| **A. `pending_period_sec`** | 첫 일치에서 `Pending`이 되고, `now − since ≥ pending_period_sec`이면 `Firing`이 된다. 일치하지 않는 평가는 `Normal`로 기록되어 대기를 처음부터 다시 시작한다 | Prometheus `for:`와 같은 의미다. 모든 알림 유형(SQL·PromQL)에 쓸 수 있다 | ① Config 역할이 이 필드를 보내지 않는다(`filter_plugins/openobserve_config.py`의 trigger 조립). 계획 비교에도 넣어야 한다. ② 평가 한 번이 여전히 “period 안의 한 점”이므로 period를 frequency 이하로 짧게(예: period 2·frequency 1) 둬야 연속성이 촘촘해진다. ③ `Normal`이 대기를 다시 시작하는지는 코드 일부에서 추론했다. 상태 기록 경로 끝까지는 추적하지 않았다. ④ DB 마이그레이션 `m20260825_000001_add_alert_pending_period_col`로 들어온 최근 기능이다. 운영 서버에서 API 왕복(GET에 값이 남는지)과 실제 대기를 먼저 확인한다 |
| **B. 원시 시리즈의 range 함수** | `max_over_time(system_cpu_utilization{state='idle'}[10m])` (= 10분 내내 idle이 이 값 이하). `rate()` 창을 늘린 `rate(x[30m])` (= 30분 평균) | 지금 엔진에서 동작한다. 원시 선택자는 `start` 이전 데이터를 읽는다. 이전 조사에서 `max_over_time(system_memory_usage[7d])`가 실제로 동작했다 | `rate([30m])`은 평균이지 “내내”가 아니다. `avg by()` 같은 집계 결과에는 range 함수를 걸 수 없다(서브쿼리가 필요해진다). EL6의 CPU별 시리즈는 바깥 `avg by(host_name)`으로 근사한다 |
| **C. SQL 메트릭 알림의 `min()`** | 디스크·메모리 사용률처럼 `_timestamp`별로 값을 만든 뒤 `min(...)`으로 구간 전체를 요구한다 | 이미 운영 중이고 의미가 정확하다. 합성 레코드 검증(O2C-030~034)도 붙는다 | 게이지에만 쉽게 쓴다(`system_cpu_utilization`은 게이지라 가능하다). 누적 counter(디스크 지연)는 SQL에서 차분해야 한다. 창 함수 `lag()`가 이 버전에서 동작하는지는 확인하지 않았다 |
| **D. `promql_multi_alert = true`** | 필터 없이 돌려 시리즈마다 마지막 값만 비교한다 | “한 점 발화”가 “마지막 값 판정”으로 바뀐다 | 지속 조건이 생기는 것은 아니다. multi 모드는 시리즈별 상태와 그룹핑 경로를 타며, 그룹핑은 비엔터프라이즈 빌드에서 꺼져 있다. OSS에서 실제 동작은 확인하지 않았다 |

권고 조합: 지속성이 필요한 알림은 **B로 식 자체를 평균·최댓값 창으로 바꾸고, A를 더하고, period를 frequency와 같게 줄인다.** A가 검증될 때까지는 B만으로도 ns0338 같은 2분 몰림은 걸러진다. 30분 평균이 100ms를 넘으려면 몰림이 매우 커야 한다.

## 3. 전수 비교표

표기:
- 우리 조건의 `p/f/s`는 period/frequency/silence(분)다.
- “지속성”은 실제 의미다. **진짜**: SQL `min()`이나 `max()=0`으로 구간 전체를 요구한다. **한 점**: §2.2에 따라 구간 안의 한 점이면 발화한다. **사건**: 로그 1건 이상이다.
- 권고는 유지, 임계 조정, 조건 변경, 등급 변경, 폐기 중 하나다.

### 3.1 PromQL 알림 (16개)

| # | 알림 (등급) | 현재 조건 | 지속성 | 대응 업계 규칙과 조건 | 차이 | 권고 | 근거 |
|---|---|---|---|---|---|---|---|
| 1 | `infra-cpu-usage-p1` (P1) | `min_over_time((floor((1 − avg by(host_name)(cpu_util{state='idle'}))×10000)/100)[10m:1m]) >= 90`, p/f/s 10/5/60 | **한 점** (서브쿼리 무시) | `NodeCPUHighUsage`: `rate(cpu{mode!~"idle\|iowait"}[2m])` 합 ×100 > 90, **for 15m, info**. AWS: >80%, 5분×3 | ① 업스트림은 호출 등급이 아니다(info) ② 우리는 iowait·steal까지 “사용”으로 센다 ③ 지속 조건이 실제로는 없다 | **등급 변경 + 조건 변경**: P2(또는 P3)로 내린다. `1 − max_over_time(cpu_util{state='idle'}[15m])`처럼 원시 시리즈 창을 쓰거나 SQL `min()`으로 바꾸고, iowait·steal은 별도 알림에 맡긴다. `pending_period_sec` 15분 | [nm-alerts], [sre-ch6], [aws-rec] |
| 2 | `infra-cpu-usage-p2` (P2) | 위 식의 `>= 80 < 90` 범위, 10/5/1440 | **한 점** | 대응 규칙 없음. AWS 권장 80%/15분이 가장 가깝다 | 80~90% 구간을 따로 알리는 업스트림 규칙은 없다. 한 점 판정이라 일상 부하의 짧은 튐에도 울린다 | **등급 변경(P3) 또는 폐기**. 1번을 P2로 내리면 이 알림은 중복이다 | [aws-rec], [prom-practice] |
| 3 | `infra-caddy-5xx-error-rate` (P1) | 10분 `increase` 기준 5xx 비율 ≥ 5%, 요청 ≥ 10건, 10/5/60 | 한 점(10분 창 비율이라 자체로 평활됨) | SRE: 증상 기반 오류율, SLO 소진율(99.9%면 1h 창 14.4배 = 오류율 1.44%) | 사용자 영향을 보는 증상 알림이라 철학에 맞다. 10분 창 5%는 99.9% SLO 기준 50배 소진에 해당해 호출 기준으로 합리적이다(계산) | **유지**. period를 5로 줄이면 창 겹침이 줄어든다. SLO를 정하면 다단 창 소진율로 옮긴다 | [sre-slo], [prom-practice] |
| 4 | `infra-caddy-4xx-error-rate` (P3) | 4xx(401·499 제외) 비율 ≥ 5%, 요청 ≥ 100건, 10/5/1440 | 한 점(평활) | 업계 공통 규칙 없음. 4xx는 클라이언트 오류라 보통 SLO에서 뺀다 | P3이라 부담이 적다 | **유지** | [sre-slo] |
| 5 | `infra-disk-fill-24h` (P2) | `free / −deriv(free[6h]) / 3600 < 24` and 사용률 ≥ 60% and deriv < 0, `mode='rw'`, 30/30/1440 | 한 점 | `NodeFilesystemSpaceFillingUp` warning: 여유 < 40% and `predict_linear(avail[6h], 24h) < 0` and readonly == 0, **for 1h**. critical: 여유 < 20%, 4h 예측, for 1h | 식은 업스트림과 같다(`predict_linear < 0` ⇔ `free/(−deriv) < 24h`). `for 1h`만 없다. 4시간 예측 critical 단계가 없다 | **조건 변경**: `pending_period_sec` 1시간. 4시간 예측·여유 20% 미만 P1을 추가 후보로 둔다(§4) | [nm-alerts] |
| 6 | `infra-network-errors` (P2) | 물리 IF의 `increase(errors[10m]) >= 10`, 10/5/60 | 한 점 | `NodeNetworkReceiveErrs`/`TransmitErrs`: `rate(errs[2m])/rate(packets[2m]) > 0.01`, **for 1h** | 절대 건수라 트래픽이 많은 IF에서는 비율이 극히 낮아도(예: 0.001%) 울리고, 적은 IF에서는 큰 비율도 놓칠 수 있다. 지속 조건이 없다 | **조건 변경**: `system_network_errors / system_network_packets`(둘 다 기본 수집) 비율 > 1% + 최소 건수 하한, `pending_period_sec` 1시간(또는 `rate([1h])`) | [nm-alerts] |
| 7 | `infra-cpu-load-saturation` (P2) | `load_average_1m / logical_count > 2`, 10/5/60 | 한 점 | `NodeSystemSaturation`: `node_load1 / cores > 2`, **for 15m** | 임계는 같다. 1분 load의 한 점만으로 울린다 | **조건 변경**: `pending_period_sec` 15분. 당장은 `system_cpu_load_average_15m`으로 바꾸면 비슷하게 평활된다 | [nm-alerts] |
| 8 | `infra-cpu-iowait` (P2) | `avg(cpu_util{state='wait'})×100 > 10`, 5/5/60 | 한 점 | 대응 규칙 없음. node-mixin과 kubernetes-mixin은 iowait를 CPU 사용에서 **뺀다**. iowait는 원인 지표다 | 증상이 아니다. 디스크 지연·포화 알림과 겹친다 | **등급 변경(P3) + 지속 조건**(15분). 디스크 지연 알림을 정비한 뒤 폐기를 검토한다 | [nm-alerts], [km-node], [sre-ch6] |
| 9 | `infra-cpu-steal` (P2) | `avg(cpu_util{state='steal'})×100 > 10`, 5/5/60 | 한 점 | 대응 규칙 없음(kubernetes-mixin은 steal을 사용에서 뺀다) | 가상화 호스트에만 의미가 있다. 조치는 하이퍼바이저 측에서 한다 | **등급 변경(P3) + 지속 조건**(15~30분) | [km-node] |
| 10 | `infra-disk-io-saturation` (P2) | `sum by(host_name,device)(rate(weighted_io_time[5m])) > 10`, 5/5/60 | 한 점 | `NodeDiskIOSaturation`: `rate(io_time_weighted[5m]) > 10`, **for 30m**. kube-prometheus는 장치를 `sd.+\|nvme.+\|vd.+\|dm-.+\|md.+` 등으로 제한한다 | 식·임계는 같다. `for 30m`이 없다. 장치 필터가 없어 파티션·dm·루프 장치가 섞인다 | **조건 변경**: `rate([30m])` 또는 `pending_period_sec` 30분, 장치 정규식 추가 | [nm-alerts], [kp-ne] |
| 11 | `infra-disk-read-latency` (P2) | `rate(op_time{read}[5m])/rate(ops{read}[5m])×1000 > 100` and 읽기 IOPS ≥ 5, 10/5/60 | **한 점** (문구는 “10분 내내”) | node-mixin에 지연 규칙은 없다(큐 길이만 본다). Microsoft: 10~15ms “consistently”. VMware: 10ms “sustained” | 임계 100ms는 업계 절대값보다 7~10배 느슨하다. HDD·쓰기 캐시 없는 RAID를 고려한 값으로 볼 수 있다. 지속 조건이 실제로는 없다 | **조건 변경**: 창을 `[30m]`으로 늘려 평균 지연으로 판정하고, `pending_period_sec` 30분, period 5. 임계는 장치 유형별 덮어쓰기(SSD 낮게)를 검토한다. 런북 문구를 고친다 | [ms-io], [vmw-kb], §2.2 |
| 12 | `infra-disk-write-latency` (P2) | 위와 같고 `direction='write'` | **한 점** | 위와 같다 | 2026-10-22 사례(§5)의 직접 원인이다 | **조건 변경**(11번과 같이). 원인이 컨트롤러 캐시인 호스트는 별도 하드웨어 알림으로 옮기고, 그동안은 만료일이 있는 호스트 예외로 다룬다 | §5 |
| 13 | `infra-inode-fill-24h` (P2) | `free / −deriv(free[1h]) / 3600 < 24` and deriv < 0, 30/30/1440 | 한 점 | `NodeFilesystemFilesFillingUp` warning: 여유 < 40% and `predict_linear(files_free[6h], 24h) < 0`, **for 1h** | 추세 창이 1시간이라 짧은 파일 생성 폭주(임시 파일)에 흔들린다. “여유 40% 미만” 하한이 없다. 지속 조건이 없다 | **조건 변경**: 창 `[6h]`, 여유 < 40% 조건, `pending_period_sec` 1시간 | [nm-alerts] |
| 14 | `infra-conntrack-limit` (P2) | `count/max×100 > 80`, 5/5/60 | 한 점 | `NodeHighNumberConntrackEntriesUsed`: `> 0.75`, for 없음 | 업스트림도 for가 없다. 임계만 75 대 80이다 | **유지**(원하면 75로 맞춘다) | [nm-alerts] |
| 15 | `infra-swap-usage` (P3) | 스왑 사용률 > 80% and 사용 가능 메모리 < 10%, 10/5/1440 | 한 점 | node-mixin에 스왑 규칙은 없다. 메모리 압박은 `NodeMemoryMajorPagesFaults`(> 500/s, 15m)와 `NodeMemoryHighUtilization`(> 90%, 15m)으로 본다 | #303·#307에서 복합 조건으로 바꿔 업스트림 철학(원인 지표는 낮은 등급)에 가까워졌다. 사용 가능 메모리 조건은 `infra-memory-usage-p1`(95%)과 겹친다 | **유지**(P3). 지속 조건은 `pending_period_sec` 15분 | [nm-alerts] |
| 16 | `infra-memory-pressure` (P2) | `rate(paging_faults{major}[5m]) > 1000` and 사용 가능 메모리 < 10%, 5/5/60 | 한 점 | `NodeMemoryMajorPagesFaults`: `rate(pgmajfault[5m]) > 500`, **for 15m**, warning | 임계를 2배로 하고 메모리 조건을 더해 업스트림보다 좁다. 지속 조건이 없다 | **조건 변경**: `pending_period_sec` 15분(또는 `rate([15m])`) | [nm-alerts] |

### 3.2 SQL 메트릭 알림 (11개)

| # | 알림 (등급) | 현재 조건 | 지속성 | 대응 업계 규칙과 조건 | 차이 | 권고 | 근거 |
|---|---|---|---|---|---|---|---|
| 17 | `infra-disk-usage-p2` (P2) | 사용률 15분 `min` ≥ 90 and < 95, tmpfs·overlay 등 제외, 15/5/1440 | **진짜** | `NodeFilesystemAlmostOutOfSpace` warning: 여유 < 5%(=사용 > 95), for 30m. Datadog: 여유 < 10% | 우리가 더 일찍(90%) 알린다. Datadog 10%와 같다 | **유지** | [nm-alerts], [dd-disk] |
| 18 | `infra-disk-usage-p1` (P1) | 15분 `min` ≥ 95, 15/5/60 | **진짜** | 업스트림 warning은 95%, critical은 97%(for 30m) | 업스트림이 warning으로 두는 95%를 우리는 P1(호출)로 둔다 | **임계 조정 검토**: P1을 97%(업스트림 critical)로 올리거나 P1에 4시간 예측을 조합한다. 볼륨 크기가 작으면 95% 유지도 타당하다 | [nm-alerts] |
| 19 | `infra-inode-usage-p2` (P2) | inode 15분 `min` ≥ 90 and < 95 | **진짜** | `NodeFilesystemAlmostOutOfFiles` warning: < 5%, for 1h | 우리가 더 일찍 알린다 | **유지** | [nm-alerts] |
| 20 | `infra-inode-usage-p1` (P1) | inode 15분 `min` ≥ 95 | **진짜** | critical: 여유 < 3%, for 1h | 18번과 같은 차이 | **임계 조정 검토**(97%) | [nm-alerts] |
| 21 | `infra-memory-usage-p2` (P2) | `1 − available/limit` 10분 `min` ≥ 90 and < 95 | **진짜** | `NodeMemoryHighUtilization`: > 90%, **for 15m**, warning | 정의(MemAvailable/MemTotal)와 임계가 같다. 창만 10분 대 15분이다 | **유지**(원하면 period 15) | [nm-alerts] |
| 22 | `infra-memory-usage-p1` (P1) | 10분 `min` ≥ 95 | **진짜** | 업스트림 critical 단계 없음 | 메모리 고갈은 원인 지표이고 증상은 `infra-oom-kill`이다. 업스트림은 호출하지 않는다 | **유지 또는 등급 변경 검토**. 운영 규모상 OOM 직전 경보로 호출할 가치가 있다면 유지한다. 그 경우 런북에 “증상 전 선행 경보”라고 밝힌다 | [nm-alerts], [sre-ch6] |
| 23 | `infra-silent-host-p2` (P2) | 수집 로스터 호스트의 `system_memory_usage`가 15분 없음, 180/5/1440 | **진짜**(부재) | kube-prometheus `TargetDown`: 10m. New Relic host not reporting: 5~60분 창. Prometheus: 메타모니터링 권장 | 범위 안이다 | **유지** | [kp-general], [nr-hnr], [prom-practice] |
| 24 | `infra-silent-host-p1` (P1) | 3시간 없음 | **진짜** | 위와 같다. 우리는 수집 허용 5시간(로그 영구 유실) 전에 올린다 | 근거가 우리 고유(ISMS 로그 보존)라 타당하다 | **유지** | 위와 같다 |
| 25 | `infra-unreachable-host` (P1) | `tcpcheck_status` 5분 `max = 0`, 5/1/60 | **진짜**(5분 연속 실패) | AWS StatusCheckFailed: 5분×2. 블랙박스 탐침도 연속 실패 for가 관행이다 | 범위 안이다. 도달성은 증상에 가깝다 | **유지** | [aws-rec] |
| 26 | `infra-app-telemetry-silent` (P2) | `jvm_memory_used{service_name='funa'}` 15분 없음 | **진짜**(부재) | 메타모니터링(Prometheus practices) | — | **유지** | [prom-practice] |
| 27 | `infra-backup-missing` (P2) | 성공 백업 26시간 없음, 1560/60/1440 | **진짜** | Prometheus: 배치는 최소 2주기 연속 실패 시 호출 | 우리는 1주기 + 2시간이다. P2(당일 확인)라 호출이 아니므로 충돌하지 않는다 | **유지** | [prom-practice] |

### 3.3 로그·SQL 알림 (26개)

| # | 알림 (등급) | 현재 조건 | 대응 업계 관행 | 차이 | 권고 | 근거 |
|---|---|---|---|---|---|---|
| 28 | `infra-ssh-login-failures-per-source` (P2) | 같은 출발지 5분 ≥ 10회, 5/1/5 | fail2ban 기본: 10분 5회면 차단. Wazuh 5712/5763: 120초 8회. Elastic: 30초 60회 | fail2ban이 5회에서 차단하므로, 10회가 보이면 fail2ban이 막지 못한다는 뜻이다. 의도에 맞다 | **유지** | [f2b], [wz-sshd], [el-ssh-ext] |
| 29 | `infra-ssh-login-failures-per-host` (P2) | 호스트 5분 ≥ 50회 | 분산 공격 관행 규칙 없음(Elastic·Wazuh는 출발지 기준) | 우리 고유 보완이다 | **유지** | — |
| 30 | `infra-root-login-success` (P1) | 외부 출발지 root 로그인 성공 1건 | 정책 위반 탐지(PermitRootLogin). Elastic에는 “실패 다수 뒤 성공” 규칙이 있다 | — | **유지**. “실패 뒤 성공” 규칙은 추가 후보(§4) | [el-ssh-ok] |
| 31 | `infra-root-login-known` (P2) | 등록·사설 출발지 root 로그인, 재통지 60분 | — | — | **유지** | — |
| 32 | `infra-sudo-escalation-failure` (P2) | sudo/su 실패 1건부터 | 1차 출처의 임계는 이번에 확인하지 못했다 | 오입력 1건에도 울린다 | **유지**. 관찰 뒤 반복(예: 5분 3회)으로 올릴지 정한다 | — |
| 33 | `infra-oom-kill` (P2) | `killed process`·`out of memory: kill process`·`invoked oom-killer` | Wazuh 5108: `Out of Memory: ` 일치, level 12(높음) | 우리 패턴이 더 넓다(cgroup OOM, 최신 커널 문구 포함). 증상 알림이다 | **유지** | [wz-syslog] |
| 34 | `infra-disk-fs-errors` (P1) | `i/o error`·`ext4-fs error`·XFS corruption·`blk_update_request`·`buffer i/o error` | Wazuh 5109: `I/O error: dev`·`end_request: I/O error, dev`, level 4. Sigma·Elastic에는 규칙 없음 | 업계 규칙 중 이를 호출 등급으로 두는 1차 출처는 없다. 데이터 손실 위험이라 P1은 우리 판단이다 | **유지**. `i/o error`는 넓은 패턴이니 오탐이 나오면 커널 출처(`kernel:`)로 좁힌다 | [wz-syslog], [sigma] |
| 35 | `infra-keepalived-script-disabled` (P1) | keepalived “Unsafe permissions”·“Disabling track script” | 우리 고유(#314) | — | **유지** | — |
| 36 | `infra-app-log-errors` (P2) | 컨테이너 ERROR 이상 1줄부터 | SRE·Prometheus: 증상 기반, 할 일이 없는 알림은 피한다. 로그 ERROR 건수에 대한 1차 출처 임계는 없다 | 1줄 기준은 잡음 위험이 크다. 같은 영향은 Caddy 5xx(증상)가 더 직접적으로 본다 | **조건 변경 검토**: 컨테이너별 5분 N건 이상이나 직전 대비 급증으로 바꾸거나 P3으로 내린다. 2주 발화 기록을 보고 정한다 | [sre-ch6], [prom-practice] |
| 37 | `infra-log-parse-errors-security-logs` (P3) | 30분 해석 실패율 ≥ 10%, 20줄 이상 | 메타모니터링 | — | **유지** | [prom-practice] |
| 38 | `infra-log-parse-errors-system-logs` (P3) | 같음 | 같음 | — | **유지** | 같음 |
| 39 | `infra-backup-failure` (P2) | `job=backup, success=false` 1건 | Prometheus: 배치 한 번 실패는 사람 개입 대상이 아니다 | P2는 호출이 아니라 당일 확인이라 충돌하지 않는다 | **유지**(또는 P3) | [prom-practice] |
| 40 | `infra-integrity-check-failure` (P2) | restic check 실패 | 저장소 손상 의심이라 1회로도 의미가 있다 | — | **유지** | — |
| 41 | `infra-maintenance-missing` (P2) | check 기록 8일 없음 | 주간 작업 + 1일 여유 | — | **유지** | [prom-practice] |
| 42 | `infra-switch-config-change` (P2) | `SYS-5-CONFIG_I` 1건 | 변경 관리 증적(ISMS) | — | **유지** | — |
| 43 | `infra-switch-login-failures` (P2) | 장비 5분 ≥ 5회 | fail2ban 기본 5회/10분과 같은 규모 | — | **유지** | [f2b] |
| 44 | `infra-switch-severity-critical` (P1) | syslog 심각도 0~2 | RFC 5424: 0 Emergency, 1 Alert(“action must be taken immediately”), 2 Critical | 정의상 즉시 조치 대상이다 | **유지** | [rfc5424] |
| 45 | `infra-switch-uplink-down` (P1, **기본 비활성**) | 감시 목록 포트의 링크 다운 | kube-prometheus `NodeNetworkInterfaceFlapping`(2분 3회 이상 변화)이 가장 가깝다 | 목록이 비어 규칙이 없다 | **유지**(목록을 채우면 활성) | [kp-node] |
| 46 | `infra-switch-mac-flap` (P2) | 10분 ≥ 2회, 재통지 60분 | 1차 출처 임계 없음 | 관찰값(3시간 25건) 기준으로 기본값이 상시 발화 수준이다 | **임계 조정 검토**(관찰 2주 뒤) | — |
| 47 | `infra-switch-syslog-silent` (P2) | 24시간 없음 | 메타모니터링 | — | **유지** | [prom-practice] |
| 48 | `infra-fortigate-admin-login-failures` (P2) | 출발지 5분 ≥ 5회 | fail2ban 기본과 같은 규모 | — | **유지** | [f2b] |
| 49 | `infra-fortigate-change-unapproved` (P1) | 승인 시간 밖 정책·계정 변경 | 변경 관리(ISMS 2.9.1) | — | **유지** | — |
| 50 | `infra-fortigate-change-approved` (P3) | 승인 시간 안 하루 요약 | 같음 | — | **유지** | — |
| 51 | `infra-fortigate-ha-failover` (P2) | `subtype=ha`(정보 로그 제외) | — | — | **유지** | — |
| 52 | `infra-fortigate-critical-detection` (P1) | UTM `severity=critical` 또는 감염 | — | — | **유지** | — |
| 53 | `infra-fortigate-syslog-silent` (P2) | 120분 없음 | 메타모니터링 | — | **유지** | [prom-practice] |

### 3.4 표 요약

- **유지 35개.** SQL 메트릭 알림과 로그 알림이 대부분이다. 조건을 손볼 이유가 업계 규칙에서 나오지 않았다.
- **조건 변경 11개.** 모두 PromQL이다. 공통 원인은 “지속 조건 부재”(§2)이며, 업스트림의 `for`(15분~1시간)를 맞추는 것이 핵심이다.
  - `infra-disk-fill-24h`
  - `infra-network-errors`
  - `infra-cpu-load-saturation`
  - `infra-disk-io-saturation`
  - `infra-disk-read-latency`·`infra-disk-write-latency`
  - `infra-inode-fill-24h`
  - `infra-memory-pressure`
  - `infra-cpu-usage-p1`: 등급 변경을 겸한다
  - `infra-cpu-iowait`·`infra-cpu-steal`: 등급 변경을 겸한다
- **등급 변경 또는 폐기 1개**: `infra-cpu-usage-p2`(P3으로 내리거나 1번과 통합).
- **검토 6개**: 관찰이 필요하다.
  - `infra-disk-usage-p1`·`infra-inode-usage-p1` 임계(97%)
  - `infra-memory-usage-p1` 등급
  - `infra-app-log-errors`
  - `infra-sudo-escalation-failure`
  - `infra-switch-mac-flap`

## 4. 추가할 만한 알림 후보

“수집” 열의 표기:
- **현재 가능**: 지금 들어오는 메트릭·로그로 만들 수 있다.
- **설정 변경**: hostmetrics 선택 메트릭이나 스크레이퍼를 켜면 된다.
- **수집 추가**: hostmetrics 밖의 수단이 필요하다.

| 우선 | 후보 | 업계 규칙 | 수집 | 우리 쪽 구현안 |
|---|---|---|---|---|
| 1 | **RAID 컨트롤러 캐시·배터리 이상** | node-mixin은 md(소프트웨어 RAID)만 본다(`NodeRAIDDegraded` for 15m critical, `NodeRAIDDiskFailure`). 하드웨어 RAID는 벤더 도구를 쓴다(§5.3) | **수집 추가** | `ssacli`가 있는 HP 호스트에서 cron 스크립트로 `ctrl all show status`를 읽어 JSON 줄(`{host, controller, controller_status, cache_status, battery_status}`)을 남기고 filelog로 수집한다(`backup.jsonl` 방식). 그 위에 SQL 로그 알림(상태 ≠ OK, P2)과 부재 알림을 둔다 |
| 2 | **시각 동기 이탈** | `NodeClockSkewDetected`(\|offset\| > 0.05s, 10m), `NodeClockNotSynchronising`(10m). Datadog NTP 기본 60초 | **수집 추가**: hostmetrics에는 timex가 없다 | chrony 호스트는 otelcol-contrib `chrony` 리시버로 넣을 수 있다(배포판 포함 여부·EL6 ntpd는 미확인). 아니면 `chronyc tracking` 결과를 JSON 줄로 남긴다. 로그 타임스탬프가 ISMS 증적이라 우선순위가 높다 |
| 3 | **파일시스템 4시간 내 고갈 (P1)** | `NodeFilesystemSpaceFillingUp` critical: 여유 < 20% and `predict_linear(avail[6h], 4h) < 0`, for 1h | **현재 가능**(`system_filesystem_usage`) | `infra-disk-fill-24h`의 식에서 24를 4로, 60%를 80%로 바꾼다. `pending_period_sec`이 검증되면 1시간 |
| 4 | **실패 뒤 성공한 SSH 무차별 대입** | Elastic “Potential Successful Linux SSH Brute Force”: 같은 출발지 실패 25회 뒤 성공(15초 안) | **현재 가능**(`security_logs`의 `event_action='ssh_login'`) | 같은 `source_address`에서 구간 안에 실패 ≥ N이고 성공 ≥ 1(사용자 무관)이면 P1. `infra-ssh-login-failures-per-source` 조치 ③(“성공 기록이 있으면 P1로 격상”)을 자동화한다 |
| 5 | **systemd 서비스 실패** | `NodeSystemdServiceFailed`(5m), `Crashlooping`(5분에 3회 이상 재시작, 15m) | **수집 추가**(메트릭) / **현재 가능**(로그, journald 수집 호스트) | `system_logs`에서 systemd의 “entered failed state”/“Failed with result” 줄을 장치(unit)별로 센다. journald 수집은 호스트별 설정이고, rsyslog 파일에도 같은 줄이 남는다 |
| 6 | **재부팅 탐지** | node-mixin·kube-prometheus에는 규칙이 없다. Datadog·node_exporter는 uptime을 기본 수집한다 | **현재 가능**(`system_uptime`, `system` 스크레이퍼 켜짐) | `system_uptime < 900` → P3 사건 알림. 15분 미만 재부팅은 Silent Host에 안 잡히므로 공백을 메운다 |
| 7 | **알림 경로 Watchdog** | kube-prometheus `Watchdog`(`vector(1)`, 항상 발화) | **현재 가능** | 지금의 자가 시험(`infra-alert-selftest`)은 수동 실행 때만 울린다. 하루 1번 정해진 시각에 울리는 상설 시험이나, ns0266 `openobserve-health.timer`가 통지까지 확인하는 방식을 검토한다 |
| 8 | **본딩 저하·인터페이스 플래핑** | `NodeBondingDegraded`(5m), `NodeNetworkInterfaceFlapping`(2분 3회 이상) | **수집 추가**(메트릭) / **현재 가능**(커널 로그 “link status definitely down”·“NIC Link is Down”) | 본딩을 쓰는 호스트가 있을 때만 로그 알림으로 만든다 |
| 9 | **커널 파일 핸들 고갈** | `NodeFileDescriptorLimit` > 70%/90%, 15m | **수집 추가**(`/proc/sys/fs/file-nr`, hostmetrics에 없음) | 낮은 우선순위. 발생하면 커널 로그 “VFS: file-max limit reached”로 잡는 쪽이 싸다 |
| 10 | **읽기 전용 재마운트** | node-mixin은 `readonly == 0`을 다른 규칙의 조건으로만 쓴다 | **현재 가능**(`system_filesystem_usage{mode}` 또는 커널 로그 “Remounting filesystem read-only”) | `infra-disk-fs-errors`에 문구를 더하는 것으로 충분할 수 있다 |

## 5. 배경 사례: 2026-10-22 `infra-disk-write-latency` 발화

### 5.1 관찰 (사용자 실측)

| 호스트 | 하드웨어·상태 | 지연 양상 | 판단 |
|---|---|---|---|
| ns0288 | HP Smart Array P440, 쓰기 캐시 **Permanently Disabled**, Cable Error, SATA RAID10 | 하루의 58% 동안 쓰기 지연이 100ms를 넘는다 | 진짜 문제(지속) |
| ns0329 | 컨트롤러 캐시 영구 비활성(배터리 미장착) | 상시 고지연 경향 | 진짜 문제(구성) |
| ns0272·ns0273 | HP ProLiant DL120 Gen9, `ssacli` 없음(캐시 상태 미확인) | 중앙값 약 95ms, 상시 | 만성. 원인 확인 필요 |
| ns0338 | — | 17:17~17:19 2분 몰림 | 일시적. 지속 아님 |

### 5.2 업계 규칙을 적용하면

- **`NodeDiskIOSaturation`**(`rate(weighted_io_time[5m]) > 10`, for 30m)
  - 평균 큐 길이는 리틀의 법칙으로 IOPS × 평균 지연이다.
  - 지연 95ms에서 큐가 10을 넘으려면 약 105 IOPS 이상이 30분 동안 이어져야 한다(10 / 0.095 ≈ 105, **추정**).
  - 결과적으로 ns0272·ns0273처럼 **느리지만 바쁘지 않은** 디스크는 이 규칙에 걸리지 않을 가능성이 크다. ns0288도 IOPS에 따라 갈린다.
  - ns0338의 2분 몰림은 `for: 30m`을 채우지 못하므로 **절대 울리지 않는다.**
  - 큐 길이 규칙은 “포화”를 보는 것이고, 캐시가 꺼져 write-through로 느려진 상태(“느림”)를 보지 않는다.
- **절대 지연 기준**(Microsoft 10~15ms “consistently”, VMware 10ms “sustained”)
  - 네 호스트 모두 “조사 대상”이다.
  - 다만 이 기준은 SAN·SSD·가상화 스토리지를 전제로 한 경험값이다(출처가 스스로 근사라고 밝힌다). SATA HDD RAID10에서 쓰기 캐시가 없으면 쓰기마다 원판 기록을 기다리므로, 수십 ms가 구조적으로 나올 수 있다(추정).
  - 그래서 우리 100ms 임계는 “HDD에서도 비정상”인 선으로 볼 수 있다. 대신 **지속 조건**이 있어야 업계 기준(“consistently”, “sustained”)과 같은 뜻이 된다.
- **우리 알림을 §2.4 권고대로 바꾸면**(`rate([30m])` 평균 > 100ms + `pending_period_sec` 30분, 추정 판정)
  - ns0288: 하루 58%가 100ms 초과라 긴 구간마다 발화한다. 맞는 판정이다.
  - ns0272·ns0273: 중앙값 95ms라 임계 바로 아래에서 오르내린다. 지금(한 점 판정)보다는 덜 울리지만 간헐 발화는 남는다. 만성 상태를 매일 알리는 것은 SRE의 “novel problem” 원칙에 맞지 않는다. 원인 조치 전까지는 만료일이 있는 호스트 예외로 두고, 하드웨어 점검을 티켓으로 추적하는 편이 맞다.
  - ns0338: 2분 몰림은 30분 평균에서 희석되어 발화하지 않는다. 맞는 판정이다.

결론: 지연 알림은 “디스크가 느리다”는 증상을 알리고, **원인(캐시 비활성·배터리·케이블 오류)은 컨트롤러 상태 알림이 따로 알려야 한다.** 그래야 ns0288·ns0329처럼 원인이 분명한 호스트가 지연 알림으로 매일 반복되지 않는다.

### 5.3 RAID 컨트롤러 캐시·배터리를 감시하는 업계 방법

| 방법 | 읽는 값 | 우리 환경 적합성 | 출처 |
|---|---|---|---|
| HPE `ssacli` | `ctrl all show status`(Controller / Cache / Battery/Capacitor Status), `ctrl slot=N show config detail` | OS 안에서 돈다. ns0272·ns0273에는 설치가 필요하다. 출력 형식을 스크립트로 파싱해 JSON 줄로 남기면 기존 filelog·SQL 알림 구조에 그대로 들어간다 | [HPE KB (ssacli 명령)][hpe-ssacli] |
| SNMP `CPQIDA-MIB` | `cpqDaAccelStatus`(enabled 3, tmpDisabled 4, **permDisabled 5** …), `cpqDaAccelErrCode`(lowBattery 4 등), `cpqDaAccelBattery`(ok 2, recharging 3, failed 4, degraded 5, **notPresent 6**, capacitorFailed 7), 트랩 `cpqDaAccelStatusChange`·`cpqDaAccelBatteryFailed` | HP SNMP 에이전트가 필요하다. ns0266의 LibreNMS가 폴링하는 경로를 쓸 수 있다(LibreNMS의 HP 지원 범위는 이번에 확인하지 않았다) | [CPQIDA-MIB (LibreNMS 사본)][cpqida] |
| iLO Redfish | DMTF `StorageController.CacheSummary.Status`, `Battery` 스키마. HPE OEM `HpeSmartStorageArrayController.BackupPowerSourceStatus` | OS와 무관하게 BMC에서 읽는다. iLO 네트워크와 계정이 필요하다. OEM 필드 값 목록은 확인하지 못했다 | [Redfish StorageController][rf-sc], [Redfish Battery][rf-bat] |
| node_exporter textfile 스크립트 | `storcli.py`(MegaRAID: `battery_backup_healthy`, `cv_state`), `md_info.sh`(md), `smartmon` | HP Smart Array용 스크립트는 **없다**. 우리는 node_exporter를 쓰지 않으므로 형식만 참고한다 | [textfile-collector-scripts][tf-scripts] |
| smartctl_exporter | 드라이브 SMART | 컨트롤러 캐시·배터리는 보지 않는다. RAID 뒤의 드라이브는 컨트롤러별 옵션(`-d cciss,N`)이 필요하다 | [smartctl_exporter][smartctl-exp] |

`CPQIDA-MIB`의 설명에 따르면 “Permanently Disabled”는 캐시 작업이 영구히 꺼졌다는 뜻이고, 이유는 cache module board error code를 보라고 한다. Battery “Failed”는 “below the sufficient voltage level and has not recharged in 36 hours”이고, “Recharging” 동안에는 write-back 캐시가 일시 중단된다. HPE 고객 권고 c05302924(Gen9 Smart Array가 배터리 문제를 캐시 모듈 고장으로 표시할 수 있음, 펌웨어 6.60 이상에서 수정)는 페이지 본문을 읽지 못해 **미확인**이다([HPE c05302924][hpe-adv]).

## 6. 남은 확인 사항

- `pending_period_sec`이 v1.0.4 운영 서버에서 API로 저장·반환되는지, PromQL 단일 알림에서 대기 후 발화하는지 확인해야 한다. 비발화 평가가 대기를 다시 시작하는지도 함께 본다. Config 역할(trigger 조립·계획 비교)을 바꾸기 전에 검증용 알림 하나로 확인한다.
- §2.3의 서브쿼리 동작(첫 step 순간값)은 코드를 읽어 얻은 결론이다. 알림 경로의 range query로 재현하지 않았다.
- `promql_multi_alert`가 OSS 빌드에서 시리즈별 마지막 값 판정으로 동작하는지 확인하지 않았다.
- New Relic의 호스트 권장 임계, Datadog의 CPU·메모리·네트워크 권장 모니터, HPE ssacli 전체 필드 목록, iLO OEM 열거값, Wazuh 5720 기본 timeframe은 1차 출처로 확인하지 못했다.
- 사례(§5)의 IOPS·큐 길이는 계산으로 낸 추정이다. 운영 서버에 `query_range`로 확인하지 않았다.

## 출처

- Google SRE: [SRE book ch.6 Monitoring Distributed Systems][sre-ch6], [SRE workbook Alerting on SLOs][sre-slo]
- Prometheus: [Alerting practices][prom-practice], [Alerting rules (`for`, `keep_firing_for`)][prom-rules], [Alertmanager configuration][am-config]
- node-mixin·mixin 계열: [node-mixin alerts.libsonnet `b9e296a`][nm-alerts], [node-mixin config.libsonnet][nm-config], [kube-prometheus node.libsonnet `f71fb6c`][kp-node], [kube-prometheus general.libsonnet][kp-general], [kube-prometheus node-exporter.libsonnet][kp-ne], [kubernetes-mixin node.libsonnet `ea8e318`][km-node]
- Grafana: [Linux node integration][grafana-linux], [Alert rule evaluation][grafana-eval]
- Datadog: [Disk space guide][dd-disk], [Metric monitor][dd-metric], [datadog-agent ntp.go][dd-ntp]
- AWS: [Recommended alarms][aws-rec], [Alarm evaluation (M out of N)][aws-eval]
- New Relic: [Host not reporting condition][nr-hnr]
- 디스크 지연: [Microsoft Learn SQL I/O troubleshooting][ms-io], [Broadcom KB 344099 (esxtop)][vmw-kb]
- OpenTelemetry: [semconv system-metrics.md `0eb883b`][semconv], hostmetrics v0.161.0 [disk][hm-disk], [cpu][hm-cpu], [paging][hm-paging], [network][hm-net], [load][hm-load], [system][hm-system]
- OpenObserve v1.0.4 소스: [alerts meta mod.rs][oo-meta], [Alert 모델 alert.rs][oo-alert-model], [API 모델][oo-api], [PromQL 평가 alerts/mod.rs][oo-eval], [aggregation_level.rs][oo-agg], [scheduler handlers.rs (구간)][oo-h-range], [handlers.rs (silence)][oo-h-silence], [handlers.rs (pending)][oo-h-pending], [alert 검증][oo-validate], [promql lib.rs][oo-promql-lib], [engine.rs 서브쿼리][oo-engine-sub], [value.rs timestamps][oo-ts], [vector_operations.rs][oo-vecop], [metrics otlp.rs][oo-otlp], [utils schema.rs][oo-schema]
- OpenObserve 문서: [Alerts][oo-doc-alerts], [Scheduled alerts][oo-doc-sched], [Alert conditions][oo-doc-cond]
- 로그 규칙: [fail2ban jail.conf][f2b], [Elastic SSH brute force (external)][el-ssh-ext], [Elastic successful SSH brute force][el-ssh-ok], [Wazuh sshd rules v4.14.0][wz-sshd], [Wazuh syslog rules v4.14.0][wz-syslog], [SigmaHQ linux builtin][sigma], [RFC 5424 §6.2.1][rfc5424]
- RAID: [CPQIDA-MIB][cpqida], [HPE KB (ssacli)][hpe-ssacli], [HPE advisory c05302924][hpe-adv], [Redfish StorageController v1_9_0][rf-sc], [Redfish Battery][rf-bat], [node-exporter-textfile-collector-scripts][tf-scripts], [smartctl_exporter][smartctl-exp]

[sre-ch6]: https://sre.google/sre-book/monitoring-distributed-systems/
[sre-slo]: https://sre.google/workbook/alerting-on-slos/
[prom-practice]: https://prometheus.io/docs/practices/alerting/
[prom-rules]: https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/
[am-config]: https://prometheus.io/docs/alerting/latest/configuration/
[nm-alerts]: https://github.com/prometheus/node_exporter/blob/b9e296a911c8beaf89177362e75cc80bfa89eb7e/docs/node-mixin/alerts/alerts.libsonnet
[nm-config]: https://github.com/prometheus/node_exporter/blob/b9e296a911c8beaf89177362e75cc80bfa89eb7e/docs/node-mixin/config.libsonnet
[kp-node]: https://github.com/prometheus-operator/kube-prometheus/blob/f71fb6c77d108ad2b4cbf4d9771b56cbe92611fb/jsonnet/kube-prometheus/components/mixin/alerts/node.libsonnet
[kp-general]: https://github.com/prometheus-operator/kube-prometheus/blob/f71fb6c77d108ad2b4cbf4d9771b56cbe92611fb/jsonnet/kube-prometheus/components/mixin/alerts/general.libsonnet
[kp-ne]: https://github.com/prometheus-operator/kube-prometheus/blob/f71fb6c77d108ad2b4cbf4d9771b56cbe92611fb/jsonnet/kube-prometheus/components/node-exporter.libsonnet
[km-node]: https://github.com/kubernetes-monitoring/kubernetes-mixin/blob/ea8e318e706c0c14fe857e9b0182f6b7e0564e88/rules/node.libsonnet
[grafana-linux]: https://grafana.com/docs/grafana-cloud/monitor-infrastructure/integrations/integration-reference/integration-linux-node/
[grafana-eval]: https://grafana.com/docs/grafana/latest/alerting/fundamentals/alert-rule-evaluation/
[dd-disk]: https://docs.datadoghq.com/monitors/guide/monitoring-available-disk-space/
[dd-metric]: https://docs.datadoghq.com/monitors/types/metric/
[dd-ntp]: https://github.com/DataDog/datadog-agent/blob/main/pkg/collector/corechecks/net/ntp/ntp.go
[aws-rec]: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Best_Practice_Recommended_Alarms_AWS_Services.html
[aws-eval]: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/alarm-evaluation.html
[nr-hnr]: https://docs.newrelic.com/docs/infrastructure/infrastructure-alerts/infrastructure-alert-conditions/create-infrastructure-host-not-reporting-condition/
[ms-io]: https://learn.microsoft.com/en-us/troubleshoot/sql/database-engine/performance/troubleshoot-sql-io-performance
[vmw-kb]: https://knowledge.broadcom.com/external/article?legacyId=1008205
[semconv]: https://github.com/open-telemetry/semantic-conventions/blob/0eb883be629282ae400a8063492626ff14dfb62f/docs/system/system-metrics.md
[hm-disk]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/internal/scraper/diskscraper/metadata.yaml
[hm-cpu]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/internal/scraper/cpuscraper/metadata.yaml
[hm-paging]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/internal/scraper/pagingscraper/metadata.yaml
[hm-net]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/internal/scraper/networkscraper/metadata.yaml
[hm-load]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/internal/scraper/loadscraper/metadata.yaml
[hm-system]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.161.0/receiver/hostmetricsreceiver/internal/scraper/systemscraper/metadata.yaml
[oo-meta]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/src/config/src/meta/alerts/mod.rs#L52-L91
[oo-alert-model]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/src/config/src/meta/alerts/alert.rs#L134
[oo-api]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/src/api/management/src/models/alerts/mod.rs#L254-L258
[oo-eval]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/src/core/src/alerts/mod.rs#L165-L341
[oo-agg]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/src/config/src/meta/alerts/aggregation_level.rs#L146-L178
[oo-h-range]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/src/core/src/alerts/scheduler/handlers.rs#L1843-L1849
[oo-h-silence]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/src/core/src/alerts/scheduler/handlers.rs#L2081-L2096
[oo-h-pending]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/src/core/src/alerts/scheduler/handlers.rs#L2206-L2300
[oo-validate]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/src/core/src/alerts/alert.rs#L663-L669
[oo-promql-lib]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/src/promql/src/lib.rs#L45-L47
[oo-engine-sub]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/src/promql/src/engine.rs#L290-L314
[oo-ts]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/src/config/src/meta/promql/value.rs#L434-L443
[oo-vecop]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/src/promql/src/binaries/vector_operations.rs#L74-L120
[oo-otlp]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/src/core/src/metrics/otlp.rs
[oo-schema]: https://github.com/openobserve/openobserve/blob/1e257e69ef0feb6029f3111d54697244a3f507db/src/config/src/utils/schema.rs
[oo-doc-alerts]: https://openobserve.ai/docs/user-guide/alerts/alerts/
[oo-doc-sched]: https://openobserve.ai/docs/user-guide/analytics/alerts/scheduled-alerts/
[oo-doc-cond]: https://openobserve.ai/docs/user-guide/analytics/alerts/alert-conditions/
[f2b]: https://github.com/fail2ban/fail2ban/blob/master/config/jail.conf
[el-ssh-ext]: https://github.com/elastic/detection-rules/blob/main/rules/linux/credential_access_potential_linux_ssh_bruteforce_external.toml
[el-ssh-ok]: https://github.com/elastic/detection-rules/blob/main/rules/linux/credential_access_potential_successful_linux_ssh_bruteforce.toml
[wz-sshd]: https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0095-sshd_rules.xml
[wz-syslog]: https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0020-syslog_rules.xml
[sigma]: https://github.com/SigmaHQ/sigma/tree/master/rules/linux/builtin
[rfc5424]: https://www.rfc-editor.org/rfc/rfc5424#section-6.2.1
[cpqida]: https://github.com/librenms/librenms/blob/master/mibs/hp/CPQIDA-MIB
[hpe-ssacli]: https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-kc0108463en_us
[hpe-adv]: https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c05302924
[rf-sc]: https://redfish.dmtf.org/schemas/v1/StorageController.v1_9_0.json
[rf-bat]: https://redfish.dmtf.org/schemas/v1/Battery.json
[tf-scripts]: https://github.com/prometheus-community/node-exporter-textfile-collector-scripts
[smartctl-exp]: https://github.com/prometheus-community/smartctl_exporter
