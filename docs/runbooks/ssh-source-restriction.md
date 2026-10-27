# 원격 접속(SSH) 출발지 제한 런북 (#371, Spec #364)

방화벽 체인을 건드리지 않고 sshd의 `Match Address` 블록으로 허용 출발지 밖의 SSH 로그인을 거부한다. 허용 출발지(사무실, 자동화 서버) 목록 값은 공개 저장소에 쓰지 않고 비공개 경로(Semaphore Environment/인벤토리 변수, 운영자 노트)에서만 다룬다. 이 문서는 절차이며, 실제 적용은 항목별 운영자 승인 뒤에 한다.

## 1. 기존 ssh_allowed_source_ips와의 관계

| 변수 | 수단 | `firewall_unmanaged` 호스트 | 비고 |
|---|---|---|---|
| `ssh_allowed_source_ips` | 호스트 방화벽 규칙(firewalld rich rule, UFW, iptables) | 적용되지 않는다(방화벽 태스크 전체가 건너뜀) | 기존 변수, 그대로 둔다 |
| `ssh_source_restriction_allowed_sources` | sshd `Match Address *,!<허용>` + `DenyUsers *` | 같은 동작 | 이 티켓의 새 변수, 기본 빈 목록(= 제한 없음) |

- 두 변수는 서로를 읽지 않는다. 방화벽 비관리(`firewall_unmanaged`) 서버에는 기존 변수가 효과가 없으므로 새 변수가 그 자리를 대신하지만, 방화벽 관리 서버의 기존 규칙을 대체하거나 제거하지는 않는다(방화벽 규칙을 지우지 않는다).
- 방화벽 관리 서버가 두 변수를 함께 쓰면 방화벽(네트워크 계층)과 sshd(애플리케이션 계층)가 겹쳐 막는다. 두 목록이 어긋나면 더 좁은 쪽이 이긴다.
- 루프백(IPv4·IPv6)은 항상 허용한다. 빈 목록으로 다시 적용하면 블록이 제거된다(롤백).

## 2. 적용 전 준비

1. 운영자가 서버별로 적용을 승인한다(항목별). 허용 출발지 목록은 비공개 경로에 있고, 허용 밖 거부 시험용 출발지도 비공개 경로에 지정한다.
2. 적용 전 기준선 스냅샷을 비공개 경로에 남긴다. sshd Match 평가는 출발지별로 보도록 `BASELINE_SSHD_MATCH_ADDRS`를 실행 때만 넘긴다(허용·비허용 출발지 각 하나 이상).

```bash
BASELINE_SSHD_MATCH_ADDRS="<허용 출발지> <거부 시험 출발지>" \
  scripts/collect-security-baseline.sh --label <호스트> --ssh <계정>@<호스트> --out <비공개 경로>
```

3. 롤백 절차(5절)를 적용 전에 읽고, 롤백 명령을 별도 세션에 준비해 둔다.
4. 대상이 `firewall_unmanaged` 소속이어도 상관없다(방화벽 태스크는 건드리지 않는다). 프로비저닝 제외 그룹 소속 서버는 이 변경 때문에 그룹을 옮기지 않고 아래 절차의 수동 수행(3절 3번)을 쓴다. 자세한 대상 선정은 #364의 운영자 지시를 따른다.

## 3. 적용 순서(락아웃 방지)

핵심: 현재 세션을 닫지 않는다. 검증은 모두 서버를 재시작하기 전에 `sshd -t`/`sshd -T -C`로 끝낸다. 임시(비영구) 시험이 통과한 뒤에만 영구 반영한다.

1. **별도 세션 유지**: 서버에 SSH 세션 두 개를 연다(작업용, 구조용). 구조용 세션은 적용이 끝나고 재접속 시험이 통과할 때까지 닫지 않는다. 가능하면 콘솔(KVM/BMC)도 확인해 둔다.
2. **임시 시험(비영구)**: 허용 목록을 넣은 임시 설정 파일을 서버의 임시 경로에 만든다(실서버 `sshd_config` 복사본 끝에 Match 블록을 붙임). 서비스는 건드리지 않는다.
   - `sshd -t -f <임시파일>`로 문법을 검증한다(종료 코드 0).
   - `sshd -T -f <임시파일> -C addr=<허용 출발지>,user=<계정>,host=probe`에는 `denyusers *`가 없어야 하고, `addr=<거부 시험 출발지>`에는 있어야 한다. 접속 중인 내 출발지(구조용 세션의 `SSH_CONNECTION` 첫 필드)도 반드시 허용 쪽으로 나와야 한다.
   - 임시 파일은 시험 뒤 지운다. 이 단계는 서비스·부팅 설정을 바꾸지 않아 재부팅하면 아무 흔적이 없다.
3. **영구 반영**: 허용 목록을 `ssh_source_restriction_allowed_sources`로 비공개 경로(Semaphore Environment 또는 인벤토리 변수)에 넣고 security 역할을 적용한다(`--tags security` 또는 사용 중인 프로비저닝 진입점). 역할은 같은 순서를 자동으로 지킨다.
   - `SEC-071`이 `sshd -t -f %s`로 검증한 뒤에만 `sshd_config`를 바꾼다(검증 실패 시 파일을 바꾸지 않음).
   - `SEC-072`가 Ansible 접속 출발지를 `sshd -T -C`로 평가해 막히면 `SEC-073`이 블록을 지우고 `SEC-074`가 중단한다. 이 경우 `Restart sshd`는 실행되지 않는다.
   - 재시작(`Restart sshd`)은 작업 세션을 끊지 않는다(기존 연결 유지). 재시작 직후 작업 세션이 아닌 **새 세션**으로 허용 출발지에서 접속이 되는지 본다.
   - 역할을 쓸 수 없는 서버(프로비저닝 제외 그룹, CentOS 6/7 raw 경로)는 운영자가 위 2번의 임시 파일과 같은 내용을 `sshd_config` 끝에 직접 넣고 `sshd -t` 통과 뒤 `systemctl reload sshd`(또는 `service sshd reload`)한다. `Match` 블록은 파일 끝에 있어야 하고 그 뒤에 다른 전역 지시어를 두지 않는다.
4. **재부팅·재시작 후 유지 확인**: 서비스 재시작(`systemctl restart sshd`) 뒤 `sshd -T -C`로 허용·거부 평가를 다시 본다. 재부팅이 허용된 점검 창에서 재부팅한 뒤에도 `sshd_config`의 블록(마커 `ANSIBLE MANAGED sshd source restriction`)과 평가 결과가 같아야 한다. 서버 재부팅은 운영자 승인 사항이다.
5. 구조용 세션은 4번까지 통과한 뒤에 닫는다. 실패하면 즉시 롤백(5절)한다.

## 4. 허용·거부 시험

- 허용: 사무실과 자동화 서버(Semaphore) 출발지에서 접속이 된다. 자동화 서버에서는 다음 playbook 실행도 확인한다.
- 거부: 허용 밖 출발지(**비공개 경로에 지정**)에서 접속이 거부된다(`Permission denied` 또는 연결 종료). 거부 시험은 한 번이며 반복 실패로 fail2ban이 허용 출발지를 막지 않게 `ignoreip`를 확인한다.
- 사후 스냅샷: 2절과 **같은 명령**을 다시 실행해 이전 스냅샷과 `diff`한다. 달라야 하는 줄은 `sshd-match-blocks` 구간(Match 블록과 출발지별 평가 결과)뿐이며 방화벽·열린 접점 구간은 같아야 한다. 이슈에는 통과 여부만 적고 스냅샷 원본은 비공개 경로에 둔다.

## 5. 롤백

- 역할 경로: `ssh_source_restriction_allowed_sources`를 빈 목록으로 두고 같은 역할을 다시 적용한다(`SEC-071`이 블록을 제거하고 `sshd -t` 검증 뒤 재시작).
- 수동: 구조용 세션에서 `sshd_config`의 `BEGIN ... ANSIBLE MANAGED sshd source restriction` ~ `END ...` 줄 사이를 지우고(적용 전 백업이 있으면 복원), `sshd -t`가 통과하면 `systemctl restart sshd`(또는 `service sshd restart`)한다.
- 새 접속이 모두 막혀 구조용 세션도 없으면 콘솔(KVM/BMC)로 접속해 같은 수동 절차를 한다.
- 롤백 뒤 같은 스냅샷 명령으로 기준선과 diff가 비는지 확인한다.

## 6. 사후 점검과 Host Audit 연계

- Host Audit(#377)이 점검할 항목은 `sshd -T -C`로 평가한 허용·비허용 출발지 결과, `sshd_config`의 Match 블록 유무, 허용 목록이 비어 있지 않은 서버 목록이다. 점검 항목 정의는 #377에서 했다: `EXP-SSH-1`~`EXP-SSH-4`([Host Audit 명세 16절](../host_audit.md), 적용은 [Host Audit 퇴행 점검 런북](host-audit-regression.md)).
- 허용 목록이 바뀌면(사무실·자동화 서버 변경) 비공개 경로의 목록과 변수를 함께 고치고 이 런북의 2~4절을 다시 거친다.
- 이 변경은 방화벽 체인을 만들거나 지우지 않으며 `ssh_allowed_source_ips`·방화벽 규칙의 값도 읽지 않는다.
