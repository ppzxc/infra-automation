# 레거시 호스트 `bk` 계정 접속 전환 런북 (root 직접 접속 → 계정 + sudo 승격)

프로비저닝하지 않은 레거시 호스트(`agents_only`, CentOS 6·7 등)의 Host Agents 접속을 root 직접 접속에서 **`bk` 계정 로그인 + sudo 승격**으로 바꾸는 절차다. 코드는 바꾸지 않고 OpenBao 값과 호스트의 sudoers만 바꾼다.

공개 저장소이므로 주소·포트·비밀번호·호스트별 결과는 이 문서에 쓰지 않는다. 대상 호스트 목록과 실행 기록은 비공개 경로(`~/.local/share/infra-automation/bk-access-20261029/`)에 둔다.

## 1. 접속 모델

| 호스트 종류 | 접속 계정 | 승격 | 값의 위치 |
|---|---|---|---|
| 프로비저닝 호스트(`setup_complete`) | `admin_users` 첫 항목(예: `ppzxc`), SSH 키 | sudo | OpenBao `hosts/<호스트>` `admin_users`, `users/<계정>`의 키 |
| 레거시 호스트(`agents_only`) | `bootstrap_user`(이 문서에서는 `bk`), 비밀번호 | sudo, 같은 비밀번호가 `ansible_become_password` | OpenBao `hosts/<호스트>` `bootstrap_user`, `hosts/<호스트>/users/bk`의 `password` |

- 레거시 호스트는 SSH 키가 없어 `resolve_connection`이 부트스트랩 폴백으로 접속하고, `bootstrap_user`는 호스트 KV 값이 실행 변수·기본값(`root`)보다 우선한다(`openbao_integration.md`, `monitoring.md`의 "비밀번호 접속 예외").
- `host_agents_allow_password_auth: true`가 이미 있는 호스트만 대상이다. 이 플래그가 없으면 `MON-020`에서 중단된다.
- `admin_users`에 비밀번호만 있는 계정(`bk`)을 넣는 방식은 쓰지 않는다. 키가 없는 admin 계정은 프로비저닝 호스트 분기에서 인식되지 않고 부트스트랩으로 되돌아간다. 비밀번호 계정은 `bootstrap_user`로 지정한다.

## 2. 사전 조건

1. OpenBao `hosts/<호스트>/users/bk`에 `username=bk`, `type=PASSWORD`, `password`가 있다.
2. 호스트에 `bk` 계정이 있고 비밀번호 로그인이 된다. 레거시 호스트에는 `ssh-rsa` 허용 옵션이 필요하다(인벤토리 호스트 변수 `ansible_ssh_common_args`).
3. **`bk`는 기본적으로 sudoers에 없다.** 로그인만 되고 승격은 `bk is not in the sudoers file`로 거부된다. 4절에서 root로 한 번 추가한다.
4. `/etc/sudoers`에 `#includedir /etc/sudoers.d`가 있고 `Defaults requiretty`가 없다(CentOS 6.9 sudo 1.8.6, CentOS 7.9 sudo 1.8.23에서 확인).

## 3. 순서

카나리 1대(OS별 1대씩) → 나머지 순서로 간다. 한 호스트에서 끝까지 확인한 뒤 넓힌다.

1. `bk`로 로그인되는지만 확인한다(`id`). 실패하면 이 호스트는 대상에서 뺀다.
2. 4절로 sudoers를 추가한다.
3. 5절로 OpenBao에 `bootstrap_user`를 쓴다.
4. Semaphore `Host Agents — Deploy All`을 `target_hosts=<카나리 1대>`로 실행한다. 로그의 `Connection decision summary`에 `원격 접속 계정: bk (부트스트랩 계정)`이 찍히고 `failed=0`, `unreachable=0`이어야 한다.
5. 6절을 확인한 뒤 같은 OS의 나머지 호스트로 넓힌다. 나머지는 `target_hosts`에 쉼표로 묶어 한 번에 실행해도 된다.

## 4. sudoers 추가 (호스트마다 한 번, root 권한 필요)

`bk`는 아직 승격할 수 없으므로 이 단계만 root 권한이 필요하다. root 직접 SSH가 막힌 호스트는 `bk`로 로그인한 뒤 `su -`로 root가 된다. `su`는 터미널이 필요하다(`ssh -tt` 또는 pty 도구).

```sh
f=$(mktemp)
echo 'bk ALL=(ALL) ALL' > "$f"
visudo -cf "$f" && install -o root -g root -m 0440 "$f" /etc/sudoers.d/bk
rm -f "$f"
visudo -c
```

- 비밀번호가 필요한 sudo다(`NOPASSWD` 아님). Ansible은 `ansible_become_password`로 넘긴다.
- 문법 오류가 있는 sudoers는 sudo 전체를 못 쓰게 만든다. 반드시 임시 파일을 `visudo -cf`로 검사한 뒤 설치하고, 설치 뒤에 `visudo -c`를 다시 돌린다.
- 확인: `bk`로 다시 로그인해 `sudo -k; sudo id -u`가 `0`이어야 한다.

## 5. OpenBao 값

호스트 KV `hosts/<호스트>`에 `bootstrap_user: "bk"`를 더한다. 기존 키는 그대로 두고, 읽은 값에 키를 더해 `POST …/data/hosts/<호스트>`로 `options.cas=<현재 버전>`과 함께 쓴다(PATCH는 권한이 없다). 쓴 뒤 기존 키가 그대로인지 비교한다. KV v2라 이전 버전이 남아 롤백에 쓸 수 있다.

## 6. 확인

- 접속 계정: Deploy 로그 `원격 접속 계정`이 `bk (부트스트랩 계정)`.
- 로그·메트릭: OpenObserve `system_logs`와 `system_cpu_load_average_1m`에 `host_name`이 최근 15분 안에 들어온다.
- 백업: 호스트에서 `set -a; . /etc/restic/env; set +a; resticprofile -f yaml -c /etc/restic/profiles.yaml -n default backup`이 성공하고 RustFS `backup-prod-<호스트>`의 스냅샷이 늘어난다. 호스트 키로는 스냅샷을 지울 수 없으므로(`backup-host-key-scope.md`) 시험으로 만든 스냅샷은 지우지 않고 보존 정책(`forget --prune`)이 정리하게 둔다.
- 전체: Semaphore 작업이 `success`이고 호스트별 `failed=0`.

## 7. 롤백

1. OpenBao `hosts/<호스트>`에서 `bootstrap_user`를 뺀 이전 버전 값으로 다시 쓴다. 기본값 `root`와 `hosts/<호스트>/users/root`로 돌아간다.
2. 호스트의 `/etc/sudoers.d/bk`를 지운다(root 필요).

## 8. 알려둘 점

- **root 직접 접속은 이 절차가 막지 않는다.** Host Agents가 root 직접 접속을 쓰지 않게 바꿀 뿐이고, 호스트의 `sshd` root 로그인 설정과 `hosts/<호스트>/users/root`는 그대로 둔다(결정: `users/root` 유지).
- 승격 전 `bk`로 `sudo`를 시도하면 호스트 보안 로그에 `not in the sudoers file` 거부가 남고 호스트에 따라 root 알림 메일이 간다. 시험은 sudoers 추가 뒤에 하거나, 거부가 남는 것을 알고 한다.
- 이 절차 뒤에도 `PASSWORD-AUTH-EXCEPTION` 경고(`MON-029`)는 계속 남는다. 만료 기준은 호스트를 `site.yml`로 하드닝(키 인증)하는 것이다.
- 레거시 호스트에서 `admin_users`가 `["root"]`로 남아 있어도 접속 계정에는 영향이 없다(`admin_users`는 `Validate an admin user is resolved` 단언을 통과시키는 용도).
