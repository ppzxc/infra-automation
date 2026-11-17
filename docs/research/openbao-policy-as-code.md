# OpenBao 정책·AppRole·마운트·네임스페이스를 코드로 관리하는 표준 도구 조사

- 질문: [#505](https://github.com/ppzxc/infra-automation/issues/505), 상위 map [#500](https://github.com/ppzxc/infra-automation/issues/500). 이 결과를 받아 쓰는 티켓은 [#506](https://github.com/ppzxc/infra-automation/issues/506)이다. 이 문서는 근거만 모은다. 결정은 그 티켓에서 한다.
- 조사일: 2026-11-17
- 1차 출처
  - OpenBao 조직 저장소: [`openbao/ansible-collection-openbao` README][ob-ansible], [전용 OpenTofu/Terraform provider RFC][ob-rfc](2026-09-17 병합, [PR #3720][ob-rfc-pr]), 이슈 [#339][ob-339]·[#1508][ob-1508]·[#2578][ob-2578]
  - OpenBao 문서: [Namespaces][ob-ns], [Self-Initialization][ob-selfinit], [AppRole API][ob-approle-api], [API Libraries][ob-libs] (Context7 `/websites/openbao`)
  - HashiCorp: [Vault provider 문서 index][tfv-index], [`vault_policy`][tfv-policy], [`vault_namespace`][tfv-ns], [`vault_approle_auth_backend_role_secret_id`(resource)][tfv-sid], [같은 이름의 ephemeral resource][tfv-sid-eph], 릴리스(최신 v5.13.0, 2026-10-14), 튜토리얼 [Learn to use the Terraform Vault provider][hc-codify]
  - OpenTofu 문서: [State and Plan Encryption][tofu-enc], [Ephemerality][tofu-eph], [1.11.0 릴리스 글][tofu-111]
  - Ansible: [`community.hashi_vault` 컬렉션 색인][chv-index](7.1.0), [`vault_write` 모듈][chv-write]
  - Semaphore UI 문서(Context7 `/semaphoreui/semaphore-docs`): [Terraform/OpenTofu README][sem-tf], [States(HTTP backend)][sem-state], [Tasks][sem-tasks]
  - 저장소: `docs/openbao_integration.md`, `docs/semaphore-setup.md`, `requirements.yml`(`community.hashi_vault >=6.0.0`), `CONTEXT.md`
- 실험: 하지 않았다. 아래 "추론"은 운영에서 확인하지 않은 판단이다.

## 표기 규칙

| 태그 | 의미 |
|---|---|
| **출처** | 위 1차 출처에 문장으로 적힌 내용 |
| **추론** | 출처에서 끌어낸 판단. 실험·운영 관측은 아니다 |
| **권고** | 이 조사의 제안. #506에서 뒤집을 수 있다 |

## 핵심 답변

1. **업계 표준은 OpenTofu/Terraform + `hashicorp/vault` provider다.** OpenBao 조직이 관리하는 Ansible 컬렉션 README가 직접 이렇게 말한다: "Further configuration management that requires access to the OpenBao API and needs authentication is not supported. Please use OpenTofu or similar "state-aware" configuration management tools for this."([ob-ansible], 출처). HashiCorp 튜토리얼도 정책(`vault_policy`), 인증(`vault_auth_backend`), 엔진(`vault_mount`)을 provider로 코드화하고 "IAC best practices such as GitOps for all updates to Vaults configuration"을 권한다([hc-codify], 출처).
2. **OpenBao 전용 provider는 아직 없다. 지금은 `hashicorp/vault` provider를 그대로 쓴다.** OpenBao 메인테이너는 2024년에 "the overlapping functionality (between Vault and OpenBao) will continue to work just fine"이라고 답했다([ob-339], 출처). 그 뒤 기능이 갈라지면서 전용 provider RFC가 2026-09-17에 병합됐다. RFC는 Vault provider의 "low-divergence soft fork"를 만들고 `tofu state replace-provider`로 옮기는 경로를 적는다([ob-rfc], 출처). 2026-11-17 기준 `openbao` 조직에 provider 저장소는 아직 없다(GitHub 조직 저장소 목록 확인, 출처). 따라서 지금 `hashicorp/vault`로 시작하고, 전용 provider가 나오면 state의 provider 주소만 바꾸는 경로가 열려 있다(추론).
3. **이 저장소에 맞는 형태(권고):** OpenTofu 루트 모듈 하나를 저장소에 두고 정책 HCL은 `.hcl` 파일로 따로 둔다(`vault_policy`가 `file()`로 읽는다). Semaphore의 OpenTofu 템플릿으로 plan·apply를 돌린다. state는 기존 S3 호환 저장소에 OpenTofu 상태·플랜 암호화(`pbkdf2`)를 걸어 둔다. **AppRole `secret_id`는 OpenTofu로 발급하지 않는다.** role(정책·만료·출발지 제한)만 코드로 두고, 발급은 운영자가 `bao` CLI로 response-wrapping해서 하는 수동 런북으로 남긴다.
4. **Ansible `community.hashi_vault`는 탈락이다.** 정책·AppRole·마운트·네임스페이스 전용 모듈이 없다([chv-index], 출처). 범용 `vault_write`는 "always reports changed status because it cannot guarantee idempotence"([chv-write], 출처)라서 드리프트 감지와 리뷰용 diff가 나오지 않는다.
5. **`bao` CLI 스크립트와 `ansible.builtin.uri` read-compare-write도 탈락이다.** 각 객체를 읽고 비교하고 쓰고, 코드에서 빠진 객체를 지우는(prune) 로직을 직접 짜야 한다. state-aware 도구가 기본으로 주는 기능을 다시 만드는 셈이다(추론). 손으로 만든 prune은 무엇을 지울지 미리 보여 주는 dry-run까지 따로 만들어야 한다.

## 1. 후보별 비교

| 기준 | OpenTofu + `hashicorp/vault` | Ansible `community.hashi_vault` | `bao` CLI 스크립트 / `uri` 직접 호출 |
|---|---|---|---|
| 정책·AppRole·마운트·네임스페이스 리소스 | 전용 리소스 있음: `vault_policy`, `vault_approle_auth_backend_role`, `vault_mount`, `vault_auth_backend`, `vault_namespace`([tfv-policy], [tfv-ns], 출처) | 전용 모듈 없음. `vault_write`로 API 경로에 쓰기만 가능([chv-index], 출처) | API 직접 호출 |
| 드리프트 감지 | `plan`이 state와 서버 값을 비교한다. 단 코드 밖에서 새로 만든 객체는 보이지 않는다(§4) | 없음. 늘 changed([chv-write], 출처) | 직접 구현 |
| 삭제(코드에서 뺀 객체 제거) | 리소스를 지우면 plan에 destroy로 나온다 | 직접 구현 | 직접 구현 |
| PR 리뷰 | 정책 HCL diff와 plan 출력 | YAML diff만. 결과 예측 없음 | 스크립트 diff만 |
| 상태 파일의 비밀 | 있음. 다룰 방법은 §3 | 없음 | 없음 |
| 새 도구 도입 | OpenTofu 바이너리, state 저장소 | 없음(이미 의존성) | 없음 |
| OpenBao 호환 위험 | Vault 전용 가정이 일부 있음(§5) | API 경로만 쓰므로 낮음 | 낮음 |
| CI 시험 | `fmt`/`validate`, dev 서버에 apply 가능(§6) | dev 서버에 실행 가능 | dev 서버에 실행 가능 |

## 2. 적용 주체와 토큰

- provider는 기본으로 주어진 토큰에서 자식 토큰을 만든다(`auth/token/create`, 기본 TTL 20분, `max_lease_ttl_seconds`). `skip_child_token = true`로 끈다([tfv-index], 출처).
- 인증은 `auth_login` 블록으로 `auth/approle/login`에 `role_id`·`secret_id`를 보내는 방식이 문서 예시로 있다([tfv-index], 출처). provider의 `namespace` 인자는 `VAULT_NAMESPACE` 환경 변수로도 설정한다([tfv-index], 출처). Semaphore Variable Group이 이미 `VAULT_ADDR`·`VAULT_NAMESPACE`를 주입하므로 같은 값을 쓸 수 있다(추론).
- **닭과 달걀**: 적용자(applier) AppRole과 그 정책도 OpenTofu가 관리한다. 그래서 처음 한 번은 `admin` 토큰으로 apply하고, 이후에는 전용 applier AppRole로 바꾼다. map의 "`admin`은 비상용" 전제와 맞는다(권고).
- **네임스페이스 생성 권한**: `infra` 네임스페이스 자체는 상위(root) 네임스페이스에서 만들어야 한다. `infra` 안에 사는 applier는 자기 네임스페이스를 만들 수 없다. 네임스페이스 생성은 일회성 bootstrap(`admin` 또는 수동 `bao namespace create`)으로 두고, OpenTofu는 `infra` 내부만 관리한다(권고, map의 1단 네임스페이스 전제 기준).
- applier 정책은 `sys/policies/acl/*`, `sys/auth/*`, `sys/mounts/*`, `auth/approle/role/*` 쓰기를 갖는다. 이 정책 자체가 사실상 관리자 권한이므로 secret_id 수명을 짧게 하고 Semaphore 출발지로 제한한다(추론).

## 3. 상태 파일 안의 비밀

- provider 문서: state와 plan은 "will contain in cleartext any values that were written into Vault"이고, 데이터 소스로 읽은 비밀도 "persisted into the Terraform state, into any plan files, and in some cases in the console output"이다([tfv-index], 출처).
- **정책·AppRole role·마운트 설정만 관리하면 state에 비밀이 거의 남지 않는다.** 정책 본문과 role 설정은 비밀이 아니다(추론). 남는 것은 role이 서버에서 만든 `role_id`(비밀 아님에 가깝지만 공개는 피함)와, `secret_id_bound_cidrs`·`token_bound_cidrs` 같은 출발지 값이다.
- **AppRole `secret_id`를 resource로 만들면 state에 남는다.** `vault_approle_auth_backend_role_secret_id`(resource)는 `secret_id`를 인자로 받거나 서버 생성값을 저장한다([tfv-sid], 출처).
- **ephemeral resource로 발급해도 전달 문제는 남는다.** 같은 이름의 ephemeral resource는 "not stored in Terraform state"이다([tfv-sid-eph], 출처). OpenTofu의 ephemeral 값도 "will not be stored in the state or the plan"이다([tofu-eph], 출처). OpenTofu는 1.11.0(2025-12-09)부터 ephemeral resource를 지원한다([tofu-111], 출처). 다만 ephemeral 값은 output으로 내보내거나 저장할 수 없다. 그래서 Semaphore 비밀 저장소에 넣을 secret_id를 만드는 데는 쓸 수 없다(추론). **결론: secret_id 발급은 OpenTofu 밖에서 한다.** 운영자가 `bao write -wrap-ttl=... -f auth/<mount>/role/<role>/secret-id`로 response-wrapped secret_id를 받고, unwrap해서 Semaphore Environment에 넣는다(권고).
- **state 보관 위치**
  - Semaphore의 내장 HTTP backend는 Pro 기능이다: "State is managed by whatever backend is configured in your Terraform code (local, S3, GCS, etc.) unless you use the built-in HTTP backend (Pro)."([sem-tf], [sem-state], 출처). Semaphore는 매 실행 전 `terraform init`을 자동으로 한다([sem-tf], 출처). 실행 디렉터리가 일회성이라 local state는 쓸 수 없다(추론).
  - 이미 운영 중인 S3 호환 저장소(RustFS)에 S3 backend로 두고, OpenTofu 상태·플랜 암호화를 건다. OpenTofu는 "will encrypt state data _at rest_"이고 plan 파일도 `plan { }` 블록으로 같이 암호화한다([tofu-enc], 출처). key provider는 `pbkdf2`(passphrase, Semaphore 비밀로 주입)를 쓴다(권고).
  - **`openbao` key provider는 쓰지 않는다.** OpenBao Transit으로 data key를 만드는 방식인데([tofu-enc], 출처), OpenBao가 고장 나면 OpenBao를 고칠 state를 못 연다. 순환 의존이다(추론).
  - state 버킷은 공개 저장소·GitHub Actions에서 접근하지 않는다. 출발지 CIDR 값은 저장소에 쓰지 않고 Semaphore가 `TF_VAR_*`로 주입한다(Semaphore는 Variable Group 값을 환경 변수로 넘기므로 `TF_VAR_` 접두사를 쓴다, [sem-tasks] Terragrunt 절, 출처). `role_id`도 코드에 고정하지 않고 서버가 만들게 둔다(권고).

## 4. 드리프트 감지

- `tofu plan`은 state에 있는 리소스의 서버 값과 코드를 비교한다. Semaphore Terraform/OpenTofu 템플릿에는 **Plan**(plan만 실행)·**Auto Approve** 토글이 있다([sem-tasks], 출처). plan 전용 템플릿을 Semaphore 일정으로 돌리고 `-detailed-exitcode`(변경이 있으면 종료 코드 2)로 실패 처리하면 정기 드리프트 감지가 된다(추론).
- **빈틈: 코드 밖에서 손으로 만든 정책·role·마운트는 plan에 나오지 않는다.** state에 없는 객체는 비교 대상이 아니다(추론). map의 "정기 점검"에 `sys/policy`·`sys/auth`·`sys/mounts`·`auth/<approle>/role` 목록을 코드의 이름 목록과 비교하는 작은 검사를 더한다(권고). 처음 전환 때 서버에만 있던 객체는 `import`하거나 지운다(`vault_policy`는 `terraform import vault_policy.example dev-team` 형식을 지원한다, [tfv-policy], 출처).

## 5. OpenBao 호환 위험

| 항목 | 내용 | 대응 |
|---|---|---|
| 네임스페이스 | provider 문서는 `namespace` 인자·`vault_namespace`를 "Available only for Vault Enterprise"라 적는다([tfv-ns], 출처). OpenBao는 오픈소스에서 네임스페이스를 제공한다([ob-ns], 출처). OpenBao 2.3.1에서 `vault_namespace`로 생성이 동작한 사례가 있다. 처음 실패는 provider의 상위 `namespace`/`VAULT_NAMESPACE`가 없는 네임스페이스를 가리켰기 때문이었다([ob-1508], 출처) | 네임스페이스 생성은 bootstrap으로 빼고(§2), provider `namespace`는 `infra`로 고정 |
| 서버 버전 파싱 | provider는 `/sys/seal-status`의 버전으로 API 지원 여부를 판단한다([tfv-index], 출처). EPEL RPM 빌드는 `2.4.4-1.el10_1` 같은 문자열을 돌려줘 provider가 panic한 사례가 있다([ob-2578], 출처, 공식 업스트림 RPM은 해당 없음) | 우리 서버 배포 방식이 해당하면 `skip_get_vault_version = true` 또는 `vault_version_override` |
| 자식 토큰 | 기본으로 자식 토큰을 만든다([tfv-index], 출처). 엔티티·네임스페이스 구성에 따라 하위 토큰 발급이 거부될 수 있다(추론) | `skip_child_token = true`로 시험 |
| 기능 차이 | OpenBao 고유 기능(profile 등)은 리소스가 없고, 일부 수정이 업스트림에 병합되지 않는다([ob-rfc], 출처) | 이 저장소 범위(ACL 정책, AppRole, KV v2 마운트)는 두 제품 공통 기능이다(추론). 전용 provider가 나오면 `state replace-provider`로 이전([ob-rfc], 출처) |

## 6. CI 시험

- GitHub Actions는 운영 OpenBao에 닿지 않고, 닿게 해서도 안 된다(공개 저장소, 추론).
- PR에서 할 수 있는 것: `tofu fmt -check`, `tofu validate`, OpenBao dev 서버 컨테이너에 같은 모듈을 apply하고, 기대 정책으로 허용/거부를 확인하는 시험(예: 작업별 토큰이 남의 경로를 못 읽는지). 정책 HCL 문법은 dev 서버에 쓰는 순간 검증된다(추론, 실험 안 함).
- 운영 plan은 Semaphore에서만 돈다. PR에는 plan 출력을 붙이지 않는다. 출력에 출발지 값 같은 비공개 정보가 들어간다(추론).
- 3-Way 명세(SPEC-ID)와 연결할 수 있는지는 이 조사 범위 밖이다. #506 이후에 정한다.

## 7. 그 밖의 후보

- **OpenBao Self-Initialization(`initialize` 스탠자)**: 처음 서버를 띄울 때 한 번만 요청을 실행한다. 다시 하려면 "remove all storage and re-initialize from scratch"해야 한다([ob-selfinit], 출처). 이미 운영 중인 서버의 지속 관리에는 맞지 않는다(추론).
- **vault-config-operator 등 Kubernetes 오퍼레이터**: 이 환경에 Kubernetes가 없어 대상이 아니다(추론).
- **`adfinis.openbao` Ansible 컬렉션**: 설치·서비스 구성·Raft 백업 역할만 있고 API 구성은 OpenTofu로 넘긴다([ob-ansible], 출처). 버전 0.0.1이다.

## 8. 열린 위험

1. 저장소에 OpenTofu라는 두 번째 도구와 state 저장소가 생긴다. 작은 팀에게 운영 부담이 늘어난다. 범위를 OpenBao 구성 하나로 한정하면 부담을 줄일 수 있다(추론).
2. applier AppRole은 사실상 관리자 권한이다. 이 secret_id가 새면 모든 정책을 바꿀 수 있다. 짧은 수명, 출발지 제한, plan 확인 뒤 수동 apply(Auto Approve 끔)로 줄인다(권고).
3. state 암호화 passphrase를 잃으면 state를 못 연다. 그래도 서버 구성은 그대로이고, 다시 `import`로 복구할 수 있다(추론). passphrase 보관 위치는 #506에서 정한다.
4. `hashicorp/vault` provider의 OpenBao 대응은 보장되지 않는다. 버전을 고정하고, 올릴 때 dev 서버 CI로 확인한다(권고).
5. secret_id 발급·교체는 수동 런북으로 남는다. 만료(`secret_id_ttl`)를 두면 교체를 놓쳤을 때 Semaphore 작업이 멈춘다. 만료 전 알림이 필요하다(추론).
6. 위의 OpenBao 호환 항목(§5)은 운영 서버 버전에서 실험하지 않았다. #506이나 구현 티켓에서 dev 서버로 확인해야 한다.

[ob-ansible]: https://github.com/openbao/ansible-collection-openbao/blob/main/README.md
[ob-rfc]: https://github.com/openbao/openbao/blob/main/website/content/community/rfcs/dedicated-tf-provider.mdx
[ob-rfc-pr]: https://github.com/openbao/openbao/pull/3720
[ob-339]: https://github.com/openbao/openbao/issues/339
[ob-1508]: https://github.com/openbao/openbao/issues/1508
[ob-2578]: https://github.com/openbao/openbao/issues/2578
[ob-ns]: https://openbao.org/docs/concepts/namespaces/
[ob-selfinit]: https://openbao.org/docs/configuration/self-init/
[ob-approle-api]: https://openbao.org/docs/api/auth/approle/
[ob-libs]: https://openbao.org/docs/api/libraries/
[tfv-index]: https://registry.terraform.io/providers/hashicorp/vault/latest/docs
[tfv-policy]: https://registry.terraform.io/providers/hashicorp/vault/latest/docs/resources/policy
[tfv-ns]: https://registry.terraform.io/providers/hashicorp/vault/latest/docs/resources/namespace
[tfv-sid]: https://registry.terraform.io/providers/hashicorp/vault/latest/docs/resources/approle_auth_backend_role_secret_id
[tfv-sid-eph]: https://registry.terraform.io/providers/hashicorp/vault/latest/docs/ephemeral-resources/approle_auth_backend_role_secret_id
[hc-codify]: https://developer.hashicorp.com/vault/tutorials/operations/codify-mgmt-vault-terraform
[tofu-enc]: https://opentofu.org/docs/language/state/encryption/
[tofu-eph]: https://opentofu.org/docs/language/ephemerality/
[tofu-111]: https://opentofu.org/blog/opentofu-1-11-0/
[chv-index]: https://docs.ansible.com/ansible/latest/collections/community/hashi_vault/index.html
[chv-write]: https://docs.ansible.com/ansible/latest/collections/community/hashi_vault/vault_write_module.html
[sem-tf]: https://github.com/semaphoreui/semaphore-docs/blob/main/docs/user-guide/apps/terraform/README.md
[sem-state]: https://github.com/semaphoreui/semaphore-docs/blob/main/docs/user-guide/apps/terraform/states.md
[sem-tasks]: https://github.com/semaphoreui/semaphore-docs/blob/main/docs/user-guide/tasks.md
