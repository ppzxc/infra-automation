"""접속 해석 통합 테스트 (Spec #511 / Ticket-12, #523).

실제 `playbooks/common/resolve_connection.yml`을 `ansible-playbook`으로 돌린다. OpenBao는 공용 가짜 서버(네임스페이스
`infra`, AppRole, `index.yml`·스키마 검사 켬, 기본 fixture)이고, `ssh`·`ssh-keygen`은 PATH 앞에 둔 스텁이다(프로브 결과를
환경 변수로 정한다). 단언은 외부 동작(접속 변수·실패 이유·요청 기록)만 본다. 경로 리터럴은 단언하지 않는다. 가짜 값만 쓴다.
"""
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
RESOLVE = ROOT_DIR / "playbooks" / "common" / "resolve_connection.yml"
CLEANUP = ROOT_DIR / "playbooks" / "common" / "cleanup_connection.yml"

DUMP = """{{ {
  'host': ansible_host | default(none), 'port': ansible_port | default(none), 'user': ansible_user | default(none),
  'password': ansible_password | default(none), 'become_method': ansible_become_method | default(none),
  'become_password': ansible_become_password | default(none), 'common_args': ansible_ssh_common_args | default(''),
  'key': (lookup('ansible.builtin.file', ansible_ssh_private_key_file) if ansible_ssh_private_key_file is defined else none),
  'python': ansible_python_interpreter | default(none), 'ip': ip | default(none), 'accounts': accounts | default(none),
  'removed': _removed_users | default(none), 'provisioned': _is_already_provisioned | default(none),
  'connection': _connection | default(none), 'normalized': _normalized_admin_users | default(none)
} | to_json }}"""


def _stub(path, body):
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def run_resolve(tmp_path, fake, hosts, probe_rc=0, extra_vars=None):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "ssh-calls.log"
    _stub(bindir / "ssh", 'printf "%s\\n" "$*" >> "$STUB_SSH_LOG"\nexit "$STUB_SSH_RC"\n')
    _stub(bindir / "ssh-keygen", 'printf "%s ENV=%s\\n" "$*" "$BAO_KEY_PASSPHRASE" >> "$STUB_KEYGEN_LOG"\nexit 0\n')
    (tmp_path / "inv.yml").write_text(yaml.safe_dump({"all": {"children": {"servers": {"hosts": {h: {} for h in hosts}}}}}))
    (tmp_path / "play.yml").write_text(yaml.safe_dump([
        {"ansible.builtin.import_playbook": str(RESOLVE), "vars": {"connection_hosts": "servers"}},
        {"hosts": "servers", "gather_facts": False, "connection": "local", "become": False, "tasks": [
            {"name": "Dump", "ansible.builtin.copy": {"content": DUMP, "dest": f"{tmp_path}/out-{{{{ inventory_hostname }}}}.json",
                                                      "mode": "0600"}, "check_mode": False}]},
        {"ansible.builtin.import_playbook": str(CLEANUP), "vars": {"connection_hosts": "servers"}},
    ]))
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", STUB_SSH_LOG=str(log), STUB_SSH_RC=str(probe_rc),
               STUB_KEYGEN_LOG=str(tmp_path / "keygen-calls.log"),
               VAULT_ADDR=fake.url, VAULT_ROLE_ID="fake-role", VAULT_SECRET_ID="fake-secret", ANSIBLE_NOCOLOR="1")
    cmd = ["ansible-playbook", "-i", str(tmp_path / "inv.yml"), str(tmp_path / "play.yml")]
    for k, v in (extra_vars or {}).items():
        cmd += ["-e", json.dumps({k: v})]
    res = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=240, cwd=ROOT_DIR, env=env)
    out = {h: json.loads((tmp_path / f"out-{h}.json").read_text()) for h in hosts if (tmp_path / f"out-{h}.json").exists()}
    calls = log.read_text().splitlines() if log.exists() else []
    return res, out, calls


def test_each_document_is_read_over_http_once_per_host_and_the_login_once_per_play(tmp_path, fake_openbao):
    """호스트당 같은 문서를 반복해 읽지 않는다(요약·전체·관리 계정 해석이 읽기 객체 하나를 나눠 쓴다)."""
    res, _, _ = run_resolve(tmp_path, fake_openbao, ["ns0001", "ns0002"])
    assert res.returncode == 0, res.stdout + res.stderr
    reads = [(r.mount, r.doc) for r in fake_openbao.reads()]
    # 호스트 사이에 공유하는 문서(automation/ssh, operators/*)는 호스트당 한 번씩이라 호스트 수만큼까지 나온다.
    for doc in set(reads):
        assert reads.count(doc) <= 2, (doc, reads.count(doc))
    per_host = [d for m, d in reads if d.startswith(("assets/ns0001", "assets/ns0002"))]
    assert len(per_host) == len(set(per_host)), per_host
    assert len(fake_openbao.logins()) == 1


def test_a_provisioned_identity_host_connects_with_the_automation_key_and_reads_only_infra_documents(tmp_path, fake_openbao):
    res, out, calls = run_resolve(tmp_path, fake_openbao, ["ns0001"])
    assert res.returncode == 0, res.stdout + res.stderr
    h = out["ns0001"]
    assert (h["host"], h["port"], h["user"]) == ("192.0.2.11", 22, "admin01")
    assert h["key"].strip() == "/fake/path/to/automation_key"
    assert (h["become_method"], h["become_password"]) == ("sudo", "fake-pw-admin01")
    assert h["password"] is None and h["provisioned"] is True and h["python"] == "/usr/bin/python3"
    assert h["connection"]["login_mode"] == "identity" and h["connection"]["password_auth_exception"] is False
    assert h["ip"] == "192.0.2.11"
    assert [a["name"] for a in h["accounts"]] == ["admin01", "olduser"]
    assert h["accounts"][1] == {"name": "olduser", "state": "absent"}
    assert h["accounts"][0]["keys"] == ["ssh-ed25519 AAAAFAKEAUTOMATIONKEY automation@example.test"]
    assert len(calls) == 1 and "admin01@192.0.2.11" in calls[0] and "-p 22" in calls[0]
    # 읽기 지점 한 곳: infra 네임스페이스, 두 마운트만, 로그인은 플레이당 한 번
    assert {r.namespace for r in fake_openbao.reads()} == {"infra"}
    assert {r.mount for r in fake_openbao.reads()} <= {"inventory", "secrets"}
    assert len(fake_openbao.logins()) == 1
    assert "fake-pw-admin01" not in res.stdout + res.stderr


def test_a_failed_admin_probe_switches_to_the_bootstrap_credential_by_name(tmp_path, fake_openbao):
    res, out, _ = run_resolve(tmp_path, fake_openbao, ["ns0001"], probe_rc=255)
    assert res.returncode == 0, res.stdout + res.stderr
    h = out["ns0001"]
    assert h["provisioned"] is False
    assert (h["user"], h["password"]) == ("root", "fake-pw-root-0001")        # Credential 자신의 비밀로 로그인
    assert (h["become_method"], h["become_password"]) == ("sudo", "fake-pw-root-0001")
    assert h["key"] is None


def test_a_non_identity_ssh_endpoint_is_a_password_exception_with_su(tmp_path, fake_openbao):
    res, out, _ = run_resolve(tmp_path, fake_openbao, ["ns0002"])
    assert res.returncode == 0, res.stdout + res.stderr
    h = out["ns0002"]
    assert (h["user"], h["password"], h["become_method"]) == ("root", "fake-pw-root-0008", "su")
    assert h["connection"]["password_auth_exception"] is True and h["provisioned"] is False


def test_a_via_endpoint_puts_the_hop_into_the_proxy_command_and_enable_becomes_the_method(tmp_path, fake_openbao):
    res, out, _ = run_resolve(tmp_path, fake_openbao, ["ns0003"])
    assert res.returncode == 0, res.stdout + res.stderr
    h = out["ns0003"]
    assert (h["host"], h["port"], h["user"], h["password"]) == ("192.0.2.13", 22, "netadmin", "fake-pw-net-0010")
    assert (h["become_method"], h["become_password"]) == ("enable", "fake-pw-enable-0011")
    assert "ProxyCommand=" in h["common_args"] and "admin01@192.0.2.11" in h["common_args"]
    assert [v["asset"] for v in h["connection"]["via"]] == ["ns0001"]


def test_the_preference_list_picks_the_first_registered_endpoint_and_does_not_fail_over(tmp_path, fake_openbao):
    res, out, calls = run_resolve(tmp_path, fake_openbao, ["ns0003"], probe_rc=255,
                                  extra_vars={"connection_endpoint_preference": ["telnet", "ssh"]})
    assert res.returncode == 0, res.stdout + res.stderr
    h = out["ns0003"]
    assert (h["port"], h["become_method"], h["connection"]["endpoint"]) == (23, None, "telnet")
    assert calls == []          # 접속을 시험하지 않았고 다른 Endpoint도 읽지 않았다


def test_an_unregistered_preference_fails_the_host_without_a_default(tmp_path, fake_openbao):
    res, out, _ = run_resolve(tmp_path, fake_openbao, ["ns0001"], extra_vars={"connection_endpoint_preference": ["https"]})
    assert res.returncode != 0 and out == {}
    assert "선호 순서" in res.stdout + res.stderr


def test_provisioning_targets_without_an_access_clause_fail(tmp_path, fake_openbao):
    res, out, _ = run_resolve(tmp_path, fake_openbao, ["ns0003"], extra_vars={"connection_requires_access": True})
    assert res.returncode != 0 and out == {}
    assert "ACCESS-MISSING" in res.stdout + res.stderr


def test_removed_accounts_are_the_union_of_the_access_clause_and_the_run_variable(tmp_path, fake_openbao):
    res, out, _ = run_resolve(tmp_path, fake_openbao, ["ns0001"], extra_vars={"target_removed_users": "legacy1, legacy2"})
    assert res.returncode == 0, res.stdout + res.stderr
    h = out["ns0001"]
    assert h["removed"] == ["olduser", "legacy1", "legacy2"]
    assert {"name": "legacy1", "state": "absent"} in h["accounts"]


@pytest.mark.parametrize("protected", ["admin01", "root"])
def test_removing_a_connection_or_bootstrap_account_is_refused(tmp_path, fake_openbao, protected):
    res, out, _ = run_resolve(tmp_path, fake_openbao, ["ns0001"], extra_vars={"target_removed_users": [protected]})
    assert res.returncode != 0 and out == {}
    assert "REMOVED-USER-CONFLICT" in res.stdout + res.stderr


def test_a_missing_required_document_fails_instead_of_falling_back(tmp_path, fake_openbao):
    fake_openbao.remove("secrets", "automation/ssh")
    res, out, _ = run_resolve(tmp_path, fake_openbao, ["ns0001"])
    assert res.returncode != 0 and out == {}
    assert "필수 문서가 없습니다" in res.stdout + res.stderr
    assert {r.mount for r in fake_openbao.reads()} <= {"inventory", "secrets"}      # 옛 secret/ 마운트 대체 읽기 없음


def test_a_mapping_shaped_removed_accounts_run_variable_is_ignored_with_a_warning(tmp_path, fake_openbao):
    res, out, _ = run_resolve(tmp_path, fake_openbao, ["ns0001"], extra_vars={"target_removed_users": {"legacy": 1}})
    assert res.returncode == 0, res.stdout + res.stderr
    assert out["ns0001"]["removed"] == ["olduser"]
    assert "mapping" in res.stdout


def test_an_automation_key_passphrase_is_stripped_from_the_temporary_key_only(tmp_path, fake_openbao):
    fake_openbao.set("secrets", "automation/ssh", {"private_key": "/fake/path/to/automation_key",
                                                   "public_key": "ssh-ed25519 AAAAFAKEAUTOMATIONKEY automation@example.test",
                                                   "passphrase": "fake-pass-automation"})
    res, out, _ = run_resolve(tmp_path, fake_openbao, ["ns0001"])
    assert res.returncode == 0, res.stdout + res.stderr
    (call,) = (tmp_path / "keygen-calls.log").read_text().splitlines()
    assert "-p -f /" in call and "_bao_admin_key" in call
    args, env = call.split(" ENV=")
    assert "fake-pass-automation" not in args and "-P" not in args.split()       # argv(ps)에는 암호문이 없다
    assert env == "fake-pass-automation"                                          # SSH_ASKPASS가 쓰는 환경 변수로만 간다
    assert "fake-pass-automation" not in res.stdout + res.stderr


def test_a_password_via_hop_is_refused_with_a_readable_reason(tmp_path, fake_openbao):
    # ns0004(https)는 ns0003(비밀번호 로그인)을 경유한다. 경유지는 키 로그인만 지원한다.
    res, out, _ = run_resolve(tmp_path, fake_openbao, ["ns0004"], extra_vars={"connection_endpoint_preference": ["https"]})
    assert res.returncode != 0 and out == {}
    assert "VIA-HOP-LOGIN" in res.stdout + res.stderr and "ns0003" in res.stdout + res.stderr


def test_the_staging_helper_really_strips_a_passphrase_through_askpass_with_the_real_ssh_keygen(tmp_path):
    """스텁이 아닌 실제 ssh-keygen: 암호문이 걸린 가짜 키가 임시 파일에서 암호문 없이 읽히고, askpass 파일은 남지 않는다."""
    import shutil
    import subprocess as sp
    if not shutil.which("ssh-keygen"):
        pytest.skip("ssh-keygen이 없다")
    key = tmp_path / "k"
    sp.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "fake-pass-xyz", "-f", str(key)], check=True)
    play = [{"hosts": "localhost", "connection": "local", "gather_facts": False, "become": False, "tasks": [
        {"ansible.builtin.include_tasks": str(ROOT_DIR / "playbooks" / "common" / "stage_ssh_key.yml"),
         "vars": {"_sk_suffix": "_bao_test_key", "_sk_key": key.read_text(), "_sk_passphrase": "fake-pass-xyz",
                  "_sk_record": "_staged"}},
        {"ansible.builtin.copy": {"content": "{{ _staged.path }}", "dest": str(tmp_path / "path.txt")}, "become": False}]}]
    (tmp_path / "pb.yml").write_text(yaml.safe_dump(play))
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(tmp_path / "pb.yml")], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=120)
    assert res.returncode == 0, res.stdout + res.stderr
    staged = Path((tmp_path / "path.txt").read_text())
    try:
        assert sp.run(["ssh-keygen", "-y", "-P", "", "-f", str(staged)], capture_output=True).returncode == 0
        assert not Path(str(staged) + ".askpass").exists()
        assert "fake-pass-xyz" not in res.stdout + res.stderr
    finally:
        staged.unlink(missing_ok=True)
