"""Host Audit 스위치 단계 (Spec #568 / Ticket-3): play·태스크 구조와 실제 ansible-playbook 실행.

수집기는 인자·stdin·시각을 기록하는 대역으로 바꾼다(장비에는 닿지 않는다). 주소·계정은 합성 값이다.
"""
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from openbao_fake import FakeOpenBao
import test_cisco_backup as tcb
from test_host_audit_switch import GOOD_CONFIG, VERSION

ROOT_DIR = Path(__file__).resolve().parent.parent
PLAYBOOK = ROOT_DIR / "playbooks" / "host_audit.yml"
CISCO_TASKS = ROOT_DIR / "roles" / "cisco_backup" / "tasks"
sys.path.insert(0, str(ROOT_DIR / "roles" / "cisco_backup" / "files"))
import cisco_cli_collector as collector  # noqa: E402


def _plays():
    return yaml.safe_load(PLAYBOOK.read_text(encoding="utf-8"))


# ------------------------------------------------------------ 구조 (빠른 시험)


def test_switch_play_runs_one_switch_at_a_time_after_the_servers_and_before_the_report():
    plays = _plays()
    names = [p["name"] for p in plays]
    play = next(p for p in plays if p["name"].startswith("Collect switch state"))
    assert play["hosts"] == "host_audit_switch_targets" and play["serial"] == 1
    assert play["connection"] == "local" and play["gather_facts"] is False and play.get("become") is False
    # 한 대의 예상 밖 실패(기록 저장 등)가 나머지 스위치 점검을 멈추지 않는다.
    assert "any_errors_fatal" not in play and play["max_fail_percentage"] == 100
    assert names.index("Collect host state (read-only)") < names.index(play["name"]) < names.index("Build Host Audit report")
    # 서버 play는 그대로다: 대상은 서버 선택 그룹뿐이다.
    server = next(p for p in plays if p["name"] == "Collect host state (read-only)")
    assert server["hosts"] == "host_audit_targets"


def test_collect_task_is_read_only_single_login_without_retry():
    tasks = {t["name"].split("]")[0].lstrip("["): t for t in yaml.safe_load((CISCO_TASKS / "audit.yml").read_text(encoding="utf-8"))
             if t.get("name", "").startswith("[CISCO-")}
    task = tasks["CISCO-010"]
    for forbidden in ("retries", "until", "delay", "loop", "with_items", "async", "poll"):
        assert forbidden not in task, forbidden
    assert task["no_log"] == "{{ cisco_backup_no_log }}" and task["failed_when"] is False and task["changed_when"] is False
    assert task["register"] == "cisco_audit_probe" and task["delegate_to"] == "localhost"
    assert "--audit" in (CISCO_TASKS.parent / "vars" / "main.yml").read_text(encoding="utf-8")
    # 한 호스트 한 수집: 수집 태스크는 한 번만 호출한다.
    assert (CISCO_TASKS / "audit.yml").read_text(encoding="utf-8").count("[CISCO-010]") == 1


def test_switch_tasks_do_not_log_secrets_and_never_loop_the_collection():
    text = (ROOT_DIR / "roles" / "host_audit" / "tasks" / "switch.yml").read_text(encoding="utf-8")
    tasks = yaml.safe_load(text)
    block = tasks[0]
    assert block["block"][0]["ansible.builtin.include_role"]["tasks_from"] == "audit"
    assert block["rescue"][0]["no_log"] is True
    assert next(t for t in tasks if t["name"].startswith("[AUD-902]"))["no_log"] is True
    for forbidden in ("retries:", "until:", "loop:"):
        assert forbidden not in text, forbidden


def test_switch_selection_is_separate_from_the_server_selection():
    text = (ROOT_DIR / "roles" / "host_audit" / "tasks" / "prepare.yml").read_text(encoding="utf-8")
    tasks = {t["name"].split("]")[0].lstrip("["): t for t in yaml.safe_load(text) if t["name"].startswith("[AUD-")}
    assert tasks["AUD-008"]["ansible.builtin.add_host"]["groups"] == "host_audit_switch_targets"
    assert tasks["AUD-004"]["ansible.builtin.add_host"]["groups"] == "host_audit_targets"
    defaults = yaml.safe_load((ROOT_DIR / "roles" / "host_audit" / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert defaults["host_audit_switch_scope_pattern"] == "cisco_switches:!host_audit_excluded"
    assert "cisco_switches" not in defaults["host_audit_scope_pattern"]
    assert defaults["host_audit_switch_enabled"] is True


# ------------------------------------------------------------ 수집기 수준: 명령 목록과 N-04 (가짜 세션)


class _Device:
    def __init__(self):
        self.sent, self.queue, self.enable_pw = [], [], False

    def send(self, data):
        self.sent.append(data.decode())
        line = data.decode().strip("\r\n")
        if data == b"\n":
            self.queue.append(b"sw>")
        elif line == "enable":
            self.enable_pw = True
            self.queue.append(b"Password:")
        elif self.enable_pw:
            self.enable_pw = False
            self.queue.append(b"\r\nsw#")
        elif line == "terminal length 0":
            self.queue.append(b"\r\nsw#")
        elif line == "show running-config":
            self.queue.append(b"show running-config\r\n" + GOOD_CONFIG.replace("\n", "\r\n").encode() + b"sw#")
        elif line == "show version":
            self.queue.append(b"show version\r\n" + VERSION.replace("\n", "\r\n").encode() + b"\r\nsw#")
        else:
            self.queue.append(b"% Invalid input\r\nsw#")

    def recv(self, timeout=0.0):
        return self.queue.pop(0) if self.queue else b""


def test_one_audit_sends_exactly_the_session_prep_and_the_two_show_commands(monkeypatch):
    monkeypatch.setattr(collector.time, "sleep", lambda _s: None)
    dev = _Device()
    out = collector.run_cisco_session(dev.send, dev.recv, enable_pass="pw", timeout=2, audit=True)
    commands = [c.rstrip("\n") for c in dev.sent]
    # 전송 목록 정확 일치: 줄 맞춤 "", enable과 그 비밀번호, 준비 명령, show 두 개. 설정 모드·저장·재시작 명령이 없다.
    assert commands == ["", "enable", "pw", "terminal length 0", "show running-config", "show version"]
    allowed = {"show running-config", "show version"}
    assert [c for c in commands if c.split(" ")[0] == "show"] and set(c for c in commands if c.startswith("show")) == allowed
    assert not any(c.split(" ")[0] in ("configure", "conf", "write", "copy", "reload", "clear", "delete") for c in commands)
    assert set(out) == {"running_config", "version"}


@pytest.mark.parametrize("mode", ["direct_ssh", "telnet"])
def test_a_wrong_password_causes_no_second_login_attempt(monkeypatch, mode, capsys):
    """N-04 로그인 실패 임계값: 인증 실패 뒤 추가 시도는 0회다(수집기 main이 한 번 시도하고 종료 코드 3)."""
    attempts = []

    def failing(*args, **kwargs):
        attempts.append(1)
        raise PermissionError("Authentication failed")

    monkeypatch.setattr(collector, "collect_direct_ssh", failing)
    monkeypatch.setattr(collector, "collect_telnet", failing)
    monkeypatch.setattr(collector, "collect_openssh_pty", failing)
    monkeypatch.setattr(collector.time, "sleep", lambda _s: None)
    monkeypatch.setattr(sys, "stdin", __import__("io").StringIO(json.dumps({"password": "x", "enable_password": "y"})))
    monkeypatch.setattr(sys, "argv", ["c", "--audit", "--mode", mode, "--host", "192.0.2.1", "--user", "u"])
    with pytest.raises(SystemExit) as exc:
        collector.main()
    assert exc.value.code == 3 and len(attempts) == 1
    assert capsys.readouterr().out == ""


# ------------------------------------------------------------ ansible-playbook 실행 (slow)

_BAOS = []
OK_EP = {"protocol": "ssh", "address": "192.0.2.13", "port": 22, "credential": "netadmin",
         "become": {"method": "enable", "credential": "enable"}}
DOWN_EP = dict(OK_EP, address="192.0.2.14")
TELNET_EP = {"protocol": "telnet", "address": "192.0.2.15", "port": 23, "credential": "netadmin"}


def _creds(*names):
    out = {}
    for ns in names:
        out[(ns, "netadmin")] = {"type": "password", "username": "netadmin", "password": "fake-pw-net-%s" % ns}
        out[(ns, "enable")] = {"type": "password", "password": "fake-pw-enable-%s" % ns}
    return out


@pytest.fixture(autouse=True)
def _close_baos():
    yield
    while _BAOS:
        _BAOS.pop().close()


@pytest.fixture
def run_audit(tmp_path):
    if shutil.which("ansible-playbook") is None:
        pytest.skip("ansible-playbook not installed")
    plays = [p for p in _plays() if p["name"] in ("Prepare Host Audit run", "Collect switch state (read-only, one at a time)")]
    assert len(plays) == 2
    (tmp_path / "play.yml").write_text(yaml.safe_dump(plays, allow_unicode=True), encoding="utf-8")
    (tmp_path / "ansible.cfg").write_text(f"[defaults]\nroles_path = {ROOT_DIR / 'roles'}\nretry_files_enabled = False\n", encoding="utf-8")
    stub = tmp_path / "collector.py"
    stub.write_text(
        "import json, os, sys, time\n"
        "start = time.time()\n"
        "stdin = json.loads(sys.stdin.read() or '{}')\n"
        "time.sleep(0.4)\n"
        "open(os.environ['STUB_RECORD'], 'a').write(json.dumps({'argv': sys.argv[1:], 'stdin': stdin, 'start': start, 'end': time.time()}) + '\\n')\n"
        "host = sys.argv[sys.argv.index('--host') + 1]\n"
        "if host == '192.0.2.14':\n"
        "    sys.exit(3)\n"
        f"sys.stdout.write(json.dumps({{'running_config': {GOOD_CONFIG!r}, 'version': {VERSION!r}}}))\n", encoding="utf-8")

    def run(store, hosts, groups=None, extra=None):
        bao = FakeOpenBao.with_schemas(store, namespace="infra", token="bao-test-token", approle=True)
        _BAOS.append(bao)
        children = {"cisco_switches": {"hosts": {h: {} for h in hosts}}}
        children.update(groups or {})
        (tmp_path / "inv.yml").write_text(yaml.safe_dump({"all": {"children": children}}), encoding="utf-8")
        out_root = tmp_path / "out"
        shutil.rmtree(out_root, ignore_errors=True)  # 한 시험에서 여러 번 돌려도 이전 실행의 기록이 섞이지 않게 한다
        (tmp_path / "record.jsonl").unlink(missing_ok=True)
        ev = {"cisco_backup_collector": str(stub), "host_audit_output_root": str(out_root), "host_audit_run_id": "ha-test",
              "deployment_environment": "production"}
        ev.update(extra or {})
        (tmp_path / "ev.yml").write_text(yaml.safe_dump(ev), encoding="utf-8")
        record = tmp_path / "record.jsonl"
        env = {k: v for k, v in os.environ.items() if not k.startswith(("VAULT_", "OPENBAO_"))}
        env.update(ANSIBLE_CONFIG=str(tmp_path / "ansible.cfg"), STUB_RECORD=str(record),
                   ANSIBLE_LOOKUP_PLUGINS=str(ROOT_DIR / "lookup_plugins"), ANSIBLE_FILTER_PLUGINS=str(ROOT_DIR / "filter_plugins"))
        env.update(bao.approle_env())
        res = subprocess.run(["ansible-playbook", "-i", str(tmp_path / "inv.yml"), str(tmp_path / "play.yml"), "-e", f"@{tmp_path / 'ev.yml'}"],
                             capture_output=True, text=True, env=env, cwd=tmp_path)
        res.out = res.stdout + res.stderr
        res.calls = [json.loads(line) for line in record.read_text().splitlines()] if record.exists() else []
        hosts_dir = out_root / "ha-test" / "hosts"
        res.records = {p.stem: json.loads(p.read_text()) for p in sorted(hosts_dir.glob("*.json"))} if hosts_dir.exists() else {}
        res.hosts_dir = hosts_dir
        return res

    return run


def _store(*, ok=(), down=(), telnet=(), unregistered=()):
    endpoints = {**{h: {"ssh": OK_EP} for h in ok}, **{h: {"ssh": DOWN_EP} for h in down}, **{h: {"telnet": TELNET_EP} for h in telnet}}
    store = tcb._store(endpoints, _creds(*endpoints))
    for h in unregistered:
        store["inventory/assets/%s" % h] = {"description": "Fake switch", "type": "switch"}
    return store


def _arg(call, flag):
    return call["argv"][call["argv"].index(flag) + 1]


@pytest.mark.slow
def test_every_switch_gets_a_record_with_the_audit_flag_one_login_and_secrets_only_on_stdin(run_audit):
    res = run_audit(_store(ok=["ns0003", "ns0004"]), ["ns0003", "ns0004"])
    assert res.returncode == 0, res.out
    assert sorted(res.records) == ["ns0003", "ns0004"] and len(res.calls) == 2
    for call in res.calls:
        assert "--audit" in call["argv"] and _arg(call, "--mode") == "direct_ssh"
        assert call["stdin"]["password"].startswith("fake-pw-net-") and call["stdin"]["enable_password"].startswith("fake-pw-enable-")
        assert "fake-pw" not in " ".join(call["argv"])
    rec = res.records["ns0003"]
    assert rec["device_type"] == "SWITCH" and rec["status"] == "ok" and rec["inventory_hostname"] == "ns0003"
    assert rec["declared"]["groups"] == ["cisco_switches"] and rec["declared"]["environment"] == "production"
    assert rec["switch"]["access"] == "ssh" and len(rec["config_vulnerability"]["results"]) == 16
    assert rec["config_vulnerability"]["results"][0]["code"] == "KISA-2026:N-01"
    assert stat.S_IMODE((res.hosts_dir / "ns0003.json").stat().st_mode) == 0o600
    assert "fake-pw" not in res.out
    assert all("fake-pw" not in p.read_text() and "swtest" not in p.read_text() for p in res.hosts_dir.glob("*.json"))


@pytest.mark.slow
def test_switches_are_audited_one_at_a_time(run_audit):
    res = run_audit(_store(ok=["ns0003", "ns0004", "ns0005"]), ["ns0003", "ns0004", "ns0005"])
    assert res.returncode == 0, res.out
    spans = sorted((c["start"], c["end"]) for c in res.calls)
    assert len(spans) == 3 and all(a_end <= b_start for (_, a_end), (b_start, _) in zip(spans, spans[1:]))


@pytest.mark.slow
def test_an_unreachable_switch_is_recorded_unavailable_without_retry_and_the_run_continues(run_audit):
    res = run_audit(_store(ok=["ns0003"], down=["ns0004"]), ["ns0004", "ns0003"])
    assert res.returncode == 0, res.out
    down = res.records["ns0004"]
    assert down["status"] == "unreachable" and down["reason"] and down["config_vulnerability"]["status"] == "failed"
    assert res.records["ns0003"]["status"] == "ok"
    # 실패한 장비도 수집기는 한 번만 불렸다(재시도 없음 = 추가 로그인 시도 0회).
    assert [_arg(c, "--host") for c in res.calls].count("192.0.2.14") == 1 and len(res.calls) == 2


@pytest.mark.slow
def test_a_switch_whose_connection_cannot_be_resolved_is_unavailable_and_the_run_continues(run_audit):
    res = run_audit(_store(ok=["ns0003"], unregistered=["ns0004"]), ["ns0004", "ns0003"])
    assert res.returncode == 0, res.out
    assert res.records["ns0004"]["status"] == "unreachable" and "접속 정보" in res.records["ns0004"]["reason"]
    assert res.records["ns0003"]["status"] == "ok" and len(res.calls) == 1


@pytest.mark.slow
def test_a_telnet_switch_is_vulnerable_for_n08(run_audit):
    res = run_audit(_store(telnet=["ns0003"]), ["ns0003"])
    assert res.returncode == 0, res.out
    (call,) = res.calls
    assert _arg(call, "--mode") == "telnet" and "--kex" not in call["argv"]
    rec = res.records["ns0003"]
    n08 = next(r for r in rec["config_vulnerability"]["results"] if r["code"] == "KISA-2026:N-08")
    assert rec["switch"]["access"] == "telnet" and n08["verdict"] == "취약" and "Telnet" in n08["evidence"]


@pytest.mark.slow
def test_bastion_hop_uses_jump_mode_and_the_hop_password_only_on_stdin(run_audit):
    store = tcb._store({"ns0003": {"ssh": {**OK_EP, "via": "ns0001/ssh"}}, "ns0001": {"ssh": tcb.BASTION_EP}},
                       {**_creds("ns0003"), **tcb.BASTION_CRED})
    res = run_audit(store, ["ns0003"])
    assert res.returncode == 0, res.out
    (call,) = res.calls
    assert _arg(call, "--mode") == "jump_ssh" and _arg(call, "--bastion-user") == "jump"
    assert call["stdin"]["bastion_password"] == "fake-pw-jump-0013" and "fake-pw" not in " ".join(call["argv"])


@pytest.mark.slow
def test_switch_selection_follows_target_hosts_and_skips_hosts_already_selected_as_servers(run_audit):
    store = _store(ok=["ns0003", "ns0004"])
    only = run_audit(store, ["ns0003", "ns0004"], extra={"target_hosts": "ns0003"})
    assert only.returncode == 0, only.out
    assert sorted(only.records) == ["ns0003"]
    # 서버 선택에 이미 들어간 호스트는 스위치 선택에서 빠진다(같은 hosts/<호스트>.json을 두 번 쓰지 않는다).
    both = run_audit(store, ["ns0003", "ns0004"], groups={"servers": {"hosts": {"ns0004": {}}}})
    assert both.returncode == 0, both.out
    assert sorted(both.records) == ["ns0003"]
    off = run_audit(store, ["ns0003", "ns0004"], extra={"host_audit_switch_enabled": False})
    assert off.returncode == 0 and off.records == {} and off.calls == []
