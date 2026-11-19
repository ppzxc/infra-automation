"""Spec #568 / Ticket-2: 수집기는 점검 목적에서도 읽기 전용 명령만 장비로 보낸다."""
import inspect
import json
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "roles" / "cisco_backup" / "files"))
import cisco_cli_collector as c  # noqa: E402

CONFIG = "Building configuration...\n\nCurrent configuration : 100 bytes\n!\nversion 15.0\nhostname sw\n!\nend\n"
VERSION = "Cisco IOS Software, Version 15.0(2)SE11\nsw uptime is 1 week\n"


class FakeDevice:
    """send_fn으로 받은 바이트를 모두 기록하고 명령마다 정해진 응답을 recv_fn으로 돌려준다."""

    def __init__(self, start=b"sw>"):
        self.sent = []
        self.queue = []
        self.start = start
        self.awaiting_enable_pw = False

    def send(self, data: bytes):
        self.sent.append(data)
        line = data.decode().strip("\r\n")
        if data == b"\n":
            self.queue.append(self.start)
        elif line == "enable":
            self.awaiting_enable_pw = True
            self.queue.append(b"Password:")
        elif self.awaiting_enable_pw:
            self.awaiting_enable_pw = False
            self.queue.append(b"\r\nsw#")
        elif line == "terminal length 0":
            self.queue.append(b"\r\nsw#")
        elif line == "show running-config":
            self.queue.append(b"show running-config\r\n" + CONFIG.replace("\n", "\r\n").encode() + b"sw#")
        elif line == "show version":
            self.queue.append(b"show version\r\n" + VERSION.replace("\n", "\r\n").encode() + b"\r\nsw#")
        else:
            self.queue.append(b"% Invalid input\r\nsw#")

    def recv(self, timeout=0.0):
        return self.queue.pop(0) if self.queue else b""

    @property
    def commands(self):
        return [d.decode().rstrip("\n") for d in self.sent]


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(c.time, "sleep", lambda _s: None)


def _run(dev, **kw):
    return c.run_cisco_session(dev.send, dev.recv, enable_pass="enable-pw", timeout=2, **kw)


@pytest.mark.parametrize("cmd", [
    "show startup-config",
    "show run",
    "show running-config all",
    "SHOW VERSION",
    " show version",
    "show version ",
    "show version\n",
    "show version\nreload",
    "reload",
    "write memory",
    "terminal length 0",
    "enable",
    "",
])
def test_command_outside_the_allowlist_is_rejected_and_nothing_is_sent(cmd):
    dev = FakeDevice()
    with pytest.raises(c.CommandNotAllowed):
        c.run_cisco_commands(dev.send, dev.recv, [cmd], enable_pass="x", timeout=1)
    assert dev.sent == []


def test_one_bad_command_in_a_list_blocks_the_whole_list_before_any_send():
    dev = FakeDevice()
    with pytest.raises(c.CommandNotAllowed):
        c.run_cisco_commands(dev.send, dev.recv, ["show version", "show startup-config"], enable_pass="x", timeout=1)
    assert dev.sent == []


@pytest.mark.parametrize("cmd", [
    "configure terminal", "conf t", "config term", "CONFIGURE terminal", "Conf T", "  conf t  ",
    "\tconfigure\tterminal", "conf", "confi t", "configure", "configure memory", "configure  terminal\r",
    "con t", "show version\r\nconf t", "show version;conf t",
])
def test_config_mode_entry_is_rejected_in_every_variant(cmd):
    dev = FakeDevice()
    with pytest.raises(c.ConfigModeRejected):
        c.run_cisco_commands(dev.send, dev.recv, [cmd], enable_pass="x", timeout=1)
    assert dev.sent == []
    # 설정 모드 거부는 허용 목록 오류의 한 종류라 호출자는 CommandNotAllowed 하나만 잡아도 된다.
    assert issubclass(c.ConfigModeRejected, c.CommandNotAllowed)


def test_the_check_guards_the_send_point_itself_not_only_the_entry():
    sent = []
    with pytest.raises(c.CommandNotAllowed):
        c._send_checked(sent.append, "conf t")
    assert sent == []
    c._send_checked(sent.append, "show version")
    assert sent == [b"show version\n"]


def test_session_prep_is_a_fixed_internal_list_callers_cannot_extend():
    assert c.SESSION_PREP_COMMANDS == ("terminal length 0",)
    sent = []
    with pytest.raises(ValueError):
        c._send_prep(sent.append, "show version")
    with pytest.raises(ValueError):
        c._send_prep(sent.append, "configure terminal")
    assert sent == []
    # 세션 함수에는 준비 명령을 넘기는 인자가 없다.
    for fn in (c.run_cisco_session, c.run_cisco_commands):
        assert not any("prep" in p for p in inspect.signature(fn).parameters)


def test_an_audit_run_sends_exactly_prep_then_the_two_read_only_commands():
    dev = FakeDevice()
    _run(dev, audit=True)
    assert dev.commands == [
        "", "enable", "enable-pw", "terminal length 0", "show running-config", "show version",
    ]


def test_audit_returns_both_outputs_and_the_version_text_is_clean():
    dev = FakeDevice()
    out = _run(dev, audit=True)
    assert set(out) == {"running_config", "version"}
    assert out["running_config"].startswith("Building configuration") and out["running_config"].endswith("end")
    assert "Cisco IOS Software, Version 15.0(2)SE11" in out["version"]
    assert "show version" not in out["version"] and not out["version"].rstrip().endswith("sw#")


def test_backup_behavior_is_unchanged_one_show_and_a_plain_string():
    dev = FakeDevice()
    out = _run(dev)
    assert isinstance(out, str) and out.startswith("Building configuration") and out.endswith("end")
    assert dev.commands == ["", "enable", "enable-pw", "terminal length 0", "show running-config"]


def test_privileged_start_skips_enable_but_still_sends_only_allowed_commands():
    dev = FakeDevice(start=b"sw#")
    _run(dev, audit=True)
    assert dev.commands == ["", "terminal length 0", "show running-config", "show version"]


def test_audit_connection_failure_is_not_retried_and_raises(monkeypatch):
    calls = []

    def boom(*a, **k):
        calls.append(1)
        raise RuntimeError("refused")

    monkeypatch.setattr(c, "paramiko", None)
    monkeypatch.setattr(c, "collect_openssh_pty", boom)
    with pytest.raises(RuntimeError):
        c.collect_direct_ssh("h", 22, "u", "p", audit=True)
    assert calls == [1]


def _fake_paramiko(error, connect_ok=False):
    class SSHException(Exception):
        pass

    class AuthenticationException(SSHException):
        pass

    class FakeParamiko:
        pass

    FakeParamiko.SSHException = SSHException
    FakeParamiko.AuthenticationException = AuthenticationException

    class SSHClient:
        def set_missing_host_key_policy(self, _p):
            pass

        def connect(self, **k):
            if not connect_ok:
                raise error(FakeParamiko)

        def invoke_shell(self):
            raise error(FakeParamiko)

        def close(self):
            pass

    FakeParamiko.SSHClient = SSHClient
    FakeParamiko.AutoAddPolicy = type("AutoAddPolicy", (), {})
    FakeParamiko.Transport = type("T", (), {})
    return FakeParamiko


@pytest.mark.parametrize("error", [
    lambda p: p.AuthenticationException("auth failed"),
    lambda p: RuntimeError("refused"),
    lambda p: TimeoutError("timed out"),
])
def test_audit_does_not_fall_back_to_a_second_login_after_auth_or_network_failure(monkeypatch, error):
    openssh = []
    monkeypatch.setattr(c, "paramiko", _fake_paramiko(error))
    monkeypatch.setattr(c, "collect_openssh_pty", lambda *a, **k: openssh.append(1))
    with pytest.raises(Exception):
        c.collect_direct_ssh("h", 22, "u", "p", audit=True)
    assert openssh == []


def test_audit_falls_back_to_openssh_once_only_for_a_pre_login_negotiation_failure(monkeypatch):
    openssh = []
    monkeypatch.setattr(c, "paramiko", _fake_paramiko(lambda p: p.SSHException("no acceptable kex")))
    monkeypatch.setattr(c, "collect_openssh_pty", lambda *a, **k: openssh.append(1) or {"running_config": "x", "version": "y"})
    assert c.collect_direct_ssh("h", 22, "u", "p", audit=True) == {"running_config": "x", "version": "y"}
    assert openssh == [1]


def test_main_audit_prints_json_and_failure_exits_nonzero(monkeypatch, capsys):
    monkeypatch.setattr(c, "collect_direct_ssh", lambda **k: {"running_config": CONFIG.strip(), "version": VERSION})
    monkeypatch.setattr(c, "read_passwords_from_stdin", lambda: {"password": "p"})
    monkeypatch.setattr(sys, "argv", ["x", "--mode", "direct_ssh", "--host", "h", "--user", "u", "--audit"])
    with pytest.raises(SystemExit) as e:
        c.main()
    assert e.value.code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == VERSION and data["running_config"].startswith("Building")

    def fail(**k):
        raise RuntimeError("down")

    monkeypatch.setattr(c, "collect_direct_ssh", fail)
    with pytest.raises(SystemExit) as e:
        c.main()
    assert e.value.code == 3
    assert capsys.readouterr().out == ""


def test_main_without_audit_still_prints_the_plain_config(monkeypatch, capsys):
    monkeypatch.setattr(c, "collect_direct_ssh", lambda **k: CONFIG.strip())
    monkeypatch.setattr(c, "read_passwords_from_stdin", lambda: {"password": "p"})
    monkeypatch.setattr(sys, "argv", ["x", "--mode", "direct_ssh", "--host", "h", "--user", "u"])
    with pytest.raises(SystemExit) as e:
        c.main()
    assert e.value.code == 0
    assert capsys.readouterr().out == CONFIG.strip()


def test_audit_does_not_fall_back_after_a_post_login_ssh_exception(monkeypatch):
    openssh = []
    monkeypatch.setattr(c, "paramiko", _fake_paramiko(lambda p: p.SSHException("channel dropped"), connect_ok=True))
    monkeypatch.setattr(c, "collect_openssh_pty", lambda *a, **k: openssh.append(1))
    with pytest.raises(Exception, match="channel dropped"):
        c.collect_direct_ssh("h", 22, "u", "p", audit=True)
    assert openssh == []


def test_login_prompt_shown_again_stops_before_any_command_is_sent():
    """로그인이 실패해 로그인 프롬프트가 다시 뜨면 명령을 비밀번호 추측으로 흘리지 않는다(N-04 1회 시도)."""
    dev = FakeDevice()
    dev.start = b"\r\nPassword: "
    with pytest.raises(RuntimeError, match="login failed"):
        c.run_cisco_commands(dev.send, dev.recv, ["show version"], enable_pass="x", timeout=1)
    assert dev.commands == [""]
