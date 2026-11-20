"""#648: 경유(jump_ssh) 수집은 내부 장비에 실제로 로그인했을 때만 설정을 수집한다.

내부 ssh가 거부·타임아웃으로 실패하면 세션은 경유 장비의 프롬프트에 남는다. 이때 명령을 보내면
경유 장비의 설정이 대상 장비의 백업으로 저장되므로, 첫 프롬프트가 경유 장비와 같으면 아무것도 보내지 않고 실패한다."""
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "roles" / "cisco_backup" / "files"))
import cisco_cli_collector as c  # noqa: E402


class Device:
    """깨우기 개행에 wake로 답하고, 이후 명령은 hostname 프롬프트로 답하는 장비."""

    def __init__(self, wake: bytes, hostname: str):
        self.wake, self.hostname = wake, hostname
        self.sent, self.queue = [], []
        self.config = f"Building configuration...\n!\nhostname {hostname}\n!\nend\n"

    def send(self, data: bytes):
        self.sent.append(data)
        line = data.decode().strip("\r\n")
        prompt = f"{self.hostname}#".encode()
        if data == b"\n":
            self.queue.append(self.wake)
        elif line == "enable":
            self.queue.append(b"\r\n" + prompt)
        elif line == "terminal length 0":
            self.queue.append(b"\r\n" + prompt)
        elif line == "show running-config":
            self.queue.append(b"show running-config\r\n" + self.config.replace("\n", "\r\n").encode() + prompt)
        else:
            self.queue.append(b"% Invalid input\r\n" + prompt)

    def recv(self, timeout=0.0):
        return self.queue.pop(0) if self.queue else b""

    def commands_after_wake(self):
        return [d.decode().rstrip("\n") for d in self.sent if d != b"\n"]


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(c.time, "sleep", lambda _s: None)


@pytest.fixture(autouse=True)
def _short_inner_wait(monkeypatch):
    monkeypatch.setattr(c, "INNER_LOGIN_WAIT", 0.3)


def _run(dev, **kw):
    return c.run_cisco_session(dev.send, dev.recv, enable_pass="pw", timeout=2, **kw)


def test_inner_login_refused_stops_before_any_command_is_sent():
    """내부 접속이 거부돼 경유 장비 프롬프트가 다시 보이면 설정을 수집하지 않고 실패한다."""
    dev = Device(b"% Connection refused by remote host\r\n\r\nbastion-sw#", "bastion-sw")
    with pytest.raises(c.InnerLoginFailed, match="Connection refused"):
        _run(dev, bastion_prompt="bastion-sw#")
    assert dev.commands_after_wake() == []


def test_inner_login_success_collects_the_target_config():
    """내부 장비의 프롬프트가 경유 장비와 다르면 로그인에 성공한 것이라 정상 수집한다(접미사가 붙은 호스트네임 포함)."""
    dev = Device(b"\r\ntarget-sw-3560#", "target-sw-3560")
    out = _run(dev, bastion_prompt="bastion-sw#")
    assert "hostname target-sw-3560" in out


def test_same_hostname_counts_as_the_bastion_even_when_the_privilege_marker_differs():
    """경유 장비를 사용자 모드(>)로 기억하고 있어도 같은 호스트네임이면 내부 로그인 실패로 본다."""
    dev = Device(b"% Connection refused by remote host\r\n\r\nbastion-sw#", "bastion-sw")
    with pytest.raises(RuntimeError, match="no command was sent"):
        _run(dev, bastion_prompt="bastion-sw>")
    assert dev.commands_after_wake() == []


def test_no_prompt_at_all_after_the_inner_ssh_is_a_failure_and_nothing_is_sent():
    """내부 ssh가 응답 없이 멈추면(프롬프트 없음) 이어서 명령을 보내지 않고 실패한다."""
    dev = Device(b"", "target-sw")
    with pytest.raises(c.InnerLoginFailed, match="no prompt"):
        _run(dev, bastion_prompt="bastion-sw#")
    assert dev.commands_after_wake() == []


def test_inner_login_failure_is_not_retried_by_a_second_login():
    """내부 로그인 실패는 접속 재시도 대상이 아니다(재시도가 로그인 실패 임계값을 건드릴 수 있다)."""
    assert issubclass(c.InnerLoginFailed, RuntimeError)
    assert c.InnerLoginFailed in c.NO_RETRY_LOGIN_ERRORS
