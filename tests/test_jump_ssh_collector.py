import subprocess
import sys
import time
from pathlib import Path
import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "roles" / "cisco_backup" / "files"))
import cisco_cli_collector

def test_jump_ssh_interactive_openssh_simulation(tmp_path):
    """Simulate bastion jump using interactive OpenSSH/PTY execution to ensure smooth prompt transition."""
    mock_bastion = tmp_path / "mock_bastion.py"
    mock_target = tmp_path / "mock_target.py"

    mock_target.write_text("""import sys
sys.stdout.write("User Access Verification\\r\\n")
sys.stdout.write("Password: ")
sys.stdout.flush()
pwd = sys.stdin.readline().strip()
if pwd != "TargetSecretPass":
    sys.stdout.write("\\r\\n% Login invalid\\r\\n")
    sys.stdout.flush()
    sys.exit(1)
sys.stdout.write("\\r\\nswitch-cisco>\\r\\n")
sys.stdout.flush()
while True:
    cmd = sys.stdin.readline()
    if not cmd:
        break
    cmd = cmd.strip()
    if cmd == "enable":
        sys.stdout.write("switch-cisco#\\r\\n")
        sys.stdout.flush()
    elif cmd == "terminal length 0":
        sys.stdout.write("switch-cisco#\\r\\n")
        sys.stdout.flush()
    elif cmd == "show running-config":
        sys.stdout.write("Building configuration...\\r\\nversion 15.0\\r\\nhostname ns0279\\r\\nend\\r\\n")
        sys.stdout.flush()
    elif cmd == "exit":
        break
""")

    mock_bastion.write_text(f"""import sys, subprocess
sys.stdout.write("ppzxc@bastion's password: ")
sys.stdout.flush()
pwd = sys.stdin.readline().strip()
if pwd != "BastionSecretPass":
    sys.stdout.write("Permission denied, please try again.\\r\\n")
    sys.stdout.flush()
    sys.exit(1)
sys.stdout.write("ppzxc@bastion:~$ ")
sys.stdout.flush()
while True:
    line = sys.stdin.readline()
    if not line:
        break
    line = line.strip()
    if "ssh " in line:
        proc = subprocess.Popen(["python3", "{mock_target}"], stdin=sys.stdin, stdout=sys.stdout)
        proc.wait()
        break
    elif line == "exit":
        break
    else:
        sys.stdout.write("ppzxc@bastion:~$ ")
        sys.stdout.flush()
""")

    # Call collect_openssh_jump_interactive
    config = cisco_cli_collector.collect_openssh_jump_interactive(
        bastion_host="bastion.internal",
        bastion_port=22,
        bastion_user="ppzxc",
        bastion_pass="BastionSecretPass",
        target_host="10.10.200.4",
        target_user="ansible-backup",
        target_pass="TargetSecretPass",
        enable_pass="TargetSecretPass",
        timeout=10,
        _bastion_cmd=["python3", str(mock_bastion)]
    )
    assert "hostname ns0279" in config
    assert "version 15.0" in config


def test_jump_ssh_with_pubkey_or_no_bastion_password(tmp_path):
    """Ensure bastion login proceeds smoothly if bastion accepts pubkey or requires no password."""
    mock_bastion = tmp_path / "mock_bastion_nopass.py"
    mock_target = tmp_path / "mock_target_nopass.py"

    mock_target.write_text("""import sys
sys.stdout.write("User Access Verification\\r\\nPassword: ")
sys.stdout.flush()
pwd = sys.stdin.readline().strip()
if pwd != "TargetSecretPass":
    sys.exit(1)
sys.stdout.write("\\r\\nswitch-cisco#\\r\\n")
sys.stdout.flush()
while True:
    cmd = sys.stdin.readline()
    if not cmd:
        break
    if cmd.strip() == "show running-config":
        sys.stdout.write("Building configuration...\\r\\nversion 15.0\\r\\nhostname ns0281\\r\\nend\\r\\n")
        sys.stdout.flush()
    elif cmd.strip() == "exit":
        break
""")

    mock_bastion.write_text(f"""import sys, subprocess
# Bastion directly opens shell (e.g. pubkey authentication)
sys.stdout.write("ppzxc@bastion:~$ ")
sys.stdout.flush()
while True:
    line = sys.stdin.readline()
    if not line:
        break
    if "ssh " in line:
        proc = subprocess.Popen(["python3", "{mock_target}"], stdin=sys.stdin, stdout=sys.stdout)
        proc.wait()
        break
""")

    config = cisco_cli_collector.collect_openssh_jump_interactive(
        bastion_host="bastion.internal",
        bastion_port=22,
        bastion_user="ppzxc",
        bastion_pass="",
        target_host="10.10.200.5",
        target_user="ansible-backup",
        target_pass="TargetSecretPass",
        enable_pass="TargetSecretPass",
        timeout=10,
        _bastion_cmd=["python3", str(mock_bastion)]
    )
    assert "hostname ns0281" in config
    assert "version 15.0" in config


def test_jump_ssh_cisco_switch_as_bastion(tmp_path):
    """Simulate jump via Cisco IOS switch acting as bastion (ns0278 -> ns0279)."""
    mock_switch_bastion = tmp_path / "mock_cisco_bastion.py"
    mock_target = tmp_path / "mock_target_from_switch.py"

    mock_target.write_text("""import sys
sys.stdout.write("User Access Verification\\r\\nPassword: ")
sys.stdout.flush()
pwd = sys.stdin.readline().strip()
if pwd != "TargetPass123":
    sys.exit(1)
sys.stdout.write("\\r\\nns0279#\\r\\n")
sys.stdout.flush()
while True:
    cmd = sys.stdin.readline()
    if not cmd:
        break
    if cmd.strip() == "show running-config":
        sys.stdout.write("Building configuration...\\r\\nversion 12.2\\r\\nhostname ns0279\\r\\nend\\r\\n")
        sys.stdout.flush()
    elif cmd.strip() == "exit":
        break
""")

    mock_switch_bastion.write_text(f"""import sys, subprocess
sys.stdout.write("User Access Verification\\r\\nPassword: ")
sys.stdout.flush()
pwd = sys.stdin.readline().strip()
if pwd != "BastionSwitchPass":
    sys.stdout.write("Login invalid\\r\\n")
    sys.stdout.flush()
    sys.exit(1)
sys.stdout.write("\\r\\nns0278#\\r\\n")
sys.stdout.flush()
while True:
    line = sys.stdin.readline()
    if not line:
        break
    line = line.strip()
    if line == "terminal length 0":
        sys.stdout.write("ns0278#\\r\\n")
        sys.stdout.flush()
    elif line.startswith("ssh -l"):
        proc = subprocess.Popen(["python3", "{mock_target}"], stdin=sys.stdin, stdout=sys.stdout)
        proc.wait()
        break
    elif line == "exit":
        break
    else:
        sys.stdout.write("ns0278#\\r\\n")
        sys.stdout.flush()
""")

    config = cisco_cli_collector.collect_openssh_jump_interactive(
        bastion_host="ns0278",
        bastion_port=22,
        bastion_user="ansible-backup",
        bastion_pass="BastionSwitchPass",
        target_host="10.10.200.79",
        target_user="ansible-backup",
        target_pass="TargetPass123",
        enable_pass="TargetPass123",
        timeout=10,
        _bastion_cmd=["python3", str(mock_switch_bastion)]
    )
    assert "hostname ns0279" in config
    assert "version 12.2" in config

