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
