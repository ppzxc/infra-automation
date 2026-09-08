#!/usr/bin/env python3
"""
Infra Automation Cisco Config Collector CLI
Collects running-config from Cisco IOS switches via:
  1. direct telnet (for Telnet-only switches)
  2. bastion jump session (for isolated internal subnet switches)
"""
import argparse
import fcntl
import json
import os
import pty
import select
import socket
import subprocess
import sys
import termios
import time

try:
    import paramiko
except ImportError:
    paramiko = None


def enable_legacy_algorithms():
    """Ensure legacy KEX, ciphers, and key types are enabled in Paramiko for Cisco IOS devices."""
    if paramiko is None:
        return
    try:
        transport = paramiko.Transport
        legacy_kex = (
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1",
            "diffie-hellman-group-exchange-sha256",
        )
        if hasattr(transport, "_preferred_kex"):
            current_kex = list(transport._preferred_kex)
            for kex in legacy_kex:
                if kex not in current_kex:
                    current_kex.append(kex)
            transport._preferred_kex = tuple(current_kex)

        legacy_keys = (
            "ssh-rsa",
            "ssh-dss",
        )
        if hasattr(transport, "_preferred_keys"):
            current_keys = list(transport._preferred_keys)
            for key in legacy_keys:
                if key not in current_keys:
                    current_keys.append(key)
            transport._preferred_keys = tuple(current_keys)

        legacy_ciphers = (
            "aes128-cbc",
            "3des-cbc",
            "aes192-cbc",
            "aes256-cbc",
        )
        if hasattr(transport, "_preferred_ciphers"):
            current_ciphers = list(transport._preferred_ciphers)
            for c in legacy_ciphers:
                if c not in current_ciphers:
                    current_ciphers.append(c)
            transport._preferred_ciphers = tuple(current_ciphers)
    except Exception:
        pass


def read_passwords_from_stdin() -> dict:
    """Read credentials from JSON-formatted stdin to prevent exposure in process table (ps aux)."""
    if not sys.stdin.isatty():
        try:
            data = sys.stdin.read().strip()
            if data:
                return json.loads(data)
        except Exception:
            pass
    return {}


def extract_clean_config(raw_output: str) -> str:
    """Extract clean running configuration text from terminal session output."""
    text = raw_output
    if "show running-config" in text:
        text = text.split("show running-config", 1)[1]

    lines = text.splitlines()
    clean_lines = []
    started = False
    for line in lines:
        if not started:
            if "Building configuration" in line or "Current configuration" in line or line.strip().startswith("!") or line.strip().startswith("version "):
                started = True
                clean_lines.append(line)
        else:
            clean_lines.append(line)
            if line.strip() == "end":
                break

    return "\n".join(clean_lines).strip() if clean_lines else text.strip()


def run_cisco_session(send_fn, recv_fn, enable_pass: str = None, timeout: int = 30) -> str:
    """Robust interactive logic for Cisco IOS CLI session."""
    def wait_for(pred_fn, wait_timeout=8.0, poll_interval=0.2):
        accum = b""
        start = time.time()
        while time.time() - start < wait_timeout:
            chunk = recv_fn(poll_interval)
            if chunk:
                accum += chunk
                if pred_fn(accum):
                    return accum
        return accum

    # Send newline to wake up console and observe initial prompt
    time.sleep(0.5)
    send_fn(b"\n")
    initial_buf = wait_for(lambda b: b.strip().endswith(b">") or b.strip().endswith(b"#"), wait_timeout=5.0)

    # Check if we need to escalate to enable mode
    if initial_buf.strip().endswith(b">") or b">" in initial_buf:
        send_fn(b"enable\n")
        enable_resp = wait_for(lambda b: b"password" in b.lower() or b.strip().endswith(b"#"), wait_timeout=5.0)
        if b"password" in enable_resp.lower() and enable_pass:
            send_fn(enable_pass.encode() + b"\n")
            wait_for(lambda b: b.strip().endswith(b"#"), wait_timeout=5.0)

    # Disable terminal paging so config outputs continuously without --More--
    send_fn(b"terminal length 0\n")
    wait_for(lambda b: b.strip().endswith(b"#"), wait_timeout=5.0)

    # Execute show running-config
    send_fn(b"show running-config\n")

    out = b""
    start_time = time.time()
    while time.time() - start_time < timeout:
        chunk = recv_fn(0.5)
        if chunk:
            out += chunk
            if b"end\r\n" in chunk or b"end\n" in chunk:
                break
            if b"--More--" in chunk or b"--more--" in chunk:
                send_fn(b" ")

    return extract_clean_config(out.decode(errors="ignore"))


def collect_telnet(host: str, port: int, user: str, password: str,
                   enable_pass: str = None, timeout: int = 30) -> str:
    """Connect to Cisco switch via direct Telnet socket."""
    s = socket.create_connection((host, port), timeout=timeout)
    time.sleep(2)
    banner = s.recv(4096).decode(errors="ignore")
    if "username" in banner.lower():
        s.sendall(user.encode() + b"\n")
        time.sleep(1)
        s.recv(4096)
    s.sendall(password.encode() + b"\n")
    time.sleep(2)
    s.recv(4096)

    def send_fn(data: bytes):
        s.sendall(data)

    def recv_fn(t: float = 1.0) -> bytes:
        try:
            r, _, _ = select.select([s], [], [], t)
            if r:
                return s.recv(8192)
            return b""
        except Exception:
            return b""

    try:
        return run_cisco_session(send_fn, recv_fn, enable_pass=enable_pass or password, timeout=timeout)
    finally:
        s.close()


def collect_openssh_pty(cmd_args: list, password: str, enable_pass: str = None,
                        target_pass: str = None, timeout: int = 30) -> str:
    """PTY-based execution of OpenSSH command with controlling terminal and robust password negotiation."""
    master, slave = pty.openpty()

    def preexec():
        os.setsid()
        try:
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        except Exception:
            pass

    proc = subprocess.Popen(
        cmd_args,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
        preexec_fn=preexec
    )
    os.close(slave)

    def pty_send(data: bytes):
        os.write(master, data)

    def pty_recv(t: float = 0.5) -> bytes:
        r, _, _ = select.select([master], [], [], t)
        if r:
            try:
                return os.read(master, 8192)
            except OSError:
                return b""
        return b""

    try:
        # If target_pass is specified, we expect password prompt for bastion first, then target switch
        passwords_to_send = [password, target_pass] if target_pass else [password]
        pass_idx = 0
        buf = b""
        login_start = time.time()

        while time.time() - login_start < 20.0 and pass_idx < len(passwords_to_send):
            chunk = pty_recv(0.3)
            if chunk:
                buf += chunk
                lower = buf.lower()
                if b"yes/no" in lower:
                    pty_send(b"yes\n")
                    buf = b""
                elif b"permission denied" in lower:
                    err_msg = buf.decode(errors="ignore").strip()
                    raise RuntimeError(f"SSH authentication failed (permission denied): {err_msg}")
                elif b"password:" in lower or b"password :" in lower:
                    current_pwd = passwords_to_send[pass_idx]
                    pty_send(current_pwd.encode() + b"\n")
                    pass_idx += 1
                    buf = b""
            if proc.poll() is not None:
                err_msg = buf.decode(errors="ignore").strip()
                raise RuntimeError(f"SSH process exited unexpectedly with code {proc.returncode}: {err_msg}")

        effective_enable = enable_pass or (target_pass if target_pass else password)
        return run_cisco_session(pty_send, pty_recv, enable_pass=effective_enable, timeout=timeout)
    finally:
        try:
            pty_send(b"exit\n")
        except Exception:
            pass
        os.close(master)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()


def get_supported_ssh_algorithms(query_type: str) -> set:
    """Query OpenSSH for supported algorithms (e.g. 'key', 'kex', 'cipher')."""
    try:
        out = subprocess.check_output(["ssh", "-Q", query_type], text=True, stderr=subprocess.DEVNULL)
        return {line.strip() for line in out.splitlines() if line.strip()}
    except Exception:
        return set()


def get_openssh_direct_args(host: str, port: int, user: str) -> list:
    """Build OpenSSH CLI invocation with legacy ciphers, key exchanges, and host keys enabled (filtered by system support)."""
    desired_kex = [
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group-exchange-sha256",
    ]
    desired_keys = ["ssh-rsa", "ssh-dss"]
    desired_ciphers = ["aes128-cbc", "3des-cbc", "aes192-cbc", "aes256-cbc"]

    sup_kex = get_supported_ssh_algorithms("kex")
    sup_keys = get_supported_ssh_algorithms("key")
    sup_ciphers = get_supported_ssh_algorithms("cipher")

    valid_kex = [k for k in desired_kex if not sup_kex or k in sup_kex]
    valid_keys = [k for k in desired_keys if not sup_keys or k in sup_keys]
    valid_ciphers = [c for c in desired_ciphers if not sup_ciphers or c in sup_ciphers]

    args = [
        "ssh",
        "-tt",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "PubkeyAuthentication=no",
        "-o", "PreferredAuthentications=password,keyboard-interactive",
    ]
    if valid_kex:
        args.extend(["-o", f"KexAlgorithms=+{','.join(valid_kex)}"])
    if valid_keys:
        args.extend(["-o", f"HostKeyAlgorithms=+{','.join(valid_keys)}"])
    if valid_ciphers:
        args.extend(["-o", f"Ciphers=+{','.join(valid_ciphers)}"])

    args.extend(["-p", str(port), f"{user}@{host}"])
    return args


def collect_direct_ssh(host: str, port: int, user: str, password: str,
                       enable_pass: str = None, timeout: int = 30) -> str:
    """Collect config via Direct SSH. Tries Paramiko first, falls back to OpenSSH PTY."""
    paramiko_err = None
    if paramiko is not None:
        try:
            enable_legacy_algorithms()
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            connect_kwargs = {
                "hostname": host,
                "port": port,
                "username": user,
                "password": password,
                "look_for_keys": False,
                "allow_agent": False,
                "timeout": timeout,
            }
            try:
                connect_kwargs["disabled_algorithms"] = dict(kex=[], ciphers=[], keys=[])
                ssh.connect(**connect_kwargs)
            except TypeError:
                del connect_kwargs["disabled_algorithms"]
                ssh.connect(**connect_kwargs)

            try:
                shell = ssh.invoke_shell()

                def send_fn(data: bytes):
                    shell.send(data)

                def recv_fn(t: float = 0.5) -> bytes:
                    start = time.time()
                    out = b""
                    while time.time() - start < t:
                        if shell.recv_ready():
                            out += shell.recv(65535)
                        else:
                            time.sleep(0.05)
                    return out

                return run_cisco_session(send_fn, recv_fn, enable_pass=enable_pass or password, timeout=timeout)
            finally:
                ssh.close()
        except Exception as pe:
            paramiko_err = pe

    cmd = get_openssh_direct_args(host, port, user)
    try:
        return collect_openssh_pty(cmd, password=password, enable_pass=enable_pass or password, timeout=timeout)
    except Exception as oe:
        if paramiko_err:
            raise RuntimeError(f"Direct SSH failed with Paramiko ({paramiko_err}) and OpenSSH ({oe})")
        raise oe


def collect_openssh_jump_interactive(bastion_host: str, bastion_port: int, bastion_user: str, bastion_pass: str,
                                     target_host: str, target_user: str, target_pass: str,
                                     enable_pass: str = None, timeout: int = 35,
                                     _bastion_cmd: list = None) -> str:
    """Collect config by SSHing into Bastion host first via PTY, then chaining SSH to target switch."""
    master, slave = pty.openpty()

    def preexec():
        os.setsid()
        try:
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        except Exception:
            pass

    cmd = _bastion_cmd or get_openssh_direct_args(bastion_host, bastion_port, bastion_user)

    proc = subprocess.Popen(
        cmd,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
        preexec_fn=preexec
    )
    os.close(slave)

    def pty_send(data: bytes):
        os.write(master, data)

    def pty_recv(t: float = 0.5) -> bytes:
        r, _, _ = select.select([master], [], [], t)
        if r:
            try:
                return os.read(master, 8192)
            except OSError:
                return b""
        return b""

    try:
        # Step 1: Handle Bastion password authentication or immediate shell
        buf = b""
        login_start = time.time()
        while time.time() - login_start < 20.0:
            chunk = pty_recv(0.3)
            if chunk:
                buf += chunk
                lower = buf.lower()
                if b"yes/no" in lower:
                    pty_send(b"yes\n")
                    buf = b""
                elif b"permission denied" in lower:
                    err_msg = buf.decode(errors="ignore").strip()
                    raise RuntimeError(f"Bastion SSH authentication failed (permission denied): {err_msg}")
                elif b"password:" in lower or b"password :" in lower:
                    if bastion_pass:
                        pty_send(bastion_pass.encode() + b"\n")
                    buf = b""
                    break
                elif b"$" in buf or b"#" in buf or b">" in buf:
                    # Shell prompt reached directly (e.g. pubkey authentication)
                    break
            if proc.poll() is not None:
                err_msg = buf.decode(errors="ignore").strip()
                raise RuntimeError(f"Bastion SSH process exited unexpectedly with code {proc.returncode}: {err_msg}")

        # Step 2: Wait for bastion shell prompt ($ or # or >)
        shell_start = time.time()
        buf = b""
        bastion_is_cisco = False
        while time.time() - shell_start < 10.0:
            chunk = pty_recv(0.3)
            if chunk:
                buf += chunk
                if b"#" in buf or b">" in buf:
                    bastion_is_cisco = True
                    break
                elif b"$" in buf:
                    break
            if proc.poll() is not None:
                err_msg = buf.decode(errors="ignore").strip()
                raise RuntimeError(f"Bastion shell exited unexpectedly: {err_msg}")

        if bastion_is_cisco:
            pty_send(b"terminal length 0\n")
        else:
            pty_send(b"stty -echo\n")
        time.sleep(0.3)
        pty_recv(0.3)

        # Step 3: From Bastion shell, SSH to target Cisco switch
        if bastion_is_cisco:
            ssh_cmd = f"ssh -l {target_user} {target_host}\n"
        else:
            ssh_cmd = (
                f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                f"-o KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256 "
                f"-o HostKeyAlgorithms=+ssh-rsa,ssh-dss "
                f"-o Ciphers=+aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc "
                f"-l {target_user} {target_host}\n"
            )
        pty_send(ssh_cmd.encode())

        # Step 4: Handle Target switch password authentication
        target_start = time.time()
        buf = b""
        while time.time() - target_start < 15.0:
            chunk = pty_recv(0.3)
            if chunk:
                buf += chunk
                lower = buf.lower()
                if b"yes/no" in lower:
                    pty_send(b"yes\n")
                    buf = b""
                elif b"permission denied" in lower:
                    err_msg = buf.decode(errors="ignore").strip()
                    raise RuntimeError(f"Target switch SSH authentication failed (permission denied): {err_msg}")
                elif b"password:" in lower or b"password :" in lower:
                    pty_send(target_pass.encode() + b"\n")
                    buf = b""
                    break
            if proc.poll() is not None:
                err_msg = buf.decode(errors="ignore").strip()
                raise RuntimeError(f"Target SSH process exited unexpectedly: {err_msg}")

        effective_enable = enable_pass or target_pass
        return run_cisco_session(pty_send, pty_recv, enable_pass=effective_enable, timeout=timeout)
    finally:
        try:
            pty_send(b"exit\nexit\n")
        except Exception:
            pass
        os.close(master)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()


def collect_jump_ssh(bastion_host: str, bastion_port: int, bastion_user: str, bastion_pass: str,
                     target_host: str, target_user: str, target_pass: str,
                     enable_pass: str = None, timeout: int = 35) -> str:
    """Collect config via Bastion jump SSH session."""
    paramiko_err = None
    if paramiko is not None:
        try:
            enable_legacy_algorithms()
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            connect_kwargs = {
                "hostname": bastion_host,
                "port": bastion_port,
                "username": bastion_user,
                "password": bastion_pass,
                "look_for_keys": False,
                "allow_agent": False,
                "timeout": timeout,
            }
            try:
                connect_kwargs["disabled_algorithms"] = dict(kex=[], ciphers=[], keys=[])
                ssh.connect(**connect_kwargs)
            except TypeError:
                del connect_kwargs["disabled_algorithms"]
                ssh.connect(**connect_kwargs)

            try:
                shell = ssh.invoke_shell()

                def send_fn(data: bytes):
                    shell.send(data)

                def recv_fn(t: float = 0.5) -> bytes:
                    start = time.time()
                    out = b""
                    while time.time() - start < t:
                        if shell.recv_ready():
                            out += shell.recv(65535)
                        else:
                            time.sleep(0.05)
                    return out

                buf = b""
                start = time.time()
                while time.time() - start < 5.0:
                    c = recv_fn(0.2)
                    if c:
                        buf += c
                        if b"$" in buf or b"#" in buf or b">" in buf:
                            break

                send_fn(b"terminal length 0\n")
                time.sleep(0.5)
                recv_fn(0.5)

                send_fn(f"ssh -l {target_user} {target_host}\n".encode())
                buf = b""
                start = time.time()
                while time.time() - start < 10.0:
                    c = recv_fn(0.3)
                    if c:
                        buf += c
                        if b"password:" in buf.lower() or b"password :" in buf.lower():
                            send_fn(f"{target_pass}\n".encode())
                            break
                        if b"yes/no" in buf.lower():
                            send_fn(b"yes\n")

                return run_cisco_session(send_fn, recv_fn, enable_pass=enable_pass or target_pass, timeout=timeout)
            finally:
                ssh.close()
        except Exception as pe:
            paramiko_err = pe

    # Fallback to interactive OpenSSH Jump session via PTY
    try:
        return collect_openssh_jump_interactive(
            bastion_host=bastion_host,
            bastion_port=bastion_port,
            bastion_user=bastion_user,
            bastion_pass=bastion_pass,
            target_host=target_host,
            target_user=target_user,
            target_pass=target_pass,
            enable_pass=enable_pass,
            timeout=timeout
        )
    except Exception as oe:
        if paramiko_err:
            raise RuntimeError(f"Jump SSH failed with Paramiko ({paramiko_err}) and OpenSSH ({oe})")
        raise oe


def main():
    parser = argparse.ArgumentParser(description="Cisco Config Collector Helper")
    parser.add_argument("--mode", choices=["telnet", "jump_ssh", "direct_ssh", "ssh"], required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", help="Password for target (prefer stdin JSON for security)")
    parser.add_argument("--enable-password", help="Enable secret for privileged EXEC mode")
    parser.add_argument("--bastion-host")
    parser.add_argument("--bastion-port", type=int, default=22)
    parser.add_argument("--bastion-user")
    parser.add_argument("--bastion-password", help="Password for bastion (prefer stdin JSON)")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    stdin_creds = read_passwords_from_stdin()
    password = stdin_creds.get("password") or args.password
    enable_password = stdin_creds.get("enable_password") or args.enable_password
    bastion_password = stdin_creds.get("bastion_password") or args.bastion_password

    if password is None:
        sys.stderr.write("Error: password must be provided via stdin or --password\n")
        sys.exit(1)

    try:
        if args.mode == "telnet":
            config = collect_telnet(
                host=args.host,
                port=args.port,
                user=args.user,
                password=password,
                enable_pass=enable_password,
                timeout=args.timeout
            )
        elif args.mode == "jump_ssh":
            if not args.bastion_host or not args.bastion_user:
                sys.stderr.write("Error: bastion parameters (host, user) required for jump_ssh mode\n")
                sys.exit(1)
            config = collect_jump_ssh(
                bastion_host=args.bastion_host,
                bastion_port=args.bastion_port,
                bastion_user=args.bastion_user,
                bastion_pass=bastion_password or "",
                target_host=args.host,
                target_user=args.user,
                target_pass=password,
                enable_pass=enable_password,
                timeout=args.timeout
            )
        elif args.mode in ("direct_ssh", "ssh"):
            config = collect_direct_ssh(
                host=args.host,
                port=args.port,
                user=args.user,
                password=password,
                enable_pass=enable_password,
                timeout=args.timeout
            )
        else:
            sys.stderr.write(f"Unknown mode: {args.mode}\n")
            sys.exit(1)

        if not config or ("Building configuration" not in config and "Current configuration" not in config and "version " not in config):
            snippet = (config[:200] + "...") if config else "None"
            sys.stderr.write(f"Error: collected output does not look like a valid running-config (len={len(config) if config else 0}, snippet={snippet!r})\n")
            sys.exit(2)

        sys.stdout.write(config)
        sys.exit(0)
    except Exception as e:
        import traceback
        sys.stderr.write(f"Error during collection on {args.host} ({type(e).__name__}): {e}\n")
        traceback.print_exc(file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
