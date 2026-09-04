#!/usr/bin/env python3
"""
Infra Automation Cisco Config Collector CLI
Collects running-config from Cisco IOS switches via:
  1. direct telnet (for Telnet-only switches)
  2. bastion jump session (for isolated internal subnet switches)
"""
import argparse
import json
import socket
import sys
import time

try:
    import paramiko
except ImportError:
    paramiko = None


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
    """Shared interactive logic for Cisco IOS CLI session."""
    time.sleep(1)
    send_fn(b"\n")
    time.sleep(0.5)
    prompt = recv_fn()

    if prompt.strip().endswith(b">"):
        send_fn(b"enable\n")
        time.sleep(1)
        resp = recv_fn()
        if b"password" in resp.lower() and enable_pass:
            send_fn(enable_pass.encode() + b"\n")
            time.sleep(1)
            recv_fn()

    send_fn(b"terminal length 0\n")
    time.sleep(1)
    recv_fn()

    send_fn(b"show running-config\n")
    time.sleep(2)

    out = b""
    start_time = time.time()
    while time.time() - start_time < timeout:
        chunk = recv_fn()
        if chunk:
            out += chunk
            if b"end\r\n" in chunk or b"end\n" in chunk:
                break
        else:
            time.sleep(0.5)

    return extract_clean_config(out.decode(errors="ignore"))


def collect_telnet(host: str, port: int, user: str, password: str,
                   enable_pass: str = None, timeout: int = 30) -> str:
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

    def recv_fn() -> bytes:
        try:
            s.settimeout(2.0)
            return s.recv(8192)
        except Exception:
            return b""

    try:
        return run_cisco_session(send_fn, recv_fn, enable_pass=enable_pass or password, timeout=timeout)
    finally:
        s.close()


def collect_jump_ssh(bastion_host: str, bastion_port: int, bastion_user: str, bastion_pass: str,
                     target_host: str, target_user: str, target_pass: str,
                     enable_pass: str = None, timeout: int = 35) -> str:
    if paramiko is None:
        raise RuntimeError("paramiko is required for jump SSH collection")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        bastion_host,
        port=bastion_port,
        username=bastion_user,
        password=bastion_pass,
        look_for_keys=False,
        allow_agent=False,
        timeout=timeout
    )
    try:
        shell = ssh.invoke_shell()
        time.sleep(1)
        shell.send("terminal length 0\n")
        time.sleep(1)
        shell.send(f"ssh -l {target_user} {target_host}\n")
        time.sleep(2)
        shell.send(f"{target_pass}\n")
        time.sleep(2)

        def send_fn(data: bytes):
            shell.send(data.decode(errors="ignore"))

        def recv_fn() -> bytes:
            time.sleep(0.3)
            out = b""
            while shell.recv_ready():
                out += shell.recv(65535)
            return out

        return run_cisco_session(send_fn, recv_fn, enable_pass=enable_pass or target_pass, timeout=timeout)
    finally:
        ssh.close()


def main():
    parser = argparse.ArgumentParser(description="Cisco Config Collector Helper")
    parser.add_argument("--mode", choices=["telnet", "jump_ssh"], required=True)
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
            if not args.bastion_host or not args.bastion_user or not bastion_password:
                sys.stderr.write("Error: bastion parameters (host, user, password) required for jump_ssh mode\n")
                sys.exit(1)
            config = collect_jump_ssh(
                bastion_host=args.bastion_host,
                bastion_port=args.bastion_port,
                bastion_user=args.bastion_user,
                bastion_pass=bastion_password,
                target_host=args.host,
                target_user=args.user,
                target_pass=password,
                enable_pass=enable_password,
                timeout=args.timeout
            )
        else:
            sys.stderr.write(f"Unknown mode: {args.mode}\n")
            sys.exit(1)

        if not config or ("Building configuration" not in config and "Current configuration" not in config and "version " not in config):
            sys.stderr.write("Error: collected output does not look like a valid running-config\n")
            sys.exit(2)

        sys.stdout.write(config)
        sys.exit(0)
    except Exception as e:
        sys.stderr.write(f"Error during collection: {e}\n")
        sys.exit(3)


if __name__ == "__main__":
    main()
