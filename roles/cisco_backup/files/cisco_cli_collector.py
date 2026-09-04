#!/usr/bin/env python3
"""
Infra Automation Cisco Config Collector CLI
Collects running-config from Cisco IOS switches via:
  1. direct telnet (for Telnet-only switches)
  2. bastion jump session (for isolated internal subnet switches)
"""
import argparse
import socket
import sys
import time

try:
    import paramiko
except ImportError:
    paramiko = None


def collect_telnet(host: str, port: int, user: str, password: str, timeout: int = 15) -> str:
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
    s.sendall(b"terminal length 0\n")
    time.sleep(1)
    s.recv(4096)
    s.sendall(b"show running-config\n")
    time.sleep(3)

    out = b""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            s.settimeout(3.0)
            chunk = s.recv(8192)
            if not chunk:
                break
            out += chunk
            if b"end\r\n" in chunk or b"end\n" in chunk:
                break
        except Exception:
            break
    s.close()
    text = out.decode(errors="ignore")
    if "show running-config" in text:
        text = text.split("show running-config", 1)[1].strip()
    return text


def collect_jump_ssh(bastion_host: str, bastion_port: int, bastion_user: str, bastion_pass: str,
                     target_host: str, target_user: str, target_pass: str, timeout: int = 25) -> str:
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
    shell = ssh.invoke_shell()
    time.sleep(1)
    shell.send("terminal length 0\n")
    time.sleep(1)
    shell.send(f"ssh -l {target_user} {target_host}\n")
    time.sleep(2)
    shell.send(f"{target_pass}\n")
    time.sleep(2)
    shell.send("terminal length 0\n")
    time.sleep(1)
    shell.send("show running-config\n")
    time.sleep(3)

    out = ""
    start_time = time.time()
    while time.time() - start_time < timeout:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode(errors="ignore")
            out += chunk
            if "end\r\n" in chunk or "end\n" in chunk:
                break
        else:
            time.sleep(1)
    ssh.close()

    if "show running-config" in out:
        out = out.split("show running-config", 1)[1].strip()
    return out


def main():
    parser = argparse.ArgumentParser(description="Cisco Config Collector Helper")
    parser.add_argument("--mode", choices=["telnet", "jump_ssh"], required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--bastion-host")
    parser.add_argument("--bastion-port", type=int, default=22)
    parser.add_argument("--bastion-user")
    parser.add_argument("--bastion-password")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    try:
        if args.mode == "telnet":
            config = collect_telnet(args.host, args.port, args.user, args.password, timeout=args.timeout)
        elif args.mode == "jump_ssh":
            if not args.bastion_host or not args.bastion_user or not args.bastion_password:
                sys.stderr.write("Error: bastion parameters required for jump_ssh mode\n")
                sys.exit(1)
            config = collect_jump_ssh(
                args.bastion_host, args.bastion_port, args.bastion_user, args.bastion_password,
                args.host, args.user, args.password, timeout=args.timeout
            )
        else:
            sys.stderr.write(f"Unknown mode: {args.mode}\n")
            sys.exit(1)

        if not config or ("Building configuration" not in config and "Current configuration" not in config):
            sys.stderr.write("Error: collected output does not look like a valid running-config\n")
            sys.exit(2)

        sys.stdout.write(config)
        sys.exit(0)
    except Exception as e:
        sys.stderr.write(f"Error during collection: {e}\n")
        sys.exit(3)


if __name__ == "__main__":
    main()
