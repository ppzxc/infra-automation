"""경유(via) 체인을 ssh ProxyCommand로 만드는 필터 (Spec #511 / Ticket-12, #523).

입력 `hops`는 `lookup('openbao_connection', ...).via`다(컨트롤러에서 가까운 경유지가 먼저). `key_files`는 hop과 같은 순서의
개인키 임시 파일 경로다. 경유지는 키 로그인(identity 또는 ssh_key Credential)만 지원한다. 비밀번호로만 들어가는 경유지는
명령행에 비밀번호를 남기지 않기 위해 거부한다.
"""
import re
import shlex

from ansible.errors import AnsibleFilterError

# ConnectTimeout: 응답 없는 경유지에서 시스템 기본(약 2분)씩 멈추지 않게 한다(관리 연결 프로브와 같은 5초).
_FIXED = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
          "-o", "IdentitiesOnly=yes"]


DEFAULT_PYTHON = "/usr/bin/python3"
_PYTHON_PATH = re.compile(r"/[A-Za-z0-9._+/-]+")


def python_interpreter_problem(value):
    """원격 Python 경로가 안 되는 이유(맞으면 None). 컨트롤러(Semaphore)의 venv 경로가 원격으로 새는 사고를 막는 규칙이다:
    절대 경로여야 하고(그래서 `auto_silent` 같은 값도 걸러진다) `venv`·`semaphore`(대소문자 무시)가 들어가거나 `/tmp/` 아래이면 안 된다."""
    if not isinstance(value, str) or not _PYTHON_PATH.fullmatch(value) or ".." in value.split("/"):
        return "절대 경로(영숫자·._+-/)여야 합니다"
    lowered = value.lower()
    if "semaphore" in lowered or "venv" in lowered or lowered.startswith("/tmp/"):
        return "컨트롤러의 venv·semaphore·임시 경로는 원격 호스트에서 쓸 수 없습니다"
    return None


def openbao_python_interpreter(value):
    """Asset 문서 `access.python_interpreter`(선택)를 원격 Python 경로로. 비면 기본 /usr/bin/python3, 잘못된 값은 실패한다."""
    if value in (None, ""):
        return DEFAULT_PYTHON
    problem = python_interpreter_problem(value)
    if problem:
        raise AnsibleFilterError("access.python_interpreter가 올바르지 않습니다: %s" % problem)
    return value


def openbao_ssh_proxy_command(hops, key_files, host, port):
    if not hops:
        raise AnsibleFilterError("ProxyCommand에는 경유지가 하나 이상 필요합니다(경유지 없는 연결은 직접 접속입니다)")
    if len(hops) != len(key_files):
        raise AnsibleFilterError("경유지 수와 키 파일 수가 다릅니다")

    def reach(n, target_host, target_port):
        hop, key = hops[n - 1], key_files[n - 1]
        login = hop["login"]
        if login.get("mode") not in ("identity", "key") or not key:
            raise AnsibleFilterError("경유지 %s/%s는 키 로그인만 지원합니다(비밀번호 경유지는 쓸 수 없습니다)"
                                     % (hop["asset"], hop["endpoint"]))
        parts = ["ssh", "-W", "%s:%s" % (target_host, target_port)] + _FIXED + [
            "-i", key, "-p", str(hop["port"]), "%s@%s" % (login["username"], hop["address"])]
        if n > 1:
            parts += ["-o", "ProxyCommand=" + reach(n - 1, hop["address"], hop["port"])]
        return shlex.join(parts)

    return reach(len(hops), host, port)


def openbao_ssh_common_args(hops, key_files, host, port):
    if not hops:
        return ""
    return "-o " + shlex.quote("ProxyCommand=" + openbao_ssh_proxy_command(hops, key_files, host, port))


def openbao_connection_summary(conn):
    """`openbao_connection` 결과에서 비밀을 뺀 요약(로그·팩트로 공개해도 되는 값만)."""
    login = conn["login"]
    out = {"asset": conn["asset"], "endpoint": conn["endpoint"], "protocol": conn["protocol"],
           "address": conn["address"], "port": conn["port"], "credential": conn["credential"],
           "login_mode": login["mode"], "username": login.get("username", ""),
           "become_method": (conn.get("become") or {}).get("method", ""),
           "password_auth_exception": conn["password_auth_exception"],
           "via": [dict({k: hop[k] for k in ("asset", "endpoint", "protocol", "address", "port", "credential")},
                        login_mode=hop["login"]["mode"]) for hop in conn["via"]]}
    return out


class FilterModule:
    def filters(self):
        return {"openbao_ssh_proxy_command": openbao_ssh_proxy_command,
                "openbao_ssh_common_args": openbao_ssh_common_args,
                "openbao_connection_summary": openbao_connection_summary,
                "openbao_python_interpreter": openbao_python_interpreter}
