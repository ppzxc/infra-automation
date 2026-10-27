"""security 역할 템플릿(auditd 규칙·fail2ban jail·journald 드롭인)을 한 번에 렌더링하는 공유 helper(Spec #364 / #372).

실제 `ansible.builtin.template` 모듈로 렌더링한다(trim_blocks 같은 ansible 기본값이 그대로 적용된다).
케이스(`CASES`)마다 변수를 다르게 줘서 한 번의 `ansible-playbook` 실행으로 모두 만든다.
#371(sshd 접근 제어)도 같은 템플릿·케이스 표를 쓰고, `shared_render()`로 프로세스당 한 번만 렌더링한다(ADR-0013).
"""
import os
import subprocess
import tempfile
from pathlib import Path

import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT_DIR / "roles" / "security" / "templates"
RENDER_LOG_ENV = "SECURITY_RENDER_LOG"  # 설정하면 렌더링마다 한 줄을 덧붙인다(세션당 한 번인지 확인하는 용도)

# 렌더링할 템플릿: 출력 이름 -> 템플릿 파일
TEMPLATE_FILES = {
    "audit": "audit.rules.j2",
    "fail2ban": "fail2ban-sshd.local.j2",
    "journald": "journald-persistent.conf.j2",
    "sshd_source": "sshd-source-restriction.conf.j2",
}

# 케이스 이름 -> 변수. 가짜 경로만 쓴다(실서버 값 아님).
CASES = {
    "default": {},
    # 명시 옵션으로만 dummy를 쓴다(기본값은 빈 값)
    "unmanaged_firewall": {"fail2ban_banaction": "dummy"},
    "managed_firewall": {"fail2ban_banaction": ""},
    "secret_paths": {
        "audit_watch_paths": ["/srv/example/app.secrets.env", "/srv/example/other.key"],
        "audit_container_config_paths": ["/etc/docker/", "/srv/example/compose/"],
    },
    # #371: 가짜 문서용 주소(RFC 5737, RFC 3849)만 쓴다.
    "ssh_source_two": {"ssh_source_restriction_allowed_sources": ["192.0.2.0/24", "198.51.100.7/32"]},
    "ssh_source_v6": {"ssh_source_restriction_allowed_sources": ["2001:db8::/32"]},
}


def render_security(workdir):
    """모든 케이스를 렌더링해 `{케이스: {출력이름: 텍스트}}`를 돌려준다."""
    workdir = Path(workdir)
    templates, cases = TEMPLATE_FILES, CASES
    tasks = []
    for case, variables in cases.items():
        for out, src in templates.items():
            tasks.append({
                "name": f"render {case} {out}",
                "ansible.builtin.template": {"src": str(TEMPLATES / src), "dest": str(workdir / f"{case}.{out}"), "mode": "0600"},
                "vars": variables,
            })
    play = [{"hosts": "localhost", "connection": "local", "gather_facts": False, "become": False, "tasks": tasks}]
    playbook = workdir / "render.yml"
    playbook.write_text(yaml.safe_dump(play), encoding="utf-8")
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(playbook)], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300, env=dict(os.environ, ANSIBLE_NOCOLOR="1"))
    assert res.returncode == 0, res.stdout + res.stderr
    if os.environ.get(RENDER_LOG_ENV):
        with open(os.environ[RENDER_LOG_ENV], "a", encoding="utf-8") as fh:
            fh.write(f"{os.getpid()}\n")
    return {case: {out: (workdir / f"{case}.{out}").read_text(encoding="utf-8") for out in templates} for case in cases}


_SHARED = {}


def shared_render():
    """프로세스(xdist 워커)당 한 번만 렌더링하고 결과를 공유한다. 여러 테스트 모듈이 같은 결과를 읽는다."""
    if "result" not in _SHARED:
        _SHARED["result"] = render_security(Path(tempfile.mkdtemp(prefix="security-render-")))
    return _SHARED["result"]


def rule_lines(text):
    """주석·빈 줄을 뺀 감사 규칙 줄."""
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def flat_tasks(tasks):
    """block/rescue/always 안까지 펼친 태스크."""
    for t in tasks:
        yield t
        for key in ("block", "rescue", "always"):
            if key in t:
                yield from flat_tasks(t[key])


def security_tasks():
    """security 역할 tasks/main.yml의 태스크(블록 안 포함)."""
    return list(flat_tasks(yaml.safe_load((ROOT_DIR / "roles" / "security" / "tasks" / "main.yml").read_text(encoding="utf-8"))))


def security_task(spec_id):
    """`[SPEC-ID]`로 시작하는 태스크 하나."""
    found = [t for t in security_tasks() if t.get("name", "").startswith(f"[{spec_id}]")]
    assert len(found) == 1, spec_id
    return found[0]
