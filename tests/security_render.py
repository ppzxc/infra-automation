"""security 역할 템플릿(auditd 규칙·fail2ban jail·journald 드롭인)을 한 번에 렌더링하는 공유 helper(Spec #364 / #372).

실제 `ansible.builtin.template` 모듈로 렌더링한다(trim_blocks 같은 ansible 기본값이 그대로 적용된다).
케이스(`CASES`)마다 변수를 다르게 줘서 한 번의 `ansible-playbook` 실행으로 모두 만든다.
#371(sshd 접근 제어)도 이 helper에 템플릿·케이스를 추가해 같은 session fixture를 재사용한다.
"""
import os
import subprocess
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
}

# 케이스 이름 -> 변수. 가짜 경로만 쓴다(실서버 값 아님).
CASES = {
    "default": {},
    "unmanaged_firewall": {"fail2ban_banaction": "dummy"},
    "managed_firewall": {"fail2ban_banaction": ""},
    "secret_paths": {
        "audit_watch_paths": ["/srv/example/app.secrets.env", "/srv/example/other.key"],
        "audit_container_config_paths": ["/etc/docker/", "/srv/example/compose/"],
    },
}


def render_security(workdir, *, extra_templates=None, extra_cases=None):
    """모든 케이스를 렌더링해 `{케이스: {출력이름: 텍스트}}`를 돌려준다. `extra_*`는 다른 티켓이 케이스·템플릿을 덧붙일 때 쓴다."""
    workdir = Path(workdir)
    templates = {**TEMPLATE_FILES, **(extra_templates or {})}
    cases = {**CASES, **(extra_cases or {})}
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


def rule_lines(text):
    """주석·빈 줄을 뺀 감사 규칙 줄."""
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
