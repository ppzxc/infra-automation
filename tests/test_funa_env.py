"""funa_env 역할(#222): 가짜 OpenBao HTTP 서버 + ansible-playbook으로 파일 렌더링을 실제 실행한다.

root가 아니므로 소유자는 현재 사용자로 바꿔 돌리고(`funa_env_owner*`), 기본값이 root:dockermgmt·0644/0640인지는
기본값 파일로 따로 검증한다.
"""
import getpass
import grp
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from openbao_fake import FakeOpenBao, default_store
import openbao_migrate as om
import openbao_validation as ov

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "filter_plugins"))

ROOT_DIR = Path(__file__).resolve().parent.parent
ROLE = ROOT_DIR / "roles" / "funa_env"
USER_GROUP = grp.getgrgid(os.getgid()).gr_name

NODE = {"node_external_hostname": "n1.funa.test", "node_external_wildcard_hostname": "*.n1.funa.test",
        "notification_header": "[FUNA n1] alert", "node_name": "n1"}
CLUSTER = {"floating_hostname": "vip.funa.test", "health_check_uri": "/health", "service_name": "funa",
           "tz": "Asia/Seoul",
           "notification_smtp_from": "a@funa.test", "notification_smtp_host": "smtp.funa.test",
           "notification_smtp_port": 25, "notification_smtp_to": "b@funa.test",
           "notification_smtp_username": "user", "notification_naver_works_bot_url": "https://bot.funa.test/x"}
PROXY = {"admin_token": "admin-token-SECRET", "db_password": "db-pass-SECRET"}
VRRP = {"notification_smtp_password": "smtp-pass-SECRET", "notification_naver_works_bot_token": "bot-token-SECRET"}
CF = {"type": "api_token", "token": "cf-token-SECRET"}
SSH = {"type": "password", "username": "root", "password": "ssh-pass-SECRET"}
SECRETS = [v for d in (PROXY, VRRP) for v in d.values()] + ["ssh-pass-SECRET", "cf-token-SECRET"]
# 저장 키 -> env 이름(렌더링 결과 확인용. 역할의 대응표와 따로 손으로 적은 기대값이다)
ENV = {"node_external_hostname": "FUNA_NODE_EXTERNAL_HOSTNAME", "tz": "TZ", "db_password": "DB_PASSWORD",
       "node_name": "FUNA_NODE_NAME", "admin_token": "FUNA_ADMIN_TOKEN"}
CLUSTER_DOC = "inventory/services/funa"


def _vars():
    return yaml.safe_load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8"))


def _asset(funa=NODE):
    return {"description": "Fake FUNA node", "type": "server", "funa": funa}


@pytest.fixture
def bao():
    with FakeOpenBao.with_schemas(store={}, namespace="infra", token="tok") as f:
        f.set("inventory", "assets/n1", _asset())
        f.set("inventory", "services/funa", CLUSTER)
        f.set("secrets", "services/funa/proxy", PROXY)
        f.set("secrets", "services/funa/vrrp", VRRP)
        f.set("secrets", "assets/n1/credentials/cloudflare", CF)
        f.set("secrets", "assets/n1/credentials/root", SSH)
        yield f


@pytest.fixture
def openbao(bao):
    return bao.url


def run(tmp_path, addr, hosts=("n1",), groups=("funa_cluster",), check=False, extra=None, diff=True):
    dest = tmp_path / "etc"
    prof = tmp_path / "profile.d"
    prof.mkdir(exist_ok=True)
    units = tmp_path / "systemd"
    units.mkdir(exist_ok=True)
    (tmp_path / "play.yml").write_text(yaml.safe_dump([{
        "hosts": "all", "gather_facts": False, "become": False, "roles": ["funa_env"]}]))
    inv = {"all": {
        "hosts": {h: {"_vault_token": "tok"} for h in hosts},
        "vars": {"ansible_connection": "local", "ansible_python_interpreter": "/usr/bin/python3", "vault_addr": addr,
                 "funa_env_dir": str(dest / "funa-cluster"), "funa_env_profile_dir": str(prof),
                 "funa_env_owner": getpass.getuser(),
                 "funa_env_owner_group": USER_GROUP, "funa_env_group": USER_GROUP,
                 "funa_env_systemd_dir": str(units), "funa_env_systemd_manage": False},
        "children": {g: {"hosts": {h: {} for h in hosts if h == "n1"}} for g in groups},
    }}
    for k, v in (extra or {}).items():
        inv["all"]["vars"][k] = v
    (tmp_path / "inv.yml").write_text(yaml.safe_dump(inv))
    cmd = ["ansible-playbook", "-i", str(tmp_path / "inv.yml"), str(tmp_path / "play.yml")]
    if diff:
        cmd.append("--diff")
    if check:
        cmd.append("--check")
    res = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=180, cwd=ROOT_DIR,
                         env={**os.environ, "ANSIBLE_NOCOLOR": "1", "ANSIBLE_ROLES_PATH": str(ROOT_DIR / "roles"),
                              "ANSIBLE_FILTER_PLUGINS": str(ROOT_DIR / "filter_plugins"),
                              "ANSIBLE_LOOKUP_PLUGINS": str(ROOT_DIR / "lookup_plugins"),
                              "ANSIBLE_LOCALHOST_WARNING": "False", "ANSIBLE_DEPRECATION_WARNINGS": "False"})
    return res, dest / "funa-cluster", prof


pytestmark = pytest.mark.skipif(shutil.which("ansible-playbook") is None, reason="ansible-playbook not installed")


def _mode(p):
    return stat.S_IMODE(p.stat().st_mode)


def _kv_of(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if line and not line.startswith("#"))


def test_renders_files_with_modes_and_consumer_separation(tmp_path, openbao):
    res, d, prof = run(tmp_path, openbao)
    assert res.returncode == 0, res.stdout + res.stderr
    cluster, proxy, vrrp = (d / "cluster.env", d / "proxy.secrets.env", d / "vrrp.secrets.env")
    assert _mode(cluster) == 0o644 and _mode(proxy) == 0o640 and _mode(vrrp) == 0o640
    assert grp.getgrgid(proxy.stat().st_gid).gr_name == USER_GROUP
    kv = _kv_of(cluster)
    assert kv[ENV["node_external_hostname"]] == "n1.funa.test" and kv[ENV["tz"]] == "Asia/Seoul"
    assert kv["FUNA_NODE_EXTERNAL_WILDCARD_HOSTNAME"] == "'*.n1.funa.test'"
    # 알림 헤더는 노드의 호스트명이 들어가므로 Asset 문서의 funa 절에서 온다(클러스터 공통 설정에는 없다).
    assert kv["FUNA_NOTIFICATION_HEADER"] == "'[FUNA n1] alert'"
    # funa 로그의 service.node.name 이 기본값 local 로 남지 않도록 노드 이름도 Asset funa 절에서 온다(funa#337).
    assert kv["FUNA_NODE_NAME"] == "n1"
    # 소비자별 분리: proxy 파일에는 keepalived 시크릿이 없고 그 반대도 같다
    assert set(_kv_of(proxy)) == {"FUNA_ADMIN_TOKEN", "DB_PASSWORD", "CLOUDFLARE_API_TOKEN"}
    assert set(_kv_of(vrrp)) == {"FUNA_NOTIFICATION_SMTP_PASSWORD", "FUNA_NOTIFICATION_NAVER_WORKS_BOT_TOKEN"}
    assert _kv_of(proxy)["CLOUDFLARE_API_TOKEN"] == "cf-token-SECRET"
    assert not any(v in proxy.read_text() for v in VRRP.values())
    assert not any(v in vrrp.read_text() for v in PROXY.values())
    assert not any(s in cluster.read_text() for s in SECRETS)
    loader = prof / "funa-cluster.sh"
    assert _mode(loader) == 0o644 and "set -a" in loader.read_text() and not re.search(r"^\s*alias\b", loader.read_text(), re.M)


def test_no_secret_in_output_or_diff(tmp_path, openbao):
    res, _, _ = run(tmp_path, openbao)
    out = res.stdout + res.stderr
    assert res.returncode == 0
    assert not any(s in out for s in SECRETS), "시크릿 값이 출력에 나왔다"


def test_second_run_changes_nothing(tmp_path, openbao):
    assert run(tmp_path, openbao)[0].returncode == 0
    res, _, _ = run(tmp_path, openbao)
    assert res.returncode == 0, res.stdout
    assert re.search(r"n1\s*:.*changed=0", res.stdout), res.stdout


def _unsafe_vrrp_dir(tmp_path):
    """keepalived가 스크립트를 비활성화하는 상태: 디렉터리 SGID·그룹 쓰기, 스크립트 그룹 쓰기(infra-automation#314)."""
    d = tmp_path / "vrrp" / "config"
    d.mkdir(parents=True)
    d.chmod(0o2775)
    for name, mode in (("check.sh", 0o775), ("notify.sh", 0o775), ("keepalived.conf", 0o664), ("note.txt", 0o666)):
        f = d / name
        f.write_text("x\n")
        f.chmod(mode)
    return d


def test_keepalived_config_is_kept_root_only_for_script_security(tmp_path, openbao):
    d = _unsafe_vrrp_dir(tmp_path)
    res, _, _ = run(tmp_path, openbao, extra={"funa_env_vrrp_config_dir": str(d)})
    assert res.returncode == 0, res.stdout + res.stderr
    assert _mode(d) == 0o755, oct(_mode(d))
    assert _mode(d / "check.sh") == 0o755 and _mode(d / "notify.sh") == 0o755
    assert _mode(d / "keepalived.conf") == 0o644
    # 스크립트·설정이 아닌 파일은 건드리지 않는다.
    assert _mode(d / "note.txt") == 0o666


def test_keepalived_config_permissions_are_idempotent(tmp_path, openbao):
    d = _unsafe_vrrp_dir(tmp_path)
    run(tmp_path, openbao, extra={"funa_env_vrrp_config_dir": str(d)})
    res, _, _ = run(tmp_path, openbao, extra={"funa_env_vrrp_config_dir": str(d)})
    assert re.search(r"n1\s*:.*changed=0", res.stdout), res.stdout


def test_missing_keepalived_config_directory_is_ignored(tmp_path, openbao):
    d = tmp_path / "no-such" / "config"
    res, _, _ = run(tmp_path, openbao, extra={"funa_env_vrrp_config_dir": str(d)})
    assert res.returncode == 0, res.stdout + res.stderr
    assert not d.exists()


def test_keepalived_config_of_a_host_outside_the_group_is_untouched(tmp_path, openbao):
    d = _unsafe_vrrp_dir(tmp_path)
    res, _, _ = run(tmp_path, openbao, groups=(), extra={"funa_env_vrrp_config_dir": str(d)})
    assert res.returncode == 0, res.stdout + res.stderr
    assert _mode(d) == 0o2775 and _mode(d / "check.sh") == 0o775


def test_login_shell_loader_loads_readable_files_only(tmp_path, openbao):
    _, d, prof = run(tmp_path, openbao)
    (d / "vrrp.secrets.env").chmod(0o000)
    script = f'. {prof}/funa-cluster.sh; echo "$TZ|$DB_PASSWORD|$FUNA_NOTIFICATION_NAVER_WORKS_BOT_TOKEN"'
    out = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
    (d / "vrrp.secrets.env").chmod(0o640)
    tz, db, bot = out.stdout.strip().split("|")
    assert (tz, db, bot) == ("Asia/Seoul", "db-pass-SECRET", "")


def test_host_outside_the_group_gets_nothing(tmp_path, openbao):
    res, d, prof = run(tmp_path, openbao, groups=("other",))
    assert res.returncode == 0, res.stdout
    assert not d.exists() and list(prof.iterdir()) == []


def _without(data, key):
    return {k: v for k, v in data.items() if k != key}


# (마운트, 문서, 덮어쓸 데이터 — None이면 문서를 지워 404, 기대 메시지)
@pytest.mark.parametrize("mount, doc, data, expect", [
    ("secrets", "services/funa/proxy", _without(PROXY, "db_password"), "secrets/services/funa/proxy 문서에 필수 키가 없습니다 — db_password"),
    ("inventory", "services/funa", _without(CLUSTER, "tz"), "inventory/services/funa 문서에 필수 키가 없습니다 — tz"),
    ("secrets", "assets/n1/credentials/cloudflare", {"type": "api_token"}, "secrets/assets/+/credentials/+ 문서에 필수 키가 없습니다 — token"),
    ("inventory", "assets/n1", {"description": "Fake", "type": "server"}, "inventory/assets/+ 문서에 필수 키가 없습니다 — funa"),
    ("inventory", "assets/n1", _asset(_without(NODE, "node_name")), "inventory/assets/n1: required key funa.node_name is missing"),
])
def test_missing_values_fail_naming_what_is_missing(tmp_path, bao, mount, doc, data, expect):
    bao.schema_check = None   # 스키마를 어긴 문서도 서버에 둬서 역할의 검증이 막는지 본다
    bao.set(mount, doc, data)
    res, d, _ = run(tmp_path, bao.url)
    out = res.stdout + res.stderr
    assert res.returncode != 0
    assert expect in out
    assert not any(s in out for s in SECRETS)
    assert not (d / "cluster.env").exists()


@pytest.mark.parametrize("mount, doc", [("secrets", "services/funa/vrrp"), ("secrets", "assets/n1/credentials/cloudflare")])
def test_missing_document_stops_without_changes_naming_the_document(tmp_path, bao, mount, doc):
    bao.remove(mount, doc)
    res, d, _ = run(tmp_path, bao.url)
    assert res.returncode != 0 and "필수 문서가 없습니다: %s/%s" % (mount, doc) in res.stdout
    assert not d.exists()


def test_unmapped_stored_key_fails_naming_it_without_the_value(tmp_path, bao):
    bao.schema_check = None
    bao.set("inventory", "services/funa", {**CLUSTER, "surprise": "surprise-value-SECRET"})
    res, d, _ = run(tmp_path, bao.url)
    out = res.stdout + res.stderr
    assert res.returncode != 0 and "surprise has no environment variable mapping" in out
    assert "surprise-value-SECRET" not in out and not (d / "cluster.env").exists()


def test_openbao_error_stops_without_changes(tmp_path, bao):
    bao.deny("inventory", "services/funa")
    res, d, _ = run(tmp_path, bao.url)
    assert res.returncode != 0 and "OpenBao 조회 실패: inventory/services/funa (HTTP 403)" in res.stdout
    assert not d.exists()


def _pattern_regex(pattern):
    return re.compile("^" + re.escape(pattern).replace(r"\+", "[^/]+") + "$")


def test_every_read_stays_inside_the_declared_patterns_and_the_infra_namespace(tmp_path, bao):
    res, _, _ = run(tmp_path, bao.url)
    assert res.returncode == 0, res.stdout + res.stderr
    declared = [_pattern_regex(p) for p in _vars()["funa_env_openbao_required"]]
    reads = bao.reads()
    assert reads and not bao.violations
    for r in reads:
        assert r.namespace == "infra" and r.token == "tok"
        assert any(rx.match(f"{r.mount}/{r.doc}") for rx in declared), r.path
    # 선언한 문서는 하나도 빠짐없이 읽는다
    assert {f"{r.mount}/{r.doc}" for r in reads} == {
        "inventory/assets/n1", "inventory/services/funa", "secrets/services/funa/proxy", "secrets/services/funa/vrrp",
        "secrets/assets/n1/credentials/cloudflare"}


def test_missing_dockermgmt_group_fails_naming_it(tmp_path, openbao):
    res, d, _ = run(tmp_path, openbao, extra={"funa_env_group": "no-such-group-xyz"})
    assert res.returncode != 0
    assert "no-such-group-xyz" in res.stdout and "docker_engine" in res.stdout
    assert not d.exists()


# --- 대응표·선언과 스키마의 일치(정적) -----------------------------------------------------------------------------
SCHEMAS = ROOT_DIR / "schemas" / "openbao"


def _schema(rel):
    return json.loads((SCHEMAS / rel).read_text(encoding="utf-8"))


def _stored_keys_in_schemas():
    asset = _schema("inventory/asset.schema.json")["properties"]["funa"]
    docs = {"asset funa": asset, "service": _schema("inventory/service_funa.schema.json"),
            "proxy": _schema("secrets/services/funa_proxy.schema.json"),
            "vrrp": _schema("secrets/services/funa_vrrp.schema.json")}
    return docs, set().union(*(set(d["properties"]) for d in docs.values()))


def test_key_map_covers_exactly_the_schema_keys_and_follows_the_migration_rule():
    key_map = _vars()["funa_env_key_map"]
    docs, keys = _stored_keys_in_schemas()
    assert set(key_map) == keys
    # 마이그레이션(#521)이 저장 키를 만드는 규칙의 역: env 이름에서 규칙을 적용하면 저장 키가 나온다
    for key, env in key_map.items():
        assert om._env_to_key(env) == key, (key, env)
    assert len(set(key_map.values())) == len(key_map)
    for d in docs.values():
        assert d["additionalProperties"] is False


def test_secret_and_non_secret_documents_share_no_key_and_filter_patterns_match_the_declaration():
    docs, _ = _stored_keys_in_schemas()
    names = list(docs)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            assert not set(docs[a]["properties"]) & set(docs[b]["properties"]), (a, b)
    import funa_env
    assert {funa_env.ASSET, funa_env.CLUSTER, funa_env.PROXY, funa_env.VRRP, funa_env.CREDENTIAL} == set(_vars()["funa_env_openbao_required"])


def test_declared_required_keys_match_the_schemas():
    v = _vars()
    declared = v["funa_env_openbao_required"]
    index = dict(ov.load_index(SCHEMAS))
    for pattern in ("inventory/services/funa", "secrets/services/funa/proxy", "secrets/services/funa/vrrp"):
        assert set(declared[pattern]) == set(_schema(index[pattern])["required"]), pattern
    for pattern in declared:
        assert pattern in index, pattern   # 선언한 패턴은 index.yml에 있다
    asset = _schema(index["inventory/assets/+"])["properties"]
    assert declared["inventory/assets/+"] == ["funa"] and "funa" in asset
    assert set(v["funa_env_node_required"]) == set(asset["funa"]["required"])
    api_token = [b for b in _schema(index["secrets/assets/+/credentials/+"])["oneOf"] if b["properties"]["type"]["const"] == "api_token"]
    assert set(declared["secrets/assets/+/credentials/+"]) <= set(api_token[0]["required"])


def test_the_cloudflare_token_is_the_node_credential_not_a_service_secret():
    v = _vars()
    assert v["funa_env_credential"] == "cloudflare" and v["funa_env_credential_env"] == "CLOUDFLARE_API_TOKEN"
    _, keys = _stored_keys_in_schemas()
    assert not any("cloudflare" in k for k in keys) and "CLOUDFLARE_API_TOKEN" not in v["funa_env_key_map"].values()
    assert "cloudflare_api_token" not in default_store()["secrets/services/funa/proxy"]
    assert default_store()["secrets/assets/ns0002/credentials/cloudflare"]["type"] == "api_token"


def test_the_assert_walks_the_declaration_and_old_knobs_are_gone():
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))[0]["block"]
    by_id = {re.match(r"\[(FUNA-\d+)", t["name"]).group(1): t for t in tasks if re.match(r"\[FUNA-\d+\]", t["name"])}
    assert "FUNA-004" not in by_id
    assert "funa_env_openbao_required" in by_id["FUNA-017"]["loop"] and by_id["FUNA-017"]["ansible.builtin.assert"]
    assert by_id["FUNA-003"]["no_log"] is True and "openbao_doc" in str(by_id["FUNA-003"])
    text = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8") + (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8")
    for retired in ("kv_fixture", "X-Vault", "VAULT_NAMESPACE", "OPENBAO_", "_vault_token", "funa_env_cluster_path", "funa_env_host_path",
                    "funa_env_node_keys", "funa_env_node_secret_keys", "funa_env_validate_certs", "ansible.builtin.uri"):
        assert retired not in text, retired


def test_defaults_match_the_standard():
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert defaults["funa_env_dir"] == "/etc/funa-cluster"
    assert defaults["funa_env_owner"] == "root" and defaults["funa_env_owner_group"] == "root"
    assert "dockermgmt" in defaults["funa_env_group"]
    tasks = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "mode: '0640'" in tasks and "mode: '0644'" in tasks


def test_secret_tasks_use_no_log_and_no_diff():
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))[0]["block"]
    by_id = {re.match(r"\[(FUNA-\d+)", t["name"]).group(1): t for t in tasks if t["name"].startswith("[FUNA-0")
             and "-FACT" not in t["name"]}
    for tid in ("FUNA-003", "FUNA-005", "FUNA-009"):
        assert by_id[tid].get("no_log") is True, tid
    assert by_id["FUNA-009"].get("diff") is False


def test_site_runs_funa_env_after_docker_engine():
    play = yaml.safe_load((ROOT_DIR / "playbooks" / "site.yml").read_text(encoding="utf-8"))[1]
    roles = [r["role"] for r in play["roles"]]
    assert roles.index("funa_env") == roles.index("docker_engine") + 1


# --- keepalived 컨테이너 부팅 뒤 기동 보장(#443) -----------------------------------------------------------------
UNIT = "funa-vrrp-ensure.service"


def _unit_exec_start(unit_path):
    lines = [ln for ln in unit_path.read_text().splitlines() if ln.startswith("ExecStart=")]
    assert len(lines) == 1, lines
    return lines[0].removeprefix("ExecStart=")


def test_ensure_unit_runs_once_after_docker_and_is_root_owned(tmp_path, openbao):
    res, _, _ = run(tmp_path, openbao)
    assert res.returncode == 0, res.stdout + res.stderr
    unit = tmp_path / "systemd" / UNIT
    text = unit.read_text()
    assert "After=docker.service" in text and "Requires=docker.service" in text
    # dockerd가 부팅 뒤 다시 시작돼도 이 유닛이 다시 실행되도록 active를 유지하고 docker에 묶는다.
    assert "PartOf=docker.service" in text and "RemainAfterExit=yes" in text
    assert "Type=oneshot" in text and "WantedBy=multi-user.target" in text
    assert "vrrp-keepalived-1" in text
    assert _mode(unit) == 0o644


def test_ensure_unit_is_idempotent(tmp_path, openbao):
    run(tmp_path, openbao)
    res, _, _ = run(tmp_path, openbao)
    assert re.search(r"n1\s*:.*changed=0", res.stdout), res.stdout


def test_ensure_unit_container_name_is_a_variable(tmp_path, openbao):
    run(tmp_path, openbao, extra={"funa_env_vrrp_container": "other-name-1"})
    assert "other-name-1" in (tmp_path / "systemd" / UNIT).read_text()


def test_ensure_unit_of_a_host_outside_the_group_is_not_created(tmp_path, openbao):
    res, _, _ = run(tmp_path, openbao, groups=())
    assert res.returncode == 0, res.stdout + res.stderr
    assert not (tmp_path / "systemd" / UNIT).exists()


def _fake_docker(tmp_path, state):
    """state: absent | stopped | running. docker 호출을 calls.log에 남기는 가짜 docker."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "calls.log"
    log.write_text("")
    (bin_dir / "docker").write_text(f"""#!/bin/sh
echo "$@" >> {log}
case "$1" in
  inspect)
    [ "{state}" = absent ] && exit 1
    case "$*" in *State.Running*) [ "{state}" = running ] && echo true || echo false;; esac
    exit 0;;
  start) exit 0;;
esac
exit 0
""")
    (bin_dir / "docker").chmod(0o755)
    return bin_dir, log


@pytest.mark.parametrize("state,starts", [("stopped", True), ("running", False), ("absent", False)])
def test_ensure_unit_starts_only_a_stopped_existing_container(tmp_path, openbao, state, starts):
    run(tmp_path, openbao)
    cmd = _unit_exec_start(tmp_path / "systemd" / UNIT)
    bin_dir, log = _fake_docker(tmp_path, state)
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30,
                         env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"})
    assert res.returncode == 0, res.stdout + res.stderr
    started = any(ln.startswith("start ") for ln in log.read_text().splitlines())
    assert started is starts, log.read_text()


def test_check_mode_skips_enabling_a_unit_that_does_not_exist_yet(tmp_path, openbao):
    # 체크 모드에서는 유닛 파일이 아직 없어 systemd 모듈이 "서비스를 찾을 수 없음"으로 실패한다(#443, 서버 체크 실행에서 발견).
    res, _, _ = run(tmp_path, openbao, check=True, extra={"funa_env_systemd_manage": True})
    assert res.returncode == 0, res.stdout + res.stderr
    assert not (tmp_path / "systemd" / UNIT).exists()
    assert re.search(r"TASK \[funa_env : \[FUNA-016\][^\n]*\n(?:[^\n]*\n){0,2}?skipping: \[n1\]", res.stdout), res.stdout
