"""Audit Watch Key 3개(`auth_config`·`container_config`·`secret_access`)의 알림과 정상 변경 구분(Spec #419, ADR-0013).

알림 정의(SQL·등급·재통지)를 렌더링 결과에서 읽고, 합성 audit 행에 렌더링된 SQL을 돌려 울리는지·안 울리는지를 본다.
합성 행은 실제 로그의 모양을 따른다: SYSCALL 행에는 파일 경로가 없고 같은 시리얼의 `type=PATH` 행에 있으며,
해석된 필드는 `\\x1d`로 이어 붙는다(`key="x"\\x1dARCH=…`). 값은 모두 가짜다.
"""
import re
import sys

import pytest

from o2c_render import ROOT_DIR, render_desired
from o2c_alert_helpers import (DEFAULTS, EXPECTED_ALERTS, FIXTURES, LONGEST_ROW_VALUES, RUNBOOK, _rendered_message, _row_lines,
                               _run_alert_on_sqlite, _sql)

sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

pytestmark = pytest.mark.xdist_group("o2c-render")

AUTH, CONTAINER, SECRET, PROVISIONING = ("infra-audit-auth-config-change", "infra-audit-container-config-change",
                                         "infra-audit-secret-access", "infra-audit-watch-provisioning")
P2_ALERTS = (AUTH, CONTAINER, SECRET)
NEW_ALERTS = P2_ALERTS + (PROVISIONING,)
KEY_OF = {AUTH: "auth_config", CONTAINER: "container_config", SECRET: "secret_access"}
OLD_WATCH, ACCOUNT_CHANGE = "infra-audit-watch-change", "infra-account-change"


@pytest.fixture(scope="session")
def desired(tmp_path_factory):
    """기본 변수로 렌더링한 알림(`store["alert"][이름]`) — 공유 렌더링과 같은 방식이다."""
    rendered = render_desired(tmp_path_factory.mktemp("o2c-audit-watch") / "desired.json")

    class Server:
        store = {"alert": {o["name"]: o["body"] for o in rendered if o["kind"] == "alert"},
                 "template": {o["name"]: o["body"] for o in rendered if o["kind"] == "template"}}
        shorts = {o["short_link"]["short"].split("/web/short/")[1].split("?")[0]: o["short_link"]["original"] for o in rendered if o.get("short_link")}

    return Server


@pytest.fixture(scope="session")
def tuned(tmp_path_factory):
    """조정 변수를 모두 바꾼 렌더링: 재통지 간격·임계·P3 간격·정상 변경 키 목록(#430처럼 키를 더한 경우)."""
    rendered = render_desired(tmp_path_factory.mktemp("o2c-audit-tuned") / "desired.json", extra={
        "o2c_audit_watch_silence_minutes": 10, "o2c_audit_watch_min_events": 2, "o2c_audit_provisioning_silence_minutes": 30,
        "o2c_audit_provisioning_keys": ["auth_config", "container_config", "secret_access", "ssh_keys"]})

    class Server:
        store = {"alert": {o["name"]: o["body"] for o in rendered if o["kind"] == "alert"}}
        shorts = {o["short_link"]["short"].split("/web/short/")[1].split("?")[0]: o["short_link"]["original"] for o in rendered if o.get("short_link")}

    return Server


@pytest.fixture(scope="session")
def narrowed(tmp_path_factory):
    """정상 변경 구분을 지정 계정으로 좁힌 렌더링(`o2c_audit_provisioning_accounts`를 Environment로 준 것과 같다)."""
    rendered = render_desired(tmp_path_factory.mktemp("o2c-audit-narrow") / "desired.json",
                              extra={"o2c_audit_provisioning_accounts": ["deployer"]})

    class Server:
        store = {"alert": {o["name"]: o["body"] for o in rendered if o["kind"] == "alert"}}

    return Server


# --- 합성 audit 행 ------------------------------------------------------------------------------------------------------
_serial = iter(range(7000, 10**6))


def event(key, *, exe, path="/etc/pam.d/system-auth", auid="opsverify", auid_num=1002, tty="pts0", syscall="openat", host="ns0272",
          comm=None, nametype="NORMAL", uid=0):
    """한 audit 사건: SYSCALL 행 하나(`key` 포함, 경로 없음)와 같은 시리얼의 CWD·PATH 행들. 실제 줄처럼 해석 필드가 `\\x1d`로 이어 붙는다."""
    n = next(_serial)
    ts = f"1792985278.{n % 1000:03d}:{n}"
    comm = comm or exe.rsplit("/", 1)[-1][:15]
    sys_body = (f'type=SYSCALL msg=audit({ts}): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=55d0c8e0 a2=241 a3=1b6 items=1 '
                f'ppid=4000 pid=4100 auid={auid_num} uid={uid} gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty={tty} ses=313 '
                f'comm="{comm}" exe="{exe}" subj=kernel key="{key}"\x1dARCH=x86_64 SYSCALL={syscall} AUID="{auid}" UID="root" GID="root"')
    rows = [{"host_name": host, "service_name": "audit", "body": sys_body}]
    if path is not None:
        name = f'name="{path}"' if path != "(null)" else "name=(null)"
        rows.append({"host_name": host, "service_name": "audit",
                     "body": f'type=PATH msg=audit({ts}): item=0 {name} inode=1 dev=fd:00 mode=0100644 ouid=0 ogid=0 nametype={nametype} cap_fp=0'})
        rows.append({"host_name": host, "service_name": "audit", "body": f'type=PATH msg=audit({ts}): item=1 name="/etc/" inode=2 nametype=PARENT'})
        rows.append({"host_name": host, "service_name": "audit", "body": f'type=CWD msg=audit({ts}): cwd="/root"'})
    return rows


def fired(desired, name, *events):
    rows = _run_alert_on_sqlite(_sql(desired, name), [r for ev in events for r in ev], "security_logs")
    return rows


def firing_alerts(desired, *events, among=NEW_ALERTS):
    return {name for name in among if fired(desired, name, *events)}


# --- 1. 등록: 알림 정의·등급·재통지 -------------------------------------------------------------------------------------
@pytest.mark.parametrize("name, severity, silence", [(AUTH, "P2 경고", 5), (CONTAINER, "P2 경고", 5), (SECRET, "P2 경고", 5),
                                                      (PROVISIONING, "P3 주의", 5)])
def test_the_new_audit_watch_alerts_are_security_log_event_alerts_with_a_grade_a_silence_and_a_runbook_entry(desired, name, severity, silence):
    alert = desired.store["alert"][name]
    assert name in EXPECTED_ALERTS and alert["stream_name"] == "security_logs" and alert["query_condition"]["type"] == "sql"
    assert alert["context_attributes"]["severity"] == severity
    trigger = alert["trigger_condition"]
    assert (trigger["period"], trigger["frequency"], trigger["silence"], alert["pending_period_sec"]) == (5, 1, silence, 0)
    anchor = name.removeprefix("infra-")
    assert alert["context_attributes"]["runbook"].endswith("alerts.md#" + anchor)
    runbook = RUNBOOK.read_text(encoding="utf-8")
    spec = (ROOT_DIR / "docs" / "openobserve_config.md").read_text(encoding="utf-8")
    assert f'<a id="{anchor}"></a>' in runbook and f"(`{name}`)" in runbook and f"`{name}`" in spec


def test_every_new_alert_keeps_a_raw_log_link_to_the_audit_lines_of_its_keys(desired):
    """SQL이 서브쿼리·조인이라 WHERE에서 파생할 수 없어 `raw_sql`을 직접 둔다. 링크가 가리키는 조회를 렌더링 결과에서 읽는다."""
    for name in NEW_ALERTS:
        alert = desired.store["alert"][name]
        assert alert["context_attributes"]["raw_log_line"].startswith("▶ 로그 보기: "), name
    for name in P2_ALERTS:
        assert f'key="{KEY_OF[name]}"' in _raw_query(desired, name), name
    for key in KEY_OF.values():
        assert f'key="{key}"' in _raw_query(desired, PROVISIONING)


def _raw_query(server, name):
    from o2c_alert_helpers import _decode_raw_url
    original = server.shorts[re.search(r"/web/short/([0-9a-f]{16})", server.store["alert"][name]["context_attributes"]["raw_log_line"]).group(1)]
    return _decode_raw_url(original)[2]


# --- 2. 침해 패턴은 울리고, 자기 키의 알림 하나만 울린다 ------------------------------------------------------------------
def test_a_hand_edit_of_a_pam_file_alerts_the_auth_config_alert_only(desired):
    ev = event("auth_config", exe="/usr/bin/vim", path="/etc/pam.d/system-auth")
    assert firing_alerts(desired, ev) == {AUTH}
    (row,) = fired(desired, AUTH, ev)
    assert (row["host_name"], row["login_user"], row["program"], row["file_path"], row["events"]) == ("ns0272", "opsverify", "vim", "/etc/pam.d/system-auth", 1)


def test_a_container_runtime_config_change_alerts_the_container_config_alert_only(desired):
    ev = event("container_config", exe="/usr/bin/vim", path="/etc/docker/daemon.json")
    assert firing_alerts(desired, ev) == {CONTAINER}


def test_opening_a_secret_file_alerts_the_secret_access_alert_only(desired):
    ev = event("secret_access", exe="/usr/bin/cat", path="/srv/example/app.secrets.env")
    assert firing_alerts(desired, ev) == {SECRET}


def test_the_alert_row_shows_host_user_executable_path_and_time(desired):
    ev = event("secret_access", exe="/usr/bin/cat", path="/srv/example/app.secrets.env")
    for r in ev:
        r["_timestamp"] = 1_792_767_302_000_000
    lines = _row_lines(desired, SECRET, ev, "security_logs")
    assert len(lines) == 1
    for part in ("ns0272", "opsverify", "cat", "/srv/example/app.secrets.env", "1건", "10-"):
        assert part in lines[0], (part, lines[0])


def test_a_file_the_path_record_does_not_name_still_alerts_with_a_fallback_label(desired):
    for path in (None, "(null)"):
        ev = event("auth_config", exe="/usr/bin/vim", path=path, syscall="fchmod")
        (row,) = fired(desired, AUTH, ev)
        assert row["file_path"] == "(경로 불명)", path


def test_a_relative_file_name_is_joined_to_the_directory_the_event_ran_in(desired):
    """실로그에서 편집기·sed는 `.env`·`compose.yml` 같은 상대 이름으로 PATH 행을 남긴다. 같은 사건의 CWD 행(`/root`)과 이어 본다."""
    (row,) = fired(desired, SECRET, event("secret_access", exe="/usr/bin/vim", path=".env"))
    assert row["file_path"] == "/root/.env"


def test_one_change_counts_once_even_when_it_touches_several_files(desired):
    ev = event("container_config", exe="/usr/bin/sed", path="/etc/docker/daemon.json", nametype="CREATE")
    rows = fired(desired, CONTAINER, ev)
    assert [r["events"] for r in rows] == [1]          # PARENT 항목은 세지 않고, 사건은 시리얼 하나로 센다


def test_other_watch_keys_and_non_syscall_rows_do_not_fire_the_new_alerts(desired):
    others = [event("identity", exe="/usr/bin/vim", path="/etc/passwd"), event("sshd_config", exe="/usr/bin/vim", path="/etc/ssh/sshd_config"),
              event("sudo_logs", exe="/usr/bin/sudo", path="/var/log/sudo.log")]
    assert firing_alerts(desired, *others) == set()
    only_path = [r for r in event("secret_access", exe="/usr/bin/cat", path="/srv/x") if "type=SYSCALL" not in r["body"]]
    assert firing_alerts(desired, only_path) == set()
    other_service = event("secret_access", exe="/usr/bin/cat", path="/srv/x")
    for r in other_service:
        r["service_name"] = "sshd"
    assert firing_alerts(desired, other_service) == set()


# --- 3. 제외: 패키지 관리자·계정 관리 도구·서비스 프로세스 --------------------------------------------------------------------
@pytest.mark.parametrize("exe, comm", [("/usr/bin/rpm", None), ("/usr/bin/dpkg", None), ("/usr/bin/apt-get", None),
                                       ("/usr/libexec/platform-python3.6", "dnf"), ("/usr/bin/python3.9", "yum"),
                                       ("/usr/sbin/useradd", None), ("/usr/bin/passwd", None), ("/usr/bin/chage", None)])
def test_pam_file_changes_by_a_package_manager_or_an_account_tool_are_left_to_others(desired, exe, comm):
    assert firing_alerts(desired, event("auth_config", exe=exe, comm=comm, tty="(none)", auid="unset", auid_num=4294967295)) == set()


def test_package_manager_exclusion_does_not_hide_other_tools_or_other_keys(desired):
    assert firing_alerts(desired, event("auth_config", exe="/usr/sbin/authselect")) == {AUTH}   # 스크립틀릿 자식 프로세스는 이름으로 못 가린다(한계)
    assert firing_alerts(desired, event("container_config", exe="/usr/bin/rpm", path="/etc/docker/daemon.json")) == {CONTAINER}
    assert firing_alerts(desired, event("secret_access", exe="/usr/bin/rpm", path="/srv/x")) == {SECRET}


def test_a_backup_service_reading_a_secret_is_excluded_but_the_same_binary_run_by_a_login_user_is_not(desired):
    svc = event("secret_access", exe="/opt/host-agents/restic/0.19.1/restic", comm="restic", tty="(none)", auid="unset", auid_num=4294967295)
    by_hand = event("secret_access", exe="/opt/host-agents/restic/0.19.1/restic", comm="restic", tty="pts1")
    assert firing_alerts(desired, svc) == set()
    assert firing_alerts(desired, by_hand) == {SECRET}


def test_the_compose_plugin_reading_an_env_file_is_excluded_for_every_user(desired):
    ev = event("secret_access", exe="/usr/libexec/docker/cli-plugins/docker-compose", comm="docker-compose", path="/srv/example/.env")
    assert firing_alerts(desired, ev) == set()


@pytest.mark.parametrize("syscall", ["getxattr", "lgetxattr", "llistxattr", "readlink"])
def test_metadata_only_syscalls_on_a_secret_file_are_not_an_open(desired, syscall):
    assert firing_alerts(desired, event("secret_access", exe="/usr/bin/ls", syscall=syscall, path="/srv/x")) == set()
    assert firing_alerts(desired, event("secret_access", exe="/usr/bin/vim", syscall="setxattr", path="/srv/x")) == {SECRET}


def test_exclusion_lists_are_role_default_variables_not_hardcoded_in_the_sql(desired):
    for var in ("o2c_audit_package_managers", "o2c_audit_secret_service_exes", "o2c_audit_secret_operator_exes",
                "o2c_audit_secret_excluded_users", "o2c_audit_secret_metadata_syscalls", "o2c_audit_provisioning_accounts",
                "o2c_audit_provisioning_keys", "o2c_audit_provisioning_silence_minutes", "o2c_audit_watch_silence_minutes",
                "o2c_audit_watch_min_events"):
        assert var in DEFAULTS, var
    assert DEFAULTS["o2c_audit_secret_excluded_users"] == [] and "restic" in " ".join(DEFAULTS["o2c_audit_secret_service_exes"])
    assert {"rpm", "dnf", "yum", "dpkg", "apt"} <= set(DEFAULTS["o2c_audit_package_managers"])


def test_an_excluded_user_list_entry_silences_that_user_only(tmp_path_factory):
    rendered = render_desired(tmp_path_factory.mktemp("o2c-audit-users") / "d.json", extra={"o2c_audit_secret_excluded_users": ["svcreader"]})
    sql = [o["body"]["query_condition"]["sql"] for o in rendered if o["name"] == SECRET][0]
    srv = event("secret_access", exe="/usr/bin/cat", auid="svcreader", tty="(none)", path="/srv/x")
    other = event("secret_access", exe="/usr/bin/cat", auid="someone", tty="pts1", path="/srv/x")
    run = lambda ev: _run_alert_on_sqlite(sql, ev, "security_logs")  # noqa: E731
    assert run(srv) == [] and len(run(other)) == 1


# --- 4. 정상 변경(Ansible become 경로) 구분: 식별 불가 → 제외하지 않고 등급을 낮춘다 -----------------------------------------------
def test_a_non_interactive_change_by_a_login_user_goes_to_the_low_grade_alert_not_the_high_one(desired):
    ev = event("secret_access", exe="/usr/bin/python3.12", comm="python3", tty="(none)", path="/srv/example/app.secrets.env")
    assert firing_alerts(desired, ev) == {PROVISIONING}          # 제외가 아니라 P3로 간다 — 사라지지 않는다
    (row,) = fired(desired, PROVISIONING, ev)
    assert (row["watch_key"], row["login_user"], row["program"], row["file_path"]) == ("비밀파일", "opsverify", "python3.12", "/srv/example/app.secrets.env")


@pytest.mark.parametrize("key, label, path", [("auth_config", "인증설정", "/etc/pam.d/sshd"), ("container_config", "컨테이너", "/etc/docker/daemon.json"),
                                               ("secret_access", "비밀파일", "/srv/example/app.secrets.env")])
def test_the_low_grade_alert_covers_every_provisioning_key(desired, key, label, path):
    ev = event(key, exe="/usr/bin/python3.12", comm="python3", tty="(none)", path=path)
    assert firing_alerts(desired, ev) == {PROVISIONING}
    (row,) = fired(desired, PROVISIONING, ev)
    assert row["watch_key"] == label


def test_an_interactive_session_or_a_service_without_a_login_stays_in_the_high_grade_alert(desired):
    interactive = event("auth_config", exe="/usr/bin/vim", tty="pts0")
    assert firing_alerts(desired, interactive) == {AUTH}
    no_login = event("secret_access", exe="/usr/bin/cat", tty="(none)", auid="unset", auid_num=4294967295, path="/srv/x")
    assert firing_alerts(desired, no_login) == {SECRET}          # 로그인 사용자 없이(auid unset) 읽는 알 수 없는 프로세스는 P2다


def test_package_manager_changes_are_not_routed_to_the_low_grade_alert_either(desired):
    ev = event("auth_config", exe="/usr/bin/rpm", tty="(none)")
    assert firing_alerts(desired, ev) == set()


def test_with_no_account_list_the_signature_is_any_non_interactive_login_and_the_list_narrows_it(desired, narrowed):
    ansible_like = event("auth_config", exe="/usr/bin/python3.12", comm="python3", tty="(none)", auid="deployer")
    stranger = event("auth_config", exe="/usr/bin/python3.12", comm="python3", tty="(none)", auid="stranger")
    assert firing_alerts(desired, ansible_like) == {PROVISIONING} and firing_alerts(desired, stranger) == {PROVISIONING}
    assert firing_alerts(narrowed, ansible_like, among=NEW_ALERTS) == {PROVISIONING}
    assert firing_alerts(narrowed, stranger, among=NEW_ALERTS) == {AUTH}          # 지정 계정이 아니면 P2로 남는다


def test_the_signature_is_one_sql_fragment_a_sibling_alert_can_reuse(desired):
    """#430(`infra-audit-watch-change`에 키를 더하는 티켓)이 같은 구분을 그대로 쓰도록, 조건은 이름 있는 변수 하나이고 키 목록도 변수다."""
    assert "tty=(none)" in DEFAULTS["o2c_audit_provisioning_filter"] or "o2c_audit_provisioning_cond" in DEFAULTS["o2c_audit_provisioning_filter"]
    assert {"auth_config", "container_config", "secret_access"} <= set(DEFAULTS["o2c_audit_provisioning_keys"])   # #430이 키를 더해도 깨지지 않는다
    assert DEFAULTS["o2c_audit_provisioning_silence_minutes"] == 5 and DEFAULTS["o2c_audit_watch_silence_minutes"] == 5
    assert DEFAULTS["o2c_audit_watch_min_events"] == 1


def test_renotify_interval_and_threshold_are_role_variables_not_hardcoded(tuned):
    for name in P2_ALERTS:
        assert tuned.store["alert"][name]["trigger_condition"]["silence"] == 10, name
    assert tuned.store["alert"][PROVISIONING]["trigger_condition"]["silence"] == 30
    twice = event("secret_access", exe="/usr/bin/cat", path="/srv/x") + event("secret_access", exe="/usr/bin/cat", path="/srv/x")
    once = event("secret_access", exe="/usr/bin/cat", path="/srv/x")
    assert len(_run_alert_on_sqlite(_sql(tuned, SECRET), twice, "security_logs")) == 1 and _run_alert_on_sqlite(_sql(tuned, SECRET), once, "security_logs") == []


def test_a_key_appended_to_the_provisioning_list_reaches_the_low_grade_alert_and_its_log_link_with_no_other_change(tuned):
    """#430의 계약: 키를 `o2c_audit_provisioning_keys`에 더하기만 하면 P3 SQL·로그 링크가 그 키를 본다(P2는 자기 알림에 `AND NOT 서명`을 붙인다)."""
    make = lambda: event("ssh_keys", exe="/usr/bin/python3.12", comm="python3", tty="(none)", path="/root/.ssh/authorized_keys")  # noqa: E731
    ev = make() + make()                                    # tuned는 임계 2: 서로 다른 사건 둘
    (row,) = _run_alert_on_sqlite(_sql(tuned, PROVISIONING), ev, "security_logs")
    assert row["watch_key"] == "ssh_keys"          # 모르는 키는 앞 8자 그대로 보인다
    assert 'key="ssh_keys"' in _raw_query(tuned, PROVISIONING)
    interactive = event("ssh_keys", exe="/usr/bin/vim", path="/root/.ssh/authorized_keys")
    assert _run_alert_on_sqlite(_sql(tuned, PROVISIONING), interactive, "security_logs") == []   # 서명이 아니면 P3가 아니다(#430의 P2가 맡는다)


# --- 5. 중복 방지: 기존 알림과 같은 변경으로 둘이 울리지 않는다 --------------------------------------------------------------------
def test_a_change_never_fires_the_existing_watch_alert_or_the_account_change_alert_as_well(desired):
    rows = [event("auth_config", exe="/usr/bin/vim"), event("container_config", exe="/usr/bin/vim", path="/etc/docker/daemon.json"),
            event("secret_access", exe="/usr/bin/cat", path="/srv/x"),
            event("secret_access", exe="/usr/bin/python3.12", comm="python3", tty="(none)", path="/srv/x")]
    for ev in rows:
        assert firing_alerts(desired, ev, among=(OLD_WATCH, ACCOUNT_CHANGE)) == set()
        assert len(firing_alerts(desired, ev)) == 1


def test_the_existing_watch_alert_does_not_gain_the_new_keys(desired):
    sql = _sql(desired, OLD_WATCH)
    for key in KEY_OF.values():
        assert f'key="{key}"' not in sql


def test_a_useradd_pam_side_effect_is_left_to_the_account_change_alert(desired):
    ev = event("auth_config", exe="/usr/sbin/useradd", path="/etc/pam.d/system-auth")
    assert firing_alerts(desired, ev) == set()


# --- 6. secret_access 대상이 없는 호스트 ---------------------------------------------------------------------------------------
def test_without_any_secret_access_records_the_alert_returns_nothing_and_does_not_fail(desired):
    unrelated = event("identity", exe="/usr/bin/vim", path="/etc/passwd")
    assert fired(desired, SECRET, unrelated) == []


def test_empty_watch_paths_render_no_secret_access_rule():
    from security_render import rule_lines, shared_render
    assert not [ln for ln in rule_lines(shared_render()["default"]["audit"]) if "secret_access" in ln]


# --- 7. 메시지 길이 ---------------------------------------------------------------------------------------------------------
def test_30_longest_rows_fit_the_notification_limit(desired):
    for name in NEW_ALERTS:
        fields = set(re.findall(r"\{(\w+)\}", desired.store["alert"][name]["row_template"]))
        longest = {"host_label": LONGEST_ROW_VALUES["host_label"], "login_user": "u" * 16, "program": "t" * 14, "file_path": "…" + "p" * 39,
                   "events": "999", "event_time": LONGEST_ROW_VALUES["event_time"], "watch_key": "컨테이너"}
        assert fields <= set(longest), (name, fields - set(longest))
        assert len(_rendered_message(desired, name, longest)) <= 5000, name


def test_the_sql_cuts_text_columns_to_the_lengths_the_message_budget_assumes(desired):
    ev = event("secret_access", exe="/opt/" + "x" * 70 + "/" + "t" * 30, auid="u" * 40, path="/" + "p" * 200)
    (row,) = fired(desired, SECRET, ev)
    assert len(row["login_user"]) <= 16 and len(row["program"]) <= 14 and len(row["file_path"]) <= 40 and row["file_path"].startswith("…") and row["file_path"].endswith("p" * 38)


# --- 8. 합성 행 픽스처(검증 단계가 실서버에서 같은 SQL로 돌린다) -----------------------------------------------------------------
@pytest.mark.parametrize("name", NEW_ALERTS)
def test_fixtures_exist_with_firing_and_quiet_cases_and_fire_as_expected_on_the_rendered_sql(desired, name):
    spec = FIXTURES[name]
    assert {c["fires"] for c in spec["cases"]} == {True, False}
    assert any("\x1d" in r["body"] for c in spec["cases"] for r in c["records"]), "실제 줄 모양(\\x1d)을 쓰는 케이스가 있어야 한다"
    records = []
    for case in spec["cases"]:
        for rec in case["records"]:
            rec = dict(rec, host_name=case["host"])
            rec["body"] = rec["body"].replace("{host}", case["host"])
            records.append(rec)
    rows = _run_alert_on_sqlite(_sql(desired, name), records, "security_logs")
    assert {r["host_name"] for r in rows} == {c["host"] for c in spec["cases"] if c["fires"]}, name


def test_a_fixture_set_never_makes_one_change_fire_two_of_the_new_alerts(desired):
    cases = [(n, c) for n in NEW_ALERTS for c in FIXTURES[n]["cases"]]
    for owner, case in cases:
        records = [dict(r, host_name=case["host"], body=r["body"].replace("{host}", case["host"])) for r in case["records"]]
        hits = {n for n in NEW_ALERTS if _run_alert_on_sqlite(_sql(desired, n), records, "security_logs")}
        assert len(hits) <= 1, (owner, case["name"], hits)


# --- 9. 명세·런북 1:1 ---------------------------------------------------------------------------------------------------------
def test_the_spec_records_the_split_decision_the_provisioning_rule_and_how_to_reuse_it():
    spec = (ROOT_DIR / "docs" / "openobserve_config.md").read_text(encoding="utf-8")
    for token in ("Spec #419", "별도 알림", "o2c_audit_provisioning_filter", "o2c_audit_provisioning_keys", "o2c_audit_provisioning_accounts",
                  "식별할 수 없", "BECOME-SUCCESS", "#430", "o2c_audit_secret_service_exes", "o2c_audit_package_managers"):
        assert token in spec, token
    for name in NEW_ALERTS:
        assert f"`{name}`" in spec


def test_the_runbook_explains_each_new_alert_and_the_low_grade_one():
    runbook = RUNBOOK.read_text(encoding="utf-8")
    for key in ("auth_config", "container_config", "secret_access"):
        assert f"`{key}`" in runbook
    assert "ausearch -k secret_access" in runbook and "정상 변경 후보" in runbook


def test_the_role_defaults_document_the_new_variables_in_the_spec_variable_table():
    spec = (ROOT_DIR / "docs" / "openobserve_config.md").read_text(encoding="utf-8")
    table = [line for line in spec.splitlines() if line.startswith("| `o2c_")]
    names = {m for line in table for m in re.findall(r"`(o2c_[a-z0-9_]+)`", line.split("|")[1])}
    for var in ("o2c_audit_package_managers", "o2c_audit_secret_service_exes", "o2c_audit_secret_operator_exes", "o2c_audit_secret_excluded_users",
                "o2c_audit_secret_metadata_syscalls", "o2c_audit_provisioning_accounts", "o2c_audit_provisioning_keys",
                "o2c_audit_provisioning_silence_minutes", "o2c_audit_watch_silence_minutes", "o2c_audit_watch_min_events"):
        assert var in names, var
