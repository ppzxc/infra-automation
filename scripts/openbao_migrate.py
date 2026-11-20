#!/usr/bin/env python3
"""옛 OpenBao 구조(`infra/prod/host`의 `secret/`)를 새 골격(`infra`의 `inventory/`·`secrets/`)으로 적재하는 일회용 스크립트.

Spec #511 / Ticket-10(#521). 대응표는 #501~#504 결정을 코드로 옮긴 것이다. 옛 구조를 지울 때 이 파일과
`tests/test_openbao_migrate.py`도 함께 지운다.

흐름: 옛 문서 읽기 -> 새 문서 만들기 -> `openbao_validation`으로 전체 검증 -> (하나라도 실패하면 아무것도 쓰지 않는다)
      -> 문서마다 `cas=0` 쓰기(있으면 같은 내용은 건너뛰고 다른 내용은 키 이름 차이만 보인다) -> 해시 대조 보고서.

옮기지 않는 것(미참조 계정 문서, 소프트 삭제 `switches/` 등)은 저장소에 적지 않고 실행 입력(`--skip-file`)으로 받는다.
항목은 옛 문서 경로(`hosts/ns0001/users/bk`), 접두사(끝이 `/`, `switches/`), 문서 안의 키(`hosts/ns0001:key`) 중 하나다.
대응표에 없는 문서·키는 오류로 멈춘다(조용히 버리지 않는다).

토큰은 `--token-file` 또는 getpass로 받는다(인자·환경변수로 받지 않는다). 하나로 옛·새 네임스페이스를 읽고 쓴다(admin).
출력에는 문서 경로·키 이름·규칙 이름·상태만 낸다. 값은 어디에도 내지 않는다.
종료 코드: 0 성공, 1 대응·검증 실패(쓰기 없음), 2 이미 있는 문서와 내용이 다름, 3 해시 불일치(차이가 없는데도), 4 통신·쓰기 오류.
"""
import argparse
import collections
import copy
import getpass
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.append(str(Path(__file__).resolve().parent.parent / "filter_plugins"))
from openbao_ssh import python_interpreter_problem  # noqa: E402
sys.path.append(str(Path(__file__).resolve().parent.parent / "lookup_plugins"))   # 끝에 붙인다(stdlib·scripts/ 이름을 가리지 않는다)
import _bao_http  # noqa: E402
import openbao_validation as ov  # noqa: E402

OLD_TOP_LEVEL = ("hosts", "users", "agents", "clusters", "fortigate")
ACCOUNT_KEYS = ("username", "type", "password", "ssh_private_key", "ssh_passphrase")
GLOBAL_ACCOUNT_KEYS = ACCOUNT_KEYS + ("ssh_public_key", "revoked_keys")  # 공개키·폐기 키는 Operator로 간다
BOOTSTRAP_KEYS = ACCOUNT_KEYS + ("ssh_public_key",)  # 공개키는 아무도 읽지 않는다(#501 §5)
DROPPED_HOST_KEYS = ("hostname", "fqdn", "cloudflare_api_token")  # 계산되는 값·아무도 읽지 않는 키(#501 §5)
INGEST_SOURCES = ("webhook_watch", "controller_token")


def _printable(text):
    """제어 문자가 보고 줄 구조를 깨지 않게 한다(openbao_validation.Violation.format과 같은 규칙)."""
    return "".join(c if c.isprintable() else "?" for c in text)


class MigrationError(Exception):
    pass


def skipped(path, skip):
    """skip 항목(문서 경로 또는 끝이 `/`인 접두사)에 걸리는지. `문서:키` 항목은 문서 단위가 아니다."""
    return any(s == path or (s.endswith("/") and path.startswith(s)) for s in skip if ":" not in s)


class Plan:
    def __init__(self):
        self.store = {}      # 새 문서 경로 -> 데이터
        self.lineage = []    # (새 문서, JSON 포인터, 옛 문서, 옛 키, 기대 값): 해시 대조용
        self.errors = []     # 경로·키 이름만 담는다


# ---- 대응표 ----------------------------------------------------------------------------------------------------------

def _as_list(value):
    if value is None or value == "":
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    return [str(v).strip() for v in value if str(v).strip()]


def _truthy(value):
    return value is True or (isinstance(value, str) and value.strip().lower() in ("true", "yes", "1"))


def _int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return value  # 스키마 검증이 규칙 이름으로 거부한다


def _credential_name(username):
    """Credential 이름은 snake_case 규칙(`^[a-z][a-z0-9_]*`)이다. 계정 이름의 하이픈·점 등은 밑줄로, 대문자는 소문자로 바꾼다.
    실제 로그인 이름은 Credential의 username에 그대로 남는다."""
    return re.sub(r"[^a-z0-9_]", "_", str(username).lower())


def _env_to_key(name):
    """FUNA 대문자 env 이름 -> 저장 키(snake_case, `FUNA_` 접두사 제거). 예: FUNA_NODE_NAME -> node_name, TZ -> tz."""
    low = name.lower()
    return low[len("funa_"):] if low.startswith("funa_") else low


class _Builder:
    def __init__(self, old, skip, ingest_source):
        if ingest_source not in INGEST_SOURCES:
            raise MigrationError("ingest_source")
        self.plan = Plan()
        self.skip = list(skip)
        self.ingest_source = ingest_source
        self.old = {p: copy.deepcopy(d) for p, d in old.items() if not skipped(p, self.skip)}
        self.keyskip = {tuple(s.split(":", 1)) for s in self.skip if ":" in s}
        for doc, key in self.keyskip:  # 문서:키 항목은 대응표가 쓰는 키여도 옮기지 않는다
            self.old.get(doc, {}).pop(key, None)
        self.consumed = set()
        self.environments = {}
        self.endpoints = collections.defaultdict(dict)   # ns -> {이름: Endpoint}
        self.logins = collections.defaultdict(set)       # ns -> 필요한 Credential 이름
        self.credentials = collections.defaultdict(dict)  # ns -> {이름: (데이터, 출처 목록)}

    # -- 보조 ---------------------------------------------------------------------------------------------------------
    def err(self, doc, what):
        line = "%s\t%s" % (_printable(doc), _printable(what))
        if line not in self.plan.errors:  # 같은 전역 계정 문서를 참조하는 호스트마다 같은 줄이 쌓이지 않게 한다
            self.plan.errors.append(line)

    def put(self, doc, parts, value, src=None):
        node = self.plan.store.setdefault(doc, {})
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = value
        if src is not None:
            self.plan.lineage.append((doc, "/" + "/".join(str(p) for p in parts), src[0], src[1], copy.deepcopy(value)))

    def take(self, doc):
        """옛 문서를 가져오고 소비 표시를 한다. 없으면 None."""
        if doc in self.old:
            self.consumed.add(doc)
            return self.old[doc]
        return None

    def finish(self, doc, data):
        """문서에 남은 키 중 skip 입력에도 없는 것은 대응표에 없는 키다."""
        for key in sorted(data):
            if (doc, key) not in self.keyskip:
                self.err(doc, "unmapped_key:%s" % key)

    # -- 호스트 -------------------------------------------------------------------------------------------------------
    def hosts(self):
        domains = {}
        names = sorted(p.split("/")[1] for p in self.old if p.startswith("hosts/") and p.count("/") == 1)
        for ns in names:
            self.host(ns, domains)
        for ns in sorted({p.split("/")[1] for p in self.old if p.startswith("fortigate/")}):
            self.fortigate(ns)
        if domains:
            common, _ = collections.Counter(domains.values()).most_common(1)[0]
            first = next(ns for ns in sorted(domains) if domains[ns] == common)
            self.put("inventory/config/common", ["domain"], common, ("hosts/%s" % first, "domain"))
            for ns, dom in sorted(domains.items()):
                if dom != common:
                    self.put("inventory/assets/%s" % ns, ["domain"], dom, ("hosts/%s" % ns, "domain"))
        for ns in sorted({p.split("/")[1] for p in self.old if p.startswith("hosts/") and p.count("/") > 1} - set(names)):
            self.err("hosts/%s" % ns, "no_host_document")
        self.credentials_and_endpoints()

    def host(self, ns, domains):
        doc = "hosts/%s" % ns
        d = self.take(doc)
        asset = "inventory/assets/%s" % ns
        for k, new in (("description", "description"), ("host_type", "type")):
            if k in d:
                self.put(asset, [new], d.pop(k), (doc, k))
        for k in sorted(k for k in d if k.startswith("isms_")):
            self.put(asset, ["isms", k[len("isms_"):]], d.pop(k), (doc, k))
        if d.get("hostname", ns) != ns:
            self.err(doc, "hostname_differs")  # 계산되는 값이라 버리는데, 관리번호와 다르면 사람이 봐야 한다
        for k in DROPPED_HOST_KEYS:
            d.pop(k, None)
        if "domain" in d:
            domains[ns] = d.pop("domain")
        admin = _as_list(d.pop("admin_users", None))
        boot = d.pop("bootstrap_user", None) or None
        removed = _as_list(d.pop("removed_users", None))
        interp = d.pop("ansible_python_interpreter", None)
        pwauth = _truthy(d.pop("host_agents_allow_password_auth", False))
        address = d.pop("ansible_host", None) or d.pop("public_ip", None) or None
        d.pop("public_ip", None)
        port = d.pop("ansible_port", None)
        user, password = d.pop("ansible_user", None), d.pop("ansible_password", None)
        ctype, bastion = d.pop("connection_type", None), d.pop("bastion_host", None)
        access = {}
        if admin:
            access["admin_credentials"] = admin
        if boot:
            access["bootstrap_credential"] = boot
        if removed:
            access["removed_accounts"] = removed
        # 옛 접속 해석은 호스트별 인터프리터를 쓰되 venv·semaphore·임시 경로 등은 걸러 기본값으로 돌렸다: 같은 규칙으로 옮긴다
        if isinstance(interp, str) and interp and python_interpreter_problem(interp) is None:
            access["python_interpreter"] = interp
        access_src = {"admin_credentials": "admin_users", "bootstrap_credential": "bootstrap_user",
                      "removed_accounts": "removed_users", "python_interpreter": "ansible_python_interpreter"}
        for k, v in access.items():
            self.put(asset, ["access", k], v, (doc, access_src[k]))
        if "CLOUDFLARE_API_TOKEN" in d:
            self.credentials[ns]["cloudflare"] = ({"type": "api_token", "token": d.pop("CLOUDFLARE_API_TOKEN")},
                                                  {"token": (doc, "CLOUDFLARE_API_TOKEN")})
        for k in sorted(k for k in d if k.startswith("FUNA_")):
            self.put(asset, ["funa", _env_to_key(k)], d.pop(k), (doc, k))
        self.finish(doc, d)
        self.asset_agents(ns)
        if (ctype is not None or user is not None) and not (admin or boot):  # 서버는 admin_users·bootstrap_user로 접속한다
            self.device_endpoint(ns, doc, address, port, user, password, ctype, bastion)
        elif address and not ("fortigate/%s" % ns in self.old and not (admin or boot)):  # 방화벽은 fortigate 문서가 맡는다
            if ctype is not None or user is not None or password is not None:
                self.err(doc, "unused_key:connection_type/ansible_user/ansible_password")  # 서버는 계정 문서로 접속한다. 조용히 버리지 않는다
            self.server_endpoint(ns, address, port, admin, boot, pwauth)
        elif admin or boot:
            self.err(doc, "no_address")

    def server_endpoint(self, ns, address, port, admin, boot, pwauth):
        login = boot if (pwauth and boot) else (admin[0] if admin else boot)
        if login is None:
            return self.err("hosts/%s" % ns, "no_login_account")
        ep = {"protocol": "ssh", "address": address, "port": _int(port if port not in (None, "") else 22), "credential": login}
        if not pwauth:
            ep["identity"] = "automation"
        if login != "root":
            ep["become"] = {"method": "sudo"}
        self.endpoints[ns]["ssh"] = ep
        self.logins[ns].add(login)

    def device_endpoint(self, ns, doc, address, port, user, password, ctype, bastion):
        if not user:
            return self.err(doc, "no_login_account")
        name = "telnet" if ctype == "telnet" else "ssh"
        cred = _credential_name(user)
        ep = {"protocol": name, "address": address, "port": _int(port if port not in (None, "") else (23 if name == "telnet" else 22)),
              "credential": cred, "become": {"method": "enable"}}
        if ctype == "jump_ssh":
            if not bastion:
                self.err(doc, "jump_without_bastion")
            else:
                ep["via"] = "%s/ssh" % bastion
        self.endpoints[ns][name] = ep
        data, srcs = {"type": "password", "username": user}, {"username": (doc, "ansible_user")}
        if password is not None:  # 없으면 스키마 검증이 password 누락을 알린다
            data["password"], srcs["password"] = password, (doc, "ansible_password")
        self.credentials[ns][cred] = (data, srcs)

    def fortigate(self, ns):
        doc = "fortigate/%s" % ns
        d = self.take(doc)
        if d is None:
            return self.err(doc, "no_document")
        # 옛 역할은 접속 대상을 fqdn 우선(인증서 이름 검증), 없으면 ansible_host로 썼다. Endpoint address는 "IP 또는 이름"이라 같은 대상을 보존한다.
        fqdn = d.pop("fqdn", None)
        address, port, token = d.pop("ansible_host", None), d.pop("ansible_port", None), d.pop("api_token", None)
        address = fqdn or address
        self.endpoints[ns]["https"] = {"protocol": "https", "address": address, "port": _int(port if port is not None else 443),
                                       "credential": "api"}
        if token is not None:
            self.credentials[ns]["api"] = ({"type": "api_token", "token": token}, {"token": (doc, "api_token")})
        self.finish(doc, d)
        if "hosts/%s" % ns not in self.old:
            self.err(doc, "no_host_document")

    # -- 에이전트(Asset 절 + 비밀) -------------------------------------------------------------------------------------
    def asset_agents(self, ns):
        doc = "hosts/%s/agents" % ns
        d = self.take(doc)
        if d is None:
            return
        asset, sec = "inventory/assets/%s" % ns, "secrets/assets/%s/agents" % ns
        secrets = {"o2_ingest_token": "ingest_token", "rustfs_access_key": "rustfs_access_key",
                   "rustfs_secret_key": "rustfs_secret_key", "restic_password": "restic_password"}
        for old, new in secrets.items():
            if old in d:
                self.put(sec, [new], d.pop(old), (doc, old))
        for k in [k for k in d if k.startswith("github_webhook_")]:   # GitHub 조직 감사 웹훅은 제거됐다(#651). 옛 값은 옮기지 않고 버린다
            d.pop(k)
        env = d.pop("host_agents_environment", None)  # 모든 호스트가 같은 값이어야 한다. 역할 기본값으로 옮겼다(#503·#504)
        if env is not None and self.environments.setdefault("value", env) != env:
            self.err(doc, "host_agents_environment_differs")
        for prefix, section in (("backup_", "backup"), ("otel_", "otel")):
            for k in sorted(k for k in d if k.startswith(prefix)):
                value = d.pop(k)
                if k == "backup_sqlite_snapshots" and isinstance(value, list):   # 옛 값은 경로 문자열 목록, 새 값은 {path} 객체 목록
                    value = [{"path": v} if isinstance(v, str) else v for v in value]
                self.put(asset, ["agents", section, k[len(prefix):]], value, (doc, k))
        if d.get("rustfs_bucket") not in (None, ""):  # 이름 규칙 밖 호스트(이전·개명)의 버킷: 호스트별 덮어쓰기
            self.put(asset, ["agents", "backup", "bucket"], d.pop("rustfs_bucket"), (doc, "rustfs_bucket"))
        else:
            d.pop("rustfs_bucket", None)
        self.finish(doc, d)

    # -- Credential·Endpoint 확정 -------------------------------------------------------------------------------------
    def credentials_and_endpoints(self):
        for p in sorted(self.old):
            parts = p.split("/")
            if len(parts) == 4 and parts[0] == "hosts" and parts[2] == "users":
                self.credentials[parts[1]].setdefault(parts[3], None)
        for ns in sorted(p.split("/")[1] for p in self.old if p.startswith("hosts/") and p.count("/") == 1):
            access = self.plan.store.get("inventory/assets/%s" % ns, {}).get("access", {})
            wanted = set(access.get("admin_credentials", [])) | set(self.logins[ns])
            if access.get("bootstrap_credential"):
                wanted.add(access["bootstrap_credential"])
            wanted |= set(self.credentials[ns])
            for name in sorted(wanted):
                self.credential(ns, name)
            if self.endpoints.get(ns):
                self.plan.store["inventory/assets/%s/endpoints" % ns] = self.endpoints[ns]

    def credential(self, ns, name):
        ready = self.credentials[ns].get(name)
        doc = "secrets/assets/%s/credentials/%s" % (ns, name)
        if ready:  # 이미 완성된 Credential(네트워크 로그인·FortiGate API·Cloudflare)
            data, srcs = ready
            self.plan.store[doc] = {}
            for k, v in data.items():
                self.put(doc, [k], v, srcs.get(k))
            return
        layers = []
        glob = self.old.get("users/%s" % name)
        boot = self.old.get("hosts/%s/bootstrap" % ns)
        host = self.old.get("hosts/%s/users/%s" % (ns, name))
        if glob is not None:
            layers.append(("users/%s" % name, glob, False))
        bname = (boot or {}).get("username") or self.plan.store.get("inventory/assets/%s" % ns, {}).get("access", {}).get(
            "bootstrap_credential")
        if boot is not None and bname == name:
            layers.append(("hosts/%s/bootstrap" % ns, boot, True))
        if host is not None:
            layers.append(("hosts/%s/users/%s" % (ns, name), host, False))
        if not layers:
            return  # 참조 검사가 규칙 이름으로 알린다(access_credential_missing 등)
        merged, src = {}, {}
        for path, layer, is_boot in layers:
            self.consumed.add(path)
            allowed = GLOBAL_ACCOUNT_KEYS if path.startswith("users/") else (BOOTSTRAP_KEYS if is_boot else ACCOUNT_KEYS)
            self.finish(path, {k: v for k, v in layer.items() if k not in allowed})
            for k in ("password", "ssh_private_key", "ssh_passphrase"):
                if layer.get(k) not in (None, ""):
                    if k.startswith("ssh_") and path.startswith("users/"):
                        continue  # 전역 계정의 키는 Automation Identity다(Credential로 복사하지 않는다)
                    if k == "ssh_private_key":
                        merged.pop("ssh_passphrase", None)  # 암호문은 키를 준 층의 것만 쓴다
                    merged[k], src[k] = layer[k], (path, k)
        if "ssh_private_key" in merged:
            data = {"type": "ssh_key", "username": name, "private_key": merged["ssh_private_key"]}
            m = {"private_key": src["ssh_private_key"]}
            if "ssh_passphrase" in merged:
                data["passphrase"], m["passphrase"] = merged["ssh_passphrase"], src["ssh_passphrase"]
            if "password" in merged:
                data["password"], m["password"] = merged["password"], src["password"]
        else:
            if "ssh_passphrase" in merged:
                self.err("secrets/assets/%s/credentials/%s" % (ns, name), "passphrase_without_key")
            data = {"type": "password", "username": name}
            m = {}
            if "password" in merged:
                data["password"], m["password"] = merged["password"], src["password"]
        self.plan.store[doc] = {}
        for k, v in data.items():
            self.put(doc, [k], v, m.get(k))

    # -- 전역 계정: 자동화 키·Operator ---------------------------------------------------------------------------------
    def global_users(self):
        keyed = []
        for path in sorted(p for p in self.old if p.startswith("users/") and p.count("/") == 1):
            name = path.split("/")[1]
            d = self.old[path]
            self.consumed.add(path)
            self.finish(path, {k: v for k, v in d.items() if k not in GLOBAL_ACCOUNT_KEYS})
            if d.get("revoked_keys") and not d.get("ssh_public_key"):
                self.err(path, "revoked_keys_without_public_key")
            if d.get("ssh_public_key"):
                self.put("inventory/operators/%s" % name, ["public_keys"], [d["ssh_public_key"]], (path, "ssh_public_key"))
                if d.get("revoked_keys"):
                    self.put("inventory/operators/%s" % name, ["revoked_keys"], _as_list(d["revoked_keys"]), (path, "revoked_keys"))
            if d.get("ssh_private_key"):
                keyed.append(path)
        if len(keyed) > 1:
            self.err("secrets/automation/ssh", "ambiguous_automation_key")
        for path in keyed[:1]:
            d = self.old[path]
            for k, new in (("ssh_private_key", "private_key"), ("ssh_public_key", "public_key"), ("ssh_passphrase", "passphrase")):
                if d.get(k):
                    self.put("secrets/automation/ssh", [new], d[k], (path, k))

    # -- Service·작업 설정 ---------------------------------------------------------------------------------------------
    def services(self):
        o2 = self.take("agents/openobserve") or {}
        rf = self.take("agents/rustfs") or {}
        ha = self.take("agents/host_audit") or {}
        gw = self.take("agents/github-webhook-watch") or {}
        # openobserve
        if "o2_endpoint" in o2:
            self.put("inventory/services/openobserve", ["url"], o2.pop("o2_endpoint"), ("agents/openobserve", "o2_endpoint"))
        if o2.get("o2_org"):   # 조직(선택). 수집 계정 이름이기도 하다(ingest())
            self.put("inventory/services/openobserve", ["org"], o2["o2_org"], ("agents/openobserve", "o2_org"))
        if o2.get("o2_ca_file"):  # 사설 CA 경로(선택)
            self.put("inventory/services/openobserve", ["ca_file"], o2.pop("o2_ca_file"), ("agents/openobserve", "o2_ca_file"))
        else:
            o2.pop("o2_ca_file", None)
        gw.pop("o2_endpoint", None)  # OpenObserve 주소와 중복(#501 §1)
        if "api_user" in o2:
            self.put("secrets/services/openobserve/admin", ["username"], o2.pop("api_user"), ("agents/openobserve", "api_user"))
            if "api_password" in o2:
                self.put("secrets/services/openobserve/admin", ["password"], o2.pop("api_password"),
                         ("agents/openobserve", "api_password"))
        self.ingest(o2, gw)
        o2.pop("o2_org", None)
        if "normal_sources" in o2:
            self.put("inventory/config/openobserve_config", ["normal_sources"], o2.pop("normal_sources"),
                     ("agents/openobserve", "normal_sources"))
        # 호스트별 알림 제외·임계값·프로비저닝 계정은 관리번호·계정이 들어가 공개 저장소(역할 기본값)에 둘 수 없다(#504 §7)
        for k, new in (("alert_resource_exclusions", "resource_exclusions"), ("alert_resource_thresholds", "resource_thresholds"),
                       ("alert_audit_provisioning_accounts", "audit_provisioning_accounts")):
            if o2.get(k):
                self.put("inventory/config/openobserve_config", [new], o2.pop(k), ("agents/openobserve", k))
            else:
                o2.pop(k, None)
        if "alert_webhook_plain_url" in o2:
            self.put("secrets/services/alert/notify", ["url"], o2.pop("alert_webhook_plain_url"),
                     ("agents/openobserve", "alert_webhook_plain_url"))
        for k in ("alert_webhook_url", "alert_webhook_token", "alert_webhook_auth_header"):
            o2.pop(k, None)  # 옛 JSON 경로는 옮기지 않는다(#503 §3)
        o2.pop("controller_ingest_token", None)
        self.finish("agents/openobserve", o2)
        # rustfs
        if "rustfs_endpoint" in rf:
            self.put("inventory/services/rustfs", ["url"], rf.pop("rustfs_endpoint"), ("agents/rustfs", "rustfs_endpoint"))
        if rf.get("rustfs_ca_file"):  # 사설 CA 경로(선택)
            self.put("inventory/services/rustfs", ["ca_file"], rf.pop("rustfs_ca_file"), ("agents/rustfs", "rustfs_ca_file"))
        else:
            rf.pop("rustfs_ca_file", None)
        for k, new in (("maintenance_access_key", "access_key"), ("maintenance_secret_key", "secret_key")):
            if k in rf:
                self.put("secrets/services/rustfs/maintenance", [new], rf.pop(k), ("agents/rustfs", k))
        self.finish("agents/rustfs", rf)
        # host_audit
        for k, new in (("storage_access_key", "access_key"), ("storage_secret_key", "secret_key")):
            if k in ha:
                self.put("secrets/services/rustfs/audit_reports", [new], ha.pop(k), ("agents/host_audit", k))
        if "mail_to" in ha:
            self.put("inventory/config/host_audit", ["mail_recipients"], _as_list(ha.pop("mail_to")), ("agents/host_audit", "mail_to"))
        for k, new in (("mail_from", "mail_sender"), ("mail_from_name", "mail_sender_display_name")):
            if ha.get(k):
                self.put("inventory/config/host_audit", [new], ha.pop(k), ("agents/host_audit", k))
            else:
                ha.pop(k, None)
        self.finish("agents/host_audit", ha)
        # GitHub 조직 감사 웹훅 설정은 제거됐다(#651). 옛 값은 옮기지 않고 버린다. 수집 계정(o2_ingest_*)만 ingest()가 쓴다.
        for k in ("github_token", "github_org", "hook_url", "o2_org"):
            gw.pop(k, None)
        gw.pop("o2_ingest_user", None)
        gw.pop("o2_ingest_password", None)
        self.finish("agents/github-webhook-watch", gw)

    def ingest(self, o2, gw):
        doc = "secrets/services/openobserve/ingest"
        if self.ingest_source == "webhook_watch":
            src = "agents/github-webhook-watch"
            if "o2_ingest_user" not in gw or "o2_ingest_password" not in gw:
                return self.err(src, "ingest_account_incomplete")
            self.put(doc, ["username"], gw["o2_ingest_user"], (src, "o2_ingest_user"))
            self.put(doc, ["password"], gw["o2_ingest_password"], (src, "o2_ingest_password"))
            return
        # 옛 소비자는 raw passcode(controller_ingest_token)를 Basic `<o2_org>:<passcode>`로 인코딩했다(조직 기본값 default).
        token = o2.get("controller_ingest_token")
        if not isinstance(token, str) or not token:
            return self.err("agents/openobserve", "controller_ingest_token_missing")
        self.put(doc, ["username"], o2.get("o2_org") or "default", ("agents/openobserve", "o2_org"))
        self.put(doc, ["password"], token, ("agents/openobserve", "controller_ingest_token"))

    def funa(self):
        for path, new in (("clusters/funa", "inventory/services/funa"), ("clusters/funa/proxy", "secrets/services/funa/proxy"),
                          ("clusters/funa/vrrp", "secrets/services/funa/vrrp")):
            d = self.take(path)
            names = collections.Counter(_env_to_key(k) for k in d or {})
            for k in sorted(d or {}):
                if names[_env_to_key(k)] > 1:
                    self.err(path, "key_collision:%s" % k)
                else:
                    self.put(new, [_env_to_key(k)], d[k], (path, k))

    def run(self):
        self.global_users()
        self.hosts()
        self.services()
        self.funa()
        for doc in sorted(set(self.old) - self.consumed):
            self.err(doc, "unmapped_document")
        return self.plan


def build_new(old, skip=(), ingest_source="webhook_watch"):
    """옛 문서 {경로: 데이터} -> Plan. 대응표의 본체다."""
    return _Builder(old, skip, ingest_source).run()


# ---- HTTP ---------------------------------------------------------------------------------------------------------

class ClientError(Exception):
    pass



class Client:
    def __init__(self, addr, namespace, token):
        self.addr, self.namespace, self.token = addr.rstrip("/"), namespace, token

    def _call(self, method, path, body=None, missing=()):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"X-Vault-Token": self.token, "X-Vault-Namespace": self.namespace, "Content-Type": "application/json"}
        req = urllib.request.Request(self.addr + path, data=data, headers=headers, method=method)
        try:
            with _bao_http.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            if e.code in missing:
                return e.code, {}
            raise ClientError("%s %s -> HTTP %d" % (method, path.split("?")[0], e.code)) from None  # 본문은 내지 않는다
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise ClientError("%s %s -> %s" % (method, path.split("?")[0], type(e).__name__)) from None

    def read(self, mount, doc):
        status, body = self._call("GET", "/v1/%s/data/%s" % (mount, urllib.parse.quote(doc)), missing=(404,))
        try:
            return None if status == 404 else body["data"]["data"]
        except (KeyError, TypeError):
            raise ClientError("GET %s/%s -> 예상 밖 응답 모양(KV v2 마운트인지 확인)" % (mount, doc)) from None

    def list(self, mount, prefix):
        status, body = self._call("GET", "/v1/%s/metadata/%s?list=true" % (mount, urllib.parse.quote(prefix)), missing=(404,))
        try:
            return [] if status == 404 else body["data"]["keys"]
        except (KeyError, TypeError):
            raise ClientError("LIST %s/%s -> 예상 밖 응답 모양(KV v2 마운트인지 확인)" % (mount, prefix)) from None

    def create(self, mount, doc, data):
        """cas=0 쓰기. 이미 있으면 False."""
        try:
            self._call("POST", "/v1/%s/data/%s" % (mount, urllib.parse.quote(doc)), {"options": {"cas": 0}, "data": data})
            return True
        except ClientError as e:
            if "HTTP 400" in str(e):
                return False
            raise


def read_old(client, mount, skip):
    docs = {}

    def walk(prefix):
        for key in client.list(mount, prefix.rstrip("/")):
            path = prefix + key
            if skipped(path, skip):
                continue
            if key.endswith("/"):
                walk(path)
            else:
                data = client.read(mount, path)
                if data is not None:  # 소프트 삭제된 문서는 읽으면 404다
                    docs[path] = data

    walk("")
    return docs


# ---- 쓰기·보고 ----------------------------------------------------------------------------------------------------

def _flatten(node, pointer=""):
    if isinstance(node, dict) and node:
        for k in sorted(node):
            yield from _flatten(node[k], "%s/%s" % (pointer, k))
    else:
        yield pointer or "/", node


def diff_keys(planned, existing):
    """두 문서의 차이를 (JSON 포인터, 종류)로. 값은 내지 않는다."""
    a, b = dict(_flatten(planned)), dict(_flatten(existing))
    out = [(p, "existing_only") for p in sorted(set(b) - set(a))] + [(p, "planned_only") for p in sorted(set(a) - set(b))]
    out += [(p, "value_differs") for p in sorted(set(a) & set(b)) if a[p] != b[p]]
    return out


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _at(doc, pointer):
    node = doc
    for part in pointer.strip("/").split("/"):
        if not isinstance(node, dict) or part not in node:
            return None, False
        node = node[part]
    return node, True


def hash_report(plan, actual, dry_run=False):
    """옛 값(기대 값)과 새 문서에서 읽은 값의 해시 대조. (줄 목록, 불일치 수). 경로·키 이름·일치 여부만 낸다."""
    lines, bad = [], 0
    for new_doc, pointer, old_doc, old_key, expected in plan.lineage:
        got = actual.get(new_doc)
        value, found = _at(got, pointer) if got is not None else (None, False)
        status = "absent" if not found else ("match" if _hash(value) == _hash(expected) else "MISMATCH")
        if got is None:
            status = "pending" if dry_run else "absent"
        bad += status in ("MISMATCH", "absent")
        lines.append("%s\t%s\t%s\t%s\t%s" % (new_doc, pointer, old_doc, old_key, status))
    return lines, bad


def apply(plan, new_client, dry_run, lines=None):
    """문서마다 상태를 정한다. (상태 줄, 새 문서에서 읽은 내용, 다른 문서 수). 중간에 실패해도 `lines`에는 지금까지가 남는다."""
    lines = [] if lines is None else lines
    actual, differs = {}, 0
    for path in sorted(plan.store):
        mount, doc = path.split("/", 1)
        existing = new_client.read(mount, doc)
        if existing is None:
            if dry_run:
                lines.append("%s\twould-write" % path)
                continue
            if new_client.create(mount, doc, plan.store[path]):
                lines.append("%s\twritten" % path)
                actual[path] = new_client.read(mount, doc)
                continue
            existing = new_client.read(mount, doc)  # 그 사이 누가 만들었다
            if existing is None:  # 읽히지 않는 문서에 cas가 실패했다: 소프트 삭제이거나 다른 400이다
                raise ClientError("POST %s -> 400, 읽히지 않는 문서(소프트 삭제인지 확인)" % path)
        actual[path] = existing
        found = diff_keys(plan.store[path], existing)
        if not found:
            lines.append("%s\tskipped" % path)
        else:
            differs += 1
            lines.append("%s\tdiffers" % path)
            lines.extend("%s\t%s\t%s" % (path, p, kind) for p, kind in found)
    return lines, actual, differs


def read_token(path):
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    return getpass.getpass("admin token: ")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    addr = os.environ.get("VAULT_ADDR", "")
    ap.add_argument("--old-addr", default=addr)
    ap.add_argument("--new-addr", default=addr)
    ap.add_argument("--old-namespace", default="infra/prod/host")
    ap.add_argument("--old-mount", default="secret")
    ap.add_argument("--new-namespace", default="infra")
    ap.add_argument("--skip-file", help="옮기지 않을 항목 목록(YAML 리스트). 저장소에 두지 않는다")
    ap.add_argument("--token-file", help="admin 토큰 파일(없으면 getpass)")
    ap.add_argument("--ingest-source", choices=INGEST_SOURCES, default="webhook_watch",
                    help="OpenObserve 수집 계정으로 남길 쪽")
    ap.add_argument("--dry-run", action="store_true", help="검증과 비교만 하고 쓰지 않는다")
    args = ap.parse_args(argv)
    if not args.old_addr or not args.new_addr:
        print("--old-addr/--new-addr 또는 VAULT_ADDR가 필요하다", file=sys.stderr)
        return 4
    try:
        skip = yaml.safe_load(Path(args.skip_file).read_text(encoding="utf-8")) if args.skip_file else []
        if skip is not None and not (isinstance(skip, list) and all(isinstance(s, str) for s in skip)):
            raise MigrationError("skip 파일은 문자열 목록(YAML 리스트)이어야 한다")
        skip = skip or []
        token = read_token(args.token_file)
        if not token:
            raise MigrationError("토큰이 비어 있다")
        old_client = Client(args.old_addr, args.old_namespace, token)
        new_client = Client(args.new_addr, args.new_namespace, token)
        plan = build_new(read_old(old_client, args.old_mount, skip), skip, args.ingest_source)
        violations = ov.validate_store(plan.store)
        if plan.errors or violations:
            for e in plan.errors:
                print("mapping\t" + e)
            for v in violations:
                print(v.format())
            print("검증 실패: 아무것도 쓰지 않았다", file=sys.stderr)
            return 1
        lines = []
        try:
            _, actual, differs = apply(plan, new_client, args.dry_run, lines)
        except ClientError:
            print("# 쓰기 중 실패: 여기까지의 상태\n" + "\n".join(lines))
            raise
        print("# %s: %d documents" % ("dry-run" if args.dry_run else "migrate", len(plan.store)))
        print("\n".join(lines))
        report, bad = hash_report(plan, actual, args.dry_run)
        print("# hash report (old value vs new document)")
        print("\n".join(report))
    except (ClientError, MigrationError, OSError, yaml.YAMLError) as e:
        print("오류: %s" % (e if isinstance(e, (ClientError, MigrationError)) else type(e).__name__), file=sys.stderr)
        return 4
    if differs:  # 이미 있는 다른 문서의 값은 해시 불일치로도 잡히므로 차이를 먼저 알린다
        return 2
    return 3 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
