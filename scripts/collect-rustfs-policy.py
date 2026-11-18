#!/usr/bin/env python3
"""RustFS 사용자·그룹·서비스 계정·정책 읽기 전용 수집기 (#368, Spec #364).

관리 API의 GET 조회만 쓴다. 접근키는 출력하지 않고 해시 앞 12자(key_id)로만 기록하며
비밀키는 어디에도 쓰지 않는다. 주소·리전은 OpenBao `inventory/services/rustfs`, 유지보수 키는
`secrets/services/rustfs/maintenance`에서 읽는다(네임스페이스 `infra`, Spec #511).
접속은 운영자 `operator` 토큰이다: 환경변수 VAULT_ADDR/VAULT_TOKEN(선택 VAULT_NAMESPACE) 또는 --env-file(줄 단위로 파싱).

사용법:
  scripts/collect-rustfs-policy.py --label ns0331 --env-file <저장소 루트 .env>
결과는 collect-security-baseline.sh와 같은 비공개 경로의
baseline/<label>/<시각>/rustfs-policy.txt(0600)에만 저장한다. 저장소 안 경로는 거부한다.
"""
import argparse
import datetime
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent / "lookup_plugins"))   # 끝에 붙인다(stdlib·scripts/ 이름을 가리지 않는다)
import _bao_http  # noqa: E402

ADMIN = "/rustfs/admin/v3"
DEFAULT_BASE = Path.home() / ".local/share/infra-automation/sec-review-20261026/baseline"
SECRET_PATTERN = re.compile(
    r"BEGIN [A-Z ]*PRIVATE KEY|[A-Za-z_]*(SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY)[A-Za-z_]*[=:] *[^ ]", re.I
)


def key_id(access_key):
    return hashlib.sha256(access_key.encode()).hexdigest()[:12]


def _hmac(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def make_fetch(endpoint, access_key, secret_key, region="us-east-1"):
    """SigV4로 서명한 GET만 보내는 fetch(path, query) -> JSON."""
    host = urllib.parse.urlparse(endpoint).netloc

    def fetch(path, query=None):
        query = query or {}
        now = datetime.datetime.now(datetime.timezone.utc)
        amz, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
        payload = hashlib.sha256(b"").hexdigest()
        cq = "&".join(
            f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}" for k, v in sorted(query.items())
        )
        signed = "host;x-amz-content-sha256;x-amz-date"
        canonical = (f"GET\n{path}\n{cq}\nhost:{host}\nx-amz-content-sha256:{payload}\n"
                     f"x-amz-date:{amz}\n\n{signed}\n{payload}")
        scope = f"{day}/{region}/s3/aws4_request"
        to_sign = f"AWS4-HMAC-SHA256\n{amz}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}"
        k = _hmac(_hmac(_hmac(_hmac(("AWS4" + secret_key).encode(), day), region), "s3"), "aws4_request")
        sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
        req = urllib.request.Request(
            endpoint + path + (("?" + cq) if cq else ""), method="GET",
            headers={"x-amz-date": amz, "x-amz-content-sha256": payload,
                     "Authorization": (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
                                       f"SignedHeaders={signed}, Signature={sig}")},
        )
        try:
            with _bao_http.urlopen(req, timeout=30) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise SystemExit(f"RustFS API 오류 {e.code}: {path}")

    return fetch


def _statements(policy):
    """정책(JSON 문자열 또는 dict)을 정렬된 줄로 요약한다."""
    if isinstance(policy, str):
        policy = json.loads(policy) if policy.strip() else {}
    lines = []
    for st in policy.get("Statement", []):
        def as_list(v):
            return sorted(v) if isinstance(v, list) else [v]
        lines.append(f"{st.get('Effect')} actions={as_list(st.get('Action', []))} "
                     f"resources={as_list(st.get('Resource', []))}")
    return sorted(lines)


def build_report(fetch):
    out = []
    users = fetch(f"{ADMIN}/list-users")
    out.append("## users")
    for name in sorted(users):
        out.append(f"{name} policy={users[name].get('policyName')} status={users[name].get('status')}")
    out.append("\n## groups")
    for g in sorted(fetch(f"{ADMIN}/groups")):
        info = fetch(f"{ADMIN}/group", {"group": g})
        out.append(f"{g} policy={info.get('policy')} status={info.get('status')} members={sorted(info.get('members', []))}")
    out.append("\n## canned-policies")
    for name in sorted(fetch(f"{ADMIN}/list-canned-policies")):
        out.append(f"[{name}]")
        out.extend("  " + l for l in _statements(fetch(f"{ADMIN}/info-canned-policy", {"name": name}).get("policy", {})))
    out.append("\n## service-accounts")
    rows = []
    for parent in sorted(users):
        for acc in fetch(f"{ADMIN}/list-service-accounts", {"user": parent}).get("accounts", []):
            ak = acc["accessKey"]
            info = fetch(f"{ADMIN}/info-service-account", {"accessKey": ak})
            policy = "\n".join("    " + l for l in _statements(info.get("policy", "")))
            rows.append((
                f"{key_id(ak)} name={acc.get('name')} parent={acc.get('parentUser')} "
                f"status={acc.get('accountStatus')} implied={acc.get('impliedPolicy')} "
                f"expiration={acc.get('expiration')}", policy))
    for head, policy in sorted(rows):
        out.append(head + ("\n" + policy if policy else ""))
    return "\n".join(out) + "\n"


def _parse_env_file(path):
    env = {}
    for line in Path(path).read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def _openbao_doc(addr, token, namespace, mount, doc):
    req = urllib.request.Request(f"{addr.rstrip('/')}/v1/{mount}/data/{doc}",
                                 headers={"X-Vault-Token": token, "X-Vault-Namespace": namespace})
    try:
        with _bao_http.urlopen(req, timeout=30) as r:
            body = json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise SystemExit(f"OpenBao 조회 실패: {mount}/{doc} (HTTP {e.code})")
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise SystemExit(f"OpenBao 접속 실패: {mount}/{doc} ({type(e).__name__})")
    data = ((body or {}).get("data") or {}).get("data")
    if not isinstance(data, dict):
        raise SystemExit(f"OpenBao 응답에 문서 데이터가 없습니다: {mount}/{doc}")
    return data


def read_rustfs_service(env):
    """RustFS 주소·리전과 유지보수 키를 새 구조에서 읽는다. 없는 문서·키는 대체값 없이 멈춘다."""
    addr, token = env.get("VAULT_ADDR"), env.get("VAULT_TOKEN")
    if not addr or not token:
        raise SystemExit("VAULT_ADDR와 VAULT_TOKEN(운영자 operator 토큰)이 필요합니다.")
    ns = env.get("VAULT_NAMESPACE") or "infra"
    svc = _openbao_doc(addr, token, ns, "inventory", "services/rustfs")
    key = _openbao_doc(addr, token, ns, "secrets", "services/rustfs/maintenance")
    try:
        return {"endpoint": svc["url"], "region": svc.get("region") or "us-east-1",
                "access_key": key["access_key"], "secret_key": key["secret_key"]}
    except KeyError as e:
        raise SystemExit(f"필수 키가 없습니다: {e.args[0]}")


def _check_out_dir(base):
    probe = base
    while not probe.exists():
        probe = probe.parent
    clean = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    top = subprocess.run(["git", "-C", str(probe), "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True, env=clean)
    if top.returncode == 0:
        raise SystemExit(f"거부: 결과 경로가 git 저장소({top.stdout.strip()}) 안입니다.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--env-file")
    ap.add_argument("--out", default=str(DEFAULT_BASE))
    args = ap.parse_args()
    env = dict(os.environ)
    if args.env_file:
        env = {**_parse_env_file(args.env_file), **env}
    base = Path(args.out)
    _check_out_dir(base)
    kv = read_rustfs_service(env)
    report = build_report(make_fetch(kv["endpoint"], kv["access_key"], kv["secret_key"], kv["region"]))
    if SECRET_PATTERN.search(report) or kv["secret_key"] in report:
        raise SystemExit("거부: 결과에 시크릿으로 보이는 패턴이 있어 저장하지 않습니다.")
    out = base / args.label / datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    out.mkdir(parents=True, mode=0o700)
    target = out / "rustfs-policy.txt"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(report)
    print(target)


if __name__ == "__main__":
    sys.exit(main())
