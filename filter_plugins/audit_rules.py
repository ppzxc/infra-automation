"""감사 규칙 적재 상태 비교 (#424).

`auditctl -l`(커널에 적재된 규칙)과 규칙 파일 본문(`audit.rules.j2`로 렌더링한 선언)을 같은 모양으로 줄여 비교한다.
`security` 역할의 `SEC-083`이 이 필터로 적재 drift를 판정하고, 핸들러가 적재 뒤 같은 필터로 결과를 확인한다.

비교 기준(근사다. 완전한 문자열 일치가 아니다):
  - watch 규칙은 (경로, 권한 문자 집합, 키)로 본다. `-w`/`-p`/`-k` 표기와 `-F path=`/`-F dir=`/`-F perm=`/`-F key=` 표기를
    같게 보고, 디렉터리 끝 `/`는 무시한다(`auditctl -l`이 찍는 방식이 감사 패키지 버전마다 다를 수 있어서다).
  - 그 밖의 규칙(syscall 등)은 키와, 키별 (arch, syscall 이름)이 적재돼 있는지를 본다. 같은 키의 줄 일부(b32 변형, open·openat의 O_TRUNC 줄)만
    거부돼도 잡기 위해서다. 줄 단위·필드 단위로는 비교하지 않는다: `auditctl -l`은 syscall을 쉼표로 합쳐 번호 순서로 찍고
    `-F auid!=-1`처럼 필드를 다르게 찍을 수 있어 문자열 비교는 오탐(매 실행 재적재·실패 반복)을 낸다. 그래서 한쪽 방향(선언 -> 적재)만 보고,
    적재가 선언보다 많이 찍히는 것(syscall·arch)은 drift로 안 본다. 한계(근사): 같은 키·arch·syscall의 줄이 필터만 달라(`-C uid!=euid`/`-C gid!=egid`,
    `-F a1&0x200`) 한쪽만 거부된 경우는 못 잡는다. `-S`에 이름 대신 번호가 찍히는 감사 패키지에서는 오탐이 날 수 있다(**미실시, #436**: 대상 감사 패키지의
    `auditctl -l` 표기 확인). arch 필드가 없는 적재 줄은 b64·b32 모두에 적재된 것으로 본다.
  - 제어 줄(`-D`, `-b`, `-f`, `-e`, `-r`, `--backlog_wait_time` 등), 주석, 빈 줄, `No rules`는 규칙이 아니다.
  - 같은 규칙의 중복과 줄 순서는 무시한다.

`augenrules --load`는 `/etc/audit/rules.d/*.rules`를 모두 합쳐 적재한다(augenrules(8): "merges all component audit rules files"). 그래서 이 역할이 만든
`overseer.rules` 밖의 `.rules` 파일(하드닝 프로파일, 손으로 둔 파일)의 규칙도 정상 적재 결과에 들어간다. `audit_rules_probe_drift`는 조회 출력의
`MARKER` 뒤에 그 파일들의 내용을 받아 선언에 합친다. 안 그러면 그런 호스트는 매 실행 drift로 보이고 적재·확인 실패가 반복된다.
"""

MARKER = "__OVERSEER_OTHER_RULES__"

_CONTROL = {"-D", "-b", "-f", "-e", "-r", "-i", "-c"}


def _signature(line):
    """규칙 한 줄을 서명 목록으로 줄인다. 규칙이 아니면 빈 목록.

    ('watch', 경로, 권한, 키) / ('key', 키) / ('sys', 키, arch 또는 None, syscall 이름). syscall 줄(`-S`)은 `-F dir=` 필터가 있어도 watch가 아니다.
    """
    line = line.strip()
    if not line or line.startswith("#") or line.lower().startswith("no rules"):
        return []
    tokens = line.split()
    if tokens[0] in _CONTROL or tokens[0].startswith("--"):
        return []
    path, perms, key, arch, syscalls = None, "", "", None, []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        if tok == "-w":
            path, i = nxt, i + 2
        elif tok == "-p":
            perms, i = nxt, i + 2
        elif tok == "-k":
            key, i = nxt, i + 2
        elif tok == "-S":
            syscalls += [n for n in nxt.split(",") if n]
            i += 2
        elif tok == "-F" and "=" in nxt:
            name, _, value = nxt.partition("=")
            if name in ("path", "dir"):
                path = value
            elif name == "perm":
                perms = value
            elif name == "key":
                key = value
            elif name == "arch":
                arch = value
            i += 2
        else:
            i += 1
    if syscalls:
        return [("key", key)] + [("sys", key, arch, n) for n in syscalls]
    if path is None:
        return [("key", key)]
    perms = perms or "rwxa"  # `-p` 없는 watch는 모든 권한이다(auditctl -l도 -p rwxa로 찍는다)
    canonical = "".join(c for c in "rwxa" if c in perms) + "".join(sorted(set(perms) - set("rwxa")))
    return [("watch", path.rstrip("/") or "/", canonical, key)]


def _signatures(text):
    found = {}
    for line in str(text or "").splitlines():
        for sig in _signature(line):
            found[sig] = None  # 순서를 지키는 집합
    return list(found)


def _describe(sig):
    if sig[0] == "key":
        return "키 %s" % sig[1] if sig[1] else "키 없는 규칙"
    if sig[0] == "sys":
        return "키 %s의 %ssyscall %s" % (sig[1] or "(키 없음)", (sig[2] + " ") if sig[2] else "", sig[3])
    _, path, perms, key = sig
    text = "watch %s 권한 %s" % (path, perms)
    return text + (" 키 %s" % key if key else "")


_ARCHES = ("b64", "b32")


def _missing_syscalls(loaded_sigs, declared_sigs):
    """선언한 (키, arch)별 syscall 이름 중 적재에 없는 것을 ('sys', 키, arch, '이름,이름') 서명으로. 키 자체가 적재 안 된 경우는 키 서명이 이미 알리므로 건너뛴다."""
    loaded_keys = {s[1] for s in loaded_sigs if s[0] == "key"}
    have = set()
    for s in loaded_sigs:
        if s[0] == "sys":
            for arch in ((s[2],) if s[2] else _ARCHES):
                have.add((s[1], arch, s[3]))
    need = {}
    for s in declared_sigs:
        if s[0] == "sys" and s[1] in loaded_keys:
            need.setdefault((s[1], s[2]), []).append(s[3])
    out = []
    for (key, arch), names in need.items():
        absent = [n for n in names if not any((key, a, n) in have for a in ((arch,) if arch else _ARCHES))]
        if absent:
            out.append(("sys", key, arch, ",".join(absent)))
    return out


def _diff(loaded, declared):
    loaded_sigs, declared_sigs = _signatures(loaded), _signatures(declared)
    missing = [s for s in declared_sigs if s[0] != "sys" and s not in loaded_sigs]
    missing += _missing_syscalls(loaded_sigs, declared_sigs)
    return (missing, [s for s in loaded_sigs if s[0] != "sys" and s not in declared_sigs])


def audit_rules_drift(loaded, declared):
    """적재된 규칙(`auditctl -l` 출력)과 선언한 규칙 파일 본문의 차이. 같으면 빈 목록. 경로가 들어 있으므로 실행 로그에 직접 싣지 않는다."""
    missing, extra = _diff(loaded, declared)
    return (["적재 안 됨: %s" % _describe(s) for s in missing]
            + ["선언에 없는 규칙이 적재됨: %s" % _describe(s) for s in extra])


def _keys(sigs):
    names = sorted({s[1] if s[0] in ("key", "sys") else s[3] for s in sigs})
    return ", ".join(n or "(키 없음)" for n in names)


def audit_rules_probe_drift(output, declared):
    """`auditctl -l` 출력 + MARKER 줄 + 다른 rules.d 파일 내용(조회 스크립트의 출력)을 선언과 비교한다. MARKER가 없으면 앞의 비교와 같다."""
    loaded, _, other = str(output or "").partition(MARKER)
    return audit_rules_drift(loaded, str(declared or "") + "\n" + other)


def audit_rules_drift_summary(output, declared):
    """`audit_rules_probe_drift`의 차이를 건수와 키 이름으로만 줄인 한 줄(경로 없음, 시크릿 감시 경로가 실행 로그에 남지 않게). 같으면 빈 문자열."""
    loaded, _, other = str(output or "").partition(MARKER)
    missing, extra = _diff(loaded, str(declared or "") + "\n" + other)
    parts = []
    if missing:
        parts.append("적재 안 됨 %d건(키: %s)" % (len(missing), _keys(missing)))
    if extra:
        parts.append("선언에 없는 규칙 %d건(키: %s)" % (len(extra), _keys(extra)))
    return ", ".join(parts)


class FilterModule(object):
    def filters(self):
        return {"audit_rules_drift": audit_rules_drift, "audit_rules_probe_drift": audit_rules_probe_drift,
                "audit_rules_drift_summary": audit_rules_drift_summary}
