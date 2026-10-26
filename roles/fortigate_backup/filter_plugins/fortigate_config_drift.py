"""FortiGate 설정 변경 감지 필터 (docs/fortigate_backup.md 7절, #286).

반환값에는 섹션·항목·설정 키의 이름만 담고 설정 값은 절대 담지 않는다(VPN 키·관리자 해시 보호).
"""
import re

_TS_RE = re.compile(r"_(\d{8}T\d{6})\.conf$")
_SET_WORDS = ("set", "unset", "append", "select", "unselect")
# 멤버가 달라진 비교에서는 멤버 고유 설정을 변경으로 보지 않는다.
_MEMBER_SPECIFIC = {("config system global", "hostname"), ("config system ha", "priority")}
# 내보낼 때마다 암호문이 새로 만들어지는 키(실측: 같은 설정을 연달아 받아도 값이 다르다).
# 값 차이는 변경으로 보지 않고, 키가 생기거나 사라진 경우만 변경으로 본다.
_VOLATILE = {("config system acme", "store-passphrase"), ("config system ha", "password")}


def _clean(text):
    return re.sub(r"[^\x20-\x7e]", "", str(text))[:60]


def _unbalanced(line):
    return len(re.findall(r'(?<!\\)"', line)) % 2 == 1


def _parse(content):
    """{경로 tuple: {키: 값}}. 헤더(#) 줄은 버리고 따옴표 안의 여러 줄 값은 한 값으로 합친다."""
    out = {}
    stack = []
    key = None
    open_quote = False
    for raw in str(content).splitlines():
        line = raw.strip()
        if open_quote:
            out[tuple(stack)][key] += "\n" + line
            open_quote = not _unbalanced(line)
            continue
        if not line or line.startswith("#"):
            continue
        word = line.split(None, 1)[0]
        if word in ("config", "edit"):
            stack.append(line)
        elif line in ("next", "end"):
            if stack:
                stack.pop()
        elif word in _SET_WORDS:
            parts = line.split(None, 2)
            name = parts[1] if len(parts) > 1 else ""
            key = name if word == "set" else f"{word} {name}"
            out.setdefault(tuple(stack), {})[key] = parts[2] if len(parts) > 2 else ""
            open_quote = _unbalanced(line)
    return out


def _label(path):
    """첫 edit까지를 항목 이름으로 쓴다: 'config firewall policy > edit 7'."""
    seg = []
    for p in path:
        seg.append(p)
        if p.startswith("edit "):
            break
    return " > ".join(_clean(s) for s in seg)


def fortigate_config_changes(current, previous, member_changed=False):
    if not str(previous).startswith("#config-version="):
        return []  # 손상되었거나 설정이 아닌 파일은 비교 기준으로 삼지 않는다.
    cur, prev = _parse(current), _parse(previous)
    found = {}
    for path in set(cur) | set(prev):
        c, p = cur.get(path, {}), prev.get(path, {})
        section = path[0] if path else ""
        keys = {
            k for k in set(c) | set(p)
            if c.get(k) != p.get(k)
            and not (member_changed and (section, k) in _MEMBER_SPECIFIC)
            and not ((section, k) in _VOLATILE and k in c and k in p)
        }
        if keys:
            found.setdefault(_label(path), set()).update(keys)
    labels_cur = {_label(p) for p in cur}
    labels_prev = {_label(p) for p in prev}
    result = []
    for label in sorted(found):
        if label not in labels_prev:
            state = "추가"
        elif label not in labels_cur:
            state = "삭제"
        else:
            state = "변경: " + ", ".join(_clean(k) for k in sorted(found[label])[:5])
        result.append(f"{label} ({state})")
    return result


def fortigate_backup_previous(names, current, prefix):
    """같은 접두사(`<장비>_`) 파일 중 현재 바로 앞 시각의 파일. 멤버는 무관, 정렬 키는 마지막 `_` 뒤 시각."""
    cur = _TS_RE.search(current)
    if not cur:
        return ""
    best = None
    for n in names:
        m = _TS_RE.search(n)
        if n.startswith(prefix) and m and m.group(1) < cur.group(1) and (best is None or m.group(1) > best[0]):
            best = (m.group(1), n)
    return best[1] if best else ""


def fortigate_backup_member(name, prefix):
    """파일명 `<장비>_<멤버>_<시각>.conf`에서 멤버."""
    return name[len(prefix):].rsplit("_", 1)[0]


class FilterModule(object):
    def filters(self):
        return {
            "fortigate_config_changes": fortigate_config_changes,
            "fortigate_backup_previous": fortigate_backup_previous,
            "fortigate_backup_member": fortigate_backup_member,
        }
