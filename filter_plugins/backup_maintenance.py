"""Repo Maintenance helpers (ADR-0006 §2.5, Spec #38 / Ticket-7).

Pure functions so the gating and the alert-contract payload are unit-testable without Ansible.
"""
import datetime
import zoneinfo
import re

ERROR_MAX = 500
SUBSET_MODES = ('auto', 'always', 'never')
_DELTA = re.compile(r'^(?:(\d+) days?, )?(\d+):(\d{2}):(\d{2})(?:\.\d+)?$')


def backup_maintenance_subset_due(date_iso, mode='auto', tz='Asia/Seoul'):
    """Whether this run adds ``check --read-data-subset=10%``.

    ``auto``: only on the first Sunday of the month (Sunday and day-of-month <= 7).
    ``always`` / ``never`` let a manual Semaphore run force or skip it.
    """
    mode = str(mode or 'auto').lower()
    if mode not in SUBSET_MODES:
        raise ValueError("backup_maintenance_read_subset must be one of %s: %r" % (', '.join(SUBSET_MODES), mode))
    if mode != 'auto':
        return mode == 'always'
    text = str(date_iso)
    if len(text) > 10:    # full timestamp (e.g. UTC "now"): the schedule is Sunday 05:00 local, so judge the local calendar day
        stamp = datetime.datetime.fromisoformat(text.replace('Z', '+00:00'))
        if stamp.tzinfo is not None:
            stamp = stamp.astimezone(zoneinfo.ZoneInfo(tz))
        day = stamp.date()
    else:
        day = datetime.date.fromisoformat(text)
    return day.weekday() == 6 and day.day <= 7


def _duration_seconds(delta):
    match = _DELTA.match(str(delta or '').strip())
    if not match:
        return 0
    days, hours, minutes, seconds = (int(g or 0) for g in match.groups())
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def _clean(text):
    """Printable ASCII only (one JSON line, no control characters), last non-empty lines, <= ERROR_MAX."""
    lines = [ln.strip() for ln in str(text or '').splitlines() if ln.strip()]
    flat = ' | '.join(lines[-3:])
    return re.sub(r'[^\x20-\x7e]', ' ', flat)[-ERROR_MAX:]


def backup_maintenance_event(result, host, command):
    """The ``job=maintenance`` backup_logs event for one host x command (docs/backup.md §6 contract).

    ``result`` is the registered ``ansible.builtin.command`` result (rc, delta, stderr, stdout).
    """
    success = result.get('rc', 1) == 0
    error = '' if success else _clean(result.get('stderr') or result.get('stdout') or result.get('msg'))
    return {
        'job': 'maintenance',
        'host': host,
        'command': command,
        'success': success,
        'duration': _duration_seconds(result.get('delta')),
        'error': error,
    }


def backup_maintenance_events(steps, host):
    """Events for the executed steps (``[{command, result}]``); skipped steps emit nothing."""
    return [backup_maintenance_event(s['result'], host, s['command']) for s in steps
            if not s['result'].get('skipped')]


def backup_maintenance_failed(results):
    """True when any executed (non-skipped) step failed."""
    return any(r.get('rc', 1) != 0 for r in results if r and not r.get('skipped'))


class FilterModule(object):
    def filters(self):
        return {
            'backup_maintenance_subset_due': backup_maintenance_subset_due,
            'backup_maintenance_event': backup_maintenance_event,
            'backup_maintenance_events': backup_maintenance_events,
            'backup_maintenance_failed': backup_maintenance_failed,
        }
