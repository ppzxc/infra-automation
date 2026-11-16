#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Host Audit — write a one-sheet xlsx with the standard library only (Spec #488 / Ticket-6, #494).

The Remediation Plan of a host is a plain table: one sheet, strings and integers, a bold header, column widths,
wrapped cells and a frozen header row. That is small enough to write with ``zipfile`` and a few XML parts, so the
runner image gets no spreadsheet library. Every zip member carries the same fixed timestamp and the members are
written in a fixed order, so the same input always gives the same bytes (the SHA-256 kept with the report proves it).
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: host_audit_xlsx_write
short_description: Write a one-sheet xlsx (header, rows, footer lines) deterministically
description:
  - Writes C(headers), C(rows) and C(footer) as one worksheet of an xlsx file at C(dest) (mode 0600).
  - Cells are strings or integers. The header row is bold, every table cell wraps, the header row is frozen and
    the columns have the given widths. The footer lines follow the rows after one blank row, in column A.
  - Zip member times are fixed, so the same input gives the same bytes. The file is left alone when it already holds them.
options:
  dest:
    description: Path of the xlsx file. The parent directory is created (mode 0700) when it does not exist.
    type: path
    required: true
  sheet:
    description: Sheet name.
    type: str
    default: Sheet1
  headers:
    description: Header cells (strings).
    type: list
    elements: str
    required: true
  rows:
    description: Rows of strings and integers, each as long as C(headers).
    type: list
    elements: list
    default: []
  footer:
    description: Lines written below the rows.
    type: list
    elements: str
    default: []
  widths:
    description: Column widths in characters, one per header (default 16).
    type: list
    elements: int
    default: []
author:
  - infra-automation
'''

EXAMPLES = r'''
- name: Write the Remediation Plan of a host
  host_audit_xlsx_write:
    dest: /tmp/host_audit/run/xlsx/host-audit-run-host.xlsx
    sheet: 이행계획서
    headers: ["그룹", "자산명"]
    rows: [["계정 관리", "host"]]
    footer: ["실행 ID: run"]
'''

RETURN = r'''
dest:
  description: Path of the file.
  returned: always
  type: str
'''

import io
import os
import re
import zipfile

from ansible.module_utils.basic import AnsibleModule

FIXED_TIME = (1980, 1, 1, 0, 0, 0)  # the earliest time a zip member can carry
DEFAULT_WIDTH = 16
MAX_CELL = 32767  # characters an xlsx cell can hold
_ILLEGAL = re.compile(u'[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]')  # incl. lone surrogates (not encodable)

# cellXfs: 0 plain, 1 header (bold, wrap, top), 2 body (wrap, top), 3 footer (top, no wrap)
STYLE_HEADER, STYLE_BODY, STYLE_FOOTER = 1, 2, 3


def _text(value):
    value = _ILLEGAL.sub(u'', value.replace(u'\r\n', u'\n').replace(u'\r', u'\n'))
    if len(value) > MAX_CELL:
        value = value[:MAX_CELL - 1] + u'…'
    return value.replace(u'&', u'&amp;').replace(u'<', u'&lt;').replace(u'>', u'&gt;')


def _column(index):
    name = u''
    index += 1
    while index:
        index, rest = divmod(index - 1, 26)
        name = u'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[rest] + name
    return name


def _cell(row, col, value, style):
    ref = u'%s%d' % (_column(col), row)
    if value is None:
        value = u''
    elif isinstance(value, bool) or not isinstance(value, (int, str)):
        value = str(value)  # a float or another type is written as its text rather than failing the whole run
    if isinstance(value, int):
        return u'<c r="%s" s="%d"><v>%d</v></c>' % (ref, style, value)
    if value == u'':
        return u'<c r="%s" s="%d"/>' % (ref, style)
    return u'<c r="%s" s="%d" t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>' % (ref, style, _text(value))


def _sheet_xml(headers, rows, footer, widths):
    cols = u''.join(u'<col min="%d" max="%d" width="%d" customWidth="1"/>' % (i + 1, i + 1, w)
                    for i, w in enumerate(widths))
    lines = [(1, [(c, h, STYLE_HEADER) for c, h in enumerate(headers)])]
    for number, row in enumerate(rows, 2):
        lines.append((number, [(c, v, STYLE_BODY) for c, v in enumerate(row)]))
    start = len(rows) + 3  # one blank row between the table and the footer
    for offset, line in enumerate(footer):
        lines.append((start + offset, [(0, line, STYLE_FOOTER)]))
    body = u''.join(u'<row r="%d">%s</row>' % (n, u''.join(_cell(n, c, v, s) for c, v, s in cells))
                    for n, cells in lines)
    return (u'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            u'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            u'<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" '
            u'state="frozen"/><selection pane="bottomLeft"/></sheetView></sheetViews>'
            u'<sheetFormatPr defaultRowHeight="15"/><cols>%s</cols><sheetData>%s</sheetData></worksheet>'
            % (cols, body))


_CONTENT_TYPES = (
    u'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    u'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    u'<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    u'<Default Extension="xml" ContentType="application/xml"/>'
    u'<Override PartName="/xl/workbook.xml" '
    u'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
    u'<Override PartName="/xl/worksheets/sheet1.xml" '
    u'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
    u'<Override PartName="/xl/styles.xml" '
    u'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
    u'</Types>')

_ROOT_RELS = (
    u'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    u'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    u'<Relationship Id="rId1" '
    u'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
    u'Target="xl/workbook.xml"/></Relationships>')

_WORKBOOK_RELS = (
    u'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    u'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    u'<Relationship Id="rId1" '
    u'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
    u'Target="worksheets/sheet1.xml"/>'
    u'<Relationship Id="rId2" '
    u'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
    u'Target="styles.xml"/></Relationships>')

_STYLES = (
    u'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    u'<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    u'<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
    u'<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
    u'<fills count="2"><fill><patternFill patternType="none"/></fill>'
    u'<fill><patternFill patternType="gray125"/></fill></fills>'
    u'<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
    u'<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
    u'<cellXfs count="4">'
    u'<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
    u'<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1" applyAlignment="1">'
    u'<alignment vertical="top" wrapText="1"/></xf>'
    u'<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1">'
    u'<alignment vertical="top" wrapText="1"/></xf>'
    u'<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1">'
    u'<alignment vertical="top"/></xf>'
    u'</cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>')


def _workbook(sheet):
    name = _text(sheet).replace(u'"', u'&quot;')
    return (u'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            u'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            u'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            u'<sheets><sheet name="%s" sheetId="1" r:id="rId1"/></sheets></workbook>' % name)


def build_xlsx(sheet, headers, rows, footer, widths):
    """The bytes of the workbook. Raises ValueError for a row that does not fit the header or an unsupported cell."""
    headers = list(headers)
    if not headers:
        raise ValueError('headers must not be empty')
    if not sheet or len(sheet) > 31 or re.search(r'[\[\]:*?/\\]', sheet):
        raise ValueError('sheet name must be 1 to 31 characters without [ ] : * ? / \\')
    for number, row in enumerate(rows, 2):
        if len(row) != len(headers):
            raise ValueError('row %d has %d cells, the header has %d' % (number, len(row), len(headers)))
    widths = [int(w) for w in widths] + [DEFAULT_WIDTH] * (len(headers) - len(widths))
    parts = [
        (u'[Content_Types].xml', _CONTENT_TYPES),
        (u'_rels/.rels', _ROOT_RELS),
        (u'xl/workbook.xml', _workbook(sheet)),
        (u'xl/_rels/workbook.xml.rels', _WORKBOOK_RELS),
        (u'xl/styles.xml', _STYLES),
        (u'xl/worksheets/sheet1.xml', _sheet_xml(headers, rows, footer, widths[:len(headers)])),
    ]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, xml in parts:
            info = zipfile.ZipInfo(name, FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            info.create_system = 3  # fixed (unix), not the platform the module happens to run on
            archive.writestr(info, xml.encode('utf-8'))
    return buffer.getvalue()


def _same(dest, data):
    """True when dest already holds exactly these bytes with mode 0600 (anything else is a change)."""
    try:
        with open(dest, 'rb') as handle:
            return handle.read() == data and (os.stat(dest).st_mode & 0o777) == 0o600
    except (IOError, OSError):
        return False


def _write(dest, data):
    """Write atomically with mode 0600; returns True when the file changed."""
    if _same(dest, data):
        return False
    directory = os.path.dirname(dest) or '.'
    if not os.path.isdir(directory):
        os.makedirs(directory, 0o700)
        os.chmod(directory, 0o700)
    tmp = '%s.%d.tmp' % (dest, os.getpid())
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
        os.replace(tmp, dest)
    except BaseException:
        # A leftover .tmp in xlsx/ would be found and kept by AUD-512.
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    return True


def main():
    module = AnsibleModule(
        argument_spec=dict(
            dest=dict(type='path', required=True),
            sheet=dict(type='str', default='Sheet1'),
            headers=dict(type='list', elements='str', required=True),
            # rows carry host evidence: keep them out of the invocation output but leave the error message visible.
            rows=dict(type='list', elements='list', default=[], no_log=True),
            footer=dict(type='list', elements='str', default=[]),
            widths=dict(type='list', elements='int', default=[]),
        ),
        supports_check_mode=True,
    )
    p = module.params
    try:
        data = build_xlsx(p['sheet'], p['headers'], p['rows'], p['footer'], p['widths'])
    except ValueError as exc:
        module.fail_json(msg=str(exc))
    changed = (not _same(p['dest'], data)) if module.check_mode else _write(p['dest'], data)
    module.exit_json(changed=changed, dest=p['dest'])


if __name__ == '__main__':
    main()
