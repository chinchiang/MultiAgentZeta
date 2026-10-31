"""Regenerate the derived parts of the toolkit design documents from spec.md.

Source of truth: the requirement blocks in ``docs/toolkit/spec.md`` plus the
acceptance-group mapping in ``groups.json`` next to this script.

Generated outputs:
  * spec.md, between ``<!-- BEGIN:AG_TABLE ... -->`` / ``<!-- END:AG_TABLE -->``
  * spec.md, between ``<!-- BEGIN:APPENDIX_A ... -->`` / ``<!-- END:APPENDIX_A -->``
  * v0.1-scope.md (whole file)

Usage (from anywhere):
  python -I docs/toolkit/tools/build.py          # validate and rewrite outputs
  python -I docs/toolkit/tools/build.py --check  # validate; exit 1 if outputs are stale

Validation failures (exit 2), checked in both modes:
  * requirement blocks: missing or empty fields, invalid level or v0.1 value,
    a 須／不得 requirement whose 驗收 is "—", duplicate IDs, numbering gaps
  * groups.json: unknown groups or requirements, groups with no members
  * TK- references to unknown IDs, in spec.md and in every other repo doc
    (design notes, review log, README, GLOSSARY.md, ADRs, research notes)
  * [R] references: definitions in design-notes.md must be unique and numbered
    1..N without gaps; every [Rn] cited in spec, design notes or review log
    must be defined
  * the shared version: the header of all four documents and the version
    sentence in spec.md §0.4 must agree (v0.1-scope.md is covered by --check,
    since it is generated from spec.md)
  * line endings: no CR characters in tracked text files of the docs tooling
"""
import collections
import json
import re
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
DOCS = TOOLS.parent
REPO = DOCS.parent.parent
SPEC = DOCS / 'spec.md'
SCOPE = DOCS / 'v0.1-scope.md'
DESIGN = DOCS / 'design-notes.md'
REVIEW = DOCS / 'review-log.md'
CONFIG = TOOLS / 'groups.json'
VERSIONED = (SPEC, DESIGN, REVIEW)  # v0.1-scope.md takes its version from spec.md


def cross_ref_docs():
    """Docs other than spec.md that may cite TK- IDs."""
    files = [DESIGN, REVIEW, DOCS / 'README.md', REPO / 'GLOSSARY.md']
    files += sorted((REPO / 'docs' / 'adr').glob('*.md'))
    files += sorted((REPO / 'docs' / 'research').glob('*.md'))
    return [f for f in files if f.exists()]


def lf_files():
    """Text files that must use LF line endings."""
    files = sorted(DOCS.glob('*.md')) + sorted(TOOLS.glob('*'))
    files += [REPO / n for n in ('GLOSSARY.md', 'AGENTS.md', 'CLAUDE.md', '.gitattributes')]
    for d in ('docs/adr', 'docs/research', 'docs/agents', '.github/workflows', '.githooks'):
        files += sorted(p for p in (REPO / d).glob('*') if p.suffix != '.pdf')
    return [f for f in files if f.is_file() and '__pycache__' not in f.parts]

LEVELS = ('須', '不得', '宜', '可')
V01 = ('必做', '可延後', '不適用')
BLOCK = re.compile(r'^#### (TK-([A-Z]{3})-(\d{3})) (.+?)\n(.*?)(?=^#### |^## |^### |\Z)', re.M | re.S)
FIELD = r'^- \*\*{}\*\*：(.*)$'


def fail(msg):
    print(f'error: {msg}', file=sys.stderr)
    sys.exit(2)


def read(path):
    return path.read_text(encoding='utf-8')


def write(path, text):
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)


def parse_requirements(spec):
    reqs = []
    for m in BLOCK.finditer(spec):
        rid, area, _num, title, body = m.groups()
        fields = {}
        for name in ('等級', '條文', '驗收', 'v0.1', '理由', '來源'):
            fm = re.search(FIELD.format(re.escape(name)), body, re.M)
            if not fm:
                fail(f'{rid}: missing field {name}')
            value = fm.group(1).strip()
            # 條文 may continue as an indented list or table on the following lines.
            if not value and not (name == '條文' and re.match(r'\n(?:\n)?  \S', body[fm.end():])):
                fail(f'{rid}: field {name} is empty')
            fields[name] = value
        if fields['等級'] not in LEVELS:
            fail(f"{rid}: invalid level {fields['等級']!r}")
        if fields['v0.1'] not in V01:
            fail(f"{rid}: invalid v0.1 value {fields['v0.1']!r}")
        if fields['等級'] in ('須', '不得') and fields['驗收'].startswith('—'):
            fail(f"{rid}: {fields['等級']} requirement needs an acceptance check (驗收 is '—')")
        reqs.append(dict(id=rid, area=area, title=title.strip(), level=fields['等級'], v0=fields['v0.1']))
    if not reqs:
        fail('no requirement blocks found in spec.md')
    return reqs


def validate(reqs, spec, cfg):
    ids = [r['id'] for r in reqs]
    dup = sorted(i for i, c in collections.Counter(ids).items() if c > 1)
    if dup:
        fail(f'duplicate IDs: {dup}')
    by_area = collections.defaultdict(list)
    for r in reqs:
        by_area[r['area']].append(int(r['id'][-3:]))
    for area, nums in by_area.items():
        if sorted(nums) != list(range(1, len(nums) + 1)):
            fail(f'{area}: numbering has gaps or does not start at 001: {sorted(nums)}')
        if area not in cfg['area_default']:
            fail(f'{area}: no area_default in groups.json')
        if area not in cfg['area_names']:
            fail(f'{area}: no area_names entry in groups.json')
    known = set(ids)
    refs = set(re.findall(r'TK-[A-Z]{3}-\d{3}', spec))
    # README-style examples are not in spec.md, so every reference must resolve.
    dangling = sorted(refs - known)
    if dangling:
        fail(f'references to unknown IDs: {dangling}')
    gids = {g['id'] for g in cfg['groups']}
    for area, g in cfg['area_default'].items():
        if g not in gids:
            fail(f'area_default {area} -> unknown group {g}')
    for g, members in cfg['overrides'].items():
        if g not in gids:
            fail(f'overrides: unknown group {g}')
        for rid in members:
            if rid not in known:
                fail(f'overrides: {g} lists unknown requirement {rid}')


def validate_repo(reqs):
    """Checks that span the other documents."""
    known = {r['id'] for r in reqs}
    for f in cross_ref_docs():
        dangling = sorted(set(re.findall(r'TK-[A-Z]{3}-\d{3}', read(f))) - known)
        if dangling:
            fail(f'{f.relative_to(REPO).as_posix()}: references to unknown IDs: {dangling}')

    design = read(DESIGN)
    defined = [int(n) for n in re.findall(r'^- \*\*\[R(\d+)\]\*\*', design, re.M)]
    dup = sorted(n for n, c in collections.Counter(defined).items() if c > 1)
    if dup:
        fail(f'design-notes.md: [R] defined more than once: {dup}')
    if sorted(defined) != list(range(1, len(defined) + 1)):
        missing = sorted(set(range(1, max(defined, default=0) + 1)) - set(defined))
        fail(f'design-notes.md: [R] numbering has gaps: missing {missing}')
    for f in (SPEC, DESIGN, REVIEW):
        undefined = sorted({int(n) for n in re.findall(r'\[R(\d+)\]', read(f))} - set(defined))
        if undefined:
            fail(f'{f.name}: cites undefined references {[f"R{n}" for n in undefined]}')

    versions = {f.name: header_value(read(f), '版本', r'v\d+\.\d+\.\d+', f.name) for f in VERSIONED}
    if len(set(versions.values())) != 1:
        fail(f'document versions disagree: {versions}')
    version = versions[SPEC.name]
    m = re.search(r'本文件 (v\d+\.\d+\.\d+) 表示設計文件的修訂；不代表工具包軟體已達 (v\d+\.\d+\.\d+)。', read(SPEC))
    if not m or m.group(1) != version or m.group(2) != version:
        found = m.groups() if m else 'sentence not found'
        fail(f'spec.md §0.4 version sentence must name {version} twice; found {found}')


def check_line_endings():
    crlf = [f.relative_to(REPO).as_posix() for f in lf_files() if b'\r' in f.read_bytes()]
    if crlf:
        fail(f'CR characters (use LF line endings) in: {crlf}')


def assign_groups(reqs, cfg):
    override = {}
    for g, members in cfg['overrides'].items():
        for rid in members:
            if rid in override:
                fail(f'{rid} listed in overrides for both {override[rid]} and {g}')
            override[rid] = g
    for r in reqs:
        r['group'] = override.get(r['id'], cfg['area_default'][r['area']])


def ag_table(reqs, cfg):
    members = collections.defaultdict(list)
    for r in reqs:
        members[r['group']].append(r['id'])
    rows = ['| 群組 | 名稱 | 通過條件 | 涵蓋條文 |', '| :--- | :--- | :--- | :--- |']
    for g in cfg['groups']:
        if not members[g['id']]:
            fail(f"group {g['id']} has no members")
        cover = '、'.join(f'`{i}`' for i in members[g['id']])
        rows.append(f"| {g['id']} | {g['name']} | {g['condition']} | {cover} |")
    return '\n'.join(rows)


def appendix(reqs, cfg):
    gname = {g['id']: g['name'] for g in cfg['groups']}
    rows = ['| 條文 | 標題 | 等級 | 驗收群組 | v0.1 |', '| :--- | :--- | :--- | :--- | :--- |']
    for r in reqs:
        rows.append(f"| `{r['id']}` | {r['title']} | {r['level']} | {r['group']} {gname[r['group']]} | {r['v0']} |")
    return '\n'.join(rows)


def replace_marked(spec, name, body):
    pat = re.compile(r'(<!-- BEGIN:' + name + r'[^>]*-->\n)(.*?)(\n<!-- END:' + name + r' -->)', re.S)
    if len(pat.findall(spec)) != 1:
        fail(f'spec.md must contain exactly one BEGIN/END:{name} marker pair')
    return pat.sub(lambda m: m.group(1) + body + m.group(3), spec)


def header_value(text, label, pattern, name='spec.md'):
    m = re.search(r'^> \*\*' + label + r'\*\*：.*?(' + pattern + ')', text, re.M)
    if not m:
        fail(f'{name} header: cannot read {label}')
    return m.group(1)


def scope_doc(reqs, cfg, spec):
    version = header_value(spec, '版本', r'v\d+\.\d+\.\d+')
    date = header_value(spec, '修訂日期', r'\d{4}-\d{2}-\d{2}')
    hdr = '\n'.join([
        f'> **版本**：{version}（四份文件共用版本號）',
        f'> **修訂日期**：{date}（臺灣時間）',
        '> **文件狀態**：架構設計草案，非已實作或已驗證的聲明。',
        '> **資訊分級**：機密／僅供英業達內部使用；未取得正式文件編號或發布核准',
        '> **文件組合**：規格 [`spec.md`](spec.md)、設計說明 [`design-notes.md`](design-notes.md)、'
        '審查處置紀錄 [`review-log.md`](review-log.md)、《v0.1 最小範圍》 [`v0.1-scope.md`](v0.1-scope.md)',
    ])
    rows = ['| 領域 | 必做 | 可延後 | 不適用 |', '| :--- | :--- | :--- | :--- |']
    cnt = collections.Counter()
    for area, name in cfg['area_names'].items():
        rs = sorted((r for r in reqs if r['area'] == area), key=lambda r: r['id'])
        if not rs:
            continue

        def cell(v, rs=rs):
            return '、'.join(f"`{r['id'][3:]}`" for r in rs if r['v0'] == v) or '—'

        rows.append(f"| `{area}` {name} | {cell('必做')} | {cell('可延後')} | {cell('不適用')} |")
        cnt.update(r['v0'] for r in rs)
    if sum(cnt.values()) != len(reqs):
        fail('some areas are missing from area_names; v0.1 counts do not add up')
    table = '\n'.join(rows)
    return f'''# 《v0.1 最小範圍》

{hdr}

<!-- 本檔由 tools/build.py 依 spec.md 產生，請勿手動編輯。 -->

## 範圍定義

原型 v0.1 對應里程碑 M0、M1 及部分 M2：以政策、隔離、可靠判定與單模型，串成已知物件越權的最小流程（設計說明第 5.3 節）。

**判定原則：** v0.1 實際會執行到的功能，相關的安全控制就是必做。例如 v0.1 會呼叫模型，送出前的機密遮罩就是必做；v0.1 不做 E2 環境，E2 擁有權驗證就可延後；v0.1 只用單一模型，多模型相關條文不適用。

標為「可延後」的條文，在 v0.1 不實作也不驗收；但 v0.1 的報告不得宣稱已涵蓋這些條文的能力（`TK-SCP-006`、`TK-EVD-014`）。

## 條文清單

共 {sum(cnt.values())} 條：必做 {cnt['必做']} 條、可延後 {cnt['可延後']} 條、不適用 {cnt['不適用']} 條。下表省略 `TK-` 前綴；各條標題見規格附錄 A。

{table}
'''


def main(argv):
    check = '--check' in argv
    spec = read(SPEC)
    cfg = json.loads(read(CONFIG))
    reqs = parse_requirements(spec)
    validate(reqs, spec, cfg)
    validate_repo(reqs)
    assign_groups(reqs, cfg)
    new_spec = replace_marked(spec, 'AG_TABLE', ag_table(reqs, cfg))
    new_spec = replace_marked(new_spec, 'APPENDIX_A', appendix(reqs, cfg))
    new_scope = scope_doc(reqs, cfg, new_spec)
    outputs = [(SPEC, spec, new_spec), (SCOPE, read(SCOPE) if SCOPE.exists() else '', new_scope)]
    stale = [p.name for p, old, new in outputs if old != new]
    cnt = collections.Counter(r['v0'] for r in reqs)
    summary = f"{len(reqs)} requirements (必做 {cnt['必做']} / 可延後 {cnt['可延後']} / 不適用 {cnt['不適用']})"
    if check:
        check_line_endings()
        if stale:
            print(f'stale: {", ".join(stale)} — run tools/build.py', file=sys.stderr)
            return 1
        print(f'ok: {summary}; outputs up to date')
        return 0
    for p, old, new in outputs:
        if old != new:
            write(p, new)
    check_line_endings()
    print(f'ok: {summary}; updated: {", ".join(stale) or "nothing"}')
    return 0


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    sys.exit(main(sys.argv[1:]))
