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

Exit codes: 0 ok; 1 outputs stale (--check only); 2 validation problems.
Nothing is written while any problem is reported.

Structure: ``check_docs(snapshot)`` is the whole check. It takes a snapshot
(repo-relative POSIX path -> file text, CR characters preserved) and returns
the problems, the outputs that need rewriting, and requirement counts. It reads
no files itself. ``load_snapshot`` (disk) and the tests (in memory) build
snapshots; ``main`` turns the result into output, writes and an exit code.

Problems are reported per stage: if requirement blocks or groups.json cannot be
parsed, only those problems are reported; otherwise every remaining check runs
and all its problems are reported together. Checks:
  * requirement blocks: missing or empty fields, invalid level or v0.1 value,
    a 須／不得 requirement whose 驗收 is "—", duplicate IDs, numbering gaps
  * groups.json: unknown groups or requirements, requirements listed in two
    overrides, areas without area_default/area_names, groups with no members
  * TK- references to unknown IDs, in spec.md and in every other repo doc
    (design notes, review log, README, GLOSSARY.md, ADRs, research notes)
  * 〈定義：〇〇〉 references to a missing '### 定義：〇〇' section of spec.md, in
    spec.md, the docs above, docs/agents/, and toolkit/ code and schemas
  * [R] references: definitions in design-notes.md must be unique and numbered
    1..N without gaps; every [Rn] cited in spec, design notes or review log
    must be defined
  * the shared version: the header of all four documents and the version
    sentence in spec.md §0.4 must agree (v0.1-scope.md is covered by the
    staleness check, since it is generated from spec.md)
  * line endings: no CR characters in tracked text files of the docs tooling
  * generated outputs: exactly one BEGIN/END marker pair per generated region
"""
import collections
import json
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]

SPEC = 'docs/toolkit/spec.md'
SCOPE = 'docs/toolkit/v0.1-scope.md'
DESIGN = 'docs/toolkit/design-notes.md'
REVIEW = 'docs/toolkit/review-log.md'
README = 'docs/toolkit/README.md'
CONFIG = 'docs/toolkit/tools/groups.json'
VERSIONED = (SPEC, DESIGN, REVIEW)  # v0.1-scope.md takes its version from spec.md

LEVELS = ('須', '不得', '宜', '可')
V01 = ('必做', '可延後', '不適用')
FIELDS = ('等級', '條文', '驗收', 'v0.1', '理由', '來源')
BLOCK = re.compile(r'^#### (TK-([A-Z]{3})-(\d{3})) (.+?)\n(.*?)(?=^#### |^## |^### |\Z)', re.M | re.S)
FIELD = r'^- \*\*{}\*\*：(.*)$'
TK_REF = re.compile(r'TK-[A-Z]{3}-\d{3}')
DEF_HEADING = re.compile(r'^### 定義：(.+?)\s*$', re.M)
DEF_REF = re.compile(r'〈定義：([^〉]+)〉')
DEF_PLACEHOLDER = '〇〇'  # the name used when docs describe the reference format itself
VERSION_SENTENCE = re.compile(r'本文件 (v\d+\.\d+\.\d+) 表示設計文件的修訂；不代表工具包軟體已達 (v\d+\.\d+\.\d+)。')

Problem = collections.namedtuple('Problem', 'rule file message')
Result = collections.namedtuple('Result', 'problems updates counts')


class Invalid(Exception):
    """Raised inside a stage when a problem makes the rest of that stage meaningless."""

    def __init__(self, rule, file, message):
        super().__init__(message)
        self.problem = Problem(rule, file, message)


# --- which files each rule applies to ---------------------------------------

def _in_dir(path, d):
    """True if path is directly inside directory d (not in a subdirectory)."""
    return path.startswith(d + '/') and '/' not in path[len(d) + 1:]


def cross_ref_docs(paths):
    """Docs other than spec.md that may cite TK- IDs."""
    fixed = [DESIGN, REVIEW, README, 'GLOSSARY.md', 'CODING_STANDARDS.md']
    dirs = sorted(p for p in paths if p.endswith('.md') and (_in_dir(p, 'docs/adr') or _in_dir(p, 'docs/research')))
    return [p for p in fixed if p in paths] + dirs


def def_ref_files(paths):
    """Files whose 〈定義：〇〇〉 references are checked: spec.md, the cross-ref docs,
    docs/agents/, and the toolkit's code and schemas (samples/ is test subject, not checked)."""
    docs = [SPEC] + cross_ref_docs(paths) + sorted(p for p in paths if p.endswith('.md') and _in_dir(p, 'docs/agents'))
    code = sorted(p for p in paths if p.startswith('toolkit/') and p.endswith(('.py', '.json')))
    return [p for p in docs if p in paths] + code


def lf_files(paths):
    """Text files that must use LF line endings."""
    root = {'GLOSSARY.md', 'AGENTS.md', 'CLAUDE.md', 'CODING_STANDARDS.md', '.gitattributes', '.gitignore',
            '.claude/settings.json'}
    dirs = ('docs/adr', 'docs/research', 'docs/agents', '.github/workflows', '.githooks', 'docs/toolkit/tools')

    def wanted(p):
        if p in root or any(_in_dir(p, d) for d in dirs):
            return True
        return _in_dir(p, 'docs/toolkit') and p.endswith('.md')

    return sorted(p for p in paths if wanted(p) and not p.endswith('.pdf'))


# --- stage 1: parse -----------------------------------------------------------

def parse_requirements(spec):
    """Return (requirements, problems). Blocks with problems are left out."""
    reqs, problems = [], []
    for m in BLOCK.finditer(spec):
        rid, area, _num, title, body = m.groups()
        fields, bad = {}, []
        for name in FIELDS:
            fm = re.search(FIELD.format(re.escape(name)), body, re.M)
            if not fm:
                bad.append(Problem('missing-field', SPEC, f'{rid}: missing field {name}'))
                continue
            value = fm.group(1).strip()
            # 條文 may continue as an indented list or table on the following lines.
            if not value and not (name == '條文' and re.match(r'\n(?:\n)?  \S', body[fm.end():])):
                bad.append(Problem('empty-field', SPEC, f'{rid}: field {name} is empty'))
            fields[name] = value
        level, v0 = fields.get('等級'), fields.get('v0.1')
        if level is not None and level and level not in LEVELS:
            bad.append(Problem('invalid-level', SPEC, f'{rid}: invalid level {level!r}'))
        if v0 is not None and v0 and v0 not in V01:
            bad.append(Problem('invalid-v01', SPEC, f'{rid}: invalid v0.1 value {v0!r}'))
        if level in ('須', '不得') and fields.get('驗收', '').startswith('—'):
            bad.append(Problem('missing-acceptance', SPEC,
                               f"{rid}: {level} requirement needs an acceptance check (驗收 is '—')"))
        problems += bad
        if not bad:
            reqs.append(dict(id=rid, area=area, title=title.strip(), level=level, v0=v0))
    if not reqs and not problems:
        problems.append(Problem('no-requirements', SPEC, 'no requirement blocks found'))
    return reqs, problems


def parse_config(snapshot):
    if CONFIG not in snapshot:
        raise Invalid('missing-file', CONFIG, 'file not found')
    try:
        cfg = json.loads(snapshot[CONFIG])
    except json.JSONDecodeError as e:
        raise Invalid('invalid-config', CONFIG, f'not valid JSON: {e}')
    missing = [k for k in ('groups', 'area_default', 'overrides', 'area_names') if k not in cfg]
    if missing:
        raise Invalid('invalid-config', CONFIG, f'missing keys: {missing}')
    return cfg


# --- stage 2: validate --------------------------------------------------------

def validate_requirements(reqs, spec, cfg):
    problems = []
    ids = [r['id'] for r in reqs]
    dup = sorted(i for i, c in collections.Counter(ids).items() if c > 1)
    if dup:
        problems.append(Problem('duplicate-id', SPEC, f'duplicate IDs: {dup}'))
    by_area = collections.defaultdict(list)
    for r in reqs:
        by_area[r['area']].append(int(r['id'][-3:]))
    for area, nums in by_area.items():
        if sorted(nums) != list(range(1, len(nums) + 1)):
            problems.append(Problem('numbering-gap', SPEC,
                                    f'{area}: numbering has gaps or does not start at 001: {sorted(nums)}'))
        if area not in cfg['area_default']:
            problems.append(Problem('area-not-configured', CONFIG, f'{area}: no area_default entry'))
        if area not in cfg['area_names']:
            problems.append(Problem('area-not-configured', CONFIG, f'{area}: no area_names entry'))
    dangling = sorted(set(TK_REF.findall(spec)) - set(ids))
    if dangling:
        problems.append(Problem('dangling-ref', SPEC, f'references to unknown IDs: {dangling}'))
    return problems


def validate_config(reqs, cfg):
    problems = []
    known = {r['id'] for r in reqs}
    gids = {g['id'] for g in cfg['groups']}
    for area, g in cfg['area_default'].items():
        if g not in gids:
            problems.append(Problem('unknown-group', CONFIG, f'area_default {area} -> unknown group {g}'))
    seen = {}
    for g, members in cfg['overrides'].items():
        if g not in gids:
            problems.append(Problem('unknown-group', CONFIG, f'overrides: unknown group {g}'))
        for rid in members:
            if rid not in known:
                problems.append(Problem('unknown-requirement', CONFIG, f'overrides: {g} lists unknown requirement {rid}'))
            if rid in seen:
                problems.append(Problem('duplicate-override', CONFIG,
                                        f'{rid} listed in overrides for both {seen[rid]} and {g}'))
            seen.setdefault(rid, g)
    return problems


def validate_cross_refs(reqs, snapshot):
    problems = []
    known = {r['id'] for r in reqs}
    for f in cross_ref_docs(snapshot):
        dangling = sorted(set(TK_REF.findall(snapshot[f])) - known)
        if dangling:
            problems.append(Problem('dangling-ref', f, f'references to unknown IDs: {dangling}'))

    definitions = set(DEF_HEADING.findall(snapshot.get(SPEC, ''))) | {DEF_PLACEHOLDER}
    for f in def_ref_files(snapshot):
        dangling = sorted(set(DEF_REF.findall(snapshot[f])) - definitions)
        if dangling:
            problems.append(Problem('dangling-def', f, f'references to unknown 定義 sections: {dangling}'))

    design = snapshot.get(DESIGN, '')
    defined = [int(n) for n in re.findall(r'^- \*\*\[R(\d+)\]\*\*', design, re.M)]
    dup = sorted(n for n, c in collections.Counter(defined).items() if c > 1)
    if dup:
        problems.append(Problem('r-duplicate', DESIGN, f'[R] defined more than once: {dup}'))
    missing = sorted(set(range(1, max(defined, default=0) + 1)) - set(defined))
    if missing:
        problems.append(Problem('r-gap', DESIGN, f'[R] numbering has gaps: missing {missing}'))
    for f in (SPEC, DESIGN, REVIEW):
        undefined = sorted({int(n) for n in re.findall(r'\[R(\d+)\]', snapshot.get(f, ''))} - set(defined))
        if undefined:
            problems.append(Problem('r-undefined', f, f'cites undefined references {[f"R{n}" for n in undefined]}'))
    return problems


def header_value(text, label, pattern, file):
    m = re.search(r'^> \*\*' + label + r'\*\*：.*?(' + pattern + ')', text, re.M)
    if not m:
        raise Invalid('header-missing', file, f'header: cannot read {label}')
    return m.group(1)


def validate_versions(snapshot):
    problems, versions = [], {}
    for f in VERSIONED:
        try:
            versions[f] = header_value(snapshot.get(f, ''), '版本', r'v\d+\.\d+\.\d+', f)
        except Invalid as e:
            problems.append(e.problem)
    if problems:
        return problems
    if len(set(versions.values())) != 1:
        shown = {Path(f).name: v for f, v in versions.items()}
        return [Problem('version-mismatch', '', f'document versions disagree: {shown}')]
    version = versions[SPEC]
    m = VERSION_SENTENCE.search(snapshot[SPEC])
    if not m or m.group(1) != version or m.group(2) != version:
        found = m.groups() if m else 'sentence not found'
        problems.append(Problem('version-sentence', SPEC, f'§0.4 version sentence must name {version} twice; found {found}'))
    return problems


def validate_line_endings(snapshot):
    crlf = [f for f in lf_files(snapshot) if '\r' in snapshot[f]]
    if crlf:
        return [Problem('crlf', '', f'CR characters (use LF line endings) in: {crlf}')]
    return []


# --- stage 3: generate --------------------------------------------------------

def assign_groups(reqs, cfg):
    override = {}
    for g, members in cfg['overrides'].items():
        for rid in members:
            override.setdefault(rid, g)
    return [dict(r, group=override.get(r['id'], cfg['area_default'][r['area']])) for r in reqs]


def ag_table(reqs, cfg):
    members = collections.defaultdict(list)
    for r in reqs:
        members[r['group']].append(r['id'])
    empty = [g['id'] for g in cfg['groups'] if not members[g['id']]]
    if empty:
        raise Invalid('empty-group', CONFIG, f'groups with no members: {empty}')
    rows = ['| 群組 | 名稱 | 通過條件 | 涵蓋條文 |', '| :--- | :--- | :--- | :--- |']
    for g in cfg['groups']:
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
        raise Invalid('marker', SPEC, f'must contain exactly one BEGIN/END:{name} marker pair')
    return pat.sub(lambda m: m.group(1) + body + m.group(3), spec)


def scope_doc(reqs, cfg, spec):
    version = header_value(spec, '版本', r'v\d+\.\d+\.\d+', SPEC)
    date = header_value(spec, '修訂日期', r'\d{4}-\d{2}-\d{2}', SPEC)
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


# --- the module's interface ---------------------------------------------------

def check_docs(snapshot):
    """Check a snapshot of the repo. Returns Result(problems, updates, counts).

    snapshot: dict of repo-relative POSIX path -> text, with CR characters kept.
    problems: list of Problem; when non-empty, updates is empty and counts is None.
    updates: dict of path -> new text, for generated outputs that are stale.
    counts: Counter of requirement v0.1 values, plus 'total'.
    """
    try:
        if SPEC not in snapshot:
            raise Invalid('missing-file', SPEC, 'file not found')
        spec = snapshot[SPEC]
        cfg = parse_config(snapshot)
    except Invalid as e:
        return Result([e.problem], {}, None)
    reqs, problems = parse_requirements(spec)
    if problems:
        return Result(problems, {}, None)

    problems = (validate_requirements(reqs, spec, cfg) + validate_config(reqs, cfg)
                + validate_cross_refs(reqs, snapshot) + validate_versions(snapshot)
                + validate_line_endings(snapshot))
    if problems:
        return Result(problems, {}, None)

    try:
        reqs = assign_groups(reqs, cfg)
        new_spec = replace_marked(spec, 'AG_TABLE', ag_table(reqs, cfg))
        new_spec = replace_marked(new_spec, 'APPENDIX_A', appendix(reqs, cfg))
        new_scope = scope_doc(reqs, cfg, new_spec)
    except Invalid as e:
        return Result([e.problem], {}, None)
    outputs = {SPEC: new_spec, SCOPE: new_scope}
    updates = {p: t for p, t in outputs.items() if snapshot.get(p) != t}
    counts = collections.Counter(r['v0'] for r in reqs)
    counts['total'] = len(reqs)
    return Result([], updates, counts)


# --- disk adapter and command line --------------------------------------------

SKIP_DIRS = {'.git', '__pycache__'}


def load_snapshot(repo=REPO):
    """Read every UTF-8 text file under repo; files that do not decode are skipped."""
    snapshot = {}
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            try:
                with open(path, encoding='utf-8', newline='') as f:
                    snapshot[path.relative_to(repo).as_posix()] = f.read()
            except (UnicodeDecodeError, OSError):
                continue
    return snapshot


def format_problem(p):
    where = f'{p.file}: ' if p.file else ''
    return f'error: {where}{p.message} [{p.rule}]'


def main(argv, repo=REPO):
    check = '--check' in argv
    result = check_docs(load_snapshot(repo))
    if result.problems:
        for p in result.problems:
            print(format_problem(p), file=sys.stderr)
        return 2
    c = result.counts
    summary = f"{c['total']} requirements (必做 {c['必做']} / 可延後 {c['可延後']} / 不適用 {c['不適用']})"
    stale = [Path(p).name for p in result.updates]
    if check:
        if stale:
            print(f'stale: {", ".join(stale)} — run tools/build.py', file=sys.stderr)
            return 1
        print(f'ok: {summary}; outputs up to date')
        return 0
    for path, text in result.updates.items():
        with open(Path(repo) / path, 'w', encoding='utf-8', newline='\n') as f:
            f.write(text)
    print(f'ok: {summary}; updated: {", ".join(stale) or "nothing"}')
    return 0


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    sys.exit(main(sys.argv[1:]))
