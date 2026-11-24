"""Regenerate the derived parts of the toolkit design documents from spec.md.

Source of truth: the requirement blocks in ``docs/toolkit/spec.md`` plus the
acceptance-group mapping in ``groups.json`` next to this script.

Generated outputs:
  * spec.md, between ``<!-- BEGIN:AG_TABLE ... -->`` / ``<!-- END:AG_TABLE -->``
  * spec.md, between ``<!-- BEGIN:APPENDIX_A ... -->`` / ``<!-- END:APPENDIX_A -->``
  * v0.1-scope.md (whole file)

Usage (from anywhere):
  python3 -I docs/toolkit/tools/build.py          # validate and rewrite outputs
  python3 -I docs/toolkit/tools/build.py --check  # validate; exit 1 if outputs are stale
  python3 -I docs/toolkit/tools/build.py --bump v1.4.14 [--date 2026-11-02] [--note "what changed"]
      # set the shared version and revision date (default: today in Taiwan time)
      # in every document header and the spec §0.4 sentence, then rewrite outputs;
      # --note also appends the row for the new version to review-log.md chapter 4
      # (the version rule needs that row; without --note you add it yourself)

  python3 -I docs/toolkit/tools/build.py --check-staged
      # pre-commit: what is staged, not the working directory, must pass every check and
      # hold up-to-date outputs; and against HEAD it must bump the version if it touches
      # a VERSIONED_PATHS path (README 版本規則)
  python3 -I docs/toolkit/tools/build.py --check-commits BASE [--fallback REF]
      # CI: every non-merge commit in BASE..HEAD, each against its first parent; when BASE
      # is empty, all zeros or unknown, the merge base of HEAD and REF is used instead

Every mode works on the repository that contains this script; --repo PATH names another
one (a clone, a throwaway repository) for any mode.

An option this script does not know, a second mode, or an option of another mode is an error:
nothing is read or written (a mistyped --check must not fall through to the mode that writes).

Exit codes: 0 ok; 1 outputs stale (--check only); 2 validation problems or a wrong command line.
Nothing is written while any problem is reported.

Structure: ``check_docs(snapshot)`` is the whole check. It takes a snapshot
(repo-relative POSIX path -> file text, CR characters preserved) and returns
the problems, the outputs that need rewriting, and requirement counts. It reads
no files itself. ``bump(snapshot, version, date)`` is the same over a snapshot,
for a new revision: it returns the header and §0.4 edits plus the regenerated
outputs, or the problems that stop the bump. ``load_snapshot`` (disk) and the tests (in memory) build
snapshots; ``main`` turns the result into output, writes and an exit code.
``check_revision(changed, base, new, parents)`` is the third entry point: the version rule for
one commit, over paths and two snapshots; only ``main``'s thin git layer reads git.

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
  * line endings: no CR characters in the text files of the docs tooling and the repository's
    own instructions and scripts (see lf_files)
  * generated outputs: exactly one BEGIN/END marker pair per generated region
"""
import collections
import datetime
import json
import os
import re
import subprocess
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
# README 版本規則: changing any of these (a trailing '/' means everything under it) needs a new shared version.
VERSIONED_PATHS = ('docs/toolkit/', 'GLOSSARY.md', 'docs/adr/', 'CODING_STANDARDS.md',
                   'AGENTS.md', 'docs/agents/', '.claude/agents/')

LEVELS = ('須', '不得', '宜', '可')
# 必做 names the stage of prototype v0.1 that accepts the requirement (spec.md §0.3).
MUST_A, MUST_B = '必做（v0.1a）', '必做（v0.1b）'
V01 = (MUST_A, MUST_B, '可延後', '不適用')
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
    root = {'README.md', 'GLOSSARY.md', 'AGENTS.md', 'CLAUDE.md', 'CODING_STANDARDS.md', '.gitattributes',
            '.gitignore', '.claude/settings.json'}
    dirs = ('docs/adr', 'docs/research', 'docs/agents', '.github/workflows', '.githooks', 'docs/toolkit/tools')
    by_suffix = (('docs/toolkit', '.md'), ('.claude/agents', '.md'),
                 ('toolkit/tools', '.sh'))  # a shell script with CR line endings does not run

    def wanted(p):
        if p in root or any(_in_dir(p, d) for d in dirs):
            return True
        return any(_in_dir(p, d) and p.endswith(suffix) for d, suffix in by_suffix)

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
        '> **文件組合**：規格 [`spec.md`](spec.md)、設計說明 [`design-notes.md`](design-notes.md)、'
        '審查處置紀錄 [`review-log.md`](review-log.md)、《v0.1 最小範圍》 [`v0.1-scope.md`](v0.1-scope.md)',
    ])
    rows = ['| 領域 | v0.1a 必做 | v0.1b 必做 | 可延後 | 不適用 |', '| :--- | :--- | :--- | :--- | :--- |']
    cnt = collections.Counter()
    for area, name in cfg['area_names'].items():
        rs = sorted((r for r in reqs if r['area'] == area), key=lambda r: r['id'])
        if not rs:
            continue

        def cell(v, rs=rs):
            return '、'.join(f"`{r['id'][3:]}`" for r in rs if r['v0'] == v) or '—'

        rows.append(f"| `{area}` {name} | {cell(MUST_A)} | {cell(MUST_B)} | {cell('可延後')} | {cell('不適用')} |")
        cnt.update(r['v0'] for r in rs)
    table = '\n'.join(rows)
    return f'''# 《v0.1 最小範圍》

{hdr}

<!-- 本檔由 tools/build.py 依 spec.md 產生，請勿手動編輯。 -->

## 範圍定義

原型 v0.1 對應里程碑 M0、M1 及部分 M2：以政策、隔離、可靠判定與單模型，串成已知物件越權的最小流程（設計說明第 5.3 節）。v0.1 分兩個階段交付與驗收：

| 階段 | 內容 | 對應里程碑 |
| :--- | :--- | :--- |
| v0.1a | 不呼叫模型的已知物件越權流程：必要輸入與前置檢查、需求確認、E1 環境與隔離、固定範本的動態執行、觀測者判定、證據與報告、覆核紀錄 | M0、M1 |
| v0.1b | 單模型審查：模型適配、審查任務、送出前的機密遮罩、資料路由、費用預算、提示注入防護、威脅清單與受控轉換 | 部分 M2 |

v0.1a 的必做條文全部通過驗收後，v0.1a 即可單獨驗收；v0.1 整體驗收須兩個階段都通過。v0.1a 不呼叫模型，其報告不得宣稱已涵蓋 v0.1b 條文的能力（`TK-EVD-014`）。

**判定原則：** 該階段實際會執行到的功能，相關的安全控制就是該階段必做。例如 v0.1b 會呼叫模型，送出前的機密遮罩就是 v0.1b 必做；v0.1a 會啟動受測應用，對外連線阻擋就是 v0.1a 必做；v0.1 不做 E2 環境，E2 擁有權驗證就可延後；v0.1 只用單一模型，多模型相關條文不適用。條文的驗收需要模型或模型審查區才能完成時，歸 v0.1b。

標為「可延後」的條文，在 v0.1 不實作也不驗收；但 v0.1 的報告不得宣稱已涵蓋這些條文的能力（`TK-SCP-006`、`TK-EVD-014`）。

## 條文清單

共 {sum(cnt.values())} 條：必做 {cnt[MUST_A] + cnt[MUST_B]} 條（v0.1a {cnt[MUST_A]} 條、v0.1b {cnt[MUST_B]} 條）、可延後 {cnt['可延後']} 條、不適用 {cnt['不適用']} 條。下表省略 `TK-` 前綴；各條標題見規格附錄 A。

{table}
'''


# --- the module's interface ---------------------------------------------------

def check_docs(snapshot):
    """Check a snapshot of the repo. Returns Result(problems, updates, counts).

    snapshot: dict of repo-relative POSIX path -> text, with CR characters kept.
    problems: list of Problem; when non-empty, updates is empty and counts is None.
    updates: dict of path -> new text, for generated outputs that are stale.
    counts: Counter of requirement v0.1 values, plus 'total' and '必做' (both stages together).
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
    counts['必做'] = counts[MUST_A] + counts[MUST_B]
    return Result([], updates, counts)


VERSION = re.compile(r'v(\d+)\.(\d+)\.(\d+)')
DATE = re.compile(r'\d{4}-\d{2}-\d{2}')


def _replace_header(text, label, pattern, value, file):
    """Replace the first value of a '> **label**：' header line; Invalid if the line is missing."""
    header = re.compile(r'^(> \*\*' + label + r'\*\*：.*?)' + pattern, re.M)
    if not header.search(text):
        raise Invalid('header-missing', file, f'header: cannot read {label}')
    return header.sub(lambda m: m.group(1) + value, text, count=1)


def _add_log_row(review_log, version, date, note):
    """review_log with the row for version appended after the last row of chapter 4; Invalid('bump-note') if it cannot."""
    chapter = re.search(r'^## 4\. .*?(?=^## |\Z)', review_log, re.M | re.S)
    rows = list(re.finditer(r'^\| v\d.*$', chapter.group(0), re.M)) if chapter else []
    if not rows:
        raise Invalid('bump-note', REVIEW, 'chapter 4 of the review log has no revision rows to append to')
    if _has_log_row(review_log, version):
        raise Invalid('bump-note', REVIEW, f'chapter 4 already has a row for {version}')
    at = chapter.start() + rows[-1].end()
    return review_log[:at] + f'\n| {version} | {date} | {note.replace("|", chr(92) + "|")} |' + review_log[at:]


def bump(snapshot, version, date, note=None):
    """Set the shared version and revision date for a new revision (README 每輪修訂的檢查清單, step 1).

    Edits the 版本 and 修訂日期 headers of spec, design notes and review log, and the
    §0.4 version sentence; v0.1-scope.md follows when the outputs are regenerated.
    Returns Result like check_docs, with updates holding every file to write. The
    snapshot must pass check_docs first, and version must be newer than the current one.
    With note (one non-empty line), the row for version is also appended to review-log.md chapter 4.
    """
    problems = []
    if not VERSION.fullmatch(version):
        problems.append(Problem('bump-version', '', f'version must look like v1.4.14; got {version!r}'))
    try:
        datetime.date.fromisoformat(date)
        if not DATE.fullmatch(date):
            raise ValueError
    except ValueError:
        problems.append(Problem('bump-date', '', f'date must be a real YYYY-MM-DD date; got {date!r}'))
    if note is not None and (not note.strip() or '\n' in note or '\r' in note):
        problems.append(Problem('bump-note', '', 'note must be one non-empty line'))
    if problems:
        return Result(problems, {}, None)
    before = check_docs(snapshot)
    if before.problems:
        return before
    current = header_value(snapshot[SPEC], '版本', VERSION.pattern, SPEC)
    as_tuple = lambda v: tuple(int(n) for n in VERSION.fullmatch(v).groups())
    if as_tuple(version) <= as_tuple(current):
        return Result([Problem('bump-version', '', f'{version} is not newer than the current {current}')], {}, None)
    edited = {}
    try:
        for f in VERSIONED:
            text = _replace_header(snapshot[f], '版本', VERSION.pattern, version, f)
            edited[f] = _replace_header(text, '修訂日期', DATE.pattern, date, f)
        if note is not None:
            edited[REVIEW] = _add_log_row(edited[REVIEW], version, date, note)
    except Invalid as e:
        return Result([e.problem], {}, None)
    edited[SPEC] = VERSION_SENTENCE.sub(
        f'本文件 {version} 表示設計文件的修訂；不代表工具包軟體已達 {version}。', edited[SPEC], count=1)
    after = check_docs({**snapshot, **edited})
    if after.problems:
        return after
    updates = {**edited, **after.updates}
    return Result([], {p: t for p, t in updates.items() if snapshot.get(p) != t}, after.counts)


def _version_tuple(v):
    return tuple(int(n) for n in VERSION.fullmatch(v).groups())


def _has_log_row(review_log, version):
    """Whether chapter 4 of the review log has a table row for version."""
    m = re.search(r'^## 4\. .*?(?=^## |\Z)', review_log, re.M | re.S)
    return bool(m) and re.search(r'^\| ' + re.escape(version) + r' \|', m.group(0), re.M) is not None


def check_revision(changed, base, new, parents=1):
    """Check one revision (a commit): changing a VERSIONED_PATHS path needs a new shared version.

    changed: repo-relative POSIX paths the revision touched. base, new: snapshots with at least
    SPEC and REVIEW, before and after (base is None for a root commit). parents: how many parents
    the revision has; only a revision with exactly one is checked. Returns a list of Problem.
    A bump counts when the spec header version is newer than base's AND review-log chapter 4 has
    a row for it. Reads no files and runs no git.
    """
    if parents != 1 or base is None:
        return []
    governed = sorted(p for p in changed if any(p == g or (g.endswith('/') and p.startswith(g)) for g in VERSIONED_PATHS))
    if not governed:
        return []
    try:
        before = header_value(base[SPEC], '版本', VERSION.pattern, SPEC)
        after = header_value(new[SPEC], '版本', VERSION.pattern, SPEC)
    except Invalid as e:
        return [e.problem]
    hint = 'run: python3 -I docs/toolkit/tools/build.py --bump v<new version>, and add its row to review-log.md chapter 4'
    if _version_tuple(after) <= _version_tuple(before):
        state = 'unchanged' if after == before else f'moved back from {before}'
        return [Problem('revision-version', '',
                        f'changed {", ".join(governed)} but the version is {state} at {after}; {hint}')]
    if not _has_log_row(new.get(REVIEW, ''), after):
        return [Problem('revision-log', REVIEW, f'version is {after} but chapter 4 has no row for it; {hint}')]
    return []


HOOKS_DIR = '.githooks'


def hooks_warning(configured):
    """The warning line for a core.hooksPath setting (None when unset), or None when it is the repository's hooks."""
    if configured is not None and configured.rstrip('/') == HOOKS_DIR:
        return None
    return (f'warning: core.hooksPath is not {HOOKS_DIR}; the pre-commit check does not run in this clone '
            f'(enable it once: git config core.hooksPath {HOOKS_DIR})')


def taiwan_today():
    """Today's date in Taiwan time (UTC+8, no daylight saving), the zone the headers use."""
    return datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).date().isoformat()


# --- disk adapter and command line --------------------------------------------

# Outside a git clone every file is read, except these: git's own, caches, and where tools keep their state
# (the virtual environment, the environment tests' logs and downloads, vendored agent skills).
SKIP_DIRS = {'.git', '__pycache__', '.venv', 'scratch', '.agents'}


def _tracked(repo):
    """The paths git tracks in the clone at repo (the index: a newly added file counts, an untracked draft does
    not), or None when repo is no clone or git cannot say."""
    if not (Path(repo) / '.git').exists():
        return None
    run = _run_git(repo, 'ls-files', '-z')
    if run.returncode != 0:
        return None
    return [p for p in run.stdout.decode('utf-8', 'replace').split('\0') if p]


def _walked(repo):
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield (Path(dirpath) / name).relative_to(repo).as_posix()


def load_snapshot(repo=REPO):
    """Read the UTF-8 text files of repo as they are in the working directory: the files git tracks when repo
    is a clone, else every file outside SKIP_DIRS. Files that do not decode, or are gone, are skipped."""
    tracked = _tracked(repo)
    snapshot = {}
    for rel in (_walked(repo) if tracked is None else tracked):
        try:
            with open(Path(repo) / rel, encoding='utf-8', newline='') as f:
                snapshot[rel] = f.read()
        except (UnicodeDecodeError, OSError):
            continue
    return snapshot


def load_staged_snapshot(repo):
    """Read the UTF-8 text files of repo as the index has them: what the next commit will hold. Blobs that
    do not decode, and entries that are no files (a submodule), are skipped."""
    entries = []
    for entry in _git_bytes(repo, 'ls-files', '-s', '-z').split(b'\0'):
        if not entry:
            continue
        meta, _, path = entry.partition(b'\t')
        mode, blob, stage = meta.split()
        if stage == b'0' and not mode.startswith(b'16'):  # unmerged entries and gitlinks hold no text to check
            entries.append((blob, path.decode('utf-8', 'replace')))
    run = subprocess.run(['git', '-C', str(repo), 'cat-file', '--batch'], capture_output=True,
                         input=b''.join(blob + b'\n' for blob, _ in entries))
    if run.returncode != 0:
        raise Invalid('git', '', f'git cat-file --batch failed: {run.stderr.decode("utf-8", "replace").strip()}')
    snapshot, out, at = {}, run.stdout, 0
    for _, path in entries:
        end = out.index(b'\n', at)
        size = int(out[at:end].split()[2])
        try:
            snapshot[path] = out[end + 1:end + 1 + size].decode('utf-8')
        except UnicodeDecodeError:
            pass
        at = end + 1 + size + 1
    return snapshot


def format_problem(p):
    where = f'{p.file}: ' if p.file else ''
    return f'error: {where}{p.message} [{p.rule}]'


def _run_git(repo, *args):
    return subprocess.run(['git', '-C', str(repo), *args], capture_output=True)


def _git_bytes(repo, *args):
    """Run git in repo and return its stdout as bytes; Invalid('git') when it fails."""
    run = _run_git(repo, *args)
    if run.returncode != 0:
        raise Invalid('git', '', f'git {" ".join(args)} failed: {run.stderr.decode("utf-8", "replace").strip()}')
    return run.stdout


def _git(repo, *args):
    """Run git in repo and return its stdout; Invalid('git') when it fails."""
    return _git_bytes(repo, *args).decode('utf-8')


def hooks_warning_for(repo):
    """hooks_warning for the clone at repo; None outside a git clone, on GitHub Actions or when git cannot say."""
    if os.environ.get('GITHUB_ACTIONS') or not (Path(repo) / '.git').exists():
        return None
    run = _run_git(repo, 'config', '--get', 'core.hooksPath')
    if run.returncode not in (0, 1):  # 1 means the setting is absent
        return None
    return hooks_warning(run.stdout.decode('utf-8').strip() if run.returncode == 0 else None)


def _git_succeeds(repo, *args):
    return _run_git(repo, *args).returncode == 0


# One change to check: from commit `old` to commit `new` (None means the index), reported under `label`.
Change = collections.namedtuple('Change', 'old new label')


def _revision_snapshot(repo, rev):
    """SPEC and REVIEW as git has them at commit rev, or in the index when rev is None."""
    return {f: _git(repo, 'show', f'{rev or ""}:{f}') for f in (SPEC, REVIEW)}


def _check_change(repo, change):
    """check_revision for one Change, which always has exactly one parent."""
    range_args = ['--cached', change.old] if change.new is None else [change.old, change.new]
    changed = [p for p in _git(repo, 'diff', '--name-only', '-z', '--no-renames', *range_args).split('\0') if p]
    problems = check_revision(changed, _revision_snapshot(repo, change.old), _revision_snapshot(repo, change.new))
    return [p._replace(message=f'{change.label}: {p.message}') for p in problems]


def check_staged(repo):
    """Problems of what is staged: the documents as the index has them must pass check_docs with their generated
    outputs up to date (a file left unstaged is not part of the commit, however current the working directory
    is), and the staged changes against HEAD must follow the version rule. The version rule is not applied to
    a first commit or a commit that concludes a merge."""
    problems = []
    staged = load_staged_snapshot(repo)
    if SPEC in staged:
        result = check_docs(staged)
        problems += [p._replace(message=f'staged: {p.message}') for p in result.problems]
        if result.updates:
            names = ', '.join(sorted(result.updates))
            problems.append(Problem('staged-stale', '', f'staged: generated outputs are out of date in the index: '
                                                        f'{names}; run tools/build.py and stage them (git add)'))
    has = lambda ref: _git_succeeds(repo, 'rev-parse', '-q', '--verify', ref)
    if not has('HEAD') or has('MERGE_HEAD'):
        return problems
    return problems + _check_change(repo, Change('HEAD', None, 'staged changes'))


def check_commits(repo, base, fallback):
    """Problems of every commit in base..HEAD; Invalid('revision-base') when no base can be decided.

    When the base is unusable and the fallback leaves an empty range, only HEAD is checked."""
    known = bool(base) and not set(base) <= {'0'} and _git_succeeds(repo, 'cat-file', '-e', f'{base}^{{commit}}')
    if not known:
        if not fallback:
            raise Invalid('revision-base', '', 'no usable base commit and no --fallback; cannot decide what to check')
        try:
            base = _git(repo, 'merge-base', 'HEAD', fallback).strip()
        except Invalid:
            raise Invalid('revision-base', '', f'no usable base commit, and no merge base of HEAD and {fallback}') from None
    commits = _git(repo, 'rev-list', '--reverse', f'{base}..HEAD').split()
    if not known and not commits:
        # The fallback is HEAD itself (the default branch was pushed): the range says nothing, so check HEAD alone.
        commits = [_git(repo, 'rev-parse', 'HEAD').strip()]
    problems = []
    for commit in commits:
        parents = _git(repo, 'rev-list', '--parents', '-n', '1', commit).split()[1:]
        if len(parents) == 1:
            problems += _check_change(repo, Change(parents[0], commit, commit[:10]))
    return problems


def _option(argv, name):
    """The value after name in argv, None if name is absent, '' if it has no value."""
    if name not in argv:
        return None
    i = argv.index(name) + 1
    return argv[i] if i < len(argv) and not argv[i].startswith('--') else ''


def _fail(rule, message):
    print(format_problem(Problem(rule, '', message)), file=sys.stderr)
    return 2


# The command line: each option, whether a value follows it, and the mode it belongs to (None: any mode).
MODES = ('--check', '--bump', '--check-staged', '--check-commits')  # none of them: validate and rewrite
OPTIONS = {'--repo': (True, None), '--check': (False, '--check'), '--bump': (True, '--bump'),
           '--date': (True, '--bump'), '--note': (True, '--bump'), '--check-staged': (False, '--check-staged'),
           '--check-commits': (True, '--check-commits'), '--fallback': (True, '--check-commits')}


def usage_problem(argv):
    """What is wrong with the command line, as (rule, message), or None. An argument that is no known option, an
    option given twice, two modes at once, or an option of a mode that was not asked for: each is an error, so a
    mistyped flag never falls through to the default mode, which writes."""
    seen, i = [], 0
    while i < len(argv):
        arg = argv[i]
        if arg not in OPTIONS:
            known = ', '.join(OPTIONS)
            return 'usage', f'unknown argument {arg!r}; the options are {known}'
        if arg in seen:
            return 'usage', f'{arg} is given more than once'
        seen.append(arg)
        takes_value = OPTIONS[arg][0]
        i += 2 if takes_value and i + 1 < len(argv) and not argv[i + 1].startswith('--') else 1
    modes = [a for a in seen if a in MODES]
    if '--bump' in modes and '--check' in modes:
        return 'bump-check', '--bump writes files; it cannot be combined with --check'
    if len(modes) > 1:
        return 'usage', f'{" and ".join(modes)} are different modes; give one'
    for arg in seen:
        mode = OPTIONS[arg][1]
        if mode is not None and mode not in modes:
            return ('bump-note' if arg == '--note' else 'usage'), f'{arg} belongs to {mode}'
    return None


def main(argv, repo=REPO):
    problem = usage_problem(argv)
    if problem:
        return _fail(*problem)
    given = _option(argv, '--repo')
    if given is not None:
        if not given or not Path(given).is_dir():
            return _fail('repo-option', f'--repo needs an existing directory; got {given!r}')
        repo = Path(given)
    if '--check-staged' in argv or '--check-commits' in argv:
        try:
            problems = (check_staged(repo) if '--check-staged' in argv
                        else check_commits(repo, _option(argv, '--check-commits'), _option(argv, '--fallback')))
        except Invalid as e:
            problems = [e.problem]
        for p in problems:
            print(format_problem(p), file=sys.stderr)
        return 2 if problems else 0
    check = '--check' in argv
    version = _option(argv, '--bump')
    if version is not None:
        date = _option(argv, '--date')
        result = bump(load_snapshot(repo), version, taiwan_today() if date is None else date,
                      note=_option(argv, '--note'))
    else:
        result = check_docs(load_snapshot(repo))
    if check and (warning := hooks_warning_for(repo)):
        print(warning, file=sys.stderr)
    if result.problems:
        for p in result.problems:
            print(format_problem(p), file=sys.stderr)
        return 2
    c = result.counts
    summary = f"{c['total']} requirements (必做 {c['必做']} = v0.1a {c[MUST_A]} + v0.1b {c[MUST_B]} / 可延後 {c['可延後']} / 不適用 {c['不適用']})"
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
    if version is not None and _option(argv, '--note') is None:
        print(f'note: add the row for {version} to review-log.md chapter 4 (or bump with --note)', file=sys.stderr)
    print(f'ok: {summary}; updated: {", ".join(stale) or "nothing"}')
    return 0


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    sys.exit(main(sys.argv[1:]))
