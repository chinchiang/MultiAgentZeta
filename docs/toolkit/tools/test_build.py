"""Tests for build.py, through its interface: check_docs(snapshot).

Run (from anywhere):
  python3 -I -m unittest discover -s docs/toolkit/tools -v
"""
import contextlib
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build  # noqa: E402

REQ = '''#### {rid} {title}

- **等級**：{level}
- **條文**：條文內容。
- **驗收**：{accept}
- **v0.1**：{v0}
- **理由**：設計說明 §1
- **來源**：v1.4.5 新增
'''

SPEC = '''# 規格

> **版本**：v9.9.9（四份文件共用版本號）
> **修訂日期**：2026-01-01（臺灣時間）

### 0.4 版本

本文件 v9.9.9 表示設計文件的修訂；不代表工具包軟體已達 v9.9.9。

## 1. 條文

{reqs}
## 14. 驗收群組

<!-- BEGIN:AG_TABLE（產生） -->
舊內容
<!-- END:AG_TABLE -->

## 附錄 A

<!-- BEGIN:APPENDIX_A（產生） -->
舊內容
<!-- END:APPENDIX_A -->
'''

DEFAULT_REQS = [
    dict(rid='TK-AAA-001', title='第一條', level='須', accept='負向測試。', v0='必做'),
    dict(rid='TK-AAA-002', title='第二條', level='宜', accept='—', v0='可延後'),
    dict(rid='TK-BBB-001', title='第三條', level='不得', accept='設定檢查。', v0='不適用'),
]

CONFIG = {
    'groups': [dict(id='AG-01', name='甲', condition='條件甲'), dict(id='AG-02', name='乙', condition='條件乙')],
    'area_default': {'AAA': 'AG-01', 'BBB': 'AG-01'},
    'overrides': {'AG-02': ['TK-AAA-002']},
    'area_names': {'AAA': '甲領域', 'BBB': '乙領域'},
}


def make(reqs=None, cfg=None, **files):
    """A minimal snapshot that passes every check; keyword args replace or add files.

    Keys use '__' for '/' and '_' for '.', e.g. docs__adr__0001_md.
    """
    reqs = DEFAULT_REQS if reqs is None else reqs
    snap = {
        build.SPEC: SPEC.format(reqs='\n'.join(REQ.format(**r) for r in reqs)),
        build.DESIGN: '# 設計說明\n\n> **版本**：v9.9.9\n> **修訂日期**：2026-01-01（臺灣時間）\n\n見 [R1]。\n\n- **[R1]** 參考資料。\n',
        build.REVIEW: '# 審查處置紀錄\n\n> **版本**：v9.9.9\n> **修訂日期**：2026-01-01（臺灣時間）\n',
        build.CONFIG: json.dumps(CONFIG if cfg is None else cfg, ensure_ascii=False),
    }
    for key, text in files.items():
        snap[key.replace('__', '/').replace('_md', '.md')] = text
    return snap


def regenerated(snap):
    """The snapshot with generated outputs brought up to date."""
    result = build.check_docs(snap)
    assert not result.problems, result.problems
    return {**snap, **result.updates}


def rules(snap):
    return {(p.rule, p.file) for p in build.check_docs(snap).problems}


class CleanSnapshot(unittest.TestCase):
    def test_fresh_snapshot_has_only_stale_outputs(self):
        result = build.check_docs(make())
        self.assertEqual(result.problems, [])
        self.assertEqual(set(result.updates), {build.SPEC, build.SCOPE})

    def test_regenerating_is_idempotent(self):
        result = build.check_docs(regenerated(make()))
        self.assertEqual((result.problems, result.updates), ([], {}))

    def test_counts(self):
        c = build.check_docs(make()).counts
        self.assertEqual((c['total'], c['必做'], c['可延後'], c['不適用']), (3, 1, 1, 1))


class Generation(unittest.TestCase):
    def setUp(self):
        self.snap = regenerated(make())
        self.spec = self.snap[build.SPEC]

    def test_group_table_uses_area_default_and_overrides(self):
        self.assertIn('| AG-01 | 甲 | 條件甲 | `TK-AAA-001`、`TK-BBB-001` |', self.spec)
        self.assertIn('| AG-02 | 乙 | 條件乙 | `TK-AAA-002` |', self.spec)

    def test_appendix_lists_every_requirement(self):
        self.assertIn('| `TK-AAA-002` | 第二條 | 宜 | AG-02 乙 | 可延後 |', self.spec)
        self.assertNotIn('舊內容', self.spec)

    def test_scope_doc(self):
        scope = self.snap[build.SCOPE]
        self.assertIn('> **版本**：v9.9.9', scope)
        self.assertIn('共 3 條：必做 1 條、可延後 1 條、不適用 1 條。', scope)
        self.assertIn('| `AAA` 甲領域 | `AAA-001` | `AAA-002` | — |', scope)


class RequirementBlocks(unittest.TestCase):
    def with_req(self, **change):
        return make([dict(DEFAULT_REQS[0], **change)] + DEFAULT_REQS[1:])

    def test_missing_field(self):
        snap = make()
        snap[build.SPEC] = snap[build.SPEC].replace('- **理由**：設計說明 §1\n', '', 1)
        self.assertEqual(rules(snap), {('missing-field', build.SPEC)})

    def test_empty_field(self):
        self.assertEqual(rules(self.with_req(accept='')), {('empty-field', build.SPEC)})

    def test_statement_may_continue_on_indented_lines(self):
        snap = make()
        snap[build.SPEC] = snap[build.SPEC].replace('- **條文**：條文內容。', '- **條文**：\n  - 第一點', 1)
        self.assertEqual(rules(snap), set())

    def test_invalid_level(self):
        self.assertEqual(rules(self.with_req(level='應')), {('invalid-level', build.SPEC)})

    def test_invalid_v01(self):
        self.assertEqual(rules(self.with_req(v0='之後')), {('invalid-v01', build.SPEC)})

    def test_must_requirement_needs_acceptance(self):
        self.assertEqual(rules(self.with_req(accept='—')), {('missing-acceptance', build.SPEC)})

    def test_no_requirements(self):
        self.assertEqual(rules(make([])), {('no-requirements', build.SPEC)})

    def test_parse_problems_are_all_reported_and_stop_later_stages(self):
        reqs = [dict(r, level='應') for r in DEFAULT_REQS]
        snap = make(reqs, GLOSSARY_md='TK-ZZZ-001')  # a later-stage problem, not reported
        problems = build.check_docs(snap).problems
        self.assertEqual([p.rule for p in problems], ['invalid-level'] * 3)

    def test_duplicate_id(self):
        snap = make(DEFAULT_REQS + [DEFAULT_REQS[0]])
        self.assertIn(('duplicate-id', build.SPEC), rules(snap))

    def test_numbering_gap(self):
        snap = make(DEFAULT_REQS + [dict(DEFAULT_REQS[0], rid='TK-AAA-004')])
        self.assertEqual(rules(snap), {('numbering-gap', build.SPEC)})


class Config(unittest.TestCase):
    def cfg(self, **change):
        return dict(CONFIG, **change)

    def test_missing_config(self):
        snap = make()
        del snap[build.CONFIG]
        self.assertEqual(rules(snap), {('missing-file', build.CONFIG)})

    def test_invalid_json(self):
        snap = make()
        snap[build.CONFIG] = '{'
        self.assertEqual(rules(snap), {('invalid-config', build.CONFIG)})

    def test_area_without_default_or_name(self):
        snap = make(cfg=self.cfg(area_default={'AAA': 'AG-01'}, area_names={'AAA': '甲領域'}))
        problems = build.check_docs(snap).problems
        self.assertEqual([p.rule for p in problems], ['area-not-configured'] * 2)

    def test_unknown_group(self):
        snap = make(cfg=self.cfg(area_default={'AAA': 'AG-09', 'BBB': 'AG-01'}))
        self.assertEqual(rules(snap), {('unknown-group', build.CONFIG)})

    def test_unknown_requirement_in_overrides(self):
        snap = make(cfg=self.cfg(overrides={'AG-02': ['TK-AAA-002', 'TK-AAA-009']}))
        self.assertEqual(rules(snap), {('unknown-requirement', build.CONFIG)})

    def test_requirement_in_two_overrides(self):
        snap = make(cfg=self.cfg(overrides={'AG-01': ['TK-AAA-002'], 'AG-02': ['TK-AAA-002']}))
        self.assertEqual(rules(snap), {('duplicate-override', build.CONFIG)})

    def test_group_without_members(self):
        snap = make(cfg=self.cfg(overrides={}))
        self.assertEqual(rules(snap), {('empty-group', build.CONFIG)})


class CrossReferences(unittest.TestCase):
    def test_dangling_ref_in_spec(self):
        snap = make()
        snap[build.SPEC] += '\n見 TK-AAA-009。\n'
        self.assertEqual(rules(snap), {('dangling-ref', build.SPEC)})

    def test_dangling_ref_in_other_docs(self):
        snap = make(GLOSSARY_md='TK-AAA-009', docs__adr__0001_md='TK-AAA-009', docs__research__note_md='TK-ZZZ-001')
        self.assertEqual(rules(snap), {('dangling-ref', 'GLOSSARY.md'), ('dangling-ref', 'docs/adr/0001.md'),
                                       ('dangling-ref', 'docs/research/note.md')})

    def test_refs_outside_the_doc_set_are_ignored(self):
        self.assertEqual(rules(make(scratch__x_md='TK-ZZZ-001', docs__adr__old__x_md='TK-ZZZ-001')), set())

    def test_r_defined_twice(self):
        snap = make()
        snap[build.DESIGN] += '- **[R1]** 重複。\n'
        self.assertEqual(rules(snap), {('r-duplicate', build.DESIGN)})

    def test_r_numbering_gap(self):
        snap = make()
        snap[build.DESIGN] += '- **[R3]** 跳號。\n'
        self.assertEqual(rules(snap), {('r-gap', build.DESIGN)})

    def test_r_undefined(self):
        snap = make()
        snap[build.REVIEW] += '見 [R2]。\n'
        self.assertEqual(rules(snap), {('r-undefined', build.REVIEW)})

    def test_all_stage_two_problems_are_reported_together(self):
        snap = make(GLOSSARY_md='TK-AAA-009')
        snap[build.REVIEW] = snap[build.REVIEW].replace('v9.9.9', 'v9.9.8') + '見 [R2]。\n'
        self.assertEqual(rules(snap), {('dangling-ref', 'GLOSSARY.md'), ('r-undefined', build.REVIEW),
                                       ('version-mismatch', '')})


class DefinitionReferences(unittest.TestCase):
    """〈定義：〇〇〉 references must name an existing '### 定義：〇〇' section of spec.md."""

    def with_definition(self, **files):
        snap = make(**files)
        snap[build.SPEC] = snap[build.SPEC].replace('## 1. 條文', '### 定義：測試結果\n\n表。\n\n## 1. 條文')
        return snap

    def test_reference_to_an_existing_definition_passes(self):
        snap = self.with_definition(GLOSSARY_md='見〈定義：測試結果〉。')
        snap['toolkit/scan.py'] = '"""依〈定義：測試結果〉。"""\n'
        self.assertEqual(rules(snap), set())

    def test_dangling_def_in_spec(self):
        snap = self.with_definition()
        snap[build.SPEC] += '\n依〈定義：不存在〉。\n'
        self.assertEqual(rules(snap), {('dangling-def', build.SPEC)})

    def test_dangling_def_in_docs_code_and_schemas(self):
        snap = self.with_definition(GLOSSARY_md='〈定義：測試結果之外〉', CODING_STANDARDS_md='〈定義：不存在〉',
                                    docs__agents__domain_md='〈定義：不存在〉')
        snap['toolkit/tests/test_report.py'] = '# 〈定義：核心資料物件〉\n'
        snap['toolkit/schemas/report-v1.json'] = '{"description": "〈定義：不存在〉"}'
        self.assertEqual(rules(snap), {('dangling-def', 'GLOSSARY.md'), ('dangling-def', 'CODING_STANDARDS.md'),
                                       ('dangling-def', 'docs/agents/domain.md'),
                                       ('dangling-def', 'toolkit/tests/test_report.py'),
                                       ('dangling-def', 'toolkit/schemas/report-v1.json')})

    def test_placeholder_name_is_ignored(self):
        self.assertEqual(rules(self.with_definition(GLOSSARY_md='以〈定義：〇〇〉引用。')), set())

    def test_refs_outside_the_checked_files_are_ignored(self):
        snap = self.with_definition(scratch__x_md='〈定義：不存在〉')
        snap['samples/object-authz/app.py'] = '# 〈定義：不存在〉\n'
        self.assertEqual(rules(snap), set())


class Versions(unittest.TestCase):
    def test_header_missing(self):
        snap = make()
        snap[build.REVIEW] = '# 審查處置紀錄\n'
        self.assertEqual(rules(snap), {('header-missing', build.REVIEW)})

    def test_versions_disagree(self):
        snap = make()
        snap[build.DESIGN] = snap[build.DESIGN].replace('v9.9.9', 'v9.9.8')
        self.assertEqual(rules(snap), {('version-mismatch', '')})

    def test_version_sentence(self):
        snap = make()
        snap[build.SPEC] = snap[build.SPEC].replace('已達 v9.9.9', '已達 v9.9.8')
        self.assertEqual(rules(snap), {('version-sentence', build.SPEC)})

    def test_scope_doc_follows_spec_version(self):
        snap = regenerated(make())
        for f in build.VERSIONED:
            snap[f] = snap[f].replace('v9.9.9', 'v9.9.10')
        self.assertEqual(set(build.check_docs(snap).updates), {build.SCOPE})


class Bump(unittest.TestCase):
    """bump(): a new revision's version and date, then the regenerated outputs."""

    def bumped(self, version='v9.9.10', date='2026-02-03', snap=None):
        return build.bump(regenerated(make()) if snap is None else snap, version, date)

    def test_bump_sets_every_header_and_the_version_sentence(self):
        result = self.bumped()
        self.assertEqual(result.problems, [])
        self.assertEqual(set(result.updates), {build.SPEC, build.DESIGN, build.REVIEW, build.SCOPE})
        for f in (build.SPEC, build.DESIGN, build.REVIEW, build.SCOPE):
            with self.subTest(file=f):
                text = result.updates[f]
                self.assertIn('> **版本**：v9.9.10', text)
                self.assertIn('> **修訂日期**：2026-02-03（臺灣時間）', text)
                self.assertNotIn('v9.9.9', text)
        self.assertIn('本文件 v9.9.10 表示設計文件的修訂；不代表工具包軟體已達 v9.9.10。', result.updates[build.SPEC])
        after = build.check_docs({**regenerated(make()), **result.updates})
        self.assertEqual((after.problems, after.updates), ([], {}))

    def test_bump_compares_versions_numerically(self):
        self.assertEqual(self.bumped(version='v10.0.0').problems, [])

    def test_version_must_be_well_formed(self):
        for version in ('1.4.14', 'v1.4', 'v1.4.14a', ''):
            with self.subTest(version=version):
                result = self.bumped(version=version)
                self.assertEqual({p.rule for p in result.problems}, {'bump-version'})
                self.assertEqual(result.updates, {})

    def test_version_must_be_newer(self):
        for version in ('v9.9.9', 'v9.9.8', 'v9.8.10'):
            with self.subTest(version=version):
                self.assertEqual({p.rule for p in self.bumped(version=version).problems}, {'bump-version'})

    def test_date_must_be_a_real_date(self):
        for date in ('2026-2-3', '2026-02-30', '', '2026/02/03'):
            with self.subTest(date=date):
                self.assertEqual({p.rule for p in self.bumped(date=date).problems}, {'bump-date'})

    def test_a_missing_date_header_stops_the_bump(self):
        snap = regenerated(make())
        snap[build.REVIEW] = '# 審查處置紀錄\n\n> **版本**：v9.9.9\n'
        result = self.bumped(snap=snap)
        self.assertEqual({(p.rule, p.file) for p in result.problems}, {('header-missing', build.REVIEW)})
        self.assertEqual(result.updates, {})

    def test_a_snapshot_that_fails_the_check_is_not_bumped(self):
        snap = regenerated(make())
        snap[build.DESIGN] = snap[build.DESIGN].replace('v9.9.9', 'v9.9.8')
        self.assertEqual({p.rule for p in self.bumped(snap=snap).problems}, {'version-mismatch'})

    def test_command_line_writes_the_bump(self):
        import contextlib, io, tempfile
        with tempfile.TemporaryDirectory() as d:
            for path, text in regenerated(make()).items():
                Path(d, path).parent.mkdir(parents=True, exist_ok=True)
                Path(d, path).write_text(text, encoding='utf-8')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(build.main(['--bump', 'v9.9.10', '--date', '2026-02-03'], repo=Path(d)), 0)
            self.assertIn('v9.9.10', Path(d, build.DESIGN).read_text(encoding='utf-8'))
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(build.main(['--bump', 'v9.9.11', '--check'], repo=Path(d)), 2)
                self.assertEqual(build.main(['--bump', 'v9.9.11', '--date'], repo=Path(d)), 2)
            self.assertIn('[bump-check]', err.getvalue())
            self.assertIn('[bump-date]', err.getvalue())
            self.assertIn('v9.9.10', Path(d, build.DESIGN).read_text(encoding='utf-8'))


class LineEndings(unittest.TestCase):
    def test_cr_in_doc_set(self):
        snap = make(AGENTS_md='a\r\nb\n')
        self.assertEqual(rules(snap), {('crlf', '')})

    def test_cr_outside_doc_set_is_ignored(self):
        self.assertEqual(rules(make(scratch__x_md='a\r\n')), set())


class Markers(unittest.TestCase):
    def test_missing_marker(self):
        snap = make()
        snap[build.SPEC] = snap[build.SPEC].replace('<!-- END:APPENDIX_A -->', '')
        self.assertEqual(rules(snap), {('marker', build.SPEC)})


def revision(version, rows=()):
    """The two files check_revision reads: the spec header and review-log chapter 4."""
    log = '# 審查處置紀錄\n\n## 4. 修訂紀錄\n\n| 版本 | 日期 | 內容 |\n|---|---|---|\n'
    log += ''.join(f'| {v} | 2026-01-01 | 修訂。 |\n' for v in rows)
    log += '\n## 5. 已取消的宣稱\n\n| v9.9.9 | 不是修訂紀錄 |\n'
    return {build.SPEC: f'# 規格\n\n> **版本**：{version}（四份文件共用版本號）\n', build.REVIEW: log}


BASE = revision('v1.4.5', rows=['v1.4.5'])
BUMPED = revision('v1.4.6', rows=['v1.4.5', 'v1.4.6'])
GOVERNED = ['docs/toolkit/spec.md', 'docs/toolkit/tools/build.py', 'docs/toolkit/README.md', 'GLOSSARY.md',
            'docs/adr/0001-x.md', 'CODING_STANDARDS.md', 'AGENTS.md', 'docs/agents/issue-tracker.md',
            '.claude/agents/reviewer.md']
EXEMPT = ['toolkit/scan.py', 'samples/a/b.json', 'README.md', 'CLAUDE.md', '.github/workflows/docs-check.yml',
          '.githooks/pre-commit']


class RevisionMustBumpVersion(unittest.TestCase):
    """check_revision(changed, base, new, parents): one revision, the paths it changed, two snapshots."""

    def test_each_governed_path_without_a_bump_is_a_problem(self):
        for path in GOVERNED:
            with self.subTest(path=path):
                problems = build.check_revision([path], BASE, BASE)
                self.assertEqual([p.rule for p in problems], ['revision-version'])
                self.assertIn(path, problems[0].message)
                self.assertIn('v1.4.5', problems[0].message)

    def test_every_changed_governed_path_is_named(self):
        problems = build.check_revision(['GLOSSARY.md', 'toolkit/scan.py', 'AGENTS.md'], BASE, BASE)
        self.assertEqual(len(problems), 1)
        self.assertIn('GLOSSARY.md', problems[0].message)
        self.assertIn('AGENTS.md', problems[0].message)
        self.assertNotIn('toolkit/scan.py', problems[0].message)

    def test_newer_version_with_its_row_passes(self):
        for path in GOVERNED:
            with self.subTest(path=path):
                self.assertEqual(build.check_revision([path], BASE, BUMPED), [])

    def test_newer_version_without_its_row_is_a_problem(self):
        new = revision('v1.4.6', rows=['v1.4.5'])
        problems = build.check_revision(['GLOSSARY.md'], BASE, new)
        self.assertEqual([p.rule for p in problems], ['revision-log'])
        self.assertIn('v1.4.6', problems[0].message)

    def test_row_in_another_chapter_does_not_count(self):
        new = revision('v1.4.6', rows=['v1.4.5'])
        new[build.REVIEW] = new[build.REVIEW].replace('v9.9.9', 'v1.4.6')
        self.assertEqual([p.rule for p in build.check_revision(['GLOSSARY.md'], BASE, new)], ['revision-log'])

    def test_older_version_is_a_problem(self):
        new = revision('v1.4.4', rows=['v1.4.5', 'v1.4.4'])
        problems = build.check_revision(['GLOSSARY.md'], BASE, new)
        self.assertEqual([p.rule for p in problems], ['revision-version'])
        self.assertIn('v1.4.4', problems[0].message)

    def test_versions_compare_as_numbers(self):
        base, new = revision('v1.4.9', rows=['v1.4.9']), revision('v1.4.10', rows=['v1.4.9', 'v1.4.10'])
        self.assertEqual(build.check_revision(['GLOSSARY.md'], base, new), [])

    def test_paths_outside_the_rule_need_no_bump(self):
        self.assertEqual(build.check_revision(EXEMPT, BASE, BASE), [])

    def test_lookalike_paths_are_not_governed(self):
        self.assertEqual(build.check_revision(['docs/toolkit-extra/a.md', 'GLOSSARY.md.bak', 'docs/other.md'],
                                              BASE, BASE), [])

    def test_root_commit_and_merge_commit_are_not_checked(self):
        self.assertEqual(build.check_revision(['GLOSSARY.md'], None, BASE, parents=0), [])
        self.assertEqual(build.check_revision(['GLOSSARY.md'], BASE, BASE, parents=2), [])

    def test_unreadable_version_is_a_problem(self):
        new = {**BASE, build.SPEC: '# 規格\n'}
        self.assertEqual([p.rule for p in build.check_revision(['GLOSSARY.md'], BASE, new)], ['header-missing'])

    def test_readme_version_rule_lists_exactly_the_governed_paths(self):
        text = Path(build.REPO, build.README).read_text(encoding='utf-8')
        sentence = next(line for line in text.splitlines() if line.startswith('- 改動 `docs/toolkit/`'))
        listed = set(re.findall(r'`([^`]+)`', sentence.split('時，')[0])) - {'tools/'}
        self.assertEqual(listed, set(build.VERSIONED_PATHS))


    def test_a_bump_alone_passes(self):
        """Only the version headers and the log row change: the revision that bumps is itself accepted."""
        bumped_files = [build.SPEC, build.DESIGN, build.REVIEW, build.SCOPE]
        self.assertEqual(build.check_revision(bumped_files, BASE, BUMPED), [])
        self.assertEqual([p.rule for p in build.check_revision(bumped_files, BASE, BASE)], ['revision-version'])


@unittest.skipUnless(shutil.which('git'), 'git is not installed')
class RevisionGitLayer(unittest.TestCase):
    """The --check-staged and --check-commits modes over throwaway repositories, through main()."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.repo = Path(self.dir.name)
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.email', 'a@b')
        self.git('config', 'user.name', 't')

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.repo), *args], check=True, capture_output=True, text=True).stdout.strip()

    def write(self, snap, **extra):
        for path, text in {**snap, **extra}.items():
            f = self.repo / path
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text, encoding='utf-8', newline='')

    def commit(self, message, snap=None, **extra):
        self.write(snap or {}, **extra)
        self.git('add', '-A')
        self.git('commit', '-q', '-m', message)
        return self.git('rev-parse', 'HEAD')

    def run_main(self, *argv):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = build.main(list(argv), repo=self.repo)
        return code, err.getvalue()

    def test_staged_in_a_repository_without_commits_is_not_checked(self):
        self.write(BASE, **{'GLOSSARY.md': 'a'})
        self.git('add', '-A')
        self.assertEqual(self.run_main('--check-staged'), (0, ''))

    def test_staged_while_a_merge_is_in_progress_is_not_checked(self):
        self.commit('base', BASE, **{'GLOSSARY.md': 'a'})
        self.git('checkout', '-q', '-b', 'side')
        self.commit('side', **{'other.txt': 'x'})
        self.git('checkout', '-q', 'main')
        self.commit('main', **{'more.txt': 'y'})
        subprocess.run(['git', '-C', str(self.repo), 'merge', '--no-commit', '--no-ff', 'side'], check=True, capture_output=True)
        self.write({}, **{'GLOSSARY.md': 'merged change'})
        self.git('add', '-A')
        self.assertEqual(self.run_main('--check-staged'), (0, ''))

    def test_staged_change_without_a_bump_still_fails(self):
        self.commit('base', BASE, **{'GLOSSARY.md': 'a'})
        self.write({}, **{'GLOSSARY.md': 'b'})
        self.git('add', '-A')
        code, err = self.run_main('--check-staged')
        self.assertEqual(code, 2)
        self.assertIn('[revision-version]', err)

    def test_base_that_is_not_an_ancestor_of_head_falls_back_to_the_merge_base(self):
        """A force push: the old tip is a real commit, but no longer in HEAD's history."""
        root = self.commit('base', BASE, **{'GLOSSARY.md': 'a'})
        old_tip = self.commit('old work', **{'GLOSSARY.md': 'old'})
        self.git('reset', '-q', '--hard', root)
        self.commit('forgot to bump', **{'GLOSSARY.md': 'new'})
        code, err = self.run_main('--check-commits', old_tip, '--fallback', root)
        self.assertEqual(code, 2)
        self.assertIn('[revision-version]', err)

    def test_commits_each_missing_a_bump_are_all_named(self):
        root = self.commit('base', BASE, **{'GLOSSARY.md': 'a'})
        first = self.commit('one', **{'GLOSSARY.md': 'b'})
        second = self.commit('two', **{'GLOSSARY.md': 'c'})
        code, err = self.run_main('--check-commits', root)
        self.assertEqual(code, 2)
        self.assertIn(first[:10], err)
        self.assertIn(second[:10], err)


class DiskAdapter(unittest.TestCase):
    def test_snapshot_keeps_cr(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'a.md').write_bytes('甲\r\n'.encode('utf-8'))
            Path(d, 'b.pdf').write_bytes(b'\xff\xfe\x00')
            Path(d, '.git').mkdir()
            Path(d, '.git', 'c.md').write_text('x', encoding='utf-8')
            self.assertEqual(build.load_snapshot(Path(d)), {'a.md': '甲\r\n'})

    def test_real_repo_is_clean(self):
        result = build.check_docs(build.load_snapshot())
        self.assertEqual([build.format_problem(p) for p in result.problems], [])
        self.assertEqual(list(result.updates), [], 'generated outputs are stale; run tools/build.py')


if __name__ == '__main__':
    unittest.main()
