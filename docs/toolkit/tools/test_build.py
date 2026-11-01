"""Tests for build.py, through its interface: check_docs(snapshot).

Run (from anywhere):
  python -I -m unittest discover -s docs/toolkit/tools -v
"""
import json
import sys
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
        build.DESIGN: '# 設計說明\n\n> **版本**：v9.9.9\n\n見 [R1]。\n\n- **[R1]** 參考資料。\n',
        build.REVIEW: '# 審查處置紀錄\n\n> **版本**：v9.9.9\n',
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
