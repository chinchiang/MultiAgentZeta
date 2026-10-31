"""Report contract, tested through validate(report) and render_markdown(report).

The fixtures are hand-written reports (not produced by the toolkit), so expected
results come from the spec's definitions rather than from the code under test.
"""
import copy
import json
import unittest
from pathlib import Path

from toolkit import report

FIXTURES = Path(__file__).with_name('fixtures')


def valid_report():
    return json.loads((FIXTURES / 'report-valid.json').read_text(encoding='utf-8'))


class Validate(unittest.TestCase):
    def test_valid_report_has_no_problems(self):
        self.assertEqual(report.validate(valid_report()), [])

    # 〈定義：共用欄位〉: schema_version, run_id, a unique id, creation time, source id;
    # TK-DAT-001 adds the commit the record is bound to.
    COMMON = ['schema_version', 'run_id', 'id', 'created_at', 'source_id', 'commit']

    @staticmethod
    def records(doc):
        """(label, record) for the report itself and every record inside it."""
        yield 'report', doc
        for i, r in enumerate(doc['execution_records']):
            yield f'execution_records/{i}', r
        for i, r in enumerate(doc['findings']):
            yield f'findings/{i}', r
        yield 'coverage', doc['coverage']

    def test_record_missing_a_common_field_is_rejected(self):
        for label, _ in self.records(valid_report()):
            for field in self.COMMON:
                with self.subTest(record=label, field=field):
                    doc = valid_report()
                    target = dict(self.records(doc))[label]
                    del target[field]
                    problems = report.validate(doc)
                    self.assertTrue(any(field in p for p in problems), problems)

    def test_empty_commit_is_rejected(self):
        doc = valid_report()
        doc['findings'][0]['commit'] = ''
        self.assertNotEqual(report.validate(doc), [])

    # TK-RUN-002: 待執行、執行中、完整完成、部分完成、受阻、失敗、已取消 (codes per the plan's Q7).
    RUN_STATUSES = ['pending', 'running', 'completed', 'partial', 'blocked', 'failed', 'cancelled']

    def test_every_run_status_of_the_spec_is_accepted(self):
        for status in self.RUN_STATUSES:
            with self.subTest(status=status):
                doc = valid_report()
                doc['status'] = status
                self.assertEqual(report.validate(doc), [])

    def test_unknown_run_status_is_rejected(self):
        for status in ['safe', 'no_vulnerabilities', 'done', '']:
            with self.subTest(status=status):
                doc = valid_report()
                doc['status'] = status
                self.assertTrue(any('status' in p for p in report.validate(doc)))

    # 〈定義：問題狀態〉 已確認: dynamic or other sufficient evidence shows the requirement is violated.
    def test_confirmed_finding_needs_a_failed_execution_record(self):
        cases = {
            'no execution record': [],
            'only a passed execution record': ['exec-0002'],
            'an execution record that does not exist': ['exec-9999'],
        }
        for case, ids in cases.items():
            with self.subTest(case=case):
                doc = valid_report()
                doc['findings'][0]['execution_record_ids'] = ids
                self.assertTrue(any('findings/0' in p for p in report.validate(doc)), report.validate(doc))

    # TK-RUN-002: 完整完成 means every planned item got a definite result (通過 or 未通過).
    NOT_DEFINITE = ['blocked', 'error', 'untested', 'unsupported']

    def test_completed_run_with_an_indefinite_test_result_is_rejected(self):
        for result in self.NOT_DEFINITE:
            with self.subTest(result=result):
                doc = valid_report()
                doc['execution_records'][1]['result'] = result
                self.assertNotEqual(report.validate(doc), [])

    def test_partial_run_may_hold_indefinite_test_results(self):
        for result in self.NOT_DEFINITE:
            with self.subTest(result=result):
                doc = valid_report()
                doc['status'] = 'partial'
                doc['execution_records'][1]['result'] = result
                self.assertEqual(report.validate(doc), [])

    def test_record_from_another_run_or_commit_is_rejected(self):
        for label, _ in list(self.records(valid_report()))[1:]:
            for field, other in (('run_id', 'run-other'), ('commit', 'deadbee')):
                with self.subTest(record=label, field=field):
                    doc = valid_report()
                    dict(self.records(doc))[label][field] = other
                    problems = report.validate(doc)
                    self.assertTrue(any(label in p and field in p for p in problems), problems)


class RenderMarkdown(unittest.TestCase):
    """TK-EVD-003: Markdown for human review is generated from the JSON report."""

    # Spec names (TK-RUN-002, 〈定義：測試結果〉, 〈定義：問題狀態〉).
    RUN_LABELS = {'pending': '待執行', 'running': '執行中', 'completed': '完整完成', 'partial': '部分完成',
                  'blocked': '受阻', 'failed': '失敗', 'cancelled': '已取消'}
    DISCLAIMER = '不代表應用沒有漏洞'

    def test_run_status_is_shown_with_its_spec_name(self):
        for status, label in self.RUN_LABELS.items():
            with self.subTest(status=status):
                doc = valid_report()
                doc['status'] = status
                self.assertIn(label, report.render_markdown(doc))

    def test_completed_run_is_not_presented_as_free_of_vulnerabilities(self):
        md = report.render_markdown(valid_report())
        self.assertIn(self.DISCLAIMER, md)
        rest = md.replace(self.DISCLAIMER, '')
        for claim in ('沒有漏洞', '無漏洞', '安全通過', '沒有發現問題'):
            self.assertNotIn(claim, rest)

    def test_test_results_and_finding_status_are_shown_separately(self):
        md = report.render_markdown(valid_report())
        self.assertIn('AUTHZ-001-same-tenant', md)
        self.assertIn('未通過', md)
        self.assertIn('通過', md.replace('未通過', ''))
        self.assertIn('已確認', md)

    def test_markdown_follows_the_json(self):
        doc = valid_report()
        doc['findings'][0]['fingerprint'] = 'sha256:' + 'ab' * 32
        self.assertIn('sha256:' + 'ab' * 32, report.render_markdown(doc))

    def test_status_reason_is_shown(self):
        doc = valid_report()
        doc['status'] = 'blocked'
        doc['status_reason'] = 'environment blocked at BuildRecipe step auth'
        md = report.render_markdown(doc)
        self.assertIn('受阻', md)
        self.assertIn('environment blocked at BuildRecipe step auth', md)

    def test_empty_status_reason_is_rejected(self):
        doc = valid_report()
        doc['status_reason'] = ''
        self.assertTrue(any('status_reason' in p for p in report.validate(doc)))

    def test_invalid_report_is_not_rendered(self):
        doc = valid_report()
        doc['status'] = 'safe'
        with self.assertRaises(ValueError):
            report.render_markdown(doc)


class Evidence(unittest.TestCase):
    """〈定義：核心資料物件〉 ExecutionRecord: every piece of evidence names its channel (actor or observer)."""

    def test_evidence_without_a_channel_is_rejected(self):
        doc = valid_report()
        del doc['execution_records'][0]['evidence'][0]['channel']
        self.assertTrue(any('channel' in p for p in report.validate(doc)))

    def test_unknown_channel_is_rejected(self):
        for channel in ('provisioning', 'admin', 'model'):
            with self.subTest(channel=channel):
                doc = valid_report()
                doc['execution_records'][0]['evidence'][0]['channel'] = channel
                self.assertNotEqual(report.validate(doc), [])

    def test_evidence_without_an_identity_is_rejected(self):
        doc = valid_report()
        del doc['execution_records'][0]['evidence'][1]['identity_ref']
        self.assertTrue(any('identity_ref' in p for p in report.validate(doc)))
