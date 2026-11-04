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

    def without_commit(self, status, preflight='completed'):
        """The example report with no commit anywhere, as a run whose ScanManifest named none."""
        doc = valid_report()
        doc['status'] = status
        if status != 'completed':
            doc['status_reason'] = 'commit (受測範圍) is missing'
        for stage in doc['stages']:
            if stage['stage'] == 'preflight' and preflight != 'completed':
                stage.update(status=preflight, reason='commit (受測範圍) is missing')
        for rec in [doc, *doc['execution_records'], *doc['findings'], doc['coverage']]:
            rec['commit'] = None
        return doc

    def test_report_blocked_at_preflight_may_name_no_commit(self):
        # TK-DAT-001's one exception: blocked before any source is read.
        self.assertEqual(report.validate(self.without_commit('blocked', preflight='blocked')), [])

    def test_example_report_without_a_commit_is_valid(self):
        doc = json.loads((FIXTURES / 'report-blocked-no-commit.json').read_text(encoding='utf-8'))
        self.assertEqual(report.validate(doc), [])
        self.assertIsNone(doc['commit'])
        self.assertEqual({s['stage']: s['status'] for s in doc['stages']}['preflight'], 'blocked')

    def test_report_blocked_after_preflight_must_name_its_commit(self):
        problems = report.validate(self.without_commit('blocked', preflight='completed'))
        self.assertTrue(any(p.startswith('commit') for p in problems), problems)

    def test_run_that_was_not_blocked_must_name_its_commit(self):
        for status in ('completed', 'partial'):
            with self.subTest(status=status):
                problems = report.validate(self.without_commit(status))
                self.assertTrue(any(p.startswith('commit') for p in problems), problems)

    # TK-RUN-002: 待執行、執行中、完整完成、部分完成、受阻、失敗、已取消 (codes per the plan's Q7).
    RUN_STATUSES = ['pending', 'running', 'completed', 'partial', 'blocked', 'failed', 'cancelled']

    def test_requirement_entries_name_their_item_source_and_review_state(self):
        for field in ('id', 'source', 'statement', 'rule', 'status', 'out_of_scope', 'confirmation'):
            with self.subTest(missing=field):
                doc = valid_report()
                del doc['requirements'][0][field]
                self.assertTrue(any('requirements' in p and field in p for p in report.validate(doc)),
                                report.validate(doc))
        doc = valid_report()
        doc['requirements'][0]['status'] = 'confirmed'  # a finding state, not a review state
        self.assertNotEqual(report.validate(doc), [])
        doc = valid_report()
        doc['requirements'][0]['source'] = 'implementation'  # TK-REQ-005
        self.assertNotEqual(report.validate(doc), [])

    def test_records_name_the_version_of_the_item_they_rest_on(self):
        # TK-REQ-004: executions and findings point at the item version they were judged on.
        for key in ('execution_records', 'findings'):
            with self.subTest(missing_in=key):
                doc = valid_report()
                del doc[key][0]['requirement_version']
                self.assertTrue(any(key in p and 'requirement_version' in p for p in report.validate(doc)),
                                report.validate(doc))
        for value in (0, '1'):
            with self.subTest(value=value):
                doc = valid_report()
                doc['execution_records'][0]['requirement_version'] = value
                self.assertNotEqual(report.validate(doc), [])
        doc = json.loads((FIXTURES / 'report-blocked-no-commit.json').read_text(encoding='utf-8'))
        doc['execution_records'][0].update(requirement_id='REQ-NOT-IN-THE-LIST', requirement_version=None)
        self.assertEqual(report.validate(doc), [])  # a test on no item of the list names no version

    def test_confirmation_list_reference_is_checked(self):
        self.assertEqual(valid_report()['confirmation_list']['updated'], False)
        for field in ('path', 'digest', 'list_version', 'updated', 's2_template', 'summary', 'out_of_scope',
                      'single_approval'):
            with self.subTest(missing=field):
                doc = valid_report()
                del doc['confirmation_list'][field]
                self.assertNotEqual(report.validate(doc), [])

    def test_summary_counts_every_review_state_of_both_sources(self):
        for source, status in (('S1', 'pending'), ('S2', 'not_applicable')):
            with self.subTest(source=source, status=status):
                doc = valid_report()
                del doc['confirmation_list']['summary'][source][status]
                self.assertNotEqual(report.validate(doc), [])
        doc = valid_report()
        doc['confirmation_list']['summary']['S2']['out_of_scope'] = 0  # out of scope is not a review state
        self.assertNotEqual(report.validate(doc), [])
        doc = valid_report()
        doc['confirmation_list']['summary']['S3'] = doc['confirmation_list']['summary']['S1']  # TK-REQ-005
        self.assertNotEqual(report.validate(doc), [])

    def test_a_finding_on_a_pending_item_cannot_be_confirmed(self):
        # TK-REQ-003: at most 證據待補 (evidence_pending).
        doc = valid_report()
        doc['requirements'][0].update(status='pending', confirmation={'by': None, 'at': None, 'version': 1})
        self.assertTrue(any('findings/0' in p and 'TK-REQ-003' in p for p in report.validate(doc)), report.validate(doc))
        doc['findings'][0]['status'] = 'evidence_pending'
        self.assertEqual(report.validate(doc), [])

    def test_a_test_on_an_item_that_cannot_be_tested_must_be_blocked(self):
        # 〈定義：確認清單〉: a pending S1 entry, a not applicable or an out-of-scope item blocks its tests.
        s1_pending = {'id': 'S1-X', 'source': 'S1', 'status': 'pending'}
        for change in (s1_pending, {'status': 'not_applicable'}, {'out_of_scope': True}):
            with self.subTest(change=change):
                doc = valid_report()
                doc['findings'] = []
                doc['requirements'][0].update(change)
                for e in doc['execution_records']:
                    e['requirement_id'] = doc['requirements'][0]['id']
                problems = report.validate(doc)
                self.assertTrue(any('execution_records/1' in p and 'blocked' in p for p in problems), problems)

    def test_a_judged_test_must_match_its_items_rule(self):
        # TK-REQ-016: an allowed case on a deny item (or a denial case on an allow item) is blocked.
        doc = valid_report()
        doc['findings'] = []
        doc['execution_records'][1].update(case_kind='allowed', checks={'access_granted': True})  # the item denies
        problems = report.validate(doc)
        self.assertTrue(any('execution_records/1' in p and 'TK-REQ-016' in p for p in problems), problems)
        doc['execution_records'][1].update(result='blocked', error='mismatch')
        doc['status'], doc['status_reason'] = 'partial', 'mismatch'
        self.assertFalse(any('TK-REQ-016' in p for p in report.validate(doc)), report.validate(doc))

    def test_records_name_the_item_version_the_report_lists(self):
        doc = valid_report()
        doc['execution_records'][1]['requirement_version'] = 2  # the listed item is version 1
        self.assertTrue(any('execution_records/1' in p and 'requirement_version' in p for p in report.validate(doc)),
                        report.validate(doc))

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


class Authorization(unittest.TestCase):
    """〈定義：測試授權紀錄〉 in the report (TK-ENV-001, TK-ENV-002, TK-ENV-006)."""

    def test_the_example_report_shows_its_authorization_and_no_source_changes(self):
        doc = valid_report()
        self.assertIs(doc['authorization']['identity_verified'], False)
        self.assertEqual(doc['source_changes'], [])
        self.assertEqual(report.validate(doc), [])

    def test_names_in_the_authorization_are_never_reported_as_verified(self):
        doc = valid_report()
        doc['authorization']['identity_verified'] = True
        self.assertNotEqual(report.validate(doc), [])

    def test_a_source_change_is_not_reported_by_v01(self):
        doc = valid_report()
        doc['source_changes'] = [{'path': 'src/auth.ts', 'reason': 'disable MFA'}]
        self.assertNotEqual(report.validate(doc), [])
        del doc['source_changes']
        self.assertNotEqual(report.validate(doc), [])

    def test_a_record_names_only_an_extra_approval_of_the_authorization(self):
        doc = valid_report()
        doc['execution_records'][0]['approval_id'] = 'APR-001'
        self.assertEqual(report.validate(doc), [])
        doc['execution_records'][0]['approval_id'] = 'APR-999'
        self.assertIn("execution_records/0: approval_id 'APR-999' is not an extra approval of the authorization",
                      '; '.join(report.validate(doc)))
        del doc['authorization']
        self.assertTrue(any('execution_records/0: approval_id' in p for p in report.validate(doc)), report.validate(doc))


class RenderMarkdown(unittest.TestCase):
    """TK-EVD-003: Markdown for human review is generated from the JSON report."""

    # Spec names (TK-RUN-002, 〈定義：測試結果〉, 〈定義：問題狀態〉).
    RUN_LABELS = {'pending': '待執行', 'running': '執行中', 'completed': '完整完成', 'partial': '部分完成',
                  'blocked': '受阻', 'failed': '失敗', 'cancelled': '已取消'}
    DISCLAIMER = '不代表應用沒有漏洞'

    # 〈定義：確認清單〉 處理狀態.
    REVIEW_LABELS = {'pending': '待確認', 'accepted': '接受', 'modified': '修改', 'not_applicable': '不適用'}

    @staticmethod
    def listed_item(**changes):
        """The example report with its listed item changed and no record resting on it, so that the item
        can take any review state (records on it are checked in Validate)."""
        doc = valid_report()
        doc['requirements'][0].update(changes)
        for r in doc['execution_records'] + doc['findings']:
            r['requirement_id'] = 'S2-TENANT-ISOLATION@documents'
        return doc

    def test_confirmation_items_are_shown_with_their_review_state(self):
        for status, label in self.REVIEW_LABELS.items():
            with self.subTest(status=status):
                md = report.render_markdown(self.listed_item(status=status))
                self.assertIn(f'| {label} |', md)
                self.assertIn('S2-OWNER-ONLY@documents', md)

    def test_an_item_nobody_reviewed_shows_no_reviewer(self):
        md = report.render_markdown(self.listed_item(status='pending', confirmation={'by': None, 'at': None, 'version': 1}))
        self.assertIn('（未確認）', md)
        self.assertNotIn('None', md)

    def test_a_legitimate_exception_shows_the_tests_it_allows_and_its_expiry(self):
        md = report.render_markdown(self.listed_item(status='modified', confirmation={
            'by': 'app-owner', 'at': '2026-11-01T09:00:00Z', 'version': 1,
            'allowed_tests': ['SHARED-READ-other-tenant'], 'expiry': '2027-05-01T00:00:00Z'}))
        self.assertIn('| 修改（合法例外：放行 `SHARED-READ-other-tenant`，到期 2027-05-01T00:00:00Z） |', md)
        md = report.render_markdown(self.listed_item(status='modified', confirmation={
            'by': 'app-owner', 'at': '2026-11-01T09:00:00Z', 'version': 1, 'allowed_tests': ['SHARED-READ-other-tenant']}))
        self.assertIn('到期 （未填）', md)
        self.assertNotIn('None', md)

    def test_the_authorization_is_shown_with_its_unverified_names_and_the_approvals_used(self):
        doc = valid_report()
        doc['execution_records'][0]['approval_id'] = 'APR-001'
        md = report.render_markdown(doc)
        self.assertIn('## 測試授權', md)
        self.assertIn('`object-authz/vulnerable`（E1）', md)
        self.assertIn('2026-11-01T00:00:00Z 至 2026-12-01T00:00:00Z', md)
        self.assertIn('身分未經驗證', md)
        self.assertIn('`APR-001`', md)
        self.assertIn('security-lead', md)
        self.assertIn('`AUTHZ-001-same-tenant`', md.split('## 測試授權')[1].split('\n## ')[0])
        self.assertIn('測試用原始碼變更：無', md)

    def test_an_item_out_of_scope_is_marked(self):
        self.assertIn('範圍外', report.render_markdown(self.listed_item(out_of_scope=True)))

    def test_review_summary_is_shown_by_source_with_the_list_it_comes_from(self):
        # TK-REQ-003 報告列出各類待確認數量; the list version and digest it counts (TK-REQ-004).
        doc = valid_report()
        doc['confirmation_list']['summary']['S2'].update(pending=2, modified=1)
        doc['confirmation_list'].update(out_of_scope=3, single_approval=['S2-TENANT-ISOLATION@documents'])
        md = report.render_markdown(doc)
        section = md[md.index('## 確認狀態摘要'):]
        self.assertIn('| 來源 | 待確認 | 接受 | 修改 | 不適用 |', section)
        self.assertIn('| S1 | 0 | 0 | 0 | 0 |', section)
        self.assertIn('| S2 | 2 | 1 | 1 | 0 |', section)
        self.assertIn('範圍外 3', section)
        self.assertIn('v1', section)
        self.assertIn('sha256:1111', section)
        self.assertIn('nextjs-supabase-object-authz', section)
        self.assertIn('單人核准', section)
        self.assertIn('S2-TENANT-ISOLATION@documents', section)

    def test_a_handed_over_list_says_the_owner_has_to_review_it(self):
        doc = valid_report()
        doc['confirmation_list']['updated'] = True
        md = report.render_markdown(doc)  # also for a completed run, which has no status_reason
        self.assertIn('待負責人處理', md)
        self.assertIn('更新 ScanManifest 的引用', md)
        self.assertNotIn('待負責人處理', report.render_markdown(valid_report()))

    def test_missing_commit_is_shown_as_not_provided(self):
        doc = json.loads((FIXTURES / 'report-blocked-no-commit.json').read_text(encoding='utf-8'))
        md = report.render_markdown(doc)
        self.assertIn('- **受測提交**：（未提供）', md)
        self.assertNotIn('None', md)

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
    """〈定義：核心資料物件與相依紀錄〉 ExecutionRecord: every piece of evidence names its channel (actor or observer)."""

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


class TestNames(unittest.TestCase):
    """A record that ran names its test with non-empty text; only one that could not run may echo unusable values."""

    FIELDS = ('test_id', 'template_id', 'requirement_id', 'actor_ref', 'resource_ref')

    def test_record_that_ran_needs_text_names(self):
        for field in self.FIELDS:
            for value in (None, ''):
                with self.subTest(field=field, value=value):
                    doc = valid_report()
                    doc['execution_records'][0][field] = value  # a failed record
                    problems = report.validate(doc)
                    self.assertTrue(any(field in p for p in problems), problems)


class ApiKeyFormats(unittest.TestCase):
    """TK-DYN-004: actor evidence names the API key format the request used (legacy anon JWT or sb_publishable_)."""

    def actor_evidence(self, doc):
        return next(ev for ev in doc['execution_records'][0]['evidence'] if ev['channel'] == 'actor')

    def test_example_report_names_the_key_format(self):
        self.assertIn(self.actor_evidence(valid_report())['api_key_format'], ('anon-jwt', 'publishable'))

    def test_both_key_formats_are_accepted(self):
        for fmt in ('anon-jwt', 'publishable'):
            with self.subTest(format=fmt):
                doc = valid_report()
                self.actor_evidence(doc)['api_key_format'] = fmt
                self.assertEqual(report.validate(doc), [])

    def test_unknown_key_format_is_rejected(self):
        for fmt in ('service_role', 'secret', ''):
            with self.subTest(format=fmt):
                doc = valid_report()
                self.actor_evidence(doc)['api_key_format'] = fmt
                self.assertNotEqual(report.validate(doc), [])

    def test_actor_evidence_without_a_key_format_is_rejected(self):
        doc = valid_report()
        del self.actor_evidence(doc)['api_key_format']
        problems = report.validate(doc)
        self.assertTrue(any('api_key_format' in p for p in problems), problems)


class Observations(unittest.TestCase):
    """TK-DYN-001 item 4: an observation covers the whole table, so changes to other rows show as side effects."""

    def observation(self, doc):
        return next(ev for ev in doc['execution_records'][0]['evidence'] if ev['channel'] == 'observer')['observation']

    def test_example_report_observes_the_table(self):
        obs = self.observation(valid_report())
        self.assertIsInstance(obs['table_rows'], int)
        self.assertTrue(obs['table_digest'])

    def test_observation_without_the_table_state_is_rejected(self):
        for field in ('table_rows', 'table_digest'):
            with self.subTest(removed=field):
                doc = valid_report()
                del self.observation(doc)[field]
                problems = report.validate(doc)
                self.assertTrue(any(field in p for p in problems), problems)

    def test_table_rows_is_a_count(self):
        for value in (-1, 1.5, '3', None):
            with self.subTest(table_rows=value):
                doc = valid_report()
                self.observation(doc)['table_rows'] = value
                self.assertNotEqual(report.validate(doc), [])


class Faults(unittest.TestCase):
    """TK-VAL-001: a self-validation run marks the execution records of undeterminable cases with the injected fault."""

    def faulted_report(self, fault=None):
        """The example partial run (session revoked); fault, when given, replaces the injected fault."""
        doc = json.loads((FIXTURES / 'report-partial-fault.json').read_text(encoding='utf-8'))
        if fault is not None:
            self.faulted_record(doc)['fault'] = fault
        return doc

    def faulted_record(self, doc):
        return next(e for e in doc['execution_records'] if 'fault' in e)

    def test_example_report_shows_a_blocked_case_with_its_fault(self):
        doc = self.faulted_report()
        ex = self.faulted_record(doc)
        self.assertEqual((ex['result'], ex['fault'], ex['checks']['identity']), ('blocked', 'session-revoked', False))
        self.assertEqual(doc['status'], 'partial')
        self.assertEqual(report.validate(doc), [])

    def test_example_report_shows_a_case_blocked_for_a_missing_api_key(self):
        # TK-DYN-004: blocked before any request, so the record carries no evidence and no checks.
        ex = next(e for e in self.faulted_report()['execution_records'] if e.get('fault') == 'api-key-missing')
        self.assertEqual((ex['result'], ex['evidence']), ('blocked', []))
        self.assertNotIn('checks', ex)
        self.assertIn("'anon-jwt'", ex['error'])

    def test_known_faults_are_accepted(self):
        for fault in ('session-revoked', 'observer-unavailable', 'observer-timeout', 'api-unreachable',
                      'api-key-missing'):
            with self.subTest(fault=fault):
                self.assertEqual(report.validate(self.faulted_report(fault)), [])

    def test_unknown_fault_is_rejected(self):
        for fault in ('network-down', ''):
            with self.subTest(fault=fault):
                self.assertNotEqual(report.validate(self.faulted_report(fault)), [])


class UnsupportedItems(unittest.TestCase):
    """TK-EVD-008: scope without a verified test method is listed with its reason, not dropped from coverage."""

    def test_example_report_lists_an_unsupported_item(self):
        items = valid_report()['coverage']['unsupported_items']
        self.assertTrue(items)
        self.assertTrue(all(i['scope'] and i['reason'] for i in items))

    def test_item_without_scope_or_reason_is_rejected(self):
        for field in ('scope', 'reason'):
            with self.subTest(removed=field):
                doc = valid_report()
                del doc['coverage']['unsupported_items'][0][field]
                problems = report.validate(doc)
                self.assertTrue(any(field in p for p in problems), problems)


class UnlistedFields(unittest.TestCase):
    """CODING_STANDARDS.md rule 9: a field the schema does not list is a validation problem, not silently kept."""

    def test_unlisted_evidence_field_is_rejected(self):
        for i in (0, 1):  # an observer and an actor piece of evidence
            with self.subTest(evidence=i):
                doc = valid_report()
                doc['execution_records'][0]['evidence'][i]['raw_password'] = 'x'
                problems = report.validate(doc)
                self.assertTrue(any('raw_password' in p for p in problems), problems)

    def test_unlisted_request_or_response_field_is_rejected(self):
        for part in ('request', 'response'):
            with self.subTest(part=part):
                doc = valid_report()
                doc['execution_records'][0]['evidence'][1][part]['authorization'] = 'Bearer x'
                problems = report.validate(doc)
                self.assertTrue(any('authorization' in p for p in problems), problems)

    def test_unlisted_observation_field_is_rejected(self):
        doc = valid_report()
        doc['execution_records'][0]['evidence'][0]['observation']['row_body'] = 'private text'
        problems = report.validate(doc)
        self.assertTrue(any('row_body' in p for p in problems), problems)

    def test_unlisted_execution_record_field_is_rejected(self):
        doc = valid_report()
        doc['execution_records'][0]['observer_password'] = 'x'
        problems = report.validate(doc)
        self.assertTrue(any('observer_password' in p for p in problems), problems)


class DenialChecks(unittest.TestCase):
    """TK-DYN-001: a denial case passes only when all four checks were made and hold."""

    # The four checks of TK-DYN-001, in the spec's order.
    CHECKS = ['resource_and_control', 'identity', 'no_disclosure_or_change', 'response_and_side_effects']

    def passed_record(self, doc):
        return next(e for e in doc['execution_records'] if e['result'] == 'passed')

    def test_passed_record_missing_any_check_is_rejected(self):
        for check in self.CHECKS:
            with self.subTest(removed=check):
                doc = valid_report()
                del self.passed_record(doc)['checks'][check]
                problems = report.validate(doc)
                self.assertTrue(any(check in p for p in problems), problems)

    def test_passed_record_without_checks_is_rejected(self):
        doc = valid_report()
        del self.passed_record(doc)['checks']
        self.assertTrue(any('checks' in p for p in report.validate(doc)))

    def test_passed_record_with_a_failing_check_is_rejected(self):
        for check in self.CHECKS:
            with self.subTest(failing=check):
                doc = valid_report()
                self.passed_record(doc)['checks'][check] = False
                problems = report.validate(doc)
                self.assertTrue(any(check in p for p in problems), problems)

    def test_failed_record_may_hold_failing_checks(self):
        doc = valid_report()
        failed = next(e for e in doc['execution_records'] if e['result'] == 'failed')
        self.assertIn(False, failed['checks'].values())
        self.assertEqual(report.validate(doc), [])

    def test_check_values_are_booleans(self):
        doc = valid_report()
        doc['execution_records'][0]['checks']['identity'] = 'yes'
        self.assertNotEqual(report.validate(doc), [])


class ObservationPoints(unittest.TestCase):
    """TK-IDN-010: the ExecutionRecord states when each observation was made."""

    def observer_evidence(self, doc):
        return next(ev for ev in doc['execution_records'][0]['evidence'] if ev['channel'] == 'observer')

    def test_observation_without_a_point_is_rejected(self):
        doc = valid_report()
        del self.observer_evidence(doc)['point']
        self.assertTrue(any('point' in p for p in report.validate(doc)))

    def test_observation_points_of_the_spec_are_accepted(self):
        for point in ('before', 'after', 'after_background'):  # 執行前、執行後、背景工作完成後
            with self.subTest(point=point):
                doc = valid_report()
                self.observer_evidence(doc)['point'] = point
                self.assertEqual(report.validate(doc), [])

    def test_unknown_observation_point_is_rejected(self):
        doc = valid_report()
        self.observer_evidence(doc)['point'] = 'whenever'
        self.assertNotEqual(report.validate(doc), [])


class AllowedCases(unittest.TestCase):
    """A case whose requirement allows the access (e.g. public data) passes when access was granted."""

    def allowed(self, doc, granted=True):
        # An allowed case rests on an item whose rule allows the access (TK-REQ-016).
        doc['requirements'].append({'id': 'S1-ANNOUNCEMENTS-PUBLIC-READ', 'source': 'S1', 'rule': 'allow',
                                    'statement': 'Anyone may read announcements.', 'status': 'accepted',
                                    'out_of_scope': False,
                                    'confirmation': {'by': 'app-owner', 'at': '2026-11-01T09:00:00Z', 'version': 1}})
        e = doc['execution_records'][1]
        e.update(requirement_id='S1-ANNOUNCEMENTS-PUBLIC-READ', requirement_version=1)
        e['case_kind'] = 'allowed'
        e['checks'] = {'access_granted': granted}
        return doc

    def exception(self, doc):
        """An allowed case on the deny item of the example report, made a 合法例外; returns the case's test_id."""
        doc['findings'] = []
        doc['requirements'][0].update(status='modified')
        doc['requirements'][0]['confirmation']['expiry'] = '2027-05-01T00:00:00Z'
        e = doc['execution_records'][1]
        e.update(case_kind='allowed', checks={'access_granted': True})
        return doc, e['test_id']

    def test_a_legitimate_exception_allows_only_the_tests_it_lists(self):
        # TK-DYN-003: the item's rule is deny; only its allowed tests are judged by allow (〈定義：確認清單〉 修改).
        doc, test_id = self.exception(valid_report())
        doc['requirements'][0]['confirmation']['allowed_tests'] = [test_id]
        self.assertEqual(report.validate(doc), [])
        for change in ({'confirmation': dict(doc['requirements'][0]['confirmation'], allowed_tests=['ANOTHER-TEST'])},
                       {'status': 'accepted'}):  # only a modified item can be a 合法例外
            with self.subTest(change=change):
                bad = copy.deepcopy(doc)
                bad['requirements'][0].update(change)
                problems = report.validate(bad)
                self.assertTrue(any('execution_records/1' in p and "rule 'deny'" in p and 'TK-REQ-016' in p
                                    for p in problems), problems)

    def test_a_denial_case_a_legitimate_exception_lists_keeps_the_items_rule(self):
        doc, test_id = self.exception(valid_report())
        denial = doc['execution_records'][0]
        doc['requirements'][0]['confirmation']['allowed_tests'] = [test_id, denial['test_id']]
        self.assertEqual(report.validate(doc), [])  # the denial case stays judged by deny

    def test_passed_allowed_case_needs_no_denial_checks(self):
        self.assertEqual(report.validate(self.allowed(valid_report())), [])

    def test_passed_allowed_case_needs_granted_access(self):
        self.assertNotEqual(report.validate(self.allowed(valid_report(), granted=False)), [])

    def test_denial_case_still_needs_its_four_checks(self):
        doc = valid_report()
        doc['execution_records'][1]['case_kind'] = 'denial'
        doc['execution_records'][1]['checks'] = {'access_granted': True}
        self.assertNotEqual(report.validate(doc), [])


class Stages(unittest.TestCase):
    """TK-RUN-001: the report records every stage of 〈定義：工作階段〉 and its status."""

    # 前置檢查、靜態與架構分析、模型審查、威脅與測試規劃、動態執行、判定與報告.
    STAGES = ['preflight', 'static_analysis', 'model_review', 'threat_planning', 'dynamic_execution',
              'judgement_report']

    def test_report_without_stages_is_rejected(self):
        doc = valid_report()
        del doc['stages']
        self.assertTrue(any('stages' in p for p in report.validate(doc)))

    def test_every_spec_stage_must_be_listed(self):
        for stage in self.STAGES:
            with self.subTest(missing=stage):
                doc = valid_report()
                doc['stages'] = [s for s in doc['stages'] if s['stage'] != stage]
                problems = report.validate(doc)
                self.assertTrue(any(stage in p for p in problems), problems)

    def test_unknown_stage_status_is_rejected(self):
        doc = valid_report()
        doc['stages'][0]['status'] = 'probably-fine'
        self.assertNotEqual(report.validate(doc), [])

    def test_stage_that_did_not_complete_needs_a_reason(self):
        for status in ('failed', 'blocked', 'not_run'):
            with self.subTest(status=status):
                doc = valid_report()
                doc['stages'][4] = {'stage': 'dynamic_execution', 'status': status}
                self.assertNotEqual(report.validate(doc), [])
