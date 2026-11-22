"""Report contract, tested through validate(report) and render_markdown(report).

The fixtures are hand-written reports (not produced by the toolkit), so expected
results come from the spec's definitions rather than from the code under test.
"""
import copy
import json
import re
import unittest
from pathlib import Path

from toolkit import report

FIXTURES = Path(__file__).with_name('fixtures')


def valid_report():
    return json.loads((FIXTURES / 'report-valid.json').read_text(encoding='utf-8'))


class Validate(unittest.TestCase):
    def test_valid_report_has_no_problems(self):
        self.assertEqual(report.validate(valid_report()), [])

    def test_each_stage_is_listed_only_once_even_with_a_different_status(self):
        for status in ('completed', 'blocked'):
            with self.subTest(status=status):
                doc = valid_report()
                doc['stages'].append({**doc['stages'][0], 'status': status, 'reason': 'regression test'})
                problems = report.validate(doc)
                self.assertTrue(any('preflight' in p and 'duplicate' in p for p in problems), problems)

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

    # 〈定義：覆核紀錄〉: a finding's review, written by hand here, not by toolkit.review.
    REVIEW = {'state': 'evidence_pending', 'opened_at': '2026-11-09T01:00:00Z',
              'decision': {'option': 'evidence_pending', 'by': {'id': 101, 'login': 'sec-alice'},
                           'at': '2026-11-09T03:00:00Z', 'reason': 'the evidence is thin'}}

    def test_a_finding_sent_back_for_evidence_cannot_be_confirmed(self):
        doc = valid_report()
        doc['findings'][0]['review'] = copy.deepcopy(self.REVIEW)
        doc['review_summary'].update(approved=0, evidence_pending=1)
        self.assertTrue(any('findings/0' in p and '覆核紀錄' in p for p in report.validate(doc)), report.validate(doc))
        doc['findings'][0]['status'] = 'evidence_pending'
        self.assertEqual(report.validate(doc), [])

    def test_every_report_shows_its_review_record_summary_and_each_finding_review(self):
        # TK-HRV-010: an unreviewed finding stays in the report, with its review state.
        for drop in ('review_record', 'review_summary', 'findings/0/review'):
            with self.subTest(drop=drop):
                doc = valid_report()
                if drop.startswith('findings'):
                    del doc['findings'][0]['review']
                else:
                    del doc[drop]
                self.assertNotEqual(report.validate(doc), [])

    def test_the_review_summary_counts_the_findings_review_states(self):
        doc = valid_report()
        doc['review_summary'] = {**doc['review_summary'], 'approved': 0, 'rejected': 1}  # the one finding is approved
        self.assertTrue(any('review_summary' in p for p in report.validate(doc)), report.validate(doc))

    def test_review_times_are_iso_8601_utc(self):
        for where in ('opened_at', 'decision/at'):
            with self.subTest(where=where):
                doc = valid_report()
                review = doc['findings'][0]['review']
                (review['decision'] if where == 'decision/at' else review)[where.split('/')[-1]] = '2026-11-02 09:00'
                problems = report.validate(doc)
                self.assertTrue(any('findings/0' in p and 'UTC' in p for p in problems), problems)

    def test_without_a_review_record_no_finding_can_be_decided(self):
        doc = valid_report()
        doc['review_record'] = None  # the finding still claims an approval
        problems = report.validate(doc)
        self.assertTrue(any('findings/0' in p and 'review_record' in p for p in problems), problems)

    def test_without_a_review_record_no_review_has_started(self):
        doc = valid_report()
        doc['review_record'] = None
        doc['findings'][0]['review'] = {'state': 'pending', 'opened_at': '2026-11-01T11:00:00Z'}
        doc['review_summary'].update(approved=0, pending=1)
        problems = report.validate(doc)
        self.assertTrue(any('findings/0' in p and 'review_record' in p for p in problems), problems)

    def test_a_review_state_matches_its_decision(self):
        cases = {'a decided state with the decision of another state': {'state': 'rejected'},
                 'a waiting state with a decision': {'state': 'pending'}}
        for name, change in cases.items():
            with self.subTest(name):
                doc = valid_report()
                doc['findings'][0]['review'].update(change)
                doc['review_summary'] = dict.fromkeys(doc['review_summary'], 0)
                doc['review_summary'][change['state']] = 1
                self.assertTrue(any('findings/0' in p and 'decision' in p for p in report.validate(doc)),
                                report.validate(doc))
        doc = valid_report()
        doc['findings'][0]['review'] = {'state': 'approved', 'opened_at': '2026-11-01T11:00:00Z'}  # no decision
        self.assertTrue(any('findings/0' in p and 'decision' in p for p in report.validate(doc)), report.validate(doc))

    def test_a_review_state_must_be_one_the_definition_lists(self):
        doc = valid_report()
        doc['findings'][0]['review'] = {**copy.deepcopy(self.REVIEW), 'state': 'auto_approved'}
        self.assertNotEqual(report.validate(doc), [])

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

    # 〈定義：覆核紀錄〉 報告: 覆核狀態.
    FINDING_REVIEW_LABELS = {'pending': '待覆核', 'overdue': '逾期覆核', 'approved': '已核准', 'rejected': '已退回',
                           'evidence_pending': '已轉證據待補'}

    def test_the_review_section_names_the_record_the_counts_and_each_decision(self):
        md = report.render_markdown(valid_report())
        section = md.split('## 覆核', 1)[1].split('\n## ', 1)[0]
        self.assertIn('`/control/review-record.json`', section)
        self.assertIn('已核准 1', section)
        self.assertIn('待覆核 0', section)
        row = next(line for line in section.splitlines() if 'finding-0001' in line)
        for part in ('已核准', 'sec-alice', '2026-11-02T09:00:00Z', "the other tenant's row came back"):
            self.assertIn(part, row)

    def test_without_a_review_record_the_section_says_so(self):
        doc = valid_report()
        doc['review_record'] = None
        doc['findings'][0]['review'] = {'state': 'pending'}
        doc['review_summary'].update(approved=0, pending=1)
        section = report.render_markdown(doc).split('## 覆核', 1)[1].split('\n## ', 1)[0]
        self.assertIn('這次執行沒有使用覆核紀錄', section)  # also when the run stopped before reading one
        self.assertIn('| 待覆核 |', section)

    def test_findings_waiting_for_review_come_first_longest_wait_first(self):
        # 〈定義：覆核紀錄〉 報告: 待覆核 and 逾期覆核 by waiting time; decided ones after them, as listed.
        doc = valid_report()
        first = doc['findings'][0]  # approved
        reviews = {'finding-0002': {'state': 'pending', 'opened_at': '2026-11-05T00:00:00Z'},
                   'finding-0003': {'state': 'overdue', 'opened_at': '2026-11-01T00:00:00Z'},
                   'finding-0004': {'state': 'pending'}}  # no issue opened yet: waiting time unknown
        for fid, rev in reviews.items():
            doc['findings'].append({**copy.deepcopy(first), 'id': fid, 'review': rev})
        doc['review_summary'].update(pending=2, overdue=1)
        self.assertEqual(report.validate(doc), [])
        section = report.render_markdown(doc).split('## 覆核', 1)[1]
        order = [fid for line in section.splitlines() for fid in re.findall(r'`(finding-\d{4})`', line)]
        self.assertEqual(order, ['finding-0003', 'finding-0002', 'finding-0004', 'finding-0001'])

    def test_a_reason_cannot_break_the_table_or_add_a_heading(self):
        # The reason is a reviewer's comment, kept as written (〈定義：覆核紀錄〉 理由); in the Markdown it stays
        # inside its cell.
        doc = valid_report()
        doc['findings'][0]['review']['decision']['reason'] = 'fine | really\n\n## 全部通過\n'
        md = report.render_markdown(doc)
        self.assertNotIn('\n## 全部通過', md)
        row = next(line for line in md.splitlines() if '`finding-0001`' in line and '已核准' in line)
        self.assertEqual(row.replace('\\|', '').count('|'), 5)  # four cells

    def test_a_reason_cannot_hide_what_follows_it(self):
        doc = valid_report()
        doc['findings'][0]['review']['decision']['reason'] = 'ok <!-- the rest of the report is hidden'
        md = report.render_markdown(doc)
        self.assertNotIn('<!--', md)
        self.assertIn('## 覆蓋', md.split('the rest of the report is hidden', 1)[1])

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
        self.assertIn('security-lead（核准者姓名由授權紀錄宣告，身分未經驗證）', md)
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


COVERAGE_FIELDS = ('inventory_source', 'inventory', 'denominator', 'executed', 'valid_judgements', 'blocked', 'errors',
                   'untested', 'cancelled', 'unsupported', 'unsupported_items', 'effective_judgement_rate',
                   'tool_support_rate', 'required_test_completion_rate', 'states', 'claim', 'tables_and_policies',
                   'excluded', 'rejected_exclusions')


def fixture(name):
    return json.loads((FIXTURES / f'{name}.json').read_text(encoding='utf-8'))


class CoverageRecord(unittest.TestCase):
    """〈定義：覆蓋面向〉, TK-EVD-008, TK-EVD-009: the numbers of the coverage record are typed, add up, and never
    show full coverage over a zero denominator."""

    def problems(self, doc):
        return report.validate(doc)

    def test_the_example_reports_carry_the_whole_record_and_are_valid(self):
        for name in ('report-valid', 'report-partial-fault', 'report-blocked-no-commit'):
            with self.subTest(report=name):
                doc = fixture(name)
                self.assertEqual(report.validate(doc), [])
                self.assertEqual([f for f in COVERAGE_FIELDS if f not in doc['coverage']], [])

    def test_a_field_the_schema_does_not_list_is_a_problem(self):
        for where in (lambda c: c, lambda c: c['inventory'], lambda c: c['states'], lambda c: c['tables_and_policies'],
                      lambda c: c['unsupported_items'][0]):
            with self.subTest(where=where(valid_report()['coverage']).keys()):
                doc = valid_report()
                where(doc['coverage'])['raw_sql'] = 'x'
                self.assertTrue(any('raw_sql' in p for p in self.problems(doc)), self.problems(doc))

    def test_a_missing_field_is_a_problem(self):
        for field in COVERAGE_FIELDS:
            with self.subTest(removed=field):
                doc = valid_report()
                del doc['coverage'][field]
                self.assertTrue(any(field in p for p in self.problems(doc)), self.problems(doc))

    def test_wrong_types_and_values_are_problems(self):
        for field, value in (('denominator', -1), ('executed', 1.5), ('effective_judgement_rate', 'high'),
                             ('tool_support_rate', True), ('claim', 'everything'), ('inventory_source', ''),
                             ('states', {'effective_judgement_rate': 'good', 'tool_support_rate': 'measured',
                                         'required_test_completion_rate': 'measured'})):
            with self.subTest(field=field, value=value):
                doc = valid_report()
                doc['coverage'][field] = value
                self.assertNotEqual(self.problems(doc), [])

    def test_inventory_and_table_counts_are_typed(self):
        for path, value in ((('inventory', 'completeness'), 'done'), (('inventory', 'rule'), ''),
                            (('inventory', 'unresolved'), 'none'), (('tables_and_policies', 'judged'), 1.5),
                            (('tables_and_policies', 'inventoried'), -1)):
            with self.subTest(path=path):
                doc = valid_report()
                doc['coverage'][path[0]][path[1]] = value
                self.assertNotEqual(self.problems(doc), [])

    def test_an_exclusion_needs_its_item_reason_confirmer_and_version(self):
        good = {'ref': 'nextjs-routes', 'reason': 'no Next.js application', 'confirmed_by': 'owner', 'version': 'v1'}
        doc = valid_report()
        doc['coverage']['excluded'] = [good]
        self.assertEqual(self.problems(doc), [])
        for field in good:
            for blank in (None, ''):
                with self.subTest(field=field, blank=blank):
                    doc = valid_report()
                    doc['coverage']['excluded'] = [{**good, field: blank}]
                    self.assertNotEqual(self.problems(doc), [])

    def test_the_denominator_is_the_execution_records_plus_the_unsupported_scopes(self):
        doc = valid_report()
        doc['coverage']['denominator'] += 1
        self.assertTrue(any('denominator' in p for p in self.problems(doc)), self.problems(doc))

    def test_the_classes_add_up_to_the_denominator(self):
        doc = valid_report()
        doc['coverage']['blocked'] += 1
        self.assertTrue(any('add up' in p for p in self.problems(doc)), self.problems(doc))

    def test_valid_judgements_cannot_exceed_what_was_executed(self):
        doc = valid_report()
        doc['coverage']['valid_judgements'] = doc['coverage']['executed'] + 1
        self.assertTrue(any('valid_judgements' in p for p in self.problems(doc)), self.problems(doc))

    def test_the_effective_rate_is_valid_judgements_over_the_denominator(self):
        doc = valid_report()
        doc['coverage']['effective_judgement_rate'] = 0.9
        self.assertTrue(any('effective_judgement_rate' in p for p in self.problems(doc)), self.problems(doc))

    def test_a_measured_rate_has_a_number_and_an_unmeasured_one_has_none(self):
        doc = valid_report()
        doc['coverage']['states']['tool_support_rate'] = 'insufficient_data'
        self.assertTrue(any('tool_support_rate' in p for p in self.problems(doc)), self.problems(doc))
        doc = valid_report()
        doc['coverage']['tool_support_rate'] = None
        self.assertTrue(any('tool_support_rate' in p for p in self.problems(doc)), self.problems(doc))

    def test_the_whole_scope_cannot_be_claimed_over_an_unknown_inventory(self):
        doc = valid_report()
        doc['coverage']['inventory']['completeness'] = 'unknown'
        self.assertTrue(any('claim' in p for p in self.problems(doc)), self.problems(doc))

    def zero_denominator(self, **changes):
        doc = fixture('report-blocked-no-commit')
        doc['execution_records'] = []
        doc['coverage'].update(denominator=0, blocked=0, unsupported=0, unsupported_items=[],
                               effective_judgement_rate=None, tool_support_rate=None,
                               required_test_completion_rate=None,
                               states={k: 'insufficient_data' for k in ('effective_judgement_rate', 'tool_support_rate',
                                                                        'required_test_completion_rate')})
        doc['coverage'].update(changes)
        return doc

    def test_a_zero_denominator_is_insufficient_data_never_full_coverage(self):
        self.assertEqual(self.problems(self.zero_denominator()), [])
        full = self.zero_denominator(effective_judgement_rate=1.0)
        self.assertTrue(any('effective_judgement_rate' in p for p in self.problems(full)), self.problems(full))
        measured = self.zero_denominator(states={k: 'measured' for k in ('effective_judgement_rate', 'tool_support_rate',
                                                                          'required_test_completion_rate')})
        self.assertTrue(any('measured' in p for p in self.problems(measured)), self.problems(measured))

    RATES = ('effective_judgement_rate', 'tool_support_rate', 'required_test_completion_rate')

    def test_over_a_zero_denominator_every_rate_is_none_and_none_is_measured(self):
        for name in self.RATES:
            with self.subTest(rate=name, what='a number'):
                doc = self.zero_denominator(**{name: 1.0})
                doc['coverage']['states'][name] = 'measured'
                self.assertTrue(any(name in p for p in self.problems(doc)), self.problems(doc))
            with self.subTest(rate=name, what='measured without a number'):
                doc = self.zero_denominator()
                doc['coverage']['states'][name] = 'measured'
                self.assertTrue(any(name in p and 'measured' in p for p in self.problems(doc)), self.problems(doc))

    def test_with_no_scheduled_case_the_completion_rate_is_none(self):
        doc = fixture('report-blocked-no-commit')
        doc['execution_records'] = []
        doc['coverage'].update(denominator=3, blocked=0, unsupported=3, effective_judgement_rate=0.0, tool_support_rate=0.0,
                               required_test_completion_rate=None,
                               states={'effective_judgement_rate': 'measured', 'tool_support_rate': 'measured',
                                       'required_test_completion_rate': 'insufficient_data'})
        self.assertEqual(self.problems(doc), [])
        doc['coverage']['required_test_completion_rate'] = 1.0
        doc['coverage']['states']['required_test_completion_rate'] = 'measured'
        self.assertTrue(any('required_test_completion_rate' in p for p in self.problems(doc)), self.problems(doc))

    def test_a_zero_denominator_is_not_applicable_only_when_something_was_excluded(self):
        excluded = [{'ref': 'nextjs-routes', 'reason': 'no Next.js application', 'confirmed_by': 'owner', 'version': 'v1'}]
        for name in self.RATES:
            with self.subTest(rate=name, what='not_applicable with nothing excluded'):
                doc = self.zero_denominator()
                doc['coverage']['states'][name] = 'not_applicable'
                self.assertTrue(any(name in p and 'not_applicable' in p for p in self.problems(doc)), self.problems(doc))
            with self.subTest(rate=name, what='insufficient_data although something was excluded'):
                doc = self.zero_denominator(excluded=excluded)
                self.assertTrue(any(name in p and 'insufficient_data' in p for p in self.problems(doc)), self.problems(doc))
        every = self.zero_denominator(excluded=excluded)
        for name in self.RATES:
            every['coverage']['states'][name] = 'not_applicable'
        self.assertEqual(self.problems(every), [])

    def test_with_exclusions_the_denominator_may_be_smaller_than_the_records_say(self):
        doc = valid_report()
        doc['coverage']['excluded'] = [{'ref': 'rls-views', 'reason': 'no views', 'confirmed_by': 'owner', 'version': 'v1'}]
        doc['coverage']['denominator'] -= 1
        doc['coverage']['unsupported'] -= 1
        doc['coverage']['effective_judgement_rate'] = doc['coverage']['valid_judgements'] / doc['coverage']['denominator']
        doc['coverage']['tool_support_rate'] = 1.0
        self.assertEqual(self.problems(doc), [])


class RenderCoverage(unittest.TestCase):
    """The 覆蓋 section of the Markdown report: the numbers, the rates, what is unresolved and what was left out,
    with a zero denominator shown as missing data, never as full coverage (TK-EVD-009)."""

    def section(self, doc):
        md = report.render_markdown(doc)
        return md[md.index('## 覆蓋'):]

    def test_a_complete_run_shows_counts_rates_and_the_claim(self):
        text = self.section(valid_report())
        for line in ('- 盤點來源：sql-rls-v1 extraction of supabase/migrations/*.sql',
                     '- 盤點完整性：完整；宣告範圍：整個範圍；擷取規則 sql-rls-v1、支援版本 postgresql-17',
                     '- 分母 4、已執行 3、有效判定 3、受阻 0、錯誤 0、未測 0、取消 0、不支援 1',
                     '- 有效判定率：75.0%；工具支援率：75.0%；必要測試完成率：100.0%',
                     '- 資料表與政策：已盤點 14、已啟用 RLS 5、尚無政策 0、未解析 0、已判定 3'):
            self.assertIn(line, text)

    def test_an_unread_project_says_it_covers_only_what_is_known(self):
        text = self.section(fixture('report-blocked-no-commit'))
        self.assertIn('- 盤點完整性：未知；宣告範圍：只涵蓋已知範圍', text)
        self.assertIn('  - 未解析：`(project)`（preflight blocked; the project files were not read）', text)
        self.assertIn('- 有效判定率：0.0%；工具支援率：40.0%；必要測試完成率：0.0%', text)

    def test_unresolved_content_names_its_file_and_line(self):
        doc = valid_report()
        doc['coverage']['inventory'].update(completeness='unknown', unresolved=[
            {'file': 'supabase/migrations/001.sql', 'line': 7, 'reason': 'table name has no schema'}])
        doc['coverage']['claim'] = 'known_scope_only'
        self.assertIn('  - 未解析：`supabase/migrations/001.sql:7`（table name has no schema）', self.section(doc))

    def test_a_zero_denominator_shows_missing_data_never_a_percentage(self):
        doc = CoverageRecord.zero_denominator(CoverageRecord())
        text = self.section(doc)
        self.assertIn('- 有效判定率：資料不足；工具支援率：資料不足；必要測試完成率：資料不足', text)
        self.assertNotIn('%', text)

    def test_everything_excluded_with_a_reason_shows_not_applicable(self):
        doc = CoverageRecord.zero_denominator(CoverageRecord())
        doc['coverage']['excluded'] = [{'ref': 'nextjs-routes', 'reason': 'no Next.js application',
                                        'confirmed_by': 'owner', 'version': 'v1'}]
        for name in doc['coverage']['states']:
            doc['coverage']['states'][name] = 'not_applicable'
        self.assertIn('- 有效判定率：不適用；工具支援率：不適用；必要測試完成率：不適用', self.section(doc))

    def test_what_needs_supplementary_observation_is_marked_and_the_rest_is_not(self):
        doc = valid_report()
        doc['coverage']['unsupported_items'] = [
            {'scope': 'nextjs-routes', 'reason': 'framework module not loaded', 'needs_supplement': True}]
        self.assertIn('  - 不支援：`nextjs-routes`（framework module not loaded；需補充觀測）', self.section(doc))
        plain = valid_report()['coverage']['unsupported_items'][0]
        self.assertIn(f'  - 不支援：`{plain["scope"]}`（{plain["reason"]}）', self.section(valid_report()))

    def test_exclusions_and_refused_exclusions_are_listed(self):
        doc = valid_report()
        doc['coverage']['excluded'] = [{'ref': 'nextjs-routes', 'reason': 'no Next.js application',
                                        'confirmed_by': 'owner', 'version': 'v1'}]
        doc['coverage']['rejected_exclusions'] = [{'ref': 'rls-views', 'problem': 'missing reason'}]
        text = self.section(doc)
        self.assertIn('  - 排除：`nextjs-routes`（no Next.js application；確認者 owner、版本 v1）', text)
        self.assertIn('  - 被拒絕的排除：`rls-views`（missing reason）', text)


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
        doc['review_summary'] = dict.fromkeys(doc['review_summary'], 0)  # no finding left to review
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


class EnvironmentInReport(unittest.TestCase):
    """TK-SCP-001, TK-ENV-007, TK-EVD-005, TK-EVD-008: environment carries unsupported and known_differences,
    is rendered in Markdown, and cannot claim completed/partial, run tests, or claim whole_scope when versions are
    outside the support matrix."""

    def unsupported_report(self, item='docker-engine 99.0.0 (matrix 29.1.3)'):
        doc = valid_report()
        reason = f'environment outside support matrix (TK-SCP-001): {item}'
        doc['status'] = 'blocked'
        doc['status_reason'] = reason
        doc['stages'][4] = {'stage': 'dynamic_execution', 'status': 'blocked', 'reason': reason}
        doc['environment']['unsupported'] = [item]
        doc['findings'] = []
        doc['review_summary'] = dict.fromkeys(doc['review_summary'], 0)
        for e in doc['execution_records']:
            e['result'] = 'unsupported'
            e['error'] = reason
            e['evidence'] = []
            e.pop('checks', None)
            e.pop('approval_id', None)
        cov = doc['coverage']
        cov['unsupported_items'].append({'scope': f'environment:{item}',
                                         'reason': 'version outside support matrix (TK-SCP-001)'})
        cov['denominator'] = len(doc['execution_records']) + len(cov['unsupported_items'])
        cov['executed'] = 0
        cov['valid_judgements'] = 0
        cov['blocked'] = 0
        cov['errors'] = 0
        cov['untested'] = 0
        cov['cancelled'] = 0
        cov['unsupported'] = cov['denominator']
        cov['effective_judgement_rate'] = 0.0
        cov['tool_support_rate'] = 0.0
        cov['required_test_completion_rate'] = 0.0
        cov['tables_and_policies']['judged'] = 0
        cov['claim'] = 'known_scope_only'
        return doc

    def test_environment_schema_requires_all_four_fields_forbids_extras_and_checks_stage_presence(self):
        for missing in ('mode', 'profile_digest', 'unsupported', 'known_differences'):
            with self.subTest(missing=missing):
                doc = valid_report()
                del doc['environment'][missing]
                self.assertTrue(any('environment' in p for p in report.validate(doc)))
        doc = valid_report()
        doc['environment']['observer_password'] = 'secret'
        self.assertTrue(any('observer_password' in p for p in report.validate(doc)))

        missing_env = valid_report()
        del missing_env['environment']
        self.assertTrue(any('environment: required' in p for p in report.validate(missing_env)))

        not_run_with_env = fixture('report-blocked-no-commit')
        not_run_with_env['environment'] = valid_report()['environment']
        self.assertTrue(any('environment: must be omitted' in p for p in report.validate(not_run_with_env)))

    def test_unsupported_environment_enforces_blocked_stage_unrun_tests_known_scope_and_coverage_item(self):
        item = 'docker-engine 99.0.0 (matrix 29.1.3)'
        base = self.unsupported_report(item)
        self.assertEqual(report.validate(base), [])

        for bad_status in ('completed', 'partial'):
            with self.subTest(status=bad_status):
                wrong = copy.deepcopy(base)
                wrong['status'] = bad_status
                self.assertTrue(any("status must be 'blocked'" in p for p in report.validate(wrong)))

        bad_stage = copy.deepcopy(base)
        bad_stage['stages'][4] = {'stage': 'dynamic_execution', 'status': 'completed'}
        self.assertTrue(any("dynamic_execution must be 'blocked'" in p for p in report.validate(bad_stage)))

        ran_test = copy.deepcopy(base)
        ran_test['execution_records'][0]['result'] = 'passed'
        ran_test['coverage']['executed'] = 1
        ran_test['coverage']['valid_judgements'] = 1
        ran_test['coverage']['unsupported'] -= 1
        ran_test['coverage']['effective_judgement_rate'] = 1 / ran_test['coverage']['denominator']
        ran_test['coverage']['tool_support_rate'] = 1 / ran_test['coverage']['denominator']
        ran_test['coverage']['required_test_completion_rate'] = 1 / len(ran_test['execution_records'])
        self.assertTrue(any('no test runs against an unverified environment' in p for p in report.validate(ran_test)))

        whole = copy.deepcopy(base)
        whole['coverage']['claim'] = 'whole_scope'
        self.assertTrue(any('whole_scope' in p for p in report.validate(whole)))

        dropped = copy.deepcopy(base)
        dropped['coverage']['unsupported_items'].pop()
        dropped['coverage']['denominator'] -= 1
        dropped['coverage']['unsupported'] -= 1
        self.assertTrue(any(f'environment:{item}' in p for p in report.validate(dropped)))

    def test_markdown_renders_known_differences_missing_environment_and_unsupported_versions_safely(self):
        md = report.render_markdown(valid_report())
        self.assertIn('## 測試環境與差異', md)
        self.assertIn('E1 local stack', md)
        self.assertNotIn('支援矩陣外版本', md)

        no_env = report.render_markdown(fixture('report-blocked-no-commit'))
        self.assertIn('## 測試環境與差異', no_env)
        self.assertIn('未建立測試環境', no_env)

        item = 'service rest img:0` <!-- hidden'
        rendered = report.render_markdown(self.unsupported_report(item))
        self.assertIn('支援矩陣外版本', rendered)
        self.assertIn(f'``environment:{item}``', rendered)  # backtick cannot close the inline code span early
        outside_code = re.sub(r'(`+).*?\1', '', rendered)
        self.assertNotIn('<!--', outside_code)
        self.assertIn('## 覆蓋', rendered)
