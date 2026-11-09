"""〈定義：覆核紀錄〉: review decisions reach the control zone only through the platform's structured
events, from accounts the roles record gives the review's role (TK-HRV-003, TK-HRV-004)."""
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from toolkit import control, report, review

FIXTURES = Path(__file__).with_name('fixtures')

SECURITY = {'id': 101, 'login': 'sec-alice'}
OTHER = {'id': 202, 'login': 'dev-bob'}

ROLES = {'schema_version': '1', 'issued_by': 'app-owner', 'issued_at': '2026-11-09T00:00:00Z',
         'accounts': [{**SECURITY, 'roles': ['security']},
                      {**OTHER, 'roles': []}]}


def record(issue=7):
    """A review record with one candidate-finding item, as publish leaves it: no decisions yet."""
    return {'schema_version': '1', 'platform': 'fake', 'repo': 'owner/reviews',
            'items': [{'review_type': 'candidate_finding', 'fingerprint': 'sha256:f1',
                       'fingerprint_version': 'fp-authz-v1', 'issue': issue,
                       'opened_at': '2026-11-09T01:00:00Z',
                       'versions': {'requirement_id': 'S2-documents-read', 'requirement_version': 1,
                                    'commit': 'abc123', 'run_id': 'run-1'},
                       'decisions': [], 'rejected': []}]}


def empty_record():
    return {'schema_version': '1', 'platform': 'fake', 'repo': 'owner/reviews', 'items': []}


def valid_report():
    """A hand-written report with one confirmed finding (shared with test_report)."""
    return json.loads((FIXTURES / 'report-valid.json').read_text(encoding='utf-8'))


def rerun(doc, run_id):
    """The report as a later run with run_id would give it: every record carries the new run_id."""
    for r in [doc, *doc['execution_records'], *doc['findings'], doc['coverage']]:
        r['run_id'] = run_id
    doc['id'] = f'report-{run_id}'
    return doc


class FakePlatform:
    """The platform seam (Q20): what the platform reports, one issue at a time."""

    def __init__(self, events=None, comments=None, failing=(), opens=None):
        self.events, self.notes, self.failing = events or {}, comments or {}, set(failing)
        self.created = []  # (number, title, body)
        self.opens = opens  # how many issues it opens before it stops answering; None: no limit

    def _reach(self, number):
        if number in self.failing:
            raise review.PlatformError(f'issue {number}: the platform did not answer')

    def create_issue(self, title, body):
        if self.opens is not None and len(self.created) >= self.opens:
            raise review.PlatformError('the platform did not answer')
        number = 100 + len(self.created)
        self.created.append((number, title, body))
        return number

    def label_events(self, number):
        self._reach(number)
        return list(self.events.get(number, []))

    def comments(self, number):
        self._reach(number)
        return list(self.notes.get(number, []))


def labeled(eid, who, label, at, action='labeled'):
    return review.LabelEvent(id=eid, action=action, actor_id=who['id'], actor_login=who['login'], label=label, at=at)


def unlabeled(eid, who, label, at):
    return labeled(eid, who, label, at, action='unlabeled')


def comment(cid, who, body, at):
    return review.Comment(id=cid, author_id=who['id'], author_login=who['login'], body=body,
                          created_at=at, updated_at=at)


class SyncAcceptsOnlyVerifiedReasonedDecisions(unittest.TestCase):

    def test_only_a_security_account_with_a_reason_decides(self):
        platform = FakePlatform(
            events={7: [labeled(9001, OTHER, 'review:approve', '2026-11-09T02:00:00Z'),
                        labeled(9002, SECURITY, 'review:reject', '2026-11-09T03:00:00Z'),
                        labeled(9003, SECURITY, 'review:approve', '2026-11-09T04:00:00Z')]},
            comments={7: [comment(1, OTHER, 'looks fine, 核准', '2026-11-09T01:30:00Z'),
                          comment(2, SECURITY, 'the leak is a test artefact', '2026-11-09T02:30:00Z')]})
        item = review.sync(record(), ROLES, platform)['items'][0]
        self.assertEqual(item['decisions'], [
            {'event_id': 9002, 'option': 'reject', 'by': SECURITY, 'at': '2026-11-09T03:00:00Z',
             'reason': 'the leak is a test artefact',
             'reason_comments': [{'id': 2, 'updated_at': '2026-11-09T02:30:00Z'}]}])
        self.assertEqual([(r['event_id'], r['option'], r['by'], r['at'], r['problem']) for r in item['rejected']], [
            (9001, 'approve', OTHER, '2026-11-09T02:00:00Z', 'no_role'),
            (9003, 'approve', SECURITY, '2026-11-09T04:00:00Z', 'no_reason')])

    def test_syncing_again_records_each_event_once(self):
        platform = FakePlatform(
            events={7: [labeled(9001, OTHER, 'review:approve', '2026-11-09T02:00:00Z'),
                        labeled(9002, SECURITY, 'review:reject', '2026-11-09T03:00:00Z')]},
            comments={7: [comment(2, SECURITY, 'the leak is a test artefact', '2026-11-09T02:30:00Z')]})
        once = review.sync(record(), ROLES, platform)
        twice = review.sync(once, ROLES, platform)
        self.assertEqual(twice, once)
        self.assertEqual((len(twice['items'][0]['decisions']), len(twice['items'][0]['rejected'])), (1, 1))

    def test_times_are_compared_as_times_not_as_text(self):
        # 03:00:00.5Z is after 03:00:00Z, although '.' sorts before 'Z' as text.
        platform = FakePlatform(
            events={7: [labeled(9002, SECURITY, 'review:reject', '2026-11-09T03:00:00Z'),
                        labeled(9003, SECURITY, 'review:approve', '2026-11-09T04:00:00Z')]},
            comments={7: [comment(2, SECURITY, 'a test artefact', '2026-11-09T02:30:00Z'),
                          comment(3, SECURITY, 'reproduced it after all', '2026-11-09T03:00:00.5Z')]})
        item = review.sync(record(), ROLES, platform)['items'][0]
        self.assertEqual([(d['event_id'], d['reason']) for d in item['decisions']],
                         [(9002, 'a test artefact'), (9003, 'reproduced it after all')])

    def test_a_comment_in_the_same_second_as_the_label_is_its_reason(self):
        # GitHub reports whole seconds: comment, then label, within one second.
        platform = FakePlatform(events={7: [labeled(9002, SECURITY, 'review:reject', '2026-11-09T03:00:00Z')]},
                                comments={7: [comment(2, SECURITY, 'a test artefact', '2026-11-09T03:00:00Z')]})
        item = review.sync(record(), ROLES, platform)['items'][0]
        self.assertEqual([d['reason'] for d in item['decisions']], ['a test artefact'])

    def test_events_are_taken_in_time_order_whatever_order_the_platform_gives(self):
        platform = FakePlatform(
            events={7: [labeled(9003, SECURITY, 'review:approve', '2026-11-09T04:00:00Z'),
                        labeled(9002, SECURITY, 'review:reject', '2026-11-09T03:00:00Z')]},
            comments={7: [comment(2, SECURITY, 'a test artefact', '2026-11-09T02:30:00Z'),
                          comment(3, SECURITY, 'reproduced it after all', '2026-11-09T03:30:00Z')]})
        item = review.sync(record(), ROLES, platform)['items'][0]
        self.assertEqual([d['event_id'] for d in item['decisions']], [9002, 9003])

    def test_events_are_told_apart_by_their_platform_id(self):
        same = ('review:approve', '2026-11-09T02:00:00Z')  # same account, option and second
        platform = FakePlatform(events={7: [labeled(9001, OTHER, *same), labeled(9002, OTHER, *same)]})
        item = review.sync(record(), ROLES, platform)['items'][0]
        self.assertEqual([r['event_id'] for r in item['rejected']], [9001, 9002])


class SyncIgnoresWhatIsNotADecision(unittest.TestCase):
    """Only adding a predefined label is a decision (〈定義：覆核紀錄〉 選項)."""

    REASON = {7: [comment(2, SECURITY, 'see the evidence', '2026-11-09T02:30:00Z')]}

    def test_a_label_that_is_not_a_decision_label_is_ignored(self):
        platform = FakePlatform(events={7: [labeled(9001, SECURITY, 'bug', '2026-11-09T03:00:00Z')]},
                                comments=self.REASON)
        item = review.sync(record(), ROLES, platform)['items'][0]
        self.assertEqual((item['decisions'], item['rejected']), ([], []))

    def test_removing_a_decision_label_is_ignored(self):
        platform = FakePlatform(events={7: [unlabeled(9001, SECURITY, 'review:reject', '2026-11-09T03:00:00Z')]},
                                comments=self.REASON)
        item = review.sync(record(), ROLES, platform)['items'][0]
        self.assertEqual((item['decisions'], item['rejected']), ([], []))


class PublishOpensAnIssuePerUnreviewedFinding(unittest.TestCase):
    """〈定義：覆核紀錄〉 項目 and 工單: publish opens the issue and keeps its number."""

    NOW = '2026-11-09T05:00:00Z'
    FINGERPRINT = 'sha256:' + '3' * 64

    def test_a_finding_without_an_item_gets_an_issue_and_an_item(self):
        platform = FakePlatform()
        rec = review.publish(empty_record(), valid_report(), platform, self.NOW)
        self.assertEqual(len(platform.created), 1)
        number, title, body = platform.created[0]
        self.assertTrue(title.startswith('候選問題覆核'), title)  # 〈定義：覆核類型〉, written here by hand
        self.assertIn('S2-OWNER-ONLY@documents', title)
        self.assertIn(self.FINGERPRINT, body)  # shown to people; never used to find the issue
        for label in ('review:approve', 'review:reject', 'review:evidence-pending'):
            self.assertIn(label, body)
        self.assertEqual(rec['items'], [{
            'review_type': 'candidate_finding', 'fingerprint': self.FINGERPRINT,
            'fingerprint_version': 'fp-authz-v1', 'issue': number, 'opened_at': self.NOW,
            'versions': {'requirement_id': 'S2-OWNER-ONLY@documents', 'requirement_version': 1,
                         'commit': 'a89be51', 'run_id': 'run-20261101-0001'},
            'decisions': [], 'rejected': []}])

    def test_a_finding_that_already_has_an_item_gets_no_second_issue(self):
        platform = FakePlatform()
        once = review.publish(empty_record(), valid_report(), platform, self.NOW)
        later = rerun(valid_report(), 'run-20261102-0001')  # the same finding, found again by a later run
        twice = review.publish(once, later, platform, '2026-11-10T05:00:00Z')
        self.assertEqual(len(platform.created), 1)
        self.assertEqual(twice, once)

    def test_a_new_requirement_version_starts_a_new_review(self):
        platform = FakePlatform()
        once = review.publish(empty_record(), valid_report(), platform, self.NOW)
        revised = valid_report()
        revised['findings'][0]['requirement_version'] = 2  # the item was revised: back to 待覆核
        twice = review.publish(once, revised, platform, '2026-11-10T05:00:00Z')
        self.assertEqual(len(platform.created), 2)
        self.assertEqual([(i['versions']['requirement_version'], i['issue']) for i in twice['items']],
                         [(1, 100), (2, 101)])

    def test_an_invalid_report_opens_no_issue(self):
        platform = FakePlatform()
        broken = valid_report()
        del broken['findings'][0]['commit']
        with self.assertRaises(review.ReportUnusable) as caught:
            review.publish(empty_record(), broken, platform, self.NOW)
        self.assertIn('commit', str(caught.exception))
        self.assertEqual(platform.created, [])


class ControlZone(unittest.TestCase):
    """A sample source and, beside it, a control zone holding the roles record."""

    NOW = '2026-11-09T06:00:00Z'

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.source, self.control = root / 'sample', root / 'control'
        self.source.mkdir()
        self.roles_path = self.control / 'review-roles.json'
        self.roles_digest = control.write(self.roles_path, ROLES, self.source)
        self.path = self.control / 'review-record.json'

    def reasoned_reject(self, number, eid):
        return ({number: [labeled(eid, SECURITY, 'review:reject', '2026-11-09T03:00:00Z')]},
                {number: [comment(eid, SECURITY, 'a test artefact', '2026-11-09T02:30:00Z')]})


class RecordFiles(ControlZone):
    """〈定義：覆核紀錄〉 同步失敗: the record is a control-zone file; each item is written whole, and a
    sync that fails half-way keeps what it wrote."""

    def test_sync_writes_the_decisions_and_gives_the_new_digest(self):
        control.write(self.path, record(issue=7), self.source)
        events, comments = self.reasoned_reject(7, 9001)
        digest = review.sync_file(self.path, self.roles_path, self.roles_digest, FakePlatform(events, comments),
                                  self.NOW, self.source)
        self.assertEqual(digest, control.file_digest(self.path))
        saved = json.loads(self.path.read_text(encoding='utf-8'))
        self.assertEqual([d['event_id'] for d in saved['items'][0]['decisions']], [9001])
        self.assertEqual(saved['synced_at'], self.NOW)

    def test_a_sync_failing_half_way_keeps_what_it_wrote(self):
        two = record(issue=7)
        two['items'].append({**copy.deepcopy(two['items'][0]), 'fingerprint': 'sha256:f2', 'issue': 8})
        control.write(self.path, two, self.source)
        events, comments = self.reasoned_reject(7, 9001)
        platform = FakePlatform(events, comments, failing={8})
        with self.assertRaises(review.SyncFailed) as caught:
            review.sync_file(self.path, self.roles_path, self.roles_digest, platform, self.NOW, self.source)
        self.assertIn('issue 8', str(caught.exception))
        saved = json.loads(self.path.read_text(encoding='utf-8'))
        self.assertEqual([[d['event_id'] for d in i['decisions']] for i in saved['items']], [[9001], []])
        self.assertNotIn('synced_at', saved)  # the last complete sync is still the one before
        self.assertEqual(sorted(p.name for p in self.control.iterdir()), ['review-record.json', 'review-roles.json'])

    def test_roles_with_another_digest_are_not_used(self):
        control.write(self.path, record(issue=7), self.source)
        before = self.path.read_bytes()
        events, comments = self.reasoned_reject(7, 9001)
        with self.assertRaises(control.RecordUnusable):
            review.sync_file(self.path, self.roles_path, 'sha256:' + '0' * 64, FakePlatform(events, comments),
                             self.NOW, self.source)
        self.assertEqual(self.path.read_bytes(), before)

    def test_a_roles_record_that_is_not_valid_is_not_used(self):
        control.write(self.path, record(issue=7), self.source)
        before = self.path.read_bytes()
        events, comments = self.reasoned_reject(7, 9001)
        for broken in ({k: v for k, v in ROLES.items() if k != 'accounts'},
                       {**ROLES, 'accounts': [{'login': 'sec-alice', 'roles': ['security']}]}):  # no numeric id
            with self.subTest(broken=broken):
                digest = control.write(self.roles_path, broken, self.source)
                with self.assertRaises(control.RecordUnusable) as caught:
                    review.sync_file(self.path, self.roles_path, digest, FakePlatform(events, comments),
                                     self.NOW, self.source)
                self.assertIn('not a valid review roles record', str(caught.exception))
                self.assertEqual(self.path.read_bytes(), before)

    def test_a_record_that_is_not_valid_is_neither_synced_nor_published(self):
        broken = record(issue=7)
        broken['items'][0]['opened_at'] = 'yesterday'
        control.write(self.path, broken, self.source)
        before = self.path.read_bytes()
        events, comments = self.reasoned_reject(7, 9001)
        platform = FakePlatform(events, comments)
        for act in (lambda: review.sync_file(self.path, self.roles_path, self.roles_digest, platform, self.NOW,
                                             self.source),
                    lambda: review.publish_file(self.path, valid_report(), platform, self.NOW, self.source)):
            with self.assertRaises(control.RecordUnusable) as caught:
                act()
            self.assertIn('not a valid review record', str(caught.exception))
        self.assertEqual((self.path.read_bytes(), platform.created), (before, []))

    def test_publish_creates_a_record_only_when_asked_to(self):
        platform = FakePlatform()
        digest = review.publish_file(self.path, valid_report(), platform, self.NOW, self.source,
                                     new={'platform': 'fake', 'repo': 'owner/reviews'})
        saved = json.loads(self.path.read_text(encoding='utf-8'))
        self.assertEqual(digest, control.file_digest(self.path))
        self.assertEqual((saved['schema_version'], saved['platform'], saved['repo']), ('1', 'fake', 'owner/reviews'))
        self.assertEqual([i['issue'] for i in saved['items']], [100])

    def test_a_new_record_never_replaces_one_that_exists(self):
        control.write(self.path, record(issue=7), self.source)
        before, platform = self.path.read_bytes(), FakePlatform()
        with self.assertRaises(control.RecordUnusable):
            review.publish_file(self.path, valid_report(), platform, self.NOW, self.source,
                                new={'platform': 'fake', 'repo': 'owner/reviews'})
        self.assertEqual((self.path.read_bytes(), platform.created), (before, []))

    def test_a_new_record_inside_the_sample_source_opens_no_issue(self):
        platform = FakePlatform()
        with self.assertRaises(control.RecordUnusable) as caught:
            review.publish_file(self.source / 'review-record.json', valid_report(), platform, self.NOW, self.source,
                                new={'platform': 'fake', 'repo': 'owner/reviews'})
        self.assertIn('inside the sample source', str(caught.exception))
        self.assertEqual(platform.created, [])  # an issue opened here could never be recorded

    def test_without_new_a_missing_record_is_lost_not_started_again(self):
        platform = FakePlatform()
        with self.assertRaises(control.RecordUnusable):
            review.publish_file(self.path, valid_report(), platform, self.NOW, self.source)
        self.assertEqual((self.path.exists(), platform.created), (False, []))

    def test_an_issue_opened_before_publish_fails_is_kept(self):
        doc = valid_report()
        second = {**copy.deepcopy(doc['findings'][0]), 'id': 'finding-0002', 'fingerprint': 'sha256:' + '4' * 64}
        doc['findings'].append(second)
        doc['review_summary']['approved'] = 2  # the copy carries the first finding's review
        self.assertEqual(report.validate(doc), [])
        platform = FakePlatform(opens=1)
        with self.assertRaises(review.PublishFailed):
            review.publish_file(self.path, doc, platform, self.NOW, self.source,
                                new={'platform': 'fake', 'repo': 'owner/reviews'})
        saved = json.loads(self.path.read_text(encoding='utf-8'))
        first = doc['findings'][0]['fingerprint']
        self.assertEqual([(i['fingerprint'], i['issue']) for i in saved['items']], [(first, 100)])
        retry = review.publish_file(self.path, doc, FakePlatform(), self.NOW, self.source)  # opens only the second
        self.assertEqual(len(json.loads(self.path.read_text(encoding='utf-8'))['items']), 2)
        self.assertEqual(retry, control.file_digest(self.path))


class ApplyToReport(unittest.TestCase):
    """〈定義：覆核紀錄〉 目前的決定, 期限與逾期, 報告: what the record does to a report's findings."""

    NOW = '2026-11-09T06:00:00Z'

    def test_without_a_record_every_finding_waits_for_review(self):
        doc = review.apply(valid_report(), None, None, self.NOW)
        self.assertEqual([f['review'] for f in doc['findings']], [{'state': 'pending'}])
        self.assertEqual([f['status'] for f in doc['findings']], ['confirmed'])
        self.assertEqual(doc['review_summary'], {'pending': 1, 'overdue': 0, 'approved': 0, 'rejected': 0,
                                                 'evidence_pending': 0})
        self.assertIsNone(doc['review_record'])
        self.assertEqual(report.validate(doc), [])

    REF = {'path': '/control/review-record.json', 'digest': 'sha256:' + 'a' * 64}

    def decided(self, option, requirement_version=1):
        """The record publish gives for the fixture's finding, with one decision by the security account."""
        rec = review.publish(empty_record(), valid_report(), FakePlatform(), '2026-11-09T01:00:00Z')
        item = rec['items'][0]
        item['versions']['requirement_version'] = requirement_version
        item['decisions'].append({'event_id': 9002, 'option': option, 'by': SECURITY, 'at': '2026-11-09T03:00:00Z',
                                  'reason': 'checked the evidence',
                                  'reason_comments': [{'id': 2, 'updated_at': '2026-11-09T02:30:00Z'}]})
        return rec

    def test_an_approval_is_shown_and_leaves_the_status(self):
        doc = review.apply(valid_report(), self.decided('approve'), self.REF, self.NOW)
        self.assertEqual(doc['findings'][0]['review'], {
            'state': 'approved', 'opened_at': '2026-11-09T01:00:00Z',
            'decision': {'option': 'approve', 'by': SECURITY, 'at': '2026-11-09T03:00:00Z',
                         'reason': 'checked the evidence'}})
        self.assertEqual(doc['findings'][0]['status'], 'confirmed')
        self.assertEqual(doc['review_record'], self.REF)
        self.assertEqual(doc['review_summary']['approved'], 1)
        self.assertEqual(report.validate(doc), [])

    def test_evidence_pending_lowers_a_confirmed_finding(self):
        doc = review.apply(valid_report(), self.decided('evidence_pending'), self.REF, self.NOW)
        self.assertEqual((doc['findings'][0]['status'], doc['findings'][0]['review']['state']),
                         ('evidence_pending', 'evidence_pending'))
        self.assertEqual(report.validate(doc), [])

    def test_a_rejection_leaves_the_finding_in_the_report_with_its_status(self):
        doc = review.apply(valid_report(), self.decided('reject'), self.REF, self.NOW)
        self.assertEqual((len(doc['findings']), doc['findings'][0]['status'], doc['findings'][0]['review']['state']),
                         (1, 'confirmed', 'rejected'))  # 退回 is not 已排除, which needs counter-evidence

    def undecided(self):
        return review.publish(empty_record(), valid_report(), FakePlatform(), '2026-11-09T01:00:00Z')

    def test_past_its_deadline_an_undecided_finding_is_overdue_and_keeps_its_status(self):
        # 候選問題覆核: 7 days from 2026-11-09T01:00:00Z (原型量測後核定)
        for now, state in (('2026-11-16T00:59:59Z', 'pending'), ('2026-11-16T01:00:00.5Z', 'overdue')):
            with self.subTest(now=now):
                doc = review.apply(valid_report(), self.undecided(), self.REF, now)
                self.assertEqual((doc['findings'][0]['review']['state'], doc['findings'][0]['status']),
                                 (state, 'confirmed'))
                self.assertEqual(doc['review_summary'][state], 1)

    def test_a_decision_after_the_deadline_still_counts(self):
        doc = review.apply(valid_report(), self.decided('approve'), self.REF, '2026-12-31T00:00:00Z')
        self.assertEqual(doc['findings'][0]['review']['state'], 'approved')

    def test_a_decision_on_another_requirement_version_does_not_carry_over(self):
        doc = review.apply(valid_report(), self.decided('evidence_pending', requirement_version=2), self.REF, self.NOW)
        self.assertEqual((doc['findings'][0]['review'], doc['findings'][0]['status']),
                         ({'state': 'pending'}, 'confirmed'))


class CommandLine(ControlZone):
    """python3 -I -m toolkit.review publish|sync, through main() with the platform injected (no network)."""

    TOKEN = {'MAZ_REVIEW_GITHUB_TOKEN': 'token-for-tests'}

    def run_main(self, *argv, environ=None, platform=None):
        made, out = [], io.StringIO()

        def factory(repo, token):
            made.append((repo, token))
            return platform or FakePlatform()
        code = review.main(list(argv), self.TOKEN if environ is None else environ, factory, out)
        return code, out.getvalue(), made

    @staticmethod
    def kept():
        """A record kept for the repository the commands name."""
        return {**record(issue=7), 'platform': 'github'}

    def sync_args(self):
        return ('sync', '--record', str(self.path), '--roles', str(self.roles_path), '--roles-digest',
                self.roles_digest, '--repo', 'owner/reviews', '--project', str(self.source))

    def test_sync_writes_the_decisions_and_prints_the_new_digest(self):
        control.write(self.path, self.kept(), self.source)
        events, comments = self.reasoned_reject(7, 9001)
        code, out, made = self.run_main(*self.sync_args(), platform=FakePlatform(events, comments))
        self.assertEqual(code, 0, out)
        self.assertEqual(made, [('owner/reviews', 'token-for-tests')])
        self.assertIn(control.file_digest(self.path), out)  # for the ScanManifest's review_record
        saved = json.loads(self.path.read_text(encoding='utf-8'))
        self.assertEqual([d['event_id'] for d in saved['items'][0]['decisions']], [9001])

    def test_without_the_token_nothing_is_synced(self):
        control.write(self.path, self.kept(), self.source)
        before = self.path.read_bytes()
        code, out, made = self.run_main(*self.sync_args(), environ={})
        self.assertNotEqual(code, 0)
        self.assertIn('MAZ_REVIEW_GITHUB_TOKEN', out)
        self.assertEqual((made, self.path.read_bytes()), ([], before))

    def publish_args(self, *extra):
        report_path = self.control / 'report.json'
        report_path.write_text(json.dumps(valid_report()), encoding='utf-8')
        return ('publish', '--record', str(self.path), '--report', str(report_path), '--repo', 'owner/reviews',
                '--project', str(self.source), *extra)

    def test_publish_with_new_starts_the_record_and_prints_its_digest(self):
        platform = FakePlatform()
        code, out, _ = self.run_main(*self.publish_args('--new'), platform=platform)
        self.assertEqual(code, 0, out)
        self.assertEqual(len(platform.created), 1)
        saved = json.loads(self.path.read_text(encoding='utf-8'))
        self.assertEqual((saved['platform'], saved['repo'], [i['issue'] for i in saved['items']]),
                         ('github', 'owner/reviews', [100]))
        self.assertIn(control.file_digest(self.path), out)

    def test_each_failure_ends_with_its_reason_and_a_nonzero_status(self):
        control.write(self.path, self.kept(), self.source)
        broken = valid_report()
        del broken['findings'][0]['commit']
        bad_report = self.control / 'bad-report.json'
        bad_report.write_text(json.dumps(broken), encoding='utf-8')
        not_json = self.control / 'not-json.json'
        not_json.write_text('<html>', encoding='utf-8')
        publish = self.publish_args()
        cases = {
            'sync stopped at issue 7': (self.sync_args(), FakePlatform(failing={7})),
            'publish stopped at finding-0001': (publish, FakePlatform(opens=0)),
            'does not exist': (('publish', '--record', str(self.control / 'gone.json'), *publish[3:]), None),
            'the report is not valid': ((*publish[:3], '--report', str(bad_report), *publish[5:]), None),
            'cannot be read': ((*publish[:3], '--report', str(not_json), *publish[5:]), None),
        }
        for reason, (argv, platform) in cases.items():
            with self.subTest(reason):
                code, out, _ = self.run_main(*argv, platform=platform)
                self.assertNotEqual(code, 0)
                self.assertIn(reason, out)
                self.assertNotIn('Traceback', out)

    def test_a_record_that_cannot_be_written_opens_no_issue(self):
        import os
        locked = self.control / 'locked'
        locked.mkdir()
        os.chmod(locked, 0o500)  # readable, not writable
        self.addCleanup(os.chmod, locked, 0o700)
        argv = list(self.publish_args('--new'))
        argv[argv.index('--record') + 1] = str(locked / 'review-record.json')
        platform = FakePlatform()
        code, out, _ = self.run_main(*argv, platform=platform)
        self.assertNotEqual(code, 0)
        self.assertIn('cannot be written', out)
        self.assertNotIn('Traceback', out)
        self.assertEqual(platform.created, [])  # an issue opened now could never be recorded

    def test_the_token_is_never_printed_or_written(self):
        control.write(self.path, self.kept(), self.source)
        events, comments = self.reasoned_reject(7, 9001)
        outputs = [self.run_main(*self.sync_args(), platform=FakePlatform(events, comments))[1],
                   self.run_main(*self.sync_args(), platform=FakePlatform(failing={7}))[1]]
        for text in outputs + [p.read_text(encoding='utf-8') for p in self.control.iterdir()]:
            self.assertNotIn('token-for-tests', text)

    def test_a_record_kept_for_another_repository_is_not_synced_against_this_one(self):
        # Issue numbers are a repository's own: issue 7 elsewhere is someone else's issue (〈定義：覆核紀錄〉 工單).
        control.write(self.path, self.kept(), self.source)  # kept for owner/reviews
        before = self.path.read_bytes()
        argv = list(self.sync_args())
        argv[argv.index('--repo') + 1] = 'someone/else'
        events, comments = self.reasoned_reject(7, 9001)
        code, out, made = self.run_main(*argv, platform=FakePlatform(events, comments))
        self.assertNotEqual(code, 0)
        self.assertIn('owner/reviews', out)
        self.assertEqual((made, self.path.read_bytes()), ([], before))


class RunAsAScript(ControlZone):
    """python3 -I toolkit/tools/review_record.py itself; only what fails before any network request is
    tried here."""

    def test_the_script_runs_and_refuses_to_start_without_the_token(self):
        import os
        import subprocess
        import sys
        control.write(self.path, {**record(issue=7), 'platform': 'github'}, self.source)
        env = {k: v for k, v in os.environ.items() if k != 'MAZ_REVIEW_GITHUB_TOKEN'}
        repo_root = Path(__file__).resolve().parents[2]
        done = subprocess.run([sys.executable, '-I', str(repo_root / 'toolkit/tools/review_record.py'),
                               'sync', '--record', str(self.path),
                               '--roles', str(self.roles_path), '--roles-digest', self.roles_digest,
                               '--repo', 'owner/reviews', '--project', str(self.source)],
                              cwd=repo_root, env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertIn('MAZ_REVIEW_GITHUB_TOKEN is not set', done.stdout)


class StatesAndOptionsAgreeWithSchemas(unittest.TestCase):
    """The 覆核狀態 and options of 〈定義：覆核紀錄〉 are defined once in report.py; the schemas and the platform
    labels list the same values, so none of them can change alone."""

    def test_review_states(self):
        states = list(report.FINDING_REVIEW_STATES)
        self.assertEqual(states, ['pending', 'overdue', 'approved', 'rejected', 'evidence_pending'])  # spec order
        self.assertEqual(report.SCHEMA['$defs']['finding_review']['properties']['state']['enum'], states)
        self.assertEqual(report.SCHEMA['properties']['review_summary']['required'], states)
        self.assertEqual(list(report.FINDING_REVIEW_LABELS), states)

    def test_options(self):
        options = list(report.DECISION_STATES)
        self.assertEqual(options, ['approve', 'reject', 'evidence_pending'])  # 核准、退回、轉證據待補
        decision = report.SCHEMA['$defs']['finding_review']['properties']['decision']['properties']
        self.assertEqual(decision['option']['enum'], options)
        self.assertEqual(review.SCHEMA['$defs']['attempt']['properties']['option']['enum'], options)
        self.assertEqual(list(report.OPTION_LABELS), options)
        self.assertEqual(list(review.OPTION_OF_LABEL.values()), options)


if __name__ == '__main__':
    unittest.main()
