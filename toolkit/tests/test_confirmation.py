"""The confirmation list (〈定義：確認清單〉), tested through toolkit.confirmation.

Fast tests only. Expected values are written from the definition, not derived from the code.
"""
import copy
import unittest
from datetime import datetime, timezone
from pathlib import Path

from toolkit import confirmation, policy, report

S1_PUBLIC = {'id': 'S1-ANNOUNCEMENTS-PUBLIC-READ', 'statement': 'Anyone, signed in or not, may read announcements.',
             'resources': ['announcements'], 'rule': 'allow'}


# A time before every expiry these tests write (〈定義：確認清單〉 到期).
NOW = datetime(2026, 11, 4, 9, 0, tzinfo=timezone.utc)


def plain(*names):
    """Resources under test that involve no high-impact category, as scope.resources gives them."""
    return [{'name': n, 'impact': []} for n in names]


class Generate(unittest.TestCase):
    def setUp(self):
        self.template = policy.load_template()
        self.doc = confirmation.generate(self.template, plain('documents', 'announcements'), [S1_PUBLIC])

    def test_items_are_each_s2_clause_on_each_resource_and_each_s1_entry(self):
        self.assertEqual(sorted(i['item_id'] for i in self.doc['items']), [
            'S1-ANNOUNCEMENTS-PUBLIC-READ',
            'S2-ANON-NO-ACCESS@announcements', 'S2-ANON-NO-ACCESS@documents',
            'S2-OWNER-ONLY@announcements', 'S2-OWNER-ONLY@documents',
            'S2-TENANT-ISOLATION@announcements', 'S2-TENANT-ISOLATION@documents'])
        items = {i['item_id']: i for i in self.doc['items']}
        owner = items['S2-OWNER-ONLY@documents']
        self.assertEqual((owner['source'], owner['clause_id'], owner['resource'], owner['rule']),
                         ('S2', 'S2-OWNER-ONLY', 'documents', 'deny'))
        s1 = items['S1-ANNOUNCEMENTS-PUBLIC-READ']
        self.assertEqual((s1['source'], s1['resources'], s1['rule']), ('S1', ['announcements'], 'allow'))

    def test_each_item_lists_its_high_impact_categories(self):
        # TK-REQ-012: an S2 item has its clause's and its resource's categories; an S1 item has its
        # resources' and its own optional ones; each list in the order of 〈定義：高影響類別〉.
        resources = [{'name': 'documents', 'impact': ['confidential']}, {'name': 'announcements', 'impact': []}]
        paid = {'id': 'S1-PAID-READ', 'statement': 'Only paying users may read reports.',
                'resources': ['announcements'], 'rule': 'deny', 'impact': ['payment']}
        both = {**S1_PUBLIC, 'id': 'S1-BOTH', 'resources': ['announcements', 'documents']}
        doc = confirmation.generate(self.template, resources, [paid, both])
        self.assertEqual({i['item_id']: i['impact'] for i in doc['items']}, {
            'S2-OWNER-ONLY@documents': ['confidential'], 'S2-OWNER-ONLY@announcements': [],
            'S2-TENANT-ISOLATION@documents': ['cross_tenant', 'confidential'],
            'S2-TENANT-ISOLATION@announcements': ['cross_tenant'],
            'S2-ANON-NO-ACCESS@documents': ['confidential'], 'S2-ANON-NO-ACCESS@announcements': [],
            'S1-PAID-READ': ['payment'], 'S1-BOTH': ['confidential']})

    def test_high_impact_items_come_first_and_items_out_of_scope_last_each_by_item_id(self):
        # 〈定義：確認清單〉 排序: in scope and high-impact, in scope, out of scope; item_id order within each.
        resources = [{'name': 'documents', 'impact': ['confidential']}, {'name': 'announcements', 'impact': []}]
        elsewhere = {**S1_PUBLIC, 'id': 'S1-AUDIT-LOG', 'resources': ['audit_log'], 'impact': ['admin']}
        doc = confirmation.generate(self.template, resources, [elsewhere, S1_PUBLIC])
        expected = ['S2-ANON-NO-ACCESS@documents', 'S2-OWNER-ONLY@documents',
                    'S2-TENANT-ISOLATION@announcements', 'S2-TENANT-ISOLATION@documents',
                    'S1-ANNOUNCEMENTS-PUBLIC-READ', 'S2-ANON-NO-ACCESS@announcements', 'S2-OWNER-ONLY@announcements',
                    'S1-AUDIT-LOG']
        self.assertEqual([i['item_id'] for i in doc['items']], expected)
        self.assertEqual([i['item_id'] for i in confirmation.generate(self.template, resources[::-1],
                                                                      [S1_PUBLIC, elsewhere])['items']], expected)

    def test_s1_entry_on_no_resource_in_scope_is_listed_out_of_scope(self):
        doc = confirmation.generate(self.template, plain('documents'), [S1_PUBLIC])
        s1 = next(i for i in doc['items'] if i['source'] == 'S1')
        self.assertEqual((s1['out_of_scope'], s1['status']), (True, 'pending'))

    def test_every_item_is_pending_with_empty_review_fields(self):
        for item in self.doc['items']:
            with self.subTest(item=item['item_id']):
                self.assertEqual(item['status'], 'pending')
                self.assertEqual(item['review'], {'by': None, 'at': None, 'reason': None, 'basis': None,
                                                  'modified_rule': None, 'allowed_tests': [], 'expiry': None})
                self.assertEqual(item['version'], 1)
                self.assertFalse(item['out_of_scope'])

    def test_list_records_its_version_and_the_s2_template_it_came_from(self):
        self.assertEqual(self.doc['list_version'], 1)
        self.assertEqual(self.doc['s2_template'], {'policy_template_id': 'nextjs-supabase-object-authz',
                                                   'version': self.template['version'],
                                                   'digest': policy.template_digest(self.template)})
        self.assertNotIn('accept_all', str(self.doc))


def accept(doc, item_id, by='app-owner', at='2026-11-02T09:00:00Z'):
    """The owner accepts an item, as a person editing the list would (test only)."""
    item = next(i for i in doc['items'] if i['item_id'] == item_id)
    item['status'] = 'accepted'
    item['review'].update(by=by, at=at)
    return doc


class Update(unittest.TestCase):
    def setUp(self):
        self.template = policy.load_template()
        self.doc = accept(confirmation.generate(self.template, plain('documents'), [S1_PUBLIC]), 'S2-OWNER-ONLY@documents')

    def item(self, doc, item_id):
        return next(i for i in doc['items'] if i['item_id'] == item_id)

    def test_nothing_changed_keeps_the_list_as_it_is(self):
        new = confirmation.update(self.doc, self.template, plain('documents'), [S1_PUBLIC], now=NOW)
        self.assertEqual(new, self.doc)

    def test_a_new_resource_adds_pending_items_and_keeps_reviewed_ones(self):
        new = confirmation.update(self.doc, self.template, plain('documents', 'files'), [S1_PUBLIC], now=NOW)
        self.assertEqual(new['list_version'], 2)
        self.assertEqual(self.item(new, 'S2-OWNER-ONLY@files')['status'], 'pending')
        kept = self.item(new, 'S2-OWNER-ONLY@documents')
        self.assertEqual((kept['status'], kept['review']['by'], kept['version']), ('accepted', 'app-owner', 1))

    def test_a_category_change_moves_an_item_and_keeps_its_version_and_review_state(self):
        # Categories are not the item's text (CONTENT): only its impact and place change, and the list's version.
        confidential = [{'name': 'documents', 'impact': ['confidential']}]
        new = confirmation.update(self.doc, self.template, confidential, [S1_PUBLIC], now=NOW)
        item = self.item(new, 'S2-OWNER-ONLY@documents')
        self.assertEqual((item['impact'], item['status'], item['version'], item['review']['by']),
                         (['confidential'], 'accepted', 1, 'app-owner'))
        self.assertNotIn('history', item)
        self.assertEqual(new['list_version'], 2)
        self.assertEqual([i['item_id'] for i in new['items']][:3], [
            'S2-ANON-NO-ACCESS@documents', 'S2-OWNER-ONLY@documents', 'S2-TENANT-ISOLATION@documents'])

    def test_a_list_in_another_order_is_sorted_without_a_new_version(self):
        shuffled = {**self.doc, 'items': self.doc['items'][::-1]}
        new = confirmation.update(shuffled, self.template, plain('documents'), [S1_PUBLIC], now=NOW)
        self.assertEqual(new, self.doc)

    def test_items_that_leave_the_scope_go_last(self):
        new = confirmation.update(self.doc, self.template, plain('files'), [S1_PUBLIC], now=NOW)
        self.assertEqual([i['item_id'] for i in new['items']], [
            'S2-TENANT-ISOLATION@files', 'S2-ANON-NO-ACCESS@files', 'S2-OWNER-ONLY@files',
            'S1-ANNOUNCEMENTS-PUBLIC-READ', 'S2-ANON-NO-ACCESS@documents', 'S2-OWNER-ONLY@documents',
            'S2-TENANT-ISOLATION@documents'])

    def test_a_list_written_before_items_had_categories_is_read_and_given_them(self):
        # 〈定義：確認清單〉 影響範圍: a list without impact is still usable; the update fills it in and keeps
        # every review state, so the owner's work is not lost (TK-REQ-004).
        both = plain('documents', 'announcements')
        doc = accept(confirmation.generate(self.template, both, [S1_PUBLIC]), 'S1-ANNOUNCEMENTS-PUBLIC-READ')
        gone = confirmation.update(doc, self.template, plain('documents'), [S1_PUBLIC], now=NOW)  # S1 item out of scope
        old = copy.deepcopy(gone)
        for item in old['items']:
            del item['impact']
        self.assertEqual(confirmation.validate(old), [])
        new = confirmation.update(old, self.template, plain('documents'), [S1_PUBLIC], now=NOW)
        self.assertEqual(new, {**gone, 'list_version': gone['list_version'] + 1})

    def test_a_changed_clause_gets_a_new_version_back_at_pending_and_keeps_the_old_one(self):
        changed = copy.deepcopy(self.template)
        changed['version'] = '2'
        changed['clauses'][0]['statement'] = '資源預設僅擁有者可讀寫，含封存資料。'
        new = confirmation.update(self.doc, changed, plain('documents'), [S1_PUBLIC], now=NOW)
        item = self.item(new, 'S2-OWNER-ONLY@documents')
        self.assertEqual((item['version'], item['status'], item['review']['by']), (2, 'pending', None))
        self.assertEqual(item['statement'], '資源預設僅擁有者可讀寫，含封存資料。')
        old = item['history'][-1]
        self.assertEqual((old['version'], old['status'], old['review']['by'], old['statement']),
                         (1, 'accepted', 'app-owner', '資源預設僅擁有者可讀寫。'))
        self.assertEqual(new['s2_template']['version'], '2')
        self.assertEqual(self.item(new, 'S2-TENANT-ISOLATION@documents')['version'], 1)

    def test_a_resource_out_of_scope_is_marked_and_keeps_its_review_state(self):
        gone = confirmation.update(self.doc, self.template, plain('files'), [S1_PUBLIC], now=NOW)
        item = self.item(gone, 'S2-OWNER-ONLY@documents')
        self.assertEqual((item['out_of_scope'], item['status']), (True, 'accepted'))
        back = confirmation.update(gone, self.template, plain('documents', 'files'), [S1_PUBLIC], now=NOW)
        item = self.item(back, 'S2-OWNER-ONLY@documents')
        self.assertEqual((item['out_of_scope'], item['status'], item['version']), (False, 'accepted', 1))

    def test_an_item_whose_clause_left_the_template_is_out_of_scope_and_keeps_its_review_state(self):
        # 〈定義：確認清單〉 更新: a clause removed from the S2 template marks its items out of scope.
        removed = copy.deepcopy(self.template)
        removed['version'] = '2'
        removed['clauses'] = [c for c in removed['clauses'] if c['id'] != 'S2-OWNER-ONLY']
        gone = confirmation.update(self.doc, removed, plain('documents'), [S1_PUBLIC], now=NOW)
        item = self.item(gone, 'S2-OWNER-ONLY@documents')
        self.assertEqual((item['out_of_scope'], item['status'], item['review']['by'], item['version']),
                         (True, 'accepted', 'app-owner', 1))
        self.assertNotIn('history', item)  # no new version: the text did not change, the clause left
        self.assertFalse(self.item(gone, 'S2-TENANT-ISOLATION@documents')['out_of_scope'])
        back = confirmation.update(gone, self.template, plain('documents'), [S1_PUBLIC], now=NOW)
        item = self.item(back, 'S2-OWNER-ONLY@documents')
        self.assertEqual((item['out_of_scope'], item['status'], item['version']), (False, 'accepted', 1))

    def test_an_s1_entry_no_longer_given_is_out_of_scope_and_keeps_its_review_state(self):
        # 〈定義：確認清單〉 更新: an S1 entry the ScanManifest no longer gives marks its item out of scope.
        both = plain('documents', 'announcements')
        doc = accept(confirmation.generate(self.template, both, [S1_PUBLIC]), 'S1-ANNOUNCEMENTS-PUBLIC-READ')
        gone = confirmation.update(doc, self.template, both, [], now=NOW)
        item = self.item(gone, 'S1-ANNOUNCEMENTS-PUBLIC-READ')
        self.assertEqual((item['out_of_scope'], item['status'], item['version']), (True, 'accepted', 1))
        reworded = dict(S1_PUBLIC, statement='Anyone may read published announcements.')
        back = self.item(confirmation.update(gone, self.template, both, [reworded], now=NOW), 'S1-ANNOUNCEMENTS-PUBLIC-READ')
        # Back in scope with a changed text: a new version, pending again (TK-REQ-004).
        self.assertEqual((back['out_of_scope'], back['status'], back['version']), (False, 'pending', 2))

    def test_s1_entry_whose_resources_left_the_scope_is_out_of_scope(self):
        both = plain('documents', 'announcements')
        doc = accept(confirmation.generate(self.template, both, [S1_PUBLIC]), 'S1-ANNOUNCEMENTS-PUBLIC-READ')
        gone = confirmation.update(doc, self.template, plain('documents'), [S1_PUBLIC], now=NOW)
        item = self.item(gone, 'S1-ANNOUNCEMENTS-PUBLIC-READ')
        self.assertEqual((item['out_of_scope'], item['status']), (True, 'accepted'))
        back = confirmation.update(gone, self.template, both, [S1_PUBLIC], now=NOW)
        self.assertEqual((self.item(back, 'S1-ANNOUNCEMENTS-PUBLIC-READ')['out_of_scope'],
                          self.item(back, 'S1-ANNOUNCEMENTS-PUBLIC-READ')['status']), (False, 'accepted'))

    def test_s1_entries_follow_the_same_rules(self):
        scope = plain('documents', 'announcements')
        doc = accept(confirmation.generate(self.template, scope, [S1_PUBLIC]), 'S1-ANNOUNCEMENTS-PUBLIC-READ')
        changed = {**S1_PUBLIC, 'rule': 'deny'}
        item = self.item(confirmation.update(doc, self.template, scope, [changed], now=NOW), 'S1-ANNOUNCEMENTS-PUBLIC-READ')
        self.assertEqual((item['version'], item['status'], item['rule']), (2, 'pending', 'deny'))
        item = self.item(confirmation.update(doc, self.template, scope, [], now=NOW), 'S1-ANNOUNCEMENTS-PUBLIC-READ')
        self.assertEqual((item['out_of_scope'], item['status']), (True, 'accepted'))

    def exception(self, expiry):
        """self.doc with S2-TENANT-ISOLATION@documents a 合法例外 expiring at expiry (as the owner would edit it)."""
        doc = copy.deepcopy(self.doc)
        item = self.item(doc, 'S2-TENANT-ISOLATION@documents')
        item['status'] = 'modified'
        item['review'].update(by='app-owner', at='2026-11-02T09:00:00Z', reason='shared with another tenant',
                              basis='sharing spec §4', modified_rule='allow',
                              allowed_tests=['SHARED-READ-other-tenant'], expiry=expiry)
        return doc

    def test_an_expired_exception_gets_a_new_version_back_at_pending_and_keeps_the_review_in_its_history(self):
        # 〈定義：確認清單〉 到期: an expiry not later than the run's start has come.
        for expiry in ('2026-11-01T00:00:00Z', '2026-11-04T09:00:00Z'):
            with self.subTest(expiry):
                doc = self.exception(expiry)
                old = copy.deepcopy(self.item(doc, 'S2-TENANT-ISOLATION@documents'))
                new = confirmation.update(doc, self.template, plain('documents'), [S1_PUBLIC], now=NOW)
                item = self.item(new, 'S2-TENANT-ISOLATION@documents')
                self.assertEqual((item['version'], item['status'], item['reset_reason']), (2, 'pending', 'expired'))
                self.assertEqual(item['review'], {'by': None, 'at': None, 'reason': None, 'basis': None,
                                                  'modified_rule': None, 'allowed_tests': [], 'expiry': None})
                self.assertEqual(item['history'], [{k: v for k, v in old.items() if k not in ('out_of_scope', 'impact')}])
                self.assertEqual(new['list_version'], doc['list_version'] + 1)
                self.assertEqual(self.item(new, 'S2-OWNER-ONLY@documents'), self.item(doc, 'S2-OWNER-ONLY@documents'))
                self.assertEqual(confirmation.validate(new), [])

    def test_an_exception_not_yet_expired_or_without_a_valid_expiry_is_kept(self):
        # A malformed expiry is no time that has come; the tests on the item are blocked instead (review_problem).
        for expiry in ('2026-11-04T09:00:01Z', 'next quarter'):
            with self.subTest(expiry):
                doc = self.exception(expiry)
                self.assertEqual(confirmation.update(doc, self.template, plain('documents'), [S1_PUBLIC], now=NOW), doc)

    def test_an_exception_out_of_scope_is_not_reset_until_it_is_back_in_scope(self):
        # 〈定義：確認清單〉 更新: an item out of scope keeps its review state and version; 到期 is judged in scope.
        doc = self.exception('2026-11-01T00:00:00Z')
        gone = confirmation.update(doc, self.template, plain('files'), [S1_PUBLIC], now=NOW)
        item = self.item(gone, 'S2-TENANT-ISOLATION@documents')
        self.assertEqual((item['out_of_scope'], item['version'], item['status']), (True, 1, 'modified'))
        back = self.item(confirmation.update(gone, self.template, plain('documents'), [S1_PUBLIC], now=NOW),
                         'S2-TENANT-ISOLATION@documents')
        self.assertEqual((back['out_of_scope'], back['version'], back['status'], back['reset_reason']),
                         (False, 2, 'pending', 'expired'))

    def test_a_text_change_after_an_expiry_drops_the_reset_reason_and_keeps_it_in_the_history(self):
        expired = confirmation.update(self.exception('2026-11-01T00:00:00Z'), self.template, plain('documents'),
                                      [S1_PUBLIC], now=NOW)
        changed = copy.deepcopy(self.template)
        changed['clauses'][1]['statement'] = '租戶間預設完全隔離，包括分享。'
        item = self.item(confirmation.update(expired, changed, plain('documents'), [S1_PUBLIC], now=NOW),
                         'S2-TENANT-ISOLATION@documents')
        self.assertEqual((item['version'], 'reset_reason' in item), (3, False))
        self.assertEqual([h.get('reset_reason') for h in item['history']], [None, 'expired'])

    def test_the_toolkit_writes_no_review_decision(self):
        # TK-REQ-009: only pending comes from the toolkit; decisions it kept were already in the list.
        changed = copy.deepcopy(self.template)
        changed['version'] = '2'
        for c in changed['clauses']:
            c['statement'] += '（修訂）'
        new = confirmation.update(self.doc, changed, plain('documents', 'files'), [S1_PUBLIC], now=NOW)
        self.assertEqual({i['status'] for i in new['items']}, {'pending'})


class Validate(unittest.TestCase):
    """validate(): the list's structure (schema); review_problem(): the fields each review state needs."""

    def setUp(self):
        self.doc = confirmation.generate(policy.load_template(), plain('documents'), [S1_PUBLIC])

    def test_generated_and_updated_lists_are_valid(self):
        self.assertEqual(confirmation.validate(self.doc), [])
        self.assertEqual(confirmation.validate(accept(self.doc, 'S2-OWNER-ONLY@documents')), [])

    def test_item_ids_follow_their_source_so_s1_and_s2_cannot_collide(self):
        # An S2 item is "clause@resource" with both parts; an S1 entry id has no "@", so it can never
        # equal an S2 item id (〈定義：確認清單〉 確認項目).
        def with_id(source, item_id, in_history=False):
            doc = copy.deepcopy(self.doc)
            n, item = next((n, i) for n, i in enumerate(doc['items'])
                           if i['item_id'] in ('S1-ANNOUNCEMENTS-PUBLIC-READ', 'S2-OWNER-ONLY@documents')
                           and i['source'] == source)
            if in_history:
                item['history'] = [dict({k: v for k, v in item.items() if k not in ('out_of_scope', 'history', 'impact')},
                                        item_id=item_id)]
            else:
                item['item_id'] = item_id
            return doc, f'items/{n}/history/0' if in_history else f'items/{n}'

        for source, item_id in (('S1', 'S1-ANNOUNCEMENTS-PUBLIC-READ'), ('S2', 'S2-OWNER-ONLY@documents')):
            with self.subTest(accepted=item_id):
                doc, _ = with_id(source, item_id)
                self.assertEqual(confirmation.validate(doc), [])
        for source, item_id, in_history in (('S1', 'S2-OWNER-ONLY@documents', False), ('S1', 'S1-X@announcements', False),
                                            ('S2', 'S2-OWNER-ONLY', False), ('S2', 'S2-OWNER-ONLY@', False),
                                            ('S2', 'S2-OWNER-ONLY@files', False), ('S2', 'S2-OWNER-ONLY@files', True)):
            with self.subTest(refused=item_id, source=source, in_history=in_history):
                doc, where = with_id(source, item_id, in_history)
                problems = confirmation.validate(doc)
                self.assertTrue(any(p.startswith(f'{where}/item_id: ') for p in problems), problems)

    def test_malformed_list_is_invalid(self):
        changes = {'unknown review state': lambda d: d['items'][0].update(status='confirmed'),
                   'an accept-all field on an item': lambda d: d['items'][0].update(accept_all=True),
                   'an unknown field in an earlier version': lambda d: d['items'][0].update(
                       history=[{**{k: v for k, v in d['items'][0].items() if k != 'out_of_scope'}, 'accept_all': True}]),
                   'items missing': lambda d: d.pop('items'),
                   'unknown source': lambda d: d['items'][0].update(source='implementation'),
                   'version not an integer': lambda d: d['items'][0].update(version='1'),
                   'no s2_template': lambda d: d.pop('s2_template')}
        for name, change in changes.items():
            with self.subTest(name):
                d = copy.deepcopy(self.doc)
                change(d)
                self.assertNotEqual(confirmation.validate(d), [])


TENANT_ITEM = 'S2-TENANT-ISOLATION@documents'
SHARED_READ = 'SHARED-READ-other-tenant'
# A 合法例外 complete in every field, on TENANT_ITEM: documents shared with another tenant (TK-DYN-003).
EXCEPTION = dict(by='app-owner', at='2026-11-02T09:00:00Z', reason='documents shared with another tenant',
                 basis=S1_PUBLIC['id'], modified_rule='allow', allowed_tests=[SHARED_READ],
                 expiry='2027-05-01T00:00:00Z')


class Reviewed(unittest.TestCase):
    """A list where the owner accepted S1_PUBLIC, and a plan with one allowed and one denial test on
    TENANT_ITEM; item() gives TENANT_ITEM in a review state."""

    def setUp(self):
        doc = confirmation.generate(policy.load_template(), plain('documents', 'announcements'), [S1_PUBLIC])
        self.items = {i['item_id']: i for i in accept(doc, S1_PUBLIC['id'])['items']}
        self.plan = {SHARED_READ: {'requirement_id': TENANT_ITEM, 'case_kind': 'allowed'},
                     'READ-other-tenant': {'requirement_id': TENANT_ITEM, 'case_kind': 'denial'},
                     'PUBLIC-READ-other-tenant': {'requirement_id': 'S2-TENANT-ISOLATION@announcements',
                                                  'case_kind': 'allowed'}}

    def item(self, status, **review):
        item = copy.deepcopy(self.items[TENANT_ITEM])
        item['status'] = status
        item['review'].update(review)
        return item

    def problem(self, item):
        return confirmation.review_problem(item, self.items)


class ReviewProblem(Reviewed):
    """review_problem(): the fields each review state needs (〈定義：確認清單〉, TK-SCP-003, TK-DYN-003)."""

    def test_pending_needs_nothing(self):
        self.assertIsNone(self.problem(self.item('pending')))

    def test_accepted_needs_who_and_when(self):
        self.assertIsNone(self.problem(self.item('accepted', by='app-owner', at='2026-11-02T09:00:00Z')))
        self.assertIn('by', self.problem(self.item('accepted', at='2026-11-02T09:00:00Z')))
        self.assertIn('at', self.problem(self.item('accepted', by='app-owner')))

    def test_not_applicable_needs_a_reason_and_a_basis(self):
        done = dict(by='app-owner', at='2026-11-02T09:00:00Z', reason='documents have no tenant', basis='spec §2')
        self.assertIsNone(self.problem(self.item('not_applicable', **done)))
        for name in ('reason', 'basis'):
            with self.subTest(missing=name):
                self.assertIn(name, self.problem(self.item('not_applicable', **{**done, name: None})))

    def test_modified_needs_a_reason_a_basis_and_the_new_rule(self):
        done = dict(by='app-owner', at='2026-11-02T09:00:00Z', reason='stricter', basis='spec §3', modified_rule='deny')
        self.assertIsNone(self.problem(self.item('modified', **done)))
        for name in ('reason', 'basis', 'modified_rule'):
            with self.subTest(missing=name):
                self.assertIn(name, self.problem(self.item('modified', **{**done, name: None})))

    def test_a_legitimate_exception_needs_an_allowed_test_and_an_expiry(self):
        self.assertIsNone(self.problem(self.item('modified', **EXCEPTION)))
        for name, empty in (('allowed_tests', []), ('expiry', None)):
            with self.subTest(missing=name):
                self.assertIn(f'lacks {name}', self.problem(self.item('modified', **{**EXCEPTION, name: empty})))

    def test_a_basis_naming_an_s1_entry_needs_that_entry_in_scope_and_reviewed(self):
        entry = self.items[S1_PUBLIC['id']]
        for change, expected in ((dict(status='pending'), 'is pending (待確認)'),
                                 (dict(status='not_applicable'), 'is not_applicable (不適用)'),
                                 (dict(out_of_scope=True), 'is out of scope')):
            with self.subTest(expected):
                self.items[S1_PUBLIC['id']] = dict(entry, **change)
                self.assertIn(f"its basis, S1 entry {S1_PUBLIC['id']!r}, {expected}", self.problem(self.item('modified', **EXCEPTION)))
        self.items[S1_PUBLIC['id']] = dict(entry, status='modified')
        self.assertIsNone(self.problem(self.item('modified', **EXCEPTION)))

    def test_a_basis_of_spec_text_must_not_be_blank(self):
        self.assertIsNone(self.problem(self.item('modified', **{**EXCEPTION, 'basis': 'sharing spec §4'})))
        self.assertIn('its basis is blank', self.problem(self.item('modified', **{**EXCEPTION, 'basis': '  '})))
        # Not an S1 entry id in the list, so it is spec text: an id-like text is not refused.
        self.assertIsNone(self.problem(self.item('modified', **{**EXCEPTION, 'basis': 'S1-NOT-IN-THE-LIST'})))

    def test_the_expiry_is_an_iso_8601_utc_time(self):
        for expiry in ('2027-05-01T00:00:00Z', '2027-05-01T00:00:00.5Z'):
            with self.subTest(expiry):
                self.assertIsNone(self.problem(self.item('modified', **{**EXCEPTION, 'expiry': expiry})))
        for expiry in ('2027-05-01', 'next quarter', '2027-05-01T00:00:00+08:00', '2027-02-30T00:00:00Z'):
            with self.subTest(expiry):
                self.assertIn('is not an ISO 8601 UTC time', self.problem(self.item('modified', **{**EXCEPTION, 'expiry': expiry})))

    def test_a_modification_that_does_not_relax_s2_lists_no_allowed_test(self):
        # Tightening, or rewriting an allow rule, is no 合法例外: allowed_tests and expiry are not needed.
        self.assertIsNone(self.problem(self.item('modified', **{**EXCEPTION, 'modified_rule': 'deny',
                                                                 'allowed_tests': [], 'expiry': None})))


class RuleFor(Reviewed):
    """〈定義：確認清單〉 修改: a 合法例外 allows only its allowed tests; another modification's rule replaces the original."""

    def test_a_legitimate_exception_allows_only_the_allowed_cases_it_lists(self):
        item = self.item('modified', **EXCEPTION)
        self.assertEqual(confirmation.rule_for(item, SHARED_READ, 'allowed'), 'allow')
        self.assertEqual(confirmation.rule_for(item, 'OTHER-ALLOWED', 'allowed'), 'deny')
        self.assertEqual(confirmation.rule_for(item, 'READ-other-tenant', 'denial'), 'deny')
        self.assertEqual(confirmation.base_rule(item), 'deny')
        # A denial case it lists is still judged by deny.
        listed = self.item('modified', **{**EXCEPTION, 'allowed_tests': [SHARED_READ, 'READ-other-tenant']})
        self.assertEqual(confirmation.rule_for(listed, 'READ-other-tenant', 'denial'), 'deny')

    def test_another_modification_rewrites_the_rule_of_every_test(self):
        public = dict(self.items[S1_PUBLIC['id']], status='modified')
        public['review'] = dict(public['review'], modified_rule='deny')
        self.assertEqual(confirmation.rule_for(public, 'PUBLIC-READ-other-tenant', 'allowed'), 'deny')
        self.assertEqual(confirmation.base_rule(public), 'deny')
        # A leftover modified_rule does not count unless the item is modified.
        self.assertEqual(confirmation.rule_for(self.item('accepted', modified_rule='allow'), SHARED_READ, 'allowed'), 'deny')


class TestProblem(Reviewed):
    """Whether a test may run on the item it rests on (〈定義：確認清單〉, TK-REQ-003, TK-REQ-016)."""

    def check(self, item, test_id, kind):
        return confirmation.test_problem(item, test_id, kind, self.items, self.plan)

    def test_case_kind_must_match_the_items_rule(self):
        deny, allow = self.item('accepted', by='app-owner', at='2026-11-02T09:00:00Z'), self.items[S1_PUBLIC['id']]
        for item, kind in ((deny, 'allowed'), (allow, 'denial')):
            with self.subTest(rule=item['rule'], kind=kind):
                self.assertIn('does not match the rule (TK-REQ-016)', self.check(item, 'T', kind))
        self.assertIsNone(self.check(deny, 'T', 'denial'))
        self.assertIsNone(self.check(allow, 'T', 'allowed'))

    def test_a_pending_s2_item_runs_and_a_pending_s1_item_blocks(self):
        s1 = dict(self.items[S1_PUBLIC['id']], status='pending')
        self.assertIsNone(self.check(self.items[TENANT_ITEM], 'READ-other-tenant', 'denial'))
        self.assertIn('待確認', self.check(s1, 'PUBLIC-READ-anonymous', 'allowed'))

    def test_not_applicable_out_of_scope_and_incompletely_reviewed_items_block(self):
        tenant = self.items[TENANT_ITEM]
        cases = {
            '不適用': self.item('not_applicable', by='app-owner', at='2026-11-02T09:00:00Z', reason='one tenant', basis='spec'),
            'out of scope': dict(self.item('accepted', by='app-owner', at='2026-11-02T09:00:00Z'), out_of_scope=True),
            'lacks at': self.item('accepted', by='app-owner'),
            # Out of scope even while pending: the item makes no test (〈定義：確認清單〉 更新).
            'is out of scope': dict(tenant, out_of_scope=True),
        }
        for expected, item in cases.items():
            with self.subTest(expected):
                self.assertIn(expected, self.check(item, 'READ-other-tenant', 'denial'))

    def test_a_legitimate_exception_runs_its_allowed_tests_and_keeps_denying_the_others(self):
        item = self.item('modified', **EXCEPTION)
        self.assertIsNone(self.check(item, SHARED_READ, 'allowed'))
        self.assertIsNone(self.check(item, 'READ-other-tenant', 'denial'))
        # An allowed case it does not list is still judged by deny.
        self.assertIn("has rule 'deny' for test 'OTHER-ALLOWED'", self.check(item, 'OTHER-ALLOWED', 'allowed'))

    def test_an_allowed_test_that_is_no_allowed_case_on_the_item_in_the_plan_blocks_only_the_allowed_cases(self):
        # TK-DYN-003: the exception must be shown by its allowed tests; a denial case is judged by deny
        # whatever the exception lists, so a plan without them still runs it.
        cases = {'NOT-PLANNED': "allowed test 'NOT-PLANNED' is not in the test plan",
                 'PUBLIC-READ-other-tenant': "rests on 'S2-TENANT-ISOLATION@announcements', not on this item",
                 'READ-other-tenant': "allowed test 'READ-other-tenant' is not an allowed case"}
        for test_id, expected in cases.items():
            with self.subTest(test_id):
                item = self.item('modified', **{**EXCEPTION, 'allowed_tests': [SHARED_READ, test_id]})
                problem = self.check(item, SHARED_READ, 'allowed')
                self.assertIn(expected, problem)
                self.assertIn('is a 合法例外 but', problem)
                self.assertIsNone(self.check(item, 'UPDATE-other-tenant', 'denial'))  # a denial case it does not list
                self.assertIsNone(self.check(item, 'READ-other-tenant', 'denial'))  # nor one it lists

    def test_a_modification_without_its_rule_is_named_before_the_case_kind(self):
        # Without modified_rule the original rule would apply and the reason would wrongly be a mismatch.
        unfinished = self.item('modified', by='app-owner', at='2026-11-02T09:00:00Z', reason='shared', basis='spec')
        self.assertIn('lacks modified_rule', self.check(unfinished, SHARED_READ, 'allowed'))


class FindingCap(unittest.TestCase):
    """The highest finding status a failed test may give, by the item it rests on (TK-REQ-003)."""

    def test_only_a_reviewed_item_can_confirm_a_finding(self):
        doc = accept(confirmation.generate(policy.load_template(), plain('documents'), []), 'S2-OWNER-ONLY@documents')
        items = {i['item_id']: i for i in doc['items']}
        owner = items['S2-OWNER-ONLY@documents']
        modified = dict(owner, status='modified', review=dict(owner['review'], reason='r', basis='b', modified_rule='deny'))
        self.assertEqual(confirmation.finding_cap(owner), 'confirmed')
        self.assertEqual(confirmation.finding_cap(modified), 'confirmed')
        self.assertEqual(confirmation.finding_cap(items['S2-TENANT-ISOLATION@documents']), 'evidence_pending')
        # Only accepted or modified items confirm; anything else is capped, whatever the order of the checks.
        self.assertEqual(confirmation.finding_cap(dict(owner, source='S1', status='pending')), 'evidence_pending')


class EnumsAgreeWithSchemas(unittest.TestCase):
    """Review states, allow/deny rules, high-impact categories and case kinds are each defined once in the code; both schemas
    list the same values, so neither side can change alone (〈定義：確認清單〉, TK-REQ-016)."""

    def test_review_states(self):
        states = list(report.REVIEW_STATES)
        self.assertEqual(states, ['pending', 'accepted', 'modified', 'not_applicable'])  # 〈定義：確認清單〉 table order
        self.assertEqual(confirmation.SCHEMA['$defs']['status']['enum'], states)
        self.assertEqual(report.SCHEMA['properties']['requirements']['items']['properties']['status']['enum'], states)
        self.assertEqual(report.SCHEMA['$defs']['review_counts']['required'], states)
        self.assertEqual(list(confirmation.REQUIRED_REVIEW), states)
        self.assertEqual(list(report.REVIEW_LABELS), states)

    def test_rules(self):
        rules = list(policy.RULES)
        self.assertEqual(confirmation.SCHEMA['$defs']['rule']['enum'], rules)
        self.assertEqual(report.SCHEMA['properties']['requirements']['items']['properties']['rule']['enum'], rules)
        self.assertEqual(sorted(report.RULE_FOR_CASE.values()), sorted(rules))

    def test_impact_categories(self):
        self.assertEqual(confirmation.SCHEMA['$defs']['impact']['items']['enum'], list(policy.IMPACT_CATEGORIES))

    def test_reset_reasons(self):
        self.assertEqual(confirmation.SCHEMA['$defs']['version_fields']['properties']['reset_reason']['const'],
                         confirmation.RESET_EXPIRED)

    def test_case_kinds(self):
        kinds = list(report.CASE_KINDS)
        self.assertEqual(kinds, ['denial', 'allowed'])
        self.assertEqual(report.SCHEMA['$defs']['execution_record']['properties']['case_kind']['enum'], kinds)
        self.assertEqual(list(report.RULE_FOR_CASE), kinds)


if __name__ == '__main__':
    unittest.main()
