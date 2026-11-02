"""The confirmation list (〈定義：確認清單〉), tested through toolkit.confirmation.

Fast tests only. Expected values are written from the definition, not derived from the code.
"""
import copy
import unittest
from pathlib import Path

from toolkit import confirmation, policy

S1_PUBLIC = {'id': 'S1-ANNOUNCEMENTS-PUBLIC-READ', 'statement': 'Anyone, signed in or not, may read announcements.',
             'resources': ['announcements'], 'rule': 'allow'}


class Generate(unittest.TestCase):
    def setUp(self):
        self.template = policy.load_template()
        self.doc = confirmation.generate(self.template, ['documents', 'announcements'], [S1_PUBLIC])

    def test_items_are_each_s2_clause_on_each_resource_and_each_s1_entry(self):
        self.assertEqual([i['item_id'] for i in self.doc['items']], [
            'S2-OWNER-ONLY@documents', 'S2-OWNER-ONLY@announcements',
            'S2-TENANT-ISOLATION@documents', 'S2-TENANT-ISOLATION@announcements',
            'S2-ANON-NO-ACCESS@documents', 'S2-ANON-NO-ACCESS@announcements',
            'S1-ANNOUNCEMENTS-PUBLIC-READ'])
        owner = self.doc['items'][0]
        self.assertEqual((owner['source'], owner['clause_id'], owner['resource'], owner['rule']),
                         ('S2', 'S2-OWNER-ONLY', 'documents', 'deny'))
        s1 = self.doc['items'][-1]
        self.assertEqual((s1['source'], s1['resources'], s1['rule']), ('S1', ['announcements'], 'allow'))

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
        self.doc = accept(confirmation.generate(self.template, ['documents'], [S1_PUBLIC]), 'S2-OWNER-ONLY@documents')

    def item(self, doc, item_id):
        return next(i for i in doc['items'] if i['item_id'] == item_id)

    def test_nothing_changed_keeps_the_list_as_it_is(self):
        new = confirmation.update(self.doc, self.template, ['documents'], [S1_PUBLIC])
        self.assertEqual(new, self.doc)

    def test_a_new_resource_adds_pending_items_and_keeps_reviewed_ones(self):
        new = confirmation.update(self.doc, self.template, ['documents', 'files'], [S1_PUBLIC])
        self.assertEqual(new['list_version'], 2)
        self.assertEqual(self.item(new, 'S2-OWNER-ONLY@files')['status'], 'pending')
        kept = self.item(new, 'S2-OWNER-ONLY@documents')
        self.assertEqual((kept['status'], kept['review']['by'], kept['version']), ('accepted', 'app-owner', 1))

    def test_a_changed_clause_gets_a_new_version_back_at_pending_and_keeps_the_old_one(self):
        changed = copy.deepcopy(self.template)
        changed['version'] = '2'
        changed['clauses'][0]['statement'] = '資源預設僅擁有者可讀寫，含封存資料。'
        new = confirmation.update(self.doc, changed, ['documents'], [S1_PUBLIC])
        item = self.item(new, 'S2-OWNER-ONLY@documents')
        self.assertEqual((item['version'], item['status'], item['review']['by']), (2, 'pending', None))
        self.assertEqual(item['statement'], '資源預設僅擁有者可讀寫，含封存資料。')
        old = item['history'][-1]
        self.assertEqual((old['version'], old['status'], old['review']['by'], old['statement']),
                         (1, 'accepted', 'app-owner', '資源預設僅擁有者可讀寫。'))
        self.assertEqual(new['s2_template']['version'], '2')
        self.assertEqual(self.item(new, 'S2-TENANT-ISOLATION@documents')['version'], 1)

    def test_a_resource_out_of_scope_is_marked_and_keeps_its_review_state(self):
        gone = confirmation.update(self.doc, self.template, ['files'], [S1_PUBLIC])
        item = self.item(gone, 'S2-OWNER-ONLY@documents')
        self.assertEqual((item['out_of_scope'], item['status']), (True, 'accepted'))
        back = confirmation.update(gone, self.template, ['documents', 'files'], [S1_PUBLIC])
        item = self.item(back, 'S2-OWNER-ONLY@documents')
        self.assertEqual((item['out_of_scope'], item['status'], item['version']), (False, 'accepted', 1))

    def test_s1_entries_follow_the_same_rules(self):
        accept(self.doc, 'S1-ANNOUNCEMENTS-PUBLIC-READ')
        changed = {**S1_PUBLIC, 'rule': 'deny'}
        item = self.item(confirmation.update(self.doc, self.template, ['documents'], [changed]),
                         'S1-ANNOUNCEMENTS-PUBLIC-READ')
        self.assertEqual((item['version'], item['status'], item['rule']), (2, 'pending', 'deny'))
        item = self.item(confirmation.update(self.doc, self.template, ['documents'], []), 'S1-ANNOUNCEMENTS-PUBLIC-READ')
        self.assertEqual((item['out_of_scope'], item['status']), (True, 'accepted'))

    def test_the_toolkit_writes_no_review_decision(self):
        # TK-REQ-009: only pending comes from the toolkit; decisions it kept were already in the list.
        changed = copy.deepcopy(self.template)
        changed['version'] = '2'
        for c in changed['clauses']:
            c['statement'] += '（修訂）'
        new = confirmation.update(self.doc, changed, ['documents', 'files'], [S1_PUBLIC])
        self.assertEqual({i['status'] for i in new['items']}, {'pending'})


class Validate(unittest.TestCase):
    """validate(): the list's structure (schema); review_problem(): the fields each review state needs."""

    def setUp(self):
        self.doc = confirmation.generate(policy.load_template(), ['documents'], [S1_PUBLIC])

    def test_generated_and_updated_lists_are_valid(self):
        self.assertEqual(confirmation.validate(self.doc), [])
        self.assertEqual(confirmation.validate(accept(self.doc, 'S2-OWNER-ONLY@documents')), [])

    def test_malformed_list_is_invalid(self):
        changes = {'unknown review state': lambda d: d['items'][0].update(status='confirmed'),
                   'items missing': lambda d: d.pop('items'),
                   'unknown source': lambda d: d['items'][0].update(source='implementation'),
                   'version not an integer': lambda d: d['items'][0].update(version='1'),
                   'no s2_template': lambda d: d.pop('s2_template')}
        for name, change in changes.items():
            with self.subTest(name):
                d = copy.deepcopy(self.doc)
                change(d)
                self.assertNotEqual(confirmation.validate(d), [])

    def item(self, status, **review):
        item = copy.deepcopy(self.doc['items'][0])
        item['status'] = status
        item['review'].update(review)
        return item

    def test_pending_needs_nothing(self):
        self.assertIsNone(confirmation.review_problem(self.item('pending')))

    def test_accepted_needs_who_and_when(self):
        self.assertIsNone(confirmation.review_problem(self.item('accepted', by='app-owner', at='2026-11-02T09:00:00Z')))
        self.assertIn('by', confirmation.review_problem(self.item('accepted', at='2026-11-02T09:00:00Z')))
        self.assertIn('at', confirmation.review_problem(self.item('accepted', by='app-owner')))

    def test_not_applicable_needs_a_reason_and_a_basis(self):
        done = dict(by='app-owner', at='2026-11-02T09:00:00Z', reason='documents have no owner', basis='S1-X')
        self.assertIsNone(confirmation.review_problem(self.item('not_applicable', **done)))
        for name in ('reason', 'basis'):
            with self.subTest(missing=name):
                self.assertIn(name, confirmation.review_problem(self.item('not_applicable', **{**done, name: None})))

    def test_modified_needs_a_reason_a_basis_and_the_new_rule(self):
        done = dict(by='app-owner', at='2026-11-02T09:00:00Z', reason='stricter', basis='spec §3',
                    modified_rule='deny')
        self.assertIsNone(confirmation.review_problem(self.item('modified', **done)))
        for name in ('reason', 'basis', 'modified_rule'):
            with self.subTest(missing=name):
                self.assertIn(name, confirmation.review_problem(self.item('modified', **{**done, name: None})))

    def test_modified_that_permits_what_s2_denies_needs_an_allowed_test_and_an_expiry(self):
        # 〈定義：確認清單〉: such a modification is a 合法例外 (TK-DYN-003).
        done = dict(by='app-owner', at='2026-11-02T09:00:00Z', reason='public data', basis='S1-X',
                    modified_rule='allow', allowed_tests=['PUBLIC-READ-anonymous'], expiry='2027-01-01')
        self.assertIsNone(confirmation.review_problem(self.item('modified', **done)))
        for name, empty in (('allowed_tests', []), ('expiry', None)):
            with self.subTest(missing=name):
                self.assertIn(name, confirmation.review_problem(self.item('modified', **{**done, name: empty})))


class ReadWrite(unittest.TestCase):
    """The list is a record in the control zone, outside the sample source, referenced by path and digest."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.source = Path(self.tmp.name) / 'project'
        self.source.mkdir()
        self.control = Path(self.tmp.name) / 'control'
        self.doc = confirmation.generate(policy.load_template(), ['documents'], [S1_PUBLIC])

    def test_written_list_reads_back_with_its_digest(self):
        path = self.control / 'confirmation-list.json'
        digest = confirmation.write(path, self.doc, self.source)
        self.assertRegex(digest, r'^sha256:[0-9a-f]{64}$')
        self.assertEqual(confirmation.read(path, digest, self.source), self.doc)

    def test_a_path_inside_the_sample_source_is_refused(self):
        for path in (self.source / 'confirmation-list.json', self.source / 'sub' / '..' / 'list.json'):
            with self.subTest(path=str(path)):
                with self.assertRaises(confirmation.ConfirmationListUnusable) as cm:
                    confirmation.write(path, self.doc, self.source)
                self.assertIn('inside the sample source', str(cm.exception))
        outside = self.control / 'list.json'
        digest = confirmation.write(outside, self.doc, self.source)
        inside = self.source / 'list.json'
        inside.write_bytes(outside.read_bytes())
        with self.assertRaises(confirmation.ConfirmationListUnusable):
            confirmation.read(inside, digest, self.source)

    def test_a_digest_that_does_not_match_is_refused(self):
        path = self.control / 'list.json'
        confirmation.write(path, self.doc, self.source)
        with self.assertRaises(confirmation.ConfirmationListUnusable) as cm:
            confirmation.read(path, 'sha256:' + '0' * 64, self.source)
        self.assertIn('digest', str(cm.exception))

    def test_an_invalid_list_is_refused(self):
        path = self.control / 'list.json'
        self.control.mkdir()
        path.write_text('{"schema_version": "1"}', encoding='utf-8')
        digest = confirmation.file_digest(path)
        with self.assertRaises(confirmation.ConfirmationListUnusable) as cm:
            confirmation.read(path, digest, self.source)
        self.assertIn('items', str(cm.exception))


if __name__ == '__main__':
    unittest.main()
