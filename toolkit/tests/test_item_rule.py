"""The rule a confirmation item imposes on a test and on a finding (〈定義：確認清單〉, TK-REQ-003, TK-REQ-016,
TK-DYN-003), tested through toolkit.item_rule.

Fast tests only. Expected values are written from the definition, not derived from the code. Each item
is given in the confirmation list's shape and converted to the report's shape (confirmation.requirement),
so the run and report.validate() are shown to judge it the same way.
"""
import copy
import unittest

from toolkit import confirmation, item_rule, policy

SHARED_READ = 'SHARED-READ-other-tenant'
S1_PUBLIC = {'id': 'S1-ANNOUNCEMENTS-PUBLIC-READ', 'statement': 'Anyone may read announcements.',
             'resources': ['announcements'], 'rule': 'allow'}
TENANT = 'S2-TENANT-ISOLATION@documents'  # an S2 clause whose rule is deny
# Spec names (〈定義：確認清單〉 處理狀態), written here, not taken from report.REVIEW_LABELS.
LABELS = {'pending': '待確認', 'accepted': '接受', 'modified': '修改', 'not_applicable': '不適用'}
DONE = dict(by='app-owner', at='2026-11-02T09:00:00Z')
EXCEPTION = dict(DONE, reason='documents shared with another tenant', basis='spec §4', modified_rule='allow',
                 allowed_tests=[SHARED_READ], expiry='2027-05-01T00:00:00Z')

# One case per way an item can stand. kinds: what (case_kind, test_id) is judged by, in the order of CASES.
CASES = (('allowed', SHARED_READ), ('allowed', 'OTHER-ALLOWED'), ('denial', SHARED_READ), ('denial', 'READ-other-tenant'))
ROWS = (
    # (name, item id, status, out_of_scope, review, rules for CASES, untestable, finding cap)
    ('accepted deny item', TENANT, 'accepted', False, DONE,
     ('deny', 'deny', 'deny', 'deny'), None, 'confirmed'),
    ('accepted item with a leftover modified_rule', TENANT, 'accepted', False,
     dict(DONE, modified_rule='allow'),
     ('deny', 'deny', 'deny', 'deny'), None, 'confirmed'),
    ('legitimate exception', TENANT, 'modified', False, EXCEPTION,
     ('allow', 'deny', 'deny', 'deny'), None, 'confirmed'),
    ('modification tightening an allow item', S1_PUBLIC['id'], 'modified', False,
     dict(DONE, reason='stricter', basis='spec §3', modified_rule='deny'),
     ('deny', 'deny', 'deny', 'deny'), None, 'confirmed'),
    ('modification keeping deny, with a leftover allowed test', TENANT, 'modified', False,
     dict(EXCEPTION, modified_rule='deny'),
     ('deny', 'deny', 'deny', 'deny'), None, 'confirmed'),
    ('modification rewriting an allow item to allow', S1_PUBLIC['id'], 'modified', False,
     dict(DONE, reason='same', basis='spec §3', modified_rule='allow'),
     ('allow', 'allow', 'allow', 'allow'), None, 'confirmed'),
    ('pending S2 clause', TENANT, 'pending', False, {},
     ('deny', 'deny', 'deny', 'deny'), None, 'evidence_pending'),
    ('pending S1 entry', S1_PUBLIC['id'], 'pending', False, {},
     ('allow', 'allow', 'allow', 'allow'),
     'is an S1 entry still pending (待確認) until it is reviewed (TK-REQ-003)', 'evidence_pending'),
    ('not applicable', TENANT, 'not_applicable', False, dict(DONE, reason='no tenants', basis='spec §2'),
     ('deny', 'deny', 'deny', 'deny'), 'is not_applicable (不適用)', 'evidence_pending'),
    ('out of scope', TENANT, 'accepted', True, DONE,
     ('deny', 'deny', 'deny', 'deny'), 'is out of scope', 'confirmed'),
)


def listed(item_id, status, out_of_scope, review):
    """The item as the confirmation list holds it."""
    doc = confirmation.generate(policy.load_template(), [{'name': 'documents', 'impact': []},
                                                         {'name': 'announcements', 'impact': []}], [S1_PUBLIC])
    item = copy.deepcopy(next(i for i in doc['items'] if i['item_id'] == item_id))
    item.update(status=status, out_of_scope=out_of_scope)
    item['review'].update(review)
    return item


class ItemRule(unittest.TestCase):
    def test_the_run_and_the_report_judge_each_item_the_same_way(self):
        for name, item_id, status, out_of_scope, review, rules, untestable, cap in ROWS:
            with self.subTest(name):
                item = confirmation.requirement(listed(item_id, status, out_of_scope, review))
                self.assertEqual([item_rule.rule_for(item, test_id, kind) for kind, test_id in CASES], list(rules))
                self.assertEqual(item_rule.untestable(item, LABELS), untestable)
                self.assertEqual(item_rule.finding_cap(item), cap)

    def test_a_requirement_shows_who_confirmed_the_item_and_only_a_legitimate_exceptions_tests(self):
        exception = confirmation.requirement(listed(TENANT, 'modified', False, EXCEPTION))
        self.assertEqual(exception, {
            'id': TENANT, 'source': 'S2', 'statement': exception['statement'], 'rule': 'deny', 'status': 'modified',
            'out_of_scope': False,
            'confirmation': {'by': 'app-owner', 'at': '2026-11-02T09:00:00Z', 'version': 1,
                             'allowed_tests': [SHARED_READ], 'expiry': '2027-05-01T00:00:00Z'}})
        # A rewritten rule replaces the original: the requirement carries it as its rule and lists no test.
        rewritten = confirmation.requirement(listed(S1_PUBLIC['id'], 'modified', False,
                                                    dict(DONE, reason='r', basis='b', modified_rule='deny')))
        self.assertEqual((rewritten['rule'], rewritten['confirmation']),
                         ('deny', {'by': 'app-owner', 'at': '2026-11-02T09:00:00Z', 'version': 1}))

    def test_only_a_modified_deny_item_listing_allowed_tests_is_a_legitimate_exception(self):
        base = {'status': 'modified', 'rule': 'deny', 'confirmation': {'allowed_tests': [SHARED_READ]}}
        self.assertTrue(item_rule.lists_allowed_tests(base))
        for change in ({'status': 'accepted'}, {'rule': 'allow'}, {'confirmation': {'allowed_tests': []}},
                       {'confirmation': {}}):
            with self.subTest(change):
                self.assertFalse(item_rule.lists_allowed_tests(dict(base, **change)))

    def test_a_report_item_without_a_confirmation_judges_every_test_by_its_rule(self):
        # validate() meets malformed reports: the rules must not raise on them.
        item = {'status': 'modified', 'rule': 'deny'}
        self.assertEqual(item_rule.rule_for(item, SHARED_READ, 'allowed'), 'deny')


class Vocabulary(unittest.TestCase):
    def test_codes_and_the_rule_each_case_kind_tests(self):
        self.assertEqual(item_rule.REVIEW_STATES, ('pending', 'accepted', 'modified', 'not_applicable'))
        self.assertEqual(item_rule.CASE_KINDS, ('denial', 'allowed'))
        self.assertEqual(item_rule.RULE_FOR_CASE, {'denial': 'deny', 'allowed': 'allow'})
        self.assertEqual(item_rule.REVIEWED, ('accepted', 'modified'))


if __name__ == '__main__':
    unittest.main()
