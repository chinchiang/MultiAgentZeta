"""The S2 default policy template (TK-REQ-008), tested through toolkit.policy.

Fast tests only; the template's self-acceptance on the samples runs in test_scan.TemplateSelfAcceptanceEnv.
"""
import copy
import unittest

from toolkit import policy


class LoadTemplate(unittest.TestCase):
    def test_the_v01_template_has_the_three_object_authorization_clauses(self):
        t = policy.load_template()
        self.assertEqual([c['id'] for c in t['clauses']],
                         ['S2-OWNER-ONLY', 'S2-TENANT-ISOLATION', 'S2-ANON-NO-ACCESS'])
        self.assertEqual({c['rule'] for c in t['clauses']}, {'deny'})
        self.assertEqual(t['stack'], {'framework': 'nextjs', 'baas': 'supabase'})


class Validate(unittest.TestCase):
    """policy.validate(): each refusal has a passing case (the shipped template) and a triggering one."""

    def assert_invalid(self, change, part):
        t = copy.deepcopy(policy.load_template())
        change(t)
        with self.assertRaises(policy.PolicyTemplateInvalid) as cm:
            policy.validate(t)
        self.assertIn(part, str(cm.exception))

    def test_the_shipped_template_is_valid(self):
        policy.validate(policy.load_template())

    def test_missing_field(self):
        for field in ('template_id', 'version', 'stack', 'clauses', 'self_acceptance'):
            with self.subTest(field=field):
                self.assert_invalid(lambda t, f=field: t.pop(f), field)
        for field in ('id', 'statement', 'rule', 'actors'):
            with self.subTest(clause_field=field):
                self.assert_invalid(lambda t, f=field: t['clauses'][1].pop(f), field)

    def test_duplicate_clause_id(self):
        self.assert_invalid(lambda t: t['clauses'][1].update(id='S2-OWNER-ONLY'), 'S2-OWNER-ONLY')

    def test_rule_is_deny_or_allow(self):
        for rule in ('permit', '', None):
            with self.subTest(rule=rule):
                self.assert_invalid(lambda t, r=rule: t['clauses'][0].update(rule=r), 'rule')

    def test_self_acceptance_case_names_a_clause_of_the_template(self):
        self.assert_invalid(lambda t: t['self_acceptance']['cases'][0].update(clause='S2-NO-SUCH'), 'S2-NO-SUCH')

    def test_self_acceptance_case_expects_a_result_for_every_sample_version(self):
        self.assert_invalid(lambda t: t['self_acceptance']['cases'][0]['expected'].pop('patched'), 'patched')
        self.assert_invalid(lambda t: t['self_acceptance']['cases'][0]['expected'].update(patched='blocked'),
                            'blocked')

    def test_every_clause_has_a_self_acceptance_case(self):
        def drop_anonymous(t):
            t['self_acceptance']['cases'] = [c for c in t['self_acceptance']['cases']
                                             if c['clause'] != 'S2-ANON-NO-ACCESS']
        self.assert_invalid(drop_anonymous, 'S2-ANON-NO-ACCESS')


# The digest of each released template version. A content change without a version bump fails here;
# a bump adds its digest after the new template passes its self-acceptance (TK-REQ-008).
PINNED_DIGESTS = {'1': 'sha256:9668480c9d7ec33f1156d678e22dfaad96a1808cd3b8553dc7ed31c272bf6150'}


class TemplateVersion(unittest.TestCase):
    def test_content_matches_the_digest_pinned_for_its_version(self):
        t = policy.load_template()
        self.assertIn(t['version'], PINNED_DIGESTS, 'new template version: pin its digest after self-acceptance')
        self.assertEqual(policy.template_digest(t), PINNED_DIGESTS[t['version']],
                         'template content changed without a version bump')

    def test_any_content_change_changes_the_digest(self):
        t = policy.load_template()
        changed = {**t, 'clauses': [{**t['clauses'][0], 'rule': 'allow'}] + t['clauses'][1:]}
        self.assertNotEqual(policy.template_digest(changed), policy.template_digest(t))
        self.assertEqual(policy.template_digest(policy.load_template()), policy.template_digest(t))


if __name__ == '__main__':
    unittest.main()
