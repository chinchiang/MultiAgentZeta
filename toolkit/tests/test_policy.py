"""The S2 default policy template (TK-REQ-008), tested through toolkit.policy.

Fast tests only; the template's self-acceptance on the samples runs in test_scan.TemplateSelfAcceptanceEnv.
"""
import copy
import re
import unittest
from pathlib import Path

from toolkit import policy


class LoadTemplate(unittest.TestCase):
    def test_the_v01_template_has_the_three_object_authorization_clauses(self):
        t = policy.load_template()
        self.assertEqual([c['id'] for c in t['clauses']],
                         ['S2-OWNER-ONLY', 'S2-TENANT-ISOLATION', 'S2-ANON-NO-ACCESS'])
        self.assertEqual({c['rule'] for c in t['clauses']}, {'deny'})
        self.assertEqual(t['stack'], {'framework': 'nextjs', 'baas': 'supabase'})

    def test_anonymous_writes_are_part_of_the_self_acceptance(self):
        # 〈定義：需求來源〉 S2: 未登入者預設不可寫入; reads alone would not exercise it.
        cases = [c for c in policy.load_template()['self_acceptance']['cases'] if c['clause'] == 'S2-ANON-NO-ACCESS']
        self.assertEqual({c['test']['template_id'] for c in cases},
                         {'cross-user-read-v1', 'cross-user-update-v1', 'cross-user-delete-v1', 'cross-user-create-v1'})


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
        for field in ('policy_template_id', 'version', 'stack', 'clauses', 'self_acceptance'):
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

    def test_duplicate_case_id(self):
        # A repeated case_id would let one result hide the other's.
        self.assert_invalid(lambda t: t['self_acceptance']['cases'][1].update(
            case_id=t['self_acceptance']['cases'][0]['case_id']), 'used twice')

    def test_malformed_structure_is_refused_as_invalid(self):
        changes = {'self_acceptance is not an object': lambda t: t.update(self_acceptance=[]),
                   'clauses is not a list': lambda t: t.update(clauses='S2-OWNER-ONLY'),
                   'a clause is not an object': lambda t: t['clauses'].append('S2-X'),
                   'a case has no test': lambda t: t['self_acceptance']['cases'][0].pop('test'),
                   'a case has no case_id': lambda t: t['self_acceptance']['cases'][0].pop('case_id'),
                   'a case is not an object': lambda t: t['self_acceptance']['cases'].append(None)}
        for name, change in changes.items():
            with self.subTest(name):
                t = copy.deepcopy(policy.load_template())
                change(t)
                self.assertRaises(policy.PolicyTemplateInvalid, policy.validate, t)

    def test_each_clause_lists_its_high_impact_categories(self):
        # TK-REQ-012: a clause names the 〈定義：高影響類別〉 it involves, [] for none; a missing list is never none.
        self.assertEqual({c['id']: c['impact'] for c in policy.load_template()['clauses']},
                         {'S2-OWNER-ONLY': [], 'S2-TENANT-ISOLATION': ['cross_tenant'], 'S2-ANON-NO-ACCESS': []})
        self.assert_invalid(lambda t: t['clauses'][1].pop('impact'), 'clauses/1.impact (高影響類別) is missing')
        self.assert_invalid(lambda t: t['clauses'][1].update(impact=None), 'clauses/1.impact (高影響類別) is missing')
        self.assert_invalid(lambda t: t['clauses'][1].update(impact='cross_tenant'), 'clauses/1.impact must be a list')
        self.assert_invalid(lambda t: t['clauses'][1].update(impact=['tenant']), "unknown high-impact category 'tenant'")
        self.assert_invalid(lambda t: t['clauses'][1].update(impact=['payment', 'payment']), "lists 'payment' twice")

    def test_every_clause_has_a_self_acceptance_case(self):
        def drop_anonymous(t):
            t['self_acceptance']['cases'] = [c for c in t['self_acceptance']['cases']
                                             if c['clause'] != 'S2-ANON-NO-ACCESS']
        self.assert_invalid(drop_anonymous, 'S2-ANON-NO-ACCESS')


# The digest of each released template version. A content change without a version bump fails here;
# a bump adds its digest after the new template passes its self-acceptance (TK-REQ-008).
PINNED_DIGESTS = {'1': 'sha256:c2eb783dab99c64a0a125b1940c58f2f6db23b94192fbaeb2ae190343e9fb8ce',
                  '2': 'sha256:2011b4bd70ce6ebacd1a0096e29f3585595f180274f28366d84a3eab461f8109'}


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


class ImpactCategoriesFollowTheSpec(unittest.TestCase):
    """policy.IMPACT_CATEGORIES is the one list of 〈定義：高影響類別〉 codes in the code; it has the codes of
    the spec's table, in its order, so neither can change alone."""

    def test_codes_and_order_match_the_definition_table(self):
        spec = (Path(__file__).resolve().parents[2] / 'docs' / 'toolkit' / 'spec.md').read_text(encoding='utf-8')
        section = spec.split('### 定義：高影響類別', 1)[1].split('\n### ', 1)[0].split('\n#### ', 1)[0]
        codes = re.findall(r'^\| `([a-z_]+)` \|', section, flags=re.M)
        self.assertEqual(codes, ['admin', 'cross_tenant', 'confidential', 'payment', 'third_party_callback'])
        self.assertEqual(list(policy.IMPACT_CATEGORIES), codes)


if __name__ == '__main__':
    unittest.main()
