"""The inventory of a project: what extraction found plus what no loaded framework module can see
(〈定義：框架模組〉, 〈定義：擷取結果〉, TK-SCP-006, TK-ARC-004), tested through toolkit.inventory.inventory(files, modules).

Fast tests only. Expected values are written from the samples and the definitions, not derived from the code.
"""
import unittest
from pathlib import Path

from toolkit import inventory
from toolkit.tests.test_extract import M, SAMPLE_VERSIONS, facts_of, sample_files  # noqa: F401

REPO = Path(__file__).resolve().parents[2]
# What no v0.1 module can see, in the order the inventory lists it (〈定義：框架模組〉 已知限制 and the Next.js surfaces).
ALWAYS_UNSUPPORTED = ['rls-functions', 'rls-views', 'rls-column-privileges', 'nextjs-routes', 'nextjs-server-actions']


def states(result):
    return [(i['scope'], i['state']) for i in result['items']]


class WithTheModuleLoaded(unittest.TestCase):
    def test_the_inventory_of_each_sample_lists_its_tables_and_policies_and_what_cannot_be_seen(self):
        for version, policies in zip(SAMPLE_VERSIONS, (9, 9, 10, 9)):
            with self.subTest(sample=version):
                result = inventory.inventory(sample_files(version), modules=('supabase-rls',))
                inventoried = [i for i in result['items'] if i['state'] == 'inventoried']
                self.assertEqual(sum(i['scope'] == 'rls-table' for i in inventoried), 5)
                self.assertEqual(sum(i['scope'] == 'rls-policy' for i in inventoried), policies)
                self.assertEqual([i['scope'] for i in result['items'] if i['state'] == 'unsupported'], ALWAYS_UNSUPPORTED)
                self.assertEqual(len(result['items']), 5 + policies + 5)  # the denominator the inventory gives
                self.assertEqual(result['completeness'], 'complete')

    def test_an_item_names_what_it_is(self):
        result = inventory.inventory(sample_files('vulnerable'), modules=('supabase-rls',))
        refs = {(i['scope'], i['ref']) for i in result['items'] if i['state'] == 'inventoried'}
        self.assertIn(('rls-table', 'public.documents'), refs)
        self.assertIn(('rls-policy', 'public.documents: tenant members update documents'), refs)


class WithoutTheModule(unittest.TestCase):
    """TK-SCP-006: no module loaded means the capability is unsupported, and coverage does not rise."""

    def test_nothing_is_inventoried_and_the_capability_is_listed_as_unsupported(self):
        for version in SAMPLE_VERSIONS:
            with self.subTest(sample=version):
                result = inventory.inventory(sample_files(version), modules=())
                self.assertEqual(result['facts'], [])
                self.assertEqual([i for i in result['items'] if i['state'] == 'inventoried'], [])
                self.assertEqual(states(result), [('rls-tables-and-policies', 'unsupported')]
                                 + [(s, 'unsupported') for s in ALWAYS_UNSUPPORTED])
                self.assertEqual(result['items'][0]['reason'], 'framework module not loaded')

    def test_what_was_unsupported_with_the_module_is_still_in_the_inventory_without_it(self):
        with_module = inventory.inventory(sample_files('vulnerable'))
        without_module = inventory.inventory(sample_files('vulnerable'), modules=())
        kept = {i['scope'] for i in without_module['items']}
        self.assertTrue({i['scope'] for i in with_module['items'] if i['state'] == 'unsupported'} <= kept)
        self.assertEqual(len(without_module['unsupported_items']), len(with_module['unsupported_items']) + 1)

    def test_an_inventory_without_the_module_is_not_complete(self):
        self.assertEqual(inventory.inventory(sample_files('vulnerable'), modules=())['completeness'], 'unknown')


class RoutesAndServerActionsNeedSupplementaryObservation(unittest.TestCase):
    """TK-ARC-004: what cannot be resolved is not taken as absent; no v0.1 module resolves Next.js."""

    def test_they_are_unsupported_and_marked_in_every_inventory(self):
        for modules in (('supabase-rls',), ()):
            with self.subTest(modules=modules):
                result = inventory.inventory(sample_files('vulnerable'), modules=modules)
                marked = [i for i in result['unsupported_items'] if i.get('needs_supplement')]
                self.assertEqual([i['scope'] for i in marked], ['nextjs-routes', 'nextjs-server-actions'])
                self.assertTrue(all('framework module not loaded' in i['reason'] for i in marked))
                self.assertTrue(all('supplementary observation' in i['reason'] for i in marked))

    def test_the_known_limits_of_the_module_are_not_marked_for_supplementary_observation(self):
        result = inventory.inventory(sample_files('vulnerable'))
        limits = [i for i in result['unsupported_items'] if i['scope'].startswith('rls-')]
        self.assertEqual([i['scope'] for i in limits], ['rls-functions', 'rls-views', 'rls-column-privileges'])
        self.assertFalse(any(i.get('needs_supplement') for i in limits))


class TheModuleDeclaresWhatTK_SCP_006Asks(unittest.TestCase):
    """TK-SCP-006: version, recognizable structure, evidence, test templates, judges, limits, self-acceptance."""

    DECLARATION = inventory.MODULES['supabase-rls']

    def test_the_seven_declarations(self):
        d = self.DECLARATION
        self.assertEqual(d['versions'], ['sql-rls-v1'])
        self.assertEqual(d['structures'], ['supabase/migrations/*.sql'])
        self.assertEqual(d['evidence'], ['migration file text'])
        self.assertEqual(d['templates'], ['nextjs-supabase-object-authz'])
        self.assertEqual(d['judges'], ['denial cases and allowed cases (spec chapter 7)'])
        self.assertEqual([u['scope'] for u in d['limitations']], ['rls-functions', 'rls-views', 'rls-column-privileges'])
        self.assertEqual(d['self_acceptance'], [f'samples/object-authz/{v}' for v in SAMPLE_VERSIONS])

    def test_what_it_declares_exists(self):
        for template in self.DECLARATION['templates']:
            self.assertTrue((REPO / 'toolkit' / 'policy-templates' / f'{template}.json').is_file(), template)
        for sample in self.DECLARATION['self_acceptance']:
            self.assertTrue((REPO / sample / 'supabase' / 'migrations').is_dir(), sample)
        self.assertEqual(self.DECLARATION['versions'], [inventory.extract.RULE])

    def test_the_specification_declares_the_same(self):
        spec = (REPO / 'docs' / 'toolkit' / 'spec.md').read_text(encoding='utf-8')
        section = spec.split('### 定義：框架模組', 1)[1].split('\n### ', 1)[0].split('\n#### ', 1)[0]
        for declared in ('supabase-rls', 'sql-rls-v1', 'supabase/migrations/*.sql', 'nextjs-supabase-object-authz',
                         'samples/object-authz'):
            self.assertIn(declared, section)


class UnresolvedContentMakesTheInventoryIncomplete(unittest.TestCase):
    def test_a_do_block_leaves_the_inventory_unknown_and_is_not_dropped(self):
        result = inventory.inventory({M: 'create table public.a (id int);\ndo $$ begin end $$;\n'})
        self.assertEqual(result['completeness'], 'unknown')
        self.assertEqual([u['line'] for u in result['unresolved']], [2])
        self.assertEqual([i['ref'] for i in result['items'] if i['scope'] == 'rls-table'], ['public.a'])


if __name__ == '__main__':
    unittest.main()
