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

    def test_the_result_says_which_modules_were_loaded(self):
        self.assertEqual(inventory.inventory(sample_files('vulnerable'))['loaded'], ['supabase-rls'])
        self.assertEqual(inventory.inventory(sample_files('vulnerable'), modules=())['loaded'], [])

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


class WhatATestCovers(unittest.TestCase):
    """inventory.covers(inventory, resources, command): the inventoried items a test of those resources and
    that command exercises: each resource as public.<name>, and the policies on it for that command or for all."""

    VULNERABLE = inventory.inventory(sample_files('vulnerable'))

    def covers(self, resources, command, inv=None):
        return inventory.covers(inv or self.VULNERABLE, resources, command)

    def test_an_update_covers_the_table_and_its_update_policy_only(self):
        self.assertEqual(self.covers(['documents'], 'update'),
                         ['public.documents', 'public.documents: tenant members update documents'])

    def test_each_command_covers_the_policies_for_that_command(self):
        self.assertEqual(self.covers(['documents'], 'select'),
                         ['public.documents', 'public.documents: members read documents shared with their tenant',
                          'public.documents: tenant members read documents'])
        self.assertEqual(self.covers(['documents'], 'insert'),
                         ['public.documents', 'public.documents: tenant members create documents'])
        self.assertEqual(self.covers(['documents'], 'delete'),
                         ['public.documents', 'public.documents: tenant members delete documents'])

    def test_a_policy_for_all_commands_is_covered_by_every_command(self):
        inv = inventory.inventory({M: 'create table public.t (id int);\n'
                                      'create policy everything on public.t using (true);\n'
                                      'create policy explicit on public.t for all using (true);\n'
                                      'create policy reads on public.t for select using (true);\n'})
        for command in ('select', 'insert', 'update', 'delete'):
            expected = ['public.t', 'public.t: everything', 'public.t: explicit']
            expected += ['public.t: reads'] if command == 'select' else []
            with self.subTest(command=command):
                self.assertEqual(self.covers(['t'], command, inv), expected)

    def test_several_resources_each_bring_their_own_table_and_policies_without_repeats(self):
        self.assertEqual(self.covers(['announcements', 'tenants', 'announcements'], 'select'),
                         ['public.announcements', 'public.announcements: anyone reads announcements',
                          'public.tenants', 'public.tenants: members read their tenants'])

    def test_a_resource_with_a_schema_is_used_as_written(self):
        inv = inventory.inventory({M: 'create table private.docs (id int);\n'
                                      'create policy p on private.docs for select using (true);\n'})
        self.assertEqual(self.covers(['private.docs'], 'select', inv), ['private.docs', 'private.docs: p'])

    def test_what_is_not_inventoried_is_not_covered(self):
        self.assertEqual(self.covers(['no_such_table'], 'select'), [])
        without_module = inventory.inventory(sample_files('vulnerable'), modules=())
        self.assertEqual(self.covers(['documents'], 'select', without_module), [])


GAP = {'scope': 'identity:tenant_admin', 'reason': 'no such identity in the BuildRecipe (測試身分)'}


class ScopesTheRunAddsAsUnsupported(unittest.TestCase):
    """A run can know scope it cannot test (an identity the BuildRecipe lacks): it joins the unsupported scopes."""

    def test_an_added_scope_is_unsupported_and_listed_after_the_fixed_ones(self):
        result = inventory.inventory(sample_files('vulnerable'), extra_unsupported=[GAP])
        self.assertEqual([i['scope'] for i in result['unsupported_items']], ALWAYS_UNSUPPORTED + ['identity:tenant_admin'])
        self.assertEqual(result['items'][-1], {**GAP, 'state': 'unsupported'})
        self.assertEqual(result['completeness'], 'complete')  # an identity gap is not unresolved content

    def test_the_added_scope_is_kept_without_the_module_too(self):
        result = inventory.inventory(sample_files('vulnerable'), modules=(), extra_unsupported=[GAP])
        self.assertEqual([i['scope'] for i in result['unsupported_items']],
                         ['rls-tables-and-policies'] + ALWAYS_UNSUPPORTED + ['identity:tenant_admin'])

    def test_what_the_caller_passed_is_not_changed(self):
        passed = [dict(GAP)]
        inventory.inventory(sample_files('vulnerable'), extra_unsupported=passed)
        self.assertEqual(passed, [GAP])


class AProjectThatWasNotRead(unittest.TestCase):
    """A run blocked before the source was verified does not read the project: nothing is inventoried and the
    inventory is unknown, not empty and complete."""

    REASON = 'preflight blocked; the project files were not read'

    def test_it_has_no_facts_and_says_why_it_is_unknown(self):
        result = inventory.not_read(self.REASON)
        self.assertEqual((result['facts'], result['completeness'], result['loaded']), ([], 'unknown', ['supabase-rls']))
        self.assertEqual(result['unresolved'], [{'file': '(project)', 'line': 0, 'reason': self.REASON}])
        self.assertEqual([i['scope'] for i in result['items']], ALWAYS_UNSUPPORTED)
        self.assertEqual({i['state'] for i in result['items']}, {'unsupported'})

    def test_it_keeps_the_scopes_the_run_added(self):
        result = inventory.not_read(self.REASON, extra_unsupported=[GAP])
        self.assertEqual(result['items'][-1], {**GAP, 'state': 'unsupported'})


if __name__ == '__main__':
    unittest.main()
