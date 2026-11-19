"""The model review path (#13): which tasks a project gives, and the slice of each, tested through
toolkit.model_review (〈定義：審查任務的單位〉, TK-REV-001, TK-REV-002, TK-REV-003).

Fast tests only. Expected values are written from the samples and the definitions, not derived from the code.
"""
import unittest
from pathlib import Path

from toolkit import extract, inventory, model_review

SAMPLES = Path(__file__).resolve().parents[2] / 'samples' / 'object-authz'
M = 'supabase/migrations/001.sql'


def sample_inventory(version='vulnerable'):
    return inventory.inventory(extract.read_migrations(SAMPLES / version))


def inventory_of(sql):
    return inventory.inventory({M: sql})


ENTRY = {'scope': 'entry', 'ref': 'GET /api/documents', 'state': 'inventoried'}


def with_entries(inv, *entries):
    """The inventory with hand-written entry items: no v0.1 extraction rule finds entries."""
    return {**inv, 'items': [*inv['items'], *entries]}


class TasksOfAProject(unittest.TestCase):
    """TK-REV-001: the tasks follow the inventory; the unit in v0.1 is a table (TK-REV-002, the database task)."""

    def test_the_sample_gives_one_database_task_per_table_in_inventory_order(self):
        tasks = model_review.review_tasks(sample_inventory())
        self.assertEqual([(t['kind'], t['id']) for t in tasks],
                         [('database', f'database:public.{name}') for name in
                          ('tenants', 'memberships', 'documents', 'document_shares', 'announcements')])

    def test_the_sample_has_no_entry_task_because_extraction_finds_no_entry(self):
        self.assertEqual([t for t in model_review.review_tasks(sample_inventory()) if t['kind'] == 'entry'], [])

    def test_an_entry_in_the_inventory_gives_an_entry_task_before_the_database_tasks(self):
        tasks = model_review.review_tasks(with_entries(sample_inventory(), ENTRY))
        self.assertEqual((tasks[0]['kind'], tasks[0]['id'], tasks[0]['unit']), ('entry', 'entry:GET /api/documents', 'GET /api/documents'))
        self.assertEqual(len(tasks), 6)

    def test_each_new_entry_adds_one_task(self):
        """TK-REV-001 acceptance: when the inventory gains an entry, a task for it appears by itself."""
        other = {'scope': 'entry', 'ref': 'POST /api/documents', 'state': 'inventoried'}
        base = model_review.review_tasks(sample_inventory())
        one = model_review.review_tasks(with_entries(sample_inventory(), ENTRY))
        two = model_review.review_tasks(with_entries(sample_inventory(), ENTRY, other))
        self.assertEqual((len(one) - len(base), len(two) - len(one)), (1, 1))

    def test_a_table_gone_from_the_project_loses_its_task(self):
        sql = 'create table public.a (id int);\ncreate table public.b (id int);\n'
        self.assertEqual([t['unit'] for t in model_review.review_tasks(inventory_of(sql))], ['public.a', 'public.b'])
        self.assertEqual([t['unit'] for t in model_review.review_tasks(inventory_of('create table public.a (id int);\n'))],
                         ['public.a'])

    def test_what_extraction_does_not_support_is_not_a_task(self):
        """The unsupported scopes (routes, Server Actions, functions) are listed by the inventory, not reviewed."""
        inv = sample_inventory()
        unsupported = [i for i in inv['items'] if i['state'] == 'unsupported']
        self.assertTrue(unsupported)
        self.assertEqual({t['unit'] for t in model_review.review_tasks(inv)} & {i['scope'] for i in unsupported}, set())

    def test_nothing_is_reviewed_when_nothing_was_inventoried(self):
        self.assertEqual(model_review.review_tasks(inventory.inventory({M: 'create table public.a (id int);'}, modules=())), [])
        self.assertEqual(model_review.review_tasks(inventory.not_read('preflight blocked')), [])


class SliceOfADatabaseTask(unittest.TestCase):
    """TK-REV-003: the slice is assembled from CodeFacts, the same every time, with a digest of its content."""

    DOCUMENTS = ['members read documents shared with their tenant', 'tenant members read documents',
                 'tenant members create documents', 'tenant members update documents', 'tenant members delete documents']

    def slice_of(self, inv, table):
        task = next(t for t in model_review.review_tasks(inv) if t['unit'] == table)
        return model_review.slice_of(task, inv)

    def test_it_holds_the_table_its_security_state_and_its_policies_in_file_order(self):
        s = self.slice_of(sample_inventory(), 'public.documents')
        self.assertEqual((s['task'], s['table'], s['rls_enabled']), ('database:public.documents', 'public.documents', True))
        self.assertEqual([p['name'] for p in s['policies']], self.DOCUMENTS)

    def test_a_policy_keeps_its_command_roles_conditions_as_written_and_source(self):
        s = self.slice_of(sample_inventory(), 'public.documents')
        update = next(p for p in s['policies'] if p['name'] == 'tenant members update documents')
        self.assertEqual((update['permissive'], update['command'], update['roles'], update['with_check']),
                         (True, 'update', ['authenticated'], None))
        self.assertIn('tenant_id in (select tenant_id from public.memberships', update['using'])
        self.assertEqual(update['source'], {'file': 'supabase/migrations/20261031000002_document_policies.sql', 'line': 13})

    def test_restrictive_and_permissive_policies_are_distinguished_in_the_slice_and_its_digest(self):
        perm = inventory_of('create table public.a (id int);\n'
                            'create policy p on public.a as permissive for select using (true);\n')
        rest = inventory_of('create table public.a (id int);\n'
                            'create policy p on public.a as restrictive for select using (true);\n')
        s_perm, s_rest = self.slice_of(perm, 'public.a'), self.slice_of(rest, 'public.a')
        self.assertEqual((s_perm['policies'][0]['permissive'], s_rest['policies'][0]['permissive']), (True, False))
        self.assertNotEqual(s_perm['digest'], s_rest['digest'])

    def test_the_policies_of_other_tables_are_not_in_it(self):
        s = self.slice_of(sample_inventory(), 'public.announcements')
        self.assertEqual([p['name'] for p in s['policies']], ['anyone reads announcements'])

    def test_a_table_without_row_level_security_says_so_and_a_disable_wins(self):
        inv = inventory_of('create table public.a (id int);\ncreate table public.b (id int);\n'
                           'alter table public.b enable row level security;\nalter table public.b disable row level security;\n')
        self.assertEqual((self.slice_of(inv, 'public.a')['rls_enabled'], self.slice_of(inv, 'public.b')['rls_enabled']),
                         (False, False))

    def test_it_names_the_rule_and_version_it_was_assembled_with(self):
        s = self.slice_of(sample_inventory(), 'public.documents')
        self.assertEqual((s['rule'], s['supported_version']), ('sql-rls-v1', 'postgresql-17'))

    def test_unresolved_content_of_any_migration_including_files_without_facts_is_disclosed_in_it(self):
        files = {
            M: 'create table public.a (id int);\n',
            'supabase/migrations/002.sql': 'do $$ begin end $$;\n',
            'supabase/migrations/003.sql': 'drop policy p on public.a;\n',
            'supabase/migrations/004.sql': None,
        }
        inv = inventory.inventory(files)
        reordered = inventory.inventory(dict(reversed(list(files.items()))))
        s, s_rev = self.slice_of(inv, 'public.a'), self.slice_of(reordered, 'public.a')
        self.assertEqual([(u['file'], u['line'], u['reason']) for u in s['unresolved']], [
            ('supabase/migrations/002.sql', 1, 'do block runs SQL that is not read'),
            ('supabase/migrations/003.sql', 1, 'statement changes a table or policy that is not tracked'),
            ('supabase/migrations/004.sql', 0, 'file could not be read'),
        ])
        self.assertEqual((s['unresolved'], s['digest']), (s_rev['unresolved'], s_rev['digest']))
        self.assertEqual(self.slice_of(sample_inventory(), 'public.documents')['unresolved'], [])
        unsorted_unresolved = [
            {'file': 'supabase/migrations/002.sql', 'line': 3, 'reason': 'statement changes a table or policy that is not tracked'},
            {'file': 'supabase/migrations/001.sql', 'line': 5, 'reason': 'table name has no schema'},
            {'file': 'supabase/migrations/001.sql', 'line': 5, 'reason': 'do block runs SQL that is not read'},
        ]
        s_unsorted = self.slice_of({**sample_inventory(), 'unresolved': unsorted_unresolved}, 'public.documents')
        s_reversed = self.slice_of({**sample_inventory(), 'unresolved': list(reversed(unsorted_unresolved))}, 'public.documents')
        self.assertEqual([(u['file'], u['line'], u['reason']) for u in s_unsorted['unresolved']], [
            ('supabase/migrations/001.sql', 5, 'do block runs SQL that is not read'),
            ('supabase/migrations/001.sql', 5, 'table name has no schema'),
            ('supabase/migrations/002.sql', 3, 'statement changes a table or policy that is not tracked'),
        ])
        self.assertEqual(s_unsorted['digest'], s_reversed['digest'])


class TheDigestOfASlice(unittest.TestCase):
    """TK-REV-003 acceptance: assembling the same input twice gives the same digest."""

    def digest(self, inv, table='public.documents'):
        task = next(t for t in model_review.review_tasks(inv) if t['unit'] == table)
        return model_review.slice_of(task, inv)['digest']

    def test_the_same_input_gives_the_same_digest_whatever_the_file_order(self):
        files = extract.read_migrations(SAMPLES / 'vulnerable')
        first = self.digest(inventory.inventory(files))
        self.assertEqual(first, self.digest(inventory.inventory(files)))
        self.assertEqual(first, self.digest(inventory.inventory(dict(reversed(list(files.items()))))))
        self.assertRegex(first, r'^sha256:[0-9a-f]{64}$')

    def test_it_changes_with_the_content_of_the_slice(self):
        patched = self.digest(sample_inventory('patched'))
        self.assertNotEqual(self.digest(sample_inventory('vulnerable')), patched)

    def test_it_does_not_change_with_what_is_not_in_the_slice(self):
        a = inventory_of('create table public.a (id int);\ncreate table public.b (id int);\n'
                         'create policy p on public.b for select using (true);\n')
        b = inventory_of('create table public.a (id int);\ncreate table public.b (id int);\n'
                         'create policy p on public.b for select using (false);\n')
        self.assertEqual(self.digest(a, 'public.a'), self.digest(b, 'public.a'))
        self.assertNotEqual(self.digest(a, 'public.b'), self.digest(b, 'public.b'))

    def test_an_entry_task_has_a_slice_and_a_digest_too(self):
        inv = with_entries(sample_inventory(), ENTRY)
        task = model_review.review_tasks(inv)[0]
        s = model_review.slice_of(task, inv)
        self.assertEqual((s['task'], s['entry']), ('entry:GET /api/documents', 'GET /api/documents'))
        self.assertEqual(s['digest'], model_review.slice_of(task, inv)['digest'])


class SliceGuards(unittest.TestCase):
    """TK-DAT-007, 〈定義：審查任務的單位〉: slice_of() refuses non-CodeFact records in the inventory."""

    def test_slice_of_refuses_an_inventory_containing_non_codefact_records(self):
        base = sample_inventory()
        db_task = next(t for t in model_review.review_tasks(base) if t['unit'] == 'public.documents')
        entry_inv = with_entries(base, ENTRY)
        entry_task = model_review.review_tasks(entry_inv)[0]
        valid_fact = dict(base['facts'][0])
        policy_fact = dict(next(f for f in base['facts'] if f['kind'] == 'policy' and f['table'] == 'public.documents'))
        without_command = {k: v for k, v in policy_fact.items() if k != 'command'}
        bad_records = [
            ('not a dict', 'CodeFact must be an object'),
            ({**valid_fact, 'method': 'model:claude'}, "method 'model:claude' is not a registered extraction rule"),
            ({**valid_fact, 'confidence': 0.9}, "field 'confidence' is not part of an extracted"),
            ({'kind': 'threat', 'source': {'file': M, 'line': 1}, 'method': 'sql-rls-v1',
              'supported_version': 'postgresql-17'}, "kind 'threat' is not extracted"),
            ({**valid_fact, 'source': None}, 'source needs a file and an integer line'),
            ({**valid_fact, 'source': {'file': M, 'line': 0}}, 'source needs a file and an integer line'),
            (without_command, "missing field 'command'"),
            ({**policy_fact, 'permissive': 'yes'}, "field 'permissive'"),
            ({**policy_fact, 'command': 'truncate'}, "field 'command'"),
            ({**valid_fact, 'name': 'unqualified'}, "field 'name'"),
            ({**valid_fact, 'kind': ['table']}, "kind \\['table'\\] is not extracted"),
            ({**valid_fact, 'source': {'file': M, 'line': 1, 'confidence': 0.9}}, "source field 'confidence'"),
        ]
        for forged, reason in bad_records:
            for task, inv in ((db_task, base), (entry_task, entry_inv)):
                with self.subTest(kind=task['kind'], reason=reason):
                    tainted = {**inv, 'facts': [*inv['facts'], forged]}
                    with self.assertRaisesRegex(ValueError, reason):
                        model_review.slice_of(task, tainted)
        quoted_dots = inventory_of('create table public."t." (id int);\n')
        self.assertEqual(model_review.slice_of(model_review.review_tasks(quoted_dots)[0], quoted_dots)['table'],
                         'public.t.')

    def test_slice_of_refuses_an_unknown_task_kind(self):
        inv = sample_inventory()
        for bad_kind in ('storage', 'middleware', 'db', '', None):
            with self.subTest(kind=bad_kind):
                with self.assertRaisesRegex(ValueError, 'task kind'):
                    model_review.slice_of({'kind': bad_kind, 'id': 'x:1', 'unit': 'public.documents'}, inv)
        for bad_task in ({'id': 'x:1', 'unit': 'public.documents'}, None, 'database:public.documents'):
            with self.subTest(task=bad_task):
                with self.assertRaisesRegex(ValueError, 'task kind'):
                    model_review.slice_of(bad_task, inv)


if __name__ == '__main__':
    unittest.main()
