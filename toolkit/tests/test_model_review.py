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
        self.assertEqual((update['command'], update['roles'], update['with_check']), ('update', ['authenticated'], None))
        self.assertIn('tenant_id in (select tenant_id from public.memberships', update['using'])
        self.assertEqual(update['source'], {'file': 'supabase/migrations/20261031000002_document_policies.sql', 'line': 13})

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

    def test_unresolved_content_of_its_source_files_is_disclosed_in_it(self):
        sql = 'create table public.a (id int);\ndo $$ begin end $$;\n'
        inv = inventory.inventory({M: sql, 'supabase/migrations/002.sql': 'create table public.b (id int);\ndo $$ begin end $$;\n'})
        s = self.slice_of(inv, 'public.a')
        self.assertEqual([(u['file'], u['line']) for u in s['unresolved']], [(M, 2)])  # not the other file's


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


if __name__ == '__main__':
    unittest.main()
