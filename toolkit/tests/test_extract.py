"""Deterministic extraction of tables, row level security and policies from SQL migrations (〈定義：擷取結果〉,
TK-ARC-004, rule sql-rls-v1), tested through toolkit.extract.extract_facts(files).

Fast tests only. Expected values are written from the samples and the definition, not derived from the code.
`files` maps a project-relative path to its text, as a snapshot does for the docs checks.
"""
import unittest
from pathlib import Path

from toolkit import extract

SAMPLES = Path(__file__).resolve().parents[2] / 'samples' / 'object-authz'
SAMPLE_VERSIONS = ('vulnerable', 'patched', 'legit', 'lax-update-policy')
SCHEMA = 'supabase/migrations/20261031000001_schema.sql'
DOCUMENT_POLICIES = 'supabase/migrations/20261031000002_document_policies.sql'
TABLES = ['public.announcements', 'public.document_shares', 'public.documents', 'public.memberships',
          'public.tenants']


def sample_files(version):
    """The sample's SQL migrations as the extractor receives them: project-relative path -> text."""
    return {path.relative_to(SAMPLES / version).as_posix(): path.read_text(encoding='utf-8')
            for path in sorted((SAMPLES / version / 'supabase' / 'migrations').glob('*.sql'))}


def of_kind(result, kind):
    return [f for f in result['facts'] if f['kind'] == kind]


class TablesOfTheSamples(unittest.TestCase):
    def test_every_sample_has_the_same_five_tables_with_their_source_lines(self):
        for version in SAMPLE_VERSIONS:
            with self.subTest(sample=version):
                tables = of_kind(extract.extract_facts(sample_files(version)), 'table')
                self.assertEqual(sorted(t['name'] for t in tables), TABLES)
        by_name = {t['name']: t['source'] for t in of_kind(extract.extract_facts(sample_files('vulnerable')), 'table')}
        self.assertEqual(by_name['public.tenants'], {'file': SCHEMA, 'line': 3})
        self.assertEqual(by_name['public.memberships'], {'file': SCHEMA, 'line': 8})
        self.assertEqual(by_name['public.documents'], {'file': SCHEMA, 'line': 15})
        self.assertEqual(by_name['public.document_shares'], {'file': SCHEMA, 'line': 42})
        self.assertEqual(by_name['public.announcements'], {'file': SCHEMA, 'line': 61})


class RowLevelSecurityOfTheSamples(unittest.TestCase):
    def test_every_sample_enables_it_on_all_five_tables_at_these_lines(self):
        for version in SAMPLE_VERSIONS:
            with self.subTest(sample=version):
                rls = of_kind(extract.extract_facts(sample_files(version)), 'rls')
                self.assertEqual(sorted((f['table'], f['enabled'], f['source']['line']) for f in rls),
                                 [('public.announcements', True, 67), ('public.document_shares', True, 48),
                                  ('public.documents', True, 26), ('public.memberships', True, 25),
                                  ('public.tenants', True, 24)])
                self.assertEqual({f['source']['file'] for f in rls}, {SCHEMA})


SCHEMA_POLICIES = ['members read their tenants', 'users read their memberships', "members read their tenants' shares",
                   'members read documents shared with their tenant', 'anyone reads announcements']
DOCUMENT_POLICY_NAMES = {
    'vulnerable': ['tenant members read documents', 'tenant members create documents',
                   'tenant members update documents', 'tenant members delete documents'],
    'patched': ['owners read documents', 'members create own documents', 'owners update documents',
                'owners delete documents'],
    'legit': ['owners read documents', 'tenant members read shared documents', 'members create own documents',
              'owners update documents', 'owners delete documents'],
    # Its file header mentions CREATE POLICY in a comment; that is not a policy.
    'lax-update-policy': ['owners read documents', 'members create own documents', 'tenant members update documents',
                          'owners delete documents'],
}


def policies(version):
    return of_kind(extract.extract_facts(sample_files(version)), 'policy')


class PoliciesOfTheSamples(unittest.TestCase):
    def test_each_sample_has_its_policies_by_name_and_table(self):
        for version in SAMPLE_VERSIONS:
            with self.subTest(sample=version):
                found = policies(version)
                self.assertEqual(sorted(f['name'] for f in found if f['source']['file'] == SCHEMA),
                                 sorted(SCHEMA_POLICIES))
                self.assertEqual([f['name'] for f in found if f['source']['file'] == DOCUMENT_POLICIES],
                                 DOCUMENT_POLICY_NAMES[version])
                self.assertEqual({f['table'] for f in found if f['source']['file'] == DOCUMENT_POLICIES},
                                 {'public.documents'})
        self.assertEqual([len(policies(v)) for v in SAMPLE_VERSIONS], [9, 9, 10, 9])

    def test_source_lines(self):
        found = policies('vulnerable')
        self.assertEqual([(f['name'], f['source']['line']) for f in found if f['source']['file'] == SCHEMA],
                         [('members read their tenants', 31), ('users read their memberships', 35),
                          ("members read their tenants' shares", 51),
                          ('members read documents shared with their tenant', 55), ('anyone reads announcements', 70)])
        self.assertEqual([f['source']['line'] for f in found if f['source']['file'] == DOCUMENT_POLICIES],
                         [4, 8, 13, 17])

    def test_command_roles_and_conditions(self):
        by_name = {f['name']: f for f in policies('vulnerable')}
        update = by_name['tenant members update documents']
        self.assertEqual((update['command'], update['roles']), ('update', ['authenticated']))
        self.assertIsNotNone(update['using'])
        self.assertIsNone(update['with_check'])  # the vulnerable policy has no WITH CHECK
        create = by_name['tenant members create documents']
        self.assertEqual(create['command'], 'insert')
        self.assertIsNone(create['using'])
        self.assertIn('owner_id = auth.uid()', create['with_check'])
        announcements = by_name['anyone reads announcements']
        self.assertEqual((announcements['roles'], announcements['using']), (['anon', 'authenticated'], 'true'))
        lax = {f['name']: f for f in policies('lax-update-policy')}['tenant members update documents']
        self.assertIsNotNone(lax['with_check'])  # the lax sample does check on update


M = 'supabase/migrations/001.sql'


def facts_of(sql, path=M):
    return extract.extract_facts({path: sql})


def names(result, kind):
    return [f.get('name') or f['table'] for f in of_kind(result, kind)]


class NothingUnresolvedInTheSamples(unittest.TestCase):
    def test_the_samples_are_fully_resolved(self):
        for version in SAMPLE_VERSIONS:
            with self.subTest(sample=version):
                self.assertEqual(extract.extract_facts(sample_files(version))['unresolved'], [])


class WhatIsNotAStatement(unittest.TestCase):
    def test_comments_and_strings_are_not_extracted(self):
        result = facts_of("-- create table public.a (id int);\n/* create table public.b (id int);\n"
                          "alter table public.b enable row level security; */\n"
                          "select 'create table public.c (id int);';\ncreate table public.real (id int);\n")
        self.assertEqual(names(result, 'table'), ['public.real'])
        self.assertEqual(of_kind(result, 'rls'), [])
        self.assertEqual(of_kind(result, 'table')[0]['source']['line'], 5)

    def test_a_function_body_is_not_extracted_and_does_not_split_the_file(self):
        result = facts_of("create function public.f() returns void language plpgsql as $body$\n"
                          "begin\nperform 1;\ncreate table public.hidden (id int);\nend\n$body$;\n"
                          "create table public.after_it (id int);\n")
        self.assertEqual(names(result, 'table'), ['public.after_it'])
        self.assertEqual([u['line'] for u in result['unresolved']], [1])  # it creates a table: listed, not read

    def test_case_and_quoting_follow_postgresql(self):
        result = facts_of('CREATE TABLE Public.Tenants (id int);\n'
                          'create policy "Mixed Case" on public."Docs" for SELECT to "Anon", Authenticated using (true);\n')
        self.assertEqual(names(result, 'table'), ['public.tenants'])
        policy = of_kind(result, 'policy')[0]
        self.assertEqual((policy['name'], policy['table'], policy['command'], policy['roles']),
                         ('Mixed Case', 'public.Docs', 'select', ['Anon', 'authenticated']))

    def test_only_migrations_are_read(self):
        result = extract.extract_facts({'supabase/seed.sql': 'create table public.seed (id int);',
                                        'src/app.ts': 'create table public.x (id int);'})
        self.assertEqual((result['facts'], result['unresolved']), ([], []))

    def test_the_result_does_not_depend_on_the_order_of_the_files(self):
        files = {'supabase/migrations/002.sql': 'create table public.b (id int);',
                 'supabase/migrations/001.sql': 'create table public.a (id int);\ncreate table public.c (id int);'}
        reordered = dict(reversed(list(files.items())))
        self.assertEqual(extract.extract_facts(files), extract.extract_facts(reordered))
        self.assertEqual([(f['source']['file'][-7:], f['source']['line']) for f in extract.extract_facts(files)['facts']],
                         [('001.sql', 1), ('001.sql', 2), ('002.sql', 1)])


class UnresolvedContentIsListedNotDropped(unittest.TestCase):
    """TK-ARC-004: what cannot be resolved is reported with its file, line and reason, never taken as absent."""

    def unresolved(self, sql):
        return facts_of(sql)['unresolved']

    def test_a_do_block_is_unresolved(self):
        self.assertEqual(self.unresolved("select 1;\ndo $$ begin execute 'create table public.t (id int)'; end $$;\n"),
                         [{'file': M, 'line': 2, 'reason': 'do block runs SQL that is not read'}])

    def test_a_table_without_a_schema_is_unresolved(self):
        result = facts_of('create table tenants (id int);\nalter table tenants enable row level security;\n'
                          'create policy p on tenants using (true);\n')
        self.assertEqual(result['facts'], [])
        self.assertEqual([(u['line'], u['reason']) for u in result['unresolved']],
                         [(1, 'table name has no schema'), (2, 'table name has no schema'),
                          (3, 'table name has no schema')])

    def test_statements_that_change_tables_or_policies_are_unresolved(self):
        for sql in ('drop table public.t;', 'drop policy p on public.t;', 'alter policy p on public.t using (true);',
                    'alter table public.t rename to u;', 'alter table public.t force row level security;',
                    'alter table public.t no force row level security;', 'alter table public.t rename column a to b;'):
            with self.subTest(sql=sql):
                self.assertEqual(self.unresolved(sql),
                                 [{'file': M, 'line': 1, 'reason': 'statement changes a table or policy that is not tracked'}])

    def test_a_policy_that_cannot_be_read_is_unresolved(self):
        self.assertEqual(self.unresolved('create policy p;'),
                         [{'file': M, 'line': 1, 'reason': 'policy statement not understood'}])

    def test_unrelated_statements_are_not_unresolved(self):
        sql = ("create extension if not exists pgcrypto;\ninsert into public.t values (1);\ngrant select on public.t to anon;\n"
               "alter table public.t add column c int;\ncreate index i on public.t (c);\ncreate view public.v as select 1;\n")
        self.assertEqual(self.unresolved(sql), [])

    def test_an_unterminated_string_or_comment_hides_the_rest_of_the_file(self):
        for sql in ("create table public.a (id int);\nselect 'never closed;\ncreate table public.b (id int);\n",
                    "create table public.a (id int);\n/* never closed\ncreate table public.b (id int);\n",
                    "create table public.a (id int);\ndo $x$ never closed;\ncreate table public.b (id int);\n"):
            with self.subTest(sql=sql):
                result = facts_of(sql)
                self.assertEqual(names(result, 'table'), ['public.a'])
                self.assertEqual(result['unresolved'],
                                 [{'file': M, 'line': 2, 'reason': 'string, comment or $-quote is never closed'}])

    def test_a_file_that_cannot_be_read_is_unresolved(self):
        result = extract.extract_facts({M: None})
        self.assertEqual(result['unresolved'], [{'file': M, 'line': 0, 'reason': 'file could not be read'}])


class OnlyExtractionMakesACodeFact(unittest.TestCase):
    """TK-DAT-007: what a model proposed or an observation showed cannot be written as a CodeFact."""

    POLICY = {'kind': 'policy', 'name': 'p', 'table': 'public.t', 'command': 'select', 'roles': ['anon'],
              'using': 'true', 'with_check': None, 'source': {'file': M, 'line': 3}, 'method': 'sql-rls-v1',
              'supported_version': 'postgresql-17'}

    def test_every_fact_extracted_from_the_samples_is_a_code_fact(self):
        for version in SAMPLE_VERSIONS:
            with self.subTest(sample=version):
                for fact in extract.extract_facts(sample_files(version))['facts']:
                    self.assertEqual(extract.codefact_problems(fact), [], fact)

    def test_a_method_that_is_not_a_registered_extraction_rule_is_refused(self):
        for method in ('model:claude', 'inferred', 'observation', 'sql-rls-v2', None):
            with self.subTest(method=method):
                self.assertEqual(extract.codefact_problems({**self.POLICY, 'method': method}),
                                 [f'method {method!r} is not a registered extraction rule'])

    def test_a_field_that_only_a_model_or_an_observation_has_is_refused(self):
        for field in ('confidence', 'rationale', 'model', 'observation_ref', 'execution_ref', 'inferred'):
            with self.subTest(field=field):
                self.assertEqual(extract.codefact_problems({**self.POLICY, field: 'x'}),
                                 [f'field {field!r} is not part of an extracted policy fact'])

    def test_a_kind_extraction_does_not_produce_is_refused(self):
        self.assertEqual(extract.codefact_problems({**self.POLICY, 'kind': 'threat'}),
                         ["kind 'threat' is not extracted by sql-rls-v1"])

    def test_a_fact_without_a_source_location_is_refused(self):
        for source in (None, {}, {'file': M}, {'file': '', 'line': 3}, {'file': M, 'line': 'three'}):
            with self.subTest(source=source):
                self.assertEqual(extract.codefact_problems({**self.POLICY, 'source': source}),
                                 ['source needs a file and an integer line'])


class NestedBlockComments(unittest.TestCase):
    """PostgreSQL block comments nest: /* outer /* inner */ still a comment */ is one comment."""

    def test_what_follows_a_nested_comment_is_still_read(self):
        result = facts_of("/* outer /* inner */ still a comment */\ncreate table public.after (id int);\n")
        self.assertEqual([(f['name'], f['source']['line']) for f in of_kind(result, 'table')], [('public.after', 2)])
        self.assertEqual(result['unresolved'], [])

    def test_nothing_inside_a_nested_comment_is_extracted_and_lines_still_count(self):
        result = facts_of("select 1;\n/* a\n/* create table public.hidden (id int);\n*/\ncreate table public.hidden2 (id int);\n*/\n"
                          "create table public.shown (id int);\n")
        self.assertEqual([(f['name'], f['source']['line']) for f in of_kind(result, 'table')], [('public.shown', 7)])

    def test_a_nested_comment_that_is_never_closed_is_unresolved_from_its_start(self):
        result = facts_of("create table public.a (id int);\n/* outer /* inner */ never closed\ncreate table public.b (id int);\n")
        self.assertEqual(names(result, 'table'), ['public.a'])
        self.assertEqual(result['unresolved'],
                         [{'file': M, 'line': 2, 'reason': 'string, comment or $-quote is never closed'}])


class PoliciesThatCannotBeRead(unittest.TestCase):
    """TK-ARC-004: a policy that cannot be read is listed as unresolved; it never stops the extraction or vanishes."""

    NOT_UNDERSTOOD = 'policy statement not understood'

    def assert_unresolved_and_the_rest_still_read(self, policy):
        result = facts_of(f'create table public.a (id int);\n{policy};\ncreate table public.b (id int);\n')
        self.assertEqual(names(result, 'table'), ['public.a', 'public.b'])
        self.assertEqual(of_kind(result, 'policy'), [])
        self.assertEqual(result['unresolved'], [{'file': M, 'line': 2, 'reason': self.NOT_UNDERSTOOD}])

    def test_a_condition_whose_parenthesis_is_never_closed(self):
        for policy in ('create policy p on public.a using (true', 'create policy p on public.a with check (id = 1',
                       'create policy p on public.a using (true) with check (id = (1'):
            with self.subTest(policy=policy):
                self.assert_unresolved_and_the_rest_still_read(policy)

    def test_a_parenthesis_closed_twice(self):
        self.assert_unresolved_and_the_rest_still_read('create policy p on public.a using (true))')

    def test_a_condition_without_parentheses(self):
        for policy in ('create policy p on public.a using true', 'create policy p on public.a with check id = 1'):
            with self.subTest(policy=policy):
                self.assert_unresolved_and_the_rest_still_read(policy)

    def test_parentheses_inside_strings_and_quoted_names_do_not_count(self):
        result = facts_of("create policy \"odd (name\" on public.a for select using (title = ')' and body <> '(');\n")
        policy = of_kind(result, 'policy')[0]
        self.assertEqual((policy['name'], policy['using']), ('odd (name', "title = ')' and body <> '('"))
        self.assertEqual(result['unresolved'], [])


class EscapedAndPlainStrings(unittest.TestCase):
    """E'...' strings take backslash escapes; ordinary strings do not (standard_conforming_strings is on)."""

    AFTER = [('public.after', 2)]

    def tables(self, sql):
        result = facts_of(sql)
        return [(f['name'], f['source']['line']) for f in of_kind(result, 'table')], result['unresolved']

    def test_a_backslash_escaped_quote_does_not_end_an_E_string(self):
        for string in ("E'it\\'s;'", "e'it\\'s;'", "E'a\\\\'", "E'say ''hi'';'"):
            with self.subTest(string=string):
                self.assertEqual(self.tables(f'select {string};\ncreate table public.after (id int);\n'),
                                 (self.AFTER, []))

    def test_a_backslash_in_an_ordinary_string_is_just_a_character(self):
        self.assertEqual(self.tables("select 'a\\';\ncreate table public.after (id int);\n"), (self.AFTER, []))

    def test_an_e_that_ends_a_word_does_not_make_the_string_an_E_string(self):
        self.assertEqual(self.tables("select name_e'x\\';\ncreate table public.after (id int);\n"), (self.AFTER, []))

    def test_an_E_string_that_is_never_closed_is_unresolved(self):
        tables, unresolved = self.tables("create table public.a (id int);\nselect E'never closed\\';\n"
                                         "create table public.b (id int);\n")
        self.assertEqual(tables, [('public.a', 1)])
        self.assertEqual(unresolved, [{'file': M, 'line': 2, 'reason': 'string, comment or $-quote is never closed'}])


class FunctionsThatMayChangeTablesOrPolicies(unittest.TestCase):
    """〈定義：擷取結果〉: a function or procedure body is not read; it is unresolved only when it mentions
    create table, create policy or row level security, so the inventory cannot be called complete."""

    REASON = 'function or procedure body may change tables or policies and is not read'

    def unresolved_of(self, sql):
        return facts_of(sql)['unresolved']

    def test_a_body_that_mentions_one_of_the_three_is_unresolved_at_the_line_of_the_statement(self):
        for body in ('create table public.t (id int)', 'CREATE  POLICY p ON public.t USING (true)',
                     'alter table public.t enable ROW LEVEL SECURITY', 'create\ntable public.t (id int)'):
            for head in ('create function public.f() returns void language plpgsql as',
                         'create or replace function public.f() returns void language plpgsql as',
                         'create procedure public.p() language plpgsql as'):
                with self.subTest(head=head, body=body):
                    self.assertEqual(self.unresolved_of(f'select 1;\n{head} $$ begin {body}; end $$;\n'),
                                     [{'file': M, 'line': 2, 'reason': self.REASON}])

    def test_a_quoted_body_counts_like_a_dollar_quoted_one(self):
        sql = "create function public.f() returns void language sql as 'create table public.t (id int)';\n"
        self.assertEqual(self.unresolved_of(sql), [{'file': M, 'line': 1, 'reason': self.REASON}])

    def test_a_function_that_mentions_none_of_the_three_is_not_unresolved_and_adds_nothing(self):
        result = facts_of("create function public.f() returns int language sql as $$ select 1 $$;\n"
                          "create function public.g() returns trigger language plpgsql as $$\n"
                          "begin new.updated_at = now(); return new; end $$;\n")
        self.assertEqual((result['facts'], result['unresolved']), ([], []))

    def test_the_rest_of_the_file_is_still_read(self):
        result = facts_of("create function public.f() returns void language plpgsql as $$ begin "
                          "create table public.hidden (id int); end $$;\ncreate table public.shown (id int);\n")
        self.assertEqual(names(result, 'table'), ['public.shown'])
        self.assertEqual(len(result['unresolved']), 1)


class EveryFactNamesTheVersionItSupports(unittest.TestCase):
    """〈定義：擷取結果〉: each CodeFact carries the PostgreSQL major version its rule was written for."""

    def test_every_extracted_fact_carries_it(self):
        for version in SAMPLE_VERSIONS:
            facts = extract.extract_facts(sample_files(version))['facts']
            self.assertTrue(facts)
            self.assertEqual({f['supported_version'] for f in facts}, {'postgresql-17'})

    def test_it_is_the_postgresql_major_version_of_the_support_matrix(self):
        import json
        matrix = json.loads((SAMPLES.parents[1] / 'toolkit' / 'support-matrix.json').read_text(encoding='utf-8'))
        image = matrix['services']['db']['image']  # e.g. public.ecr.aws/supabase/postgres:17.11.0.006
        self.assertEqual('postgresql-' + image.rsplit(':', 1)[1].split('.')[0], extract.SUPPORTED_VERSION)

    def test_a_fact_without_it_or_with_another_is_not_a_code_fact(self):
        policy = OnlyExtractionMakesACodeFact.POLICY
        without = {k: v for k, v in policy.items() if k != 'supported_version'}
        self.assertEqual(extract.codefact_problems(without), ["supported_version None is not 'postgresql-17'"])
        self.assertEqual(extract.codefact_problems({**policy, 'supported_version': 'postgresql-9'}),
                         ["supported_version 'postgresql-9' is not 'postgresql-17'"])


if __name__ == '__main__':
    unittest.main()
