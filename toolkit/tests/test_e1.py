"""E1 environment module, tested through its interface: prepare / reset / destroy.

Fast tests need no Docker. Environment tests (class names ending in Env) start a
real local Supabase stack and are skipped unless MAZ_ENV_TESTS=1.

  python3 -m unittest discover -s toolkit/tests -t .
"""
import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

from toolkit import e1

REPO = Path(__file__).resolve().parents[2]
SAMPLES = REPO / 'samples' / 'object-authz'
ENV_TESTS = os.environ.get('MAZ_ENV_TESTS') == '1'
needs_env = unittest.skipUnless(ENV_TESTS, 'environment test: set MAZ_ENV_TESTS=1 (starts a real Supabase stack)')

# 〈TK-IDN-001〉 說明: v0.1 identities for object-level authorization.
V01_IDENTITIES = {'anonymous', 'owner', 'same_tenant_non_owner', 'other_tenant_user'}


def published_bindings(project_id):
    """(host IP, host port) of every published port of the project's containers, read from Docker."""
    import subprocess
    names = subprocess.run(['docker', 'ps', '--format', '{{.Names}}'], capture_output=True, text=True).stdout.split()
    out = []
    for name in (n for n in names if n.endswith('_' + project_id)):
        inspect = subprocess.run(['docker', 'inspect', '--format', '{{json .NetworkSettings.Ports}}', name],
                                 capture_output=True, text=True).stdout
        for bindings in (json.loads(inspect) or {}).values():
            out += [(b['HostIp'], b['HostPort']) for b in bindings or []]
    return out


# 〈定義：建置配方最低內容〉 (spec.md): the six steps, and for each the settings
# named in the table's 「必要設定與驗證」 column.
STEPS = {
    'source_build': ['source_digest',     # 固定提交
                     'lockfiles',         # 依賴鎖定
                     'tools',             # 可信工具來源
                     'build_commands',    # 建置命令
                     'resources',         # 所需資源
                     'download_policy'],  # 下載政策
    'service_init': ['services',          # 啟動順序、版本、相依服務
                     'migrations',        # 資料庫遷移
                     'extensions'],       # 必要擴充
    'test_data': ['seed',                 # 初始狀態
                  'tenants', 'accounts', 'roles', 'sharing_exceptions',
                  'related_resources', 'markers'],
    'auth': ['identities',                # 專用測試身分
             'token_transport',           # Cookie／標頭傳遞
             'token_refresh',             # 權杖取得與更新
             'expiry_revocation_check'],  # 過期與撤銷檢查
    'health': ['services_up',             # 應用、資料庫及背景服務可用
               'legit_operations'],       # 合法業務操作可完成
    'snapshot_reset': ['seed_version',    # 遷移與種子版本
                       'reset_scope',     # 可復原範圍
                       'reset_check',     # 重置後驗證
                       'cleanup'],        # 清理與銷毀
}


def write_recipe(d, recipe):
    (Path(d) / e1.RECIPE_FILE).write_text(json.dumps(recipe), encoding='utf-8')


def full_recipe():
    return {step: {field: 'x' for field in fields} for step, fields in STEPS.items()}


class RecipeRequired(unittest.TestCase):
    def test_project_without_recipe_is_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            result = e1.prepare(Path(d))
        self.assertIsInstance(result, e1.Blocked)
        self.assertEqual(result.step, 'recipe')
        self.assertIn('BuildRecipe', result.reason)

    def test_recipe_missing_a_step_is_blocked_before_start(self):
        for step in STEPS:
            with self.subTest(step=step), tempfile.TemporaryDirectory() as d:
                recipe = full_recipe()
                del recipe[step]
                write_recipe(d, recipe)
                result = e1.prepare(Path(d))
                self.assertIsInstance(result, e1.Blocked)
                self.assertEqual(result.step, 'recipe')
                self.assertIn(step, result.reason)

    def test_complete_recipe_passes_the_recipe_check(self):
        with tempfile.TemporaryDirectory() as d:
            write_recipe(d, full_recipe())
            result = e1.prepare(Path(d))
        self.assertNotEqual(getattr(result, 'step', None), 'recipe', result)

    def test_step_missing_a_required_setting_is_blocked_before_start(self):
        for step, field in ((s, f) for s, fs in STEPS.items() for f in fs):
            with self.subTest(setting=f'{step}.{field}'), tempfile.TemporaryDirectory() as d:
                recipe = copy.deepcopy(full_recipe())
                del recipe[step][field]
                write_recipe(d, recipe)
                result = e1.prepare(Path(d))
                self.assertIsInstance(result, e1.Blocked)
                self.assertEqual(result.step, 'recipe')
                self.assertIn(f'{step}.{field}', result.reason)

    def test_unreadable_recipe_is_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / e1.RECIPE_FILE).write_text('{', encoding='utf-8')
            result = e1.prepare(Path(d))
        self.assertEqual((type(result), result.step), (e1.Blocked, 'recipe'))


class SourcePinned(unittest.TestCase):
    """來源與建置：固定提交. A changed project must not be built as if it were the confirmed one."""

    def project(self, d):
        (Path(d) / 'supabase').mkdir()
        (Path(d) / 'supabase' / 'seed.sql').write_text('-- seed\n', encoding='utf-8')
        recipe = full_recipe()
        recipe['source_build']['source_digest'] = e1.source_digest(Path(d))
        write_recipe(d, recipe)

    def assert_digest_blocked(self, result, expected):
        blocked = isinstance(result, e1.Blocked) and result.step == 'source_build' and 'source_digest' in result.reason
        self.assertEqual(blocked, expected, result)

    def test_unchanged_project_passes_the_digest_check(self):
        with tempfile.TemporaryDirectory() as d:
            self.project(d)
            self.assert_digest_blocked(e1.prepare(Path(d)), False)

    def test_modified_file_is_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            self.project(d)
            (Path(d) / 'supabase' / 'seed.sql').write_text('-- changed\n', encoding='utf-8')
            self.assert_digest_blocked(e1.prepare(Path(d)), True)

    def test_added_file_is_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            self.project(d)
            (Path(d) / 'supabase' / 'extra.sql').write_text('select 1;\n', encoding='utf-8')
            self.assert_digest_blocked(e1.prepare(Path(d)), True)

    def test_tool_state_directories_are_not_part_of_the_source(self):
        # The Supabase CLI writes supabase/.temp and supabase/.branches while running.
        with tempfile.TemporaryDirectory() as d:
            self.project(d)
            (Path(d) / 'supabase' / '.temp').mkdir()
            (Path(d) / 'supabase' / '.temp' / 'cli-latest').write_text('v', encoding='utf-8')
            self.assert_digest_blocked(e1.prepare(Path(d)), False)


@needs_env
class PrepareVulnerableEnv(unittest.TestCase):
    """The vulnerable version starts from a clean state and passes its health checks."""

    @classmethod
    def setUpClass(cls):
        cls.result = e1.prepare(SAMPLES / 'vulnerable')

    @classmethod
    def tearDownClass(cls):
        if isinstance(cls.result, e1.Ready):
            e1.destroy(cls.result.env)

    def setUp(self):
        self.assertIsInstance(self.result, e1.Ready, self.result)
        self.profile = self.result.profile

    def test_profile_records_mode_e1(self):
        self.assertEqual(self.profile['mode'], 'E1')

    def test_profile_records_the_pinned_cli(self):
        self.assertEqual(self.profile['tools']['supabase-cli']['version'], '2.122.0')

    def test_profile_records_each_running_service_with_an_image_digest(self):
        services = self.profile['services']
        self.assertTrue({'db', 'auth', 'rest', 'kong'} <= set(services), services)
        for name, s in services.items():
            self.assertTrue(s['image_digest'].startswith('sha256:'), (name, s))

    def test_every_v01_identity_has_a_recorded_path(self):
        identities = self.profile['identities']
        self.assertEqual(set(identities), V01_IDENTITIES)
        for name, i in identities.items():
            self.assertTrue(i['path'], name)
        self.assertEqual(identities['anonymous']['login'], 'none')
        for name in V01_IDENTITIES - {'anonymous'}:
            self.assertEqual(identities[name]['login'], 'ok', name)

    def test_legit_operation_completed(self):
        ops = self.profile['health']['legit_operations']
        self.assertEqual([(o['identity'], o['marker'], o['ok']) for o in ops],
                         [('owner', 'MARK-A-ALICE-PRIVATE', True)])

    def test_disabled_services_are_known_differences(self):
        diffs = ' '.join(self.profile['known_differences'])
        for service in ('storage', 'realtime', 'edge_runtime'):
            self.assertIn(service, diffs)

    def test_profile_holds_no_credentials(self):
        text = json.dumps(self.profile)
        env = self.result.env
        secrets_held = ([env.anon_key, env.observer['password']]
                        + [t for tokens in env.tokens.values() for t in tokens.values()])
        self.assertEqual(len(env.tokens), 3)
        for value in secrets_held:
            self.assertNotIn(value, text)
        for word in ('service_role', 'SERVICE_ROLE', 'secret key'):
            self.assertNotIn(word, text)

    def test_published_ports_bind_to_loopback_only(self):
        # TK-ENV-008, observed from Docker itself rather than from the profile.
        bindings = published_bindings(self.result.env.project_id)
        self.assertTrue(bindings, 'no published ports found')
        self.assertEqual({ip for ip, _port in bindings}, {'127.0.0.1'}, bindings)

    def test_running_versions_are_in_the_support_matrix(self):
        self.assertEqual(self.profile['unsupported'], [])


@needs_env
class OutsideSupportMatrixEnv(unittest.TestCase):
    """TK-SCP-001: a running version outside the support matrix is marked unsupported."""

    def test_service_version_outside_the_matrix_is_unsupported(self):
        matrix = json.loads(e1.SUPPORT_MATRIX.read_text(encoding='utf-8'))
        matrix['services']['rest']['image'] = 'public.ecr.aws/supabase/postgrest:v0.0.0'
        result = e1.prepare(SAMPLES / 'vulnerable', matrix=matrix)
        try:
            self.assertIsInstance(result, e1.Ready, result)
            unsupported = result.profile['unsupported']
            self.assertEqual(len(unsupported), 1, unsupported)
            self.assertIn('rest', unsupported[0])
        finally:
            if isinstance(result, e1.Ready):
                e1.destroy(result.env)


class SampleVersions(unittest.TestCase):
    """TK-VAL-001: the three versions differ only in their document policies."""

    SHARED = ['supabase/migrations/20261031000001_schema.sql', 'supabase/seed.sql']

    def test_shared_schema_and_seed_are_identical(self):
        for rel in self.SHARED:
            with self.subTest(file=rel):
                contents = {v: (SAMPLES / v / rel).read_bytes() for v in ('vulnerable', 'patched', 'legit')}
                self.assertEqual(len(set(contents.values())), 1, rel)


@needs_env
class PrepareOtherVersionsEnv(unittest.TestCase):
    EXPECTED_LEGIT_OPERATIONS = {
        'patched': [('owner', 'MARK-A-ALICE-PRIVATE', True)],
        'legit': [('owner', 'MARK-A-ALICE-PRIVATE', True), ('same_tenant_non_owner', 'MARK-A-ALICE-SHARED', True)],
    }

    def test_version_prepares_and_passes_health_checks(self):
        for version, expected in self.EXPECTED_LEGIT_OPERATIONS.items():
            with self.subTest(version=version):
                result = e1.prepare(SAMPLES / version)
                try:
                    self.assertIsInstance(result, e1.Ready, result)
                    ops = result.profile['health']['legit_operations']
                    self.assertEqual([(o['identity'], o['marker'], o['ok']) for o in ops], expected)
                    self.assertEqual(result.profile['unsupported'], [])
                finally:
                    if isinstance(result, e1.Ready):
                        e1.destroy(result.env)


# The markers written by the samples' seed.sql (literal, not read back from the recipe).
SEED_MARKERS = ['MARK-A-ALICE-PRIVATE', 'MARK-A-ALICE-SHARED', 'MARK-B-CAROL-PRIVATE']


def document_titles(project_id):
    """Titles in the documents table, read from the database container."""
    import subprocess
    r = subprocess.run(['docker', 'exec', f'supabase_db_{project_id}', 'psql', '-U', 'postgres', '-At', '-c',
                        'select title from public.documents order by title'], capture_output=True, text=True)
    return r.stdout.split()


def delete_as(env, identity, marker):
    import urllib.request
    req = urllib.request.Request(f'{env.api_url}/rest/v1/documents?title=eq.{marker}', method='DELETE', headers={
        'apikey': env.anon_key, 'Authorization': 'Bearer ' + env.tokens[identity]['access_token'],
        'Prefer': 'return=representation'})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


@needs_env
class ResetEnv(unittest.TestCase):
    """快照與重置: after a reset the state equals the initial seed, and the identities work again."""

    def test_reset_restores_the_seed_state(self):
        result = e1.prepare(SAMPLES / 'patched')
        self.assertIsInstance(result, e1.Ready, result)
        env = result.env
        try:
            self.assertEqual(document_titles(env.project_id), SEED_MARKERS)
            deleted = delete_as(env, 'owner', 'MARK-A-ALICE-SHARED')
            self.assertEqual([d['title'] for d in deleted], ['MARK-A-ALICE-SHARED'])
            self.assertEqual(document_titles(env.project_id), ['MARK-A-ALICE-PRIVATE', 'MARK-B-CAROL-PRIVATE'])

            after = e1.reset(env)
            self.assertIsInstance(after, e1.Ready, after)
            self.assertEqual(document_titles(env.project_id), SEED_MARKERS)
            self.assertTrue(all(o['ok'] for o in after.profile['health']['legit_operations']))
            self.assertEqual(after.profile['identities']['owner']['login'], 'ok')
            self.assertEqual({ip for ip, _ in published_bindings(env.project_id)}, {'127.0.0.1'})
        finally:
            e1.destroy(env)


def leftovers(project_id):
    """Containers, volumes and networks of the project still known to Docker."""
    import subprocess

    def ls(*cmd):
        return subprocess.run(['docker', *cmd], capture_output=True, text=True).stdout.split()
    return {
        'containers': [n for n in ls('ps', '-a', '--format', '{{.Names}}') if n.endswith('_' + project_id)],
        'volumes': [v for v in ls('volume', 'ls', '--format', '{{.Name}}') if v.endswith('_' + project_id)],
        'networks': [n for n in ls('network', 'ls', '--format', '{{.Name}}') if n.endswith('_' + project_id)],
    }


@needs_env
class DestroyEnv(unittest.TestCase):
    """快照與重置：清理與銷毀."""

    def test_destroy_removes_containers_volumes_and_network(self):
        result = e1.prepare(SAMPLES / 'vulnerable')
        self.assertIsInstance(result, e1.Ready, result)
        project_id = result.env.project_id
        self.assertTrue(leftovers(project_id)['containers'])
        e1.destroy(result.env)
        self.assertEqual(leftovers(project_id), {'containers': [], 'volumes': [], 'networks': []})
        self.assertFalse(result.env.usable)


def failing_copy(d, version='vulnerable', recipe_change=None, file_change=None):
    """Copy a sample into d with one deliberate fault; source changes are re-pinned like a recipe author would."""
    import shutil
    dst = Path(d) / 'sample'
    shutil.copytree(SAMPLES / version, dst, ignore=shutil.ignore_patterns('.temp', '.branches'))
    config = dst / 'supabase' / 'config.toml'
    config.write_text(config.read_text(encoding='utf-8').replace(
        f'project_id = "maz-object-authz-{version}"', 'project_id = "maz-failure-sample"'), encoding='utf-8')
    if file_change:
        rel, append = file_change
        with open(dst / rel, 'a', encoding='utf-8') as f:
            f.write(append)
    recipe = json.loads((dst / e1.RECIPE_FILE).read_text(encoding='utf-8'))
    recipe['source_build']['source_digest'] = e1.source_digest(dst)
    if recipe_change:
        recipe_change(recipe)
    write_recipe(dst, recipe)
    return dst


@needs_env
class StepFailuresEnv(unittest.TestCase):
    """〈定義：建置配方最低內容〉「失敗時處理」 for each step."""

    def assert_blocked(self, result, step, reason_part):
        self.assertIsInstance(result, e1.Blocked, result)
        self.assertEqual(result.step, step, result)
        self.assertIn(reason_part, result.reason)
        self.assertEqual(leftovers('maz-failure-sample'), {'containers': [], 'volumes': [], 'networks': []})

    def test_broken_migration_blocks_service_init_and_keeps_the_error(self):
        with tempfile.TemporaryDirectory() as d:
            src = failing_copy(d, file_change=('supabase/migrations/20261031000002_document_policies.sql',
                                               '\nthis is not sql;\n'))
            result = e1.prepare(src)
        self.assert_blocked(result, 'service_init', 'failed to start')
        self.assertIn('syntax error', result.detail)

    def test_migration_not_listed_in_the_recipe_is_never_applied_silently(self):
        with tempfile.TemporaryDirectory() as d:
            src = failing_copy(d, recipe_change=lambda r: r['service_init']['migrations'].pop())
            result = e1.prepare(src)
        self.assert_blocked(result, 'service_init', 'differ from the recipe')

    def test_missing_seeded_resource_blocks_test_data(self):
        with tempfile.TemporaryDirectory() as d:
            src = failing_copy(d, recipe_change=lambda r: r['test_data']['markers'].append('MARK-NOT-SEEDED'))
            result = e1.prepare(src)
        self.assert_blocked(result, 'test_data', 'MARK-NOT-SEEDED')

    def test_identity_without_an_account_blocks_auth(self):
        def change(r):
            r['auth']['identities'][1]['email'] = 'nobody@tenant-a.test'
        with tempfile.TemporaryDirectory() as d:
            result = e1.prepare(failing_copy(d, recipe_change=change))
        self.assert_blocked(result, 'auth', 'owner')

    def test_failed_legit_operation_blocks_even_with_the_api_up(self):
        # In the patched version a same-tenant non-owner must not read the owner's private document.
        def change(r):
            r['health']['legit_operations'].append(
                {'identity': 'same_tenant_non_owner', 'read': 'documents', 'marker': 'MARK-A-ALICE-PRIVATE'})
        with tempfile.TemporaryDirectory() as d:
            result = e1.prepare(failing_copy(d, version='patched', recipe_change=change))
        self.assert_blocked(result, 'health', 'legit operation failed')

    def test_failed_reset_isolates_the_environment(self):
        with tempfile.TemporaryDirectory() as d:
            src = failing_copy(d)
            ready = e1.prepare(src)
            self.assertIsInstance(ready, e1.Ready, ready)
            with open(src / 'supabase' / 'seed.sql', 'a', encoding='utf-8') as f:
                f.write('\nthis is not sql;\n')
            result = e1.reset(ready.env)
            self.assert_blocked(result, 'snapshot_reset', 'environment isolated')
            self.assertFalse(ready.env.usable)
            again = e1.reset(ready.env)
            self.assertEqual((again.step, 'must not be reused' in again.reason), ('snapshot_reset', True))


def psql_as(env, role, password, sql):
    """Run SQL as a login role over the network address the observer uses; returns (ok, output).

    Not 127.0.0.1: the db image trusts loopback connections without checking the password.
    """
    import subprocess
    r = subprocess.run(['docker', 'exec', '-e', f'PGPASSWORD={password}', f'supabase_db_{env.project_id}',
                        'psql', '-h', env.observer['host'], '-U', role, '-d', 'postgres', '-At', '-v', 'ON_ERROR_STOP=1',
                        '-c', sql], capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


@needs_env
class ObserverRoleEnv(unittest.TestCase):
    """TK-IDN-012: the observer uses a dedicated read-only login role, never service_role."""

    @classmethod
    def setUpClass(cls):
        cls.result = e1.prepare(SAMPLES / 'patched')

    @classmethod
    def tearDownClass(cls):
        if isinstance(cls.result, e1.Ready):
            e1.destroy(cls.result.env)

    def setUp(self):
        self.assertIsInstance(self.result, e1.Ready, self.result)
        self.env = self.result.env
        self.role, self.password = self.env.observer['role'], self.env.observer['password']

    def query(self, sql):
        return psql_as(self.env, self.role, self.password, sql)

    def test_profile_records_the_observer_grants(self):
        self.assertEqual(self.result.profile['observer'],
                         {'role': 'maz_observer', 'select_on': ['public.documents'], 'bypassrls': True})

    def test_observer_reads_every_row_of_the_judged_table(self):
        self.assertEqual(self.query('select count(*) from public.documents'), (True, '3'))

    def test_wrong_password_is_refused(self):
        ok, out = psql_as(self.env, self.role, 'not-the-password', 'select 1')
        self.assertFalse(ok, out)

    def test_observer_cannot_read_other_tables(self):
        for table in ('public.memberships', 'public.tenants', 'auth.users'):
            with self.subTest(table=table):
                ok, out = self.query(f'select count(*) from {table}')
                self.assertFalse(ok, out)
                self.assertIn('permission denied', out)

    def test_observer_cannot_write(self):
        statements = [
            "insert into public.documents (tenant_id, owner_id, title, body) select tenant_id, owner_id, 'X', 'x' "
            "from public.documents limit 1",
            "update public.documents set body = 'x'",
            'delete from public.documents',
        ]
        for sql in statements:
            with self.subTest(sql=sql.split()[0]):
                ok, out = self.query(sql)
                self.assertFalse(ok, out)
                self.assertIn('permission denied', out)

    def test_observer_is_not_privileged_and_cannot_become_service_role(self):
        ok, out = self.query("select rolsuper, rolcreaterole, rolcreatedb from pg_roles where rolname = current_user")
        self.assertEqual((ok, out), (True, 'f|f|f'))
        for role in ('service_role', 'postgres', 'authenticated'):
            with self.subTest(role=role):
                ok, out = self.query(f'set role {role}')
                self.assertFalse(ok, out)
