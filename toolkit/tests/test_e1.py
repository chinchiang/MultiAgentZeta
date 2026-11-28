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
# TK-VAL-001: every version of the sample. The last two each break one check of a denial case and nothing else.
SAMPLE_VERSIONS = ('vulnerable', 'patched', 'legit', 'lax-update-policy', 'leaky-denial', 'side-effect-on-denial')
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
                  'related_resources', 'markers',
                  'synthetic_statement'],  # 合成資料來源聲明 (TK-SBX-011)
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
    recipe = {step: {field: 'x' for field in fields} for step, fields in STEPS.items()}
    recipe['test_data']['related_resources'] = []  # the values that reach database commands have a shape
    recipe['auth']['identities'] = []
    recipe['test_data'].update(accounts=[], seed='supabase/seed.sql', synthetic_statement=dict(STATEMENT))
    return recipe


# TK-SBX-011: a complete statement that the test data is synthetic, as a person confirming a recipe writes it.
STATEMENT = {'method': 'written by hand for the test', 'confirmed_by': 'recipe-author', 'confirmed_at': '2026-11-04T00:00:00Z'}


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

    def test_the_stack_publishes_no_port_and_is_reached_through_loopback_only(self):
        # TK-ENV-008, observed from Docker and from the host's sockets rather than from the profile.
        import socket
        env = self.result.env
        self.assertEqual(published_bindings(env.project_id), [])
        self.assertEqual([r._server.getsockname() for r in env.relays], [('127.0.0.1', 54321), ('127.0.0.1', 54322)])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:  # no packet is sent: this only picks a route
            s.connect(('192.0.2.1', 9))
            host_address = s.getsockname()[0]
        if not host_address.startswith('127.'):
            for port in (54321, 54322):
                with self.subTest(port=port), self.assertRaises(OSError):
                    socket.create_connection((host_address, port), timeout=3).close()

    def test_the_stack_reaches_nothing_outside_by_address_or_by_name(self):
        # TK-SBX-004 negative case, from inside the application's own container. The control is a container on
        # Docker's default network: where that one reaches the outside, the failure below is the network's doing.
        import subprocess
        env = self.result.env
        image = self.profile['services']['db']['image']
        control = subprocess.run(['docker', 'run', '--rm', '--entrypoint', 'bash', image, '-c',
                                  'timeout 8 bash -c "</dev/tcp/1.1.1.1/443" && echo OPEN; '
                                  'getent hosts example.com && echo RESOLVED'],
                                 capture_output=True, text=True, timeout=120).stdout
        self.assertIn('OPEN', control, 'the host itself reaches nothing: the check below would prove nothing')
        self.assertIn('RESOLVED', control)
        found = _probe(f'supabase_db_{env.project_id}')
        self.assertIn('CLOSED', found['outbound_ip'], found)
        self.assertIn('UNRESOLVED', found['dns'], found)

    def test_profile_records_the_isolation_that_was_checked(self):
        isolation = self.profile['isolation']
        self.assertEqual((isolation['outbound'], isolation['method']), ('blocked', 'internal-network'))
        self.assertEqual(isolation['host_access'], ['127.0.0.1:54321 -> kong:8000', '127.0.0.1:54322 -> db:5432'])
        self.assertEqual(isolation['containers_checked'], sorted(self.profile['services']))
        self.assertTrue(isolation['limits'])

    def test_no_container_is_privileged_or_mounts_the_host(self):
        # TK-SBX-001, TK-SBX-002, read from Docker itself.
        import subprocess
        env = self.result.env
        names = [f'supabase_{s}_{env.project_id}' for s in self.profile['services']]
        for c in json.loads(subprocess.run(['docker', 'inspect', *names], capture_output=True, text=True).stdout):
            with self.subTest(container=c['Name']):
                self.assertIs(c['HostConfig']['Privileged'], False)
                self.assertEqual([m for m in c['Mounts'] if m['Type'] not in ('volume', 'tmpfs')], [])

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


class ServiceImagesAgainstTheMatrix(unittest.TestCase):
    """TK-SCP-001, 〈定義：建置配方最低內容〉 服務初始化與版本核對: a service image is the pinned one when its
    repository, tag and digest are; the registry it was pulled from is not compared."""
    DIGEST = 'sha256:' + '1' * 64
    PINNED = {'image': 'public.ecr.aws/supabase/postgrest:v16.5', 'digest': DIGEST}

    def test_the_pinned_image_is_in_the_matrix(self):
        self.assertTrue(e1.service_in_matrix(self.PINNED, 'public.ecr.aws/supabase/postgrest:v16.5', self.DIGEST))

    def test_the_same_content_from_another_registry_is_in_the_matrix(self):
        for image in ('ghcr.io/supabase/postgrest:v16.5', 'supabase/postgrest:v16.5',
                      'localhost:5000/supabase/postgrest:v16.5'):
            with self.subTest(image=image):
                self.assertTrue(e1.service_in_matrix(self.PINNED, image, self.DIGEST))

    def test_another_digest_tag_or_repository_is_outside_the_matrix(self):
        other = 'sha256:' + '2' * 64
        for image, digest in (('public.ecr.aws/supabase/postgrest:v16.5', other),
                              ('ghcr.io/supabase/postgrest:v16.5', other),
                              ('public.ecr.aws/supabase/postgrest:v16.6', self.DIGEST),
                              ('public.ecr.aws/supabase/postgrest', self.DIGEST),
                              ('public.ecr.aws/someone/postgrest:v16.5', self.DIGEST),
                              ('public.ecr.aws/supabase/postgrest:v16.5', '')):
            with self.subTest(image=image, digest=digest):
                self.assertFalse(e1.service_in_matrix(self.PINNED, image, digest))

    def test_a_service_the_matrix_does_not_pin_is_outside_it(self):
        for pinned in (None, {}, {'image': 'supabase/postgrest:v16.5'}, {'digest': self.DIGEST},
                       {'image': 'supabase/postgrest:v16.5', 'digest': ''}):
            with self.subTest(pinned=pinned):
                self.assertFalse(e1.service_in_matrix(pinned, 'supabase/postgrest:v16.5', pinned and pinned.get('digest') or ''))
        self.assertFalse(e1.service_in_matrix({'digest': self.DIGEST}, 'supabase/postgrest:v16.5', self.DIGEST))

    def test_every_service_of_the_support_matrix_pins_an_image_and_a_digest(self):
        for name, pinned in e1.load_matrix()['services'].items():
            with self.subTest(service=name):
                self.assertTrue(e1.service_in_matrix(pinned, pinned['image'], pinned['digest']))


def _probe(container):
    """What a container can reach, from inside it: an outside address by IP, and an outside name."""
    import subprocess

    def inside(script):
        r = subprocess.run(['docker', 'exec', container, 'bash', '-c', script], capture_output=True, text=True, timeout=60)
        return (r.stdout + r.stderr).strip().replace('\n', ' | ')[:200] or f'exit {r.returncode}'
    return {'outbound_ip': inside('timeout 8 bash -c "</dev/tcp/1.1.1.1/443" && echo OPEN || echo CLOSED'),
            'dns': inside('getent hosts example.com && echo RESOLVED || echo UNRESOLVED')}


def isolated_stack(project_id, network=None, **changes):
    """`docker network inspect` and `docker inspect` output of a stack that meets 〈定義：E1 隔離〉."""
    network = network or f'maz_e1_{project_id}'
    container = {'Name': f'/supabase_db_{project_id}', 'HostConfig': {'Privileged': False},
                 'NetworkSettings': {'Networks': {network: {'IPAddress': '172.18.0.2'}}, 'Ports': {'5432/tcp': None}},
                 'Mounts': [{'Type': 'volume', 'Source': '/var/lib/docker/volumes/db/_data', 'Destination': '/var/lib/postgresql/data'}]}
    container.update(changes)
    return {'Internal': True}, [container]


class IsolationProblems(unittest.TestCase):
    """〈定義：E1 隔離〉 啟動後檢查 (TK-SBX-001, TK-SBX-002, TK-SBX-004, TK-SBX-005, TK-ENV-008), on inspect output."""

    PROJECT = Path('/work/sample')
    TOOLKIT = Path('/opt/maz/toolkit')

    def problems(self, network=None, **changes):
        net, containers = isolated_stack('p', **changes)
        return e1.isolation_problems(net if network is None else network, containers, 'maz_e1_p', self.PROJECT, self.TOOLKIT)

    def test_a_stack_on_an_internal_network_with_only_volumes_has_no_problem(self):
        self.assertEqual(self.problems(), [])

    def test_a_bind_mount_from_the_project_under_test_is_allowed(self):
        self.assertEqual(self.problems(Mounts=[{'Type': 'bind', 'Source': '/work/sample/supabase/functions',
                                                'Destination': '/functions'}]), [])

    def test_a_network_that_is_not_internal_is_a_problem(self):
        for network in ({'Internal': False}, {}, [], 'x'):
            with self.subTest(network=network):
                self.assertTrue(any('not internal' in p for p in self.problems(network=network)))

    def test_a_privileged_container_is_a_problem(self):
        for host in ({'Privileged': True}, {}, None):
            with self.subTest(host=host):
                self.assertTrue(any('privileged' in p for p in self.problems(HostConfig=host)))

    def test_a_container_on_another_network_is_a_problem(self):
        for networks in ({'maz_e1_p': {}, 'bridge': {}}, {'host': {}}, {}):
            with self.subTest(networks=networks):
                found = self.problems(NetworkSettings={'Networks': networks})
                self.assertTrue(any('attached to' in p for p in found), found)

    def test_a_published_port_is_a_problem(self):
        settings = {'Networks': {'maz_e1_p': {}}, 'Ports': {'5432/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '54322'}]}}
        self.assertTrue(any('publishes' in p for p in self.problems(NetworkSettings=settings)))

    def test_the_docker_control_socket_is_a_problem_whatever_the_mount_type(self):
        for mount in ({'Type': 'bind', 'Source': '/var/run/docker.sock', 'Destination': '/var/run/docker.sock'},
                      {'Type': 'volume', 'Source': '/x', 'Destination': '/run/docker.sock'}):
            with self.subTest(mount=mount):
                self.assertTrue(any('control socket' in p for p in self.problems(Mounts=[mount])))

    def test_a_host_path_outside_the_project_is_a_problem(self):
        for source in ('/home/user', '/home/user/.ssh', '/home/user/.aws', '/', '/work', '/work/sample-other', ''):
            with self.subTest(source=source):
                found = self.problems(Mounts=[{'Type': 'bind', 'Source': source, 'Destination': '/x'}])
                self.assertTrue(any('outside the project' in p for p in found), found)

    def test_a_mount_that_reaches_the_control_area_is_a_problem_even_inside_the_project(self):
        net, containers = isolated_stack('p', Mounts=[{'Type': 'bind', 'Source': '/work/sample', 'Destination': '/x'}])
        for toolkit in ('/work/sample/toolkit', '/work/sample'):
            with self.subTest(toolkit=toolkit):
                found = e1.isolation_problems(net, containers, 'maz_e1_p', self.PROJECT, Path(toolkit))
                self.assertTrue(any('outside the project' in p for p in found), found)

    def test_what_cannot_be_read_is_a_problem_not_a_pass(self):
        self.assertTrue(any('mounts could not be read' in p for p in self.problems(Mounts=None)))
        for containers in ([], None, ['x']):
            with self.subTest(containers=containers):
                self.assertTrue(e1.isolation_problems({'Internal': True}, containers, 'maz_e1_p', self.PROJECT, self.TOOLKIT))


class Relays(unittest.TestCase):
    """〈定義：E1 隔離〉 宿主機入口: toolkit.forward.Relay, against a server on the loopback interface."""

    def setUp(self):
        import socket
        import threading
        from toolkit import forward
        self.forward, self.socket = forward, socket
        self.upstream = socket.socket()
        self.upstream.bind(('127.0.0.1', 0))
        self.upstream.listen(4)
        self.addCleanup(self.upstream.close)

        def reverse():
            while True:
                try:
                    c, _ = self.upstream.accept()
                except OSError:
                    return
                c.sendall(c.recv(100)[::-1])
                c.close()
        threading.Thread(target=reverse, daemon=True).start()

    def relay(self, lookup):
        probe = self.socket.socket()
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
        probe.close()
        relay = self.forward.Relay(port, lookup, self.upstream.getsockname()[1])
        self.addCleanup(relay.close)
        return relay

    def ask(self, port):
        with self.socket.create_connection(('127.0.0.1', port), timeout=5) as s:
            try:
                s.sendall(b'abc')
                return s.recv(100)
            except ConnectionError:  # closed with the request unread: a reset, not an answer
                return b''

    def test_a_connection_is_passed_to_the_address_looked_up(self):
        self.assertEqual(self.ask(self.relay(lambda: '127.0.0.1').port), b'cba')

    def test_a_target_that_is_not_there_closes_the_connection_and_the_relay_goes_on(self):
        answers = iter(['', '127.0.0.1'])
        relay = self.relay(lambda: next(answers))
        self.assertEqual(self.ask(relay.port), b'')
        self.assertEqual(self.ask(relay.port), b'cba')

    def test_a_lookup_that_raises_closes_the_connection(self):
        def lookup():
            raise RuntimeError('docker is gone')
        self.assertEqual(self.ask(self.relay(lookup).port), b'')

    def test_it_listens_on_the_loopback_interface_only(self):
        relay = self.relay(lambda: '127.0.0.1')
        self.assertEqual(relay._server.getsockname()[0], '127.0.0.1')  # TK-ENV-008

    def test_the_port_is_free_again_once_closed(self):
        relay = self.relay(lambda: '127.0.0.1')  # its accept() is already waiting in another thread
        relay.close()
        with self.assertRaises(ConnectionRefusedError):
            self.socket.create_connection(('127.0.0.1', relay.port), timeout=5)
        again = self.socket.socket()  # no SO_REUSEADDR: a listener left behind would refuse this
        self.addCleanup(again.close)
        again.bind(('127.0.0.1', relay.port))

    def test_a_port_already_taken_is_an_error(self):
        relay = self.relay(lambda: '127.0.0.1')
        with self.assertRaises(OSError):
            self.forward.Relay(relay.port, lambda: '127.0.0.1', 1)


class SampleVersions(unittest.TestCase):
    """TK-VAL-001: the sample versions differ only in their document policies."""

    SHARED = ['supabase/migrations/20261031000001_schema.sql', 'supabase/seed.sql']

    def test_shared_schema_and_seed_are_identical(self):
        for rel in self.SHARED:
            with self.subTest(file=rel):
                contents = {v: (SAMPLES / v / rel).read_bytes() for v in SAMPLE_VERSIONS}
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
SEED_MARKERS = ['MARK-A-ALICE-PRIVATE', 'MARK-A-ALICE-SHARED', 'MARK-A-ALICE-SHARED-TO-B', 'MARK-B-CAROL-PRIVATE']


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
            self.assertEqual(document_titles(env.project_id), [m for m in SEED_MARKERS if m != 'MARK-A-ALICE-SHARED'])

            after = e1.reset(env)
            self.assertIsInstance(after, e1.Ready, after)
            self.assertEqual(document_titles(env.project_id), SEED_MARKERS)
            self.assertTrue(all(o['ok'] for o in after.profile['health']['legit_operations']))
            self.assertEqual(after.profile['identities']['owner']['login'], 'ok')
            self.assertEqual(published_bindings(env.project_id), [])
            self.assertEqual(after.profile['isolation']['outbound'], 'blocked')  # checked again after the reset
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
        self.assertEqual(e1.destroy(result.env), [])  # TK-ENV-003: checked, nothing is left
        self.assertEqual(leftovers(project_id), {'containers': [], 'volumes': [], 'networks': []})
        self.assertFalse(result.env.usable)
        self.assertEqual(result.env.relays, [])

    def test_a_destroy_that_stops_nothing_names_what_is_left_and_the_environment_is_not_reused(self):
        from unittest import mock
        result = e1.prepare(SAMPLES / 'vulnerable')
        self.assertIsInstance(result, e1.Ready, result)
        env = result.env
        try:
            with mock.patch.object(e1, '_stop_stack', return_value=['supabase stop: exit 1: simulated']):
                left = e1.destroy(env)
            self.assertIn(f'container supabase_db_{env.project_id}', left)
            self.assertIn(f'network {env.network}', left)
            self.assertTrue(any(x.startswith('volume ') for x in left), left)
            self.assertIn('while stopping: supabase stop: exit 1: simulated', left)
            env.usable = False  # what the real stop does first
            again = e1.reset(env)
            self.assertEqual((type(again), again.step), (e1.Blocked, 'snapshot_reset'))  # TK-SBX-010
        finally:
            self.assertEqual(e1.destroy(env), [])

    def test_logging_out_ends_the_sessions_refresh_tokens(self):
        # 〈定義：中止與清理〉 撤銷測試憑證, against the real auth service.
        from toolkit import environment
        ready = environment.prepare(SAMPLES / 'vulnerable')
        self.assertIsInstance(ready, e1.Ready, ready)
        ops = ready.env
        try:
            env = ops._env
            held = {name: dict(tokens) for name, tokens in env.tokens.items()}
            self.assertTrue(held)
            self.assertEqual(set(ops.revoke_sessions().values()), {'revoked'})
            self.assertEqual(env.tokens, {})
            for name, tokens in held.items():
                with self.subTest(identity=name):
                    status, _ = e1._http('POST', f'{env.api_url}/auth/v1/token?grant_type=refresh_token',
                                         {'apikey': env.anon_key}, {'refresh_token': tokens['refresh_token']})
                    self.assertNotEqual(status, 200)
                    self.assertNotEqual(status, 0)  # the auth service answered: it refused
        finally:
            self.assertEqual(ops.destroy(), [])


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
        self.assertEqual(self.query('select count(*) from public.documents'), (True, str(len(SEED_MARKERS))))

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

    def test_observer_cannot_lock_rows_or_the_table(self):
        # TK-IDN-010: the role holds SELECT only, and every lock beyond the one a plain read takes needs more.
        row_locks = [f'select title from public.documents {clause}'
                     for clause in ('for update', 'for no key update', 'for share', 'for key share')]
        table_locks = [f'begin; lock table public.documents in {mode} mode; commit'
                       for mode in ('row share', 'row exclusive', 'share update exclusive', 'share',
                                    'share row exclusive', 'exclusive', 'access exclusive')]
        for sql in row_locks + table_locks:
            with self.subTest(sql=sql):
                ok, out = self.query(sql)
                self.assertFalse(ok, out)
                self.assertIn('permission denied', out)

    def locks_on_documents(self):
        """Locks on the judged table that Postgres lists right now, read by the provisioning identity."""
        return sorted(e1._psql(self.env, "select l.mode || ' ' || l.granted from pg_locks l join pg_class c "
                                         "on c.oid = l.relation where c.oid = 'public.documents'::regclass "
                                         "and l.pid <> pg_backend_pid();").splitlines())

    def test_an_observation_leaves_no_lock_on_the_judged_table(self):
        # TK-IDN-010: the lock state of the data under test is the same before and after the template's read.
        from toolkit import observer
        before = self.locks_on_documents()
        state = observer.document_row_state(self.env, 'MARK-A-ALICE-PRIVATE')
        self.assertTrue(state['resource_exists'], state)
        self.assertEqual(self.locks_on_documents(), before)
        self.assertEqual(before, [])

    def test_observer_is_not_privileged_and_cannot_become_service_role(self):
        ok, out = self.query("select rolsuper, rolcreaterole, rolcreatedb from pg_roles where rolname = current_user")
        self.assertEqual((ok, out), (True, 'f|f|f'))
        for role in ('service_role', 'postgres', 'authenticated'):
            with self.subTest(role=role):
                ok, out = self.query(f'set role {role}')
                self.assertFalse(ok, out)


class ResetWithoutRecovery(unittest.TestCase):
    """復原方式: a recipe that declares no reset is never reset (nothing is touched)."""

    def test_reset_refuses_when_the_recipe_declares_none(self):
        recipe = full_recipe()
        recipe['snapshot_reset']['reset_scope'] = 'none'
        env = e1.Environment(Path('.'), 'maz-never-started', recipe, cli='/nonexistent/supabase')
        result = e1.reset(env)
        self.assertEqual((type(result), result.step), (e1.Blocked, 'snapshot_reset'))
        self.assertIn('no reset', result.reason)


class TestDataMustBeSynthetic(unittest.TestCase):
    """TK-SBX-011, TK-SBX-012: when the recipe is read, its test data needs the statement that it is synthetic,
    accounts in the reserved domains and a seed file inside the source under test; otherwise test_data is
    blocked and nothing is started (no command is run)."""

    def read(self, change):
        from unittest import mock
        recipe = full_recipe()
        change(recipe)
        with tempfile.TemporaryDirectory() as d, mock.patch('subprocess.run') as run_command:
            write_recipe(d, recipe)
            result = e1.prepare(Path(d))
            self.assertEqual(run_command.call_count, 0 if result.step in ('recipe', 'test_data') else run_command.call_count)
        self.assertIsInstance(result, e1.Blocked)
        return result

    def assert_test_data_blocked(self, change, word):
        result = self.read(change)
        self.assertEqual(result.step, 'test_data', result)
        self.assertIn(word, result.reason)
        return result

    def assert_test_data_accepted(self, change):
        self.assertNotIn(self.read(change).step, ('recipe', 'test_data'))  # it stops later, at the source check

    def test_a_complete_statement_reserved_accounts_and_a_seed_inside_the_source_are_accepted(self):
        self.assert_test_data_accepted(lambda r: r['test_data'].update(accounts=['alice@tenant-a.test']))

    def test_a_recipe_without_the_statement_is_incomplete(self):
        result = self.read(lambda r: r['test_data'].pop('synthetic_statement'))
        self.assertEqual(result.step, 'recipe')
        self.assertIn('test_data.synthetic_statement', result.reason)

    def test_each_field_of_the_statement_is_required(self):
        for field in ('method', 'confirmed_by', 'confirmed_at'):  # 產生方式、確認者、確認時間
            for value in (None, '', '   ', 7):
                with self.subTest(field=field, value=value):
                    def change(r, field=field, value=value):
                        if value is None:
                            del r['test_data']['synthetic_statement'][field]
                        else:
                            r['test_data']['synthetic_statement'][field] = value
                    self.assertIn(field, self.assert_test_data_blocked(change, 'synthetic_statement lacks').reason)

    def test_a_statement_that_is_no_object_blocks(self):
        for value in ('synthetic', ['method'], None):
            with self.subTest(value=value):
                self.assert_test_data_blocked(lambda r: r['test_data'].update(synthetic_statement=value), 'synthetic_statement')

    def test_every_class_of_reserved_domain_is_accepted(self):
        for account in ('a@tenant.test', 'a@corp.example', 'a@x.invalid', 'a@dev.localhost', 'a@example.com',
                        'a@example.net', 'a@example.org', 'a@mail.example.com', 'a@a.b.example.net',
                        'a@sub.example.org', 'A@TENANT.TEST'):
            with self.subTest(account=account):
                self.assert_test_data_accepted(lambda r: r['test_data'].update(accounts=[account]))

    def test_an_account_outside_the_reserved_domains_blocks(self):
        for account in ('alice@gmail.com', 'a@example.com.evil.io', 'a@notexample.com', 'a@test.io', 'a@examplecom',
                        'a@company.co'):
            with self.subTest(account=account):
                result = self.assert_test_data_blocked(lambda r: r['test_data'].update(accounts=[account]),
                                                       'outside the reserved domains')
                self.assertIn(account, result.reason)

    def test_the_email_of_an_identity_is_checked_like_an_account(self):
        self.assert_test_data_blocked(
            lambda r: r['auth'].update(identities=[{'name': 'owner', 'email': 'alice@gmail.com'}]),
            'outside the reserved domains')

    EXCEPTION = {'account': 'billing@partner.io', 'reason': 'the payment sandbox only mails real domains',
                 'confirmed_by': 'app-owner', 'confirmed_at': '2026-11-04T00:00:00Z'}

    def test_a_domain_exception_exempts_the_account_it_names_and_no_other(self):
        self.assert_test_data_accepted(lambda r: r['test_data'].update(
            accounts=['billing@partner.io', 'a@tenant.test'], domain_exceptions=[self.EXCEPTION]))
        result = self.assert_test_data_blocked(lambda r: r['test_data'].update(
            accounts=['billing@partner.io', 'ops@partner.io'], domain_exceptions=[self.EXCEPTION]),
            'outside the reserved domains')
        self.assertIn('ops@partner.io', result.reason)
        self.assertNotIn('billing@partner.io', result.reason)

    def test_an_incomplete_domain_exception_exempts_nothing(self):
        for field in ('account', 'reason', 'confirmed_by', 'confirmed_at'):
            with self.subTest(field=field):
                exception = {k: v for k, v in self.EXCEPTION.items() if k != field}
                result = self.assert_test_data_blocked(lambda r: r['test_data'].update(
                    accounts=['billing@partner.io'], domain_exceptions=[exception]), 'domain_exceptions[0] lacks')
                self.assertIn(field, result.reason)
        self.assert_test_data_blocked(lambda r: r['test_data'].update(domain_exceptions='billing@partner.io'),
                                      'domain_exceptions must be a list')

    def test_a_seed_file_outside_the_source_blocks_and_no_exception_waives_it(self):
        for seed in ('../seed.sql', '/etc/passwd', 'supabase/../../seed.sql', '', '.'):
            with self.subTest(seed=seed):
                self.assert_test_data_blocked(lambda r: r['test_data'].update(seed=seed), 'not inside the source')
        self.assert_test_data_blocked(lambda r: r['test_data'].update(
            seed='../seed.sql', accounts=['billing@partner.io'], domain_exceptions=[self.EXCEPTION]),
            'does not waive')

    def test_a_seed_file_that_is_a_link_out_of_the_source_blocks(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
            (Path(outside) / 'seed.sql').write_text('select 1;', encoding='utf-8')
            (Path(d) / 'supabase').mkdir()
            try:
                (Path(d) / 'supabase' / 'seed.sql').symlink_to(Path(outside) / 'seed.sql')
            except OSError:
                self.skipTest('symbolic links are not available here')
            write_recipe(d, full_recipe())
            result = e1.prepare(Path(d))
        self.assertEqual((type(result), result.step), (e1.Blocked, 'test_data'))
        self.assertIn('not inside the source', result.reason)

    def test_the_samples_state_that_their_data_is_synthetic(self):
        for version in SAMPLE_VERSIONS:
            with self.subTest(version=version):
                recipe, blocked = e1.load_recipe(SAMPLES / version)
                self.assertIsNone(blocked)
                self.assertEqual(sorted(recipe['test_data']['synthetic_statement']), ['confirmed_at', 'confirmed_by', 'method'])
                self.assertNotIn('domain_exceptions', recipe['test_data'])


class RecipeValuesInDatabaseCommands(unittest.TestCase):
    """〈定義：建置配方最低內容〉 資料庫命令中的配方值 (TK-ENV-004): a table name or email of the recipe that is
    not a plain one blocks its step when the recipe is read, before anything is started."""

    def blocked(self, change):
        recipe = full_recipe()
        change(recipe)
        with tempfile.TemporaryDirectory() as d:
            write_recipe(d, recipe)
            result = e1.prepare(Path(d))
        self.assertIsInstance(result, e1.Blocked)
        return result

    def test_a_related_resource_that_is_no_plain_table_name_blocks_test_data(self):
        for value in (['memberships; drop table public.documents'], ['public.memberships'], ['a b'], [''], [7],
                      'memberships'):
            with self.subTest(value=value):
                result = self.blocked(lambda r: r['test_data'].update(related_resources=value))
                self.assertEqual(result.step, 'test_data')
                self.assertIn('related_resources', result.reason)

    def test_an_observer_table_that_is_no_plain_table_name_blocks_auth(self):
        for value in (['public.documents to public; --'], ['a.b.c'], ['"documents"'], 'public.documents'):
            with self.subTest(value=value):
                result = self.blocked(lambda r: r.update(observer={'select_on': value}))
                self.assertEqual(result.step, 'auth')
                self.assertIn('observer.select_on', result.reason)

    def test_an_identity_email_with_a_quote_or_a_space_blocks_auth(self):
        for email in ("alice@tenant-a.test' or '1'='1", 'alice @tenant-a.test', 'alice', 7):
            with self.subTest(email=email):
                result = self.blocked(lambda r: r['auth'].update(identities=[{'name': 'owner', 'email': email}]))
                self.assertEqual(result.step, 'auth')
                self.assertIn('email', result.reason)

    def test_identities_that_are_not_named_objects_block_auth(self):
        for value in ('x', ['owner'], [{'email': 'alice@tenant-a.test'}]):
            with self.subTest(value=value):
                result = self.blocked(lambda r: r['auth'].update(identities=value))
                self.assertEqual(result.step, 'auth')
                self.assertIn('identities', result.reason)

    def test_the_recipes_of_the_samples_are_accepted(self):
        for version in SAMPLE_VERSIONS:
            with self.subTest(version=version):
                recipe, blocked = e1.load_recipe(SAMPLES / version)
                self.assertEqual(recipe['sample'], f'object-authz/{version}')
                self.assertEqual(recipe['source_build']['source_digest'], e1.source_digest(SAMPLES / version))
                self.assertIsNone(blocked)
                self.assertTrue(recipe['observer']['select_on'])
                self.assertTrue(recipe['test_data']['related_resources'])


class ACommandThatDoesNotComplete(unittest.TestCase):
    """TK-ENV-004 失敗時處理, TK-SBX-010, TK-ENV-003: a database or container command that fails, times out or
    cannot be started blocks its step; a failed reset isolates the environment; an interrupt stops the stack.
    The commands are replaced at subprocess.run, so no Docker is needed."""

    def setUp(self):
        import hashlib
        from unittest import mock
        self.mock = mock
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        bin_path = Path(self.tmp.name) / 'fake-supabase'
        bin_path.write_bytes(b'#!/bin/sh\n')
        self.matrix = {'tools': {'supabase-cli': {'version': '2.122.0',
                                                  'binary_sha256': hashlib.sha256(bin_path.read_bytes()).hexdigest()}}}
        patcher = mock.patch.dict(os.environ, {'MAZ_SUPABASE_BIN': str(bin_path)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.commands = []
        self.relays = []  # no real port in a fast test: (port, inner port) of each relay asked for

        def relay(port, lookup, inner):
            self.relays.append((port, inner))
            return mock.Mock(port=port, inner_port=inner)
        patcher = mock.patch('toolkit.forward.Relay', side_effect=relay)
        patcher.start()
        self.addCleanup(patcher.stop)

    def inspected(self, cmd, **changes):
        """Answers for the commands that read the stack's isolation; None for any other command."""
        network, containers = isolated_stack('maz-failure-sample', **changes)
        if cmd[:2] == ['docker', 'ps']:
            return 0, 'supabase_db_maz-failure-sample\timage\t\n', ''
        if cmd[:3] == ['docker', 'network', 'inspect']:
            return 0, json.dumps([network]), ''
        if cmd[:2] == ['docker', 'inspect'] and '-f' not in cmd:
            return 0, json.dumps(containers), ''
        return None

    def run_commands(self, answer):
        """Replace subprocess.run: `answer(argv)` returns (returncode, stdout, stderr) or raises."""
        import subprocess

        def fake(cmd, **kwargs):
            self.commands.append(list(cmd))
            code, out, err = answer(cmd)
            return subprocess.CompletedProcess(cmd, code, out, err)
        patcher = self.mock.patch('subprocess.run', side_effect=fake)
        patcher.start()
        self.addCleanup(patcher.stop)

    def stopped(self):
        return any(c[1:2] == ['stop'] for c in self.commands)

    def started_env(self):
        recipe = json.loads((SAMPLES / 'patched' / e1.RECIPE_FILE).read_text(encoding='utf-8'))
        return e1.Environment(SAMPLES / 'patched', 'maz-never-started', recipe, cli='/nonexistent/supabase')

    def test_a_failing_database_command_blocks_its_step_and_stops_the_stack(self):
        def answer(cmd):
            if 'psql' in cmd:
                return 1, '', 'ERROR:  relation "pg_extension" does not exist'
            if cmd[1:2] == ['status']:
                return 0, '{"API_URL": "http://127.0.0.1:1", "ANON_KEY": "k"}', ''
            return self.inspected(cmd) or (0, '', '')
        self.run_commands(answer)
        result = e1.prepare(failing_copy(self.tmp.name), matrix=self.matrix)
        self.assertEqual((type(result), result.step), (e1.Blocked, 'service_init'))
        self.assertIn('pg_extension', result.detail)
        self.assertTrue(self.stopped())

    def start_with(self, **changes):
        def answer(cmd):
            if cmd[1:2] == ['status']:
                return 0, '{"API_URL": "http://127.0.0.1:1", "ANON_KEY": "k"}', ''
            return self.inspected(cmd, **changes) or (0, '', '')
        self.run_commands(answer)
        return e1.prepare(failing_copy(self.tmp.name), matrix=self.matrix)

    def test_the_network_is_created_internal_and_the_relays_stand_before_the_stack_starts(self):
        self.start_with()
        create = next(c for c in self.commands if c[:3] == ['docker', 'network', 'create'])
        self.assertIn('--internal', create)  # TK-SBX-004
        self.assertEqual(self.relays, [(54321, 8000), (54322, 5432)])
        self.assertLess(self.commands.index(create), next(i for i, c in enumerate(self.commands) if c[1:2] == ['start']))

    def test_a_started_stack_that_is_not_isolated_blocks_service_init_and_is_stopped(self):
        result = self.start_with(HostConfig={'Privileged': True})
        self.assertEqual((type(result), result.step), (e1.Blocked, 'service_init'))
        self.assertIn('not isolated', result.reason)
        self.assertIn('privileged', result.detail)
        self.assertTrue(self.stopped())

    def test_isolation_that_cannot_be_inspected_blocks_service_init(self):
        def answer(cmd):
            if cmd[1:2] == ['status']:
                return 0, '{"API_URL": "http://127.0.0.1:1", "ANON_KEY": "k"}', ''
            return 0, '', ''  # docker inspect prints nothing
        self.run_commands(answer)
        result = e1.prepare(failing_copy(self.tmp.name), matrix=self.matrix)
        self.assertEqual((type(result), result.step), (e1.Blocked, 'service_init'))
        self.assertIn('isolation', result.reason)
        self.assertTrue(self.stopped())

    def test_a_port_that_cannot_be_listened_on_blocks_service_init_before_the_stack_starts(self):
        self.run_commands(lambda cmd: (0, '', ''))
        with self.mock.patch('toolkit.forward.Relay', side_effect=OSError(98, 'Address already in use')):
            result = e1.prepare(failing_copy(self.tmp.name), matrix=self.matrix)
        self.assertEqual((type(result), result.step), (e1.Blocked, 'service_init'))
        self.assertIn('127.0.0.1:54321', result.reason)
        self.assertFalse(any(c[1:2] == ['start'] for c in self.commands))

    def test_a_command_that_times_out_blocks_its_step(self):
        import subprocess

        def answer(cmd):
            if cmd[1:2] == ['start']:
                raise subprocess.TimeoutExpired(cmd, 900)
            return 0, '', ''
        self.run_commands(answer)
        result = e1.prepare(failing_copy(self.tmp.name), matrix=self.matrix)
        self.assertEqual((type(result), result.step), (e1.Blocked, 'service_init'))
        self.assertIn('TimeoutExpired', result.reason)
        self.assertTrue(self.stopped())

    def test_an_interrupt_while_starting_stops_the_stack_and_is_not_swallowed(self):
        def answer(cmd):
            if cmd[1:2] == ['start']:
                raise KeyboardInterrupt
            return 0, '', ''
        self.run_commands(answer)
        with self.assertRaises(KeyboardInterrupt):
            e1.prepare(failing_copy(self.tmp.name), matrix=self.matrix)
        self.assertTrue(self.stopped())

    def test_destroy_reports_nothing_left_when_docker_lists_nothing_of_the_stack(self):
        self.run_commands(lambda cmd: (0, 'supabase_db_another-project\nbridge\n', ''))
        env = self.started_env()
        self.assertEqual(e1.destroy(env), [])
        self.assertFalse(env.usable)
        self.assertTrue(self.stopped())

    def test_destroy_names_the_containers_volumes_and_network_still_listed(self):
        def answer(cmd):
            if cmd[1:2] == ['stop']:
                return 1, '', 'failed to stop'
            if cmd[:2] == ['docker', 'ps']:
                self.assertIn('-a', cmd)  # a stopped container is still there
                return 0, 'supabase_db_maz-never-started\nsupabase_db_other\n', ''
            if cmd[:3] == ['docker', 'volume', 'ls']:
                return 0, 'supabase_db_maz-never-started\n', ''
            if cmd[:3] == ['docker', 'network', 'ls']:
                return 0, 'bridge\nmaz_e1_maz-never-started\n', ''
            return 0, '', ''
        self.run_commands(answer)
        left = e1.destroy(self.started_env())
        self.assertEqual(left[:3], ['container supabase_db_maz-never-started', 'volume supabase_db_maz-never-started',
                                    'network maz_e1_maz-never-started'])
        self.assertTrue(any('while stopping: fake-supabase stop: exit 1' in x or 'stop: exit 1' in x for x in left), left)

    def test_what_docker_cannot_list_is_not_known_to_be_gone(self):
        import subprocess

        def answer(cmd):
            if cmd[:2] == ['docker', 'ps']:
                raise subprocess.TimeoutExpired(cmd, 60)
            if cmd[:3] == ['docker', 'volume', 'ls']:
                return 1, '', 'Cannot connect to the Docker daemon'
            return 0, '', ''
        self.run_commands(answer)
        left = e1.destroy(self.started_env())
        self.assertTrue(any(x.startswith('containers not checked') for x in left), left)
        self.assertTrue(any(x.startswith('volumes not checked') for x in left), left)

    def test_a_stop_command_that_does_not_complete_does_not_raise_from_destroy(self):
        import subprocess

        def answer(cmd):
            if cmd[1:2] == ['stop']:
                raise subprocess.TimeoutExpired(cmd, 300)
            return 0, '', ''
        self.run_commands(answer)
        self.assertEqual(e1.destroy(self.started_env()), [])  # nothing is listed: it is gone, however stop ended

    def test_a_reset_whose_database_command_fails_isolates_the_environment(self):
        def answer(cmd):
            if 'psql' in cmd:
                return 2, '', 'psql: error: connection to server failed'
            return 0, '', ''
        self.run_commands(answer)
        env = self.started_env()
        result = e1.reset(env, matrix=self.matrix)
        self.assertEqual((type(result), result.step), (e1.Blocked, 'snapshot_reset'))
        self.assertIn('connection to server failed', result.detail)
        self.assertFalse(env.usable)
        self.assertTrue(self.stopped())
        again = e1.reset(env, matrix=self.matrix)  # TK-SBX-010: not reused
        self.assertEqual((type(again), again.step), (e1.Blocked, 'snapshot_reset'))
        self.assertIn('isolated earlier', again.reason)

    def test_a_reset_that_cannot_stop_the_stack_is_still_blocked_and_isolated(self):
        import subprocess

        def answer(cmd):
            if cmd[1:2] in (['db'], ['stop']):
                raise subprocess.TimeoutExpired(cmd, 300)
            return 0, '', ''
        self.run_commands(answer)
        env = self.started_env()
        result = e1.reset(env, matrix=self.matrix)
        self.assertEqual((type(result), result.step), (e1.Blocked, 'snapshot_reset'))
        self.assertFalse(env.usable)

    def test_seeded_titles_are_read_one_a_line(self):
        self.run_commands(lambda cmd: (0, 'MARK A\nMARK-B\n', ''))
        self.assertEqual(e1._seeded_markers(self.started_env()), ['MARK A', 'MARK-B'])


class SourceBuildFastChecks(unittest.TestCase):
    """TK-SCP-001, TK-SBX-008, 〈定義：建置配方最低內容〉 來源與建置: tools, binary digest, lockfiles and
    build_commands are checked through e1.prepare() before any container or network is started."""

    def setUp(self):
        import hashlib
        from unittest import mock
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bin_path = Path(self.tmp.name) / 'fake-supabase'
        self.bin_path.write_bytes(b'#!/bin/sh\necho 2.122.0\n')
        self.bin_sha = hashlib.sha256(self.bin_path.read_bytes()).hexdigest()
        self.matrix = {'tools': {'supabase-cli': {'version': '2.122.0', 'binary_sha256': self.bin_sha}}}
        patcher = mock.patch.dict(os.environ, {'MAZ_SUPABASE_BIN': str(self.bin_path)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def prepare_copy(self, recipe_change=None, matrix=None):
        d = tempfile.mkdtemp(dir=self.tmp.name)
        src = failing_copy(d, recipe_change=recipe_change)
        return e1.prepare(src, matrix=self.matrix if matrix is None else matrix)

    def test_tool_not_in_support_matrix_is_blocked_at_source_build(self):
        res = self.prepare_copy(lambda r: r['source_build'].update(tools=['unlisted-cli']))
        self.assertEqual((type(res), res.step), (e1.Blocked, 'source_build'))
        self.assertIn("'unlisted-cli' is not in the support matrix", res.reason)

    def test_tool_binary_digest_mismatch_is_blocked_at_source_build(self):
        wrong_matrix = {'tools': {'supabase-cli': {'version': '2.122.0', 'binary_sha256': '0' * 64}}}
        res = self.prepare_copy(matrix=wrong_matrix)
        self.assertEqual((type(res), res.step), (e1.Blocked, 'source_build'))
        self.assertIn('does not match the support matrix digest', res.reason)

    def test_missing_lockfile_is_blocked_at_source_build(self):
        res = self.prepare_copy(lambda r: r['source_build'].update(lockfiles=['package-lock.json']))
        self.assertEqual((type(res), res.step), (e1.Blocked, 'source_build'))
        self.assertIn("lockfiles not found: ['package-lock.json']", res.reason)

    def test_non_empty_build_commands_are_blocked_until_sandbox_exists(self):
        res = self.prepare_copy(lambda r: r['source_build'].update(build_commands=['npm run build']))
        self.assertEqual((type(res), res.step), (e1.Blocked, 'source_build'))
        self.assertIn('TK-SBX-008', res.reason)

    def test_valid_source_build_passes_and_advances_to_service_init(self):
        # Removing a migration from the recipe stops at service_init before creating any Docker network.
        res = self.prepare_copy(lambda r: r['service_init'].update(migrations=[]))
        self.assertEqual((type(res), res.step), (e1.Blocked, 'service_init'))
