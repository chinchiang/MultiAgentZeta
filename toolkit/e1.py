"""E1 environment module: a local Supabase stack prepared from a confirmed BuildRecipe.

Interface:
  prepare(project_dir, matrix=None) -> Ready | Blocked
  reset(env) -> Ready | Blocked
  destroy(env) -> None

Each BuildRecipe step (〈定義：建置配方最低內容〉) either succeeds or returns
Blocked(step, reason, detail) with the table's failure handling; a stack that was
started is stopped again before Blocked is returned. Ready.profile is the
EnvironmentProfile: JSON-serializable and free of credentials. Ready.env holds
the live handles (API URL, per-identity tokens) and never leaves the control area.

Runs where Docker runs (WSL/Linux). The Supabase CLI is found via MAZ_SUPABASE_BIN
or PATH and must match the support matrix's binary digest.
"""
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from toolkit import transport

RECIPE_FILE = 'build-recipe.json'
SUPPORT_MATRIX = Path(__file__).with_name('support-matrix.json')
TOOL_ENV = {'supabase-cli': 'MAZ_SUPABASE_BIN'}
TOOL_EXE = {'supabase-cli': 'supabase'}

# 〈定義：建置配方最低內容〉: each step and its required settings.
RECIPE_STEPS = {
    'source_build': ('source_digest', 'lockfiles', 'tools', 'build_commands', 'resources', 'download_policy'),
    'service_init': ('services', 'migrations', 'extensions'),
    'test_data': ('seed', 'tenants', 'accounts', 'roles', 'sharing_exceptions', 'related_resources', 'markers'),
    'auth': ('identities', 'token_transport', 'token_refresh', 'expiry_revocation_check'),
    'health': ('services_up', 'legit_operations'),
    'snapshot_reset': ('seed_version', 'reset_scope', 'reset_check', 'cleanup'),
}

ANON_PATH = 'anon API key in the apikey header -> data API (/rest/v1), role anon'
USER_PATH = ('password grant at /auth/v1/token -> access token in the Authorization: Bearer header '
             '-> data API (/rest/v1), role authenticated, RLS applies')


@dataclass(frozen=True)
class Blocked:
    """Preparation stopped; step names the BuildRecipe step that failed. detail keeps tool output."""
    step: str
    reason: str
    detail: str = ''


@dataclass
class Environment:
    """Live handles of a prepared stack. Holds tokens: keep inside the control area."""
    project_dir: Path
    project_id: str
    recipe: dict
    cli: str
    api_url: str = ''
    anon_key: str = ''
    tokens: dict = field(default_factory=dict)  # identity name -> {'access_token', 'refresh_token'}
    observer: dict = field(default_factory=dict)  # {'role', 'password'}; control area only (TK-IDN-005)
    api_keys: dict = field(default_factory=dict)  # public API key format -> key
    usable: bool = True

    @property
    def network(self):
        return f'maz_e1_{self.project_id}'


@dataclass(frozen=True)
class Ready:
    profile: dict
    env: Environment


class _Stop(Exception):
    def __init__(self, blocked):
        super().__init__(blocked.reason)
        self.blocked = blocked


class _CommandFailed(Exception):
    """A database or container command did not complete: it failed, timed out or could not be started."""


def _step(name, action, *args):
    """Run one BuildRecipe step. A command that does not complete blocks that step (TK-ENV-004,
    〈定義：建置配方最低內容〉 失敗時處理) instead of leaving prepare() or reset() as an exception."""
    try:
        return action(*args)
    except _CommandFailed as e:
        raise _Stop(Blocked(name, f'a command of this step did not complete: {type(e.__cause__ or e).__name__}',
                            str(e))) from e


# --- recipe and source ----------------------------------------------------------

def recipe_problems(recipe):
    """Missing steps and settings of a BuildRecipe, as 'step' or 'step.setting'."""
    if not isinstance(recipe, dict):
        return ['recipe must be a JSON object']
    problems = []
    for step, settings in RECIPE_STEPS.items():
        if not isinstance(recipe.get(step), dict):
            problems.append(step)
            continue
        problems += [f'{step}.{s}' for s in settings if s not in recipe[step]]
    return problems


# 〈定義：建置配方最低內容〉 資料庫命令中的配方值: the only recipe values that reach SQL the provisioning
# identity runs. A table is a plain identifier, optionally schema-qualified; an email has no quote,
# backslash, space or control character.
_SQL_IDENTIFIER = r'[A-Za-z_][A-Za-z0-9_]*'
_NAME = re.compile(_SQL_IDENTIFIER)
_TABLE = re.compile(rf'{_SQL_IDENTIFIER}(\.{_SQL_IDENTIFIER})?')
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+")


def _is_list_of(pattern, values):
    return isinstance(values, list) and all(isinstance(v, str) and pattern.fullmatch(v) for v in values)


def sql_value_problem(recipe):
    """(step, reason) for the first recipe value that would reach a database command without being a plain
    table name or email address (〈定義：建置配方最低內容〉, TK-ENV-004), or None. The values are never escaped
    into shape: a recipe that needs escaping is refused."""
    if not _is_list_of(_NAME, recipe['test_data']['related_resources']):
        return 'test_data', ('related_resources must list plain table names of the public schema '
                             '(letters, digits and underscores)')
    observer = recipe.get('observer')
    if observer is not None and not (isinstance(observer, dict) and _is_list_of(_TABLE, observer.get('select_on', []))):
        return 'auth', 'observer.select_on must list plain table names, optionally schema-qualified'
    identities = recipe['auth']['identities']
    if not (isinstance(identities, list) and all(isinstance(i, dict) and isinstance(i.get('name'), str)
                                                 for i in identities)):
        return 'auth', 'identities must be a list of objects, each with a name'
    emails = [i['email'] for i in identities if i.get('email')]
    if not _is_list_of(_EMAIL, emails):
        return 'auth', 'an identity email must be a plain email address without quotes or spaces'
    return None


MODE = 'E1'  # the environment mode this module provides (〈定義：測試授權紀錄〉 environment)


def load_recipe(project_dir):
    """Return (recipe, None) or (None, Blocked)."""
    path = Path(project_dir) / RECIPE_FILE
    if not path.is_file():
        return None, Blocked('recipe', f'no BuildRecipe ({RECIPE_FILE}); a confirmed recipe must be supplied by a person')
    try:
        recipe = json.loads(path.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return None, Blocked('recipe', f'BuildRecipe is not valid JSON: {e}')
    problems = recipe_problems(recipe)
    if problems:
        return None, Blocked('recipe', 'BuildRecipe is incomplete; missing: ' + ', '.join(problems))
    problem = sql_value_problem(recipe)
    if problem:
        return None, Blocked(*problem)
    return recipe, None


def source_digest(project_dir):
    """Digest of a sample project's source, for pinning in source_build.source_digest.

    Covers every file except the BuildRecipe itself and dot-directories, which
    hold tool state (the Supabase CLI writes supabase/.temp and supabase/.branches).
    """
    root = Path(project_dir)
    h = hashlib.sha256()
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root)
        if not path.is_file() or rel.as_posix() == RECIPE_FILE:
            continue
        if any(part.startswith('.') for part in rel.parts[:-1]):
            continue
        h.update(rel.as_posix().encode('utf-8') + b'\n')
        h.update(hashlib.sha256(path.read_bytes()).digest())
    return 'sha256:' + h.hexdigest()


def load_matrix(matrix=None):
    if matrix is not None:
        return matrix
    return json.loads(SUPPORT_MATRIX.read_text(encoding='utf-8'))


def _file_sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _trusted_tool(name, matrix):
    """Path of a tool whose binary digest matches the support matrix, or raise _Stop."""
    entry = matrix.get('tools', {}).get(name)
    if not entry or 'binary_sha256' not in entry:
        raise _Stop(Blocked('source_build', f'tool {name!r} is not in the support matrix'))
    path = os.environ.get(TOOL_ENV.get(name, ''), '') or shutil.which(TOOL_EXE.get(name, name))
    if not path or not Path(path).is_file():
        raise _Stop(Blocked('source_build', f'tool {name!r} not found (set {TOOL_ENV.get(name)} or PATH)'))
    if _file_sha256(path) != entry['binary_sha256']:
        raise _Stop(Blocked('source_build', f'tool {name!r} at {path} does not match the support matrix digest'))
    return path


def _check_source(project_dir, recipe, matrix):
    sb = recipe['source_build']
    pinned, actual = sb['source_digest'], source_digest(project_dir)
    if pinned != actual:
        raise _Stop(Blocked('source_build',
                            f'source_digest does not match the confirmed recipe (pinned {pinned}, found {actual})'))
    if not isinstance(sb['tools'], list) or not sb['tools']:
        raise _Stop(Blocked('source_build', 'tools must list the tools the recipe needs'))
    tools = {name: _trusted_tool(name, matrix) for name in sb['tools']}
    missing = [f for f in sb['lockfiles'] if not (Path(project_dir) / f).is_file()]
    if missing:
        raise _Stop(Blocked('source_build', f'lockfiles not found: {missing}'))
    if sb['build_commands']:
        raise _Stop(Blocked('source_build', 'build commands need the sandbox (TK-SBX-008); not supported yet'))
    return tools


# --- processes and HTTP ---------------------------------------------------------

def _run(cmd, timeout=900, stdin=None):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=stdin)
    except (subprocess.TimeoutExpired, OSError, UnicodeDecodeError) as e:
        raise _CommandFailed(f'{Path(cmd[0]).name} {cmd[1] if len(cmd) > 1 else ""}: {type(e).__name__}') from e


def _tail(text, lines=40):
    return '\n'.join(text.strip().splitlines()[-lines:])


def _http(method, url, headers=None, body=None, timeout=15):
    """Return (status, parsed JSON or text); (0, the reason) when there is no reply."""
    try:
        status, raw = transport.http(method, url, headers, body, timeout)
        raw = raw.decode()
    except (transport.RequestTimeout, transport.RequestFailed) as e:
        return 0, str(e)
    try:
        return status, json.loads(raw) if raw else None
    except json.JSONDecodeError:
        return status, raw


def _psql(env, sql):
    """Run SQL as the provisioning identity (postgres, inside the db container)."""
    try:
        r = transport.docker_exec(f'supabase_db_{env.project_id}',
                                  ['psql', '-U', 'postgres', '-d', 'postgres', '-At', '-v', 'ON_ERROR_STOP=1'],
                                  stdin=sql, timeout=60)
    except (subprocess.TimeoutExpired, OSError, UnicodeDecodeError) as e:
        raise _CommandFailed(f'psql: {type(e).__name__}') from e
    if r.returncode:
        raise _CommandFailed(_tail(r.stderr or r.stdout))
    return r.stdout


# --- steps ----------------------------------------------------------------------

def _project_config(project_dir):
    return tomllib.loads((Path(project_dir) / 'supabase' / 'config.toml').read_text(encoding='utf-8'))


def _check_migrations(project_dir, recipe):
    """〈定義：建置配方最低內容〉 服務初始化: verify migrations on disk match the recipe before starting the stack."""
    si = recipe['service_init']
    found = sorted(p.name for p in (project_dir / 'supabase' / 'migrations').glob('*.sql'))
    if found != sorted(si['migrations']):
        raise _Stop(Blocked('service_init', f'migrations on disk {found} differ from the recipe {sorted(si["migrations"])}; '
                                            'migrations are never skipped or added silently'))


def _start(env):
    si = env.recipe['service_init']
    _create_network(env)
    r = _run([env.cli, 'start', '--workdir', str(env.project_dir), '--network-id', env.network])
    if r.returncode:
        raise _Stop(Blocked('service_init', 'the stack failed to start (migrations and seed are applied at start)',
                            _tail(r.stdout + r.stderr)))
    _read_status(env)
    have = set(_psql(env, 'select extname from pg_extension;').split())
    missing = [e for e in si['extensions'] if e not in have]
    if missing:
        raise _Stop(Blocked('service_init', f'required extensions missing: {missing}'))


LOOPBACK_OPTION = 'com.docker.network.bridge.host_binding_ipv4'


def _create_network(env):
    """A dedicated network whose published ports bind to 127.0.0.1 only (TK-ENV-008).

    The CLI leaves the host IP empty, and on a user-defined network the default
    comes from this network option, not from the daemon's "ip" setting.
    """
    _run(['docker', 'network', 'rm', env.network], timeout=60)
    r = _run(['docker', 'network', 'create', '--driver', 'bridge', '--ipv6=false',
              '-o', f'{LOOPBACK_OPTION}=127.0.0.1', env.network], timeout=60)
    if r.returncode:
        raise _Stop(Blocked('service_init', f'cannot create the loopback-only network {env.network}',
                            _tail(r.stdout + r.stderr)))


def _read_status(env):
    r = _run([env.cli, 'status', '-o', 'json', '--workdir', str(env.project_dir)], timeout=120)
    try:
        status = json.loads(r.stdout[r.stdout.index('{'):])
    except ValueError:
        raise _Stop(Blocked('service_init', 'cannot read the stack status', _tail(r.stdout + r.stderr)))
    env.api_url = status.get('API_URL', '')
    env.anon_key = status.get('ANON_KEY') or status.get('PUBLISHABLE_KEY', '')
    # Public API keys in both formats (TK-DYN-004): legacy anon JWT and sb_publishable_.
    env.api_keys = {f: k for f, k in (('anon-jwt', status.get('ANON_KEY')),
                                      ('publishable', status.get('PUBLISHABLE_KEY'))) if k}
    if not env.api_url or not env.anon_key:
        raise _Stop(Blocked('service_init', 'stack status lacks the API URL or anon key'))


def _seeded_markers(env):
    return _psql(env, 'select title from public.documents order by title;').splitlines()  # one title a line: a title may hold spaces


def _check_test_data(env):
    td = env.recipe['test_data']
    have = set(_seeded_markers(env))
    missing = [m for m in td['markers'] if m not in have]
    if missing:
        raise _Stop(Blocked('test_data', f'seeded resources missing: {missing}; dependent cases are blocked, '
                                         'permissions are not guessed'))
    for table in td['related_resources']:
        if _psql(env, f'select count(*) from public.{table};').strip() == '0':
            raise _Stop(Blocked('test_data', f'related resource table {table!r} is empty'))


OBSERVER_ROLE = 'maz_observer'


def _create_observer(env):
    """Dedicated read-only login role for the observer (TK-IDN-012), created by the provisioning identity.

    BYPASSRLS lets it read every row of the judged tables without touching the
    application's own policies; it gets SELECT on recipe.observer.select_on only.
    """
    tables = (env.recipe.get('observer') or {}).get('select_on') or []
    if not tables:
        return
    password = secrets.token_urlsafe(24)
    grants = ''.join(f'grant select on {t} to {OBSERVER_ROLE};\n' for t in tables)
    schemas = sorted({t.split('.')[0] for t in tables})
    usage = ''.join(f'grant usage on schema {s} to {OBSERVER_ROLE};\n' for s in schemas)
    try:
        _psql(env, f"""
do $$ begin
  if exists (select 1 from pg_roles where rolname = '{OBSERVER_ROLE}') then
    execute 'drop owned by {OBSERVER_ROLE}';
    execute 'drop role {OBSERVER_ROLE}';
  end if;
end $$;
create role {OBSERVER_ROLE} login password '{password}' bypassrls nosuperuser nocreatedb nocreaterole noinherit;
{usage}{grants}""")
    except _CommandFailed as e:
        raise _Stop(Blocked('auth', f'cannot create the observer role {OBSERVER_ROLE}', str(e))) from e
    env.observer = {'role': OBSERVER_ROLE, 'password': password, 'select_on': list(tables),
                    'host': _db_address(env)}


def _db_address(env):
    """The db container's address on the toolkit network.

    The image trusts connections to 127.0.0.1 inside the container without a
    password; connections to this address use scram-sha-256, so the observer
    really authenticates as its own role.
    """
    r = _run(['docker', 'inspect', '-f', '{{json .NetworkSettings.Networks}}', f'supabase_db_{env.project_id}'],
             timeout=60)
    try:
        address = json.loads(r.stdout)[env.network]['IPAddress']
    except (json.JSONDecodeError, KeyError, TypeError):
        address = ''
    if not address:
        raise _Stop(Blocked('auth', f'cannot find the db address on {env.network} for the observer'))
    return address


def _login(env, name, email, password):
    status, body = _http('POST', f'{env.api_url}/auth/v1/token?grant_type=password',
                         {'apikey': env.anon_key}, {'email': email, 'password': password})
    if status != 200 or not isinstance(body, dict) or 'access_token' not in body:
        raise _Stop(Blocked('auth', f'{name}: login failed (HTTP {status}); no other identity is substituted',
                            json.dumps(body, ensure_ascii=False)[:2000]))
    return body


def _check_auth(env):
    for ident in env.recipe['auth']['identities']:
        name, email = ident['name'], ident.get('email')
        if not email:
            continue
        password = secrets.token_urlsafe(24)  # per-environment, held in memory only
        updated = _psql(env, f"update auth.users set encrypted_password = extensions.crypt('{password}', "
                             f"extensions.gen_salt('bf')) where email = '{email}' returning id;")
        if not updated.strip():
            raise _Stop(Blocked('auth', f'{name}: account {email} not found in the seeded data'))
        tokens = _login(env, name, email, password)
        status, refreshed = _http('POST', f'{env.api_url}/auth/v1/token?grant_type=refresh_token',
                                  {'apikey': env.anon_key}, {'refresh_token': tokens['refresh_token']})
        if status != 200 or 'access_token' not in (refreshed or {}):
            raise _Stop(Blocked('auth', f'{name}: token refresh failed (HTTP {status})'))
        env.tokens[name] = {'access_token': refreshed['access_token'], 'refresh_token': refreshed['refresh_token']}


def _headers(env, identity):
    h = {'apikey': env.anon_key}
    if identity in env.tokens:
        h['Authorization'] = 'Bearer ' + env.tokens[identity]['access_token']
    return h


def _check_health(env):
    up = {}
    for service in env.recipe['health']['services_up']:
        path = {'rest': '/rest/v1/', 'auth': '/auth/v1/health'}.get(service)
        if not path:
            raise _Stop(Blocked('health', f'no health check known for service {service!r}'))
        up[service], _ = _http('GET', env.api_url + path, {'apikey': env.anon_key})
    down = {s: c for s, c in up.items() if c != 200}
    if down:
        raise _Stop(Blocked('health', f'services not available: {down}'))
    results = []
    for op in env.recipe['health']['legit_operations']:
        status, rows = _http('GET', f"{env.api_url}/rest/v1/{op['read']}?select=title&title=eq.{op['marker']}",
                             _headers(env, op['identity']))
        ok = status == 200 and rows == [{'title': op['marker']}]
        results.append({'identity': op['identity'], 'read': op['read'], 'marker': op['marker'], 'ok': ok})
        if not ok:
            raise _Stop(Blocked('health', f"legit operation failed: {op['identity']} cannot read {op['marker']} "
                                          f"(HTTP {status}); a reachable API is not enough to pass"))
    return {'services_up': up, 'legit_operations': results}


# --- EnvironmentProfile -----------------------------------------------------------

def _containers(env):
    r = _run(['docker', 'ps', '--format', '{{.Names}}\t{{.Image}}\t{{.Ports}}'], timeout=60)
    suffix = '_' + env.project_id
    out = {}
    for line in r.stdout.splitlines():
        name, image, ports = (line.split('\t') + ['', ''])[:3]
        if name.startswith('supabase_') and name.endswith(suffix):
            out[name[len('supabase_'):-len(suffix)]] = {'image': image, 'ports': ports}
    return out


def _image_digest(image):
    r = _run(['docker', 'image', 'inspect', '--format', '{{json .RepoDigests}}', image], timeout=60)
    try:
        digests = json.loads(r.stdout)
    except json.JSONDecodeError:
        return ''
    return digests[0].split('@', 1)[1] if digests else ''


def _profile(env, tools, matrix, health):
    services = {}
    for svc, c in _containers(env).items():
        services[svc] = {'image': c['image'], 'image_digest': _image_digest(c['image']), 'ports': c['ports']}
    cli_entry = matrix['tools']['supabase-cli']
    version = _run([tools['supabase-cli'], '--version'], timeout=60).stdout.strip()
    engine = _run(['docker', 'version', '--format', '{{.Server.Version}}'], timeout=60).stdout.strip()
    config = _project_config(env.project_dir)
    disabled = sorted(k for k, v in config.items() if isinstance(v, dict) and v.get('enabled') is False)
    identities = {}
    for ident in env.recipe['auth']['identities']:
        name = ident['name']
        identities[name] = ({'path': ANON_PATH, 'login': 'none'} if 'email' not in ident
                            else {'path': USER_PATH, 'login': 'ok', 'account': ident['email']})
    unsupported = []
    if version != cli_entry['version']:
        unsupported.append(f'supabase-cli {version} (matrix {cli_entry["version"]})')
    engine_entry = matrix['tools'].get('docker-engine', {})
    if engine != engine_entry.get('version'):
        unsupported.append(f'docker-engine {engine} (matrix {engine_entry.get("version")})')
    for svc, s in services.items():
        pinned = matrix.get('services', {}).get(svc) or {}
        if (pinned.get('image'), pinned.get('digest')) != (s['image'], s['image_digest']):
            unsupported.append(f'service {svc} {s["image"]}@{s["image_digest"]} '
                               f'(matrix {pinned.get("image")}@{pinned.get("digest")})')
    return {
        'profile_version': '1',
        'mode': MODE,
        'sample': env.recipe.get('sample', ''),
        'source_digest': env.recipe['source_build']['source_digest'],
        'seed_version': env.recipe['snapshot_reset']['seed_version'],
        'tools': {'supabase-cli': {'version': version, 'binary_sha256': cli_entry['binary_sha256']},
                  'docker-engine': {'version': engine}},
        'services': services,
        'identities': identities,
        'health': health,
        'observer': ({'role': env.observer['role'], 'select_on': env.observer['select_on'], 'bypassrls': True}
                     if env.observer else None),
        'unsupported': unsupported,
        'known_differences': [f'service disabled in this stack: {d}' for d in disabled] + [
            'E1 local stack: no cloud network, real third-party identity or hosted-only limits; '
            'results here do not imply E2 or production (TK-ENV-007)',
        ],
    }


# --- interface ------------------------------------------------------------------

def prepare(project_dir, matrix=None):
    """Prepare an E1 stack for the project's BuildRecipe. Returns Ready or Blocked."""
    project_dir = Path(project_dir).resolve()
    recipe, blocked = load_recipe(project_dir)
    if blocked:
        return blocked
    matrix = load_matrix(matrix)
    env = None
    try:
        tools = _check_source(project_dir, recipe, matrix)
        _check_migrations(project_dir, recipe)
        env = Environment(project_dir, _project_config(project_dir)['project_id'], recipe, tools['supabase-cli'])
        _step('service_init', _start, env)
        _step('test_data', _check_test_data, env)
        _step('auth', _create_observer, env)
        _step('auth', _check_auth, env)
        health = _step('health', _check_health, env)
        return Ready(_step('health', _profile, env, tools, matrix, health), env)
    except _Stop as stop:
        if env is not None:
            _stop_quietly(env)
        return stop.blocked
    except BaseException:  # an interrupt (Ctrl-C) too: a started stack is never left running (TK-ENV-003)
        if env is not None:
            _stop_quietly(env)
        raise


def reset(env, matrix=None):
    """Re-apply migrations and seed, verify the result and log the identities in again.

    Returns a fresh Ready (the reset invalidates every session). If anything
    fails, the environment is isolated (stopped) and must not be reused.
    """
    if env.recipe['snapshot_reset'].get('reset_scope') == 'none':
        return Blocked('snapshot_reset', 'the BuildRecipe declares no reset (reset_scope "none"); nothing was touched')
    if not env.usable:
        return Blocked('snapshot_reset', 'environment was isolated earlier and must not be reused')
    matrix = load_matrix(matrix)
    try:
        return _step('snapshot_reset', _reset, env, matrix)
    except _Stop as stop:  # TK-SBX-010: whatever failed, the environment is isolated and not reused
        _stop_quietly(env)
        return Blocked('snapshot_reset', stop.blocked.reason, stop.blocked.detail)
    except BaseException:
        _stop_quietly(env)
        raise


def _reset(env, matrix):
    r = _run([env.cli, 'db', 'reset', '--workdir', str(env.project_dir), '--network-id', env.network])
    if r.returncode:
        raise _Stop(Blocked('snapshot_reset', 'reset failed; environment isolated, later cases stop',
                            _tail(r.stdout + r.stderr)))
    expected = sorted(env.recipe['test_data']['markers'])
    found = _seeded_markers(env)
    if found != expected:
        raise _Stop(Blocked('snapshot_reset', f'reset check failed: found {found}, expected {expected}; '
                                              'environment isolated'))
    env.tokens.clear()
    _create_observer(env)
    _check_auth(env)
    health = _check_health(env)
    return Ready(_profile(env, {'supabase-cli': env.cli}, matrix, health), env)


def _stop_stack(env):
    env.usable = False
    _run([env.cli, 'stop', '--no-backup', '--workdir', str(env.project_dir)], timeout=300)
    _run(['docker', 'network', 'rm', env.network], timeout=60)


def _stop_quietly(env):
    """Stop the stack on a failure path. The environment is marked unusable first, and a stop command that
    does not complete does not replace the failure being handled."""
    env.usable = False
    try:
        _stop_stack(env)
    except _CommandFailed:
        pass


def destroy(env):
    """Stop the stack and remove its containers and volumes."""
    _stop_stack(env)
