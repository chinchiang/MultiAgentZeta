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

from toolkit import forward, transport

RECIPE_FILE = 'build-recipe.json'
SUPPORT_MATRIX = Path(__file__).with_name('support-matrix.json')
TOOL_ENV = {'supabase-cli': 'MAZ_SUPABASE_BIN'}
TOOL_EXE = {'supabase-cli': 'supabase'}

# 〈定義：建置配方最低內容〉: each step and its required settings.
RECIPE_STEPS = {
    'source_build': ('source_digest', 'lockfiles', 'tools', 'build_commands', 'resources', 'download_policy'),
    'service_init': ('services', 'migrations', 'extensions'),
    'test_data': ('seed', 'tenants', 'accounts', 'roles', 'sharing_exceptions', 'related_resources', 'markers',
                  'synthetic_statement'),
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
    relays: list = field(default_factory=list)  # forward.Relay: the host's way into the internal network
    isolation: dict = field(default_factory=dict)  # 〈定義：E1 隔離〉: what was checked after the last start

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

# 〈定義：必要輸入〉 部署資訊, besides the build method (source_build) and the external services
# (service_init.services): the names of the environment variables the application needs, never their values,
# and the test substitutes of its external services. Both are stated, as an empty list when there are none.
DEPLOYMENT = ('environment_variables', 'test_substitutes')
SUBSTITUTE_FIELDS = ('service', 'substitute')


def deployment_problem(recipe):
    """Why the deployment information of a recipe cannot be used, or None. A name of an environment variable is
    a name: anything with a value in it is refused, so that no secret is written into a recipe (TK-IDN-005)."""
    deployment = recipe['deployment']
    names = deployment['environment_variables']
    if not _is_list_of(_NAME, names):
        return ('deployment.environment_variables must list variable names only (letters, digits and underscores): '
                'a recipe never holds a value')
    substitutes = deployment['test_substitutes']
    if not (isinstance(substitutes, list) and all(
            isinstance(s, dict) and all(_filled(s.get(f)) for f in SUBSTITUTE_FIELDS) for s in substitutes)):
        return 'deployment.test_substitutes must list objects with ' + ' and '.join(SUBSTITUTE_FIELDS)
    return None


def deployment_differences(recipe):
    """〈定義：必要輸入〉 部署資訊 標示環境差異: what the E1 stack does not give the application, from what its recipe
    declares. The stack runs no application process, so no declared variable is set in it."""
    deployment = recipe['deployment']
    return [f'environment variable {name} is declared by the application and is not set in this stack: what '
            f'depends on it is not exercised' for name in deployment['environment_variables']] + [
            f'external service {s["service"]} is replaced by the test substitute {s["substitute"]}: its real '
            f'behaviour is not verified' for s in deployment['test_substitutes']]


def recipe_problems(recipe):
    """Missing steps and settings of a BuildRecipe, as 'step' or 'step.setting'."""
    if not isinstance(recipe, dict):
        return ['recipe must be a JSON object']
    problems = []
    for step, settings in {**RECIPE_STEPS, 'deployment': DEPLOYMENT}.items():
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
    unstated = [i['name'] for i in identities if i.get('email') and not (isinstance(i.get('login'), str) and i['login'].strip())]
    if unstated:  # 〈定義：認證與登入方式〉: the way an identity logs in is stated, never guessed
        return 'auth', f'identities {", ".join(unstated)} do not state how they log in (login); it is not guessed'
    return None


# 〈定義：認證與登入方式〉 (TK-ENV-005): the one way of logging in this version automates, in the E1 stack's own
# auth service. Every other way (SSO, OAuth, multi-factor, anything by hand) needs a person: the identity
# is blocked, and no other identity or way of logging in stands in for it.
AUTOMATED_LOGIN = 'password'
UNVERIFIED_AUTHENTICATION = (
    'authentication goes through the local auth service of the E1 stack by password: the production identity '
    "provider's SSO or OAuth configuration, multi-factor authentication and third-party identities are not "
    'verified (TK-ENV-005)')


def login_problem(identity):
    """Why an identity of the recipe is not logged in by the toolkit, or None (TK-ENV-005)."""
    if 'email' not in identity or identity['login'] == AUTOMATED_LOGIN:
        return None
    return (f'login {identity["login"]!r} needs a person or is not automated in this version; the identity is not '
            f'logged in and nothing stands in for it')


# TK-SBX-012 [R59]: the names reserved for testing and documentation, where no real mailbox can exist.
RESERVED_TLDS = ('test', 'example', 'invalid', 'localhost')
RESERVED_DOMAINS = ('example.com', 'example.net', 'example.org')
STATEMENT_FIELDS = ('method', 'confirmed_by', 'confirmed_at')  # TK-SBX-011: 產生方式, 確認者, 確認時間
EXCEPTION_FIELDS = ('account', 'reason', 'confirmed_by', 'confirmed_at')  # TK-SBX-012 網域例外


def in_reserved_domain(email):
    """Whether an email address is in a domain reserved for testing (TK-SBX-012)."""
    domain = email.rpartition('@')[2].lower().rstrip('.')
    return bool(domain) and (domain.rpartition('.')[2] in RESERVED_TLDS
                             or any(domain == d or domain.endswith('.' + d) for d in RESERVED_DOMAINS))


def _filled(value):
    return isinstance(value, str) and bool(value.strip())


def test_data_problem(project_dir, recipe):
    """Why the test data of a recipe may not be used, or None (TK-SBX-011, TK-SBX-012): the statement that it is
    synthetic, by a person, with every field; every test account in a reserved domain unless a complete domain
    exception names it; the seed file inside the source under test, which no exception waives. Whether the data
    is synthetic is the confirmer's statement, never inferred here (TK-SCP-003)."""
    td = recipe['test_data']
    statement = td['synthetic_statement']
    if not isinstance(statement, dict):
        return 'synthetic_statement must be an object with ' + ', '.join(STATEMENT_FIELDS)
    missing = [f for f in STATEMENT_FIELDS if not _filled(statement.get(f))]
    if missing:
        return 'synthetic_statement lacks ' + ', '.join(missing)
    exceptions = td.get('domain_exceptions', [])
    if not isinstance(exceptions, list):
        return 'domain_exceptions must be a list'
    for i, e in enumerate(exceptions):
        lacking = list(EXCEPTION_FIELDS) if not isinstance(e, dict) else [f for f in EXCEPTION_FIELDS if not _filled(e.get(f))]
        if lacking:
            return f'domain_exceptions[{i}] lacks {", ".join(lacking)}; an incomplete exception exempts nothing'
    exempt = {e['account'] for e in exceptions}
    accounts = td['accounts']
    if not (isinstance(accounts, list) and all(isinstance(a, str) for a in accounts)):
        return 'accounts must be a list of email addresses'
    emails = accounts + [i['email'] for i in recipe['auth']['identities'] if i.get('email')]
    outside = sorted({a for a in emails if a not in exempt and not in_reserved_domain(a)})
    if outside:
        return (f'test accounts outside the reserved domains: {", ".join(outside)}; use .test, .example, .invalid, '
                f'.localhost or example.com/.net/.org, or have a person confirm a domain exception')
    seed = td['seed']
    root = Path(project_dir).resolve()
    if not _filled(seed) or root not in (root / seed).resolve().parents:
        return f'the seed file {seed!r} is not inside the source under test; a domain exception does not waive this'
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
    problem = deployment_problem(recipe)
    if problem:
        return None, Blocked('recipe', problem)
    problem = test_data_problem(project_dir, recipe)
    if problem:
        return None, Blocked('test_data', problem)
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
    _open_relays(env)
    r = _run([env.cli, 'start', '--workdir', str(env.project_dir), '--network-id', env.network])
    if r.returncode:
        raise _Stop(Blocked('service_init', 'the stack failed to start (migrations and seed are applied at start)',
                            _tail(r.stdout + r.stderr)))
    _read_status(env)
    env.isolation = _check_isolation(env)
    have = set(_psql(env, 'select extname from pg_extension;').split())
    missing = [e for e in si['extensions'] if e not in have]
    if missing:
        raise _Stop(Blocked('service_init', f'required extensions missing: {missing}'))


LOOPBACK_OPTION = 'com.docker.network.bridge.host_binding_ipv4'

# 〈定義：E1 隔離〉 宿主機入口: the two ports the CLI and the toolkit use, and the container port behind each.
RELAYED = (('api', 54321, 'kong', 8000), ('db', 54322, 'db', 5432))
ISOLATION_LIMITS = (
    'containers share the host kernel: container isolation is not full isolation (TK-SBX-007)',
    'no CPU, memory, process or disk limit is set on the stack containers (TK-SBX-003)',
    'the db container holds the database the observer role lives in (TK-IDN-005)',
)


def _create_network(env):
    """A dedicated internal network (TK-SBX-004, TK-ENV-008, 〈定義：E1 隔離〉): Docker drops traffic between an
    internal network and every other network, resolves no outside name on it and publishes no port from it.

    The loopback option stays so that a port could only ever be published on 127.0.0.1.
    """
    _run(['docker', 'network', 'rm', env.network], timeout=60)
    r = _run(['docker', 'network', 'create', '--driver', 'bridge', '--ipv6=false', '--internal',
              '-o', f'{LOOPBACK_OPTION}=127.0.0.1', env.network], timeout=60)
    if r.returncode:
        raise _Stop(Blocked('service_init', f'cannot create the internal network {env.network}',
                            _tail(r.stdout + r.stderr)))


def _address(env, service):
    """The address of a stack container on the toolkit network; '' when it is not there (yet)."""
    try:
        r = _run(['docker', 'inspect', '-f', '{{json .NetworkSettings.Networks}}',
                  f'supabase_{service}_{env.project_id}'], timeout=60)
        return json.loads(r.stdout)[env.network]['IPAddress'] or ''
    except (_CommandFailed, json.JSONDecodeError, KeyError, TypeError):
        return ''


def _open_relays(env):
    """〈定義：E1 隔離〉 宿主機入口: listen on 127.0.0.1 where the CLI and the toolkit expect the API and the
    database, before the stack starts (the CLI applies migrations through the database port)."""
    _close_relays(env)
    config = _project_config(env.project_dir)
    for section, default, service, inner in RELAYED:
        port = (config.get(section) or {}).get('port', default)
        try:
            env.relays.append(forward.Relay(port, lambda service=service: _address(env, service), inner))
        except (OSError, OverflowError, TypeError) as e:
            raise _Stop(Blocked('service_init', f'cannot listen on 127.0.0.1:{port} for the {service} service: '
                                                f'{type(e).__name__}', str(e))) from e


def _close_relays(env):
    for relay in env.relays:
        relay.close()
    env.relays.clear()


def _inside(path, directory):
    return path == directory or directory in path.parents


def isolation_problems(network, containers, env_network, project_dir, toolkit_dir):
    """〈定義：E1 隔離〉 啟動後檢查: what makes a started stack unfit to be tested, from `docker network inspect`
    and `docker inspect` output. An empty list means every check held.

    The network is internal (TK-SBX-004); every container is unprivileged (TK-SBX-002), attached to that network
    only, publishes no port (TK-ENV-008), and mounts nothing from the host but files of the project under test:
    not the Docker control socket (TK-SBX-001) and nothing of the control area (TK-SBX-005)."""
    problems = []
    if not isinstance(network, dict) or network.get('Internal') is not True:
        problems.append(f'network {env_network} is not internal')
    if not isinstance(containers, list) or not containers:
        return problems + ['no stack container could be inspected']
    for c in containers:
        if not isinstance(c, dict):
            problems.append('a container could not be inspected')
            continue
        name = str(c.get('Name', '?')).lstrip('/')
        host = c.get('HostConfig') if isinstance(c.get('HostConfig'), dict) else {}
        settings = c.get('NetworkSettings') if isinstance(c.get('NetworkSettings'), dict) else {}
        if host.get('Privileged') is not False:
            problems.append(f'{name}: runs privileged')
        networks = sorted(settings.get('Networks') or {})
        if networks != [env_network]:
            problems.append(f'{name}: attached to {networks}, not to {env_network} only')
        published = [p for p, bound in (settings.get('Ports') or {}).items() if bound]
        if published:
            problems.append(f'{name}: publishes {sorted(published)}')
        mounts = c.get('Mounts')
        if not isinstance(mounts, list):
            problems.append(f'{name}: mounts could not be read')
            continue
        for m in mounts:
            m = m if isinstance(m, dict) else {}
            source, kind = str(m.get('Source', '')), m.get('Type')
            if source.endswith('docker.sock') or str(m.get('Destination', '')).endswith('docker.sock'):
                problems.append(f'{name}: mounts the Docker control socket')
            elif kind in ('volume', 'tmpfs'):
                continue
            else:
                path = Path(source)
                if not source or not _inside(path, project_dir) or _inside(path, toolkit_dir) or _inside(toolkit_dir, path):
                    problems.append(f'{name}: mounts {source or "an unknown source"} from the host, '
                                    'outside the project under test')
    return problems


def _check_isolation(env):
    """Check the started stack against 〈定義：E1 隔離〉 and return the isolation record of the profile."""
    services = sorted(_containers(env))
    names = [f'supabase_{s}_{env.project_id}' for s in services]
    try:
        network = json.loads(_run(['docker', 'network', 'inspect', env.network], timeout=60).stdout)[0]
        containers = json.loads(_run(['docker', 'inspect', *names], timeout=60).stdout) if names else []
    except (json.JSONDecodeError, IndexError, KeyError, TypeError):
        raise _Stop(Blocked('service_init', 'cannot inspect the stack to check its isolation'))
    problems = isolation_problems(network, containers, env.network, env.project_dir, Path(__file__).resolve().parent)
    if len(containers) != len(names):
        problems.append('not every stack container could be inspected')
    if problems:
        raise _Stop(Blocked('service_init', 'the started stack is not isolated as required; it was stopped',
                            '\n'.join(problems)))
    return {'outbound': 'blocked', 'method': 'internal-network',
            'host_access': [f'127.0.0.1:{r.port} -> {service}:{r.inner_port}'
                            for r, (_, _, service, _) in zip(env.relays, RELAYED)],
            'containers_checked': services,
            'limits': list(ISOLATION_LIMITS)}


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
    address = _address(env, 'db')
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
    """Log in every identity whose login this version automates. Resetting the password of a test account is
    provisioning that identity's own credential on synthetic data; no control of the application is changed
    (〈定義：認證與登入方式〉)."""
    for ident in env.recipe['auth']['identities']:
        if ident.get('email') and not login_problem(ident):
            _open_session(env, ident['name'], ident['email'])


def _open_session(env, name, email):
    """Give the identity a new password, log it in and keep its refreshed session."""
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


def relogin(env, name):
    """〈定義：故障注入〉 影響限於該案例: give an identity whose session a fault ended a new one. Returns Blocked when
    it cannot; the identity then has no session at all, so a later case that needs it is blocked at its identity
    check instead of running with a session nobody can vouch for."""
    identity = next((i for i in env.recipe['auth']['identities'] if i['name'] == name), {})
    email = identity.get('email')
    env.tokens.pop(name, None)
    if not email or login_problem(identity):
        return None  # an anonymous identity, or one the toolkit does not log in, has no session to give back
    try:
        _step('auth', _open_session, env, name, email)
    except _Stop as stop:
        return stop.blocked
    return None


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


def _without_registry(image):
    """An image reference without its registry host: 'ghcr.io/supabase/kong:2.8.1' -> 'supabase/kong:2.8.1'.
    The first component is a host when it has a dot or a port, or is localhost."""
    first, _, rest = image.partition('/')
    return rest if rest and ('.' in first or ':' in first or first == 'localhost') else image


def service_in_matrix(pinned, image, digest):
    """Whether a running service image is the one the support matrix pins (TK-SCP-001, 〈定義：建置配方最低內容〉
    服務初始化與版本核對): the same repository, tag and content digest. The registry host is not compared: the
    CLI pulls from a mirror registry when its first one fails, and a digest names the same content wherever it
    was pulled from. Without a digest on both sides nothing is known to be the same."""
    pinned = pinned or {}
    return bool(digest) and digest == pinned.get('digest') and isinstance(pinned.get('image'), str) and (
        _without_registry(pinned['image']) == _without_registry(image))


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
        if login_problem(ident):  # TK-ENV-005: blocked, with its reason; no path is claimed for it
            identities[name] = {'path': f'not logged in: login {ident["login"]!r} is not automated', 'login': 'blocked',
                                'account': ident['email'], 'reason': login_problem(ident)}
            continue
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
        if not service_in_matrix(pinned, s['image'], s['image_digest']):
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
        'isolation': env.isolation,
        # TK-SBX-011, TK-SBX-012: who says the data is synthetic, and the accounts a person let out of the
        # reserved domains.
        'test_data': {'synthetic_statement': {f: env.recipe['test_data']['synthetic_statement'][f] for f in STATEMENT_FIELDS},
                      'domain_exceptions': [{f: e[f] for f in EXCEPTION_FIELDS}
                                            for e in env.recipe['test_data'].get('domain_exceptions', [])]},
        'unsupported': unsupported,
        'deployment': {'environment_variables': list(env.recipe['deployment']['environment_variables']),
                       'test_substitutes': [{f: s[f] for f in SUBSTITUTE_FIELDS}
                                            for s in env.recipe['deployment']['test_substitutes']]},
        # 〈定義：必要輸入〉 部署資訊: what the E1 stack does not give the application, as the recipe declares it
        'known_differences': [f'service disabled in this stack: {d}' for d in disabled] + deployment_differences(env.recipe) + [
            UNVERIFIED_AUTHENTICATION,
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
    env.isolation = _check_isolation(env)  # the reset restarts containers: what was checked is checked again
    env.tokens.clear()
    _create_observer(env)
    _check_auth(env)
    health = _check_health(env)
    return Ready(_profile(env, {'supabase-cli': env.cli}, matrix, health), env)


def _stop_stack(env):
    """Stop the stack, remove its network and close the relays. Returns what the commands said went wrong, as
    text; whether anything is left is for _leftovers() to say."""
    env.usable = False
    said = []
    try:
        for cmd, timeout in (([env.cli, 'stop', '--no-backup', '--workdir', str(env.project_dir)], 300),
                             (['docker', 'network', 'rm', env.network], 60)):
            try:
                r = _run(cmd, timeout=timeout)
                if r.returncode:
                    said.append(f'{Path(cmd[0]).name} {cmd[1]}: exit {r.returncode}: {_tail(r.stdout + r.stderr, 5)}')
            except _CommandFailed as e:
                said.append(str(e))
    finally:
        _close_relays(env)
    return said


def _stop_quietly(env):
    """Stop the stack on a failure path. The environment is marked unusable first, and a stop command that
    does not complete does not replace the failure being handled."""
    env.usable = False
    _stop_stack(env)


def _leftovers(env):
    """〈定義：中止與清理〉 銷毀的查證: the containers, volumes and network of this stack that Docker still lists.
    What cannot be listed is reported as not checked: a stack that cannot be seen is not known to be gone."""
    suffix, found = '_' + env.project_id, []
    for kind, args, mine in (
            ('container', ['ps', '-a', '--format', '{{.Names}}'], lambda n: n.startswith('supabase_') and n.endswith(suffix)),
            ('volume', ['volume', 'ls', '--format', '{{.Name}}'], lambda n: n.startswith('supabase_') and n.endswith(suffix)),
            ('network', ['network', 'ls', '--format', '{{.Name}}'], lambda n: n == env.network)):
        try:
            r = _run(['docker', *args], timeout=60)
        except _CommandFailed as e:
            found.append(f'{kind}s not checked: {e}')
            continue
        if r.returncode:
            found.append(f'{kind}s not checked: docker exit {r.returncode}')
            continue
        found += [f'{kind} {n}' for n in sorted(r.stdout.split()) if mine(n)]
    return found


def destroy(env):
    """Stop the stack, remove its containers, volumes and network, and check that they are gone (TK-ENV-003,
    〈定義：中止與清理〉). Returns what is left, as text: an empty list means the environment no longer exists.
    Whatever is left, the environment is never used again (TK-SBX-010)."""
    said = _stop_stack(env)
    left = _leftovers(env)
    return left + [f'while stopping: {x}' for x in said] if left else []
