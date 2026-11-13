"""A stack that answers from a script: the scripted adapter of toolkit.environment's transport seam.

Instead of urllib and `docker exec`, the transport reads what a test wrote. A test builds a World (what the
data API and the observer's database answer, and what an actor's attempt changes), hands scan.run() a
`prepare` that returns it, and runs a ScanManifest through the real code on top of the transport: the request
handling, the observer's reading of psql output, the fault injection and the judgement. It does not model a
security policy: a World answers as its test says, and whether a real policy answers so stays with the
environment tests against a real Supabase stack.
"""
import json
import subprocess
from dataclasses import dataclass, field

from toolkit import e1, environment

OBSERVER_ROLE = 'maz_observer'
OBSERVER_PASSWORD = 'observer-secret'
EMAILS = {'owner': 'owner@example.test', 'other_tenant_user': 'carol@example.test'}


@dataclass
class World:
    """What the stack answers. `rows` is the table of documents by title: (owner, tenant, shared, digest).
    An actor's attempt is answered by `attempt` (status, body); `mutates` says whether it also changes the
    table, which only the observer can see."""
    rows: dict = field(default_factory=lambda: {'MARK-A-ALICE-PRIVATE': ('alice', 'tenant-a', 'f', 'digest-0')})
    attempt: tuple = (200, [])
    mutates: bool = False
    observer_error: Exception | None = None  # raised by every observer query (a timeout, a missing tool)
    observer_text: str | None = None  # replaces the table query's output, e.g. text in the wrong shape
    http_error: Exception | None = None  # raised by every request of the data API
    revoked: set = field(default_factory=set)  # session tokens a logout ended
    http_calls: list = field(default_factory=list)
    exec_calls: list = field(default_factory=list)


class Transport:
    """toolkit.transport's interface, answered by a World."""

    def __init__(self, world):
        self.world = world

    def http(self, method, url, headers, body, timeout):
        w = self.world
        w.http_calls.append((method, url, dict(headers or {}), body))
        if w.http_error:
            raise w.http_error
        host, path = url.split('://', 1)[1].split('/', 1)
        if host.startswith('127.0.0.1:'):  # the closed port of the api-unreachable fault
            raise environment.RequestFailed(f'{method} /{path}: connection refused')
        who = (headers or {}).get('Authorization', '').removeprefix('Bearer ')
        if path.startswith('auth/v1/user'):
            email = EMAILS.get(who.removeprefix('token-'))
            return (200, json.dumps({'email': email}).encode()) if email and who not in w.revoked else (
                401, b'{"message":"no session"}')
        if path.startswith('auth/v1/logout'):
            w.revoked.add(who)
            return 204, b''
        title = path.split('title=eq.', 1)[1].split('&', 1)[0] if 'title=eq.' in path else None
        if who == 'token-owner':  # the owner's control operation
            return 200, json.dumps([{'title': title, 'body': 'b'}]).encode()
        status, data = w.attempt
        if w.mutates and method != 'GET':
            w.rows[title] = ('alice', 'tenant-a', 'f', 'digest-changed')
        return status, json.dumps(data).encode() if data is not None else b''

    def docker_exec(self, container, command, env=None, stdin=None, timeout=60):
        w = self.world
        w.exec_calls.append((container, list(command)))
        if w.observer_error:
            raise w.observer_error
        if timeout < 0.001:  # a time limit no read can meet (the observer-timeout fault)
            raise subprocess.TimeoutExpired(command, timeout)
        if (env or {}).get('PGPASSWORD') != OBSERVER_PASSWORD:
            return subprocess.CompletedProcess(command, 2, '', 'password authentication failed for user')
        sql = command[-1]
        if 'where title =' in sql:
            title = sql.split("title = '", 1)[1].split("'", 1)[0]
            row = w.rows.get(title)
            out = '\t'.join(row) if row else ''
        else:
            out = w.observer_text if w.observer_text is not None else f'{len(w.rows)}\t' + '|'.join(
                f'{t}:{v[3]}' for t, v in sorted(w.rows.items()))
        return subprocess.CompletedProcess(command, 0, out + '\n' if out else '', '')


class Lifecycle:
    """e1's reset and destroy, recorded instead of touching Docker. reset_fails: the reset cannot restore the seed."""

    def __init__(self, reset_fails=False):
        self.calls, self.reset_fails = [], reset_fails

    def reset(self, env):
        self.calls.append('reset')
        return e1.Blocked('snapshot_reset', 'scripted reset failed') if self.reset_fails else e1.Ready({}, env)

    def destroy(self, env):
        self.calls.append('destroy')


def handles(api_keys=None):
    """The live handles of a stack: the session tokens of the identities, the observer's login and the API keys."""
    recipe = {'auth': {'identities': [{'name': n, 'email': EMAILS[n]} for n in EMAILS] + [{'name': 'anonymous'}],
                       'token_transport': 'Authorization: Bearer header'},
              'snapshot_reset': {'reset_scope': 'full'}}
    return e1.Environment(
        project_dir='.', project_id='scripted', recipe=recipe, cli='', api_url='http://scripted.test',
        tokens={n: {'access_token': f'token-{n}', 'refresh_token': 'r'} for n in EMAILS},
        observer={'role': OBSERVER_ROLE, 'password': OBSERVER_PASSWORD, 'host': '10.0.0.2'},
        api_keys={'anon-jwt': 'anon-key', 'publishable': 'sb_publishable_key'} if api_keys is None else api_keys)


def prepare_with(world, api_keys=None, reset_fails=False):
    """A `prepare` for scan.run(): a ready stack whose transport is the world. Returns it and its lifecycle."""
    lifecycle = Lifecycle(reset_fails)
    profile = {'mode': 'E1', 'identities': {n: {'login': 'ok', 'path': 'scripted'} for n in [*EMAILS, 'anonymous']}}

    def prepare(project_dir):
        env = environment.Operations(handles(api_keys), Transport(world), lifecycle)
        return e1.Ready(profile, env)
    return prepare, lifecycle
