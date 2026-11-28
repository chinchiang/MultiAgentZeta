"""What a run does to a prepared stack: actor requests, observer reads and faults.

A prepared stack (e1.prepare) is a bag of live handles: the API URL, the identities' session tokens, the
API keys, the observer's login. Operations hands them out as operations instead, so a run never reads or
rewrites a handle itself, and a fault is applied and undone in one place:

  request(identity, method, path, ...) -> (status, parsed body)   as an actor (TK-IDN-008: the actor channel)
  observe(marker) -> state                                          as the observer (the observer channel)
  inject(fault, ...) -> undo                                        a fault of 〈定義：測試結果〉 and its undo
  require_api_keys(formats), identity_email(name), has_session(name), observer_role, token_transport
  reset(), destroy()                                                the stack's own lifecycle, e1's

The provisioning identity (migrations, seed, reset) stays in e1 and is not reachable from here. The
transport (toolkit.transport) is the seam: the real adapter is urllib and `docker exec`, a scripted one
answers from a test (tests/scripted.py). Tokens and the observer's password never leave the control area.
"""
import json
import secrets
import socket
from dataclasses import dataclass

from toolkit import e1, observer
from toolkit import transport as real_transport
from toolkit.transport import RequestFailed, RequestTimeout  # raised by request(); named here for its callers

FAULTS = ('session-revoked', 'observer-unavailable', 'observer-timeout', 'api-unreachable', 'api-key-missing')


@dataclass(frozen=True)
class UnparsedBody:
    """Non-empty UTF-8 response body that is not valid JSON (TK-DYN-001, TK-DYN-002, TK-IDN-008, 〈定義：測試結果〉):
    kept distinct from an empty body (None) and parsed JSON values so the judge can inspect it for disclosures."""
    text: str


class LimitReached(Exception):
    """A request or an observer read would exceed the run's request limit, so it was not made (TK-BUD-003).
    scan.run() does not dispatch a case it cannot afford; this is the stop behind that count."""


class ApiKeyUnavailable(Exception):
    """The environment does not provide an API key format the case needs: the case is blocked, and no
    request goes out with an empty key (TK-DYN-004, TK-IDN-003; 〈定義：測試結果〉 受阻)."""


class InjectionFailed(Exception):
    """A fault of a self-validation run could not be applied (〈定義：故障注入〉): its case is blocked, with the
    evidence of the attempt, and is never judged as if the fault were in place."""

    def __init__(self, message, evidence=None):
        super().__init__(message)
        self.evidence = evidence


class Aborted(Exception):
    """The run was aborted (TK-RUN-004): a request or observer read that had not gone out yet is not made, and
    the case it belonged to ends without a known outcome (〈定義：中止與清理〉)."""


def _reject_nonstandard_json_constant(token):
    raise ValueError(f'non-RFC-8259 JSON constant: {token}')


def closed_local_url():
    """A loopback URL on a port nothing listens on: connections to it are refused (api-unreachable)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    return f'http://127.0.0.1:{port}'


class Operations:
    """The operations a run has on one prepared stack (e1.Environment), over a transport and a lifecycle."""

    def __init__(self, env, transport=real_transport, lifecycle=e1):
        self._env, self._transport = env, transport
        self.request_limit = None  # 執行限制 max_requests, set by scan.run(); None counts without a limit
        self.requests = 0  # actor requests and observer reads made for the run's cases
        self.before_request = None  # set by scan.run(): called before each one, raises Aborted once the run is aborted
        self._reset, self._destroy = lifecycle.reset, lifecycle.destroy  # not the module: no provisioning step is reachable
        self._relogin = lifecycle.relogin

    @property
    def observer_role(self):
        return self._env.observer['role']

    @property
    def token_transport(self):
        """How the identities' credentials travel, as confirmed in the BuildRecipe (TK-IDN-003)."""
        return self._env.recipe['auth']['token_transport']

    def identity_email(self, name):
        """The email the BuildRecipe gives an identity, or None for an anonymous one."""
        return next((i.get('email') for i in self._env.recipe['auth']['identities'] if i['name'] == name), None)

    def has_session(self, name):
        return name in self._env.tokens

    def require_api_keys(self, formats):
        """Raise ApiKeyUnavailable if the stack lacks one of these API key formats (TK-DYN-004, TK-IDN-003)."""
        missing = sorted(set(formats) - {f for f, k in self._env.api_keys.items() if k})
        if missing:
            raise ApiKeyUnavailable(f'the environment provides no API key of format {", ".join(map(repr, missing))}')

    def _count(self, what):
        """Count one request or observer read before it is made; refuse the one past the limit (TK-BUD-003)."""
        if self.before_request:
            self.before_request()
        if self.request_limit is not None and self.requests >= self.request_limit:
            raise LimitReached(f'{what} not made: the run has used its {self.request_limit} requests')
        self.requests += 1

    def request(self, identity, method, path, body=None, api_key='anon-jwt', prefer='return=representation',
                timeout=15):
        """An actor request through the data API, as the given identity. Returns (status, parsed body)."""
        env = self._env
        if not env.api_keys.get(api_key):
            raise ApiKeyUnavailable(f'the environment provides no API key of format {api_key!r}')
        self._count(f'{method} {path}')
        headers = {'apikey': env.api_keys[api_key], 'Prefer': prefer}
        if identity in env.tokens:
            headers['Authorization'] = 'Bearer ' + env.tokens[identity]['access_token']
        status, raw = self._transport.http(method, env.api_url + path, headers, body, timeout)
        if not raw:
            return status, None
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError as e:  # bytes that are not UTF-8 text: no readable reply
            raise RequestFailed(f'{method} {path}: response body is not text ({e.reason})') from e
        try:
            return status, json.loads(text, parse_constant=_reject_nonstandard_json_constant)
        except RecursionError as e:  # TK-RUN-001, 〈定義：測試結果〉 執行錯誤: JSON too deep to parse never passes
            raise RequestFailed(f'{method} {path}: response JSON exceeds parser nesting limit') from e
        except (json.JSONDecodeError, ValueError):
            return status, UnparsedBody(text)

    def observe(self, marker):
        """Template document-row-state-v1 as the observer (observer.ObservationFailed when it cannot read)."""
        self._count('observer read')
        return observer.document_row_state(self._env, marker, self._transport)

    def inject(self, fault, actor_ref, key_format, timeout):
        """Apply a fault of a test, if it has one (〈定義：故障注入〉). Returns (undo, evidence): the function that
        undoes what can be undone, and the evidence of the injection when it was a request. Raises
        InjectionFailed when the fault could not be applied. key_format is the API key format the
        api-key-missing fault removes."""
        env = self._env
        if fault == 'session-revoked':
            return self._revoke_session(actor_ref, timeout)
        if fault in observer.OBSERVER_FAULTS:  # the observer's login is the observer component's to change (TK-IDN-005)
            return observer.inject(env, fault), None
        if fault == 'api-unreachable':  # every data API request of this case is refused, the owner's control included
            saved_url, env.api_url = env.api_url, closed_local_url()

            def reconnect():
                env.api_url = saved_url
            return reconnect, None
        if fault == 'api-key-missing':  # the environment lacks an API key format (TK-DYN-004)
            saved_key = env.api_keys.pop(key_format, None)

            def restore_key():
                if saved_key is not None:
                    env.api_keys[key_format] = saved_key
            return restore_key, None
        return (lambda: None), None

    LOGOUT = '/auth/v1/logout?scope=global'

    def _revoke_session(self, actor_ref, timeout):
        """The session-revoked fault: log the actor out. Whatever comes of it, the actor gets a new session
        when the case is over, so the fault stays within its case: a logout that timed out may still have
        reached the auth service."""
        evidence = {'channel': 'actor', 'identity_ref': actor_ref, 'api_key_format': 'anon-jwt',
                    'request': {'method': 'POST', 'path': self.LOGOUT}}

        def new_session():
            self._relogin(self._env, actor_ref)
        try:
            status, _ = self.request(actor_ref, 'POST', self.LOGOUT, timeout=timeout)
        except (RequestTimeout, RequestFailed) as e:
            new_session()
            raise InjectionFailed(f'the logout did not complete: {e}', {**evidence, 'injection': 'failed'}) from e
        evidence['response'] = {'status': status, 'rows': None}
        if status != 204:
            new_session()
            raise InjectionFailed(f'the logout was answered with HTTP {status}', {**evidence, 'injection': 'failed'})
        return new_session, {**evidence, 'injection': 'applied'}

    def reset(self):
        """Reset the stack to its seed (e1.reset). Returns e1.Blocked when it cannot, else None."""
        result = self._reset(self._env)
        return result if isinstance(result, e1.Blocked) else None

    def revoke_sessions(self, timeout=15):
        """〈定義：中止與清理〉 撤銷測試憑證: log every identity's session out and drop the tokens from
        memory. Returns {identity: 'revoked' | 'not_confirmed'}; a logout the auth service did
        not answer is not confirmed. These requests are the run's own, not a case's: they are not counted."""
        env, outcome = self._env, {}
        for name, tokens in sorted(env.tokens.items()):
            headers = {'apikey': env.anon_key or next(iter(env.api_keys.values()), ''),
                       'Authorization': 'Bearer ' + tokens['access_token']}
            try:
                status, _ = self._transport.http('POST', env.api_url + '/auth/v1/logout?scope=global', headers, None, timeout)
                # 204: logged out. 401 or 403: the session was already gone (a session-revoked case ended it).
                outcome[name] = 'revoked' if status in (204, 401, 403) else 'not_confirmed'
            except (RequestTimeout, RequestFailed):
                outcome[name] = 'not_confirmed'
        env.tokens.clear()
        return outcome

    def destroy(self):
        """Destroy the stack (e1.destroy). Returns what is left of it, as text; an empty list when nothing is."""
        return list(self._destroy(self._env) or [])


def prepare(project_dir):
    """e1.prepare, with the live handles behind Operations: the default `prepare` of scan.run()."""
    ready = e1.prepare(project_dir)
    return ready if isinstance(ready, e1.Blocked) else e1.Ready(ready.profile, Operations(ready.env))
