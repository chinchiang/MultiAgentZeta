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

from toolkit import e1, observer
from toolkit import transport as real_transport
from toolkit.transport import RequestFailed, RequestTimeout  # raised by request(); named here for its callers

FAULTS = ('session-revoked', 'observer-unavailable', 'observer-timeout', 'api-unreachable', 'api-key-missing')


class ApiKeyUnavailable(Exception):
    """The environment does not provide an API key format the case needs: the case is blocked, and no
    request goes out with an empty key (TK-DYN-004, TK-IDN-003; 〈定義：測試結果〉 受阻)."""


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
        self._reset, self._destroy = lifecycle.reset, lifecycle.destroy  # not the module: no provisioning step is reachable

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

    def request(self, identity, method, path, body=None, api_key='anon-jwt', prefer='return=representation',
                timeout=15):
        """An actor request through the data API, as the given identity. Returns (status, parsed body)."""
        env = self._env
        if not env.api_keys.get(api_key):
            raise ApiKeyUnavailable(f'the environment provides no API key of format {api_key!r}')
        headers = {'apikey': env.api_keys[api_key], 'Prefer': prefer}
        if identity in env.tokens:
            headers['Authorization'] = 'Bearer ' + env.tokens[identity]['access_token']
        status, raw = self._transport.http(method, env.api_url + path, headers, body, timeout)
        try:
            return status, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return status, None
        except UnicodeDecodeError as e:  # bytes json cannot even decode: no readable reply
            raise RequestFailed(f'{method} {path}: response body is not text ({e.reason})') from e

    def observe(self, marker):
        """Template document-row-state-v1 as the observer (observer.ObservationFailed when it cannot read)."""
        return observer.document_row_state(self._env, marker, self._transport)

    def inject(self, fault, actor_ref, key_format, timeout):
        """Apply a fault of a test, if it has one. Returns a function that undoes what can be undone.
        key_format is the API key format the api-key-missing fault removes."""
        env = self._env
        if fault == 'session-revoked':
            self.request(actor_ref, 'POST', '/auth/v1/logout?scope=global', timeout=timeout)
            return lambda: None  # the actor stays logged out for the rest of the run
        if fault == 'observer-unavailable':
            saved = env.observer['password']
            env.observer['password'] = 'wrong-' + secrets.token_hex(8)

            def restore():
                env.observer['password'] = saved
            return restore
        if fault == 'observer-timeout':  # a query time limit no read can meet (TK-IDN-009)
            env.observer['timeout_seconds'] = 0.000001

            def no_limit_override():
                env.observer.pop('timeout_seconds', None)
            return no_limit_override
        if fault == 'api-unreachable':  # every data API request of this case is refused, the owner's control included
            saved_url, env.api_url = env.api_url, closed_local_url()

            def reconnect():
                env.api_url = saved_url
            return reconnect
        if fault == 'api-key-missing':  # the environment lacks an API key format (TK-DYN-004)
            saved_key = env.api_keys.pop(key_format, None)

            def restore_key():
                if saved_key is not None:
                    env.api_keys[key_format] = saved_key
            return restore_key
        return lambda: None

    def reset(self):
        """Reset the stack to its seed (e1.reset). Returns e1.Blocked when it cannot, else None."""
        result = self._reset(self._env)
        return result if isinstance(result, e1.Blocked) else None

    def destroy(self):
        self._destroy(self._env)


def prepare(project_dir):
    """e1.prepare, with the live handles behind Operations: the default `prepare` of scan.run()."""
    ready = e1.prepare(project_dir)
    return ready if isinstance(ready, e1.Blocked) else e1.Ready(ready.profile, Operations(ready.env))
