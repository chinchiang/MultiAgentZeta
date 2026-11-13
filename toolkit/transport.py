"""How the toolkit talks to a stack: an HTTP exchange and a command run in a container.

Each mechanism is written once. The provisioning identity (e1), the observer (observer) and the
actors (environment) each bring their own credentials and their own reading of the answer; none of them
reads another's. This is the seam where a script can stand in for the network and Docker (tests/scripted.py).
Interface of an adapter: http(method, url, headers, body, timeout) and docker_exec(container, command, env,
stdin, timeout), as the two functions below.
"""
import json
import socket
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from http.client import HTTPException


class RequestTimeout(Exception):
    """A request exceeded the test's time limit: an execution error, never a pass (〈定義：測試結果〉)."""


class RequestFailed(Exception):
    """A request got no HTTP response (connection refused or reset, a broken reply): an execution
    error for its case, never a pass, and never the end of the run (〈定義：測試結果〉, TK-RUN-001)."""


def _path(url):
    """The path and query of url: what an error names, not the host."""
    parts = urllib.parse.urlsplit(url)
    return parts.path + ('?' + parts.query if parts.query else '')


def http(method, url, headers=None, body=None, timeout=15):
    """(status, reply bytes) of one HTTP exchange; body is a JSON value or None. An error status is an answer,
    not an exception. Raises RequestTimeout, or RequestFailed when there is no reply that can be read."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=dict(headers or {}))
    if data is not None:
        req.add_header('Content-Type', 'application/json')
    where = f'{method} {_path(url)}'
    try:
        # Reading an error reply's body can fail too, so it sits inside the same handling.
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            with e:
                return e.code, e.read()
    except (TimeoutError, socket.timeout) as e:
        raise RequestTimeout(f'{where} exceeded {timeout} s') from e
    except urllib.error.URLError as e:
        if isinstance(e.reason, (TimeoutError, socket.timeout)):
            raise RequestTimeout(f'{where} exceeded {timeout} s') from e
        raise RequestFailed(f'{where}: {e.reason}') from e
    except (OSError, HTTPException) as e:  # e.g. the connection was reset mid-reply
        raise RequestFailed(f'{where}: {e!r}') from e


def docker_exec(container, command, env=None, stdin=None, timeout=60):
    """The CompletedProcess (text) of `docker exec` of command in container; env maps variable names to values
    passed in, stdin is text to feed it. Raises subprocess.TimeoutExpired, OSError or UnicodeDecodeError, as
    subprocess.run does."""
    flags = ['-i'] if stdin is not None else []
    for name, value in (env or {}).items():
        flags += ['-e', f'{name}={value}']
    return subprocess.run(['docker', 'exec', *flags, container, *command], capture_output=True, text=True,
                          timeout=timeout, input=stdin)
