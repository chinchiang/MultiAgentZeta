"""Observer: reads actual state for judgement, as the dedicated read-only role (TK-IDN-004, TK-IDN-012).

Runs in the control area only. Observation is by template (TK-IDN-006): callers
pick a template and a resource, never SQL. The observer connects to the db
address on the toolkit network, where the image checks the role's password.
"""
import hashlib
import re
import subprocess

MARKER = re.compile(r'^[A-Z0-9-]{1,64}$')


class ObservationFailed(Exception):
    """The observer could not read the state; a judgement must not treat this as a pass (TK-IDN-009)."""


# Time limit of one observer query; env.observer['timeout_seconds'] overrides it (self-validation, TK-VAL-001).
QUERY_TIMEOUT_SECONDS = 60


def _query(env, sql):
    obs = env.observer
    if not obs:
        raise ObservationFailed('no observer role in this environment')
    limit = obs.get('timeout_seconds', QUERY_TIMEOUT_SECONDS)
    try:
        r = subprocess.run(['docker', 'exec', '-e', f'PGPASSWORD={obs["password"]}', f'supabase_db_{env.project_id}',
                            'psql', '-h', obs['host'], '-U', obs['role'], '-d', 'postgres', '-At', '-F', '\t',
                            '-v', 'ON_ERROR_STOP=1', '-c', sql], capture_output=True, text=True, timeout=limit)
    except subprocess.TimeoutExpired as e:  # TK-IDN-009: a read that did not finish is not a read
        raise ObservationFailed(f'observer query timed out after {limit} s') from e
    except OSError as e:  # the container tool cannot be started (TK-IDN-009)
        raise ObservationFailed(f'container tool unavailable: {e.strerror or e}') from e
    except UnicodeDecodeError as e:  # output that is not text cannot be read (TK-IDN-009)
        raise ObservationFailed(f'observer output is not text ({e.reason})') from e
    if r.returncode:
        raise ObservationFailed((r.stderr or r.stdout).strip()[-500:])
    return [line.split('\t') for line in r.stdout.splitlines()]


def document_row_state(env, marker):
    """Template document-row-state-v1: the target row (existence, sharing flag, digest) and a digest
    of the whole documents table, so that changes to other rows are seen as side effects."""
    if not MARKER.match(marker):
        raise ObservationFailed(f'invalid resource marker {marker!r}')
    rows = _query(env, "select owner_id, tenant_id, shared, md5(title || body) from public.documents "
                       f"where title = '{marker}'")
    table = _query(env, "select count(*), coalesce(md5(string_agg(id::text || owner_id || tenant_id || title "
                        "|| body || shared::text, '|' order by id)), '') from public.documents")
    try:
        state = {'template': 'document-row-state-v1', 'table_rows': int(table[0][0]),
                 'table_digest': hashlib.sha256(table[0][1].encode()).hexdigest()}
        if not rows:
            return {**state, 'resource_exists': False}
        owner, tenant, shared, digest = rows[0]
    except (IndexError, ValueError) as e:  # output not in the template's shape: no reliable state (TK-IDN-009)
        raise ObservationFailed(f'observer output is not in the expected shape: {e}') from e
    return {**state, 'resource_exists': True, 'shared': shared == 't',
            'state_digest': hashlib.sha256(f'{owner}|{tenant}|{shared}|{digest}'.encode()).hexdigest()}
