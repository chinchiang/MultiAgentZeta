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


def _query(env, sql):
    obs = env.observer
    if not obs:
        raise ObservationFailed('no observer role in this environment')
    r = subprocess.run(['docker', 'exec', '-e', f'PGPASSWORD={obs["password"]}', f'supabase_db_{env.project_id}',
                        'psql', '-h', obs['host'], '-U', obs['role'], '-d', 'postgres', '-At', '-F', '\t',
                        '-v', 'ON_ERROR_STOP=1', '-c', sql], capture_output=True, text=True, timeout=60)
    if r.returncode:
        raise ObservationFailed((r.stderr or r.stdout).strip()[-500:])
    return [line.split('\t') for line in r.stdout.splitlines()]


def document_row_state(env, marker):
    """Template document-row-state-v1: existence, sharing flag and a digest of the row."""
    if not MARKER.match(marker):
        raise ObservationFailed(f'invalid resource marker {marker!r}')
    rows = _query(env, "select owner_id, tenant_id, shared, md5(title || body) from public.documents "
                       f"where title = '{marker}'")
    if not rows:
        return {'template': 'document-row-state-v1', 'resource_exists': False}
    owner, tenant, shared, digest = rows[0]
    return {'template': 'document-row-state-v1', 'resource_exists': True, 'shared': shared == 't',
            'state_digest': hashlib.sha256(f'{owner}|{tenant}|{shared}|{digest}'.encode()).hexdigest()}
