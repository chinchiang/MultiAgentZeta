"""Run the environment tests (MAZ_ENV_TESTS=1) outside the calling session, and report their progress.

    toolkit/tools/run-env-tests.sh NAME [-p PATTERN] [-k NAME_FILTER ...]   # start, return at once
    toolkit/tools/run-env-tests.sh --status NAME                           # progress of a run

A run is detached from the shell that starts it (a new session), so ending that shell or agent session
does not stop it. A start is refused while a run holds scratch/logs/env-tests.lock or any other test
process of this toolkit is running on the machine (another clone, a manual run, a process a stopped run
left behind); otherwise the Docker resources of the maz-* sample projects that an earlier run left are
removed first. The log is scratch/logs/NAME.log: a header line, the `unittest -v` output (one line per
test), and an end line with the exit code. Times are shown in GMT+8.
"""
import json
import os
import re
import subprocess
import sys
import time
import unittest
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LOGS = REPO / 'scratch' / 'logs'
LOCK = LOGS / 'env-tests.lock'
START_DIR = 'toolkit/tests'
DISCOVER = ['discover', '-s', START_DIR, '-t', '.']  # the run and count_tests() use the same discovery
GMT8 = timezone(timedelta(hours=8))
NAME_PATTERN = re.compile(r'^[A-Za-z0-9._-]+$')
# Docker resources of the sample projects (project_id maz-* in samples/*/supabase/config.toml, see e1.py).
ORPHAN_PATTERN = re.compile(r'^(supabase_[a-z_]+_|maz_e1_)maz-[A-Za-z0-9-]+$')

_HEADER = re.compile(r'^# env-tests name=(?P<name>\S+) head=(?P<head>\S+) args=(?P<args>\[.*\]) '
                     r'total=(?P<total>\d+) started=(?P<started>\S+)$', re.M)
_END = re.compile(r'^# end exit=(?P<exit>-?\d+) wall=(?P<wall>[\d.]+) ended=(?P<ended>\S+)$', re.M)
_NOT_STARTED = re.compile(r'^# not started: (.*)$', re.M)
_TEST_ID = re.compile(r'^\s*(\w+ \([\w.]+\))')  # how unittest -v names a test, a subtest or a class fixture
_FIXTURES = ('setUpClass', 'tearDownClass', 'setUpModule', 'tearDownModule')  # their errors count no test
# A result closes the text after ' ... ', possibly after output the test itself wrote on the same line.
_RESULT = re.compile(r'(?P<r>ok|FAIL|ERROR|expected failure|unexpected success)$|(?P<s>skipped)(?: .*)?$')
_FAILED_BLOCK = re.compile(r'^(?:FAIL|ERROR): (.+)$', re.M)
_RAN = re.compile(r'^Ran (\d+) tests? in ', re.M)


class Busy(Exception):
    """Another environment test run, or another test process, is in progress."""


@dataclass
class Status:
    name: str
    head: str
    args: list
    total: int
    started: datetime
    done: int = 0
    skipped: int = 0
    failures: list = field(default_factory=list)
    finished: bool = False
    exit: int | None = None
    wall: float | None = None
    ran: int | None = None
    ended: datetime | None = None
    problem: str | None = None  # why the run ended before its tests started

    @property
    def not_run(self):
        """Planned tests that never ran, e.g. after a setUpClass error; known once the run has ended."""
        return self.total - self.ran if self.ran is not None else None


def _utc(text):
    return datetime.strptime(text, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_log(text):
    """The Status a run's log shows. A test is done once its result is printed; failures are those the
    output names, and once the run has ended, those of unittest's closing FAIL/ERROR blocks."""
    head = _HEADER.search(text)
    if not head or head.start() != 0:
        raise ValueError('not an env-tests log: the header line is missing')
    results, failures, current = {}, [], None
    for line in text.splitlines()[1:]:
        named = _TEST_ID.match(line)
        if named and not line.startswith(' '):
            current = named[1]
        label, sep, tail = line.rpartition(' ... ')
        found = _RESULT.search(tail) if sep else None
        if not found:
            continue
        own = _TEST_ID.match(label)
        test = own[1] if own else current
        if found['r'] in ('FAIL', 'ERROR', 'unexpected success'):
            failures.append(label.strip() if own else current)
        if test and not test.startswith(_FIXTURES):
            results.setdefault(test, 'skipped' if found['s'] else found['r'])
    end, ran, not_started = _END.search(text), _RAN.search(text), _NOT_STARTED.search(text)
    s = Status(name=head['name'], head=head['head'], args=json.loads(head['args']), total=int(head['total']),
               started=_utc(head['started']), done=len(results),
               skipped=sum(r == 'skipped' for r in results.values()), failures=failures, finished=bool(end),
               ran=int(ran[1]) if ran else None, problem=not_started[1] if not_started else None)
    if end:
        s.exit, s.wall, s.ended = int(end['exit']), float(end['wall']), _utc(end['ended'])
        blocks = _FAILED_BLOCK.findall(text)
        if blocks:
            s.failures = blocks
        if s.ran is None and s.problem:
            s.ran = 0
    return s


def _filters(args):
    """-p and -k of unittest discover; any other argument is refused, so the count cannot drift from the run."""
    pattern, names, rest = 'test*.py', [], list(args)
    while rest:
        flag = rest.pop(0)
        if flag not in ('-p', '-k') or not rest:
            raise ValueError(f'only -p PATTERN and -k NAME_FILTER are passed to unittest, got {flag!r}')
        value = rest.pop(0)
        if flag == '-p':
            pattern = value
        else:
            names.append(value if '*' in value else f'*{value}*')  # as unittest's -k does
    return pattern, names


def count_tests(args):
    """How many tests `unittest discover` (DISCOVER) runs with these -p and -k arguments."""
    pattern, names = _filters(args)
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    loader = unittest.TestLoader()
    loader.testNamePatterns = names or None
    return loader.discover(str(REPO / START_DIR), pattern=pattern, top_level_dir=str(REPO)).countTestCases()


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def read_lock(path):
    """(pid, run name) of the lock, or None when there is none or it is unreadable."""
    try:
        pid, _, name = Path(path).read_text(encoding='utf-8').strip().partition(' ')
    except FileNotFoundError:
        return None
    return (int(pid), name) if pid.isdigit() else None


def _write_lock(path, pid, name, exclusive):
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    with os.fdopen(os.open(path, flags, 0o644), 'w', encoding='utf-8') as f:
        f.write(f'{pid} {name}\n')


def acquire_lock(path, pid, name):
    """Record that run `name` (process pid) is in progress; refuse while another live run holds the lock.
    The lock file is created exclusively, so two starts at once cannot both pass; a lock whose process is
    gone is replaced."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    for _ in range(2):
        try:
            _write_lock(path, pid, name, exclusive=True)
            return
        except FileExistsError:
            held = read_lock(path)
            if held and _alive(held[0]):
                raise Busy(f'an environment test run is in progress: pid {held[0]} running {held[1]!r}; '
                           f'see run-env-tests.sh --status {held[1]}') from None
            path.unlink(missing_ok=True)
    raise Busy(f'could not take the lock {path}')


def release_lock(path, pid):
    """Remove the lock if this process holds it."""
    held = read_lock(path)
    if held and held[0] == pid:
        Path(path).unlink(missing_ok=True)


def other_test_runs(ps_output, exclude):
    """Lines of `ps -eo pid,args` that are unittest runs of this toolkit's tests, other than the pids in exclude."""
    found = []
    for line in ps_output.splitlines():
        pid, _, cmd = line.strip().partition(' ')
        argv = cmd.split()
        if (pid.isdigit() and int(pid) not in exclude and argv and 'python' in Path(argv[0]).name
                and 'unittest' in argv and 'discover' in argv and START_DIR in argv):
            found.append(f'{pid} {cmd.strip()}')
    return found


def _docker(*args):
    r = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=120)
    if r.returncode:
        raise RuntimeError(f'docker {" ".join(args[:2])} failed: {r.stderr.strip() or r.stdout.strip()}')
    return r.stdout


def remove_orphans():
    """Remove the sample projects' containers, then volumes and networks, that an earlier run left behind.
    A Docker command that fails is an error, never "nothing left behind"."""
    removed = []
    for kind, ls, rm in (('container', ['ps', '-a', '--format', '{{.Names}}'], ['rm', '-f']),
                         ('volume', ['volume', 'ls', '--format', '{{.Name}}'], ['volume', 'rm']),
                         ('network', ['network', 'ls', '--format', '{{.Name}}'], ['network', 'rm'])):
        names = [n for n in _docker(*ls).split() if ORPHAN_PATTERN.match(n)]
        if names:
            _docker(*rm, *names)
            removed += [f'{kind} {n}' for n in names]
    return removed


def _head():
    try:
        sha = subprocess.run(['git', 'rev-parse', '--short', 'HEAD'], cwd=REPO, capture_output=True, text=True,
                             check=True).stdout.strip()
        dirty = subprocess.run(['git', 'status', '--porcelain'], cwd=REPO, capture_output=True, text=True,
                               check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return 'unknown'
    return (sha or 'unknown') + ('+worktree' if dirty else '')


def _log_path(name):
    """The log of run `name`; the name must be a plain file name."""
    if not NAME_PATTERN.match(name):
        raise ValueError(f'run name must match {NAME_PATTERN.pattern}, got {name!r}')
    return LOGS / f'{name}.log'


def start(name, args):
    """Start run `name` detached and return its log path."""
    log = _log_path(name)
    _filters(args)
    acquire_lock(LOCK, os.getpid(), name)
    try:
        ps = subprocess.run(['ps', '-eo', 'pid,args'], capture_output=True, text=True, check=True).stdout
        others = other_test_runs(ps, exclude={os.getpid()})
        if others:
            raise Busy('other test processes are running, so their Docker resources are left alone: '
                       + '; '.join(others))
        for r in remove_orphans():
            print(f'removed leftover {r}', file=sys.stderr)
        with open(log, 'w', encoding='utf-8') as out:
            child = subprocess.Popen([sys.executable, '-I', __file__, '_run', name, *args], cwd=REPO,
                                     stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                     start_new_session=True)
        _write_lock(LOCK, child.pid, name, exclusive=False)  # hand the lock to the run
    except BaseException:
        release_lock(LOCK, os.getpid())
        raise
    return log


def _fetch_cli():
    """MAZ_SUPABASE_BIN from fetch-supabase-cli.sh, or (None, why it failed)."""
    r = subprocess.run([str(REPO / 'toolkit' / 'tools' / 'fetch-supabase-cli.sh')], capture_output=True, text=True)
    if r.returncode:
        last = (r.stderr.strip().splitlines() or [f'exit {r.returncode}'])[-1]
        return None, f'fetch-supabase-cli.sh failed: {last}'
    return r.stdout.strip(), None


def _run(name, args):
    """The detached run itself: header, the tests, end line, always; then the lock is released."""
    t0, code = time.monotonic(), 2
    try:
        try:
            total, problem = count_tests(args), None
        except Exception as e:  # the header is written whatever happens, so --status can say why
            total, problem = 0, f'the tests could not be counted: {e}'
        print(f'# env-tests name={name} head={_head()} args={json.dumps(args)} total={total} started={_now()}',
              flush=True)
        cli = None
        if not problem:
            cli, problem = _fetch_cli()
        if problem:
            print(f'# not started: {problem}', flush=True)
        else:
            env = {**os.environ, 'MAZ_ENV_TESTS': '1', 'MAZ_SUPABASE_BIN': cli}
            code = subprocess.run([sys.executable, '-I', '-m', 'unittest', *DISCOVER, '-v', *args], cwd=REPO,
                                  stdin=subprocess.DEVNULL, env=env).returncode
        return code
    finally:
        print(f'# end exit={code} wall={time.monotonic() - t0:.1f} ended={_now()}', flush=True)
        release_lock(LOCK, os.getpid())


def _previous_wall(status):
    """The duration of the latest finished run with the same arguments, for the estimate."""
    best = None
    for f in LOGS.glob('*.log'):
        try:
            s = parse_log(f.read_text(encoding='utf-8'))
        except (ValueError, OSError):
            continue
        if (s.finished and not s.problem and s.args == status.args and s.name != status.name
                and (best is None or s.ended > best.ended)):
            best = s
    return best.wall if best else None


def _gmt8(dt):
    return dt.astimezone(GMT8).strftime('%m-%d %H:%M:%S') + ' GMT+8'


def describe(status, previous_wall=None, running=True):
    """The status lines for a person."""
    s = status
    lines = [f'{s.name}: head {s.head}, args {s.args or "(all)"}, started {_gmt8(s.started)}']
    progress = f'{s.done}/{s.total} tests done' + (f', {s.skipped} skipped' if s.skipped else '')
    if s.finished and s.problem:
        lines.append(f'not started (exit {s.exit}): {s.problem}')
    elif s.finished:
        verdict = 'OK' if s.exit == 0 else f'FAILED (exit {s.exit})'
        lines.append(f'finished {_gmt8(s.ended)}: {verdict}, {progress}; unittest ran {s.ran} in {s.wall:.0f} s')
        if s.not_run:
            lines.append(f'{s.not_run} planned tests did not run (see the errors below)')
    elif running:
        lines.append(f'running: {progress}')
        if previous_wall:
            lines.append(f'estimated end {_gmt8(s.started + timedelta(seconds=previous_wall))} '
                         f'(the last run with the same arguments took {previous_wall:.0f} s)')
    else:
        lines.append(f'STOPPED before its end line: {progress}; the run is gone, nothing more will be written')
    lines.append('failures: ' + (', '.join(s.failures) if s.failures else 'none'))
    return '\n'.join(lines)


def status(name):
    log = _log_path(name)
    if not log.exists():
        raise ValueError(f'no run named {name!r}: {log.relative_to(REPO)} does not exist')
    held = read_lock(LOCK)
    running = bool(held) and held[1] == name and _alive(held[0])
    text = log.read_text(encoding='utf-8')
    if not _HEADER.match(text):
        if running:
            return f'{name}: starting (counting the tests)'
        raise ValueError(f'{log.relative_to(REPO)} has no header line; the run did not start:\n{text[-2000:]}')
    s = parse_log(text)
    return describe(s, _previous_wall(s), running and not s.finished)


def main(argv):
    if len(argv) >= 2 and argv[0] == '_run':
        return _run(argv[1], argv[2:])
    if len(argv) == 2 and argv[0] == '--status':
        try:
            print(status(argv[1]))
        except ValueError as e:
            print(e, file=sys.stderr)
            return 2
        return 0
    if argv and not argv[0].startswith('-'):
        try:
            log = start(argv[0], argv[1:])
        except (Busy, ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as e:
            print(f'not started: {e}', file=sys.stderr)
            return 2
        print(f'started {argv[0]}: log {log.relative_to(REPO)}; progress: toolkit/tools/run-env-tests.sh --status {argv[0]}')
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
