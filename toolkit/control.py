"""Records in the control zone: the confirmation list (〈定義：確認清單〉) and the test authorization
record (〈定義：測試授權紀錄〉).

A record lives outside the sample source, where the code under test cannot write it, and a
ScanManifest references it by path and content digest. A record whose file is gone is not used, and
is never replaced by a new one: that would drop what people recorded in it (TK-REQ-004, TK-ENV-002).
"""
import fcntl
import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


class RecordUnusable(Exception):
    """A control-zone record cannot be used: inside the sample source, missing, unreadable or with another digest."""


def outside_source(path, source_root, what):
    """path resolved, when it is outside source_root; a record inside the sample source could be written by
    the code under test. Check it before acting on the record's behalf, e.g. before opening an issue."""
    path, root = Path(path).resolve(), Path(source_root).resolve()
    if path == root or root in path.parents:
        raise RecordUnusable(f'{path} is inside the sample source; the {what} belongs in the control zone')
    return path


def _digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def file_digest(path):
    return _digest(Path(path).read_bytes())


@contextmanager
def writer(path, source_root, what):
    """Serialize a whole read/modify/write operation, including any review checkpoints."""
    path = outside_source(path, source_root, what)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Lock the stable directory inode. The record inode changes on every replacement.
        lock = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as e:
        raise RecordUnusable(f'{path} cannot be written: {e}') from e

    def save(doc):
        data = (json.dumps(doc, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
        try:
            tmp = tempfile.NamedTemporaryFile(dir=path.parent, delete=False)
            partial = Path(tmp.name)
            try:
                with tmp:
                    tmp.write(data)
                os.replace(partial, path)
            finally:
                partial.unlink(missing_ok=True)
        except OSError as e:
            raise RecordUnusable(f'{path} cannot be written: {e}') from e
        return _digest(data)

    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
        except OSError as e:
            raise RecordUnusable(f'{path} cannot be locked: {e}') from e
        yield save
    finally:
        os.close(lock)


def write(path, doc, source_root, what='record'):
    with writer(path, source_root, what) as save:
        return save(doc)


def read(path, digest, source_root, what='record'):
    """The record at path, after checking where it is and its digest; what names it in errors. Its
    structure is the caller's to check."""
    path = outside_source(path, source_root, what)
    if not path.exists():
        # Not "no record yet": a new one would drop what people recorded in it (TK-REQ-004).
        raise RecordUnusable(f'{path} is referenced with digest {digest} but does not exist; restore the file')
    try:
        data = path.read_bytes()
        actual = _digest(data)
        doc = json.loads(data.decode('utf-8'))
    except (OSError, ValueError) as e:
        raise RecordUnusable(f'{path} cannot be read: {e}') from e
    if actual != digest:
        raise RecordUnusable(f'digest of {path} is {actual}, the ScanManifest says {digest}')
    return doc


def current(path, source_root, what='record'):
    """The record at path as it is now, for the tool that keeps it up to date; no digest to compare,
    since that tool writes the next one. A missing file is an error, never an empty record."""
    path = outside_source(path, source_root, what)
    if not path.exists():
        raise RecordUnusable(f'{path} does not exist; restore the file, or create a new {what} explicitly')
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as e:
        raise RecordUnusable(f'{path} cannot be read: {e}') from e


# The times control-zone records carry: ISO 8601 UTC such as 2027-05-01T00:00:00Z (〈定義：確認清單〉 到期,
# 〈定義：測試授權紀錄〉 期間).
UTC_TIME = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$')


def utc_time(value):
    """value as an aware datetime, or None when it is not an ISO 8601 UTC time or no such time."""
    if not isinstance(value, str) or not UTC_TIME.match(value):
        return None
    try:
        return datetime.fromisoformat(value[:-1]).replace(tzinfo=timezone.utc)
    except ValueError:  # the right shape but no such time, e.g. February 30
        return None
