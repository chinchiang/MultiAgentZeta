"""The review record (〈定義：覆核紀錄〉): review decisions kept in the control zone.

Decisions come only from the platform's structured events: a predefined label, and the account the
platform reports as having added it. The roles record says which accounts may make which review;
free text is kept as the reason and never read as a decision (TK-HRV-003, TK-HRV-004).
"""
import argparse
import copy
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema

from toolkit import control, report

SCHEMAS = Path(__file__).parent / 'schemas'
SCHEMA = json.loads((SCHEMAS / 'review-record-v1.json').read_text(encoding='utf-8'))
ROLES_SCHEMA = json.loads((SCHEMAS / 'review-roles-v1.json').read_text(encoding='utf-8'))

# 〈定義：覆核紀錄〉 選項: the predefined platform label of each option of 候選問題覆核.
OPTION_OF_LABEL = {'review:approve': 'approve', 'review:reject': 'reject',
                   'review:evidence-pending': 'evidence_pending'}
ROLE_FOR = {'candidate_finding': 'security'}  # 〈定義：覆核類型〉 候選問題覆核: 資安人員
# 〈定義：覆核紀錄〉 期限與逾期: from when the review starts; 原型量測後核定 (TK-HRV-008).
DEADLINES = {'candidate_finding': timedelta(days=7)}


def _schema_problems(schema, doc):
    return [f'{"/".join(map(str, e.absolute_path)) or "(record)"}: {e.message}'
            for e in jsonschema.Draft202012Validator(schema).iter_errors(doc)]


def _roles(path, digest, source_root):
    """The review roles record at path (〈定義：覆核紀錄〉 角色), checked against its schema."""
    roles = control.read(path, digest, source_root, 'review roles record')
    problems = _schema_problems(ROLES_SCHEMA, roles)
    if not problems and control.utc_time(roles['issued_at']) is None:
        problems = [f'issued_at: {roles["issued_at"]!r} is not an ISO 8601 UTC time']
    if problems:
        raise control.RecordUnusable(f'{path} is not a valid review roles record: ' + '; '.join(problems))
    return roles


def _write(path, record, source_root):
    """control.write() of the review record; a file system that refuses it makes the record unusable."""
    try:
        return control.write(path, record, source_root, 'review record')
    except OSError as e:
        raise control.RecordUnusable(f'{path} cannot be written: {e}') from e


def _current(path, source_root):
    """The review record at path as it is now, checked like a referenced one (〈定義：覆核紀錄〉)."""
    record = control.current(path, source_root, 'review record')
    problems = validate(record)
    if problems:
        raise control.RecordUnusable(f'{path} is not a valid review record: ' + '; '.join(problems))
    return record


def validate(record):
    """Problems of a review record (〈定義：覆核紀錄〉): its schema, then its times, which deadlines and the
    order of decisions are computed from (ISO 8601 UTC). An empty list means it can be used."""
    problems = _schema_problems(SCHEMA, record)
    if problems:
        return problems
    times = [('synced_at', record['synced_at'])] if 'synced_at' in record else []
    for i, item in enumerate(record['items']):
        times.append((f'items/{i}/opened_at', item['opened_at']))
        for kind in ('decisions', 'rejected'):
            times += [(f'items/{i}/{kind}/{n}/at', e['at']) for n, e in enumerate(item[kind])]
        for n, d in enumerate(item['decisions']):
            times += [(f'items/{i}/decisions/{n}/reason_comments/{k}/updated_at', c.get('updated_at'))
                      for k, c in enumerate(d['reason_comments'])]
    return [f'{where}: {value!r} is not an ISO 8601 UTC time' for where, value in times
            if control.utc_time(value) is None]


class ReportUnusable(Exception):
    """A report publish cannot use: report.validate() finds problems in it."""


class PlatformError(Exception):
    """The platform could not be reached or did not answer as expected."""


class PublishFailed(Exception):
    """A publish stopped part-way; the issues opened before it are in the record."""


class SyncFailed(Exception):
    """A sync stopped part-way; the items written before it stay in the record."""


@dataclass(frozen=True)
class LabelEvent:
    """A label added or removed on the platform (action 'labeled' or 'unlabeled'), by the account the
    platform reports; id is the platform's event id."""
    id: int
    action: str
    actor_id: int
    actor_login: str
    label: str
    at: str


@dataclass(frozen=True)
class Comment:
    id: int
    author_id: int
    author_login: str
    body: str
    created_at: str
    updated_at: str


def _roles_of(roles, account_id):
    """The review roles of an account, matched by its numeric id; the login is only shown (〈定義：覆核紀錄〉 角色)."""
    for a in roles['accounts']:
        if a['id'] == account_id:
            return set(a['roles'])
    return set()


def _platform_time(value):
    """A time the platform reported, as an aware datetime; one that is not ISO 8601 UTC is the platform's error."""
    t = control.utc_time(value)
    if t is None:
        raise PlatformError(f'the platform reported {value!r}, which is not an ISO 8601 UTC time')
    return t


def _sync_item(item, roles, platform):
    """Append to item the decisions and rejected attempts its issue reports since the last sync: an account
    without the review's role, or with no comment since the last decision, is a rejected attempt. The
    platform's times are whole seconds, so a comment in the label's second counts, and in the second of the
    last decision belongs to that one
    (〈定義：覆核紀錄〉 選項, 身分, 角色, 理由)."""
    role = ROLE_FOR[item['review_type']]
    comments = [(_platform_time(c.created_at), c) for c in platform.comments(item['issue'])]
    events = sorted(platform.label_events(item['issue']), key=lambda e: (_platform_time(e.at), e.id))
    since = control.utc_time(item['decisions'][-1]['at']) if item['decisions'] else None
    seen = {e['event_id'] for e in item['decisions'] + item['rejected']}
    for event in events:
        option = OPTION_OF_LABEL.get(event.label)
        if event.action != 'labeled' or option is None:
            continue  # only adding a decision label is a decision; removing one is not
        if event.id in seen:
            continue  # recorded by an earlier sync; the record only grows
        entry = {'event_id': event.id, 'option': option,
                 'by': {'id': event.actor_id, 'login': event.actor_login}, 'at': event.at}
        if role not in _roles_of(roles, event.actor_id):
            item['rejected'].append({**entry, 'problem': 'no_role'})
            continue
        at = _platform_time(event.at)
        reasons = [c for t, c in comments if c.author_id == event.actor_id and (since is None or t > since) and t <= at]
        if not reasons:
            item['rejected'].append({**entry, 'problem': 'no_reason'})
            continue
        item['decisions'].append({**entry, 'reason': '\n\n'.join(c.body for c in reasons),
                                  'reason_comments': [{'id': c.id, 'updated_at': c.updated_at} for c in reasons]})
        since = at


def sync(record, roles, platform):
    """The record with the decisions the platform reports on each item's issue, checked against roles
    (〈定義：覆核紀錄〉)."""
    record = copy.deepcopy(record)
    for item in record['items']:
        _sync_item(item, roles, platform)
    return record


def _item_for(record, finding):
    """The record's item for a finding: same fingerprint, fingerprint version and requirement version
    (TK-DAT-013 1); a revised requirement or fingerprint algorithm starts a new review."""
    key = finding['fingerprint'], finding['fingerprint_version'], finding['requirement_version']
    for item in record['items']:
        if (item['fingerprint'], item['fingerprint_version'],
                item['versions']['requirement_version']) == key:
            return item
    return None


def _checked(report_doc):
    problems = report.validate(report_doc)
    if problems:
        raise ReportUnusable('the report is not valid; no issue was opened: ' + '; '.join(problems))
    return report_doc


def _publish_finding(record, finding, report_doc, platform, now):
    """Open the issue and add the item of a finding the record has no item for (〈定義：覆核紀錄〉 項目, 工單)."""
    if _item_for(record, finding):
        return  # already under review; its item and issue carry on
    title, body = report.render_review_issue(finding, report_doc, OPTION_OF_LABEL)
    number = platform.create_issue(title, body)
    record['items'].append({
        'review_type': 'candidate_finding', 'fingerprint': finding['fingerprint'],
        'fingerprint_version': finding['fingerprint_version'], 'issue': number, 'opened_at': now,
        'versions': {'requirement_id': finding['requirement_id'],
                     'requirement_version': finding['requirement_version'],
                     'commit': report_doc['commit'], 'run_id': report_doc['run_id']},
        'decisions': [], 'rejected': []})


def publish(record, report_doc, platform, now):
    """The record with an item, and an issue on the platform, for each finding of the report that has
    none; now is when the review starts."""
    record = copy.deepcopy(record)
    for finding in _checked(report_doc)['findings']:
        _publish_finding(record, finding, report_doc, platform, now)
    return record


def sync_file(path, roles_path, roles_digest, platform, now, source_root):
    """sync() on the review record at path, with the roles record at roles_path; both are control-zone
    records outside source_root. Each item is written whole as soon as it is read; a sync that fails part-way
    keeps what it wrote (〈定義：覆核紀錄〉 同步失敗). Returns the digest of the record written."""
    roles = _roles(roles_path, roles_digest, source_root)
    record = _current(path, source_root)
    for item in record['items']:
        try:
            _sync_item(item, roles, platform)
        except PlatformError as e:
            raise SyncFailed(f'sync stopped at issue {item["issue"]}: {e}; the items before it are written, '
                             f'the last complete sync is {record.get("synced_at") or "none"}') from e
        _write(path, record, source_root)  # each item whole, as soon as it is read
    record['synced_at'] = now
    return _write(path, record, source_root)


def publish_file(path, report_doc, platform, now, source_root, new=None):
    """publish() on the review record at path, a control-zone record outside source_root. new
    ({'platform', 'repo'}) starts a record; without it the record must exist (〈定義：覆核紀錄〉 建立與遺失).
    Each opened issue is written at once, so a publish that fails part-way loses none (同步失敗). Returns
    its digest."""
    if new:
        control.outside_source(path, source_root, 'review record')  # before any issue is opened
        if Path(path).exists():
            raise control.RecordUnusable(f'{path} exists; a new review record never replaces one, which would '
                                         f'drop the decisions in it')
        record = {'schema_version': '1', 'platform': new['platform'], 'repo': new['repo'], 'items': []}
    else:
        record = _current(path, source_root)
    _checked(report_doc)
    digest = _write(path, record, source_root)  # before any issue is opened: the record can be written
    for finding in report_doc['findings']:
        opened = len(record['items'])
        try:
            _publish_finding(record, finding, report_doc, platform, now)
        except PlatformError as e:
            raise PublishFailed(f'publish stopped at {finding["id"]}: {e}; the issues opened before it are in '
                                f'the record, run publish again for the rest') from e
        try:
            digest = _write(path, record, source_root)  # an opened issue is never lost
        except control.RecordUnusable as e:
            numbers = [i['issue'] for i in record['items'][opened:]]
            raise PublishFailed(f'issue {numbers} was opened but {e}; add it to the record by hand') from e
    return digest


def _review_of(item, now):
    """A finding's review as the report shows it: its state, and the current decision when there is one.
    Past its deadline an undecided review is overdue; that changes nothing else (TK-HRV-007)."""
    if item is None:
        return {'state': 'pending'}
    shown = {'opened_at': item['opened_at']}
    if not item['decisions']:
        late = control.utc_time(now) > control.utc_time(item['opened_at']) + DEADLINES[item['review_type']]
        return {'state': 'overdue' if late else 'pending', **shown}
    d = item['decisions'][-1]
    return {'state': report.DECISION_STATES[d['option']], **shown,
            'decision': {'option': d['option'], 'by': d['by'], 'at': d['at'], 'reason': d['reason']}}


def apply(report_doc, record, ref, now):
    """The report with each finding's review state and current decision from the review record at ref
    ({path, digest}); without a record every finding waits for review. A decision only ever makes the status
    more cautious: evidence_pending lowers confirmed to evidence_pending (〈定義：覆核紀錄〉 目前的決定).
    Past its deadline an undecided review is overdue (期限與逾期)."""
    doc = copy.deepcopy(report_doc)
    for finding in doc['findings']:
        item = _item_for(record, finding) if record else None
        finding['review'] = _review_of(item, now)
        if finding['review']['state'] == 'evidence_pending' and finding['status'] == 'confirmed':
            finding['status'] = 'evidence_pending'  # a decision only ever makes the status more cautious
    doc['review_record'] = dict(ref) if ref else None  # null: this run used no review record
    states = [f['review']['state'] for f in doc['findings']]
    doc['review_summary'] = {s: states.count(s) for s in report.FINDING_REVIEW_STATES}
    return doc


TOKEN_VARIABLE = 'MAZ_REVIEW_GITHUB_TOKEN'


def _parser():
    parser = argparse.ArgumentParser(prog='python3 -I toolkit/tools/review_record.py',
                                     description='Keep the review record (〈定義：覆核紀錄〉) in step with the platform.')
    actions = parser.add_subparsers(dest='action', required=True)
    for name in ('publish', 'sync'):
        p = actions.add_parser(name)
        p.add_argument('--record', required=True, help='the review record, in the control zone')
        p.add_argument('--repo', required=True, help='OWNER/NAME of the repository the issues are on')
        p.add_argument('--project', required=True, help='the sample source, which the records must stay out of')
    publish = actions.choices['publish']
    publish.add_argument('--report', required=True, help='the JSON report whose findings get an issue')
    publish.add_argument('--new', action='store_true', help='start a new review record; never replaces one')
    sync = actions.choices['sync']
    sync.add_argument('--roles', required=True, help='the review roles record, in the control zone')
    sync.add_argument('--roles-digest', required=True, help='its digest')
    return parser


def _report(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as e:
        raise ReportUnusable(f'the report {path} cannot be read: {e}') from e


def main(argv, environ, platform_factory, out):
    """The command line. platform_factory(repo, token) gives the platform; the token comes from
    MAZ_REVIEW_GITHUB_TOKEN and is never printed or written, and without it nothing is done. A record kept
    for another platform or repository is not used: its issue numbers mean other issues there
    (〈定義：覆核紀錄〉 身分, 工單). Returns the exit status."""
    args = _parser().parse_args(argv)
    token = environ.get(TOKEN_VARIABLE)
    if not token:
        print(f'{TOKEN_VARIABLE} is not set: nothing was {args.action}ed and nothing was written', file=out)
        return 2
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    try:
        if not (args.action == 'publish' and args.new):
            kept = _current(args.record, args.project)
            if (kept['platform'], kept['repo']) != ('github', args.repo):
                raise control.RecordUnusable(
                    f'{args.record} is kept for {kept["platform"]} {kept["repo"]}, not github {args.repo}: its '
                    f'issue numbers mean other issues there')
        platform = platform_factory(args.repo, token)
        if args.action == 'sync':
            digest = sync_file(args.record, args.roles, args.roles_digest, platform, now, args.project)
        else:
            new = {'platform': 'github', 'repo': args.repo} if args.new else None
            digest = publish_file(args.record, _report(args.report), platform, now, args.project, new=new)
    except (SyncFailed, PublishFailed, control.RecordUnusable, ReportUnusable) as e:
        print(f'{args.action} failed: {e}', file=out)
        return 1
    print(f'review record {args.record}: {digest}', file=out)
    return 0
