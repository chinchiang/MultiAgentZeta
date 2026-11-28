"""Report contract of a scan run: validate(report) and render_markdown(report).

The JSON report is the native format (TK-EVD-003); its structure is the versioned
JSON Schema in schemas/report-v1.json. validate() also checks the conditions that
span records, which JSON Schema cannot express.
"""
import hashlib
import json
import re
from pathlib import Path

import jsonschema

from toolkit import control, item_rule, policy

SCHEMA = json.loads((Path(__file__).parent / 'schemas' / 'report-v1.json').read_text(encoding='utf-8'))


def _schema_problems(doc):
    validator = jsonschema.Draft202012Validator(SCHEMA)
    return [f'{"/".join(map(str, e.absolute_path)) or "(report)"}: {e.message}' for e in validator.iter_errors(doc)]


def _list(doc, key):
    value = doc.get(key) if isinstance(doc, dict) else None
    return value if isinstance(value, list) else []


def _records(doc):
    """(label, record) of every record inside the report."""
    for key in ('execution_records', 'findings'):
        for i, r in enumerate(_list(doc, key)):
            yield f'{key}/{i}', r
    if isinstance(doc, dict) and isinstance(doc.get('coverage'), dict):
        yield 'coverage', doc['coverage']


STAGES = ('preflight', 'static_analysis', 'model_review', 'threat_planning', 'dynamic_execution', 'judgement_report')


def _cross_record_problems(doc):
    problems = []
    listed = {s.get('stage') for s in _list(doc, 'stages') if isinstance(s, dict)}
    if isinstance(doc, dict) and 'stages' in doc:
        problems += [f'stages: stage {s!r} of 〈定義：工作階段〉 is not listed' for s in STAGES if s not in listed]
    if isinstance(doc, dict):
        for label, r in _records(doc):
            for field in ('run_id', 'commit'):
                if isinstance(r, dict) and field in r and field in doc and r[field] != doc[field]:
                    problems.append(f'{label}: {field} {r[field]!r} differs from the report ({doc[field]!r}); '
                                    'every record belongs to this run and its tested commit')
    results = {r.get('id'): r.get('result') for r in _list(doc, 'execution_records') if isinstance(r, dict)}
    seen = {}
    for i, f in enumerate(_list(doc, 'findings')):
        if not isinstance(f, dict):
            continue
        ids = f.get('execution_record_ids') if isinstance(f.get('execution_record_ids'), list) else []
        problems += [f'findings/{i}: execution_record_ids names {x!r}, which is no execution record of this report'
                     for x in ids if not isinstance(x, str) or x not in results]
        # 〈定義：覆核紀錄〉 項目: one finding per fingerprint, fingerprint version and requirement version.
        key = json.dumps([f.get('fingerprint'), f.get('fingerprint_version'), f.get('requirement_version')], default=str)
        if key in seen:
            problems.append(f'findings/{i}: same fingerprint, fingerprint version and requirement version as '
                            f'findings/{seen[key]}; they are one finding with both execution records (〈定義：覆核紀錄〉)')
        seen.setdefault(key, i)
        if f.get('status') != 'confirmed':
            continue
        if not any(results.get(x) == 'failed' for x in ids if isinstance(x, str)):
            problems.append(f'findings/{i}: a confirmed finding needs a failed execution record; '
                            f'execution_record_ids {ids} do not include one')
    return (problems + _limit_problems(doc) + _requirement_problems(doc) + _approval_problems(doc)
            + _review_problems(doc) + _environment_problems(doc) + _coverage_problems(doc) + _abort_problems(doc)
            + _package_problems(doc))


# TK-DAT-009: what every evidence reference carries besides the evidence itself.
EVIDENCE_TYPES = {'actor': 'request_response', 'observer': 'observation'}  # by the channel it was obtained through
EVIDENCE_SOURCES = {'actor': "the application's API, as the identity named", 'observer': 'the database, as the read-only observer role'}
EVIDENCE_ACCESS = 'restricted'  # evidence may hold test data and paths: it is not for general distribution
REFERENCE_FIELDS = ('digest', 'type', 'captured_at', 'source', 'access_level')


def evidence_digest(evidence):
    """The content digest of one piece of evidence (TK-DAT-009): over everything but its id and the digest
    itself. It helps to notice that bytes changed; it proves nothing about where the evidence came from."""
    content = {k: v for k, v in evidence.items() if k not in ('id', 'digest')}
    return 'sha256:' + hashlib.sha256(json.dumps(content, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def evidence_reference(evidence, captured_at):
    """The evidence with the fields of its reference (TK-DAT-009): type, capture time, source, access level and,
    last, the digest of all of it."""
    channel = evidence['channel']
    ref = {**evidence, 'type': EVIDENCE_TYPES[channel], 'captured_at': captured_at, 'source': EVIDENCE_SOURCES[channel],
           'access_level': EVIDENCE_ACCESS}
    return {**ref, 'digest': evidence_digest(ref)}


def changed_evidence(doc):
    """The ids of the evidence whose content no longer matches its digest (TK-DAT-009)."""
    return [ev.get('id') for e in _list(doc, 'execution_records') if isinstance(e, dict)
            for ev in e.get('evidence') or [] if isinstance(ev, dict) and ev.get('digest') != evidence_digest(ev)]


def _texts(value):
    return isinstance(value, str) and bool(value.strip())


def evidence_package(doc):
    """〈定義：最低證據包的項目〉 (TK-EVD-001): each item of the minimum evidence package and whether this report
    holds it, computed from the report alone. present names where the item is, missing says why it is not
    there, not_applicable says why this version has no such thing. Nothing is counted as present on trust."""
    env = doc.get('environment') if isinstance(doc.get('environment'), dict) else None
    execs = [e for e in _list(doc, 'execution_records') if isinstance(e, dict)]
    ran = [e for e in execs if e.get('evidence')]
    evidence = [ev for e in ran for ev in e['evidence'] if isinstance(ev, dict)]
    findings = [f for f in _list(doc, 'findings') if isinstance(f, dict)]
    by_id = {e.get('id'): e for e in execs}
    denials = [e for e in ran if e.get('case_kind') != 'allowed']
    images = env.get('service_images') if env else None
    coverage = doc.get('coverage') if isinstance(doc.get('coverage'), dict) else {}
    no_env = 'no environment was prepared'

    def held(code, ok, where, why):
        return {'item': code, 'status': 'present' if ok else 'missing', 'note': where if ok else why}

    def none(code, why):
        return {'item': code, 'status': 'not_applicable', 'note': why}
    return [
        held('commit', _texts(doc.get('commit')), 'commit', 'the ScanManifest named no commit'),
        none('build_artifact_digest', 'no build is run in this version; the source is the one the BuildRecipe pins'),
        held('container_image_digests', bool(images) and all(isinstance(i, dict) and _texts(i.get('digest')) for i in images),
             'environment.service_images', no_env if not env else 'a service image has no content digest'),
        held('environment_differences', env is not None, 'environment.known_differences', no_env),
        held('requirement_test_finding_links',
             bool(execs) and all(_texts(e.get('requirement_id')) for e in ran)
             and all(i in by_id for f in findings for i in f.get('execution_record_ids') or []),
             'execution_records[].requirement_id, findings[].execution_record_ids',
             'no test was recorded' if not execs else 'a record or a finding names nothing that is in the report'),
        none('threat_links', 'threat modelling is not part of this version (stage threat_planning is not_run)'),
        held('toolkit_version', _texts(doc.get('toolkit_version')), 'toolkit_version', 'the report names no toolkit version'),
        held('rule_and_template_versions',
             _texts((coverage.get('inventory') or {}).get('rule')) and all(_texts(e.get('template_id')) for e in ran),
             'coverage.inventory.rule, execution_records[].template_id, findings[].fingerprint_version',
             'the extraction rule or a test template is not named'),
        none('model_and_prompt_versions', 'no model is called in this version'),
        held('identity_references', bool(doc.get('authorization_matrix')), 'authorization_matrix, execution_records[].actor_ref',
             no_env),
        held('synthetic_data_version', bool(env) and _texts(env.get('seed_version')), 'environment.seed_version, environment.test_data',
             no_env if not env else 'the BuildRecipe names no seed version'),
        none('random_seed', 'no test of this version draws random input'),
        held('preconditions', bool(ran) and all(e.get('checks') is not None for e in ran if e.get('result') in ('passed', 'failed')),
             'execution_records[].checks', 'no case ran' if not ran else 'a judged case has no checks'),
        held('requests_and_responses', any(ev.get('channel') == 'actor' for ev in evidence),
             'execution_records[].evidence: method, path, status and row count; no body is kept, so nothing needs masking',
             'no case made a request'),
        (held('positive_control_and_state_difference', any(ev.get('channel') == 'observer' for ev in evidence),
              "execution_records[].evidence: the owner's control request and the observer's states before and after",
              'no denial case reached its observation')
         if denials or not ran else none('positive_control_and_state_difference', 'no denial case ran: allowed cases make no observation')),
        held('error_records', bool(execs), 'execution_records[].error', 'no test was recorded'),
        held('timing', bool(execs) and all(_texts(e.get('started_at')) and _texts(e.get('ended_at')) for e in execs),
             'execution_records[].started_at and ended_at, limits.elapsed_seconds', 'a record has no start or end time'),
        none('cost', 'no model is called: nothing is billed'),
        none('retries', 'no request is retried in this version'),
        held('cancellation', True, 'abort' if 'abort' in doc else 'no abort was requested; a cancelled case is named in execution_records[].result', ''),
        (held('reproduction_steps', all(any(by_id.get(i, {}).get('evidence') for i in f.get('execution_record_ids') or []) for f in findings),
              "the requests of each finding's execution records, in order", 'a finding has no execution record with evidence')
         if findings else none('reproduction_steps', 'the run has no finding')),
        ({'item': 'fix_and_regression', 'status': 'missing',
          'note': 'this version writes no fix suggestion; the failed test is the regression test to run again'}
         if findings else none('fix_and_regression', 'the run has no finding')),
        held('limitations', bool(coverage), 'coverage.claim, coverage.unsupported_items, environment.known_differences, stages',
             'the report has no coverage record'),
    ]


def _package_problems(doc):
    """TK-EVD-001: the evidence package a report states is the one its content gives; in particular nothing is
    stated as held that the report does not hold."""
    if not isinstance(doc, dict) or not isinstance(doc.get('evidence_package'), list):
        return []
    computed = evidence_package(doc)
    stated = doc['evidence_package']
    if [i.get('item') if isinstance(i, dict) else None for i in stated] != [i['item'] for i in computed]:
        return ['evidence_package: it lists every item of 〈定義：最低證據包的項目〉 once, in order (TK-EVD-001)']
    return [f"evidence_package/{c['item']}: stated {s.get('status')!r}, but the report gives {c['status']!r}: {c['note']} (TK-EVD-001)"
            for s, c in zip(stated, computed) if s.get('status') != c['status']]



ABORT_STEPS = ('dispatch_stopped', 'credentials_revoked', 'in_flight_ended', 'evidence_kept', 'in_flight_checked',
               'environment_isolated')  # TK-RUN-005


def _abort_problems(doc):
    """〈定義：中止與清理〉 (TK-RUN-004, TK-RUN-005, TK-RUN-006, TK-ENV-003): a cleanup record exactly when an
    environment was prepared; an environment that was not destroyed has its leftovers named and the run is
    not completed; a cancelled run has an abort record and a cancelled case; the abort's steps are in the
    order of TK-RUN-005 with times that do not go back, and over_limit is what the times and limits give."""
    if not isinstance(doc, dict):
        return []
    problems = []
    cleanup = doc.get('cleanup')
    if ('cleanup' in doc) != ('environment' in doc):
        problems.append('cleanup: present exactly when an environment was prepared (TK-ENV-003)')
    if isinstance(cleanup, dict):
        failed, left = cleanup.get('environment') == 'destroy_failed', cleanup.get('leftovers')
        if failed != bool(left):
            problems.append('cleanup: leftovers are named exactly when the environment was not destroyed (TK-ENV-003)')
        if failed and doc.get('status') == 'completed':
            problems.append("cleanup: status cannot be 'completed' when the environment was not destroyed (TK-ENV-003)")
    stages = {s.get('stage'): s.get('status') for s in _list(doc, 'stages') if isinstance(s, dict)}
    if ('environment_build' in doc) != (stages.get('dynamic_execution') not in (None, 'not_run')):
        problems.append('environment_build: present exactly when the environment was asked for, that is when '
                        'dynamic_execution is not not_run (〈定義：環境建置的量測〉)')
    measure = doc.get('environment_build')
    if isinstance(measure, dict):
        counts = {**{k: v for k, v in measure.items() if k != 'authentication'},
                  **{f'authentication/{n}': v for n, v in (measure.get('authentication') or {}).items()}}
        problems += [f'environment_build/{name}: successes cannot exceed attempts (TK-ENV-006)'
                     for name, c in counts.items()
                     if isinstance(c, dict) and isinstance(c.get('attempts'), int) and isinstance(c.get('successes'), int)
                     and c['successes'] > c['attempts']]
    if doc.get('self_validation') is not True and any(isinstance(e, dict) and 'fault' in e
                                                      for e in _list(doc, 'execution_records')):
        problems.append('execution_records: a fault is injected in a self-validation run only; the report of such '
                        'a run says self_validation (〈定義：故障注入〉)')
    abort = doc.get('abort')
    if doc.get('status') == 'cancelled':
        if not isinstance(abort, dict):
            problems.append('abort: a cancelled run records who asked for the abort, why and when (TK-RUN-004)')
        if not any(isinstance(e, dict) and e.get('result') == 'cancelled' for e in _list(doc, 'execution_records')):
            problems.append('status: a cancelled run has at least one cancelled case (TK-RUN-005)')
    if not isinstance(abort, dict):
        return problems
    steps = [s for s in abort.get('steps') or [] if isinstance(s, dict)]
    order = [ABORT_STEPS.index(s['step']) for s in steps if s.get('step') in ABORT_STEPS]
    if order != sorted(set(order)):
        problems.append('abort: steps are in the order of TK-RUN-005, each once')
    seconds = [s.get('seconds') for s in steps if isinstance(s.get('seconds'), (int, float))]
    if seconds != sorted(seconds):
        problems.append('abort: the time of a step is not before the step ahead of it (TK-RUN-005)')
    measured, limits = abort.get('seconds'), abort.get('limits_seconds')
    if isinstance(measured, dict) and isinstance(limits, dict):
        over = [n for n, v in measured.items() if isinstance(v, (int, float)) and isinstance(limits.get(n), (int, float))
                and v > limits[n]]
        if sorted(over) != sorted(abort.get('over_limit') or []):
            problems.append(f'abort: over_limit must be {sorted(over)}, the times above their limit (TK-RUN-006)')
    return problems


def _limit_problems(doc):
    """〈定義：執行限制的執行〉 (TK-BUD-003): a run never used more than its stated limit on requests or ran more
    cases at once than it allows, and a run that left a limit unstated did not get past preflight."""
    limits = doc.get('limits') if isinstance(doc, dict) else None
    if not isinstance(limits, dict):
        return []
    problems = []
    stated, used = limits.get('max_requests'), limits.get('requests')
    if isinstance(stated, int) and isinstance(used, int) and used > stated:
        problems.append(f'limits: {used} requests were made, more than max_requests {stated} (TK-BUD-003)')
    allowed, ran = limits.get('max_concurrency'), limits.get('concurrency')
    if isinstance(allowed, int) and isinstance(ran, int) and ran > allowed:
        problems.append(f'limits: {ran} cases ran at once, more than max_concurrency {allowed} (TK-BUD-003)')
    unstated = [name for name in ('max_requests', 'max_duration_seconds', 'max_concurrency') if limits.get(name) is None]
    ran_any = any(isinstance(e, dict) and e.get('result') in ('passed', 'failed', 'error')
                  for e in _list(doc, 'execution_records'))
    if unstated and (used or ran_any):
        problems.append(f'limits: {", ".join(unstated)} not stated, yet cases ran; a run without its limits is '
                        f'blocked in preflight and no unlimited default is used (TK-SCP-002)')
    return problems


def _environment_problems(doc):
    """Environment summary and versions outside the support matrix (〈定義：核心資料物件與相依紀錄〉, 〈定義：工作階段〉,
    TK-SCP-001, TK-ENV-007, TK-EVD-005, TK-EVD-008, TK-EVD-009): environment is required once dynamic_execution
    completed or failed (or status is completed/partial) and omitted when dynamic_execution is not_run; when
    environment.unsupported is non-empty, dynamic_execution and overall status must be blocked, no test can run
    beyond blocked/unsupported, coverage cannot claim whole_scope, and every unsupported environment entry must
    appear in coverage.unsupported_items."""
    if not isinstance(doc, dict):
        return []
    stages = {s.get('stage'): s.get('status') for s in _list(doc, 'stages') if isinstance(s, dict)}
    has_env = 'environment' in doc
    problems = []
    if not has_env and (doc.get('status') in ('completed', 'partial')
                        or stages.get('dynamic_execution') in ('completed', 'failed', 'cancelled')):
        problems.append('environment: required when status is completed/partial or dynamic_execution ran '
                        '(〈定義：核心資料物件與相依紀錄〉, TK-EVD-005)')
    if has_env and stages.get('dynamic_execution') == 'not_run':
        problems.append("environment: must be omitted when dynamic_execution is 'not_run' "
                        "(〈定義：核心資料物件與相依紀錄〉)")
    env = doc.get('environment')
    unsupported = env.get('unsupported') if isinstance(env, dict) else None
    if not (isinstance(unsupported, list) and unsupported):
        return problems
    if doc.get('status') != 'blocked':
        problems.append(f"environment: status must be 'blocked' when environment.unsupported is non-empty, "
                        f"not {doc.get('status')!r} (TK-SCP-001, TK-ENV-007)")
    for s in _list(doc, 'stages'):
        if isinstance(s, dict) and s.get('stage') == 'dynamic_execution' and s.get('status') != 'blocked':
            problems.append(f"stages: dynamic_execution must be 'blocked' when environment.unsupported is non-empty, "
                            f"not {s.get('status')!r} (TK-SCP-001, 〈定義：工作階段〉)")
    for i, e in enumerate(_list(doc, 'execution_records')):
        if isinstance(e, dict) and e.get('result') not in ('blocked', 'unsupported'):
            problems.append(f"execution_records/{i}: result cannot be {e.get('result')!r} when environment.unsupported "
                            f"is non-empty; no test runs against an unverified environment (TK-SCP-001, TK-ENV-007)")
    cov = doc.get('coverage') if isinstance(doc.get('coverage'), dict) else {}
    if cov.get('claim') == 'whole_scope':
        problems.append("coverage: claim cannot be 'whole_scope' when environment.unsupported is non-empty "
                        "(TK-SCP-001, TK-EVD-009)")
    scopes = {i.get('scope') for i in _list(cov, 'unsupported_items') if isinstance(i, dict)}
    problems += [f"coverage: unsupported_items lacks 'environment:{u}' from environment.unsupported "
                 f"(TK-SCP-001, TK-EVD-008)"
                 for u in dict.fromkeys(u for u in unsupported if isinstance(u, str))
                 if f'environment:{u}' not in scopes]
    return problems


COVERAGE_CLASSES = ('executed', 'blocked', 'errors', 'untested', 'cancelled', 'unsupported')


def _count(cov, name):
    value = cov.get(name)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _coverage_problems(doc):
    """The numbers of the coverage record that the schema cannot tie together (〈定義：覆蓋面向〉, TK-EVD-008,
    TK-EVD-009): the classes add up to the denominator, which is the execution records plus the unsupported
    scopes; a rate is what its numbers give, and over a zero denominator it is none, never full coverage."""
    cov = doc.get('coverage') if isinstance(doc, dict) else None
    if not isinstance(cov, dict):
        return []
    problems = []
    den, executed, valid = _count(cov, 'denominator'), _count(cov, 'executed'), _count(cov, 'valid_judgements')
    classes = [_count(cov, c) for c in COVERAGE_CLASSES]
    records, items, excluded = _list(doc, 'execution_records'), cov.get('unsupported_items'), cov.get('excluded')
    if executed is not None and valid is not None and valid > executed:
        problems.append(f'coverage: valid_judgements {valid} is more than executed {executed}')
    if den is not None and None not in classes and sum(classes) != den:
        problems.append(f'coverage: {", ".join(COVERAGE_CLASSES)} add up to {sum(classes)}, not the denominator {den}')
    # 〈定義：覆蓋面向〉 排除項: what an exclusion took out is named, so the denominator is counted, not bounded.
    left_ids = cov.get('excluded_record_ids')
    record_ids = [r.get('id') for r in records if isinstance(r, dict)]
    cases = len(records)
    if isinstance(left_ids, list):
        if len(set(map(str, left_ids))) != len(left_ids):
            problems.append('coverage: excluded_record_ids names an execution record more than once')
        problems += [f'coverage: excluded_record_ids names {i!r}, which is no execution record of this report'
                     for i in left_ids if i not in record_ids]
        if left_ids and not excluded:
            problems.append('coverage: execution records are left out of the denominator but nothing is excluded')
        cases -= len({i for i in left_ids if isinstance(i, str)} & set(record_ids))
    if den is not None and isinstance(items, list) and isinstance(excluded, list):
        left_refs = {e.get('ref') for e in excluded if isinstance(e, dict)}
        scopes = sum(not (isinstance(u, dict) and u.get('scope') in left_refs) for u in items)
        if den != cases + scopes:
            problems.append(f'coverage: denominator {den} is not the {cases} execution records plus the {scopes} '
                            f'unsupported scopes that are not excluded ({cases + scopes})')
    states = cov.get('states') if isinstance(cov.get('states'), dict) else {}
    unsupported = _count(cov, 'unsupported')
    wanted = {  # what each rate is, when it can be told: None means the report does not say
        'effective_judgement_rate': valid / den if den and valid is not None else None,
        'tool_support_rate': (den - unsupported) / den if den and unsupported is not None else None,
        'required_test_completion_rate': executed / cases if cases > 0 and executed is not None else None}
    # A rate with nothing to divide by has no number, and says why (TK-EVD-009): not applicable when something was
    # excluded, insufficient data when not. The completion rate has no cases to divide by when every execution
    # record was left out with its items, or none exists.
    has_excluded = isinstance(excluded, list) and bool(excluded)
    zero = {name: den == 0 for name in wanted}
    zero['required_test_completion_rate'] = den == 0 or cases <= 0
    for name, number in wanted.items():
        rate, state = cov.get(name), states.get(name)
        if zero[name]:
            if rate is not None:
                problems.append(f'coverage: {name} {rate!r} is over a zero denominator and must be none, never full coverage '
                                f'(TK-EVD-009)')
            expected = 'not_applicable' if has_excluded else 'insufficient_data'
            if state is not None and state != expected:
                problems.append(f'coverage: {name} is {state!r} over a zero denominator; it is {expected!r} when '
                                f'{"something was" if has_excluded else "nothing was"} excluded (TK-EVD-009)')
        elif state == 'measured' and rate is None:
            problems.append(f'coverage: {name} is measured but has no number')
        elif state in ('not_applicable', 'insufficient_data') and rate is not None:
            problems.append(f'coverage: {name} is {state} but has the number {rate!r}')
        elif isinstance(rate, (int, float)) and number is not None and abs(rate - number) > 1e-9:
            problems.append(f'coverage: {name} {rate!r} is not {number!r}, what its numbers give')
    inv = cov.get('inventory') if isinstance(cov.get('inventory'), dict) else {}
    if cov.get('claim') == 'whole_scope' and inv.get('completeness') != 'complete':
        problems.append(f"coverage: claim 'whole_scope' needs a complete inventory, but it is {inv.get('completeness')!r} (TK-EVD-009)")
    return problems


def _review_problems(doc):
    """A decision only ever makes a finding's status more cautious: one sent back for evidence is not
    confirmed (〈定義：覆核紀錄〉 目前的決定)."""
    problems = []
    summary = doc.get('review_summary') if isinstance(doc, dict) else None
    if isinstance(summary, dict):
        states = [f['review'].get('state') for f in _list(doc, 'findings')
                  if isinstance(f, dict) and isinstance(f.get('review'), dict)]
        problems += [f'review_summary: {s} is {n}, but {states.count(s)} findings are in that review state '
                     f'(〈定義：覆核紀錄〉 報告)' for s, n in summary.items() if isinstance(n, int) and n != states.count(s)]

    for i, f in enumerate(_list(doc, 'findings')):
        review = f.get('review') if isinstance(f, dict) else None
        if not isinstance(review, dict):
            continue
        decision = review.get('decision') if isinstance(review.get('decision'), dict) else {}
        state, option = review.get('state'), decision.get('option')
        if doc.get('review_record') is None and (state != 'pending' or decision or 'opened_at' in review):
            problems.append(f'findings/{i}: review_record is null, so no review started and nobody decided '
                            f'anything: the review is pending with no start and no decision (〈定義：覆核紀錄〉)')
        elif state in WAITING_STATES and decision:
            problems.append(f'findings/{i}: review state {state} has a decision; a decided review is in the '
                            f'state its decision leaves (〈定義：覆核紀錄〉)')
        elif state in DECISION_STATES.values() and DECISION_STATES.get(option) != state:
            problems.append(f'findings/{i}: review state {state} does not match its decision {option!r} '
                            f'(〈定義：覆核紀錄〉)')
        problems += [f'findings/{i}: review {where} {value!r} is not an ISO 8601 UTC time (〈定義：覆核紀錄〉)'
                     for where, value in (('opened_at', review.get('opened_at')), ('decision at', decision.get('at')))
                     if value is not None and control.utc_time(value) is None]

    def sent_back(f):
        decision = f.get('review', {}).get('decision') if isinstance(f.get('review'), dict) else None
        return isinstance(decision, dict) and decision.get('option') == 'evidence_pending'
    return problems + [f'findings/{i}: its current review decision is evidence_pending, so its status is '
                       f'evidence_pending, not confirmed (〈定義：覆核紀錄〉)'
                       for i, f in enumerate(_list(doc, 'findings'))
                       if isinstance(f, dict) and f.get('status') == 'confirmed' and sent_back(f)]


def _approval_problems(doc):
    """An execution record names only an extra approval the report's authorization holds (〈定義：測試授權紀錄〉)."""
    granted = doc.get('authorization') if isinstance(doc, dict) else None
    approvals = granted.get('extra_approvals') if isinstance(granted, dict) else None
    ids = {a.get('approval_id') for a in approvals if isinstance(a, dict)} if isinstance(approvals, list) else set()
    return [f'execution_records/{i}: approval_id {e["approval_id"]!r} is not an extra approval of the authorization '
            f'(TK-ENV-001)'
            for i, e in enumerate(_list(doc, 'execution_records'))
            if isinstance(e, dict) and 'approval_id' in e and e['approval_id'] not in ids]


def listed_item(items, record):
    """The item a record or a planned test rests on, by its requirement_id, or None: the one lookup the
    toolkit and validate() share. items maps ids to confirmation-list items or requirements[] entries."""
    rid = record.get('requirement_id') if isinstance(record, dict) else None
    return items.get(rid) if isinstance(rid, str) else None


REVIEW_LABELS = dict(zip(item_rule.REVIEW_STATES, ('待確認', '接受', '修改', '不適用')))


def _requirement_problems(doc):
    """Records against the confirmation items the report lists: version (TK-REQ-004), blocked tests
    (〈定義：確認清單〉), case kind against the rule (TK-REQ-016) and the finding cap (TK-REQ-003)."""
    items = {r.get('id'): r for r in _list(doc, 'requirements') if isinstance(r, dict) and isinstance(r.get('id'), str)}
    problems = []
    for i, e in enumerate(_list(doc, 'execution_records')):
        item = listed_item(items, e)
        if item is None:
            continue
        version = (item.get('confirmation') or {}).get('version')
        if e.get('requirement_version') != version:
            problems.append(f'execution_records/{i}: requirement_version {e.get("requirement_version")!r} differs '
                            f'from version {version!r} of {item["id"]!r} in requirements (TK-REQ-004)')
        if e.get('result') == 'blocked':
            continue
        reason = item_rule.untestable(item, REVIEW_LABELS)
        if reason:
            problems.append(f'execution_records/{i}: {item["id"]!r} {reason}; a test on it must be blocked, '
                            f'not {e.get("result")!r} (〈定義：確認清單〉)')
        kind = e.get('case_kind', item_rule.DENIAL)
        rule = item_rule.rule_for(item, e.get('test_id'), kind)
        if e.get('result') in ('passed', 'failed') and item_rule.RULE_FOR_CASE.get(kind) != rule:
            problems.append(f'execution_records/{i}: a {kind} case on {item["id"]!r} (rule {rule!r} for '
                            f'{e.get("test_id")!r}) must be blocked, not {e.get("result")!r} (TK-REQ-016)')
    for i, f in enumerate(_list(doc, 'findings')):
        item = listed_item(items, f)
        if item and f.get('status') == 'confirmed' and item_rule.finding_cap(item) != 'confirmed':
            problems.append(f'findings/{i}: {item["id"]!r} is {item.get("status")!r}; a finding on it is at most '
                            f'evidence_pending, not confirmed (TK-REQ-003)')
    return problems


def validate(doc):
    """Problems with a report, as human-readable strings; [] means valid."""
    return _schema_problems(doc) + _cross_record_problems(doc)


# Spec names for the codes used in the JSON report.
RUN_LABELS = {'pending': '待執行', 'running': '執行中', 'completed': '完整完成', 'partial': '部分完成',
              'blocked': '受阻', 'failed': '失敗', 'cancelled': '已取消'}
RESULT_LABELS = {'passed': '通過', 'failed': '未通過', 'blocked': '受阻', 'error': '執行錯誤',
                 'untested': '未測試', 'cancelled': '取消', 'unsupported': '不支援'}
FINDING_LABELS = {'confirmed': '已確認', 'evidence_pending': '證據待補', 'not_reproduced': '本次未重現',
                  'excluded': '已排除', 'fixed_pending_regression': '已修復待回歸', 'regression_passed': '回歸通過'}
COMPLETED_NOTE = ('「完整完成」表示計畫內的測試都取得明確結果；只對本次範圍與條件有效，'
                  '不代表應用沒有漏洞（TK-RUN-002）。')


# Every text of a report that a person or a file outside the toolkit wrote (a ScanManifest, a BuildRecipe, a
# control-zone record, the platform) goes through one of these before it reaches the Markdown (TK-EVD-002).

def _inline(text):
    """Single-line escaped text safe in Markdown prose (no line break and no raw HTML, TK-EVD-002)."""
    return ' '.join(str(text).split()).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def _code(text):
    """Single-line Markdown code span that untrusted backticks or HTML cannot break out of (TK-EVD-002)."""
    s = ' '.join(str(text).split())
    ticks = max((len(m.group(0)) for m in re.finditer(r'`+', s)), default=0)
    fence = '`' * (ticks + 1)
    pad = ' ' if not s or s[0] in '` ' or s[-1] in '` ' else ''
    return f'{fence}{pad}{s}{pad}{fence}'


def _cell(text):
    """Free text inside one Markdown table cell: no line break, no cell border, and no HTML, which a renderer
    would act on (a comment opener hides the rest of the report)."""
    return _inline(text).replace('|', '\\|')


def _tcode(text):
    """A code span inside one Markdown table cell: a cell border ends the cell even inside a code span."""
    return _code(text).replace('|', '\\|')


def _codes(values, cell=False):
    return '、'.join((_tcode if cell else _code)(v) for v in values)


def _confirmation_summary(listed):
    """TK-REQ-003 各類待確認數量 by source, for the list version they come from (TK-REQ-004), and the
    items approved by one person (〈定義：確認清單〉 單人核准)."""
    t = listed['s2_template']
    lines = ['', '## 確認狀態摘要', '',
             f'- **確認清單**：{_code(listed["path"])} v{_inline(listed["list_version"])}（{_code(listed["digest"])}）'
             + ('；本次產生或更新，待負責人處理：處理其中待確認的項目，再以此路徑與摘要更新 ScanManifest 的引用'
                if listed['updated'] else ''),
             f'- **S2 範本**：{_code(t["policy_template_id"])} v{_inline(t["version"])}（{_code(t["digest"])}）', '',
             '| 來源 | ' + ' | '.join(REVIEW_LABELS.values()) + ' |',
             '| :--- |' + ' ---: |' * len(REVIEW_LABELS)]
    for source, counts in listed['summary'].items():
        lines.append(f'| {_cell(source)} | ' + ' | '.join(_cell(counts[s]) for s in REVIEW_LABELS) + ' |')
    lines += ['', f'- 範圍外 {_inline(listed["out_of_scope"])} 項（不是處理狀態，不計入上表）']
    if listed['single_approval']:
        lines.append('- 單人核准（修改與不適用，尚無第二人核准，TK-REQ-014）：'
                     + _codes(listed['single_approval']))
    return lines


def _operations(ops):
    """Resource × HTTP method operations of 〈定義：測試授權紀錄〉 as one line."""
    return '；'.join(f'{_code(o["resource"])} ' + '、'.join(_inline(m) for m in o['methods']) for o in ops)


def _authorization_section(doc):
    """〈定義：測試授權紀錄〉: what the run was authorized for, by whom (declared, not verified), and the extra
    approvals its tests ran under (TK-ENV-001); and the source changes made for it (TK-ENV-006)."""
    a = doc['authorization']
    lines = ['', '## 測試授權', '',
             f'- **授權紀錄**：{_code(a["path"])}（{_code(a["digest"])}）',
             '- **目標**：' + _codes(a['targets']) + f'（{_inline(a["environment"])}）',
             f'- **期間**：{_inline(a["valid_from"])} 至 {_inline(a["valid_until"])}',
             f'- **資料範圍**：{_inline(a["data_scope"])}',
             '- **允許操作**：' + _operations(a['operations']),
             f'- **簽發**：{_inline(a["issued_by"])} {_inline(a["issued_at"])}；應用負責人 {_inline(a["roles"]["app_owner"])}，'
             f'執行者 {_inline(a["roles"]["operator"])}'
             '（身分未經驗證：是宣告的名稱，TK-HRV-004 的經驗證身分目前只用於覆核紀錄）']
    used = {}
    for e in doc['execution_records']:
        if e.get('approval_id'):
            used.setdefault(e['approval_id'], []).append(e.get('test_id', e['id']))
    for ap in a['extra_approvals']:
        tests = _codes(used.get(ap['approval_id'], [])) or '（本次未使用）'
        lines.append(f'- **額外核准** {_code(ap["approval_id"])}：{_inline(ap["by"])} {_inline(ap["at"])}，'
                     f'至 {_inline(ap["valid_until"])}；' + _operations(ap['operations'])
                     + f'；理由：{_inline(ap["reason"])}；用於 {tests}')
    lines.append('- 測試用原始碼變更：無（受測原始碼即 `source_digest` 釘選的版本）')
    return lines


# 〈定義：覆核紀錄〉: the options of 候選問題覆核 and the 覆核狀態 each one leaves; a finding with no decision
# is pending, or overdue past its deadline. toolkit.review and validate() share these.
DECISION_STATES = {'approve': 'approved', 'reject': 'rejected', 'evidence_pending': 'evidence_pending'}
WAITING_STATES = ('pending', 'overdue')
FINDING_REVIEW_STATES = WAITING_STATES + tuple(DECISION_STATES.values())  # in the report's order
# 〈定義：覆核紀錄〉 報告: 覆核狀態 and the options of 候選問題覆核.
FINDING_REVIEW_LABELS = {'pending': '待覆核', 'overdue': '逾期覆核', 'approved': '已核准', 'rejected': '已退回',
                       'evidence_pending': '已轉證據待補'}
OPTION_LABELS = {'approve': '核准', 'reject': '退回', 'evidence_pending': '轉證據待補'}
REVIEW_TYPE_LABELS = {'candidate_finding': '候選問題覆核'}  # 〈定義：覆核類型〉


def render_review_issue(finding, doc, option_of_label):
    """Title and body of the issue a finding's review is made on (〈定義：覆核紀錄〉 工單). option_of_label maps
    each predefined platform label to its option. The fingerprint is shown to people, never searched."""
    title = f'{REVIEW_TYPE_LABELS["candidate_finding"]}：{_inline(finding["requirement_id"])}'
    options = '、'.join(f'`{label}`（{OPTION_LABELS[option]}）' for label, option in option_of_label.items())
    body = (f'- 指紋：{_code(finding["fingerprint"])}（{_inline(finding["fingerprint_version"])}）\n'
            f'- 需求：{_code(finding["requirement_id"])} 第 {finding["requirement_version"]} 版\n'
            f'- 提交：{_code(doc["commit"])}，執行：{_code(doc["run_id"])}\n\n'
            f'決定方式：先留言寫下理由，再加上其中一個標籤：{options}。留言本身不算決定。')
    return title, body


OUTBOUND_LABELS = {'blocked': '已阻擋'}
ISOLATION_METHOD_LABELS = {'internal-network': '內部網路：不與其他網路互通，不解析外部名稱，不發布連接埠'}


def _test_data_lines(test_data):
    """TK-SBX-011, TK-SBX-012: who states the test data is synthetic, and each domain exception, marked as
    approved by one person (TK-REQ-014 is not implemented)."""
    st = test_data['synthetic_statement']
    lines = [f'- **合成資料來源聲明（TK-SBX-011）**：{_inline(st["method"])}；確認者 {_inline(st["confirmed_by"])}，'
             f'{_code(st["confirmed_at"])}（資料是否為合成資料以此聲明為準，工具不自行推定）']
    for e in test_data['domain_exceptions']:
        lines.append(f'- **網域例外（TK-SBX-012，單人核准，尚無第二人核准）**：{_code(e["account"])}；理由：{_inline(e["reason"])}；'
                     f'確認者 {_inline(e["confirmed_by"])}，{_code(e["confirmed_at"])}')
    return lines


def _isolation_lines(isolation):
    """〈定義：E1 隔離〉 as checked after the stack started (TK-SBX-004, TK-ENV-008), with what it does not cover
    (TK-EVD-014)."""
    return [f'- **對外連線（TK-SBX-004）**：{OUTBOUND_LABELS[isolation["outbound"]]}'
            f'（{ISOLATION_METHOD_LABELS[isolation["method"]]}）',
            '- **宿主機入口（TK-ENV-008，只在本機回送位址）**：' + (_codes(isolation['host_access']) or '（無）'),
            '- **已檢查的容器（非特權、只接內部網路、未掛載宿主機控制通訊端與專案以外的路徑）**：'
            + _codes(isolation['containers_checked']),
            '- **隔離未涵蓋的範圍**：',
            *[f'  - {_inline(x)}' for x in isolation['limits']]]


CLEANUP_LABELS = {'destroyed': '已銷毀（查證後無殘留）', 'destroy_failed': '銷毀失敗（平台異常，環境不再使用）'}
ABORT_SOURCE_LABELS = {'operator': '操作者', 'system': '系統'}
ABORT_STEP_LABELS = {'dispatch_stopped': '停止派送', 'credentials_revoked': '撤銷測試工作階段',
                     'in_flight_ended': '在途案例結束', 'evidence_kept': '保留已取得的證據',
                     'in_flight_checked': '核對在途案例', 'environment_isolated': '環境隔離並銷毀'}
ABORT_TIME_LABELS = {'dispatch_stopped': '派送停止時間', 'in_flight_ended': '程序終止時間（在途案例結束）',
                     'environment_isolated': '環境隔離時間'}
SESSION_LABELS = {'revoked': '已撤銷', 'not_confirmed': '未能確認'}


BUILD_PART_LABELS = {'build': '建置成功率（來源與建置）', 'initialization': '初始化成功率（服務初始化）',
                     'test_data': '測試資料', 'health': '健康檢查', 'recovery': '復原成功率（快照與重置）'}
BUILD_PART_ORDER = ('build', 'initialization', 'test_data', 'authentication', 'health', 'recovery')


def _attempts(count):
    """成功 n／嘗試 m, or that the part was not reached: a part without an attempt has no rate."""
    return f'成功 {count["successes"]}／嘗試 {count["attempts"]}' if count['attempts'] else '未嘗試'


def _build_measure_section(measure):
    """〈定義：環境建置的量測〉 (TK-ENV-006): each part on its own line, authentication per identity; never mixed into
    the coverage or any detection rate."""
    if not measure:
        return []
    lines = ['', '## 環境建置量測', '',
             '各項分開計算，不併入覆蓋比率與漏洞檢出率（TK-ENV-006）；沒有走到的步驟記為未嘗試，不算進分母。', '']
    for part in BUILD_PART_ORDER:
        if part == 'authentication':
            lines.append('- **各角色的認證成功率**：' + ('' if measure['authentication'] else '（沒有由工具登入的身分）'))
            lines += [f'  - {_code(name)}：{_attempts(count)}' for name, count in sorted(measure['authentication'].items())]
        else:
            lines.append(f'- **{BUILD_PART_LABELS[part]}**：{_attempts(measure[part])}')
    return lines


def _cleanup_section(doc):
    """〈定義：中止與清理〉: the abort, if there was one, with its steps and times (TK-RUN-004 to TK-RUN-006), and
    whether the environment is gone (TK-ENV-003)."""
    abort, cleanup = doc.get('abort'), doc.get('cleanup')
    if not abort and not cleanup:
        return []
    lines = ['', '## 中止與清理', '']
    if abort:
        lines.append(f'- **中止（TK-RUN-004）**：由{ABORT_SOURCE_LABELS[abort["source"]]}觸發，'
                     f'{_code(abort["requested_at"])}；原因：{_inline(abort["reason"])}')
        lines.append('- **處理順序（TK-RUN-005）**：')
        lines += [f'  {i}. {ABORT_STEP_LABELS[s["step"]]}：{_code(s["at"])}（第 {s["seconds"]:g} 秒）'
                  for i, s in enumerate(abort['steps'], 1)]
        lines.append('- **中止時間（TK-RUN-006）**：')
        for name, label in ABORT_TIME_LABELS.items():
            value, limit = abort['seconds'][name], abort['limits_seconds'][name]
            shown = '未達到' if value is None else f'{value:g} 秒'
            lines.append(f'  - {label}：{shown}（上限 {limit:g} 秒）' + ('，**超過上限**' if name in abort['over_limit'] else ''))
        if abort['sessions']:
            lines.append('- **測試工作階段**：' + '、'.join(f'{_code(n)} {SESSION_LABELS[v]}'
                                                         for n, v in sorted(abort['sessions'].items())))
        lines.append('- **在途案例**：' + (f'{_code(abort["in_flight"])} 未完成，結果未知' if abort['in_flight']
                                         else '中止時沒有案例在執行'))
        lines.append('- **中止未涵蓋的範圍**：')
        lines += [f'  - {_inline(x)}' for x in abort['not_covered']]
    if cleanup:
        lines.append(f'- **環境清理（TK-ENV-003）**：{CLEANUP_LABELS[cleanup["environment"]]}')
        lines += [f'  - 殘留：{_inline(x)}' for x in cleanup['leftovers']]
    return lines


def _environment_section(env):
    """〈定義：核心資料物件與相依紀錄〉 EnvironmentProfile: support-matrix warnings (TK-SCP-001) and known
    differences from E2 or production (TK-ENV-007, TK-EVD-005)."""
    lines = ['', '## 測試環境與差異', '']
    if not env:
        lines.append('- **測試環境**：本次執行未建立測試環境，尚無環境差異紀錄')
        return lines
    lines.append(f'- **環境模式**：{_code(env["mode"])}（{_code(env["profile_digest"])}）')
    if env['unsupported']:
        lines.append('- **支援矩陣外版本（不支援，TK-SCP-001）**：')
        lines += [f'  - {_inline(u)}' for u in env['unsupported']]
    if env['known_differences']:
        lines.append('- **環境差異（TK-ENV-007、TK-EVD-005）**：')
        lines += [f'  - {_inline(d)}' for d in env['known_differences']]
    else:
        lines.append('- **環境差異**：（無宣告差異）')
    return lines + _test_data_lines(env['test_data']) + _isolation_lines(env['isolation'])


def _limits_section(limits):
    """〈定義：執行限制的執行〉: each limit as stated and what the run used of it."""
    def stated(value, unit=''):
        return f'{value}{unit}' if value is not None else '（未提供）'
    return ['', '## 執行限制', '',
            f'- 請求數：已用 {limits["requests"]}，上限 {stated(limits["max_requests"])}'
            '（測試案例的行為者請求與觀測者讀取；環境建置與重置的請求不計）',
            f'- 時間：已用 {limits["elapsed_seconds"]:.0f} 秒，上限 {stated(limits["max_duration_seconds"], " 秒")}',
            f'- 並行數：實際 {limits["concurrency"]}，上限 {stated(limits["max_concurrency"])}',
            '- 費用上限與網路允許清單在這個版本只檢查是否提供，尚未據以限制執行（TK-EVD-014）']


def _waiting_first(finding):
    """Sort key: findings waiting for review (待覆核, 逾期覆核) first, the longest wait first, those with no
    issue opened yet after them; decided findings last. sorted() keeps the report's order among equals."""
    review = finding['review']
    if review['state'] not in WAITING_STATES:
        return 2, 0
    opened = control.utc_time(review.get('opened_at'))
    return (1, 0) if opened is None else (0, opened.timestamp())


def _review_section(doc):
    """〈定義：覆核紀錄〉 報告: the record used, the count per review state and each finding's review."""
    ref = doc['review_record']
    lines = ['', '## 覆核', '',
             f'- **覆核紀錄**：{_code(ref["path"])}（{_code(ref["digest"])}）' if ref
             else '- **覆核紀錄**：這次執行沒有使用覆核紀錄，每一筆問題都待覆核',
             '- **數量**：' + '、'.join(f'{FINDING_REVIEW_LABELS[k]} {n}' for k, n in doc['review_summary'].items())]
    if not doc['findings']:
        return lines
    lines += ['', '| 問題 | 覆核狀態 | 開始覆核 | 目前的決定 |', '| :--- | :--- | :--- | :--- |']
    for f in sorted(doc['findings'], key=_waiting_first):
        r = f['review']
        d = r.get('decision')
        decided = (f'{OPTION_LABELS[d["option"]]}：{_cell(d["by"]["login"])}（帳號 {_cell(d["by"]["id"])}）{_cell(d["at"])}；'
                   f'理由：{_cell(d["reason"])}' if d else '—')
        lines.append(f'| {_tcode(f["id"])} | {FINDING_REVIEW_LABELS[r["state"]]} | {_cell(r.get("opened_at", "—"))} '
                     f'| {decided} |')
    return lines


# 〈定義：覆蓋面向〉 in Chinese: the completeness of the inventory, what the report claims to cover, the rates and what
# a rate with no number is called (TK-EVD-009).
COMPLETENESS_LABELS = {'complete': '完整', 'unknown': '未知'}
CLAIM_LABELS = {'whole_scope': '整個範圍', 'known_scope_only': '只涵蓋已知範圍'}
RATE_LABELS = {'effective_judgement_rate': '有效判定率', 'tool_support_rate': '工具支援率',
               'required_test_completion_rate': '必要測試完成率'}
RATE_STATE_LABELS = {'not_applicable': '不適用', 'insufficient_data': '資料不足'}


def _coverage_lines(c):
    """The 覆蓋 section: counts, rates (a rate with no number says why, never a percentage), the tables and
    policies, and the unresolved, unsupported, excluded and refused-exclusion items one by one."""
    inv, tp = c['inventory'], c['tables_and_policies']
    rates = '；'.join(f"{RATE_LABELS[name]}：" + (f'{c[name] * 100:.1f}%' if c['states'][name] == 'measured'
                                                else RATE_STATE_LABELS[c['states'][name]]) for name in RATE_LABELS)
    lines = ['', '## 覆蓋', '', f'- 盤點來源：{_inline(c["inventory_source"])}',
             f'- 盤點完整性：{COMPLETENESS_LABELS[inv["completeness"]]}；宣告範圍：{CLAIM_LABELS[c["claim"]]}；'
             f'擷取規則 {_inline(inv["rule"])}、支援版本 {_inline(inv["supported_version"])}',
             f'- 分母 {c["denominator"]}、已執行 {c["executed"]}、有效判定 {c["valid_judgements"]}、受阻 {c["blocked"]}、'
             f'錯誤 {c["errors"]}、未測 {c["untested"]}、取消 {c["cancelled"]}、不支援 {c["unsupported"]}',
             f'- {rates}',
             f'- 資料表與政策：已盤點 {tp["inventoried"]}、已啟用 RLS {tp["rls_enabled"]}、尚無政策 {tp["without_policy"]}、'
             f'未解析 {tp["unresolved"]}、已判定 {tp["judged"]}']
    lines += [f'  - 未解析：{_code(u["file"] + (":" + str(u["line"]) if u["line"] else ""))}（{_inline(u["reason"])}）'
              for u in inv['unresolved']]
    lines += [f'  - 不支援：{_code(u["scope"])}（{_inline(u["reason"])}'
              f'{"；需補充觀測" if u.get("needs_supplement") else ""}）'
              for u in c['unsupported_items']]
    lines += [f'  - 排除：{_code(e["ref"])}（{_inline(e["reason"])}；確認者 {_inline(e["confirmed_by"])}、'
              f'版本 {_inline(e["version"])}）' for e in c['excluded']]
    if c['excluded_record_ids']:
        lines.append('  - 隨排除項移出分母的執行紀錄：' + '、'.join(_code(i) for i in c['excluded_record_ids']))
    lines += [f'  - 被拒絕的排除：{_code(r["ref"])}（{_inline(r["problem"])}）' for r in c['rejected_exclusions']]
    return lines


def _shown(value, default=''):
    """A field of a test that could not run is recorded as given, which may be no text at all (TK-IDN-009)."""
    return default if value is None else value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


# 〈定義：故障注入〉: what a reader must know before reading the results of such a run.
SELF_VALIDATION_NOTE = '工具包自我驗證（含故障注入，不是對應用的掃描結果）'


def _scope_section(scope):
    """TK-EVD-005 範圍: what the ScanManifest put in scope; a report whose scope could not be read says so."""
    lines = ['', '## 範圍', '']
    if not scope:
        return lines + ['- 這次執行的 ScanManifest 沒有可讀取的受測範圍。']
    return lines + [f'- **受測端點**：{_codes(scope["endpoints"]) or "（無）"}',
                    f'- **受測資源**：{_codes(scope["resources"]) or "（無）"}',
                    f'- **允許操作**：{_codes(scope["allowed_operations"]) or "（無）"}',
                    f'- **資料範圍**：{_inline(scope["data_scope"])}']


# TK-EVD-005: the three lists of findings a report always has, by the status of 〈定義：問題狀態〉.
FINDING_LISTS = (('confirmed', '已確認問題'), ('evidence_pending', '待補證問題'), ('not_reproduced', '未重現問題'))
NOT_JUDGED = ('blocked', 'error', 'untested', 'cancelled', 'unsupported')


def _findings_by_status(findings):
    lines = []
    for status, title in FINDING_LISTS:
        ids = [f['id'] for f in findings if f['status'] == status]
        lines.append(f'- **{title}**：' + (_codes(ids) if ids else '（無）'))
    return lines + ['']


def _not_judged_section(records):
    """TK-EVD-005 受阻與未測試清單: every test without a verdict, with why. A report is not only its findings."""
    lines = ['', '## 受阻與未測試清單', '']
    rows = [e for e in records if e['result'] in NOT_JUDGED]
    if not rows:
        return lines + ['（無：計畫內的測試都取得了判定）']
    lines += ['| 測試 | 結果 | 原因 |', '| :--- | :--- | :--- |']
    lines += [f'| {_tcode(_shown(e.get("test_id"), e["id"]))} | {RESULT_LABELS[e["result"]]} | {_cell(e.get("error") or "（未記錄）")} |'
              for e in rows]
    return lines


def _exceptions_section(doc):
    """TK-EVD-005 例外: everything that let this run do or accept more than the default, in one place: the
    confirmation items a person modified or set aside, the extra approvals tests ran under, the domain exceptions
    of the test data and the items excluded from the coverage."""
    lines = ['', '## 例外', '']
    items = [f'確認項目 {_code(r["id"])}：{REVIEW_LABELS[r["status"]]}' for r in doc['requirements']
             if r.get('status') in ('modified', 'not_applicable')]
    approvals = sorted({e['approval_id'] for e in doc['execution_records'] if e.get('approval_id')})
    items += [f'額外核准 {_code(a)}（測試授權紀錄）' for a in approvals]
    env = doc.get('environment') or {}
    items += [f'網域例外 {_code(e["account"])}（單人核准）' for e in (env.get('test_data') or {}).get('domain_exceptions', [])]
    items += [f'覆蓋排除項 {_code(x["ref"])}' for x in doc['coverage'].get('excluded', [])]
    return lines + ([f'- {i}' for i in items] if items else ['（無）'])


PACKAGE_STATUS_LABELS = {'present': '具備', 'missing': '缺件', 'not_applicable': '不適用'}
PACKAGE_ITEM_LABELS = {
    'commit': '受測提交識別碼', 'build_artifact_digest': '建置產物摘要', 'container_image_digests': '容器映像摘要',
    'environment_differences': '環境差異', 'requirement_test_finding_links': '需求、測試、判定與問題的關聯',
    'threat_links': '威脅的關聯', 'toolkit_version': '工具版本', 'rule_and_template_versions': '規則與範本版本',
    'model_and_prompt_versions': '適配器、模型與提示範本版本', 'identity_references': '測試身分參照',
    'synthetic_data_version': '合成資料版本', 'random_seed': '隨機種子', 'preconditions': '必要前置條件',
    'requests_and_responses': '遮罩後的請求與回應', 'positive_control_and_state_difference': '正向對照與狀態差異',
    'error_records': '錯誤紀錄', 'timing': '時間', 'cost': '費用', 'retries': '重試', 'cancellation': '取消紀錄',
    'reproduction_steps': '可重現步驟', 'fix_and_regression': '修復建議與回歸測試', 'limitations': '限制'}
INCOMPLETE_NOTE = '證據包有缺件：本報告的結論只及於已具備的項目，不代表受測範圍內沒有其他問題。'


def _evidence_package_section(package):
    """〈定義：最低證據包的項目〉 (TK-EVD-001, TK-EVD-006): every item with whether the report holds it; what is
    missing is named, and a report with a missing item says what its conclusions do not reach."""
    missing = [i for i in package if i['status'] == 'missing']
    lines = ['', '## 證據包', '',
             f'- 具備 {sum(i["status"] == "present" for i in package)} 項、缺件 {len(missing)} 項、'
             f'不適用 {sum(i["status"] == "not_applicable" for i in package)} 項']
    if missing:
        lines += [f'- **缺件**：' + '、'.join(PACKAGE_ITEM_LABELS[i['item']] for i in missing), '', f'> {INCOMPLETE_NOTE}']
    lines += ['', '| 項目 | 狀態 | 位置或原因 |', '| :--- | :--- | :--- |']
    lines += [f'| {PACKAGE_ITEM_LABELS[i["item"]]} | {PACKAGE_STATUS_LABELS[i["status"]]} | {_cell(i["note"] or "—")} |'
              for i in package]
    return lines


def render_markdown(doc):
    """Markdown for human review, generated from a valid JSON report. Raises ValueError if invalid."""
    problems = validate(doc)
    if problems:
        raise ValueError('invalid report: ' + '; '.join(problems))
    # TK-DAT-001: a report blocked at preflight may name no commit.
    commit_text = _code(doc['commit']) if doc['commit'] is not None else '（未提供）'
    lines = [f'# 執行報告 {_code(doc["run_id"])}', '',
             f'- **整體執行狀態**：{RUN_LABELS[doc["status"]]}（`{doc["status"]}`）'
             + (f'；原因：{_inline(doc["status_reason"])}' if doc.get('status_reason') else ''),
             f'- **受測提交**：{commit_text}',
             f'- **報告建立時間**：{_inline(doc["created_at"])}']
    if doc.get('self_validation'):
        lines.append(f'- **執行類型**：{SELF_VALIDATION_NOTE}')
    if doc.get('environment'):
        lines.append(f'- **環境模式**：{_inline(doc["environment"].get("mode", ""))}')
    lines.append(f'- **工具版本**：{_code(doc["toolkit_version"])}')
    if doc['status'] == 'completed':
        lines += ['', f'> {COMPLETED_NOTE}']
    lines += _scope_section(doc.get('scope'))

    if doc.get('requirements'):
        lines += ['', '## 安全需求（確認項目）', '', '| 確認項目 | 來源 | 內容 | 處理狀態 | 確認者 |',
                  '| :--- | :--- | :--- | :--- | :--- |']
        for r in doc['requirements']:
            c = r['confirmation']
            state = REVIEW_LABELS[r['status']] + ('（範圍外）' if r['out_of_scope'] else '')
            if c.get('allowed_tests'):
                state += ('（合法例外：放行 ' + _codes(c['allowed_tests'], cell=True)
                          + f'，到期 {_cell(c.get("expiry", "（未填）"))}）')
            who = f'{_cell(c["by"])} {_cell(c["at"])}' if c['by'] else '（未確認）'
            lines.append(f'| {_tcode(r["id"])} v{_cell(c["version"])} | {r["source"]} | {_cell(r["statement"])} '
                         f'| {state} | {who} |')

    if doc.get('confirmation_list'):
        lines += _confirmation_summary(doc['confirmation_list'])

    if doc.get('authorization'):
        lines += _authorization_section(doc)

    lines += _environment_section(doc.get('environment'))
    lines += _build_measure_section(doc.get('environment_build'))
    lines += _cleanup_section(doc)
    lines += _limits_section(doc['limits'])

    if doc.get('authorization_matrix'):
        lines += ['', '## 授權矩陣中的身分', '', '| 身分 | 傳遞方式 | 路徑 |', '| :--- | :--- | :--- |']
        for m in doc['authorization_matrix']:
            lines.append(f'| {_tcode(m["identity"])} | {_cell(m["transport"])} | {_cell(m["path"])} |')

    lines += ['', '## 測試結果', '', '| 測試 | 行為者 | 資源 | 結果 |', '| :--- | :--- | :--- | :--- |']
    for e in doc['execution_records']:
        lines.append(f'| {_tcode(_shown(e.get("test_id"), e["id"]))} | {_tcode(_shown(e.get("actor_ref")))} '
                     f'| {_tcode(_shown(e.get("resource_ref")))} | {RESULT_LABELS[e["result"]]} |')

    lines += _not_judged_section(doc['execution_records'])

    lines += ['', '## 問題紀錄', '']
    lines += _findings_by_status(doc['findings'])
    if doc['findings']:
        lines += ['| 問題 | 狀態 | 需求 | 根因 | 指紋 |', '| :--- | :--- | :--- | :--- | :--- |']
        for f in doc['findings']:
            lines.append(f'| {_tcode(f["id"])} | {FINDING_LABELS[f["status"]]} | {_tcode(f["requirement_id"])} '
                         f'| {_cell(f["root_cause"])} | {_tcode(f["fingerprint"])}（{_cell(f["fingerprint_version"])}） |')
    else:
        lines.append('本次計畫內的測試未產生問題紀錄；這只代表上列測試的結果，不涵蓋計畫以外的範圍。')

    lines += _review_section(doc)

    lines += _exceptions_section(doc)
    lines += _coverage_lines(doc['coverage'])
    lines += _evidence_package_section(doc['evidence_package'])
    lines.append('')
    return '\n'.join(lines)
