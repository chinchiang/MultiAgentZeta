"""Report contract of a scan run: validate(report) and render_markdown(report).

The JSON report is the native format (TK-EVD-003); its structure is the versioned
JSON Schema in schemas/report-v1.json. validate() also checks the conditions that
span records, which JSON Schema cannot express.
"""
import json
from pathlib import Path

import jsonschema

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
    for i, f in enumerate(_list(doc, 'findings')):
        if not isinstance(f, dict) or f.get('status') != 'confirmed':
            continue
        ids = f.get('execution_record_ids') or []
        if not any(results.get(x) == 'failed' for x in ids):
            problems.append(f'findings/{i}: a confirmed finding needs a failed execution record; '
                            f'execution_record_ids {ids} do not include one')
    return problems + _requirement_problems(doc)


def _untestable(item):
    """Why tests on a listed item must be blocked (〈定義：確認清單〉, TK-REQ-003), or None."""
    if item.get('out_of_scope'):
        return 'is out of scope'
    if item.get('status') == 'not_applicable':
        return 'is not applicable'
    if item.get('status') == 'pending' and item.get('source') == 'S1':
        return 'is a pending S1 entry'
    return None


def _requirement_problems(doc):
    """Records against the confirmation items the report lists: version (TK-REQ-004), blocked tests
    (〈定義：確認清單〉) and the finding cap of pending items (TK-REQ-003)."""
    items = {r.get('id'): r for r in _list(doc, 'requirements') if isinstance(r, dict) and isinstance(r.get('id'), str)}
    problems = []
    for i, e in enumerate(_list(doc, 'execution_records')):
        item = items.get(e.get('requirement_id')) if isinstance(e, dict) and isinstance(e.get('requirement_id'), str) else None
        if item is None:
            continue
        version = (item.get('confirmation') or {}).get('version')
        if e.get('requirement_version') != version:
            problems.append(f'execution_records/{i}: requirement_version {e.get("requirement_version")!r} differs '
                            f'from version {version!r} of {item["id"]!r} in requirements (TK-REQ-004)')
        reason = _untestable(item)
        if reason and e.get('result') != 'blocked':
            problems.append(f'execution_records/{i}: {item["id"]!r} {reason}; a test on it must be blocked, '
                            f'not {e.get("result")!r} (〈定義：確認清單〉)')
    for i, f in enumerate(_list(doc, 'findings')):
        item = items.get(f.get('requirement_id')) if isinstance(f, dict) and isinstance(f.get('requirement_id'), str) else None
        if item and item.get('status') == 'pending' and f.get('status') == 'confirmed':
            problems.append(f'findings/{i}: {item["id"]!r} is pending; a finding on it is at most evidence_pending, '
                            f'not confirmed (TK-REQ-003)')
    return problems


def validate(doc):
    """Problems with a report, as human-readable strings; [] means valid."""
    return _schema_problems(doc) + _cross_record_problems(doc)


# Spec names for the codes used in the JSON report.
RUN_LABELS = {'pending': '待執行', 'running': '執行中', 'completed': '完整完成', 'partial': '部分完成',
              'blocked': '受阻', 'failed': '失敗', 'cancelled': '已取消'}
RESULT_LABELS = {'passed': '通過', 'failed': '未通過', 'blocked': '受阻', 'error': '執行錯誤',
                 'untested': '未測試', 'unsupported': '不支援'}
# 〈定義：確認清單〉 處理狀態 of a confirmation item; not a finding state.
REVIEW_LABELS = {'pending': '待確認', 'accepted': '接受', 'modified': '修改', 'not_applicable': '不適用'}
FINDING_LABELS = {'confirmed': '已確認', 'evidence_pending': '證據待補', 'not_reproduced': '本次未重現',
                  'excluded': '已排除', 'fixed_pending_regression': '已修復待回歸', 'regression_passed': '回歸通過'}
COMPLETED_NOTE = ('「完整完成」表示計畫內的測試都取得明確結果；只對本次範圍與條件有效，'
                  '不代表應用沒有漏洞（TK-RUN-002）。')


def _confirmation_summary(listed):
    """TK-REQ-003 各類待確認數量 by source, for the list version they come from (TK-REQ-004), and the
    items approved by one person (〈定義：確認清單〉 單人核准)."""
    t = listed['s2_template']
    lines = ['', '## 確認狀態摘要', '',
             f'- **確認清單**：`{listed["path"]}` v{listed["list_version"]}（`{listed["digest"]}`）'
             + ('；本次產生或更新，待負責人處理' if listed['updated'] else ''),
             f'- **S2 範本**：`{t["policy_template_id"]}` v{t["version"]}（`{t["digest"]}`）', '',
             '| 來源 | ' + ' | '.join(REVIEW_LABELS.values()) + ' |', '| :--- |' + ' ---: |' * len(REVIEW_LABELS)]
    for source, counts in listed['summary'].items():
        lines.append(f'| {source} | ' + ' | '.join(str(counts[s]) for s in REVIEW_LABELS) + ' |')
    lines += ['', f'- 範圍外 {listed["out_of_scope"]} 項（不是處理狀態，不計入上表）']
    if listed['single_approval']:
        lines.append('- 單人核准（修改與不適用，尚無第二人核准，TK-REQ-014）：'
                     + '、'.join(f'`{i}`' for i in listed['single_approval']))
    return lines


def render_markdown(doc):
    """Markdown for human review, generated from a valid JSON report. Raises ValueError if invalid."""
    problems = validate(doc)
    if problems:
        raise ValueError('invalid report: ' + '; '.join(problems))
    # TK-DAT-001: a report blocked at preflight may name no commit.
    commit_text = f'`{doc["commit"]}`' if doc['commit'] is not None else '（未提供）'
    lines = [f'# 執行報告 `{doc["run_id"]}`', '',
             f'- **整體執行狀態**：{RUN_LABELS[doc["status"]]}（`{doc["status"]}`）'
             + (f'；原因：{doc["status_reason"]}' if doc.get('status_reason') else ''),
             f'- **受測提交**：{commit_text}',
             f'- **報告建立時間**：{doc["created_at"]}']
    if doc.get('environment'):
        lines.append(f'- **環境模式**：{doc["environment"].get("mode", "")}')
    if doc['status'] == 'completed':
        lines += ['', f'> {COMPLETED_NOTE}']

    if doc.get('requirements'):
        lines += ['', '## 安全需求（確認項目）', '', '| 確認項目 | 來源 | 內容 | 處理狀態 | 確認者 |',
                  '| :--- | :--- | :--- | :--- | :--- |']
        for r in doc['requirements']:
            c = r['confirmation']
            state = REVIEW_LABELS[r['status']] + ('（範圍外）' if r['out_of_scope'] else '')
            who = f'{c["by"]} {c["at"]}' if c['by'] else '（未確認）'
            lines.append(f'| `{r["id"]}` v{c["version"]} | {r["source"]} | {r["statement"]} | {state} | {who} |')

    if doc.get('confirmation_list'):
        lines += _confirmation_summary(doc['confirmation_list'])

    if doc.get('authorization_matrix'):
        lines += ['', '## 授權矩陣中的身分', '', '| 身分 | 傳遞方式 | 路徑 |', '| :--- | :--- | :--- |']
        for m in doc['authorization_matrix']:
            lines.append(f'| `{m["identity"]}` | {m.get("transport", "")} | {m.get("path", "")} |')

    lines += ['', '## 測試結果', '', '| 測試 | 行為者 | 資源 | 結果 |', '| :--- | :--- | :--- | :--- |']
    for e in doc['execution_records']:
        lines.append(f'| `{e.get("test_id", e["id"])}` | `{e.get("actor_ref", "")}` | `{e.get("resource_ref", "")}` '
                     f'| {RESULT_LABELS[e["result"]]} |')

    lines += ['', '## 問題紀錄', '']
    if doc['findings']:
        lines += ['| 問題 | 狀態 | 需求 | 根因 | 指紋 |', '| :--- | :--- | :--- | :--- | :--- |']
        for f in doc['findings']:
            label = FINDING_LABELS.get(f.get('status'), f.get('status', ''))
            lines.append(f'| `{f["id"]}` | {label} | `{f.get("requirement_id", "")}` | {f.get("root_cause", "")} '
                         f'| `{f.get("fingerprint", "")}`（{f.get("fingerprint_version", "")}） |')
    else:
        lines.append('本次計畫內的測試未產生問題紀錄；這只代表上列測試的結果，不涵蓋計畫以外的範圍。')

    c = doc['coverage']
    lines += ['', '## 覆蓋', '', f'- 盤點來源：{c.get("inventory_source", "")}',
              f'- 分母 {c.get("denominator")}、已執行 {c.get("executed")}、有效判定 {c.get("valid_judgements")}、'
              f'受阻 {c.get("blocked")}、未測 {c.get("untested")}、不支援 {c.get("unsupported")}']
    for u in c.get('unsupported_items', []):
        lines.append(f'  - 不支援：`{u["scope"]}`（{u["reason"]}）')
    lines.append('')
    return '\n'.join(lines)
