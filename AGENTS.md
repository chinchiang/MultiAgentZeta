## Project documents

Before editing `docs/toolkit/`, `GLOSSARY.md`, or `docs/adr/`, read `docs/toolkit/README.md`: document roles, shared version rule, `TK-` requirement format, per-revision checklist. Terms follow `GLOSSARY.md`.

Before committing doc changes, run `python -I docs/toolkit/tools/build.py --check` and review the diff against `CODING_STANDARDS.md`. The pre-commit hook needs `git config core.hooksPath .githooks` once per clone.

## Toolkit prototype

Code lives in `toolkit/`, samples in `samples/`. Fast tests: `python -I -m unittest discover -s toolkit/tests -t .` (install from the hash-pinned `toolkit/requirements.lock`). Environment tests need `MAZ_ENV_TESTS=1` and Docker.

## Agent skills

- **Issue tracker**: GitHub Issues (`chinchiang/MultiAgentZeta`). See `docs/agents/issue-tracker.md`.
- **Triage labels**: canonical names, unchanged. See `docs/agents/triage-labels.md`.
- **Domain docs**: single-context (`GLOSSARY.md`, `docs/adr/` at the root). Before exploring or naming a domain concept, see `docs/agents/domain.md`.
