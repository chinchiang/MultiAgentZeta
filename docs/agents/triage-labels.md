# Triage Labels

The five canonical triage roles (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`) and the category labels `bug` and `enhancement` use their canonical names unchanged; each label's meaning is its GitHub description (`gh label list`).

Choosing between the two ready roles: work that needs a person to operate an account, credential, or paid service (for example #21, toolkit test credentials) is `ready-for-human`; any other fully specified work is `ready-for-agent`.

Stage labels: a ticket whose requirements belong to one stage of prototype v0.1 carries `v0.1a` (the flow that calls no model) or `v0.1b` (single-model review); the stages are defined in `docs/toolkit/spec.md` §0.3 and each requirement's stage is its `v0.1` field. A ticket takes the stage of the requirements in its `## 對應條文`; when they span both stages, split the ticket. Tickets for development tooling (`docs/toolkit/tools/`, `toolkit/tools/`), tickets on a 可延後 requirement and the spec issue itself carry no stage label. Finish `v0.1a` tickets before starting `v0.1b` ones.
