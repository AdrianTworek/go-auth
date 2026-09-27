# go-auth — Agent Instructions

## Agent skills

Configuration for the engineering skills, kept inline here rather than in separate files
so that it survives a fresh clone (`ai-docs/` is gitignored).

### Issue tracker

Issues and specs for this repo live as markdown files in `ai-docs/`, **not** in GitHub
Issues. `ai-docs/` is gitignored (`.gitignore` → `/ai-docs/`), so the tracker is local to
the working copy and never pushed. It also holds `ROADMAP.md`, the shared working doc for
direction and shipped work — read it before writing a new spec, and keep it current as
tickets land.

Conventions:

- One feature per directory: `ai-docs/<feature-slug>/`
- The spec is `ai-docs/<feature-slug>/spec.md`
- Implementation issues are one file per ticket at
  `ai-docs/<feature-slug>/issues/<NN>-<slug>.md`, numbered from `01`, never a single
  combined tickets file
- Triage state is a `Status:` line near the top of each issue file, using the role strings
  under "Triage labels" below
- Comments and conversation history append to the bottom of the file under a
  `## Comments` heading
- `ROADMAP.md` is reserved, and `agents` must not be used as a feature slug

When a skill says **"publish to the issue tracker"**: create a new file under
`ai-docs/<feature-slug>/`, creating the directory if needed.

When a skill says **"fetch the relevant ticket"**: read the file at the referenced path.
The user will normally pass the path or the issue number directly.

Wayfinding operations (`/wayfinder`) — the **map** is a file with one **child** file per
ticket:

- **Map**: `ai-docs/<effort>/map.md` (the Notes / Decisions-so-far / Fog body)
- **Child ticket**: `ai-docs/<effort>/issues/NN-<slug>.md`, numbered from `01`, with the
  question in the body. A `Type:` line records the ticket type
  (`research`/`prototype`/`grilling`/`task`); a `Status:` line records
  `claimed`/`resolved`
- **Blocking**: a `Blocked by: NN, NN` line near the top. A ticket is unblocked when every
  file it lists is `resolved`
- **Frontier**: scan `ai-docs/<effort>/issues/` for files that are open, unblocked and
  unclaimed; first by number wins
- **Claim**: set `Status: claimed` and save before any work
- **Resolve**: append the answer under an `## Answer` heading, set `Status: resolved`, then
  append a context pointer (gist + link) to the map's Decisions-so-far in `map.md`

### Triage labels

The skills speak in terms of five canonical triage roles. This tracker has no label
system, so the role string is written as the `Status:` value in the issue file.

| Role              | Meaning                                  |
| ----------------- | ---------------------------------------- |
| `needs-triage`    | Maintainer needs to evaluate this issue  |
| `needs-info`      | Waiting on reporter for more information |
| `ready-for-agent` | Fully specified, ready for an AFK agent  |
| `ready-for-human` | Requires human implementation            |
| `wontfix`         | Will not be actioned                     |

### Domain docs

Single-context repo: one `CONTEXT.md` and one `docs/adr/` at the root.

Before exploring the codebase, read `CONTEXT.md` at the repo root, plus any ADRs in
`docs/adr/` that touch the area you're about to work in. If they don't exist, **proceed
silently** — don't flag their absence and don't suggest creating them upfront.
`/domain-modeling` (reached via `/grill-with-docs` and `/improve-codebase-architecture`)
creates them lazily, when terms or decisions actually get resolved.

```
/
├── CONTEXT.md
├── docs/adr/
│   ├── 0001-<decision>.md
│   └── 0002-<decision>.md
├── core/
└── adapters/
```

When your output names a domain concept (an issue title, a refactor proposal, a
hypothesis, a test name), use the term as defined in `CONTEXT.md`. Don't drift to synonyms
the glossary explicitly avoids. If the concept isn't in the glossary yet, that's a signal:
either you're inventing language the project doesn't use (reconsider) or there's a real
gap (note it for `/domain-modeling`).

If your output contradicts an existing ADR, surface it explicitly rather than silently
overriding it:

> _Contradicts ADR-0002 (thin per-framework adapters), but worth reopening because…_
