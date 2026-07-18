<!-- AUTO-SYNCED from agents KB: AGENT.md @ fab34a5.
     Do NOT edit here — edit the source in ~/projects/agents and re-run scripts/sync-conventions.sh. -->

# Agent Rules

This file defines general rules and guidelines that apply to **all projects**, regardless of technology.
Technology-specific rules live in `/technologies/`.

---

## Model Roles & Orchestration

When the session runs on **Claude Fable 5** (model id `claude-fable-5`):

- Fable 5 is **never used as a coding agent**. It does not write or edit product code
  directly.
- Fable 5's role is **architecture and validation**: understand the task, read the
  relevant code and conventions, design the change (files, structure, contracts, naming,
  i18n keys, tests), then **delegate the implementation to Opus 4.8 subagents**
  (Agent tool with `model: "opus"`), giving each a precise, self-contained spec.
- After a subagent finishes, Fable 5 **validates** the result: review the diff against
  the spec and the KB conventions, run typecheck/lint/tests, and send follow-up fixes
  back to the (or a new) Opus agent rather than patching the code itself.
- Trivial non-code chores (running builds/tests, git operations, file listing) stay
  with Fable 5 — the rule covers writing code, not operating tools.

---

## General Principles

- Write clean, readable, and maintainable code.
- Prefer clarity over cleverness.
- Follow the principle of least surprise.
- Keep functions and components small and focused (single responsibility).

---

## Code Style

- Use consistent naming conventions appropriate for the language.
- Avoid magic numbers and strings — use named constants.
- Remove dead code and unused imports.
- Keep indentation consistent throughout a file.

---

## Comments & Documentation

- Write comments to explain *why*, not *what*.
- Document public APIs, functions, and non-obvious logic.
- Keep comments up to date with code changes.

---

## Git & Workflow

- Write clear, descriptive commit messages.
- Keep commits focused — one logical change per commit.
- Never commit secrets, credentials, or environment-specific values.

### Creating repositories

- Create new repositories with the **`gh` CLI** (`gh repo create`), not the web UI, so
  it's scriptable and repeatable.
- **Always ask the user whether the repo should be public or private before creating
  it** — never assume a default. (Most repos are public; only some are private.)
- Ask which owner/org it belongs under when it's not obvious (personal `Janne6565` vs an
  org like `Magenta-Mause`).
- Name and place new repos to match the local convention:
  `~/projects/<project-name>/<repo-name>` (see `/projects/README.md`). For multi-repo
  projects use the `<project>-backend` / `-frontend` / `-deployment` pattern.

---

## Testing

- Write tests for critical logic and edge cases.
- Tests should be readable and serve as documentation.
- Aim for meaningful coverage, not just high percentages.

---

## Technology-Specific Rules

For technology or framework-specific guidelines, refer to the relevant file in `/technologies/`:

- `/technologies/SPRING_BOOT.md` — layered architecture, package structure, JPA, error handling
- `/technologies/REACT.md` — component/hook split, state, typed i18n, Orval, testing

---

## Concept-Specific Rules

For cross-cutting infrastructure and architectural guidelines, refer to `/concepts/`:

- `/concepts/DEPLOYMENT.md` — GitOps model, Kustomize layout, ArgoCD conventions
- `/concepts/CICD.md` — GitHub Actions build → ghcr.io → tag-bump loop, image tags
- `/concepts/CLUSTER.md` — the k3s cluster map, namespaces, ingress/TLS, add-ons
- `/concepts/MONITORING.md` — SigNoz (OTel) observability; how to instrument + dashboard new projects
- `/concepts/AUTH.md` — stateless self-issued JWT model (access/refresh, 2FA, OAuth), backend + frontend

---

## Tooling & Standard Stack

- `/TOOLS.md` — the default toolbox (frontend, backend, infra, testing) and when to
  deviate from it.

---

## Project Knowledge Base

For an overview of every project — its idea, stack, what stands out, where it lives
on disk, and its cluster namespace — see `/projects/`:

- `/projects/README.md` — index + "how the projects relate" overview
- One file per project (e.g. `/projects/cosy.md`, `/projects/strata.md`)

**Working with a project's code:** repos are not referenced by machine-specific paths.
Each project's repos live under `~/projects/<project-name>/` (multi-repo projects use
one subfolder per repo: `~/projects/<project-name>/<repo-name>/`). Before reading or
working on a project, for each repo in its doc's **Repos** field: clone it there if the
local folder is missing, otherwise `git pull` first — **always work from the latest**.
See `/projects/README.md` for the full convention.
