# Contributing to FirmWire

Thank you for your support and interest in improving FirmWire. <3

If you find a bug or want to suggest an improvement, please feel free to open an issue in this repository or contact the maintainers directly.

## Pull Request Guidelines

This section has two separate workflows:

- Guidelines for maintainers of this fork
- Guidelines for contributors to this repository

### For Maintainers of This Fork

This repository is a fork of the upstream FirmWire project. To keep contributions clean and easy to upstream, maintain a strict branch model.

#### Branch Roles

- `upstream-*` branches are tracking branches that mirror upstream branches exactly.
- The naming convention is `upstream-<name>`, where `<name>` is the exact upstream branch name.
- Example: upstream branch `dev/v1.2.0` must be mirrored as `upstream-dev/v1.2.0`.
- Never add custom commits directly to any `upstream-*` or `upstream/` branches.
- `pr/*` branches are for changes intended to be proposed upstream.
- Every `pr/*` branch must be created from an `upstream-*` tracking branch.
- `loris` is the private integration branch for this fork.
- `loris` can include both:
  - PR-worthy commits (merged/cherry-picked from `pr/*` branches)
  - Private, local-only commits that should never be sent upstream
- Never open upstream pull requests from `loris`.

#### Keep Tracking Branches in Sync

Assuming:

- `upstream` remote points to FirmWire/FirmWire
- tracking branch `upstream-dev/v1.2.0` should mirror `upstream/dev/v1.2.0`

Run:

```bash
git fetch upstream

git checkout upstream-dev/v1.2.0
git merge --ff-only upstream/dev/v1.2.0
```

`--ff-only` is required. It prevents accidental merge commits and guarantees your tracking branch stays a pure mirror.

Then update your fork copy:

```bash
git push origin upstream-dev/v1.2.0
```

#### Rebase PR Branches When Base Tracking Branch Moves

If your PR branch base is updated, rebase onto the refreshed tracking branch.

Example:

```bash
git checkout pr/cortex-a
git rebase upstream-dev/v1.2.0
```

If `pr/cortex-a` is already pushed or already has an open PR, push rewritten history safely:

```bash
git push --force-with-lease origin pr/cortex-a
```

Use `--force-with-lease` (not plain force push) to avoid overwriting others unexpectedly.

### For Contributors to This Repository

If you are contributing to this repository (and are not maintaining fork mirror branches), use this simpler workflow.

#### Branching and PR Flow

- Do not commit directly on shared branches in this repository.
- Start a new feature/fix branch from the branch you want to target.
- Make your commits in that new branch.
- Open a pull request from your branch.

Example:

```bash
git fetch origin
git checkout -b my/feature-name origin/loris
```

Replace `origin/loris` with whatever target base branch is appropriate for your PR.

#### If the Base Branch Changes While You Are Working

Rebase your branch so your work stays on top of the latest base.

```bash
git fetch origin
git checkout my/feature-name
git rebase origin/loris
```

If your branch was already pushed, update the remote branch with:

```bash
git push --force-with-lease origin my/feature-name
```

#### Contributor Checklist

- Keep PRs focused on one logical change when possible.
- Write clear commit messages.
- Prefer small, reviewable commits over one very large commit.
- Ask questions early by opening a draft PR if you want feedback before finalizing.

## FirmWire Coding Rules

Please follow these coding rules for pull requests.

### Dependencies

- Avoid adding new dependencies unless necessary.
- Avoid changing versions of existing dependencies unless discussed and agreed in a relevant issue/PR.

### Python Style

- Follow PEP 8 formatting conventions where practical.
- Long lines may be tolerated when readability is better and breaking lines would hurt clarity.
- Prefer double quotes (`"`) for strings when possible.
- For hardcoded immutable literal sequences, prefer tuples over lists.
- Keep imports sorted alphabetically.
- Keep import groups clean (stdlib, third-party, local project imports).

### Commit Message Style

Use meaningful commit messages with a verb-first short header line.

Recommended verbs include:

- `ADD`: introduce a new feature, file, or behavior
- `UPDATE`: change existing behavior or implementation
- `FIX`: resolve a bug or incorrect behavior
- `REFACTOR`: improve structure without changing external behavior
- `REMOVE`: delete obsolete code or files
- `DOCS`: update documentation only
- `TEST`: add or improve tests
- `CHORE`: maintenance work (build scripts, metadata, housekeeping)
- `PERF`: performance-focused improvements

Suggested format:

```text
VERB: short summary

[optional detailed paragraph or bullet list]
```

Examples:

```text
FIX: handle empty TOC entries in Shannon loader

- Guard against missing table offsets
- Add warning log for malformed records
```

```text
REFACTOR: simplify MediaTek task hook registration
```

Thanks again for contributing to FirmWire.