# Contributing to FirmWire

Thank you for your support and interest in improving FirmWire. <3

If you find a bug or want to suggest an improvement, please feel free to open an issue in this repository or contact the maintainers directly.

## Pull Request Guidelines

This section has two separate workflows:

- Guidelines for the Loris Maintainers team (members with write access)
- Guidelines for external contributors to this repository

### For the Loris Maintainers Team

This repository is a private fork of the upstream FirmWire project (`FirmWire/FirmWire`). Members of the **Loris Maintainers** team have write access and help maintain this fork. To keep history clean and easy to upstream, we follow a strict branch model that is enforced by repository rulesets (see [Branch Protection](#branch-protection-rulesets)).

#### Branch Roles

- `loris` is the default integration branch for this fork. It may contain both PR-worthy commits and private, local-only commits that should never be sent upstream. Never open an upstream pull request from `loris`.
- `upstream-*` branches are tracking branches that mirror upstream branches exactly. The naming convention is `upstream-<name>`, where `<name>` is the exact upstream branch name (for example, upstream branch `dev/v1.2.0` is mirrored as `upstream-dev/v1.2.0`). They must stay pure, fast-forward-only mirrors; never add custom commits to an `upstream-*` branch.
- `dev/*` is the upstream project's own branch namespace (e.g. `dev/v1.2.0`). Do not create or modify `dev/*` branches in this fork.
- `pr/*` branches stage changes intended to be proposed upstream. Only the repository admin creates and manages `pr/*` branches.
- `user/<github_username>/*` branches are your personal working branches — the only namespace team members push to.

Everything outside `user/<your-username>/*` is reserved for the admin and is protected by rulesets. Do not create, modify, or push to those branches.

#### Working on a User Branch

Do all of your work on branches under your own namespace:

```
user/<github_username>/<descriptive-name>
```

Rules for the `<descriptive-name>` part:

1. **If your work relates to an issue, start with the issue number.** For example, if your username is `johndoe` and you are working on issue #3, name the branch like:

   ```
   user/johndoe/issue-3/fix-a-bug
   ```

   where `fix-a-bug` is a short description based on the issue.
2. **Use dashes (`-`), not underscores (`_`), to separate words** in each path segment whenever possible (e.g. `fix-a-bug`, not `fix_a_bug`).

You may freely create, push, and force-push branches under `user/<your-username>/`. Do not push to another member's `user/...` namespace.

#### Choosing a Base Branch

The branch you create your user branch from depends on the task, and should be agreed on in the relevant issue before you start. For example:

- Work intended to be proposed **upstream** (`FirmWire/FirmWire`) should be based on the matching upstream mirror, e.g. `upstream-dev/v1.2.0`.
- Work targeting this fork's integration branch should be based on `loris`.

Example:

```bash
git fetch origin
# base chosen per the issue — here, an upstream mirror:
git checkout -b user/johndoe/issue-3/fix-a-bug origin/upstream-dev/v1.2.0
```

#### Opening Pull Requests

- Open pull requests from your `user/<username>/*` branch into the agreed base branch **within this repository**.
- Do not open pull requests to the upstream `FirmWire/FirmWire` repository directly from a user branch. Upstream PRs are sent by the admin from a `pr/*` branch (see [Admin Responsibilities](#admin-responsibilities)).

#### Keeping Your Branch Up to Date

If the base branch moves while you are working, rebase so your work stays on top:

```bash
git fetch origin
git checkout user/johndoe/issue-3/fix-a-bug
git rebase origin/upstream-dev/v1.2.0   # or origin/loris, per your base
```

If your branch is already pushed, update the remote branch with:

```bash
git push --force-with-lease origin user/johndoe/issue-3/fix-a-bug
```

Use `--force-with-lease` (not a plain force push) to avoid overwriting work unexpectedly.

### Admin Responsibilities

These tasks are performed by the repository admin (and anyone granted the GitHub **Maintain** role). The branches involved are protected by rulesets so regular team members cannot modify them.

#### Keep Tracking Branches in Sync

Assuming the `upstream` remote points to `FirmWire/FirmWire`, and `upstream-dev/v1.2.0` should mirror `upstream/dev/v1.2.0`:

```bash
git fetch upstream
git checkout upstream-dev/v1.2.0
git merge --ff-only upstream/dev/v1.2.0
git push origin upstream-dev/v1.2.0
```

`--ff-only` is required. It prevents accidental merge commits and guarantees the tracking branch stays a pure mirror.

#### Send Pull Requests Upstream from `pr/*`

Changes destined for upstream are consolidated into a `pr/*` branch by the admin — never sent to upstream directly from user branches.

- Create each `pr/*` branch from the relevant `upstream-*` mirror.
- If several members contributed, bring all of their changes together into the `pr/*` branch, make any final edits, then open the upstream pull request from `pr/*`.
- If the base mirror moves, rebase the PR branch onto it and push with `--force-with-lease`:

```bash
git checkout pr/cortex-a
git rebase upstream-dev/v1.2.0
git push --force-with-lease origin pr/cortex-a
```

#### Branch Protection (Rulesets)

The branch model above is enforced by repository rulesets. Bypass is limited to repository admins (the **Maintain** role can be added per-person if you want to delegate mirror/PR upkeep):

- `upstream-**` — locked to admins/maintainers; fast-forward only, no force pushes (pure mirrors that preserve upstream history verbatim).
- `dev/**` — reserved for the upstream namespace; team members cannot create or modify them.
- `pr/**` — managed only by admins/maintainers for upstream PRs.
- `loris` — requires a pull request before merging; no force pushes.
- All other non-`user/**` branches — locked to admins/maintainers.

Team members work freely only under `user/<github_username>/**`.

Use `--force-with-lease` (not plain force push) to avoid overwriting others unexpectedly.

### For External Contributors to This Repository

If you are a Loris Maintainers team member with write access, follow the section above instead. If you are an external contributor without write access (and are not maintaining fork mirror branches), use this simpler workflow from your own fork.

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