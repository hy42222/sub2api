---
name: sub2api-upstream-sync
description: Use when syncing upstream/main or an explicitly requested official release into this fork's main and prod branches, reviewing their divergence, or updating the document that tracks prod-specific behavior.
---

# Sub2API Upstream Sync

## Overview

Keep `main` as the selected upstream baseline, merge that baseline into `prod` without rewriting history, and maintain `docs/MAIN_PROD_DIFF.md` as the record of production-specific behavior.

## Workflow

1. Check `git status --short --branch`; stop if unrelated work is present. Verify `upstream` and `origin`, then run `git fetch upstream --tags`.
2. Select the requested source:
   - For an upstream branch sync, update local `main` with `git switch main` and `git merge --ff-only upstream/main`.
   - For an explicitly requested release-only sync, identify the latest non-draft, non-prerelease GitHub release with `gh release view --repo Wei-Shaw/sub2api --json tagName,publishedAt,isPrerelease,isDraft,targetCommitish,url`. Verify its tag resolves and is an ancestor of `upstream/main`; then fast-forward local `main` to that tag with `git merge --ff-only <release-tag>`. Do not include commits after the release tag. Record how many commits `upstream/main` is ahead of the selected release baseline.
3. Before changing `prod`, inspect `git log --left-right main...prod` and `git diff --stat main...prod`.
4. Switch to `prod` and create an explicit merge commit:
   - Branch sync: `git merge --no-ff main -m 'merge: sync upstream main into prod'`.
   - Release sync: `git merge --no-ff main -m 'merge: sync upstream release <tag> into prod'`.
5. Resolve conflicts semantically, then run tests relevant to changed areas. Do not use `reset`, rebase published branches, or an `ours` merge strategy to conceal conflicts.
6. Update `docs/MAIN_PROD_DIFF.md` after every successful merge. Record the selected source/tag, `main` SHA, merge commit and its parents, the `prod` merge snapshot SHA, prod-only non-merge commits grouped by behavior, and the complete `git diff --name-status main..prod` output. Keep the list focused on the merge snapshot; identify later docs-only maintenance separately instead of trying to list the document's own commit.
7. Verify `git merge-base --is-ancestor main prod`. If `main` is not an ancestor of `prod`, stop and investigate.
8. Push only the explicitly requested remote branch. Do not push `main` or rewrite history unless explicitly requested.

## Documentation Rules

- Describe persistent tree differences with `main..prod`, not `main...prod`.
- Treat merge commits as synchronization history, not product functionality. Group non-merge commits by behavior and preserve the full commit list for the recorded merge snapshot.
- Keep the document current rather than appending stale snapshots. Include exact file statuses from `git diff --name-status main..prod`.
- For release-only syncs, make clear that `main` intentionally stops at the release tag and that later `upstream/main` commits were excluded.
