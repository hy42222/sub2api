---
name: sub2api-upstream-sync
description: Use when syncing upstream/main into this fork's main and prod branches, reviewing their divergence, or updating the document that tracks prod-specific behavior after an upstream merge.
---

# Sub2API Upstream Sync

## Overview

Keep `main` aligned to `upstream/main`, merge it into `prod` without rewriting history, and maintain `docs/MAIN_PROD_DIFF.md` as the source of truth for production-only behavior.

## Workflow

1. Check `git status --short --branch`; stop if unrelated work is present. Run `git fetch upstream`.
2. Ensure `main` tracks `upstream/main`:

   ```bash
   git switch -c main --track upstream/main  # first run only
   git switch main
   git merge --ff-only upstream/main
   ```

3. Inspect divergence before changing `prod`:

   ```bash
   git log --left-right main...prod
   git diff --stat main...prod
   ```

4. Merge with an explicit merge commit:

   ```bash
   git switch prod
   git merge --no-ff main -m 'merge: sync upstream main into prod'
   ```

5. Resolve conflicts semantically, then run the tests relevant to changed areas. Do not use `reset`, rebase published branches, or an `ours` merge strategy to conceal conflicts.
6. Update `docs/MAIN_PROD_DIFF.md` after every successful merge. Record the `main` and `prod` SHAs, the merge commit, prod-only non-merge commits from `git log --no-merges main..prod`, their user-visible purpose, and files from `git diff --name-status main..prod`.
7. Verify the relationship with `git merge-base --is-ancestor main prod`. Do not push unless explicitly requested.

## Documentation Rules

- After the merge, use `main..prod`, not `main...prod`, to describe the persistent prod-only tree difference.
- Treat merge commits as synchronization history, not product functionality. List the underlying non-merge commits and group them by behavior.
- Keep the document current rather than appending stale snapshots. Preserve concise historical context only when it explains a remaining prod-only change.
- If `main` is not an ancestor of `prod` after the merge, stop and investigate before declaring the sync complete.

## Resources (optional)

Create only the resource directories this skill actually needs. Delete this section if no resources are required.

### scripts/
Executable code (Python/Bash/etc.) that can be run directly to perform specific operations.

**Examples from other skills:**
- PDF skill: `fill_fillable_fields.py`, `extract_form_field_info.py` - utilities for PDF manipulation
- DOCX skill: `document.py`, `utilities.py` - Python modules for document processing

**Appropriate for:** Python scripts, shell scripts, or any executable code that performs automation, data processing, or specific operations.

**Note:** Scripts may be executed without loading into context, but can still be read by Codex for patching or environment adjustments.

### references/
Documentation and reference material intended to be loaded into context to inform Codex's process and thinking.

**Examples from other skills:**
- Product management: `communication.md`, `context_building.md` - detailed workflow guides
- BigQuery: API reference documentation and query examples
- Finance: Schema documentation, company policies

**Appropriate for:** In-depth documentation, API references, database schemas, comprehensive guides, or any detailed information that Codex should reference while working.

### assets/
Files not intended to be loaded into context, but rather used within the output Codex produces.

**Examples from other skills:**
- Brand styling: PowerPoint template files (.pptx), logo files
- Frontend builder: HTML/React boilerplate project directories
- Typography: Font files (.ttf, .woff2)

**Appropriate for:** Templates, boilerplate code, document templates, images, icons, fonts, or any files meant to be copied or used in the final output.

---

**Not every skill requires all three types of resources.**
