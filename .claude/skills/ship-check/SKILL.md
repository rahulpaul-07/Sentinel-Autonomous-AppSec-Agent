---
name: ship-check
description: Pre-push audit for a project before committing, pushing, or publishing. Use when the user says they are about to push, ship, deploy, submit, or share a repo, or asks whether something is ready. Runs tests, checks for leaked secrets, verifies built artifacts are current, and confirms claims in docs still match measured reality.
---

# Ship check

Run before a push, a submission, or sharing a repo with anyone who matters.
Work through every section. Report a single verdict at the end: SHIP or FIX
FIRST, with the blocking items named.

## 1. Secrets

The highest-severity, least-recoverable failure. Check in this order:

- `git check-ignore -v .env` -- confirm it actually matches an ignore rule.
  Print nothing means it is NOT ignored.
- Scan tracked files for key-shaped strings: `sk-`, `gsk_`, `ghp_`, `AKIA`,
  `-----BEGIN`, `api_key=`, `password=`, `token=` followed by a literal.
- `git log -p | grep` for the same patterns. **A key removed in a later commit is
  still in history and still compromised.** If one is found, say plainly that
  rotating the key is required and that deleting the file does not undo it.
- Check that `.env.example` contains placeholders only, never real values.

## 2. Tests

- Run the full suite. Report the count and the time.
- Run it from a **clean environment** if one can be made -- a fresh venv with
  only the declared dependencies. A suite that passes only in the author's
  shell is not a passing suite.
- Confirm any test added for a recent bug fix has been verified by reverting the
  fix (see the integration-test-review skill).

## 3. Working tree and history

- `git status --short` -- no untracked files that should be committed, no
  generated output that should be ignored (reports, JSON dumps, patches, logs).
- Scan recent commit messages for AI attribution, co-author trailers, or
  placeholder text.
- Check for duplicate or fixup commits that should have been squashed.
- Confirm the author identity on recent commits is correct:
  `git log -5 --format='%an <%ae>'`

## 4. Build artifacts

If the repo commits built output (a `docs/` folder served by Pages, a compiled
bundle, a generated schema):

- Rebuild it and check `git status` afterwards. **Any diff means the committed
  artifact is stale relative to its source.**
- Verify no stale hashed assets are accumulating from previous builds.
- Confirm the artifact references only files that exist.

## 5. Claims versus reality

Every number and capability claim in the README, the docs, or a project page
must trace to something real. For each one, ask:

- Where did this number come from, and when?
- Has the code changed since it was measured in a way that would move it?
- Is it a single sample presented as a general result?
- Does a documented feature still exist and still work the way it is described?

**A claim measured under an older version of the system is stale even if it was
true when written.** Flag it. Understating is recoverable; overstating is not.

## 6. A new reader's first five minutes

- Does the quickstart work verbatim, from a clean clone, in order?
- Does it install everything it needs, including dev tools the tests require?
- Are version constraints stated where they bite?
- Does the first command a reader runs produce something meaningful?

## 7. Failure messages at boundaries

For each external boundary -- config file, API call, subprocess, missing
dependency -- check what a user sees when it fails. A library's raw traceback
reaching the user is a defect. The message should name what is wrong and what to
do about it.

## Output

```
SECRETS        pass / FAIL  <detail>
TESTS          pass / FAIL  <count, environment>
TREE & HISTORY pass / FAIL  <detail>
ARTIFACTS      pass / FAIL  <detail>
CLAIMS         pass / FAIL  <which claim, why stale>
FIRST 5 MIN    pass / FAIL  <detail>
BOUNDARIES     pass / FAIL  <detail>

VERDICT: SHIP / FIX FIRST
blocking: <list>
```

Be specific about what blocks. "Could be better" is not a verdict.
