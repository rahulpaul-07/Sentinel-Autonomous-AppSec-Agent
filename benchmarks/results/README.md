# Measured results

Every number the README or the project page reports comes from a file in this
directory. Each file is the unedited `--json` output of a run, and records the model,
the Sentinel commit it ran on, whether tracked files had uncommitted changes, and the
sandbox image each target ran in.

Rules for adding one:

* Run from a clean tree (`git status` shows no modified tracked files), so the result
  ties to a commit. The output flags a dirty tree; do not publish a flagged run.
* Commit the file as written. Never edit a results file; re-run instead.
* A file with `"complete": false` was stopped by a provider's usage limit. Finish it
  with the same command plus `--resume` before publishing it. Resuming is refused unless
  the commit, model and settings match and the tree is clean, so a completed file is one
  measurement even when its runs were made hours apart; each run records when it started
  and how many tokens it used.
* Name it `<date>-<harness>-<model>.json`, for example
  `2026-09-24-eval-gpt-oss-120b.json`.
* When the README quotes a figure, name the file it came from.
