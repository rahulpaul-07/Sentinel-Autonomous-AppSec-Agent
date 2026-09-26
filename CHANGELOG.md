# Changelog

## 0.3.0 — September 2026: security audit

A review of the pipeline against its own threat model: the exploit is untrusted code,
and the scanned target is untrusted input that the model reads. Every defect below was
reproduced against 0.2.0 before it was fixed, and every fix has a regression test that
fails when it is reverted.

### Security

- **Witness integrity (critical).** An exploit could grade itself `LINE_PROVEN` without
  calling the vulnerable function, by printing a record-shaped line and exiting before
  the harness, or by importing `__main__` and editing the tracer's hit set. Trace
  records are now authenticated with a per-run nonce, tracer state lives in closures,
  the record goes out through a private descriptor, and exploits reaching for frames,
  trace hooks, `os._exit`, `__main__` or `ctypes` are refused before they run.
- **Gate soundness (high).** The static gate rejected real vulnerabilities before
  validation: `realpath`/`resolve` counted as path sanitizers, a sanitizer on one
  argument excused another, `["sh", "-c", x]` counted as shell-free, and sinks missing
  from the catalogue counted as absent. Sanitizers are now resolved through imports and
  checked by a second taint pass; tainted calls the gate cannot model fail open.
- **Report XSS (high).** Model-supplied severity reached the HTML report unescaped. It is
  escaped, normalised at parse time, and the report carries a CSP forbidding script.
- **Prompt injection (high).** Target source is fenced with random delimiters it cannot
  contain, and every system prompt marks fenced text as data.
- **Sandbox.** Exploits run as `nobody` with `no-new-privileges` and swap capped; output
  is truncated to 1 MB inside the container; model requests time out.
- **Discovery.** Symlinks are never followed out of the target; virtualenvs and build
  output are never scanned.
- **Dependencies.** `aiohttp` 3.14.1 → 3.14.3 (PYSEC-2026-3545/3546/3547); site
  `postcss` 8.4.49 → 8.5.28, `vite` 5 → 6.4.3.

### Added

- Fix verification: the exploits that proved a file's findings are replayed against a
  patched copy of the tree. Fixes are `verified`, `still_exploitable` or `inconclusive`.
- `--sarif PATH` (SARIF 2.1.0 for GitHub code scanning) and `--fail-on SEVERITY`.
- `--max-findings`, `--no-verify-fix`, documented exit codes, `SENTINEL_LLM_TIMEOUT`.
- Provider failures that retrying cannot fix (a bad key, an unknown model) are one clean
  `ModelError` line with exit code 5 instead of a library traceback, in all three CLIs.
- ruff with bandit rules, `pip-audit` and `npm audit` in CI.
- A benchmark hygiene test that fails if a target's comments hint at its labels.

### Changed

- One fix per file now covers every proven finding in it; it must parse and differ from
  the original. `--yes` applies only verified fixes.
- Applying a fix keeps the file's line endings.
- Candidates past the `--max-findings` budget are kept on the report, highest
  confidence graded first.
- Benchmark targets no longer carry answer-key comments. **Published results predate
  this and need re-measuring.**
- The project page was rebuilt without template components or third-party requests.

### Fixed

- A project stored under a directory named `build` (or any ignored name) was mapped
  as empty by `ingest`.
- `sentinel-eval` only worked from the repository root.
