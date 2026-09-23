---
name: integration-test-review
description: Review tests for over-mocking and missing integration coverage. Use when writing or reviewing tests, when adding a test for a bug fix, when a bug slipped past a passing suite, or when the user asks whether their tests are good enough. Checks that tests assert on how boundaries are CALLED rather than only what they return.
---

# Integration test review

## Why this exists

A suite can be fully green while the system is completely broken. The failure
mode is specific and common: tests mock an external boundary and assert on its
**return value**, so nothing ever checks the **arguments** the code passed in.

Real example from this repository. The validator wrapped each proof-of-concept
in a harness that imported the target module from a mounted directory, but it
called `Sandbox.run(command)` without `workdir` -- the argument that adds the
bind mount. Nothing was mounted, every exploit died with `ModuleNotFoundError`,
and **63 tests passed** because all of them stubbed `Sandbox.run` and asserted on
the `SandboxResult` it returned.

The test that would have caught it is three lines:

```python
def test_validator_mounts_the_target(monkeypatch):
    calls = []
    def run(self, command, workdir=None):
        calls.append({"command": command, "workdir": workdir})
        return SandboxResult(0, "SENTINEL_PWNED\n", "", False)
    monkeypatch.setattr("sentinel.sandbox.Sandbox.run", run)

    Validator(StubLLM(), Sandbox(), target="targets/app").validate(finding, "src")

    assert calls[0]["workdir"] is not None   # the whole bug, caught
```

## The review

Work through these in order. Report findings plainly; do not soften them.

### 1. Find every mocked boundary

List each `monkeypatch.setattr`, `unittest.mock.patch`, fake, or stub in the
suite. For each one, name what real thing it replaces: a network call, a
subprocess, a container, the filesystem, a clock, a model API.

### 2. For each boundary, ask: does anything assert on the CALL?

A boundary that is only ever asserted on by its return value is unprotected.
Anything about how it is invoked -- a missing argument, a wrong flag, a
malformed path, a swapped parameter order -- passes silently.

Flag every boundary where no test inspects the arguments. For each, propose the
recording-stub test that would close it.

### 3. Check the contract between caller and callee

Where a mock stands in for something with a real contract, verify the mock still
honors it. A stub whose signature has drifted from the real function will accept
calls the real thing would reject. Check:

- the stub's signature matches the real callable's
- required arguments are required in the stub too
- the stub returns the same shape the real thing returns

### 4. Look for the interaction gap

A bug can live in how two correct pieces combine. Ask which pairs of components
are only ever tested apart, and whether any of those pairs share state, ordering,
or a counting rule.

Real example: two tiers of finding counted separately, where a header used the
wrong one. The single-tier tests passed because with one tier populated, both
counts coincide. Only a test rendering **both at once** exposed it.

### 5. Demand one real end-to-end path

Every project needs at least one test that exercises the real thing -- real
subprocess, real container, real file. Slow and occasionally flaky is fine.
If the suite has none, say so directly and propose the smallest one that would
have caught the most recent bug.

### 6. Verify every regression test by reverting

A test written for a bug fix is not a test until it has been seen to fail.
For each new regression test, instruct:

1. revert the fix
2. run the test, confirm it FAILS
3. restore the fix
4. run again, confirm it PASSES

If a regression test passes with the bug reintroduced, it tests nothing. Say so.

## Output

Report as:

```
BOUNDARY: <what is mocked>           ASSERTED ON CALL: yes / NO
  risk: <what could break silently>
  proposed test: <the assertion that would catch it>
```

Then: interaction gaps, whether a real end-to-end test exists, and any
regression test not yet verified by reverting.

## What not to do

- Do not propose raising coverage percentage as a remedy. Coverage counts lines
  executed, not properties checked; the 63-test example had the mount line
  covered.
- Do not suggest mocking more. The fix for an over-mocked suite is never a
  better mock.
- Do not praise a suite for its size. Report what is unprotected.
