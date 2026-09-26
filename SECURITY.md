# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **Report a vulnerability**
button on this repository's Security tab, not in a public issue. Include the commit, a
reproduction, and what an attacker gains. Expect an acknowledgement within a week.

## What counts

Sentinel executes model-written exploit code and reads code nobody has vetted, so these
are in scope:

- escaping the Docker sandbox, or reaching the network or the host filesystem from it
- an exploit influencing its own grade (for example, reaching `LINE_PROVEN` without
  executing the reported line)
- the static gate rejecting a real vulnerability on anything other than positive evidence
- scanned code reading host files outside the target, or steering the model into a result
  that is then reported as proven
- script execution or data leakage from the HTML report

Known and documented limits are listed under *Security model* and *Limitations* in the
[README](README.md). In particular, `--build-env` runs `pip install` for the target's
dependencies with network access and is out of scope by design; use it only on code you
would install.
