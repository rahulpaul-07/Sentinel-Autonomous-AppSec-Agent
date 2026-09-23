---
name: honest-claims
description: Check that claims in a README, project page, report, or resume trace to real evidence. Use when writing or reviewing documentation, results sections, portfolio descriptions, or any text stating what a system achieves. Catches single samples quoted as general results, stale numbers, and capability claims the code no longer supports.
---

# Honest claims

Overstatement is the fastest way to lose a technical reader, and the damage is
asymmetric: understating a result costs a little credit, while one inflated
number invites doubt about everything else on the page.

Review every claim against these.

## 1. Provenance

For each number, capability, or comparison, ask:

- **Where did it come from?** A measurement, a single run, an estimate, or
  nothing at all?
- **When?** Name the date. A number measured before a significant change is
  stale even if nobody edited the sentence.
- **Under what version?** If the system changed in a way that would move the
  number, the number needs re-measuring or an explicit note.

Flag anything that cannot be traced to a specific run, test, or source.

## 2. Sample size and variance

- How many cases produced this number?
- Is a single run being quoted as a general result?
- Is a best-observed result presented as typical?
- Would repeating it give the same answer? Anything stochastic -- a hosted model,
  a timing measurement, a benchmark on shared hardware -- will not.

**A range with its spread is more credible than a point estimate, not less.**
Prefer "precision 71-100% across three runs" to "precision 100%". A reader who
sees the spread trusts the rest of the page.

## 3. The strength of the claim versus the strength of the evidence

Match the verb to what was shown:

| Evidence | Honest verb |
|---|---|
| ran once, worked | "demonstrated on" |
| ran across a small labelled set | "measured on N cases" |
| proved a property | "proves" |
| pattern-matched it | "detects" / "flags" |
| it executed but was not verified | "attempted" |

Flag any verb stronger than its evidence. Especially: "proves", "guarantees",
"ensures", "always", "never", "production-ready", "scalable".

## 4. The untested versus the failed

A claim that was never tested and a claim that was tested and failed are
different results. Conflating them overstates in one direction or the other.
Check that the text distinguishes:

- we tested it and it held
- we tested it and it did not hold
- we could not test it, and why

## 5. What is missing

Absence is a form of overstatement. Check the text states:

- the limitations a knowledgeable reader would ask about
- what the system does NOT do that its name or framing implies
- the conditions under which the numbers would not hold

If a limitation is known and unlisted, adding it makes the rest more credible.

## 6. Comparisons

- Is the comparison against a real alternative, fairly configured?
- Is the baseline named specifically enough to be checked?
- Is "faster" / "better" / "more accurate" quantified and scoped?

Vague superiority claims ("unlike typical tools") need either a named
alternative or removal.

## Output

For each flagged claim:

```
CLAIM:    <quote it>
ISSUE:    unsourced / stale / oversized sample / verb too strong / missing caveat
EVIDENCE: <what actually supports it>
REWRITE:  <the honest version>
```

Then note any limitation that should be stated and is not.

## The standard

The goal is not hedging everything into mush. A real result stated plainly is
the most persuasive thing on the page. The goal is that **every sentence a
skeptical reader checks turns out to be true** -- because the ones they cannot
check are then believed.
