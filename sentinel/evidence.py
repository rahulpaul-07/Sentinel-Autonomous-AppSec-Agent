"""
sentinel/evidence.py
--------------------
The evidence ladder.

A scanner that answers "is this a bug?" with yes/no is throwing away the most
useful thing it knows: *how much* it actually demonstrated. Sentinel grades every
candidate on what was proven about it, and reports the grade.

    UNREACHABLE   Static analysis found no path by which attacker-controlled data
                  can reach the reported line. Rejected before any model call --
                  costs nothing and kills a common class of hallucination.

    UNPROVEN      An exploit was attempted and never produced the success marker.
                  The claim could not be demonstrated.

    CLASS_ONLY    The exploit printed the marker, but the reported line never
                  executed while it ran. This proves the vulnerability *class* is
                  exploitable in principle -- it does NOT prove this line is.
                  In the literature this is the "simulated vulnerability" failure:
                  an LLM writes a generic demo that satisfies a shallow success
                  signal without touching the code under test.

    LINE_PROVEN   The exploit printed the marker AND the reported line executed
                  during the run. The specific claim was demonstrated.

Only LINE_PROVEN is a proof about *this code*. Collapsing CLASS_ONLY into
"confirmed" is exactly the overstatement this project exists to avoid, so the two
are counted and reported separately everywhere.
"""

from __future__ import annotations

from enum import Enum


class Evidence(str, Enum):
    """How much was actually demonstrated about a candidate finding."""

    UNREACHABLE = "unreachable"
    UNPROVEN = "unproven"
    CLASS_ONLY = "class_only"
    LINE_PROVEN = "line_proven"

    @property
    def is_confirmed(self) -> bool:
        """Did an exploit actually run and succeed?

        True for both proof tiers. This is the permissive reading, kept because it
        is what a v1-style scanner would have reported -- useful as a baseline to
        compare against, not as the headline number.
        """
        return self in (Evidence.CLASS_ONLY, Evidence.LINE_PROVEN)

    @property
    def is_line_proven(self) -> bool:
        """Was the *specific reported location* demonstrated? The strict reading."""
        return self is Evidence.LINE_PROVEN

    @property
    def label(self) -> str:
        return {
            Evidence.UNREACHABLE: "Unreachable",
            Evidence.UNPROVEN: "Unproven",
            Evidence.CLASS_ONLY: "Class only",
            Evidence.LINE_PROVEN: "Line proven",
        }[self]

    @property
    def blurb(self) -> str:
        return {
            Evidence.UNREACHABLE: "No path found from attacker-controlled input to this line.",
            Evidence.UNPROVEN: "The exploit never succeeded.",
            Evidence.CLASS_ONLY: "Exploit succeeded, but the reported line never ran.",
            Evidence.LINE_PROVEN: "Exploit succeeded and the reported line executed.",
        }[self]

    @property
    def rank(self) -> int:
        """Ordering for sorting strongest evidence first."""
        return {
            Evidence.LINE_PROVEN: 3,
            Evidence.CLASS_ONLY: 2,
            Evidence.UNPROVEN: 1,
            Evidence.UNREACHABLE: 0,
        }[self]
