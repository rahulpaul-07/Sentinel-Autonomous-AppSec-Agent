"""
patch_demo.py
-------------
The complete pipeline: hunt -> prove -> fix.
For every CONFIRMED finding, show a real secure-code diff.
Run from the project root:  python patch_demo.py
"""

from pathlib import Path

from sentinel.llm import LLMClient
from sentinel.tools import Tools
from sentinel.hunter import Hunter
from sentinel.sandbox import Sandbox
from sentinel.validator import Validator
from sentinel.patcher import Patcher


def main() -> None:
    target = "targets/vulnerable_app"
    llm = LLMClient()
    tools = Tools(target)
    hunter = Hunter(llm, tools)
    validator = Validator(llm, Sandbox())
    patcher = Patcher(llm)

    findings = hunter.hunt()
    print(f"Hunter found {len(findings)} candidate finding(s).\n")

    for f in findings:
        numbered = tools.read_file(f.file)            # context for validation
        result = validator.validate(f, numbered)
        if not result.confirmed:
            print(f"[skip] {f.vuln_class} at {f.file}:{f.line} - unconfirmed\n")
            continue

        print(f"[CONFIRMED] {f.vuln_class} at {f.file}:{f.line} - generating fix...")
        raw = (Path(target) / f.file).read_text()     # raw source for patching
        patch = patcher.propose(f, raw)
        print(patch.diff if patch.diff else "(model proposed no change)")
        print()


if __name__ == "__main__":
    main()