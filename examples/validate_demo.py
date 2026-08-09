"""
validate_demo.py
----------------
Full pipeline: hunt for vulnerabilities, then PROVE each one in the sandbox.
Run from the project root:  python validate_demo.py
"""

from sentinel.llm import LLMClient
from sentinel.tools import Tools
from sentinel.hunter import Hunter
from sentinel.sandbox import Sandbox
from sentinel.validator import Validator


def main() -> None:
    llm = LLMClient()
    tools = Tools("targets/vulnerable_app")
    hunter = Hunter(llm, tools)
    sandbox = Sandbox()
    validator = Validator(llm, sandbox)

    print("Hunting for vulnerabilities...\n")
    findings = hunter.hunt()
    print(f"Found {len(findings)} candidate findings. Proving each one...\n")

    confirmed_count = 0
    for f in findings:
        code = tools.read_file(f.file)
        print(f"Validating {f.vuln_class} at {f.file}:{f.line} ...")
        result = validator.validate(f, code)
        if result.confirmed:
            confirmed_count += 1
            print("   -> CONFIRMED (exploit ran and printed the marker)\n")
        else:
            print("   -> unconfirmed (no proof produced)")
            print(f"      sandbox said: {result.output[:200]!r}\n")

    print(f"Summary: {confirmed_count}/{len(findings)} findings PROVEN by execution.")


if __name__ == "__main__":
    main()