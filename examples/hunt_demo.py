"""
hunt_demo.py
------------
Run the Hunter on the vulnerable app and print what the AI found.
Run from the project root:  python hunt_demo.py
"""

from sentinel.llm import LLMClient
from sentinel.tools import Tools
from sentinel.hunter import Hunter


def main() -> None:
    llm = LLMClient()
    tools = Tools("targets/vulnerable_app")
    hunter = Hunter(llm, tools)

    print("Hunting for vulnerabilities... (the model is thinking)\n")
    findings = hunter.hunt()

    if not findings:
        print("No findings (or the model returned nothing parseable).")
        return

    for f in findings:
        print(f"[{f.severity.upper()}] {f.vuln_class}  -  {f.file}:{f.line}")
        print(f"    {f.description}")
        print(f"    confidence: {f.confidence}")
        print()


if __name__ == "__main__":
    main()