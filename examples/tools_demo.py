"""
tools_demo.py
-------------
Try out the tool layer on the vulnerable app.
Run from the project root:  python tools_demo.py
"""

from sentinel.tools import Tools


def main() -> None:
    tools = Tools("targets/vulnerable_app")

    print("Files in target:")
    for f in tools.list_files():
        print(f"  {f}")
    print()

    print("grep for dangerous calls (os.system, .execute):")
    for m in tools.grep(r"os\.system|\.execute\("):
        print(f"  {m.path}:{m.line_number}  ->  {m.line}")
    print()

    print("Reading app.py lines 30-36:")
    print(tools.read_file("app.py", start_line=30, end_line=36))


if __name__ == "__main__":
    main()