"""
sandbox_demo.py
---------------
Prove the sandbox works AND that the cage holds.
Run from the project root:  python sandbox_demo.py
"""

from sentinel.sandbox import Sandbox


def main() -> None:
    sandbox = Sandbox()

    print("1) Run Python inside the container (expect 4):")
    r = sandbox.run('python3 -c "print(2 + 2)"')
    print(f"   exit_code={r.exit_code}  stdout={r.stdout.strip()!r}\n")

    print("2) Try to reach the internet (expect FAILURE = caged):")
    r = sandbox.run('python3 -c "import urllib.request; urllib.request.urlopen(\'http://example.com\')"')
    print(f"   exit_code={r.exit_code}  (non-zero means the network was blocked)\n")

    print("3) Try to run forever (expect a timeout):")
    short = Sandbox(timeout_seconds=5)
    r = short.run("sleep 60")
    print(f"   timed_out={r.timed_out}")


if __name__ == "__main__":
    main()