"""
ingest_demo.py
--------------
Run code ingestion on the vulnerable test app and print what we found.
Run from the project root:  python ingest_demo.py
"""

from sentinel.ingest import ingest


def main() -> None:
    code_map = ingest("targets/vulnerable_app")
    print(code_map.summary())
    print()

    for file_info in code_map.files:
        print(f"File: {file_info.path.name}")
        print(f"  Imports:   {file_info.imports}")
        for func in file_info.functions:
            print(f"  Function:  {func.name}()  (lines {func.start_line}-{func.end_line})")
        print()


if __name__ == "__main__":
    main()