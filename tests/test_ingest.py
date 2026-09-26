"""Unit tests for code ingestion."""

from sentinel.ingest import ingest

TARGET = "targets/vulnerable_app"


def test_ingest_finds_functions():
    code_map = ingest(TARGET)
    names = {fn.name for fi in code_map.files for fn in fi.functions}
    assert {"get_user", "ping"} <= names


def test_ingest_finds_imports():
    code_map = ingest(TARGET)
    imports = {imp for fi in code_map.files for imp in fi.imports}
    assert "os" in imports
    assert "flask" in imports
