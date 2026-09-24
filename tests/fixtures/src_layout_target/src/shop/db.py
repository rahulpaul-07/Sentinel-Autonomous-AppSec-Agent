"""Deliberately vulnerable module in a src-layout package, for the Docker tests."""

import sqlite3

from .config import TABLE


def login(username):
    conn = sqlite3.connect(":memory:")
    conn.execute(f"CREATE TABLE {TABLE} (name TEXT)")
    conn.execute(f"INSERT INTO {TABLE} VALUES ('admin')")
    query = f"SELECT * FROM {TABLE} WHERE name = '" + username + "'"
    return conn.execute(query).fetchall()
