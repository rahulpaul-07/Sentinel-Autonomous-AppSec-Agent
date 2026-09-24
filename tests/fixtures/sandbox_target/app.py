"""
Stdlib-only target for the real-Docker tests. Deliberately vulnerable.

It imports nothing outside the standard library, so it runs in the bare default
sandbox image. That keeps these tests about the sandbox and the witness, not
about dependency installation.
"""

import sqlite3

API_TOKEN = "fixture-token-not-a-real-secret"


def setup():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (name TEXT, pw TEXT)")
    conn.execute("INSERT INTO users VALUES ('admin', 's3cret')")
    return conn


def login(conn, username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return conn.execute(query).fetchall()
