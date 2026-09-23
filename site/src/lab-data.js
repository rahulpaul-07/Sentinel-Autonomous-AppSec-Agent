// Recorded from real runs of sentinel/witness.py against the target below.
// These are captured outputs of the actual tracing harness, replayed in the
// browser -- not a simulation, and not invented numbers.

export const LAB_TARGET = "import sqlite3\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\ndef setup():\n    conn = sqlite3.connect(\":memory:\")\n    conn.execute(\"CREATE TABLE users (name TEXT, pw TEXT)\")\n    conn.execute(\"INSERT INTO users VALUES ('admin','s3cret')\")\n    return conn\n\ndef login(conn, username):\n    query = \"SELECT * FROM users WHERE name = '\" + username + \"'\"\n    return conn.execute(query).fetchall()\n";

export const LAB_SINK_LINE = 14;

export const LAB_RUNS = [
  {
    "id": "generic",
    "name": "Reproduce the pattern",
    "blurb": "The classic hallucinated proof: valid SQL injection, demonstrated on a throwaway table. Never imports the target.",
    "poc": "import sqlite3\nconn = sqlite3.connect(\":memory:\")\nconn.execute(\"CREATE TABLE t (a TEXT)\")\nconn.execute(\"INSERT INTO t VALUES ('x')\")\nq = \"SELECT * FROM t WHERE a = '\" + \"' OR '1'='1\" + \"'\"\nif conn.execute(q).fetchall():\n    print(\"SENTINEL_PWNED\")",
    "marker": true,
    "fileExecuted": false,
    "lineExecuted": false,
    "executedLines": [],
    "evidence": "class_only",
    "explain": "The exploit never executed any code in app.py -- it demonstrated the vulnerability class in isolation.",
    "stdout": "SENTINEL_PWNED"
  },
  {
    "id": "import_only",
    "name": "Import and claim",
    "blurb": "Imports the module so the file shows up in the trace, then prints the marker without calling anything.",
    "poc": "import app\nprint(\"SENTINEL_PWNED\")",
    "marker": true,
    "fileExecuted": true,
    "lineExecuted": false,
    "executedLines": [
      1,
      2,
      4,
      6,
      12
    ],
    "evidence": "class_only",
    "explain": "The exploit ran code in app.py, but never reached line 14 (nearest executed line: 12).",
    "stdout": "SENTINEL_PWNED"
  },
  {
    "id": "targeted",
    "name": "Drive the real code",
    "blurb": "Imports the target and calls login() with a malicious username, exercising the reported line.",
    "poc": "import app\nconn = app.setup()\nrows = app.login(conn, \"' OR '1'='1\")\nif rows:\n    print(\"SENTINEL_PWNED\")",
    "marker": true,
    "fileExecuted": true,
    "lineExecuted": true,
    "executedLines": [
      1,
      2,
      4,
      6,
      7,
      8,
      9,
      10,
      12,
      13,
      14
    ],
    "evidence": "line_proven",
    "explain": "app.py:14 executed while the exploit ran.",
    "stdout": "SENTINEL_PWNED"
  },
  {
    "id": "targeted_safe",
    "name": "Drive it with benign input",
    "blurb": "Calls the same real code path with a harmless username. The line runs; the exploit does not succeed.",
    "poc": "import app\nconn = app.setup()\nrows = app.login(conn, \"alice\")\nif rows:\n    print(\"SENTINEL_PWNED\")",
    "marker": false,
    "fileExecuted": true,
    "lineExecuted": true,
    "executedLines": [
      1,
      2,
      4,
      6,
      7,
      8,
      9,
      10,
      12,
      13,
      14
    ],
    "evidence": "unproven",
    "explain": "app.py:14 executed while the exploit ran.",
    "stdout": ""
  }
];
