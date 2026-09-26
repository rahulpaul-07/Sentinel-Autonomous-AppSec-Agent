"""
Benchmark fixture for Sentinel's evaluation. Do not deploy.
Its labels live in ground_truth.json, never in this file, so the
model under test cannot read the answers. Keep line numbers stable.

"""

import os
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)


SECRET_KEY = os.environ.get("APP_SECRET_KEY", "")


@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
    return str(cursor.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "")

    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
    return result.stdout


if __name__ == "__main__":
    app.run()