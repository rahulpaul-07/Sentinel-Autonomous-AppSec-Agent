"""
Benchmark fixture for Sentinel's evaluation. Do not deploy.
Its labels live in ground_truth.json, never in this file, so the
model under test cannot read the answers. Keep line numbers stable.


"""

import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)



SECRET_KEY = "super-secret-admin-password-123"


@app.route("/user")
def get_user():


    username = request.args.get("username", "")

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()




    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)

    return str(cursor.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "")



    os.system("ping -c 1 " + host)

    return "pinged " + host


if __name__ == "__main__":
    app.run(debug=True)