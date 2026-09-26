"""
Benchmark fixture for Sentinel's evaluation. Do not deploy.
Its labels live in ground_truth.json, never in this file, so the
model under test cannot read the answers. Keep line numbers stable.
"""

import os

from flask import Flask, request

app = Flask(__name__)

BASE_DIR = "/var/www/files"


@app.route("/download")
def download():
    filename = request.args.get("file", "")



    path = os.path.join(BASE_DIR, filename)
    with open(path) as handle:
        return handle.read()


if __name__ == "__main__":
    app.run()