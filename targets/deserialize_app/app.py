"""
Benchmark fixture for Sentinel's evaluation. Do not deploy.
Its labels live in ground_truth.json, never in this file, so the
model under test cannot read the answers. Keep line numbers stable.
"""

import base64
import pickle

from flask import Flask, request

app = Flask(__name__)


@app.route("/load")
def load():
    blob = request.args.get("data", "")



    raw = base64.b64decode(blob)
    obj = pickle.loads(raw)
    return str(obj)


if __name__ == "__main__":
    app.run()