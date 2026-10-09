import os

from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/")
def home():
    return jsonify(
        {
            "application": "DevSecOps Secure Pipeline",
            "status": "running"
        }
    )


@app.route("/health")
def health():
    return jsonify(
    {
        "status": "healthy"
    }
)


if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "127.0.0.1")
    app.run(host=host, port=5000)