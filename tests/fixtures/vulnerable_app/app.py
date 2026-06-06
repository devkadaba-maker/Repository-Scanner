"""
Intentionally vulnerable Flask app — for testing the security-audit-agent ONLY.
DO NOT deploy this in production or expose it to any network.
"""

import sqlite3
import subprocess
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# B105: Hardcoded password (bandit HIGH)
SECRET_KEY = "hardcoded_super_secret_password_123"
DATABASE = "/tmp/audit_test.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'password')"
    )
    conn.commit()
    conn.close()


@app.route("/login")
def login():
    """SQL injection: raw string formatting in query (bandit B608)."""
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    conn = get_db()
    # VULNERABILITY: SQL injection via string formatting
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        result = conn.execute(query).fetchone()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    conn.close()
    if result:
        return jsonify({"status": "ok", "user": dict(result)})
    return jsonify({"status": "failed"}), 401


@app.route("/ping")
def ping():
    """Command injection: unsanitised user input to subprocess shell=True (bandit B602)."""
    host = request.args.get("host", "127.0.0.1")
    # VULNERABILITY: shell=True with user-controlled input
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
    return output


@app.route("/eval")
def eval_endpoint():
    """Code injection: eval() on user-controlled input (bandit B307)."""
    expr = request.args.get("expr", "1+1")
    # VULNERABILITY: eval() on untrusted input
    result = eval(expr)  # noqa: S307
    return jsonify({"result": result})


@app.route("/file")
def read_file():
    """Path traversal: no sanitisation of filename (bandit B601 / manual)."""
    filename = request.args.get("name", "readme.txt")
    base_dir = "/tmp/"
    # VULNERABILITY: path traversal — no restriction on ../ sequences
    filepath = os.path.join(base_dir, filename)
    try:
        with open(filepath) as f:
            return f.read()
    except FileNotFoundError:
        return "not found", 404


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=True)
