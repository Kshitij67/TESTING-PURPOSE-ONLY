"""
Vulnerable Demo App - Intentional security flaws for Semgrep testing.
DO NOT use in production.
"""
import hashlib
import os
import pickle
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# --- VULN 1: Hardcoded secret ---
DATABASE_PASSWORD = "SuperSecret123!"
API_KEY = "AKIAIOSFODNN7EXAMPLE"


# --- VULN 2: SQL Injection ---
@app.route("/user")
def get_user():
    username = request.args.get("username")
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    result = conn.execute(query)
    return str(result.fetchall())


# --- VULN 3: Command Injection ---
@app.route("/ping")
def ping():
    host = request.args.get("host")
    output = os.system("ping -c 1 " + host)
    return str(output)


# --- VULN 4: Insecure Deserialization ---
@app.route("/load", methods=["POST"])
def load_data():
    data = request.get_data()
    obj = pickle.loads(data)
    return str(obj)


# --- VULN 5: Weak Hashing for Passwords ---
@app.route("/register", methods=["POST"])
def register():
    password = request.form.get("password")
    hashed = hashlib.md5(password.encode()).hexdigest()
    return f"Stored hash: {hashed}"


# --- VULN 6: Path Traversal ---
@app.route("/read")
def read_file():
    filename = request.args.get("file")
    with open("/var/data/" + filename, "r") as f:
        return f.read()


if __name__ == "__main__":
    app.run(debug=True)
