
from flask import Flask, request, session
import sqlite3
import os
import hashlib
from cryptography.fernet import Fernet
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "change-this-secret")

KEY = os.environ.get("DATA_KEY")
if KEY:
    KEY = KEY.encode()
else:
    KEY = Fernet.generate_key()

cipher = Fernet(KEY)
ACCESS_CODE = os.environ.get("ACCESS_CODE", "CODE123")

def database():
    conn = sqlite3.connect("task2.db")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            note BLOB
        )
    """)
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def page_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return "Please log in first.", 401
        if not session.get("verified"):
            return "Access code verification required.", 403
        return fn(*args, **kwargs)
    return wrapper

@app.route("/", methods=["GET", "POST"])
def home():
    message = ""
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or not password:
            message = "Enter username and password."
        else:
            conn = database()
            row = conn.execute(
                "SELECT password FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if row:
                message = "Username already exists. Please log in."
            else:
                conn.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, hash_password(password))
                )
                conn.commit()
                message = "Account created. You can now log in."
            conn.close()

    return f"""
    <h1>CodeAlpha Task 2 - Data Leak Protection</h1>
    <h2>Create Account</h2>
    <form method="post">
      <input name="username" placeholder="Username" required>
      <input name="password" type="password"
             placeholder="Password" required>
      <button>Create Account</button>
    </form>
    <h2>Login</h2>
    <form action="/login" method="post">
      <input name="username" placeholder="Username" required>
      <input name="password" type="password"
             placeholder="Password" required>
      <button>Login</button>
    </form>
    <p>{message}</p>
    """

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"].strip()
    password = request.form["password"]
    conn = database()
    row = conn.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()

    if row and row[0] == hash_password(password):
        session.clear()
        session["user"] = username
        return """
        <h2>Login successful</h2>
        <form method="post" action="/verify">
          <input name="code" placeholder="Access code" required>
          <button>Verify Access Code</button>
        </form>
        """
    return "Invalid username or password.", 401

@app.route("/verify", methods=["POST"])
def verify():
    if not session.get("user"):
        return "Please log in first.", 401
    if request.form["code"] != ACCESS_CODE:
        return "Invalid access code.", 403
    session["verified"] = True
    return """
    <h2>Access granted</h2>
    <form method="post" action="/note">
      <textarea name="note" placeholder="Sensitive note"
                required></textarea>
      <button>Encrypt and Save</button>
    </form>
    <a href="/note">View saved note</a>
    """

@app.route("/note", methods=["GET", "POST"])
@page_required
def note():
    conn = database()
    if request.method == "POST":
        encrypted = cipher.encrypt(
            request.form["note"].encode()
        )
        conn.execute(
            "UPDATE users SET note = ? WHERE username = ?",
            (encrypted, session["user"])
        )
        conn.commit()

    row = conn.execute(
        "SELECT note FROM users WHERE username = ?",
        (session["user"],)
    ).fetchone()
    conn.close()

    saved = ""
    if row and row[0]:
        saved = cipher.decrypt(row[0]).decode()

    return f"""
    <h2>Your protected note</h2>
    <p>{saved}</p>
    <a href="/">Home</a>
    """

if __name__ == "__main__":
    database().close()
    app.run(debug=True)
