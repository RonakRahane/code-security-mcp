# Intentionally vulnerable fixture. Test corpus only, never runnable code.
# Use this to test: scan_file({ filePath: "/path/to/this/file" })

import os
import pickle
import yaml
import hashlib
import random
import subprocess
import sqlite3
from flask import Flask, request, render_template_string, send_file, redirect

app = Flask(__name__)

# SECRETS
SECRET_KEY = "super-secret-flask-key-that-should-be-in-env"
app.secret_key = "another-hardcoded-secret-key"
API_KEY = "sk_live_notarealkeyusedasfix"
DATABASE_URL = "postgresql://admin:password123@db.example.com:5432/prod"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

# SQL INJECTION
@app.route("/users")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return str(cursor.fetchall())

@app.route("/search")
def search():
    query = request.args.get("q")
    cursor.execute("SELECT * FROM products WHERE name = '%s'" % query)
    return str(cursor.fetchall())

# COMMAND INJECTION
@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system(f"ping -c 1 {host}")
    return "Done"

@app.route("/convert")
def convert():
    filename = request.args.get("file")
    subprocess.call(f"convert {filename} output.pdf", shell=True)
    return "Converted"

@app.route("/legacy")
def legacy():
    cmd = request.args.get("cmd")
    result = os.popen(cmd).read()
    return result

# INSECURE DESERIALIZATION
@app.route("/load", methods=["POST"])
def load_data():
    data = request.get_data()
    obj = pickle.loads(data)
    return str(obj)

@app.route("/config")
def load_config():
    config_data = request.args.get("config")
    config = yaml.load(config_data)
    return str(config)

# XSS / TEMPLATE INJECTION
@app.route("/greet")
def greet():
    name = request.args.get("name")
    return render_template_string(f"<h1>Hello {name}</h1>")

# PATH TRAVERSAL
@app.route("/download")
def download():
    filename = request.args.get("file")
    return send_file(f"/uploads/{filename}")

@app.route("/read")
def read_file():
    path = request.args.get("path")
    content = open(f"/data/{path}").read()
    return content

# WEAK CRYPTO
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def generate_token():
    return str(random.randint(100000, 999999))

def hash_data(data):
    return hashlib.sha1(data.encode()).hexdigest()

# AUTH ISSUES
import jwt

def get_user_from_token(token):
    # No verification!
    data = jwt.decode(token, options={"verify_signature": False})
    return data

def check_admin(request):
    assert request.user.is_admin  # assert stripped with -O flag!

# DJANGO-STYLE ISSUES
DEBUG = True
ALLOWED_HOSTS = ['*']

# FLASK DEBUG IN PRODUCTION
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
