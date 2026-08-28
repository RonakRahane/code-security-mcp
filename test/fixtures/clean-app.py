"""Secure-by-construction Flask service.

Part of the benchmark corpus, labelled "clean": any alert raised here is an
unambiguous false positive. It contains the constructs that naive pattern
matching over-reports: SQL text, subprocess calls, deserialisation, hashing,
and credential-shaped names, all used correctly.
"""

import hashlib
import hmac
import json
import os
import secrets
import subprocess  # nosec: used only with argument lists below
from pathlib import Path

import yaml

UPLOAD_ROOT = Path("/srv/uploads").resolve()
ALLOWED_TOOLS = {"identify", "exiftool"}


def get_api_key() -> str:
    """Credentials come from the environment, never from source."""
    api_key = os.environ.get("SERVICE_API_KEY")
    if not api_key:
        raise RuntimeError("SERVICE_API_KEY is not configured")
    return api_key


def find_user_by_id(connection, user_id):
    """Parameterised query: static SQL, values bound separately."""
    with connection.cursor() as cursor:
        cursor.execute("SELECT id, email FROM users WHERE id = %s", (user_id,))
        return cursor.fetchone()


def list_active_users(connection):
    """Multi-line SQL with no interpolation."""
    query = """
        SELECT id, email
        FROM users
        WHERE active = true
        ORDER BY created_at DESC
    """
    with connection.cursor() as cursor:
        cursor.execute(query)
        return cursor.fetchall()


def hash_password(password: str) -> bytes:
    """Memory-hard KDF with a random salt."""
    salt = secrets.token_bytes(16)
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)


def verify_signature(payload: bytes, signature: str, key: bytes) -> bool:
    """Constant-time comparison over a SHA-256 HMAC."""
    expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def resolve_upload_path(filename: str) -> Path:
    """Containment check after resolution prevents traversal."""
    candidate = (UPLOAD_ROOT / Path(filename).name).resolve()
    if UPLOAD_ROOT not in candidate.parents and candidate != UPLOAD_ROOT:
        raise ValueError("Invalid upload path")
    return candidate


def inspect_image(tool: str, file_path: str) -> str:
    """Argument list with an allowlist; shell is never invoked."""
    if tool not in ALLOWED_TOOLS:
        raise ValueError("Unsupported tool")
    result = subprocess.run(
        [tool, "--", str(resolve_upload_path(file_path))],
        capture_output=True,
        check=True,
        shell=False,
        timeout=30,
    )
    return result.stdout.decode()


def load_config(raw: str) -> dict:
    """safe_load never constructs arbitrary Python objects."""
    return yaml.safe_load(raw)


def parse_payload(raw: str) -> dict:
    """JSON parsing instead of pickle or eval."""
    return json.loads(raw)
