import hashlib
import secrets
import sqlite3

from flask import g, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from config import ADMIN_PASSWORD, ADMIN_USERNAME, APP_ROOT, DB


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(stored_hash: str, password: str) -> tuple[bool, bool]:
    if stored_hash.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored_hash, password), False
    legacy_ok = stored_hash == hashlib.sha256(password.encode()).hexdigest()
    return legacy_ok, legacy_ok


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


def close_db(_e=None):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(DB)
    db.execute(
        """CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        api_key TEXT UNIQUE
    )"""
    )
    db.execute(
        """CREATE TABLE IF NOT EXISTS sessions_map (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        waha_session_name TEXT NOT NULL,
        UNIQUE(user_id, waha_session_name)
    )"""
    )
    db.execute(
        """CREATE TABLE IF NOT EXISTS gateway_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        session_name TEXT NOT NULL,
        event_type TEXT NOT NULL DEFAULT 'message',
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )"""
    )
    cols = {row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()}
    if "api_key" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN api_key TEXT")
    if ADMIN_PASSWORD:
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, role, api_key) VALUES (?,?,?,?)",
                (ADMIN_USERNAME, hash_password(ADMIN_PASSWORD), "admin", secrets.token_hex(16)),
            )
        except sqlite3.IntegrityError:
            pass
    missing_api_key_ids = [row[0] for row in db.execute("SELECT id FROM users WHERE api_key IS NULL OR api_key='' ").fetchall()]
    for user_id in missing_api_key_ids:
        db.execute("UPDATE users SET api_key=? WHERE id=?", (secrets.token_hex(16), user_id))
    db.commit()
    db.close()


def current_user():
    if not session.get("user_id"):
        return None
    return get_db().execute(
        "SELECT id, username, role, api_key FROM users WHERE id=?",
        (session["user_id"],),
    ).fetchone()


def ensure_user_api_key(user_id: int) -> str:
    row = get_db().execute("SELECT api_key FROM users WHERE id=?", (user_id,)).fetchone()
    if row and row["api_key"]:
        return row["api_key"]
    api_key = secrets.token_hex(16)
    get_db().execute("UPDATE users SET api_key=? WHERE id=?", (api_key, user_id))
    get_db().commit()
    return api_key


def public_base_url() -> str:
    root = request.url_root.rstrip("/")
    if APP_ROOT and root.endswith(APP_ROOT):
        return root
    if APP_ROOT:
        return request.host_url.rstrip("/") + APP_ROOT
    return root


def gateway_owner(session_name: str, api_key: str):
    return get_db().execute(
        """SELECT u.id, u.username, u.role, u.api_key
        FROM users u
        JOIN sessions_map sm ON sm.user_id = u.id
        WHERE sm.waha_session_name=? AND u.api_key=?
        LIMIT 1""",
        (session_name, api_key),
    ).fetchone()
