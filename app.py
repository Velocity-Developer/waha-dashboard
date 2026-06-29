#!/usr/bin/env python3
"""WAHA Dashboard Multi-User"""
import asyncio
import hashlib
import json
import os
import secrets
import sqlite3
from functools import wraps

import httpx
from flask import Flask, flash, g, redirect, render_template_string, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(__file__)
WAHA_URL = os.environ.get("WAHA_URL", "http://127.0.0.1:3001")
WAHA_API_KEY = os.environ.get("WAHA_API_KEY", "")
DB = os.path.join(BASE_DIR, "waha_users.db")
SECRET_KEY = os.environ.get("WAHA_DASH_SECRET") or secrets.token_hex(32)
PORT = int(os.environ.get("PORT", "8084"))
ADMIN_USERNAME = os.environ.get("WAHA_DASH_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("WAHA_DASH_ADMIN_PASSWORD", "")
APP_ROOT = os.environ.get("APP_ROOT", "")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)


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


@app.teardown_appcontext
def close_db(_e):
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
        role TEXT NOT NULL DEFAULT 'user'
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
    if ADMIN_PASSWORD:
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                (ADMIN_USERNAME, hash_password(ADMIN_PASSWORD), "admin"),
            )
        except sqlite3.IntegrityError:
            pass
    db.commit()
    db.close()


init_db()


def login_required(f):
    @wraps(f)
    def dec(*a, **kw):
        if "user_id" not in session:
            flash("Silakan login dulu", "warning")
            return redirect(url_for("login"))
        return f(*a, **kw)

    return dec


def admin_required(f):
    @wraps(f)
    @login_required
    def dec(*a, **kw):
        u = get_db().execute("SELECT role FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not u or u["role"] != "admin":
            flash("Akses ditolak", "danger")
            return redirect(url_for("index"))
        return f(*a, **kw)

    return dec


def is_admin() -> bool:
    return session.get("role") == "admin"


def can_access_session(name: str) -> bool:
    if is_admin():
        return True
    row = get_db().execute(
        "SELECT 1 FROM sessions_map WHERE user_id=? AND waha_session_name=?",
        (session.get("user_id"), name),
    ).fetchone()
    return bool(row)


async def awaha(method, path, json_data=None):
    async with httpx.AsyncClient(base_url=WAHA_URL) as cl:
        headers = {"X-Api-Key": WAHA_API_KEY, "Accept": "application/json"}
        if json_data is not None:
            headers["Content-Type"] = "application/json"
        r = await cl.request(method, path, headers=headers, json=json_data, timeout=30)
        return r.status_code, r.text


def waha(method, path, json_data=None):
    if not WAHA_API_KEY:
        raise RuntimeError("WAHA_API_KEY belum diset")
    return asyncio.run(awaha(method, path, json_data))


@app.context_processor
def inject_globals():
    return {"app_root": APP_ROOT}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["username"].strip()
        raw_password = request.form["password"]
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if row:
            ok, needs_upgrade = verify_password(row["password_hash"], raw_password)
            if not ok:
                flash("Username atau password salah", "danger")
                return render_template_string(LOGIN_TPL, username=session.get("username"), role=session.get("role"))
            if needs_upgrade:
                db.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(raw_password), row["id"]))
                db.commit()
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]
            flash("Login berhasil", "success")
            return redirect(url_for("index"))
        flash("Username atau password salah", "danger")
    return render_template_string(LOGIN_TPL, username=session.get("username"), role=session.get("role"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Logout berhasil", "info")
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form["username"].strip()
        p = request.form["password"]
        if not u or not p:
            flash("Username dan password wajib diisi", "danger")
            return render_template_string(REGISTER_TPL, username=session.get("username"), role=session.get("role"))
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password_hash) VALUES (?,?)", (u, hash_password(p)))
            db.commit()
            flash("Registrasi berhasil, silakan login", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username sudah dipakai", "danger")
    return render_template_string(REGISTER_TPL, username=session.get("username"), role=session.get("role"))


@app.route("/")
@login_required
def index():
    data = "[]"
    try:
        _, data = waha("GET", "/api/sessions")
    except Exception as e:
        flash(f"Gagal konek WAHA: {e}", "danger")
    sessions = json.loads(data) if isinstance(data, str) else []
    if not is_admin():
        owned = {
            row["waha_session_name"]
            for row in get_db().execute(
                "SELECT waha_session_name FROM sessions_map WHERE user_id=?",
                (session["user_id"],),
            ).fetchall()
        }
        sessions = [s for s in sessions if s.get("name") in owned]
    return render_template_string(
        INDEX_TPL,
        username=session.get("username"),
        role=session.get("role"),
        sessions=sessions,
        auto_qr=request.args.get("qr", ""),
    )


@app.route("/users")
@admin_required
def users_list():
    db = get_db()
    rows = db.execute("SELECT id, username, role FROM users ORDER BY id").fetchall()
    mapped = db.execute(
        """SELECT sm.waha_session_name, u.username
        FROM sessions_map sm JOIN users u ON u.id = sm.user_id
        ORDER BY sm.waha_session_name, u.username"""
    ).fetchall()
    session_names = []
    try:
        _, data = waha("GET", "/api/sessions")
        session_names = sorted({s.get("name") for s in json.loads(data) if s.get("name")})
    except Exception:
        pass
    return render_template_string(
        USERS_TPL,
        username=session.get("username"),
        role=session.get("role"),
        users=rows,
        mapped=mapped,
        session_names=session_names,
    )


@app.route("/users/create", methods=["POST"])
@admin_required
def users_create():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "user")
    if not username or not password:
        flash("Username dan password wajib diisi", "danger")
        return redirect(url_for("users_list"))
    if role not in {"admin", "user"}:
        role = "user"
    try:
        get_db().execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
            (username, hash_password(password), role),
        )
        get_db().commit()
        flash(f"User '{username}' dibuat", "success")
    except sqlite3.IntegrityError:
        flash("Username sudah dipakai", "danger")
    return redirect(url_for("users_list"))


@app.route("/users/update", methods=["POST"])
@admin_required
def users_update():
    user_id = request.form.get("user_id", type=int)
    username = request.form.get("username", "").strip()
    role = request.form.get("role", "user")
    password = request.form.get("password", "")
    if not user_id or not username:
        flash("User tidak valid", "danger")
        return redirect(url_for("users_list"))
    if role not in {"admin", "user"}:
        role = "user"
    db = get_db()
    row = db.execute("SELECT id, username FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        flash("User tidak ditemukan", "danger")
        return redirect(url_for("users_list"))
    try:
        if password:
            db.execute(
                "UPDATE users SET username=?, role=?, password_hash=? WHERE id=?",
                (username, role, hash_password(password), user_id),
            )
        else:
            db.execute(
                "UPDATE users SET username=?, role=? WHERE id=?",
                (username, role, user_id),
            )
        db.commit()
        if user_id == session.get("user_id"):
            session["username"] = username
            session["role"] = role
        flash(f"User '{row['username']}' diupdate", "success")
    except sqlite3.IntegrityError:
        flash("Username sudah dipakai", "danger")
    return redirect(url_for("users_list"))


@app.route("/users/delete", methods=["POST"])
@admin_required
def users_delete():
    user_id = request.form.get("user_id", type=int)
    if not user_id:
        flash("User tidak valid", "danger")
        return redirect(url_for("users_list"))
    if user_id == session.get("user_id"):
        flash("Tidak bisa hapus user login sendiri", "danger")
        return redirect(url_for("users_list"))
    db = get_db()
    row = db.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        flash("User tidak ditemukan", "danger")
        return redirect(url_for("users_list"))
    db.execute("DELETE FROM sessions_map WHERE user_id=?", (user_id,))
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    flash(f"User '{row['username']}' dihapus", "info")
    return redirect(url_for("users_list"))


@app.route("/sessions/assign", methods=["POST"])
@admin_required
def sessions_assign():
    user_id = request.form.get("user_id", type=int)
    session_name = request.form.get("session_name", "").strip()
    if not user_id or not session_name:
        flash("User dan session wajib dipilih", "danger")
        return redirect(url_for("users_list"))
    row = get_db().execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        flash("User tidak ditemukan", "danger")
        return redirect(url_for("users_list"))
    get_db().execute("DELETE FROM sessions_map WHERE waha_session_name=?", (session_name,))
    get_db().execute(
        "INSERT INTO sessions_map (user_id, waha_session_name) VALUES (?,?)",
        (user_id, session_name),
    )
    get_db().commit()
    flash(f"Session '{session_name}' di-assign ke '{row['username']}'", "success")
    return redirect(url_for("users_list"))


@app.route("/session/start", methods=["POST"])
@login_required
def session_start():
    name = request.form.get("name", "").strip()
    if not name:
        flash("Nama session wajib diisi", "danger")
        return redirect(url_for("index"))
    try:
        st, _ = waha("POST", "/api/sessions/start", {"name": name, "config": {"webhook_url": ""}})
        if st in (200, 201):
            get_db().execute(
                "INSERT OR IGNORE INTO sessions_map (user_id, waha_session_name) VALUES (?,?)",
                (session["user_id"], name),
            )
            get_db().commit()
        flash(
            f"Session '{name}' started. QR akan dibuka otomatis." if st in (200, 201) else f"Gagal start session (HTTP {st})",
            "success" if st in (200, 201) else "danger",
        )
        if st in (200, 201):
            return redirect(url_for("index", qr=name))
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("index"))


@app.route("/session/stop", methods=["POST"])
@login_required
def session_stop():
    name = request.form.get("name", "")
    if not can_access_session(name):
        flash("Akses session ditolak", "danger")
        return redirect(url_for("index"))
    try:
        waha("DELETE", f"/api/sessions/{name}/stop")
        flash(f"Session '{name}' stopped", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("index"))


@app.route("/session/qr/<name>")
@login_required
def session_qr(name):
    if not can_access_session(name):
        return {"error": "Akses session ditolak"}, 403
    try:
        st, data = waha("GET", f"/api/{name}/auth/qr")
        if int(st) != 200:
            return data, int(st), {"Content-Type": "application/json"}
        payload = json.loads(data) if isinstance(data, str) else data
        if payload.get("data") and payload.get("mimetype"):
            return {"qr": f"data:{payload['mimetype']};base64,{payload['data']}"}, 200
        if payload.get("qr") or payload.get("code"):
            return payload, 200
        return {"error": "QR belum tersedia", "raw": payload}, 404
    except Exception as e:
        return {"error": str(e)}, 500


@app.route("/session/status/<name>")
@login_required
def session_status(name):
    if not can_access_session(name):
        return {"error": "Akses session ditolak"}, 403
    try:
        st, data = waha("GET", f"/api/sessions/{name}")
        return data, int(st), {"Content-Type": "application/json"}
    except Exception as e:
        return {"error": str(e)}, 500


@app.route("/session/logout", methods=["POST"])
@login_required
def session_logout():
    name = request.form.get("name", "")
    if not can_access_session(name):
        flash("Akses session ditolak", "danger")
        return redirect(url_for("index"))
    try:
        waha("DELETE", f"/api/sessions/{name}/logout")
        flash(f"Session '{name}' logged out", "info")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("index"))


BASE = """<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WAHA Dashboard</title>
  <base href="{{ app_root }}/">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
  <style>
    :root {
      --bg: #f8fafc;
      --panel: #ffffff;
      --panel-2: #f8fafc;
      --line: #e2e8f0;
      --line-2: #cbd5e1;
      --text: #0f172a;
      --muted: #64748b;
      --primary: #2563eb;
      --primary-2: #1d4ed8;
      --danger: #dc2626;
      --warning: #d97706;
      --success: #16a34a;
      --info: #0891b2;
      --radius: 16px;
      --radius-sm: 12px;
      --shadow: 0 18px 45px rgba(15, 23, 42, .08);
    }
    * { box-sizing: border-box; }
    html, body { margin: 0; padding: 0; }
    body {
      background: linear-gradient(180deg, #f8fafc 0%, #eef2ff 100%);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }
    a { color: var(--primary); text-decoration: none; }
    a:hover { color: var(--primary-2); }
    .container { width: min(1180px, calc(100% - 32px)); margin: 0 auto; }
    .row { display: flex; flex-wrap: wrap; margin: -10px; }
    .col-12, .col-md-4, .col-md-6, .col-lg-4, .col-lg-5, .col-lg-7 { width: 100%; padding: 10px; }
    @media (min-width: 768px) {
      .col-md-4 { width: 33.3333%; }
      .col-md-6 { width: 50%; }
    }
    @media (min-width: 992px) {
      .col-lg-4 { width: 33.3333%; }
      .col-lg-5 { width: 41.6667%; }
      .col-lg-7 { width: 58.3333%; }
    }
    .justify-content-center { justify-content: center; }
    .justify-content-between { justify-content: space-between; }
    .align-items-center { align-items: center; }
    .align-items-start { align-items: flex-start; }
    .d-flex { display: flex; }
    .gap-2 { gap: 8px; }
    .g-3 { gap: 0; }
    .flex-wrap { flex-wrap: wrap; }
    .text-center { text-align: center; }
    .text-white { color: #fff; }
    .text-warning { color: #b45309; }
    .text-danger { color: #b91c1c; }
    .text-light-emphasis, .text-secondary { color: var(--muted); }
    .fw-bold { font-weight: 700; }
    .display-6 { font-size: 44px; }
    .m-0 { margin: 0; }
    .mb-0 { margin-bottom: 0; }
    .mb-1 { margin-bottom: 4px; }
    .mb-3 { margin-bottom: 16px; }
    .mb-4 { margin-bottom: 20px; }
    .mt-1 { margin-top: 8px; }
    .mt-2 { margin-top: 12px; }
    .mt-3 { margin-top: 16px; }
    .mt-5 { margin-top: 40px; }
    .me-2 { margin-right: 8px; }
    .me-3 { margin-right: 12px; }
    .p-0 { padding: 0; }
    .p-3 { padding: 20px; }
    .p-4 { padding: 28px; }
    .p-5 { padding: 40px; }
    .w-100 { width: 100%; }
    .h-100 { height: 100%; }
    .card {
      background: rgba(255, 255, 255, .88);
      border: 1px solid rgba(148, 163, 184, .2);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      backdrop-filter: blur(10px);
    }
    .navbar {
      position: sticky;
      top: 0;
      z-index: 40;
      background: rgba(255, 255, 255, .82);
      border-bottom: 1px solid rgba(148, 163, 184, .18);
      backdrop-filter: blur(12px);
    }
    .navbar .container, .navbar-collapse, .navbar-nav { display: flex; align-items: center; }
    .navbar .container { min-height: 72px; justify-content: space-between; }
    .navbar-brand { font-size: 20px; color: var(--text); }
    .navbar-collapse.show { display: flex; flex: 1; justify-content: space-between; }
    .navbar-nav { list-style: none; padding: 0; margin: 0 0 0 20px; gap: 8px; }
    .nav-link {
      display: inline-flex; align-items: center; padding: 10px 14px; border-radius: 12px; color: var(--muted);
    }
    .nav-link:hover { background: rgba(37, 99, 235, .08); color: var(--primary); }
    .btn {
      appearance: none; border: 1px solid transparent; border-radius: 12px; cursor: pointer;
      padding: 10px 14px; font: inherit; font-weight: 600; color: #fff; background: #334155;
      transition: .18s ease; text-decoration: none; display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    }
    .btn:hover { transform: translateY(-1px); filter: brightness(1.02); }
    .btn-sm { padding: 8px 12px; font-size: 14px; border-radius: 10px; }
    .btn-primary { background: linear-gradient(180deg, var(--primary), var(--primary-2)); box-shadow: 0 10px 24px rgba(37, 99, 235, .18); }
    .btn-secondary, .btn-outline-secondary { background: #f8fafc; border-color: var(--line-2); color: var(--text); }
    .btn-outline-primary { background: #eff6ff; border-color: #bfdbfe; color: var(--primary); }
    .btn-outline-danger { background: #fef2f2; border-color: #fecaca; color: var(--danger); }
    .btn-outline-warning { background: #fffbeb; border-color: #fde68a; color: var(--warning); }
    .btn-outline-info { background: #ecfeff; border-color: #a5f3fc; color: var(--info); }
    .btn-outline-success { background: #f0fdf4; border-color: #bbf7d0; color: var(--success); }
    .form-label { display: block; margin-bottom: 8px; color: #334155; font-size: 14px; }
    .form-control, .form-select {
      width: 100%; background: #fff; border: 1px solid rgba(148, 163, 184, .35);
      color: var(--text); border-radius: 12px; padding: 12px 14px; outline: 0; font: inherit;
    }
    .form-control-sm, .form-select-sm { padding: 9px 12px; font-size: 14px; }
    .form-control:focus, .form-select:focus {
      border-color: rgba(96, 165, 250, .75); box-shadow: 0 0 0 4px rgba(59, 130, 246, .12);
    }
    .form-control::placeholder { color: #94a3b8; }
    .input-group { display: flex; align-items: stretch; }
    .input-group .form-control { border-top-right-radius: 0; border-bottom-right-radius: 0; }
    .input-group .btn { border-top-left-radius: 0; border-bottom-left-radius: 0; }
    .badge {
      display: inline-flex; align-items: center; border-radius: 999px; padding: 6px 10px; font-size: 12px; font-weight: 700;
      border: 1px solid rgba(255,255,255,.06);
    }
    .bg-success { background: #dcfce7; color: #166534; }
    .bg-danger { background: #fee2e2; color: #991b1b; }
    .bg-warning { background: #fef3c7; color: #92400e; }
    .bg-primary { background: #dbeafe; color: #1d4ed8; }
    .bg-secondary { background: #e2e8f0; color: #475569; }
    .table-responsive { overflow-x: auto; }
    .table { width: 100%; border-collapse: collapse; background: transparent; }
    .table th, .table td { padding: 14px 16px; border-bottom: 1px solid rgba(148, 163, 184, .16); text-align: left; }
    .table th { color: #475569; font-size: 12px; text-transform: uppercase; letter-spacing: .06em; background: rgba(248, 250, 252, .85); }
    .table-striped tbody tr:nth-child(odd) { background: rgba(248,250,252,.65); }
    .table-striped tbody tr:hover { background: rgba(219,234,254,.25); }
    .align-middle td, .align-middle th { vertical-align: middle; }
    hr { border: 0; border-top: 1px solid rgba(148, 163, 184, .16); }
    .border-secondary { border-color: rgba(148, 163, 184, .16) !important; }
    .modal { position: fixed; inset: 0; z-index: 1055; display: none; overflow-x: hidden; overflow-y: auto; background: rgba(15, 23, 42, .3); padding: 24px; }
    .modal.show { display: block; }
    .modal-dialog { width: min(520px, 100%); margin: 6vh auto; }
    .modal-sm .modal-dialog, .modal-dialog.modal-sm { width: min(360px, 100%); }
    .modal-content { background: #fff; border: 1px solid rgba(148, 163, 184, .2); border-radius: 18px; box-shadow: var(--shadow); overflow: hidden; }
    .modal-header, .modal-footer { padding: 16px 20px; display: flex; align-items: center; justify-content: space-between; }
    .modal-body { padding: 20px; }
    .modal-title { margin: 0; font-size: 18px; color: var(--text); }
    .btn-close { background: transparent; border: 0; color: #475569; font-size: 18px; cursor: pointer; opacity: .75; }
    .btn-close::before { content: '✕'; }
    .btn-close:hover { opacity: 1; }
    .spinner-border {
      width: 36px; height: 36px; border-radius: 50%; display: inline-block; border: 3px solid rgba(148,163,184,.28); border-top-color: #60a5fa;
      animation: spin .8s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .toast-container { position: fixed; top: 18px; right: 18px; z-index: 9999; width: min(380px, calc(100% - 24px)); }
    .toast { border-radius: 14px; border: 1px solid rgba(148,163,184,.14); margin-bottom: 10px; overflow: hidden; box-shadow: 0 18px 40px rgba(15, 23, 42, .1); }
    .toast-body { padding: 14px 16px; }
    .text-bg-danger { background: #fff1f2; color: #9f1239; }
    .text-bg-success { background: #f0fdf4; color: #166534; }
    .text-bg-warning { background: #fffbeb; color: #92400e; }
    .text-bg-info { background: #ecfeff; color: #0f766e; }
    @media (max-width: 767px) {
      .container { width: min(100% - 24px, 1180px); }
      .navbar .container, .navbar-collapse.show { display: block; }
      .navbar-nav { margin: 12px 0 0; flex-wrap: wrap; }
      .d-flex.justify-content-between.align-items-center.mb-3 { flex-direction: column; align-items: stretch; gap: 12px; }
      .table th, .table td { padding: 12px; }
      .p-4, .p-5 { padding: 20px; }
    }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg mb-4">
  <div class="container">
    <a class="navbar-brand fw-bold text-white" href="{{ app_root or '/' }}"><i class="bi bi-whatsapp"></i> WAHA</a>
    <div class="collapse navbar-collapse show">
      <ul class="navbar-nav me-auto">
        <li class="nav-item"><a class="nav-link" href="{{ app_root or '/' }}">Sessions</a></li>
        {% if role == 'admin' %}
        <li class="nav-item"><a class="nav-link" href="{{ app_root }}/users">Users</a></li>
        {% endif %}
      </ul>
      {% if username %}
      <span class="text-light-emphasis me-3"><i class="bi bi-person-circle"></i> {{ username }}</span>
      <a href="{{ app_root }}/logout" class="btn btn-outline-secondary btn-sm">Logout</a>
      {% endif %}
    </div>
  </div>
</nav>
<div class="container">
{% with msgs = get_flashed_messages(with_categories=true) %}
{% if msgs %}
<div class="toast-container position-fixed top-0 end-0 p-3">
{% for cat, msg in msgs %}
<div class="toast align-items-center text-bg-{{ 'danger' if cat=='danger' else 'success' if cat=='success' else 'warning' if cat=='warning' else 'info' }} border-0 show" role="alert">
<div class="d-flex"><div class="toast-body">{{ msg }}</div>
<button type="button" class="btn-close me-2 m-auto" data-bs-dismiss="toast"></button>
</div></div>
{% endfor %}
</div>
{% endif %}
{% endwith %}
{% block content %}{% endblock %}
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>document.querySelectorAll('.toast').forEach(t => setTimeout(() => t.remove(), 5000))</script>
</body>
</html>"""

LOGIN_TPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="row justify-content-center mt-5"><div class="col-md-4"><div class="card p-4">
<h4 class="text-center mb-4"><i class="bi bi-whatsapp"></i> WAHA Login</h4>
<form method="post" action="{{ app_root }}/login">
<div class="mb-3"><label class="form-label">Username</label><input name="username" class="form-control" required autofocus></div>
<div class="mb-3"><label class="form-label">Password</label><input name="password" type="password" class="form-control" required></div>
<button type="submit" class="btn btn-primary w-100">Login</button>
</form>
<p class="text-center mt-3 mb-0"><small><a href="{{ app_root }}/register">Register</a></small></p>
</div></div></div>
{% endblock %}""")

REGISTER_TPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="row justify-content-center mt-5"><div class="col-md-4"><div class="card p-4">
<h4 class="text-center mb-4">Register</h4>
<form method="post" action="{{ app_root }}/register">
<div class="mb-3"><label class="form-label">Username</label><input name="username" class="form-control" required autofocus></div>
<div class="mb-3"><label class="form-label">Password</label><input name="password" type="password" class="form-control" required></div>
<button type="submit" class="btn btn-primary w-100">Daftar</button>
</form>
<p class="text-center mt-3 mb-0"><small><a href="{{ app_root }}/login">Sudah punya akun? Login</a></small></p>
</div></div></div>
{% endblock %}""")

INDEX_TPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="d-flex justify-content-between align-items-center mb-3">
<h4 class="m-0"><i class="bi bi-phone"></i> Sessions</h4>
<button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#startModal"><i class="bi bi-plus-lg"></i> Start New</button>
</div>
<div class="row">
{% for s in sessions %}
<div class="col-md-6 col-lg-4 mb-3"><div class="card p-3 h-100">
<div class="d-flex justify-content-between align-items-start">
<div><h5 class="mb-1">{{ s.name }}</h5><small class="text-light-emphasis">{% if s.me %}{{ s.me }}{% else %}-{% endif %}</small></div>
<span class="badge {% if s.status == 'WORKING' %}bg-success{% elif s.status in ['STOPPED','FAILED'] %}bg-danger{% else %}bg-warning{% endif %}">{{ s.status }}</span>
</div><hr class="my-2 border-secondary"><div class="d-flex gap-2 flex-wrap">
{% if s.status == 'WORKING' %}
<form method="post" action="{{ app_root }}/session/stop" onsubmit="return confirm('Stop {{ s.name }}?')"><input type="hidden" name="name" value="{{ s.name }}"><button class="btn btn-outline-warning btn-sm"><i class="bi bi-stop-circle"></i> Stop</button></form>
<form method="post" action="{{ app_root }}/session/logout" onsubmit="return confirm('Logout {{ s.name }}?')"><input type="hidden" name="name" value="{{ s.name }}"><button class="btn btn-outline-danger btn-sm"><i class="bi bi-box-arrow-right"></i> Logout</button></form>
{% elif s.status == 'SCAN_QR_CODE' %}
<button class="btn btn-outline-info btn-sm qr-btn" data-name="{{ s.name }}"><i class="bi bi-qr-code"></i> QR</button>
{% elif s.status in ['STOPPED','FAILED'] %}
<form method="post" action="{{ app_root }}/session/start"><input type="hidden" name="name" value="{{ s.name }}"><button class="btn btn-outline-success btn-sm"><i class="bi bi-play-circle"></i> Start</button></form>
{% endif %}
</div></div></div>
{% else %}
<div class="col-12"><div class="card p-5 text-center"><i class="bi bi-inbox display-6"></i><p class="mt-2">Belum ada session. Klik <strong>Start New</strong>.</p></div></div>
{% endfor %}
</div>
<div class="modal fade" id="startModal" tabindex="-1"><div class="modal-dialog"><div class="modal-content" ><form method="post" action="{{ app_root }}/session/start">
<div class="modal-header border-secondary"><h5 class="modal-title">Start New Session</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
<div class="modal-body"><label class="form-label">Nama Session</label><input name="name" class="form-control" placeholder="misal: bisnis_1" required></div>
<div class="modal-footer border-secondary"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Batal</button><button type="submit" class="btn btn-primary">Start</button></div>
</form></div></div></div>
<div class="modal fade" id="qrModal" tabindex="-1"><div class="modal-dialog modal-sm"><div class="modal-content" >
<div class="modal-header border-secondary"><h5 class="modal-title">QR Code</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
<div class="modal-body text-center" id="qrBody"><div class="spinner-border"></div><p class="mt-2">Loading QR...</p></div>
</div></div></div>
<script>
const APP_ROOT = {{ app_root|tojson }};
const AUTO_QR = {{ auto_qr|tojson }};
const qrModalEl = document.getElementById('qrModal');
const qrBodyEl = document.getElementById('qrBody');
const qrModal = new bootstrap.Modal(qrModalEl);
let qrPollTimer = null;
let qrCountdownTimer = null;
let qrActiveName = '';
let qrCountdown = 0;
const CONNECT_SOUND = new Audio('data:audio/wav;base64,UklGRlYAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YTIAAAAAAAcPEBAPBwAA+Pj4AAcPEA8PBwAA+Pj4AAcPEA8PBwAA+Pj4AAcPEA8PBwAA+Pj4AA==');

function stopQrPolling() {
  if (qrPollTimer) clearTimeout(qrPollTimer);
  if (qrCountdownTimer) clearInterval(qrCountdownTimer);
  qrPollTimer = null;
  qrCountdownTimer = null;
}

function setQrBody(html) {
  qrBodyEl.innerHTML = html;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>\"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}

function updateCountdownLabel() {
  const el = document.getElementById('qrCountdown');
  if (el) el.textContent = `refresh lagi ${qrCountdown} detik`;
}

function startCountdown(seconds=3) {
  if (qrCountdownTimer) clearInterval(qrCountdownTimer);
  qrCountdown = seconds;
  updateCountdownLabel();
  qrCountdownTimer = setInterval(() => {
    qrCountdown = Math.max(qrCountdown - 1, 0);
    updateCountdownLabel();
  }, 1000);
}

function copyPairingCode(code) {
  navigator.clipboard.writeText(code).then(() => {
    showToast('Pairing code berhasil disalin', 'success');
  }).catch(() => {
    showToast('Gagal salin pairing code', 'danger');
  });
}

function playConnectedFx() {
  try {
    CONNECT_SOUND.currentTime = 0;
    CONNECT_SOUND.play().catch(() => {});
  } catch (e) {}
}

async function loadQr(name, firstLoad=false) {
  qrActiveName = name;
  if (firstLoad) setQrBody('<div class="spinner-border"></div><p class="mt-2">Loading QR...</p>');
  try {
    const r = await fetch(APP_ROOT + '/session/qr/' + encodeURIComponent(name), {cache: 'no-store'});
    const d = await r.json();
    if (d.qr) {
      setQrBody('<img src="' + d.qr + '" class="img-fluid" style="max-width:250px"><p class="mt-2 text-light-emphasis">Scan dengan WhatsApp</p><p class="mt-1 text-light-emphasis"><small id="qrCountdown">refresh lagi 3 detik</small></p>');
    } else if (d.code) {
      const safeCode = escapeHtml(d.code);
      setQrBody('<h2 class="fw-bold" style="letter-spacing:8px">' + safeCode + '</h2><p class="mt-2 text-light-emphasis">Masukkan kode di WhatsApp</p><div class="d-flex justify-content-center mt-2"><button type="button" class="btn btn-outline-primary btn-sm" id="copyPairCode"><i class="bi bi-copy"></i> Copy pairing code</button></div><p class="mt-2 text-light-emphasis"><small id="qrCountdown">refresh lagi 3 detik</small></p>');
      const copyBtn = document.getElementById('copyPairCode');
      if (copyBtn) copyBtn.addEventListener('click', () => copyPairingCode(d.code), {once: true});
    } else {
      setQrBody('<p class="text-warning">QR belum tersedia</p><p class="mt-1 text-light-emphasis"><small id="qrCountdown">refresh lagi 3 detik</small></p>');
    }
  } catch (e) {
    setQrBody('<p class="text-danger">Gagal load QR</p><p class="mt-1 text-light-emphasis"><small id="qrCountdown">refresh lagi 3 detik</small></p>');
  }

  if (!document.body.classList.contains('modal-open') || qrActiveName !== name) return;
  try {
    const rs = await fetch(APP_ROOT + '/session/status/' + encodeURIComponent(name), {cache: 'no-store'});
    const s = await rs.json();
    if (s.status === 'WORKING') {
      stopQrPolling();
      playConnectedFx();
      showToast(`Session ${name} connected`, 'success');
      setQrBody('<div class="text-center"><i class="bi bi-check-circle" style="font-size:48px;color:var(--success)"></i><p class="mt-2 fw-bold">Session connected</p><p class="text-light-emphasis">Halaman akan reload...</p></div>');
      setTimeout(() => window.location.href = APP_ROOT + '/', 1200);
      return;
    }
  } catch (e) {}

  stopQrPolling();
  startCountdown(3);
  qrPollTimer = setTimeout(() => loadQr(name), 3000);
}

document.querySelectorAll('.qr-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    qrModal.show();
    loadQr(btn.dataset.name, true);
  });
});
qrModalEl.addEventListener('hidden.bs.modal', () => {
  stopQrPolling();
  qrActiveName = '';
  setQrBody('<div class="spinner-border"></div><p class="mt-2">Loading QR...</p>');
});
if (AUTO_QR) {
  const btn = document.querySelector(`.qr-btn[data-name="${AUTO_QR}"]`);
  if (btn) setTimeout(() => btn.click(), 250);
}
</script>
{% endblock %}""")

USERS_TPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<h4><i class="bi bi-people"></i> Users</h4>
<div class="row g-3 mt-1">
  <div class="col-lg-5">
    <div class="card p-3">
      <h5 class="mb-3">Buat User</h5>
      <form method="post" action="{{ app_root }}/users/create">
        <div class="mb-3"><label class="form-label">Username</label><input name="username" class="form-control" required></div>
        <div class="mb-3"><label class="form-label">Password</label><div class="input-group"><input name="password" type="password" class="form-control password-input" required><button class="btn btn-outline-secondary toggle-password" type="button"><i class="bi bi-eye"></i></button></div></div>
        <div class="mb-3"><label class="form-label">Role</label><select name="role" class="form-select"><option value="user">user</option><option value="admin">admin</option></select></div>
        <button class="btn btn-primary w-100">Buat User</button>
      </form>
    </div>
    <div class="card p-3 mt-3">
      <h5 class="mb-3">Assign Session Lama</h5>
      <form method="post" action="{{ app_root }}/sessions/assign">
        <div class="mb-3"><label class="form-label">Session WAHA</label><select name="session_name" class="form-select" required>{% for name in session_names %}<option value="{{ name }}">{{ name }}</option>{% endfor %}</select></div>
        <div class="mb-3"><label class="form-label">Owner</label><select name="user_id" class="form-select" required>{% for u in users %}<option value="{{ u.id }}">{{ u.username }} ({{ u.role }})</option>{% endfor %}</select></div>
        <button class="btn btn-outline-info w-100">Assign</button>
      </form>
    </div>
  </div>
  <div class="col-lg-7">
    <div class="card p-0">
      <table class="table table-striped mb-0 align-middle">
        <thead><tr><th>ID</th><th>Username</th><th>Role</th><th style="width:1%">Aksi</th></tr></thead>
        <tbody>
        {% for u in users %}
        <tr>
          <td>{{ u.id }}</td>
          <td>{{ u.username }}</td>
          <td><span class="badge bg-{{ 'primary' if u.role=='admin' else 'secondary' }}">{{ u.role }}</span></td>
          <td>
            <div class="d-flex gap-2">
              <button class="btn btn-outline-primary btn-sm edit-user-btn"
                data-id="{{ u.id }}"
                data-username="{{ u.username }}"
                data-role="{{ u.role }}"
                data-bs-toggle="modal"
                data-bs-target="#editUserModal">Edit</button>
              {% if u.id != session.user_id %}
              <form method="post" action="{{ app_root }}/users/delete" onsubmit="return confirm('Hapus user {{ u.username }}?')">
                <input type="hidden" name="user_id" value="{{ u.id }}">
                <button class="btn btn-outline-danger btn-sm">Hapus</button>
              </form>
              {% endif %}
            </div>
          </td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
    <div class="card p-3 mt-3">
      <h5 class="mb-3">Mapping Session</h5>
      <div class="table-responsive">
        <table class="table table-striped mb-0">
          <thead><tr><th>Session</th><th>Owner</th></tr></thead>
          <tbody>
          {% for m in mapped %}
          <tr><td>{{ m.waha_session_name }}</td><td>{{ m.username }}</td></tr>
          {% else %}
          <tr><td colspan="2" class="text-center text-light-emphasis">Belum ada mapping</td></tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>
<div class="modal fade" id="editUserModal" tabindex="-1"><div class="modal-dialog"><div class="modal-content" >
<form method="post" action="{{ app_root }}/users/update">
  <div class="modal-header border-secondary"><h5 class="modal-title">Edit User</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
  <div class="modal-body">
    <input type="hidden" name="user_id" id="edit_user_id">
    <div class="mb-3"><label class="form-label">Username</label><input name="username" id="edit_username" class="form-control" required></div>
    <div class="mb-3"><label class="form-label">Role</label><select name="role" id="edit_role" class="form-select"><option value="user">user</option><option value="admin">admin</option></select></div>
    <div class="mb-0"><label class="form-label">Password Baru</label><div class="input-group"><input name="password" type="password" class="form-control password-input" placeholder="kosong = tetap"><button class="btn btn-outline-secondary toggle-password" type="button"><i class="bi bi-eye"></i></button></div></div>
  </div>
  <div class="modal-footer border-secondary"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Batal</button><button class="btn btn-primary">Simpan</button></div>
</form>
</div></div></div>
<script>
document.querySelectorAll('.edit-user-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.getElementById('edit_user_id').value = btn.dataset.id;
    document.getElementById('edit_username').value = btn.dataset.username;
    document.getElementById('edit_role').value = btn.dataset.role;
    const pwd = document.querySelector('#editUserModal .password-input');
    if (pwd) pwd.value = '';
  });
});
document.querySelectorAll('.toggle-password').forEach(btn => {
  btn.addEventListener('click', () => {
    const input = btn.closest('.input-group').querySelector('.password-input');
    const icon = btn.querySelector('i');
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    icon.className = show ? 'bi bi-eye-slash' : 'bi bi-eye';
  });
});
</script>
{% endblock %}""")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=False)
