import json
import sqlite3

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from db import get_db, hash_password
from helpers import admin_required, waha

bp = Blueprint("admin", __name__)


@bp.route("/users")
@admin_required
def users_list():
    db = get_db()
    rows = db.execute("SELECT id, username, role, avatar_path FROM users ORDER BY id").fetchall()
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
    return render_template(
        "users.html",
        username=session.get("username"),
        role=session.get("role"),
        users=rows,
        mapped=mapped,
        session_names=session_names,
    )


@bp.route("/users/create", methods=["POST"])
@admin_required
def users_create():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "user")
    if not username or not password:
        flash("Username dan password wajib diisi", "danger")
        return redirect(url_for("admin.users_list"))
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
    return redirect(url_for("admin.users_list"))


@bp.route("/users/update", methods=["POST"])
@admin_required
def users_update():
    user_id = request.form.get("user_id", type=int)
    username = request.form.get("username", "").strip()
    role = request.form.get("role", "user")
    password = request.form.get("password", "")
    if not user_id or not username:
        flash("User tidak valid", "danger")
        return redirect(url_for("admin.users_list"))
    if role not in {"admin", "user"}:
        role = "user"
    db = get_db()
    row = db.execute("SELECT id, username FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        flash("User tidak ditemukan", "danger")
        return redirect(url_for("admin.users_list"))
    try:
        if password:
            db.execute(
                "UPDATE users SET username=?, role=?, password_hash=? WHERE id=?",
                (username, role, hash_password(password), user_id),
            )
        else:
            db.execute("UPDATE users SET username=?, role=? WHERE id=?", (username, role, user_id))
        db.commit()
        if user_id == session.get("user_id"):
            session["username"] = username
            session["role"] = role
        flash(f"User '{row['username']}' diupdate", "success")
    except sqlite3.IntegrityError:
        flash("Username sudah dipakai", "danger")
    return redirect(url_for("admin.users_list"))


@bp.route("/users/delete", methods=["POST"])
@admin_required
def users_delete():
    user_id = request.form.get("user_id", type=int)
    if not user_id:
        flash("User tidak valid", "danger")
        return redirect(url_for("admin.users_list"))
    if user_id == session.get("user_id"):
        flash("Tidak bisa hapus user login sendiri", "danger")
        return redirect(url_for("admin.users_list"))
    db = get_db()
    row = db.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        flash("User tidak ditemukan", "danger")
        return redirect(url_for("admin.users_list"))
    db.execute("DELETE FROM sessions_map WHERE user_id=?", (user_id,))
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    flash(f"User '{row['username']}' dihapus", "info")
    return redirect(url_for("admin.users_list"))


@bp.route("/sessions/assign", methods=["POST"])
@admin_required
def sessions_assign():
    user_id = request.form.get("user_id", type=int)
    session_name = request.form.get("session_name", "").strip()
    if not user_id or not session_name:
        flash("User dan session wajib dipilih", "danger")
        return redirect(url_for("admin.users_list"))
    row = get_db().execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        flash("User tidak ditemukan", "danger")
        return redirect(url_for("admin.users_list"))
    get_db().execute("DELETE FROM sessions_map WHERE waha_session_name=?", (session_name,))
    get_db().execute("INSERT INTO sessions_map (user_id, waha_session_name) VALUES (?,?)", (user_id, session_name))
    get_db().commit()
    flash(f"Session '{session_name}' di-assign ke '{row['username']}'", "success")
    return redirect(url_for("admin.users_list"))
