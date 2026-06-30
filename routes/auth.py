import sqlite3

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from db import get_db, hash_password, verify_password

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
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
                return render_template("login.html", username=session.get("username"), role=session.get("role"))
            if needs_upgrade:
                db.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(raw_password), row["id"]))
                db.commit()
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]
            flash("Login berhasil", "success")
            return redirect(url_for("dashboard.index"))
        flash("Username atau password salah", "danger")
    return render_template("login.html", username=session.get("username"), role=session.get("role"))


@bp.route("/logout")
def logout():
    session.clear()
    flash("Logout berhasil", "info")
    return redirect(url_for("auth.login"))


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form["username"].strip()
        p = request.form["password"]
        if not u or not p:
            flash("Username dan password wajib diisi", "danger")
            return render_template("register.html", username=session.get("username"), role=session.get("role"))
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password_hash) VALUES (?,?)", (u, hash_password(p)))
            db.commit()
            flash("Registrasi berhasil, silakan login", "success")
            return redirect(url_for("auth.login"))
        except sqlite3.IntegrityError:
            flash("Username sudah dipakai", "danger")
    return render_template("register.html", username=session.get("username"), role=session.get("role"))
