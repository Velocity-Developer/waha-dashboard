import asyncio
from functools import wraps

import httpx
from flask import flash, redirect, session, url_for

from config import WAHA_API_KEY, WAHA_URL
from db import get_db


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


def login_required(f):
    @wraps(f)
    def dec(*a, **kw):
        if "user_id" not in session:
            flash("Silakan login dulu", "warning")
            return redirect(url_for("auth.login"))
        return f(*a, **kw)

    return dec


def admin_required(f):
    @wraps(f)
    @login_required
    def dec(*a, **kw):
        u = get_db().execute("SELECT role FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not u or u["role"] != "admin":
            flash("Akses ditolak", "danger")
            return redirect(url_for("dashboard.index"))
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
