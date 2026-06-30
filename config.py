import os
import secrets

BASE_DIR = os.path.dirname(__file__)
WAHA_URL = os.environ.get("WAHA_URL", "http://127.0.0.1:3001")
WAHA_API_KEY = os.environ.get("WAHA_API_KEY", "")
DB = os.path.join(BASE_DIR, "waha_users.db")
SECRET_KEY = os.environ.get("WAHA_DASH_SECRET") or secrets.token_hex(32)
PORT = int(os.environ.get("PORT", "8084"))
ADMIN_USERNAME = os.environ.get("WAHA_DASH_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("WAHA_DASH_ADMIN_PASSWORD", "")
APP_ROOT = os.environ.get("APP_ROOT", "")
AVATAR_DIR = os.path.join(BASE_DIR, "static", "uploads", "avatars")
os.makedirs(AVATAR_DIR, exist_ok=True)
