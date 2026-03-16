import os
import secrets
from werkzeug.utils import secure_filename
from flask import session
from config import Config
from functools import wraps
from flask import abort
from flask_login import current_user

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            abort(403)
        return func(*args, **kwargs)
    return wrapper


def ensure_dirs():
    os.makedirs(Config.STORAGE_ENC, exist_ok=True)
    os.makedirs(Config.STORAGE_TMP, exist_ok=True)

def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in Config.ALLOWED_EXTENSIONS

def safe_name(filename: str) -> str:
    
    return secure_filename(filename)

def new_csrf_token() -> str:
    token = secrets.token_urlsafe(32)
    session["csrf_token"] = token
    return token

def validate_csrf(token: str) -> bool:
    return bool(token) and token == session.get("csrf_token")
