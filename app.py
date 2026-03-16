import os
import uuid
import sqlite3
from datetime import timedelta

from flask import session, Flask, render_template, request, redirect, url_for, flash, send_file, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# Project-specific imports
from config import Config
from db import get_db, close_db, query_one, query_all, execute
from security_utils import ensure_dirs, allowed_file, safe_name, new_csrf_token, validate_csrf, admin_required
from crypto_utils import encrypt_bytes, decrypt_bytes
from scan_utils import sha256_bytes, vt_check_hash, calculate_vt_risk, yara_scan_stub

app = Flask(__name__)

# Session and security settings
app.config.update(
    SESSION_PERMANENT=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

app.config["SECRET_KEY"] = Config.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = Config.MAX_CONTENT_LENGTH
app.permanent_session_lifetime = timedelta(minutes=15)

# Ensure necessary directories exist
ensure_dirs()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# --- AUTOMATIC SQLITE DATABASE CREATION ---
def init_sqlite_db():
    db_path = "database.db"
    if not os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            original_name TEXT,
            stored_name TEXT,
            sha256 TEXT,
            size_bytes INTEGER,
            mime_type TEXT,
            vt_status TEXT,
            vt_risk TEXT DEFAULT 'UNKNOWN',
            vt_malicious INTEGER DEFAULT 0,
            vt_suspicious INTEGER DEFAULT 0,
            vt_undetected INTEGER DEFAULT 0,
            vt_harmless INTEGER DEFAULT 0,
            vt_timeout INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            details TEXT,
            ip TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.commit()
        conn.close()

class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]
        self.email = row["email"]
        self.password_hash = row["password_hash"]
        try:
            self.role = row["role"]
        except:
            self.role = "user"

    def is_admin(self):
        return self.role == "admin"

@login_manager.user_loader
def load_user(user_id):
    row = query_one("SELECT * FROM users WHERE id=%s", (user_id,))
    return User(row) if row else None

@app.teardown_appcontext
def teardown_db(exception):
    close_db(exception)

def audit(action: str, details: str = ""):
    uid = current_user.id if current_user.is_authenticated else None
    ip = request.remote_addr
    ua = request.headers.get("User-Agent", "")
    execute(
        "INSERT INTO audit_logs (user_id, action, details, ip, user_agent) VALUES (%s,%s,%s,%s,%s)",
        (uid, action, details[:500], ip, ua[:255])
    )

# --- ROUTES ---

@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    csrf = new_csrf_token() if request.method == "GET" else None
    if request.method == "POST":
        if not validate_csrf(request.form.get("csrf_token", "")): abort(400)
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if len(username) < 3 or len(password) < 6 or "@" not in email:
            flash("Invalid data.", "danger")
            return redirect(url_for("register"))
        if query_one("SELECT id FROM users WHERE username=%s OR email=%s", (username, email)):
            flash("User already exists.", "warning")
            return redirect(url_for("register"))
        execute("INSERT INTO users (username, email, password_hash) VALUES (%s,%s,%s)", (username, email, generate_password_hash(password)))
        audit("register", f"username={username}")
        flash("Registration successful.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", csrf_token=csrf)

@app.route("/login", methods=["GET", "POST"])
def login():
    csrf = new_csrf_token() if request.method == "GET" else None
    if request.method == "POST":
        if not validate_csrf(request.form.get("csrf_token", "")): abort(400)
        row = query_one("SELECT * FROM users WHERE username=%s", (request.form.get("username", ""),))
        if not row or not check_password_hash(row["password_hash"], request.form.get("password", "")):
            flash("Username or password is incorrect.", "danger")
            return redirect(url_for("login"))
        user = User(row)
        login_user(user)
        audit("login_success", f"user_id={user.id}")
        return redirect(url_for("dashboard"))
    return render_template("login.html", csrf_token=csrf)

@app.route("/logout")
@login_required
def logout():
    audit("logout", f"user_id={current_user.id}")
    logout_user()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    files = query_all("SELECT * FROM files WHERE user_id=%s ORDER BY created_at DESC", (current_user.id,))
    return render_template("dashboard.html", files=files)

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    csrf = new_csrf_token() if request.method == "GET" else None
    if request.method == "POST":
        if not validate_csrf(request.form.get("csrf_token", "")): abort(400)
        f = request.files.get("file")
        password = request.form.get("enc_password", "")
        if not f or len(password) < 6:
            flash("File and minimum 6-character password are required.", "warning")
            return redirect(url_for("upload"))
        orig = safe_name(f.filename)
        data = f.read()
        sha = sha256_bytes(data)
        vt = vt_check_hash(sha, Config.VT_API_KEY)
        stats = vt.get("stats") or {}
        vt_risk = calculate_vt_risk(vt["status"], stats)
        if vt_risk == "HIGH":
            audit("upload_blocked", f"sha256={sha}")
            flash("Malicious file blocked!", "danger")
            return redirect(url_for("upload"))
        stored_name = f"{uuid.uuid4().hex}.bin"
        with open(os.path.join(Config.STORAGE_ENC, stored_name), "wb") as out:
            out.write(encrypt_bytes(data, password))
        execute("INSERT INTO files (user_id, original_name, stored_name, sha256, size_bytes, mime_type, vt_status, vt_risk, vt_malicious) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (current_user.id, orig, stored_name, sha, len(data), f.mimetype, vt["status"], vt_risk, int(stats.get("malicious", 0))))
        flash("File uploaded successfully.", "success")
        return redirect(url_for("dashboard"))
    return render_template("upload.html", csrf_token=csrf)

@app.route("/file/<int:file_id>")
@login_required
def file_view(file_id):
    row = query_one("SELECT * FROM files WHERE id=%s AND user_id=%s", (file_id, current_user.id))
    if not row: abort(404)
    return render_template("file_view.html", file=row)

@app.route("/file/<int:file_id>/download", methods=["POST"])
@login_required
def file_download(file_id):
    if not validate_csrf(request.form.get("csrf_token", "")): abort(400)
    row = query_one("SELECT * FROM files WHERE id=%s AND user_id=%s", (file_id, current_user.id))
    try:
        with open(os.path.join(Config.STORAGE_ENC, row["stored_name"]), "rb") as f:
            plain = decrypt_bytes(f.read(), request.form.get("dec_password", ""))
        tmp_path = os.path.join(Config.STORAGE_TMP, f"{uuid.uuid4().hex}_{row['original_name']}")
        with open(tmp_path, "wb") as out: out.write(plain)
        return send_file(tmp_path, as_attachment=True, download_name=row["original_name"])
    except:
        flash("Incorrect password.", "danger")
        return redirect(url_for("file_view", file_id=file_id))

@app.route("/file/<int:file_id>/delete", methods=["POST"])
@login_required
def file_delete(file_id):
    if not validate_csrf(request.form.get("csrf_token", "")): abort(400)
    row = query_one("SELECT * FROM files WHERE id=%s AND user_id=%s", (file_id, current_user.id))
    if row:
        try: os.remove(os.path.join(Config.STORAGE_ENC, row["stored_name"]))
        except: pass
        execute("DELETE FROM files WHERE id=%s", (file_id,))
        flash("File deleted.", "info")
    return redirect(url_for("dashboard"))

@app.route("/logs")
@login_required
def logs():
    rows = query_all("SELECT * FROM audit_logs WHERE user_id=%s ORDER BY created_at DESC LIMIT 100", (current_user.id,))
    return render_template("logs.html", logs=rows)

@app.route("/delete_log/<int:log_id>", methods=["POST"])
@login_required
def delete_log(log_id):
    if current_user.role != 'admin':
        return "İcazə yoxdur", 403
        
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM audit_logs WHERE id = ?", (log_id,))
    conn.commit()
    conn.close()
    
    return redirect(url_for("admin_logs"))


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash("Access Denied!", "danger")
        return redirect(url_for("index"))

    if current_user.id == user_id:
        flash("You cannot delete your own admin account!", "warning")
        return redirect(url_for("admin_users"))

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    
    conn.commit()
    conn.close()
    
    flash("User deleted successfully.", "success")
    return redirect(url_for("admin_users"))

# --- ADMIN ROUTES ---
@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    # Bütün istifadəçiləri bazadan çəkirik
    rows = query_all("SELECT id, username, email, role FROM users ORDER BY id DESC")
    return render_template("admin_users.html", users=rows)

@app.route("/admin/files")
@login_required
@admin_required
def admin_files():
    rows = query_all("SELECT files.*, users.username FROM files JOIN users ON files.user_id = users.id ORDER BY files.created_at DESC")
    return render_template("admin_files.html", files=rows)

@app.route("/admin/logs")
@login_required
@admin_required
def admin_logs():
    rows = query_all("SELECT audit_logs.*, users.username FROM audit_logs LEFT JOIN users ON audit_logs.user_id = users.id ORDER BY created_at DESC LIMIT 500")
    return render_template("admin_logs.html", logs=rows)

@app.route("/admin/cti")
@login_required
@admin_required
def admin_cti():
    risk_rows = query_all("SELECT vt_risk, COUNT(*) AS count FROM files GROUP BY vt_risk")
    risks = {"LOW": 0, "UNKNOWN": 0, "MEDIUM": 0, "HIGH": 0}
    for r in risk_rows:
        if r["vt_risk"] in risks: risks[r["vt_risk"]] = r["count"]
    blocked_row = query_one("SELECT COUNT(*) AS count FROM audit_logs WHERE action LIKE 'upload_blocked%'")
    return render_template("admin_cti.html", risks=risks, blocked_count=blocked_row["count"] if blocked_row else 0)

if __name__ == "__main__":
    init_sqlite_db()
    app.run(host="127.0.0.1", port=5000, debug=True)