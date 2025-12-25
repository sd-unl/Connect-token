import os
import secrets
import hmac
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text

# --- FIXED IMPORTS ---
# 1. Standard requests library for HTTP calls (like getting userinfo)
import requests as http_requests
# 2. Google Auth specific requests for the Request class (for ID tokens)
from google.oauth2 import id_token
from google.auth.transport import requests as google_auth_requests

app = Flask(__name__)

# --- CONFIGURATION ---
DEFAULT_GDRIVE_ID = os.environ.get("GDRIVE_ID", "PASTE_YOUR_GDRIVE_ID_HERE")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
SESSION_SECRET = os.environ.get("SESSION_SECRET", "change-this-secret-now")
DB_URL = os.environ.get("DATABASE_URL")

# --- DATABASE CONNECTION ---
if DB_URL:
    if DB_URL.startswith("postgres://"):
        DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
    engine = create_engine(DB_URL)
else:
    print("⚠️ WARNING: DATABASE_URL not set. Using local SQLite.")
    engine = create_engine("sqlite:///temp.db")

# --- DATABASE INITIALIZATION ---
def init_db():
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS licenses (
                key_code TEXT PRIMARY KEY,
                status TEXT DEFAULT 'unused',
                duration_hours INT DEFAULT 24
            );
        """))
        
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS file_registry (
                id SERIAL PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                gdrive_id TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """))
        
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS active_sessions (
                user_email TEXT PRIMARY KEY,
                expires_at TIMESTAMP
            );
        """))
        conn.commit()

with app.app_context():
    init_db()

# --- HELPER FUNCTIONS ---

def generate_session_token(email, hours):
    expiry = datetime.now() + timedelta(hours=hours)
    expiry_str = expiry.isoformat()
    message = f"{email}:{expiry_str}"
    signature = hmac.new(
        SESSION_SECRET.encode(), message.encode(), hashlib.sha256
    ).hexdigest()[:16]
    return f"{email}:{expiry_str}:{signature}"

def verify_google_token(token, token_type="access_token"):
    """Verifies Google token and returns user email."""
    if token_type == "id_token":
        try:
            idinfo = id_token.verify_oauth2_token(
                token, google_auth_requests.Request(), GOOGLE_CLIENT_ID
            )
            if not idinfo.get('email_verified', False): return None, "Email not verified"
            return idinfo.get('email'), None
        except Exception as e: return None, str(e)
    else:
        # FIX: Use the standard 'http_requests' library, not google_auth_requests
        try:
            response = http_requests.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {token}"}, timeout=10
            )
            if response.status_code != 200: return None, "Invalid token"
            return response.json().get('email'), None
        except Exception as e: return None, str(e)

# --- ROUTES ---

@app.route('/')
def home():
    return "License Server v2 (Fixed). Multi-File Support Active."

@app.route('/api/authorize', methods=['POST'])
def authorize():
    data = request.json or {}
    google_token = data.get('google_token')
    token_type = data.get('token_type', 'access_token')
    provided_key = data.get('key')
    requested_file = data.get('requested_file')

    if not google_token:
        return jsonify({"authorized": False, "error": "Google token required"}), 400

    # 1. Verify Identity
    email, error = verify_google_token(google_token, token_type)
    if error:
        return jsonify({"authorized": False, "error": f"Google auth failed: {error}"}), 403

    gdrive_id_to_return = None

    with engine.connect() as conn:
        # 2. Check Session
        session = conn.execute(
            text("SELECT expires_at FROM active_sessions WHERE user_email = :e"), {"e": email}
        ).fetchone()

        if session:
            expires_at = session[0]
            if isinstance(expires_at, str): expires_at = datetime.fromisoformat(expires_at)
            
            if datetime.now() < expires_at:
                remaining = (expires_at - datetime.now()).total_seconds() / 3600
                
                # 3. GET THE REQUESTED FILE ID
                if requested_file:
                    file_row = conn.execute(
                        text("SELECT gdrive_id FROM file_registry WHERE name = :n"), 
                        {"n": requested_file}
                    ).fetchone()
                    if file_row:
                        gdrive_id_to_return = file_row[0]
                    else:
                        return jsonify({"authorized": False, "error": f"File '{requested_file}' not found on server."}), 404
                else:
                    row = conn.execute(text("SELECT gdrive_id FROM file_registry LIMIT 1")).fetchone()
                    gdrive_id_to_return = row[0] if row else DEFAULT_GDRIVE_ID

                return jsonify({
                    "authorized": True, "email": email, "hours_remaining": round(remaining, 2),
                    "gdrive_id": gdrive_id_to_return,
                    "session_token": generate_session_token(email, remaining)
                })
            else:
                conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
                conn.commit()

        # 4. Check License Key
        if not provided_key:
            return jsonify({"authorized": False, "needs_key": True, "error": "Active license required."}), 401

        row = conn.execute(
            text("SELECT status, duration_hours FROM licenses WHERE key_code = :k"), {"k": provided_key}
        ).fetchone()

        if not row: return jsonify({"authorized": False, "error": "Invalid license key"}), 403
        if row[0] == 'used': return jsonify({"authorized": False, "error": "Key already used"}), 403

        # 5. Activate & Determine File
        new_expiry = datetime.now() + timedelta(hours=row[1])
        conn.execute(text("UPDATE licenses SET status = 'used' WHERE key_code = :k"), {"k": provided_key})
        conn.execute(text("INSERT INTO active_sessions (user_email, expires_at) VALUES (:e, :t)"), {"e": email, "t": new_expiry})
        conn.commit()

        if requested_file:
            file_row = conn.execute(text("SELECT gdrive_id FROM file_registry WHERE name = :n"), {"n": requested_file}).fetchone()
            gdrive_id_to_return = file_row[0] if file_row else DEFAULT_GDRIVE_ID
        else:
            row = conn.execute(text("SELECT gdrive_id FROM file_registry LIMIT 1")).fetchone()
            gdrive_id_to_return = row[0] if row else DEFAULT_GDRIVE_ID

        return jsonify({
            "authorized": True, "message": f"Activated for {row[1]} hours",
            "email": email, "hours_remaining": row[1],
            "gdrive_id": gdrive_id_to_return,
            "session_token": generate_session_token(email, row[1])
        })

# --- ADMIN ROUTES ---

@app.route('/admin')
def admin_ui():
    return """
    <html><body style="font-family:sans-serif; padding: 20px; max-width: 800px; margin: auto;">
        <h1>🛠️ Admin Dashboard</h1>
        
        <div style="background:#f4f4f4; padding:15px; border-radius:8px; margin-bottom:20px;">
            <h2>📂 Manage Files</h2>
            <input type="text" id="fname" placeholder="File Name (e.g., app_v1)" style="width: 200px; padding: 5px;">
            <input type="text" id="fid" placeholder="GDrive ID (e.g., 1H7I5...)" style="width: 300px; padding: 5px;">
            <button onclick="addFile()" style="padding: 5px 15px;">Add File</button>
            <div id="fileList" style="margin-top:10px; font-family:monospace; font-size:12px;"></div>
        </div>

        <div style="background:#eef; padding:15px; border-radius:8px;">
            <h2>🔑 License Generator</h2>
            <input type="number" id="hr" value="24" style="padding: 10px;"> hours<br><br>
            <button onclick="genKey()" style="padding: 10px 20px;">Generate Key</button>
            <h2 id="res" style="color: green; font-family: monospace;"></h2>
        </div>

        <script>
            loadFiles();
            async function loadFiles() {
                const res = await fetch('/admin/get_files');
                const data = await res.json();
                const list = data.files;
                let html = '<strong>Registered Files:</strong><ul>';
                list.forEach(f => { html += `<li><b>${f.name}</b>: ${f.gdrive_id}</li>`; });
                html += '</ul>';
                document.getElementById('fileList').innerHTML = html;
            }
            async function addFile() {
                const name = document.getElementById('fname').value;
                const id = document.getElementById('fid').value;
                if(!name || !id) return alert("Fill both fields");
                await fetch('/admin/add_file', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({name: name, gdrive_id: id}) });
                document.getElementById('fname').value = ''; document.getElementById('fid').value = '';
                loadFiles();
            }
            async function genKey() {
                const res = await fetch('/admin/create', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({duration: parseInt(document.getElementById('hr').value)}) });
                const d = await res.json();
                document.getElementById('res').innerText = d.key;
            }
        </script>
    </body></html>
    """

@app.route('/admin/get_files', methods=['GET'])
def get_files():
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT name, gdrive_id FROM file_registry ORDER BY id DESC")).fetchall()
        files = [{"name": r[0], "gdrive_id": r[1]} for r in rows]
        return jsonify({"files": files})

@app.route('/admin/add_file', methods=['POST'])
def add_file():
    data = request.json
    try:
        with engine.connect() as conn:
            conn.execute(text("INSERT INTO file_registry (name, gdrive_id) VALUES (:n, :g)"), {"n": data.get('name'), "g": data.get('gdrive_id')})
            conn.commit()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/admin/create', methods=['POST'])
def create_key():
    data = request.json or {}
    key = secrets.token_hex(8)
    duration = data.get('duration', 24)
    with engine.connect() as conn:
        conn.execute(text("INSERT INTO licenses (key_code, duration_hours) VALUES (:k, :d)"), {"k": key, "d": duration})
        conn.commit()
    return jsonify({"key": key, "duration": duration})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
