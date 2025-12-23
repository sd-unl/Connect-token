import os
import secrets
import hmac
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text
import requests as http_requests

# Google Auth imports for ID Token verification
from google.oauth2 import id_token
from google.auth.transport import requests as google_auth_requests

app = Flask(__name__)

# --- CONFIGURATION ---
# Replace this with the ID of your ZIP file on Google Drive
# Example Link: https://drive.google.com/file/d/1Nyxu_mJYZ2hUZWy_YjaI3dvR7v2RJ3jc/view
# The ID is: 1Nyxu_mJYZ2hUZWy_YjaI3dvR7v2RJ3jc
GDRIVE_ID = os.environ.get("GDRIVE_ID", "PASTE_YOUR_GDRIVE_ID_HERE")

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
SESSION_SECRET = os.environ.get("SESSION_SECRET", "change-this-to-a-random-string-in-production")
DB_URL = os.environ.get("DATABASE_URL")

# --- DATABASE CONNECTION ---
if DB_URL:
    # Fix for Render/Heroku postgres naming
    if DB_URL.startswith("postgres://"):
        DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
    engine = create_engine(DB_URL)
else:
    print("⚠️ WARNING: DATABASE_URL not set. Using temporary local SQLite.")
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
            CREATE TABLE IF NOT EXISTS active_sessions (
                user_email TEXT PRIMARY KEY,
                expires_at TIMESTAMP
            );
        """))
        conn.commit()

# Initialize tables on startup
with app.app_context():
    init_db()

# --- HELPER FUNCTIONS ---

def generate_session_token(email, hours):
    """Generate a signed session token for .so module verification."""
    expiry = datetime.now() + timedelta(hours=hours)
    expiry_str = expiry.isoformat()
    message = f"{email}:{expiry_str}"
    signature = hmac.new(
        SESSION_SECRET.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()[:16]
    return f"{email}:{expiry_str}:{signature}"

def verify_google_token(token, token_type="access_token"):
    """Verifies Google token and returns user email."""
    if token_type == "id_token":
        try:
            # Cryptographic verification of ID Token
            idinfo = id_token.verify_oauth2_token(
                token, 
                google_auth_requests.Request(), 
                GOOGLE_CLIENT_ID
            )
            if not idinfo.get('email_verified', False):
                return None, "Email not verified by Google"
            return idinfo.get('email'), None
        except Exception as e:
            return None, str(e)
    else:
        # Simple API verification of Access Token
        try:
            response = http_requests.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10
            )
            if response.status_code != 200:
                return None, "Invalid access token"
            user_info = response.json()
            return user_info.get('email'), None
        except Exception as e:
            return None, str(e)

# --- ROUTES ---

@app.route('/')
def home():
    return "License Server Online. Google Drive ID Dispatcher Active."

@app.route('/api/authorize', methods=['POST'])
def authorize():
    """
    Main authorization endpoint.
    If authorized, returns the Google Drive File ID for module download.
    """
    data = request.json or {}
    google_token = data.get('google_token')
    token_type = data.get('token_type', 'access_token')
    provided_key = data.get('key')

    if not google_token:
        return jsonify({"authorized": False, "error": "Google token required"}), 400

    # 1. Verify Google Identity
    email, error = verify_google_token(google_token, token_type)
    if error:
        return jsonify({"authorized": False, "error": f"Google auth failed: {error}"}), 403

    with engine.connect() as conn:
        # 2. Check for existing active session in DB
        session = conn.execute(
            text("SELECT expires_at FROM active_sessions WHERE user_email = :e"),
            {"e": email}
        ).fetchone()

        if session:
            expires_at = session[0]
            # Handle string or datetime object depending on DB type
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
            
            if datetime.now() < expires_at:
                remaining = (expires_at - datetime.now()).total_seconds() / 3600
                return jsonify({
                    "authorized": True,
                    "email": email,
                    "hours_remaining": round(remaining, 2),
                    "gdrive_id": GDRIVE_ID,  # <--- ACCESS GRANTED
                    "session_token": generate_session_token(email, remaining)
                })
            else:
                # Session expired, remove it
                conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
                conn.commit()

        # 3. If no session, check for License Key
        if not provided_key:
            return jsonify({
                "authorized": False, 
                "needs_key": True, 
                "error": "Active license required. New user or session expired."
            }), 401

        row = conn.execute(
            text("SELECT status, duration_hours FROM licenses WHERE key_code = :k"),
            {"k": provided_key}
        ).fetchone()

        if not row:
            return jsonify({"authorized": False, "error": "Invalid license key"}), 403
        
        status, duration = row
        if status == 'used':
            return jsonify({"authorized": False, "error": "Key already used"}), 403

        # 4. Activate License & Create Session
        new_expiry = datetime.now() + timedelta(hours=duration)
        conn.execute(text("UPDATE licenses SET status = 'used' WHERE key_code = :k"), {"k": provided_key})
        conn.execute(
            text("INSERT INTO active_sessions (user_email, expires_at) VALUES (:e, :t)"), 
            {"e": email, "t": new_expiry}
        )
        conn.commit()

        return jsonify({
            "authorized": True,
            "message": f"Activated for {duration} hours",
            "email": email,
            "hours_remaining": duration,
            "gdrive_id": GDRIVE_ID, # <--- ACCESS GRANTED
            "session_token": generate_session_token(email, duration)
        })

# --- ADMIN ROUTES ---

@app.route('/admin')
def admin_ui():
    """Simple UI to generate license keys"""
    return """
    <html><body style="font-family:sans-serif; text-align:center; padding-top: 50px;">
        <h1>🔑 License Generator</h1>
        <p>Current GDrive ID: <code>""" + GDRIVE_ID + """</code></p>
        <input type="number" id="hr" value="24" style="padding: 10px;"> hours<br><br>
        <button onclick="gen()" style="padding: 10px 20px; cursor: pointer;">Generate Key</button>
        <h2 id="res" style="color: green; font-family: monospace;"></h2>
        <script>
            async function gen() {
                const res = await fetch('/admin/create', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({duration: parseInt(document.getElementById('hr').value)})
                });
                const d = await res.json();
                document.getElementById('res').innerText = d.key;
            }
        </script>
    </body></html>
    """

@app.route('/admin/create', methods=['POST'])
def create_key():
    """Admin API to create a new key"""
    data = request.json or {}
    key = secrets.token_hex(8)
    duration = data.get('duration', 24)
    with engine.connect() as conn:
        conn.execute(
            text("INSERT INTO licenses (key_code, duration_hours) VALUES (:k, :d)"), 
            {"k": key, "d": duration}
        )
        conn.commit()
    return jsonify({"key": key, "duration": duration})

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "database": "connected"})

if __name__ == '__main__':
    # Listen on port 10000 for Render
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
