import os
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text
import requests as http_requests

# Google Auth imports for ID Token verification
from google.oauth2 import id_token
from google.auth.transport import requests as google_auth_requests

app = Flask(__name__)

# --- DATABASE CONNECTION ---
DB_URL = os.environ.get("DATABASE_URL")

if DB_URL:
    if DB_URL.startswith("postgres://"):
        DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
    engine = create_engine(DB_URL)
else:
    print("⚠️ WARNING: DATABASE_URL not set. Using temporary local SQLite.")
    engine = create_engine("sqlite:///temp.db")

# --- OPTIONAL: Set your Google Client ID for stricter verification ---
# If you have a GCP project, set this. Otherwise, leave as None for general verification.
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)

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

init_db()

def verify_google_token(token, token_type="access_token"):
    """
    Verifies a Google token and returns the user's email.
    
    Supports two verification methods:
    1. access_token: Verifies via Google's userinfo API
    2. id_token: Cryptographic verification (more secure)
    
    Returns: (email, error_message)
    """
    
    if token_type == "id_token":
        # Method 1: Cryptographic ID Token Verification (Preferred)
        try:
            # Verify the ID token
            idinfo = id_token.verify_oauth2_token(
                token,
                google_auth_requests.Request(),
                GOOGLE_CLIENT_ID  # Can be None for general verification
            )
            
            # Check if email is verified
            if not idinfo.get('email_verified', False):
                return None, "Email not verified by Google"
            
            email = idinfo.get('email')
            if not email:
                return None, "No email in token"
                
            return email, None
            
        except ValueError as e:
            return None, f"Invalid ID token: {str(e)}"
        except Exception as e:
            return None, f"Token verification failed: {str(e)}"
    
    else:
        # Method 2: Access Token Verification via Google API
        try:
            # Verify access token with Google's userinfo endpoint
            response = http_requests.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10
            )
            
            if response.status_code != 200:
                # Try tokeninfo as fallback
                response = http_requests.get(
                    f"https://oauth2.googleapis.com/tokeninfo?access_token={token}",
                    timeout=10
                )
                if response.status_code != 200:
                    return None, "Invalid access token"
            
            user_info = response.json()
            email = user_info.get('email')
            
            if not email:
                return None, "Could not retrieve email from token"
            
            # Optional: Check if email is verified
            if user_info.get('verified_email') == False:
                return None, "Email not verified"
                
            return email, None
            
        except http_requests.RequestException as e:
            return None, f"Network error during verification: {str(e)}"
        except Exception as e:
            return None, f"Token verification failed: {str(e)}"


@app.route('/')
def home():
    return "License Server is Online. (Google Token Verification Enabled)"

# --- ADMIN PANEL ---
@app.route('/admin')
def admin_ui():
    return """
    <!DOCTYPE html>
    <html>
    <body style="font-family: sans-serif; text-align: center; padding: 50px;">
        <h1>🔑 Key Generator</h1>
        <label>Duration (hours): <input type="number" id="duration" value="24" min="1"></label><br><br>
        <button onclick="generate()" style="padding: 10px 20px;">Generate Key</button>
        <p id="result" style="font-family: monospace; font-size: 20px; font-weight: bold;"></p>
        <script>
            async function generate() {
                const duration = document.getElementById('duration').value;
                const res = await fetch('/admin/create', { 
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({duration: parseInt(duration)})
                });
                const data = await res.json();
                document.getElementById('result').innerText = data.key;
            }
        </script>
    </body>
    </html>
    """

@app.route('/admin/create', methods=['POST'])
def create_key_api():
    data = request.json or {}
    duration = data.get('duration', 24)
    key = secrets.token_hex(8)
    with engine.connect() as conn:
        conn.execute(
            text("INSERT INTO licenses (key_code, duration_hours) VALUES (:k, :d)"), 
            {"k": key, "d": duration}
        )
        conn.commit()
    return jsonify({"key": key, "duration_hours": duration})

# --- AUTHORIZATION API (with Google Token Verification) ---
@app.route('/api/authorize', methods=['POST'])
def authorize():
    data = request.json or {}
    google_token = data.get('google_token')
    token_type = data.get('token_type', 'access_token')  # 'access_token' or 'id_token'
    provided_key = data.get('key')

    # --- STEP 1: Verify Google Token ---
    if not google_token:
        return jsonify({
            "authorized": False, 
            "error": "Google token required. Please authenticate with Google."
        }), 400

    email, error = verify_google_token(google_token, token_type)
    
    if error:
        return jsonify({
            "authorized": False, 
            "error": f"Google verification failed: {error}"
        }), 403
    
    print(f"✅ Verified Google user: {email}")

    # --- STEP 2: Check License/Session ---
    with engine.connect() as conn:
        # Check if user has an active session
        session = conn.execute(
            text("SELECT expires_at FROM active_sessions WHERE user_email = :e"),
            {"e": email}
        ).fetchone()

        if session:
            expires_at = session[0]
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
            
            if datetime.now() < expires_at:
                remaining = expires_at - datetime.now()
                hours_left = remaining.total_seconds() / 3600
                return jsonify({
                    "authorized": True, 
                    "message": "Session Valid",
                    "email": email,
                    "hours_remaining": round(hours_left, 2)
                })
            else:
                # Session expired, delete it
                conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
                conn.commit()

        # --- STEP 3: If no active session, validate the License Key ---
        if not provided_key:
            return jsonify({
                "authorized": False, 
                "error": "Session expired or new user. License key required.",
                "email": email,
                "needs_key": True
            }), 401

        row = conn.execute(
            text("SELECT status, duration_hours FROM licenses WHERE key_code = :k"),
            {"k": provided_key}
        ).fetchone()

        if not row:
            return jsonify({"authorized": False, "error": "Invalid license key"}), 403
        
        status, duration = row
        if status == 'used':
            return jsonify({"authorized": False, "error": "License key already used"}), 403

        # --- STEP 4: Activate License ---
        new_expiry = datetime.now() + timedelta(hours=duration)
        conn.execute(text("UPDATE licenses SET status = 'used' WHERE key_code = :k"), {"k": provided_key})
        
        # Upsert Session
        conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
        conn.execute(
            text("INSERT INTO active_sessions (user_email, expires_at) VALUES (:e, :t)"), 
            {"e": email, "t": new_expiry}
        )
        conn.commit()

        return jsonify({
            "authorized": True, 
            "message": f"License activated! Access granted for {duration} hours.",
            "email": email,
            "hours_remaining": duration
        })

# --- STATUS CHECK ENDPOINT ---
@app.route('/api/status', methods=['POST'])
def check_status():
    """Check license status without consuming a key"""
    data = request.json or {}
    google_token = data.get('google_token')
    token_type = data.get('token_type', 'access_token')
    
    if not google_token:
        return jsonify({"error": "Google token required"}), 400
    
    email, error = verify_google_token(google_token, token_type)
    
    if error:
        return jsonify({"error": f"Verification failed: {error}"}), 403
    
    with engine.connect() as conn:
        session = conn.execute(
            text("SELECT expires_at FROM active_sessions WHERE user_email = :e"),
            {"e": email}
        ).fetchone()
        
        if session:
            expires_at = session[0]
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
            
            if datetime.now() < expires_at:
                remaining = expires_at - datetime.now()
                return jsonify({
                    "has_license": True,
                    "email": email,
                    "expires_at": expires_at.isoformat(),
                    "hours_remaining": round(remaining.total_seconds() / 3600, 2)
                })
        
        return jsonify({
            "has_license": False,
            "email": email,
            "message": "No active license"
        })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
