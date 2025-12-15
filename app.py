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

# --- DATABASE CONNECTION ---
DB_URL = os.environ.get("DATABASE_URL")

if DB_URL:
    if DB_URL.startswith("postgres://"):
        DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
    engine = create_engine(DB_URL)
else:
    print("⚠️ WARNING: DATABASE_URL not set. Using temporary local SQLite.")
    engine = create_engine("sqlite:///temp.db")

# --- CONFIGURATION ---
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
SESSION_SECRET = os.environ.get("SESSION_SECRET", "change-this-to-a-random-string-in-production")

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

init_db()

# --- HELPER FUNCTIONS ---

def generate_session_token(email, hours):
    """
    Generate a signed session token for .so module verification.
    Format: email:expiry_iso:signature
    """
    expiry = datetime.now() + timedelta(hours=hours)
    expiry_str = expiry.isoformat()
    
    # Create HMAC signature
    message = f"{email}:{expiry_str}"
    signature = hmac.new(
        SESSION_SECRET.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()[:16]
    
    return f"{email}:{expiry_str}:{signature}"


def verify_session_token(token):
    """
    Verify a session token.
    Returns: (is_valid, email, error_message)
    """
    try:
        parts = token.split(':')
        if len(parts) != 3:
            return False, None, "Invalid token format"
        
        email, expiry_str, signature = parts
        
        # Check expiry
        expiry = datetime.fromisoformat(expiry_str)
        if datetime.now() > expiry:
            return False, email, "Session expired"
        
        # Verify signature
        message = f"{email}:{expiry_str}"
        expected_sig = hmac.new(
            SESSION_SECRET.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()[:16]
        
        if not hmac.compare_digest(signature, expected_sig):
            return False, None, "Invalid signature"
        
        return True, email, None
        
    except Exception as e:
        return False, None, str(e)


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
            idinfo = id_token.verify_oauth2_token(
                token,
                google_auth_requests.Request(),
                GOOGLE_CLIENT_ID
            )
            
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
            response = http_requests.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10
            )
            
            if response.status_code != 200:
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
            
            if user_info.get('verified_email') == False:
                return None, "Email not verified"
                
            return email, None
            
        except http_requests.RequestException as e:
            return None, f"Network error during verification: {str(e)}"
        except Exception as e:
            return None, f"Token verification failed: {str(e)}"


# --- ROUTES ---

@app.route('/')
def home():
    return "License Server is Online. (Google Token + Session Verification Enabled)"


# --- ADMIN PANEL ---
@app.route('/admin')
def admin_ui():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>License Admin</title>
        <style>
            body { font-family: sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
            .container { background: white; padding: 30px; border-radius: 10px; max-width: 400px; margin: auto; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            input { padding: 10px; margin: 10px; font-size: 16px; }
            button { padding: 12px 24px; font-size: 16px; background: #4CAF50; color: white; border: none; border-radius: 5px; cursor: pointer; }
            button:hover { background: #45a049; }
            #result { font-family: monospace; font-size: 24px; font-weight: bold; margin-top: 20px; padding: 15px; background: #e8f5e9; border-radius: 5px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔑 License Key Generator</h1>
            <p>
                <label>Duration (hours):</label><br>
                <input type="number" id="duration" value="24" min="1" max="8760">
            </p>
            <button onclick="generate()">Generate Key</button>
            <p id="result"></p>
        </div>
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
    """Create a new license key"""
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


@app.route('/admin/keys', methods=['GET'])
def list_keys():
    """List all license keys (for admin)"""
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT key_code, status, duration_hours FROM licenses")).fetchall()
        keys = [{"key": r[0], "status": r[1], "duration_hours": r[2]} for r in rows]
    return jsonify({"keys": keys})


@app.route('/admin/sessions', methods=['GET'])
def list_sessions():
    """List all active sessions (for admin)"""
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT user_email, expires_at FROM active_sessions")).fetchall()
        sessions = []
        for r in rows:
            expires_at = r[1]
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
            sessions.append({
                "email": r[0], 
                "expires_at": expires_at.isoformat(),
                "is_active": datetime.now() < expires_at
            })
    return jsonify({"sessions": sessions})


# --- MAIN AUTHORIZATION API ---
@app.route('/api/authorize', methods=['POST'])
def authorize():
    """
    Main authorization endpoint.
    Verifies Google token and checks/activates license.
    Returns session_token for .so module verification.
    """
    data = request.json or {}
    google_token = data.get('google_token')
    token_type = data.get('token_type', 'access_token')
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
                
                # Generate session token for .so verification
                session_token = generate_session_token(email, hours_left)
                
                return jsonify({
                    "authorized": True, 
                    "message": "Session Valid",
                    "email": email,
                    "hours_remaining": round(hours_left, 2),
                    "session_token": session_token
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

        # Generate session token for .so verification
        session_token = generate_session_token(email, duration)

        return jsonify({
            "authorized": True, 
            "message": f"License activated! Access granted for {duration} hours.",
            "email": email,
            "hours_remaining": duration,
            "session_token": session_token
        })


# --- SESSION VERIFICATION API (for .so modules) ---
@app.route('/api/verify_session', methods=['POST'])
def verify_session():
    """
    Quick verification endpoint for compiled .so modules.
    Checks if a session token is valid without consuming anything.
    """
    data = request.json or {}
    session_token = data.get('session_token')
    
    if not session_token:
        return jsonify({"valid": False, "error": "No session token provided"}), 400
    
    is_valid, email, error = verify_session_token(session_token)
    
    if is_valid:
        return jsonify({
            "valid": True,
            "email": email
        })
    else:
        return jsonify({
            "valid": False,
            "error": error
        }), 403


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


# --- REVOKE SESSION (Admin) ---
@app.route('/admin/revoke', methods=['POST'])
def revoke_session():
    """Revoke a user's session (admin function)"""
    data = request.json or {}
    email = data.get('email')
    
    if not email:
        return jsonify({"error": "Email required"}), 400
    
    with engine.connect() as conn:
        result = conn.execute(
            text("DELETE FROM active_sessions WHERE user_email = :e"), 
            {"e": email}
        )
        conn.commit()
        
        if result.rowcount > 0:
            return jsonify({"success": True, "message": f"Session revoked for {email}"})
        else:
            return jsonify({"success": False, "message": "No active session found"})


# --- HEALTH CHECK ---
@app.route('/health')
def health():
    """Health check endpoint"""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return jsonify({"status": "healthy", "database": "connected"})
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
