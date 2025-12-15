# Add to your existing app.py

# --- SESSION VERIFICATION (for .so modules) ---
@app.route('/api/verify_session', methods=['POST'])
def verify_session():
    """
    Quick verification endpoint for compiled modules.
    Checks if a session token is valid without consuming anything.
    """
    data = request.json or {}
    session_token = data.get('session_token')
    
    if not session_token:
        return jsonify({"valid": False, "error": "No session token"}), 400
    
    # Session token format: email:expiry_timestamp:signature
    try:
        parts = session_token.split(':')
        if len(parts) != 3:
            return jsonify({"valid": False, "error": "Invalid token format"}), 403
        
        email, expiry_str, signature = parts
        expiry = datetime.fromisoformat(expiry_str)
        
        # Check expiry
        if datetime.now() > expiry:
            return jsonify({"valid": False, "error": "Session expired"}), 403
        
        # Verify signature (simple HMAC)
        import hmac
        import hashlib
        secret = os.environ.get("SESSION_SECRET", "default-secret-change-me")
        expected_sig = hmac.new(
            secret.encode(), 
            f"{email}:{expiry_str}".encode(), 
            hashlib.sha256
        ).hexdigest()[:16]
        
        if not hmac.compare_digest(signature, expected_sig):
            return jsonify({"valid": False, "error": "Invalid signature"}), 403
        
        return jsonify({
            "valid": True,
            "email": email,
            "expires_at": expiry_str
        })
        
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)}), 403


def generate_session_token(email, hours):
    """Generate a signed session token"""
    import hmac
    import hashlib
    
    expiry = datetime.now() + timedelta(hours=hours)
    expiry_str = expiry.isoformat()
    
    secret = os.environ.get("SESSION_SECRET", "default-secret-change-me")
    signature = hmac.new(
        secret.encode(), 
        f"{email}:{expiry_str}".encode(), 
        hashlib.sha256
    ).hexdigest()[:16]
    
    return f"{email}:{expiry_str}:{signature}"


# Update your /api/authorize endpoint to return session_token:
# Add this line before the final return in the authorized case:
#   session_token = generate_session_token(email, hours_remaining)
#   Add "session_token": session_token to the response JSON
