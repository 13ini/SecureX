from flask import Flask, render_template_string, request, redirect, url_for, session, flash, jsonify
import sqlite3
import hashlib
import secrets
import json
import os
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from base64 import b64encode, b64decode
import functools

# Initialize Flask app
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configuration
CONFIG = {
    "app_config": {
        "key_size": 2048,
        "hash_algorithm": "SHA256",
        "encryption_algorithm": "RSA-OAEP",
        "signature_algorithm": "RSA-PSS"
    },
    "ca_config": {
        "ca_name": "SecureChat CA",
        "validity_days": 365
    }
}

DATABASE_PATH = "secure_chat.db"
KEYS_DIR = "user_keys"

# Create keys directory
os.makedirs(KEYS_DIR, exist_ok=True)

# Database initialization
def init_database():
    """Initialize SQLite database with required tables"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            public_key TEXT NOT NULL,
            certificate TEXT NOT NULL,
            security_q1 TEXT NOT NULL,
            security_a1_hash TEXT NOT NULL,
            security_q2 TEXT NOT NULL,
            security_a2_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # Messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            message_id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            recipient_id INTEGER NOT NULL,
            encrypted_message TEXT NOT NULL,
            digital_signature TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_read BOOLEAN DEFAULT 0,
            FOREIGN KEY (sender_id) REFERENCES users(user_id),
            FOREIGN KEY (recipient_id) REFERENCES users(user_id)
        )
    ''')
    
    # Admin users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Login attempts table (tracks failed attempts per username for lockout)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            locked BOOLEAN DEFAULT 0,
            locked_at TIMESTAMP NULL
        )
    ''')
    
    # Create default admin if doesn't exist
    admin_salt = secrets.token_hex(16)
    admin_password = hash_password("admin123", admin_salt)
    try:
        cursor.execute(
            "INSERT INTO admin_users (username, password_hash) VALUES (?, ?)",
            ("admin", admin_password + ":" + admin_salt)
        )
    except sqlite3.IntegrityError:
        pass  # Admin already exists
    
    conn.commit()
    conn.close()

# Cryptographic Functions
def hash_password(password, salt):
    """Hash password using SHA-256 with salt"""
    return hashlib.sha256((password + salt).encode()).hexdigest()

def generate_key_pair():
    """Generate RSA key pair (2048-bit)"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=CONFIG["app_config"]["key_size"],
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_certificate(username, public_key, private_key):
    """Generate self-signed X.509 certificate"""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"NP"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Bagmati"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Kathmandu"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=CONFIG["ca_config"]["validity_days"])
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    return cert

def save_private_key(username, private_key, password):
    """Encrypt and save private key"""
    encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
    
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )
    
    key_path = os.path.join(KEYS_DIR, f"{username}_private.pem")
    with open(key_path, 'wb') as f:
        f.write(pem)

def load_private_key(username, password):
    """Load and decrypt private key"""
    key_path = os.path.join(KEYS_DIR, f"{username}_private.pem")
    try:
        with open(key_path, 'rb') as f:
            pem = f.read()
        
        private_key = serialization.load_pem_private_key(
            pem,
            password=password.encode(),
            backend=default_backend()
        )
        return private_key
    except Exception as e:
        return None

def public_key_from_pem(pem_string):
    """Convert PEM string to public key object"""
    return serialization.load_pem_public_key(
        pem_string.encode(),
        backend=default_backend()
    )

def encrypt_message(message, public_key_pem):
    """Encrypt message with recipient's public key"""
    public_key = public_key_from_pem(public_key_pem)
    
    # For longer messages, we'd use hybrid encryption (AES + RSA)
    # For simplicity, using RSA directly (limited to key_size/8 - padding bytes)
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return b64encode(ciphertext).decode()

def decrypt_message(encrypted_message, private_key):
    """Decrypt message with recipient's private key"""
    ciphertext = b64decode(encrypted_message.encode())
    
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

def sign_message(message, private_key):
    """Create digital signature for message"""
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return b64encode(signature).decode()

def verify_signature(message, signature_b64, public_key_pem):
    """Verify digital signature"""
    public_key = public_key_from_pem(public_key_pem)
    signature = b64decode(signature_b64.encode())
    
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Authentication decorators
def login_required(f):
    """Decorator to require user login"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin login"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Admin access required', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# HTML Templates
HOME_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>SecureChat - Home</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            padding: 40px;
            max-width: 500px;
            width: 100%;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
        }
        h1 {
            color: #2d3748;
            margin-bottom: 10px;
            font-size: 2.5em;
        }
        .subtitle {
            color: #718096;
            margin-bottom: 30px;
            font-size: 1.1em;
        }
        .btn {
            display: block;
            width: 100%;
            padding: 15px;
            margin: 10px 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            transition: transform 0.2s;
            border: none;
            cursor: pointer;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        .btn-secondary {
            background: linear-gradient(135deg, #4c51bf 0%, #434190 100%);
        }
        .icon { font-size: 4em; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🔐</div>
        <h1>SecureChat</h1>
        <p class="subtitle">PKI-Based Encrypted Messaging</p>
        <a href="{{ url_for('register') }}" class="btn">Register New Account</a>
        <a href="{{ url_for('login') }}" class="btn">Login</a>
        <a href="{{ url_for('admin_login') }}" class="btn btn-secondary">Admin Panel</a>
    </div>
</body>
</html>
'''

REGISTER_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Register - SecureChat</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            padding: 40px;
            max-width: 600px;
            margin: 20px auto;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 {
            color: #2d3748;
            margin-bottom: 30px;
            text-align: center;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            color: #4a5568;
            margin-bottom: 5px;
            font-weight: 600;
        }
        input, select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input:focus, select:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        .alert {
            padding: 12px;
            margin-bottom: 20px;
            border-radius: 8px;
            font-weight: 500;
        }
        .alert-error {
            background: #fee;
            color: #c53030;
            border: 1px solid #fc8181;
        }
        .alert-success {
            background: #f0fff4;
            color: #22543d;
            border: 1px solid #48bb78;
        }
        .back-link {
            display: block;
            text-align: center;
            margin-top: 20px;
            color: #667eea;
            text-decoration: none;
        }
        .info-box {
            background: #ebf8ff;
            border-left: 4px solid #4299e1;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Register Account</h1>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="info-box">
            <strong>Note:</strong> Your RSA key pair (2048-bit) and digital certificate will be automatically generated upon registration.
        </div>
        
        <form method="POST">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required minlength="3">
            </div>
            
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required minlength="6">
            </div>
            
            <div class="form-group">
                <label>Confirm Password</label>
                <input type="password" name="confirm_password" required>
            </div>
            
            <div class="form-group">
                <label>Security Question 1</label>
                <select name="security_q1" required>
                    <option value="">Select a question</option>
                    <option value="What was your childhood nickname?">What was your childhood nickname?</option>
                    <option value="What is your mother's maiden name?">What is your mother's maiden name?</option>
                    <option value="What was the name of your first pet?">What was the name of your first pet?</option>
                    <option value="What city were you born in?">What city were you born in?</option>
                </select>
            </div>
            
            <div class="form-group">
                <label>Answer 1</label>
                <input type="text" name="security_a1" required>
            </div>
            
            <div class="form-group">
                <label>Security Question 2</label>
                <select name="security_q2" required>
                    <option value="">Select a question</option>
                    <option value="What is your favorite book?">What is your favorite book?</option>
                    <option value="What was your first car?">What was your first car?</option>
                    <option value="What is your favorite food?">What is your favorite food?</option>
                    <option value="What was your high school mascot?">What was your high school mascot?</option>
                </select>
            </div>
            
            <div class="form-group">
                <label>Answer 2</label>
                <input type="text" name="security_a2" required>
            </div>
            
            <button type="submit" class="btn">Register</button>
        </form>
        
        <a href="{{ url_for('index') }}" class="back-link">← Back to Home</a>
    </div>
</body>
</html>
'''

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Login - SecureChat</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            padding: 40px;
            max-width: 450px;
            width: 100%;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 {
            color: #2d3748;
            margin-bottom: 30px;
            text-align: center;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            color: #4a5568;
            margin-bottom: 5px;
            font-weight: 600;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 14px;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        .alert {
            padding: 12px;
            margin-bottom: 20px;
            border-radius: 8px;
            font-weight: 500;
        }
        .alert-error {
            background: #fee;
            color: #c53030;
            border: 1px solid #fc8181;
        }
        .links {
            text-align: center;
            margin-top: 20px;
        }
        .links a {
            color: #667eea;
            text-decoration: none;
            margin: 0 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Login</h1>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <form method="POST">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required>
            </div>
            
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            
            <button type="submit" class="btn">Login</button>
        </form>
        
        <div class="links">
            <a href="{{ url_for('forgot_password') }}">Forgot Password?</a>
            <a href="{{ url_for('index') }}">← Back</a>
        </div>
    </div>
    <script>
        // If the flash message contains "locked", start a 10-minute countdown
        var flashEl = document.querySelector('.alert-error');
        if (flashEl && flashEl.textContent.indexOf('locked') !== -1) {
            var seconds = 600; // 10 minutes
            var timerDiv = document.createElement('div');
            timerDiv.style.cssText = 'text-align:center;margin-top:18px;padding:12px;background:#fff5f5;border-radius:8px;color:#c53030;font-weight:600;font-size:15px;';
            timerDiv.innerHTML = '🔒 Account locked. Unlocking in <span id="countdown">10:00</span>…';
            document.querySelector('.container').appendChild(timerDiv);

            var interval = setInterval(function () {
                seconds--;
                if (seconds <= 0) {
                    clearInterval(interval);
                    timerDiv.innerHTML = '✅ Lockout expired. You may try again.';
                    timerDiv.style.background = '#f0fff4';
                    timerDiv.style.color = '#22543d';
                    return;
                }
                var m = Math.floor(seconds / 60);
                var s = seconds % 60;
                document.getElementById('countdown').textContent = m + ':' + (s < 10 ? '0' : '') + s;
            }, 1000);
        }
    </script>
</body>
</html>
'''

FORGOT_PASSWORD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Forgot Password - SecureChat</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            padding: 40px;
            max-width: 500px;
            margin: 50px auto;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 { color: #2d3748; margin-bottom: 30px; text-align: center; }
        .form-group { margin-bottom: 20px; }
        label { display: block; color: #4a5568; margin-bottom: 5px; font-weight: 600; }
        input { width: 100%; padding: 12px; border: 2px solid #e2e8f0; border-radius: 8px; font-size: 14px; }
        input:focus { outline: none; border-color: #667eea; }
        .btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
        }
        .alert { padding: 12px; margin-bottom: 20px; border-radius: 8px; font-weight: 500; }
        .alert-error { background: #fee; color: #c53030; border: 1px solid #fc8181; }
        .alert-success { background: #f0fff4; color: #22543d; border: 1px solid #48bb78; }
        .back-link { display: block; text-align: center; margin-top: 20px; color: #667eea; text-decoration: none; }
        .step { display: none; }
        .step.active { display: block; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔑 Password Recovery</h1>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <form method="POST">
            {% if not security_questions %}
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required>
            </div>
            <button type="submit" class="btn">Continue</button>
            {% else %}
            <input type="hidden" name="username" value="{{ username }}">
            <div class="form-group">
                <label>{{ security_questions[0] }}</label>
                <input type="text" name="answer1" required>
            </div>
            <div class="form-group">
                <label>{{ security_questions[1] }}</label>
                <input type="text" name="answer2" required>
            </div>
            <div class="form-group">
                <label>New Password</label>
                <input type="password" name="new_password" required minlength="6">
            </div>
            <button type="submit" class="btn">Reset Password</button>
            {% endif %}
        </form>
        
        <a href="{{ url_for('login') }}" class="back-link">← Back to Login</a>
    </div>
</body>
</html>
'''

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - SecureChat</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .header {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header h1 { color: #2d3748; }
        .header .user-info { color: #4a5568; }
        .btn-logout {
            padding: 10px 20px;
            background: #fc8181;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            text-decoration: none;
            font-weight: 600;
        }
        .container {
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 20px;
            max-width: 1400px;
            margin: 0 auto;
        }
        .users-panel, .chat-panel {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        .users-panel h2, .chat-panel h2 {
            color: #2d3748;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e2e8f0;
        }
        .user-item {
            padding: 15px;
            margin: 10px 0;
            background: #f7fafc;
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.3s;
            border-left: 4px solid transparent;
        }
        .user-item:hover {
            background: #edf2f7;
            border-left-color: #667eea;
            transform: translateX(5px);
        }
        .user-item.active {
            background: #ebf8ff;
            border-left-color: #4299e1;
        }
        .chat-area {
            height: 400px;
            overflow-y: auto;
            border: 2px solid #e2e8f0;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            background: #f7fafc;
        }
        .message {
            margin: 15px 0;
            padding: 12px 15px;
            border-radius: 10px;
            max-width: 80%;
        }
        .message-sent {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            margin-left: auto;
            text-align: right;
        }
        .message-received {
            background: #e2e8f0;
            color: #2d3748;
        }
        .message-meta {
            font-size: 0.85em;
            opacity: 0.8;
            margin-top: 5px;
        }
        .compose-area {
            display: flex;
            gap: 10px;
        }
        .compose-area textarea {
            flex: 1;
            padding: 12px;
            border: 2px solid #e2e8f0;
            border-radius: 10px;
            resize: none;
            font-family: inherit;
        }
        .compose-area textarea:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn-send {
            padding: 12px 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            font-weight: 600;
        }
        .empty-state {
            text-align: center;
            color: #718096;
            padding: 60px 20px;
        }
        .signature-badge {
            display: inline-block;
            padding: 3px 8px;
            background: #48bb78;
            color: white;
            border-radius: 4px;
            font-size: 0.75em;
            margin-left: 5px;
        }
        .signature-badge.invalid {
            background: #fc8181;
        }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🔐 SecureChat Dashboard</h1>
            <div class="user-info">Logged in as: <strong>{{ username }}</strong></div>
        </div>
        <a href="{{ url_for('logout') }}" class="btn-logout">Logout</a>
    </div>
    
    <div class="container">
        <div class="users-panel">
            <h2>👥 Users</h2>
            {% for user in users %}
                {% if user.user_id != current_user_id %}
                <div class="user-item" onclick="selectUser({{ user.user_id }}, '{{ user.username }}')">
                    <strong>{{ user.username }}</strong>
                    <div style="font-size: 0.85em; color: #718096;">
                        Joined: {{ user.created_at[:10] }}
                    </div>
                </div>
                {% endif %}
            {% endfor %}
        </div>
        
        <div class="chat-panel">
            <h2 id="chat-title">💬 Select a user to start chatting</h2>
            <div id="chat-area" class="chat-area">
                <div class="empty-state">
                    <div style="font-size: 3em; margin-bottom: 10px;">💬</div>
                    <p>Select a user from the left panel to view messages</p>
                </div>
            </div>
            <div class="compose-area" id="compose-area" style="display: none;">
                <textarea id="message-input" rows="3" placeholder="Type your message (max 190 characters for RSA encryption)..."></textarea>
                <button class="btn-send" onclick="sendMessage()">Send 🔒</button>
            </div>
        </div>
    </div>
    
    <script>
        let selectedUserId = null;
        let selectedUsername = '';
        
        function selectUser(userId, username) {
            selectedUserId = userId;
            selectedUsername = username;
            
            // Update UI
            document.querySelectorAll('.user-item').forEach(item => {
                item.classList.remove('active');
            });
            event.currentTarget.classList.add('active');
            
            document.getElementById('chat-title').innerHTML = '💬 Chat with ' + username;
            document.getElementById('compose-area').style.display = 'flex';
            
            loadMessages(userId);
        }
        
        function loadMessages(userId) {
            fetch('/get_messages?user_id=' + userId)
                .then(response => response.json())
                .then(data => {
                    const chatArea = document.getElementById('chat-area');
                    if (data.messages.length === 0) {
                        chatArea.innerHTML = '<div class="empty-state"><div style="font-size: 3em;">📭</div><p>No messages yet. Start the conversation!</p></div>';
                    } else {
                        chatArea.innerHTML = data.messages.map(msg => {
                            const isSent = msg.is_sent;
                            const className = isSent ? 'message-sent' : 'message-received';
                            const signatureBadge = msg.signature_valid ? 
                                '<span class="signature-badge">✓ Verified</span>' : 
                                '<span class="signature-badge invalid">⚠ Invalid Signature</span>';
                            
                            return `
                                <div class="message ${className}">
                                    <div>${msg.decrypted_message}</div>
                                    <div class="message-meta">
                                        ${msg.timestamp} ${signatureBadge}
                                    </div>
                                </div>
                            `;
                        }).join('');
                        chatArea.scrollTop = chatArea.scrollHeight;
                    }
                });
        }
        
        function sendMessage() {
            const messageInput = document.getElementById('message-input');
            const message = messageInput.value.trim();
            
            if (!message || !selectedUserId) {
                alert('Please enter a message');
                return;
            }
            
            if (message.length > 190) {
                alert('Message too long for RSA encryption. Please keep under 190 characters.');
                return;
            }
            
            fetch('/send_message', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    recipient_id: selectedUserId,
                    message: message
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    messageInput.value = '';
                    loadMessages(selectedUserId);
                } else {
                    alert('Failed to send message: ' + data.error);
                }
            });
        }
        
        // Auto-refresh messages every 5 seconds
        setInterval(() => {
            if (selectedUserId) {
                loadMessages(selectedUserId);
            }
        }, 5000);
    </script>
</body>
</html>
'''

ADMIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel - SecureChat</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #2d3748 0%, #1a202c 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .header {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 { color: #2d3748; }
        .btn-logout {
            padding: 10px 20px;
            background: #fc8181;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            text-decoration: none;
            font-weight: 600;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        .stat-card h3 {
            color: #718096;
            font-size: 0.9em;
            margin-bottom: 10px;
        }
        .stat-card .value {
            color: #2d3748;
            font-size: 2.5em;
            font-weight: bold;
        }
        .panel {
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        .panel h2 {
            color: #2d3748;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e2e8f0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }
        th {
            background: #f7fafc;
            color: #4a5568;
            font-weight: 600;
        }
        .btn-action {
            padding: 6px 12px;
            margin: 0 2px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.85em;
        }
        .btn-view {
            background: #4299e1;
            color: white;
        }
        .btn-disable {
            background: #fc8181;
            color: white;
        }
        .btn-enable {
            background: #48bb78;
            color: white;
        }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.7);
            justify-content: center;
            align-items: center;
        }
        .modal.active {
            display: flex;
        }
        .modal-content {
            background: white;
            padding: 30px;
            border-radius: 15px;
            max-width: 800px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
        }
        .modal-content h3 {
            margin-bottom: 20px;
            color: #2d3748;
        }
        .close-modal {
            float: right;
            font-size: 1.5em;
            cursor: pointer;
            color: #718096;
        }
        .cert-data {
            background: #f7fafc;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            word-break: break-all;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>⚙️ Admin Panel</h1>
        <a href="{{ url_for('admin_logout') }}" class="btn-logout">Logout</a>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <h3>TOTAL USERS</h3>
            <div class="value">{{ stats.total_users }}</div>
        </div>
        <div class="stat-card">
            <h3>ACTIVE USERS</h3>
            <div class="value">{{ stats.active_users }}</div>
        </div>
        <div class="stat-card">
            <h3>TOTAL MESSAGES</h3>
            <div class="value">{{ stats.total_messages }}</div>
        </div>
    </div>
    
    <div class="panel">
        <h2>👥 User Management</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Registered</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {% for user in users %}
                <tr>
                    <td>{{ user.user_id }}</td>
                    <td>{{ user.username }}</td>
                    <td>{{ user.created_at[:16] }}</td>
                    <td>
                        {% if user.is_active %}
                            <span style="color: #48bb78;">● Active</span>
                        {% else %}
                            <span style="color: #fc8181;">● Disabled</span>
                        {% endif %}
                    </td>
                    <td>
                        <button class="btn-action btn-view" onclick="viewCertificate({{ user.user_id }})">View Certificate</button>
                        {% if user.is_active %}
                            <button class="btn-action btn-disable" onclick="toggleUser({{ user.user_id }}, 0)">Disable</button>
                        {% else %}
                            <button class="btn-action btn-enable" onclick="toggleUser({{ user.user_id }}, 1)">Enable</button>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    
    <div class="panel">
        <h2>📊 Message Activity</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>From</th>
                    <th>To</th>
                    <th>Timestamp</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {% for msg in messages %}
                <tr>
                    <td>{{ msg.message_id }}</td>
                    <td>{{ msg.sender_username }}</td>
                    <td>{{ msg.recipient_username }}</td>
                    <td>{{ msg.timestamp[:16] }}</td>
                    <td>
                        {% if msg.is_read %}
                            <span style="color: #48bb78;">Read</span>
                        {% else %}
                            <span style="color: #718096;">Unread</span>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    
    <div class="modal" id="certModal">
        <div class="modal-content">
            <span class="close-modal" onclick="closeModal()">×</span>
            <h3 id="modalTitle">Certificate Details</h3>
            <div>
                <strong>Public Key:</strong>
                <div class="cert-data" id="publicKeyData"></div>
            </div>
            <div>
                <strong>Certificate:</strong>
                <div class="cert-data" id="certificateData"></div>
            </div>
        </div>
    </div>
    
    <script>
        function viewCertificate(userId) {
            fetch('/admin/get_certificate?user_id=' + userId)
                .then(response => response.json())
                .then(data => {
                    document.getElementById('modalTitle').textContent = 'Certificate: ' + data.username;
                    document.getElementById('publicKeyData').textContent = data.public_key;
                    document.getElementById('certificateData').textContent = data.certificate;
                    document.getElementById('certModal').classList.add('active');
                })
                .catch(err => {
                    alert('Failed to load certificate: ' + err);
                });
        }
        
        function closeModal() {
            document.getElementById('certModal').classList.remove('active');
        }
        
        // Close modal when clicking outside it
        document.getElementById('certModal').addEventListener('click', function(e) {
            if (e.target === this) closeModal();
        });
        
        function toggleUser(userId, status) {
            fetch('/admin/toggle_user', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    user_id: userId,
                    is_active: status
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                }
            });
        }
    </script>
</body>
</html>
'''

# Routes
@app.route('/')
def index():
    """Home page"""
    return render_template_string(HOME_TEMPLATE)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration with key generation and certificate issuance"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        security_q1 = request.form['security_q1']
        security_a1 = request.form['security_a1']
        security_q2 = request.form['security_q2']
        security_a2 = request.form['security_a2']
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template_string(REGISTER_TEMPLATE)
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return render_template_string(REGISTER_TEMPLATE)
        
        # Check if username exists
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('Username already exists', 'error')
            conn.close()
            return render_template_string(REGISTER_TEMPLATE)
        
        try:
            # Generate cryptographic materials
            private_key, public_key = generate_key_pair()
            certificate = generate_certificate(username, public_key, private_key)
            
            # Serialize public key and certificate
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            
            certificate_pem = certificate.public_bytes(
                encoding=serialization.Encoding.PEM
            ).decode()
            
            # Save private key (encrypted with password)
            save_private_key(username, private_key, password)
            
            # Hash password and security answers
            salt = secrets.token_hex(16)
            password_hash = hash_password(password, salt)
            
            answer1_salt = secrets.token_hex(16)
            answer1_hash = hash_password(security_a1.lower(), answer1_salt)
            
            answer2_salt = secrets.token_hex(16)
            answer2_hash = hash_password(security_a2.lower(), answer2_salt)
            
            # Store in database
            cursor.execute('''
                INSERT INTO users (
                    username, password_hash, salt, public_key, certificate,
                    security_q1, security_a1_hash, security_q2, security_a2_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                username, password_hash, salt, public_key_pem, certificate_pem,
                security_q1, answer1_hash + ":" + answer1_salt,
                security_q2, answer2_hash + ":" + answer2_salt
            ))
            
            conn.commit()
            conn.close()
            
            flash('Registration successful! Your RSA key pair and certificate have been generated.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            flash(f'Registration failed: {str(e)}', 'error')
            conn.close()
            return render_template_string(REGISTER_TEMPLATE)
    
    return render_template_string(REGISTER_TEMPLATE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login with certificate validation and 3-strike lockout (10 min)"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # ----------------------------------------------------------
        # 1. Check / initialise the login_attempts row for this user
        # ----------------------------------------------------------
        cursor.execute(
            "SELECT failed_attempts, locked, locked_at FROM login_attempts WHERE username = ?",
            (username,)
        )
        attempt_row = cursor.fetchone()

        if attempt_row is None:
            # First-ever attempt for this username – create the row
            cursor.execute(
                "INSERT INTO login_attempts (username, failed_attempts, locked, locked_at) VALUES (?, 0, 0, NULL)",
                (username,)
            )
            conn.commit()
            failed_attempts, locked, locked_at = 0, 0, None
        else:
            failed_attempts, locked, locked_at = attempt_row

        # ----------------------------------------------------------
        # 2. If account is locked, check whether the 10-min window
        #    has passed; if not, reject immediately.
        # ----------------------------------------------------------
        if locked and locked_at:
            locked_time = datetime.strptime(locked_at, "%Y-%m-%d %H:%M:%S.%f") if '.' in locked_at else datetime.strptime(locked_at, "%Y-%m-%d %H:%M:%S")
            remaining = 600 - (datetime.utcnow() - locked_time).total_seconds()  # 600 s = 10 min

            if remaining > 0:
                mins = int(remaining // 60) + 1          # round up to next whole minute
                flash(f'Account is locked. Please wait {mins} minute(s) before trying again.', 'error')
                conn.close()
                return render_template_string(LOGIN_TEMPLATE)
            else:
                # Lockout expired – reset the row
                cursor.execute(
                    "UPDATE login_attempts SET failed_attempts = 0, locked = 0, locked_at = NULL WHERE username = ?",
                    (username,)
                )
                conn.commit()
                failed_attempts = 0

        # ----------------------------------------------------------
        # 3. Look up the user record
        # ----------------------------------------------------------
        cursor.execute(
            "SELECT user_id, password_hash, salt, is_active FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()

        if not user:
            # Username doesn't exist – don't reveal that; just say invalid
            flash('Invalid username or password', 'error')
            conn.close()
            return render_template_string(LOGIN_TEMPLATE)

        user_id, stored_hash, salt, is_active = user

        if not is_active:
            flash('Your account has been disabled. Contact administrator.', 'error')
            conn.close()
            return render_template_string(LOGIN_TEMPLATE)

        # ----------------------------------------------------------
        # 4. Verify password
        # ----------------------------------------------------------
        if hash_password(password, salt) != stored_hash:
            # Wrong password – increment counter
            failed_attempts += 1

            if failed_attempts >= 3:
                # Lock the account for 10 minutes
                now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute(
                    "UPDATE login_attempts SET failed_attempts = ?, locked = 1, locked_at = ? WHERE username = ?",
                    (failed_attempts, now, username)
                )
                conn.commit()
                conn.close()
                flash('Too many failed attempts. Your account is now locked for 10 minutes.', 'error')
                return render_template_string(LOGIN_TEMPLATE)
            else:
                # Save incremented counter, show remaining attempts
                cursor.execute(
                    "UPDATE login_attempts SET failed_attempts = ? WHERE username = ?",
                    (failed_attempts, username)
                )
                conn.commit()
                conn.close()
                remaining_tries = 3 - failed_attempts
                flash(f'Invalid username or password. {remaining_tries} attempt(s) remaining before lockout.', 'error')
                return render_template_string(LOGIN_TEMPLATE)

        # ----------------------------------------------------------
        # 5. Password correct – verify private key (certificate check)
        # ----------------------------------------------------------
        private_key = load_private_key(username, password)
        if not private_key:
            flash('Certificate validation failed', 'error')
            conn.close()
            return render_template_string(LOGIN_TEMPLATE)

        # ----------------------------------------------------------
        # 6. Login successful – reset attempts, build session
        # ----------------------------------------------------------
        cursor.execute(
            "UPDATE login_attempts SET failed_attempts = 0, locked = 0, locked_at = NULL WHERE username = ?",
            (username,)
        )
        conn.commit()
        conn.close()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        session['user_id'] = user_id
        session['username'] = username
        session['private_key_pem'] = private_key_pem
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))

    return render_template_string(LOGIN_TEMPLATE)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Password recovery using security questions"""
    if request.method == 'POST':
        username = request.form.get('username')
        
        # Step 1: Get security questions
        if 'answer1' not in request.form:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT security_q1, security_q2 FROM users WHERE username = ?",
                (username,)
            )
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                flash('Username not found', 'error')
                return render_template_string(FORGOT_PASSWORD_TEMPLATE)
            
            return render_template_string(
                FORGOT_PASSWORD_TEMPLATE,
                security_questions=result,
                username=username
            )
        
        # Step 2: Verify answers and reset password
        else:
            answer1 = request.form['answer1']
            answer2 = request.form['answer2']
            new_password = request.form['new_password']
            
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT security_a1_hash, security_a2_hash, public_key FROM users WHERE username = ?",
                (username,)
            )
            result = cursor.fetchone()
            
            if not result:
                flash('User not found', 'error')
                conn.close()
                return redirect(url_for('forgot_password'))
            
            stored_a1, stored_a2, public_key_pem = result
            
            # Verify answers
            hash1, salt1 = stored_a1.split(':')
            hash2, salt2 = stored_a2.split(':')
            
            if (hash_password(answer1.lower(), salt1) != hash1 or
                hash_password(answer2.lower(), salt2) != hash2):
                flash('Security answers incorrect', 'error')
                conn.close()
                return redirect(url_for('forgot_password'))
            
            # Update password
            new_salt = secrets.token_hex(16)
            new_hash = hash_password(new_password, new_salt)
            
            cursor.execute(
                "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
                (new_hash, new_salt, username)
            )
            conn.commit()
            conn.close()
            
            # Note: Private key needs to be regenerated as it was encrypted with old password
            # For simplicity, we're not implementing this here - in production,
            # you'd need to re-encrypt the private key with the new password
            
            flash('Password reset successful! Please login with your new password.', 'success')
            return redirect(url_for('login'))
    
    return render_template_string(FORGOT_PASSWORD_TEMPLATE)

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard with messaging interface"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Get all users except current user
    cursor.execute(
        "SELECT user_id, username, created_at FROM users WHERE is_active = 1"
    )
    users = [dict(zip(['user_id', 'username', 'created_at'], row)) for row in cursor.fetchall()]
    
    conn.close()
    
    return render_template_string(
        DASHBOARD_TEMPLATE,
        username=session['username'],
        current_user_id=session['user_id'],
        users=users
    )

@app.route('/get_messages')
@login_required
def get_messages():
    """Get messages between current user and selected user"""
    other_user_id = request.args.get('user_id', type=int)
    current_user_id = session['user_id']
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Get messages
    cursor.execute('''
        SELECT m.message_id, m.sender_id, m.recipient_id, m.encrypted_message,
               m.digital_signature, m.timestamp, m.is_read,
               s.username as sender_username, s.public_key as sender_public_key
        FROM messages m
        JOIN users s ON m.sender_id = s.user_id
        WHERE (m.sender_id = ? AND m.recipient_id = ?) OR
              (m.sender_id = ? AND m.recipient_id = ?)
        ORDER BY m.timestamp ASC
    ''', (current_user_id, other_user_id, other_user_id, current_user_id))
    
    messages = cursor.fetchall()
    conn.close()
    
    # Load private key from session
    private_key_pem = session.get('private_key_pem')
    if not private_key_pem:
        return jsonify({'messages': [], 'error': 'Session expired'})
    
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    
    result = []
    for msg in messages:
        msg_id, sender_id, recipient_id, encrypted_msg, signature, timestamp, is_read, sender_username, sender_public_key = msg
        
        is_sent = sender_id == current_user_id
        
        # Decrypt message if current user is recipient
        try:
            if recipient_id == current_user_id:
                decrypted = decrypt_message(encrypted_msg, private_key)
            else:
                # For sent messages, we can't decrypt them (encrypted with recipient's key)
                decrypted = "[Sent - Encrypted with recipient's key]"
            
            # Verify signature
            signature_valid = verify_signature(decrypted if recipient_id == current_user_id else encrypted_msg, 
                                               signature, sender_public_key)
        except Exception as e:
            decrypted = f"[Decryption failed: {str(e)}]"
            signature_valid = False
        
        result.append({
            'message_id': msg_id,
            'is_sent': is_sent,
            'decrypted_message': decrypted,
            'timestamp': timestamp,
            'signature_valid': signature_valid
        })
    
    return jsonify({'messages': result})

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    """Send encrypted message with digital signature"""
    data = request.json
    recipient_id = data['recipient_id']
    message = data['message']
    
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get recipient's public key
        cursor.execute("SELECT public_key FROM users WHERE user_id = ?", (recipient_id,))
        recipient_public_key = cursor.fetchone()[0]
        
        # Get sender's private key from session
        private_key_pem = session.get('private_key_pem')
        if not private_key_pem:
            return jsonify({'success': False, 'error': 'Session expired, please login again'})
        
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        
        # Encrypt message with recipient's public key
        encrypted_message = encrypt_message(message, recipient_public_key)
        
        # Sign the original message with sender's private key
        signature = sign_message(message, private_key)
        
        # Store message
        cursor.execute('''
            INSERT INTO messages (sender_id, recipient_id, encrypted_message, digital_signature)
            VALUES (?, ?, ?, ?)
        ''', (session['user_id'], recipient_id, encrypted_message, signature))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT admin_id, password_hash FROM admin_users WHERE username = ?",
            (username,)
        )
        admin = cursor.fetchone()
        conn.close()
        
        if not admin:
            flash('Invalid credentials', 'error')
            return render_template_string(LOGIN_TEMPLATE.replace('Login', 'Admin Login'))
        
        admin_id, stored_data = admin
        stored_hash, salt = stored_data.split(':')
        
        if hash_password(password, salt) != stored_hash:
            flash('Invalid credentials', 'error')
            return render_template_string(LOGIN_TEMPLATE.replace('Login', 'Admin Login'))
        
        session['admin_id'] = admin_id
        session['admin_username'] = username
        return redirect(url_for('admin_panel'))
    
    return render_template_string(LOGIN_TEMPLATE.replace('Login', 'Admin Login').replace('login', 'admin_login'))

@app.route('/admin/panel')
@admin_required
def admin_panel():
    """Admin dashboard"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Get statistics
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
    active_users = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM messages")
    total_messages = cursor.fetchone()[0]
    
    stats = {
        'total_users': total_users,
        'active_users': active_users,
        'total_messages': total_messages
    }
    
    # Get all users
    cursor.execute("SELECT user_id, username, created_at, is_active, certificate, public_key FROM users")
    users = [dict(zip(['user_id', 'username', 'created_at', 'is_active', 'certificate', 'public_key'], row)) 
             for row in cursor.fetchall()]
    
    # Get recent messages (metadata only)
    cursor.execute('''
        SELECT m.message_id, m.timestamp, m.is_read,
               s.username as sender_username,
               r.username as recipient_username
        FROM messages m
        JOIN users s ON m.sender_id = s.user_id
        JOIN users r ON m.recipient_id = r.user_id
        ORDER BY m.timestamp DESC
        LIMIT 50
    ''')
    messages = [dict(zip(['message_id', 'timestamp', 'is_read', 'sender_username', 'recipient_username'], row))
                for row in cursor.fetchall()]
    
    conn.close()
    
    return render_template_string(ADMIN_TEMPLATE, stats=stats, users=users, messages=messages)

@app.route('/admin/toggle_user', methods=['POST'])
@admin_required
def toggle_user():
    """Enable/disable user account"""
    data = request.json
    user_id = data['user_id']
    is_active = data['is_active']
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_active = ? WHERE user_id = ?", (is_active, user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/admin/get_certificate')
@admin_required
def get_certificate():
    """Return user certificate and public key as JSON for the admin modal"""
    user_id = request.args.get('user_id', type=int)
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, public_key, certificate FROM users WHERE user_id = ?",
        (user_id,)
    )
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'username': row[0],
        'public_key': row[1],
        'certificate': row[2]
    })

@app.route('/admin/logout')
def admin_logout():
    """Admin logout"""
    session.clear()
    return redirect(url_for('index'))

# Main execution
if __name__ == '__main__':
    # Initialize database
    init_database()
    
    # Save configuration to JSON
    with open('config.json', 'w') as f:
        json.dump(CONFIG, f, indent=2)
    
    print("=" * 60)
    print("SecureChat System Starting...")
    print("=" * 60)
    print("Database:", DATABASE_PATH)
    print("Keys Directory:", KEYS_DIR)
    print("Default Admin: username=admin, password=admin123")
    print("=" * 60)
    print("Navigate to: http://localhost:5000")
    print("=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)

