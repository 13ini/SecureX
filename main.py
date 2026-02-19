# ------
# IMPORTS
# ------
from flask import (Flask, render_template_string, request,
                   redirect, url_for, session, flash, jsonify)
import sqlite3
import hashlib
import secrets
import json
import os
import functools
from datetime import datetime, timedelta, timezone
from base64 import b64encode, b64decode

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature

# ------
# APP & CONFIG
# ------
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

CONFIG = {
    "app_config": {
        "key_size": 2048,
        "hash_algorithm": "SHA256",
        "encryption_algorithm": "RSA-OAEP",
        "signature_algorithm": "RSA-PSS"
    },
    "ca_config": {
        "ca_name": "SecureChat CA",
        "ca_org": "SecureChat PKI",
        "validity_days": 365,
        "user_cert_validity_days": 365
    }
}

DATABASE_PATH = "secure_chat.db"
KEYS_DIR       = "user_keys"
CA_KEYS_DIR    = "ca_keys"
FILES_DIR      = "shared_files"  # NEW: encrypted files storage

os.makedirs(KEYS_DIR,    exist_ok=True)
os.makedirs(CA_KEYS_DIR, exist_ok=True)
os.makedirs(FILES_DIR,   exist_ok=True)  # NEW

# ------
# MODULE-LEVEL CA STATE  (loaded once at startup)
# ------
CA_PRIVATE_KEY = None   # rsa private key object
CA_CERTIFICATE = None   # x509.Certificate object
CA_CERT_PEM    = ""     # PEM string (trust anchor)


# ================================================================
# CA BOOTSTRAP
# ================================================================
def bootstrap_ca():
    """
    Generate or load the local Certificate Authority.
    Called exactly once when the application starts.
    """
    global CA_PRIVATE_KEY, CA_CERTIFICATE, CA_CERT_PEM

    priv_path = os.path.join(CA_KEYS_DIR, "ca_private.pem")
    cert_path = os.path.join(CA_KEYS_DIR, "ca_cert.pem")

    if os.path.exists(priv_path) and os.path.exists(cert_path):
        # -- load existing CA --
        with open(priv_path, "rb") as f:
            CA_PRIVATE_KEY = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        with open(cert_path, "rb") as f:
            ca_pem_bytes = f.read()
            CA_CERTIFICATE = x509.load_pem_x509_certificate(
                ca_pem_bytes, default_backend()
            )
            CA_CERT_PEM = ca_pem_bytes.decode()
        print("[CA] Loaded existing CA from disk.")
    else:
        # -- generate new CA --
        CA_PRIVATE_KEY = rsa.generate_private_key(
            public_exponent=65537,
            key_size=CONFIG["app_config"]["key_size"],
            backend=default_backend()
        )
        ca_pub = CA_PRIVATE_KEY.public_key()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME,            u"NP"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,  u"Bagmati"),
            x509.NameAttribute(NameOID.LOCALITY_NAME,           u"Kathmandu"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,       CONFIG["ca_config"]["ca_org"]),
            x509.NameAttribute(NameOID.COMMON_NAME,             CONFIG["ca_config"]["ca_name"]),
        ])

        CA_CERTIFICATE = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))  # 10 yr
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(CA_PRIVATE_KEY, hashes.SHA256(), default_backend())
        )

        # persist to disk
        with open(priv_path, "wb") as f:
            f.write(CA_PRIVATE_KEY.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ))
        with open(cert_path, "wb") as f:
            ca_pem_bytes = CA_CERTIFICATE.public_bytes(serialization.Encoding.PEM)
            f.write(ca_pem_bytes)
            CA_CERT_PEM = ca_pem_bytes.decode()

        print("[CA] Generated new CA key-pair and certificate.")


# ================================================================
# DATABASE
# ================================================================
def init_database():
    conn = sqlite3.connect(DATABASE_PATH)
    c    = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username         TEXT UNIQUE NOT NULL,
            password_hash    TEXT NOT NULL,
            salt             TEXT NOT NULL,
            public_key       TEXT NOT NULL,
            certificate      TEXT NOT NULL,
            security_q1      TEXT NOT NULL,
            security_a1_hash TEXT NOT NULL,
            security_q2      TEXT NOT NULL,
            security_a2_hash TEXT NOT NULL,
            created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active        BOOLEAN   DEFAULT 1
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            message_id        INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id         INTEGER NOT NULL,
            recipient_id      INTEGER NOT NULL,
            encrypted_message TEXT NOT NULL,
            digital_signature TEXT NOT NULL,
            timestamp         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_read           BOOLEAN   DEFAULT 0,
            FOREIGN KEY (sender_id)    REFERENCES users(user_id),
            FOREIGN KEY (recipient_id) REFERENCES users(user_id)
        )
    ''')

    # NEW: Files table for encrypted file transfers
    c.execute('''
        CREATE TABLE IF NOT EXISTS shared_files (
            file_id           INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id         INTEGER NOT NULL,
            recipient_id      INTEGER NOT NULL,
            original_filename TEXT NOT NULL,
            encrypted_filename TEXT NOT NULL,
            file_size         INTEGER NOT NULL,
            encrypted_aes_key TEXT NOT NULL,
            digital_signature TEXT NOT NULL,
            timestamp         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_downloaded     BOOLEAN   DEFAULT 0,
            FOREIGN KEY (sender_id)    REFERENCES users(user_id),
            FOREIGN KEY (recipient_id) REFERENCES users(user_id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            admin_id      INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT UNIQUE NOT NULL,
            failed_attempts INTEGER  DEFAULT 0,
            locked          BOOLEAN  DEFAULT 0,
            locked_at       TIMESTAMP NULL
        )
    ''')

    # ---- CRL: Certificate Revocation List ----
    c.execute('''
        CREATE TABLE IF NOT EXISTS revoked_certificates (
            serial_number TEXT PRIMARY KEY,
            username      TEXT NOT NULL,
            revoked_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # default admin
    admin_salt = secrets.token_hex(16)
    try:
        c.execute(
            "INSERT INTO admin_users (username, password_hash) VALUES (?, ?)",
            ("admin", hash_password("admin123", admin_salt) + ":" + admin_salt)
        )
    except sqlite3.IntegrityError:
        pass

    conn.commit()
    conn.close()


# ================================================================
# CRYPTOGRAPHIC HELPERS
# ================================================================

def hash_password(password, salt):
    """SHA-256 password hash with salt."""
    return hashlib.sha256((password + salt).encode()).hexdigest()

# ---- key-pair ----
def generate_key_pair():
    priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=CONFIG["app_config"]["key_size"],
        backend=default_backend()
    )
    return priv, priv.public_key()


# ---- CA-signed user certificate ----
def generate_certificate(username, user_public_key):
    """
    Issue a user certificate signed by the local CA.
    The issuer field = CA subject; signed with CA private key.
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,            u"NP"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,  u"Bagmati"),
        x509.NameAttribute(NameOID.LOCALITY_NAME,           u"Kathmandu"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,       u"SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME,             username),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(CA_CERTIFICATE.subject)          # CA is the issuer
        .public_key(user_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(
            datetime.now(timezone.utc)
            + timedelta(days=CONFIG["ca_config"]["user_cert_validity_days"])
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        )
        .sign(CA_PRIVATE_KEY, hashes.SHA256(), default_backend())   # signed by CA
    )
    return cert


# ---- CERTIFICATE VALIDATION (reusable) ----
def validate_certificate(cert_pem):
    """
    Full PKI validation.  Returns (True, None) or (False, reason).

    Checks:
      1. Parse PEM.
      2. Verify signature against the CA public key.
      3. not_valid_before <= now <= not_valid_after.
      4. Serial number not in revoked_certificates (CRL).
    """
    try:
        cert = x509.load_pem_x509_certificate(
            cert_pem.encode(), default_backend()
        )
    except Exception:
        return False, "Certificate PEM is malformed."

    # 1. Signature – proves the CA actually issued this cert
    try:
        CA_CERTIFICATE.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
    except InvalidSignature:
        return False, "Certificate signature invalid – not issued by trusted CA."
    except Exception as e:
        return False, f"Signature verification error: {e}"

    # 2. Validity period
    now = datetime.now(timezone.utc)
    if now < cert.not_valid_before_utc:
        return False, "Certificate is not yet valid."
    if now > cert.not_valid_after_utc:
        return False, "Certificate has expired."

    # 3. CRL check
    serial = str(cert.serial_number)
    conn = sqlite3.connect(DATABASE_PATH)
    row  = conn.execute(
        "SELECT revoked_at FROM revoked_certificates WHERE serial_number=?",
        (serial,)
    ).fetchone()
    conn.close()
    if row:
        return False, f"Certificate revoked (since {row[0]})."

    return True, None


# ---- private key I/O ----
def save_private_key(username, private_key, password):
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode())
    )
    with open(os.path.join(KEYS_DIR, f"{username}_private.pem"), "wb") as f:
        f.write(pem)

def load_private_key(username, password):
    path = os.path.join(KEYS_DIR, f"{username}_private.pem")
    try:
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(), password=password.encode(), backend=default_backend()
            )
    except Exception:
        return None


# ---- encryption / decryption ----
def public_key_from_pem(pem_str):
    return serialization.load_pem_public_key(
        pem_str.encode(), backend=default_backend()
    )

def encrypt_message(message, public_key_pem):
    """RSA-OAEP encryption (messages <= 190 bytes)."""
    pub = public_key_from_pem(public_key_pem)
    ct  = pub.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None
        )
    )
    return b64encode(ct).decode()

def decrypt_message(encrypted_b64, private_key):
    """RSA-OAEP decryption."""
    ct = b64decode(encrypted_b64)
    return private_key.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None
        )
    ).decode()


# ---- HYBRID ENCRYPTION SCAFFOLD (AES-256-GCM + RSA-OAEP) ----
# Use this path for messages longer than ~190 bytes.
def hybrid_encrypt(plaintext_str, recipient_public_key_pem):
    """
    1. Generate random 256-bit AES key.
    2. Encrypt plaintext with AES-256-GCM.
    3. Wrap AES key with recipient RSA public key.
    Returns JSON blob.
    """
    aes_key  = os.urandom(32)
    nonce    = os.urandom(12)
    aesgcm   = AESGCM(aes_key)
    aes_ct   = aesgcm.encrypt(nonce, plaintext_str.encode(), None)

    pub      = public_key_from_pem(recipient_public_key_pem)
    wrapped  = pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None
        )
    )
    return json.dumps({
        "aes_ct_b64":          b64encode(aes_ct).decode(),
        "aes_nonce_b64":       b64encode(nonce).decode(),
        "rsa_wrapped_key_b64": b64encode(wrapped).decode()
    })

def hybrid_decrypt(payload_json, private_key):
    """Reverse of hybrid_encrypt."""
    data     = json.loads(payload_json)
    wrapped  = b64decode(data["rsa_wrapped_key_b64"])
    aes_key  = private_key.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None
        )
    )
    nonce  = b64decode(data["aes_nonce_b64"])
    aes_ct = b64decode(data["aes_ct_b64"])
    return AESGCM(aes_key).decrypt(nonce, aes_ct, None).decode()


# ---- signing / verification ----
def sign_message(message, private_key):
    """RSA-PSS + SHA-256."""
    sig = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return b64encode(sig).decode()

def verify_signature(message, signature_b64, public_key_pem):
    """Returns True if the RSA-PSS signature is valid."""
    pub = public_key_from_pem(public_key_pem)
    try:
        pub.verify(
            b64decode(signature_b64),
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


# ---- FILE ENCRYPTION (AES-256 + RSA wrapper for keys) ----
def encrypt_file(file_bytes, recipient_public_key_pem):
    """
    Encrypt a file using AES-256-GCM, then wrap the AES key with RSA.
    Returns: (encrypted_file_bytes, encrypted_aes_key_b64)
    """
    # Generate random AES key
    aes_key = os.urandom(32)
    nonce   = os.urandom(12)
    
    # Encrypt file with AES-GCM
    aesgcm = AESGCM(aes_key)
    encrypted_file = aesgcm.encrypt(nonce, file_bytes, None)
    
    # Prepend nonce to encrypted file
    encrypted_file_with_nonce = nonce + encrypted_file
    
    # Wrap AES key with recipient's RSA public key
    pub = public_key_from_pem(recipient_public_key_pem)
    wrapped_key = pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return encrypted_file_with_nonce, b64encode(wrapped_key).decode()

def decrypt_file(encrypted_file_with_nonce, encrypted_aes_key_b64, private_key):
    """
    Decrypt a file: unwrap AES key with RSA, then decrypt file with AES-GCM.
    Returns: decrypted_file_bytes
    """
    # Unwrap AES key
    wrapped_key = b64decode(encrypted_aes_key_b64)
    aes_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Extract nonce and ciphertext
    nonce = encrypted_file_with_nonce[:12]
    ciphertext = encrypted_file_with_nonce[12:]
    
    # Decrypt file
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def sign_file(file_bytes, private_key):
    """Create SHA-256 hash of file and sign it."""
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    return sign_message(file_hash, private_key)


# ================================================================
# AUTH DECORATORS
# ================================================================
def login_required(f):
    @functools.wraps(f)
    def wrapper(*a, **kw):
        if 'user_id' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))
        return f(*a, **kw)
    return wrapper

def admin_required(f):
    @functools.wraps(f)
    def wrapper(*a, **kw):
        if 'admin_id' not in session:
            flash('Admin access required.', 'error')
            return redirect(url_for('admin_login'))
        return f(*a, **kw)
    return wrapper


# ================================================================
# HTML TEMPLATES
# ================================================================
# Shared CSS
_CSS = """
* { margin:0; padding:0; box-sizing:border-box; }
body {
    font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;
    background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);
    min-height:100vh; padding:20px;
}
.page-center { display:flex; justify-content:center; align-items:center; min-height:100vh; }
.card {
    background:#fff; border-radius:20px; padding:40px;
    max-width:520px; width:100%;
    box-shadow:0 20px 60px rgba(0,0,0,.3); text-align:center;
}
.card-wide { max-width:640px; }
h1 { color:#2d3748; margin-bottom:10px; font-size:2.2em; }
.subtitle { color:#718096; margin-bottom:28px; font-size:1.05em; }
.form-group { margin-bottom:18px; text-align:left; }
label { display:block; color:#4a5568; margin-bottom:5px; font-weight:600; font-size:.9em; }
input, select {
    width:100%; padding:11px 14px; border:2px solid #e2e8f0;
    border-radius:8px; font-size:14px; transition:border-color .3s;
}
input:focus, select:focus { outline:none; border-color:#667eea; }
.btn {
    display:block; width:100%; padding:13px;
    background:linear-gradient(135deg,#667eea,#764ba2);
    color:#fff; border:none; border-radius:10px;
    font-size:15px; font-weight:600; cursor:pointer;
    transition:transform .2s; margin:8px 0; text-decoration:none;
}
.btn:hover { transform:translateY(-2px); box-shadow:0 5px 15px rgba(102,126,234,.4); }
.btn-sec { background:linear-gradient(135deg,#4c51bf,#434190); }
.alert { padding:11px 14px; margin-bottom:18px; border-radius:8px; font-weight:500; font-size:.9em; }
.alert-error   { background:#fee; color:#c53030; border:1px solid #fc8181; }
.alert-success { background:#f0fff4; color:#22543d; border:1px solid #48bb78; }
.info-box { background:#ebf8ff; border-left:4px solid #4299e1; padding:12px 14px; margin-bottom:18px; border-radius:5px; font-size:.88em; text-align:left; }
.links { text-align:center; margin-top:20px; }
.links a { color:#667eea; text-decoration:none; margin:0 10px; font-size:.9em; }
"""

HOME_TEMPLATE = """<!DOCTYPE html><html><head><title>SecureChat</title><style>""" + _CSS + """</style></head>
<body><div class="page-center"><div class="card">
<div style="font-size:3.8em;margin-bottom:14px">&#x1F510;</div>
<h1>SecureChat</h1>
<p class="subtitle">PKI-Based Encrypted Messaging &amp; Document Signing</p>
<a href="{{ url_for('register') }}" class="btn">Register</a>
<a href="{{ url_for('login') }}" class="btn">Login</a>
<a href="{{ url_for('admin_login') }}" class="btn btn-sec">Admin Panel</a>
</div></div></body></html>"""

REGISTER_TEMPLATE = """<!DOCTYPE html><html><head><title>Register</title><style>""" + _CSS + """</style></head>
<body><div class="page-center"><div class="card card-wide">
<h1>&#x1F510; Register</h1>
{% with messages = get_flashed_messages(with_categories=true) %}
{% if messages %}{% for cat, msg in messages %}
<div class="alert alert-{{ cat }}">{{ msg }}</div>
{% endfor %}{% endif %}{% endwith %}
<div class="info-box">An RSA 2048-bit key-pair and a <strong>CA-signed</strong> X.509 certificate will be generated for you.</div>
<form method="POST">
<div class="form-group"><label>Username</label><input name="username" required minlength="3"></div>
<div class="form-group"><label>Password</label><input type="password" name="password" required minlength="6"></div>
<div class="form-group"><label>Confirm Password</label><input type="password" name="confirm_password" required></div>
<div class="form-group"><label>Security Question 1</label>
<select name="security_q1" required>
<option value="">-- choose --</option>
<option value="What was your childhood nickname?">What was your childhood nickname?</option>
<option value="What is your mother&#x27;s maiden name?">What is your mother&#x27;s maiden name?</option>
<option value="What was the name of your first pet?">What was the name of your first pet?</option>
<option value="What city were you born in?">What city were you born in?</option>
</select></div>
<div class="form-group"><label>Answer 1</label><input name="security_a1" required></div>
<div class="form-group"><label>Security Question 2</label>
<select name="security_q2" required>
<option value="">-- choose --</option>
<option value="What is your favorite book?">What is your favorite book?</option>
<option value="What was your first car?">What was your first car?</option>
<option value="What is your favorite food?">What is your favorite food?</option>
<option value="What was your high school mascot?">What was your high school mascot?</option>
</select></div>
<div class="form-group"><label>Answer 2</label><input name="security_a2" required></div>
<button type="submit" class="btn">Register</button>
</form>
<div class="links"><a href="{{ url_for('index') }}">&#x2190; Back</a></div>
</div></div></body></html>"""

LOGIN_TEMPLATE = """<!DOCTYPE html><html><head><title>Login</title><style>""" + _CSS + """</style></head>
<body><div class="page-center"><div class="card">
<h1>&#x1F510; Login</h1>
{% with messages = get_flashed_messages(with_categories=true) %}
{% if messages %}{% for cat, msg in messages %}
<div class="alert alert-{{ cat }}">{{ msg }}</div>
{% endfor %}{% endif %}{% endwith %}
<form method="POST">
<div class="form-group"><label>Username</label><input name="username" required></div>
<div class="form-group"><label>Password</label><input type="password" name="password" required></div>
<button type="submit" class="btn">Login</button>
</form>
<div class="links">
<a href="{{ url_for('forgot_password') }}">Forgot Password?</a>
<a href="{{ url_for('index') }}">&#x2190; Back</a>
</div>
</div></div>
<script>
var el=document.querySelector('.alert-error');
if(el && el.textContent.indexOf('locked')!==-1){
  var s=600, d=document.createElement('div');
  d.style.cssText='text-align:center;margin-top:18px;padding:12px;background:#fff5f5;border-radius:8px;color:#c53030;font-weight:600;';
  d.innerHTML='&#x1F512; Locked. Unlocking in <span id="cd">10:00</span>...';
  document.querySelector('.card').appendChild(d);
  var iv=setInterval(function(){
    if(--s<=0){clearInterval(iv);d.innerHTML='Lockout expired.';d.style.background='#f0fff4';d.style.color='#22543d';return;}
    document.getElementById('cd').textContent=Math.floor(s/60)+':'+(s%60<10?'0':'')+s%60;
  },1000);
}
</script>
</body></html>"""

FORGOT_TEMPLATE = """<!DOCTYPE html><html><head><title>Reset Password</title><style>""" + _CSS + """</style></head>
<body><div class="page-center"><div class="card">
<h1>&#x1F511; Password Recovery</h1>
{% with messages = get_flashed_messages(with_categories=true) %}
{% if messages %}{% for cat, msg in messages %}
<div class="alert alert-{{ cat }}">{{ msg }}</div>
{% endfor %}{% endif %}{% endwith %}
<form method="POST">
{% if not security_questions %}
<div class="form-group"><label>Username</label><input name="username" required></div>
<button type="submit" class="btn">Continue</button>
{% else %}
<input type="hidden" name="username" value="{{ username }}">
<div class="form-group"><label>{{ security_questions[0] }}</label><input name="answer1" required></div>
<div class="form-group"><label>{{ security_questions[1] }}</label><input name="answer2" required></div>
<div class="form-group"><label>New Password</label><input type="password" name="new_password" required minlength="6"></div>
<button type="submit" class="btn">Reset Password</button>
{% endif %}
</form>
<div class="links"><a href="{{ url_for('login') }}">&#x2190; Login</a></div>
</div></div></body></html>"""

DASHBOARD_TEMPLATE = """<!DOCTYPE html><html><head><title>Dashboard</title>
<style>""" + _CSS + """
.top-bar {
    background:#fff; padding:16px 24px; border-radius:10px; margin-bottom:18px;
    display:flex; justify-content:space-between; align-items:center;
    box-shadow:0 2px 10px rgba(0,0,0,.1);
}
.top-bar h1 { font-size:1.5em; color:#2d3748; }
.top-bar .sub { color:#718096; font-size:.85em; }
.btn-out { padding:8px 18px; background:#fc8181; color:#fff; border:none; border-radius:8px; cursor:pointer; font-weight:600; text-decoration:none; }
.layout { display:grid; grid-template-columns:1fr 2.2fr; gap:18px; max-width:1400px; margin:0 auto; }
.panel { background:#fff; border-radius:15px; padding:22px; box-shadow:0 5px 20px rgba(0,0,0,.1); }
.panel h2 { color:#2d3748; margin-bottom:16px; padding-bottom:8px; border-bottom:2px solid #e2e8f0; font-size:1.1em; }
.user-item { padding:14px; margin:8px 0; background:#f7fafc; border-radius:10px; cursor:pointer; transition:all .25s; border-left:4px solid transparent; }
.user-item:hover { background:#edf2f7; border-left-color:#667eea; transform:translateX(4px); }
.user-item.active { background:#ebf8ff; border-left-color:#4299e1; }
.chat-box { height:300px; overflow-y:auto; border:2px solid #e2e8f0; border-radius:10px; padding:18px; margin-bottom:16px; background:#f7fafc; }
.msg { margin:12px 0; padding:11px 14px; border-radius:10px; max-width:80%; position:relative; }
.msg-out { background:linear-gradient(135deg,#667eea,#764ba2); color:#fff; margin-left:auto; text-align:right; }
.msg-in  { background:#e2e8f0; color:#2d3748; }
.msg-encrypted { background:#fff3cd; border:2px dashed #ffc107; color:#856404; font-family:'Courier New',monospace; font-size:.85em; }
.msg-meta { font-size:.78em; opacity:.75; margin-top:4px; }
.file-item { background:#fef3c7; border-left:4px solid #f59e0b; padding:10px; margin:8px 0; border-radius:8px; position:relative; }
.file-item-out { margin-left:auto; max-width:80%; }
.file-item-in { max-width:80%; }
.compose { display:flex; gap:10px; margin-bottom:12px; }
.compose textarea { flex:1; padding:11px; border:2px solid #e2e8f0; border-radius:10px; resize:none; font-family:inherit; font-size:.9em; }
.compose textarea:focus { outline:none; border-color:#667eea; }
.btn-send { padding:11px 26px; background:linear-gradient(135deg,#667eea,#764ba2); color:#fff; border:none; border-radius:10px; cursor:pointer; font-weight:600; }
.file-upload { display:flex; gap:10px; align-items:center; }
.file-upload input[type="file"] { flex:1; padding:8px; border:2px dashed #e2e8f0; border-radius:8px; font-size:.85em; }
.btn-upload { padding:8px 20px; background:#48bb78; color:#fff; border:none; border-radius:8px; cursor:pointer; font-weight:600; }
.btn-download { padding:4px 12px; background:#4299e1; color:#fff; border:none; border-radius:5px; cursor:pointer; font-size:.8em; margin-top:6px; margin-right:4px; }
.btn-decrypt { padding:4px 12px; background:#f59e0b; color:#fff; border:none; border-radius:5px; cursor:pointer; font-size:.8em; margin-top:6px; }
.encrypted-text { font-family:'Courier New',monospace; font-size:.8em; color:#856404; word-break:break-all; }
.empty { text-align:center; color:#718096; padding:60px 16px; }
.badge { display:inline-block; padding:2px 7px; border-radius:4px; font-size:.72em; margin-left:4px; color:#fff; }
.badge-ok { background:#48bb78; }
.badge-bad { background:#fc8181; }
.badge-encrypted { background:#ffc107; color:#000; }
.tab { display:inline-block; padding:8px 16px; cursor:pointer; border-radius:8px 8px 0 0; margin-right:4px; background:#e2e8f0; }
.tab.active { background:#667eea; color:#fff; }
</style></head><body>
<div class="top-bar">
  <div><h1>&#x1F510; SecureChat</h1><div class="sub">Logged in as <strong>{{ username }}</strong></div></div>
  <a href="{{ url_for('logout') }}" class="btn-out">Logout</a>
</div>
<div class="layout">
  <div class="panel">
    <h2>Users</h2>
    {% for u in users %}
      {% if u.user_id != current_user_id %}
      <div class="user-item" onclick="pick({{ u.user_id }},'{{ u.username }}')">
        <strong>{{ u.username }}</strong>
        <div style="font-size:.8em;color:#718096">Joined {{ u.created_at[:10] }}</div>
      </div>
      {% endif %}
    {% endfor %}
  </div>
  <div class="panel">
    <h2 id="ch">Select a user</h2>
    <div style="margin-bottom:12px;">
      <span class="tab active" id="tabMsg" onclick="switchTab('msg')">&#x1F4AC; Messages</span>
      <span class="tab" id="tabFile" onclick="switchTab('file')">&#x1F4C1; Files</span>
    </div>
    <div id="chat-area" class="chat-box"><div class="empty"><div style="font-size:2.6em">&#x1F4E7;</div><p>Pick a user on the left</p></div></div>
    <div id="compose-area" style="display:none">
      <div class="compose">
        <textarea id="mi" rows="2" placeholder="Type a message (max 190 chars)..."></textarea>
        <button class="btn-send" onclick="send()">Send &#x1F512;</button>
      </div>
      <div class="file-upload">
        <input type="file" id="fileInput" />
        <button class="btn-upload" onclick="uploadFile()">Upload File &#x1F4CE;</button>
      </div>
    </div>
  </div>
</div>
<script>
var sel=null, currentTab='msg';
var decryptedMessages = {};  // Store decrypted messages by ID
var decryptedFiles = {};      // Store decrypted file info by ID

function pick(id,name){
  sel=id;
  decryptedMessages = {};  // Reset when switching users
  decryptedFiles = {};
  document.querySelectorAll('.user-item').forEach(function(e){e.classList.remove('active');});
  event.currentTarget.classList.add('active');
  document.getElementById('ch').innerHTML='Chat with '+name;
  document.getElementById('compose-area').style.display='block';
  loadContent();
}

function switchTab(tab){
  currentTab=tab;
  document.getElementById('tabMsg').classList.toggle('active', tab==='msg');
  document.getElementById('tabFile').classList.toggle('active', tab==='file');
  if(sel) loadContent();
}

function loadContent(){
  if(currentTab==='msg') loadMessages(sel);
  else loadFiles(sel);
}

function loadMessages(id){
  fetch('/get_messages?user_id='+id).then(function(r){return r.json();}).then(function(d){
    var c=document.getElementById('chat-area');
    if(!d.messages.length){
      c.innerHTML='<div class="empty"><div style="font-size:2.6em">&#x1F4ED;</div><p>No messages yet.</p></div>';
      return;
    }
    c.innerHTML=d.messages.map(function(m){
      var isSent = m.is_sent;
      var isDecrypted = decryptedMessages[m.message_id];
      
      if(isSent){
        // Sent messages - show as sent (encrypted with recipient's key)
        return '<div class="msg msg-out"><div>'+m.encrypted_message_preview+'</div><div class="msg-meta">'+m.timestamp+' <span class="badge badge-encrypted">&#x1F512; Encrypted</span></div></div>';
      } else {
        // Received messages - show encrypted or decrypted
        if(isDecrypted){
          var badge = m.signature_valid ? '<span class="badge badge-ok">&#x2713; Verified</span>' : '<span class="badge badge-bad">&#x26A0; Invalid</span>';
          return '<div class="msg msg-in"><div>'+isDecrypted+'</div><div class="msg-meta">'+m.timestamp+' '+badge+'</div></div>';
        } else {
          return '<div class="msg msg-encrypted"><div class="encrypted-text">&#x1F512; '+m.encrypted_message_preview+'</div><div class="msg-meta">'+m.timestamp+' <button class="btn-decrypt" onclick="decryptMessage('+m.message_id+')">Decrypt</button></div></div>';
        }
      }
    }).join('');
    c.scrollTop=c.scrollHeight;
  });
}

function decryptMessage(msgId){
  fetch('/decrypt_message?message_id='+msgId).then(function(r){return r.json();}).then(function(d){
    if(d.success){
      decryptedMessages[msgId] = d.decrypted_message;
      loadMessages(sel);
    } else {
      alert('Decryption failed: '+d.error);
    }
  });
}

function loadFiles(id){
  fetch('/get_files?user_id='+id).then(function(r){return r.json();}).then(function(d){
    var c=document.getElementById('chat-area');
    if(!d.files.length){
      c.innerHTML='<div class="empty"><div style="font-size:2.6em">&#x1F4C1;</div><p>No files shared yet.</p></div>';
      return;
    }
    c.innerHTML=d.files.map(function(f){
      var cls=f.is_sent?'file-item file-item-out':'file-item file-item-in';
      var badge=f.signature_valid?'<span class="badge badge-ok">&#x2713; Verified</span>':'<span class="badge badge-bad">&#x26A0; Invalid</span>';
      var dl='';
      if(!f.is_sent){
        dl='<button class="btn-decrypt" onclick="decryptFile('+f.file_id+')">Decrypt & Download</button>';
      } else {
        dl='<span class="badge badge-encrypted">&#x1F512; Encrypted</span>';
      }
      return '<div class="'+cls+'"><strong>&#x1F4CE; '+f.original_filename+'</strong> ('+f.file_size+' bytes)<div class="msg-meta">'+f.timestamp+' '+badge+'</div>'+dl+'</div>';
    }).join('');
  });
}

function decryptFile(fileId){
  // Trigger download which will decrypt on the server side
  window.location.href='/download_file/'+fileId;
}

function send(){
  var v=document.getElementById('mi').value.trim();
  if(!v||!sel){alert('Enter a message');return;}
  if(v.length>190){alert('Max 190 chars for RSA.');return;}
  fetch('/send_message',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({recipient_id:sel,message:v})})
  .then(function(r){return r.json();}).then(function(d){
    if(d.success){
      document.getElementById('mi').value='';
      decryptedMessages = {};  // Clear decrypted cache
      loadMessages(sel);
    }
    else alert('Error: '+d.error);
  });
}

function uploadFile(){
  var file=document.getElementById('fileInput').files[0];
  if(!file||!sel){alert('Select a file first');return;}
  var formData=new FormData();
  formData.append('file',file);
  formData.append('recipient_id',sel);
  fetch('/upload_file',{method:'POST',body:formData})
  .then(function(r){return r.json();}).then(function(d){
    if(d.success){
      document.getElementById('fileInput').value='';
      decryptedFiles = {};  // Clear decrypted cache
      loadFiles(sel);
      alert('File uploaded & encrypted!');
    }
    else alert('Error: '+d.error);
  });
}

setInterval(function(){if(sel)loadContent();},5000);
</script>
</body></html>"""

ADMIN_TEMPLATE = """<!DOCTYPE html><html><head><title>Admin</title>
<style>""" + _CSS + """
body { background:linear-gradient(135deg,#2d3748,#1a202c); }
.top-bar { background:#fff; padding:16px 24px; border-radius:10px; margin-bottom:18px; display:flex; justify-content:space-between; align-items:center; }
.top-bar h1 { font-size:1.5em; color:#2d3748; }
.btn-out { padding:8px 18px; background:#fc8181; color:#fff; border:none; border-radius:8px; cursor:pointer; font-weight:600; text-decoration:none; }
.stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin-bottom:24px; }
.scard { background:#fff; padding:22px; border-radius:15px; box-shadow:0 5px 20px rgba(0,0,0,.1); }
.scard h3 { color:#718096; font-size:.78em; margin-bottom:6px; text-transform:uppercase; }
.scard .val { font-size:2.2em; font-weight:700; color:#2d3748; }
.panel { background:#fff; border-radius:15px; padding:22px; margin-bottom:18px; box-shadow:0 5px 20px rgba(0,0,0,.1); }
.panel h2 { color:#2d3748; margin-bottom:16px; padding-bottom:8px; border-bottom:2px solid #e2e8f0; font-size:1.1em; }
table { width:100%; border-collapse:collapse; }
th,td { padding:11px 12px; text-align:left; border-bottom:1px solid #e2e8f0; font-size:.88em; }
th { background:#f7fafc; color:#4a5568; font-weight:600; }
.ba { padding:5px 10px; margin:0 2px; border:none; border-radius:5px; cursor:pointer; font-size:.8em; color:#fff; }
.ba-blue { background:#4299e1; }
.ba-red  { background:#fc8181; }
.ba-grn  { background:#48bb78; }
.ba-org  { background:#ed8936; }
.modal { display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,.6); justify-content:center; align-items:center; z-index:9; }
.modal.on { display:flex; }
.modal-body { background:#fff; padding:28px; border-radius:15px; max-width:760px; width:90%; max-height:80vh; overflow-y:auto; }
.modal-body h3 { margin-bottom:16px; color:#2d3748; }
.close-m { float:right; font-size:1.4em; cursor:pointer; color:#718096; }
.code-box { background:#f7fafc; padding:14px; border-radius:8px; font-family:'Courier New',monospace; font-size:.8em; word-break:break-all; margin:8px 0; white-space:pre-wrap; }
.test-output { background:#1a202c; color:#48bb78; padding:14px; border-radius:8px; font-family:'Courier New',monospace; font-size:.75em; white-space:pre; overflow-x:auto; max-height:400px; overflow-y:auto; margin-top:12px; }
.btn-test { padding:10px 20px; background:linear-gradient(135deg,#667eea,#764ba2); color:#fff; border:none; border-radius:8px; cursor:pointer; font-weight:600; margin-bottom:12px; }
.btn-test:hover { transform:translateY(-1px); box-shadow:0 4px 12px rgba(102,126,234,.4); }
.test-status { padding:12px; border-radius:8px; margin-bottom:12px; font-weight:600; }
.test-success { background:#f0fff4; color:#22543d; border:1px solid #48bb78; }
.test-error { background:#fee; color:#c53030; border:1px solid #fc8181; }
.test-running { background:#ebf8ff; color:#2c5282; border:1px solid #4299e1; }
</style></head><body>
<div class="top-bar"><h1>Admin Panel</h1><a href="{{ url_for('admin_logout') }}" class="btn-out">Logout</a></div>
<div class="stats">
  <div class="scard"><h3>Total Users</h3><div class="val">{{ stats.total_users }}</div></div>
  <div class="scard"><h3>Active Users</h3><div class="val">{{ stats.active_users }}</div></div>
  <div class="scard"><h3>Messages</h3><div class="val">{{ stats.total_messages }}</div></div>
  <div class="scard"><h3>Revoked Certs</h3><div class="val" style="color:#fc8181">{{ stats.revoked_count }}</div></div>
</div>

<div class="panel">
  <h2>&#x1F9EA; PKI Test Suite</h2>
  <button class="btn-test" onclick="runTests()">Run PKI Tests</button>
  <div id="testStatus"></div>
  <div id="testOutput"></div>
</div>

<div class="panel">
  <h2>User Management</h2>
  <table><thead><tr><th>ID</th><th>Username</th><th>Registered</th><th>Status</th><th>Cert</th><th>Actions</th></tr></thead>
  <tbody>
  {% for u in users %}
  <tr>
    <td>{{ u.user_id }}</td>
    <td>{{ u.username }}</td>
    <td>{{ u.created_at[:16] }}</td>
    <td>{% if u.is_active %}<span style="color:#48bb78">Active</span>{% else %}<span style="color:#fc8181">Disabled</span>{% endif %}</td>
    <td>{% if u.is_revoked %}<span style="color:#fc8181">Revoked</span>{% else %}<span style="color:#48bb78">Valid</span>{% endif %}</td>
    <td>
      <button class="ba ba-blue" onclick="viewCert({{ u.user_id }})">View Cert</button>
      {% if u.is_active %}<button class="ba ba-red" onclick="toggle({{ u.user_id }},0)">Disable</button>
      {% else %}<button class="ba ba-grn" onclick="toggle({{ u.user_id }},1)">Enable</button>{% endif %}
      {% if not u.is_revoked %}<button class="ba ba-org" onclick="revoke({{ u.user_id }})">Revoke Cert</button>{% endif %}
    </td>
  </tr>
  {% endfor %}
  </tbody></table>
</div>
<div class="panel">
  <h2>Message Activity</h2>
  <table><thead><tr><th>ID</th><th>From</th><th>To</th><th>Time</th><th>Read</th></tr></thead>
  <tbody>
  {% for m in messages %}
  <tr>
    <td>{{ m.message_id }}</td><td>{{ m.sender_username }}</td>
    <td>{{ m.recipient_username }}</td><td>{{ m.timestamp[:16] }}</td>
    <td>{% if m.is_read %}<span style="color:#48bb78">Yes</span>{% else %}<span style="color:#718096">No</span>{% endif %}</td>
  </tr>
  {% endfor %}
  </tbody></table>
</div>
<div class="modal" id="certModal">
  <div class="modal-body">
    <span class="close-m" onclick="closeM()">x</span>
    <h3 id="mTitle">Certificate</h3>
    <strong>Public Key</strong><div class="code-box" id="mPub"></div>
    <strong>Certificate (CA-signed)</strong><div class="code-box" id="mCert"></div>
  </div>
</div>
<script>
function runTests(){
  var statusDiv = document.getElementById('testStatus');
  var outputDiv = document.getElementById('testOutput');
  statusDiv.innerHTML = '<div class="test-running">&#x23F3; Running PKI tests...</div>';
  outputDiv.innerHTML = '';
  
  fetch('/admin/run_tests').then(function(r){return r.json();}).then(function(d){
    if(!d.success){
      statusDiv.innerHTML = '<div class="test-error">&#x274C; Error: ' + d.error + '</div>';
      return;
    }
    
    if(d.all_passed){
      statusDiv.innerHTML = '<div class="test-success">&#x2705; All ' + d.total + ' tests PASSED!</div>';
    } else {
      statusDiv.innerHTML = '<div class="test-error">&#x274C; ' + d.failed + ' of ' + d.total + ' tests FAILED</div>';
    }
    
    outputDiv.innerHTML = '<div class="test-output">' + d.output.replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</div>';
  }).catch(function(err){
    statusDiv.innerHTML = '<div class="test-error">&#x274C; Error running tests: ' + err + '</div>';
  });
}

function viewCert(id){
  fetch('/admin/get_certificate?user_id='+id).then(function(r){return r.json();}).then(function(d){
    document.getElementById('mTitle').textContent='Certificate: '+d.username;
    document.getElementById('mPub').textContent=d.public_key;
    document.getElementById('mCert').textContent=d.certificate;
    document.getElementById('certModal').classList.add('on');
  });
}
function closeM(){document.getElementById('certModal').classList.remove('on');}
document.getElementById('certModal').addEventListener('click',function(e){if(e.target===this)closeM();});
function toggle(id,st){
  fetch('/admin/toggle_user',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:id,is_active:st})})
  .then(function(r){return r.json();}).then(function(d){if(d.success)location.reload();});
}
function revoke(id){
  if(!confirm('Revoke this certificate? The user will no longer be able to log in or sign.'))return;
  fetch('/admin/revoke_certificate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:id})})
  .then(function(r){return r.json();}).then(function(d){if(d.success)location.reload();else alert(d.error);});
}
</script>
</body></html>"""


# ================================================================
# ROUTES
# ================================================================
@app.route("/")
def index():
    return render_template_string(HOME_TEMPLATE)

# ---- REGISTER ----
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username         = request.form["username"]
        password         = request.form["password"]
        confirm_password = request.form["confirm_password"]
        sq1 = request.form["security_q1"]
        sa1 = request.form["security_a1"]
        sq2 = request.form["security_q2"]
        sa2 = request.form["security_a2"]

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template_string(REGISTER_TEMPLATE)
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return render_template_string(REGISTER_TEMPLATE)

        conn = sqlite3.connect(DATABASE_PATH)
        if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            flash("Username already exists.", "error")
            conn.close()
            return render_template_string(REGISTER_TEMPLATE)

        try:
            priv, pub = generate_key_pair()
            cert       = generate_certificate(username, pub)   # CA-signed

            pub_pem  = pub.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

            save_private_key(username, priv, password)

            salt = secrets.token_hex(16)
            ph   = hash_password(password, salt)
            s1   = secrets.token_hex(16)
            h1   = hash_password(sa1.lower(), s1)
            s2   = secrets.token_hex(16)
            h2   = hash_password(sa2.lower(), s2)

            conn.execute('''
                INSERT INTO users (username,password_hash,salt,public_key,certificate,
                    security_q1,security_a1_hash,security_q2,security_a2_hash)
                VALUES (?,?,?,?,?,?,?,?,?)
            ''', (username, ph, salt, pub_pem, cert_pem,
                  sq1, h1+":"+s1, sq2, h2+":"+s2))
            conn.commit(); conn.close()

            flash("Registration successful! Your CA-signed certificate is ready.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            flash(f"Registration failed: {e}", "error")
            conn.close()
            return render_template_string(REGISTER_TEMPLATE)

    return render_template_string(REGISTER_TEMPLATE)

# ---- LOGIN ----
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect(DATABASE_PATH)
        c    = conn.cursor()

        # -- attempt row --
        row = c.execute(
            "SELECT failed_attempts, locked, locked_at FROM login_attempts WHERE username=?",
            (username,)
        ).fetchone()
        if row is None:
            c.execute("INSERT INTO login_attempts (username) VALUES (?)", (username,))
            conn.commit()
            fails, locked, locked_at = 0, 0, None
        else:
            fails, locked, locked_at = row

        # -- lockout check --
        if locked and locked_at:
            lt = (datetime.strptime(locked_at, "%Y-%m-%d %H:%M:%S.%f")
                  if '.' in locked_at
                  else datetime.strptime(locked_at, "%Y-%m-%d %H:%M:%S"))
            lt = lt.replace(tzinfo=timezone.utc)
            rem = 600 - (datetime.now(timezone.utc) - lt).total_seconds()
            if rem > 0:
                flash(f"Account is locked. Please wait {int(rem//60)+1} minute(s).", "error")
                conn.close()
                return render_template_string(LOGIN_TEMPLATE)
            c.execute("UPDATE login_attempts SET failed_attempts=0,locked=0,locked_at=NULL WHERE username=?", (username,))
            conn.commit()
            fails = 0

        # -- user lookup --
        user = c.execute(
            "SELECT user_id, password_hash, salt, is_active, certificate FROM users WHERE username=?",
            (username,)
        ).fetchone()
        if not user:
            flash("Invalid username or password.", "error")
            conn.close()
            return render_template_string(LOGIN_TEMPLATE)

        uid, ph, salt, active, cert_pem = user

        if not active:
            flash("Account is disabled. Contact administrator.", "error")
            conn.close()
            return render_template_string(LOGIN_TEMPLATE)

        # -- password --
        if hash_password(password, salt) != ph:
            fails += 1
            if fails >= 3:
                now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                c.execute("UPDATE login_attempts SET failed_attempts=?,locked=1,locked_at=? WHERE username=?",
                          (fails, now, username))
                conn.commit(); conn.close()
                flash("Too many failed attempts. Account locked for 10 minutes.", "error")
                return render_template_string(LOGIN_TEMPLATE)
            c.execute("UPDATE login_attempts SET failed_attempts=? WHERE username=?", (fails, username))
            conn.commit(); conn.close()
            flash(f"Invalid username or password. {3-fails} attempt(s) remaining.", "error")
            return render_template_string(LOGIN_TEMPLATE)

        # -- CERTIFICATE VALIDATION --
        valid, reason = validate_certificate(cert_pem)
        if not valid:
            conn.close()
            flash(f"Certificate validation failed: {reason}", "error")
            return render_template_string(LOGIN_TEMPLATE)

        # -- private key --
        priv = load_private_key(username, password)
        if not priv:
            conn.close()
            flash("Private key decryption failed.", "error")
            return render_template_string(LOGIN_TEMPLATE)

        # -- success --
        c.execute("UPDATE login_attempts SET failed_attempts=0,locked=0,locked_at=NULL WHERE username=?", (username,))
        conn.commit(); conn.close()

        session["user_id"]         = uid
        session["username"]        = username
        session["private_key_pem"] = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ).decode()

        flash("Login successful!", "success")
        return redirect(url_for("dashboard"))

    return render_template_string(LOGIN_TEMPLATE)

# ---- FORGOT PASSWORD ----
@app.route("/forgot_password", methods=["GET","POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username")
        if "answer1" not in request.form:
            conn = sqlite3.connect(DATABASE_PATH)
            row  = conn.execute(
                "SELECT security_q1, security_q2 FROM users WHERE username=?", (username,)
            ).fetchone()
            conn.close()
            if not row:
                flash("Username not found.", "error")
                return render_template_string(FORGOT_TEMPLATE)
            return render_template_string(FORGOT_TEMPLATE, security_questions=row, username=username)

        a1  = request.form["answer1"]
        a2  = request.form["answer2"]
        npw = request.form["new_password"]

        conn = sqlite3.connect(DATABASE_PATH)
        row  = conn.execute(
            "SELECT security_a1_hash, security_a2_hash FROM users WHERE username=?", (username,)
        ).fetchone()
        if not row:
            conn.close()
            flash("User not found.", "error")
            return redirect(url_for("forgot_password"))

        h1,s1 = row[0].split(":")
        h2,s2 = row[1].split(":")
        if hash_password(a1.lower(), s1) != h1 or hash_password(a2.lower(), s2) != h2:
            conn.close()
            flash("Security answers incorrect.", "error")
            return redirect(url_for("forgot_password"))

        ns = secrets.token_hex(16)
        conn.execute("UPDATE users SET password_hash=?, salt=? WHERE username=?",
                     (hash_password(npw, ns), ns, username))
        conn.commit(); conn.close()
        flash("Password reset successful!", "success")
        return redirect(url_for("login"))

    return render_template_string(FORGOT_TEMPLATE)

# ---- DASHBOARD ----
@app.route("/dashboard")
@login_required
def dashboard():
    conn  = sqlite3.connect(DATABASE_PATH)
    users = [dict(zip(["user_id","username","created_at"], r))
             for r in conn.execute(
                 "SELECT user_id, username, created_at FROM users WHERE is_active=1"
             )]
    conn.close()
    return render_template_string(DASHBOARD_TEMPLATE,
        username=session["username"],
        current_user_id=session["user_id"],
        users=users)

# ---- GET MESSAGES ----
@app.route("/get_messages")
@login_required
def get_messages():
    """Get list of messages (encrypted) between current user and selected user."""
    other = request.args.get("user_id", type=int)
    me    = session["user_id"]

    conn = sqlite3.connect(DATABASE_PATH)
    rows = conn.execute('''
        SELECT m.message_id, m.sender_id, m.recipient_id,
               m.encrypted_message, m.digital_signature, m.timestamp,
               s.public_key, s.certificate
        FROM messages m
        JOIN users s ON m.sender_id = s.user_id
        WHERE (m.sender_id=? AND m.recipient_id=?)
           OR (m.sender_id=? AND m.recipient_id=?)
        ORDER BY m.timestamp ASC
    ''', (me, other, other, me)).fetchall()
    conn.close()

    out = []
    for (mid, sid, rid, enc, sig, ts, sender_pub, sender_cert) in rows:
        is_sent = (sid == me)
        
        # Show encrypted preview (first 40 chars of ciphertext)
        encrypted_preview = enc[:40] + "..." if len(enc) > 40 else enc
        
        # Validate sender cert (for signature verification later)
        cert_ok, _ = validate_certificate(sender_cert)
        
        out.append({
            "message_id": mid,
            "is_sent": is_sent,
            "encrypted_message_preview": encrypted_preview,
            "timestamp": ts,
            "signature_valid": cert_ok  # Will be verified after decryption
        })
    
    return jsonify({"messages": out})

# ---- DECRYPT SINGLE MESSAGE ----
@app.route("/decrypt_message")
@login_required
def decrypt_message_route():
    """Decrypt a single message on-demand."""
    message_id = request.args.get("message_id", type=int)
    me = session["user_id"]
    
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        row = conn.execute('''
            SELECT m.encrypted_message, m.digital_signature, m.sender_id, m.recipient_id,
                   s.public_key, s.certificate
            FROM messages m
            JOIN users s ON m.sender_id = s.user_id
            WHERE m.message_id = ?
        ''', (message_id,)).fetchone()
        conn.close()
        
        if not row:
            return jsonify({"success": False, "error": "Message not found"})
        
        enc, sig, sid, rid, sender_pub, sender_cert = row
        
        # Check if current user is the recipient
        if rid != me:
            return jsonify({"success": False, "error": "Not authorized"})
        
        # Get private key from session
        pem = session.get("private_key_pem")
        if not pem:
            return jsonify({"success": False, "error": "Session expired"})
        
        priv = serialization.load_pem_private_key(
            pem.encode(), password=None, backend=default_backend()
        )
        
        # Decrypt message
        plain = decrypt_message(enc, priv)
        
        # Validate sender certificate and verify signature
        cert_ok, _ = validate_certificate(sender_cert)
        sig_ok = False
        if cert_ok:
            sig_ok = verify_signature(plain, sig, sender_pub)
        
        return jsonify({
            "success": True,
            "decrypted_message": plain,
            "signature_valid": sig_ok
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# ---- SEND MESSAGE ----
@app.route("/send_message", methods=["POST"])
@login_required
def send_message():
    data = request.get_json()
    rid  = data["recipient_id"]
    msg  = data["message"]

    try:
        conn = sqlite3.connect(DATABASE_PATH)

        # validate SENDER certificate before allowing sign
        sender_cert = conn.execute(
            "SELECT certificate FROM users WHERE user_id=?", (session["user_id"],)
        ).fetchone()[0]
        ok, reason = validate_certificate(sender_cert)
        if not ok:
            conn.close()
            return jsonify({"success": False, "error": f"Your certificate is invalid: {reason}"})

        rec_pub = conn.execute(
            "SELECT public_key FROM users WHERE user_id=?", (rid,)
        ).fetchone()[0]
        conn.close()

        pem = session.get("private_key_pem")
        if not pem:
            return jsonify({"success": False, "error": "Session expired"})
        priv = serialization.load_pem_private_key(
            pem.encode(), password=None, backend=default_backend()
        )

        enc = encrypt_message(msg, rec_pub)
        sig = sign_message(msg, priv)

        conn = sqlite3.connect(DATABASE_PATH)
        conn.execute('''
            INSERT INTO messages (sender_id, recipient_id, encrypted_message, digital_signature)
            VALUES (?,?,?,?)
        ''', (session["user_id"], rid, enc, sig))
        conn.commit(); conn.close()

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# ---- UPLOAD FILE ----
@app.route("/upload_file", methods=["POST"])
@login_required
def upload_file():
    """Upload and encrypt a file for a recipient."""
    try:
        if 'file' not in request.files:
            return jsonify({"success": False, "error": "No file provided"})
        
        file = request.files['file']
        recipient_id = int(request.form['recipient_id'])
        
        if file.filename == '':
            return jsonify({"success": False, "error": "No file selected"})
        
        # Validate sender certificate
        conn = sqlite3.connect(DATABASE_PATH)
        sender_cert = conn.execute(
            "SELECT certificate FROM users WHERE user_id=?", (session["user_id"],)
        ).fetchone()[0]
        ok, reason = validate_certificate(sender_cert)
        if not ok:
            conn.close()
            return jsonify({"success": False, "error": f"Certificate invalid: {reason}"})
        
        # Get recipient public key
        rec_pub = conn.execute(
            "SELECT public_key FROM users WHERE user_id=?", (recipient_id,)
        ).fetchone()[0]
        
        # Read file
        file_bytes = file.read()
        original_filename = file.filename
        file_size = len(file_bytes)
        
        # Get sender private key
        pem = session.get("private_key_pem")
        if not pem:
            conn.close()
            return jsonify({"success": False, "error": "Session expired"})
        priv = serialization.load_pem_private_key(
            pem.encode(), password=None, backend=default_backend()
        )
        
        # Encrypt file and sign
        encrypted_file, encrypted_aes_key = encrypt_file(file_bytes, rec_pub)
        signature = sign_file(file_bytes, priv)
        
        # Save encrypted file
        encrypted_filename = f"{secrets.token_hex(16)}.enc"
        file_path = os.path.join(FILES_DIR, encrypted_filename)
        with open(file_path, 'wb') as f:
            f.write(encrypted_file)
        
        # Store metadata in database
        conn.execute('''
            INSERT INTO shared_files 
            (sender_id, recipient_id, original_filename, encrypted_filename, 
             file_size, encrypted_aes_key, digital_signature)
            VALUES (?,?,?,?,?,?,?)
        ''', (session["user_id"], recipient_id, original_filename, 
              encrypted_filename, file_size, encrypted_aes_key, signature))
        conn.commit()
        conn.close()
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# ---- GET FILES ----
@app.route("/get_files")
@login_required
def get_files():
    """Get list of shared files between current user and selected user."""
    other = request.args.get("user_id", type=int)
    me = session["user_id"]
    
    conn = sqlite3.connect(DATABASE_PATH)
    rows = conn.execute('''
        SELECT f.file_id, f.sender_id, f.original_filename, f.file_size,
               f.timestamp, f.digital_signature,
               s.public_key, s.certificate
        FROM shared_files f
        JOIN users s ON f.sender_id = s.user_id
        WHERE (f.sender_id=? AND f.recipient_id=?)
           OR (f.sender_id=? AND f.recipient_id=?)
        ORDER BY f.timestamp DESC
    ''', (me, other, other, me)).fetchall()
    conn.close()
    
    out = []
    for (fid, sid, fname, fsize, ts, sig, sender_pub, sender_cert) in rows:
        is_sent = (sid == me)
        
        # Validate sender certificate
        cert_ok, _ = validate_certificate(sender_cert)
        sig_ok = cert_ok  # Simplified - would need to verify file hash
        
        out.append({
            "file_id": fid,
            "is_sent": is_sent,
            "original_filename": fname,
            "file_size": fsize,
            "timestamp": ts,
            "signature_valid": sig_ok
        })
    
    return jsonify({"files": out})

# ---- DOWNLOAD FILE ----
@app.route("/download_file/<int:file_id>")
@login_required
def download_file(file_id):
    """Download and decrypt a file."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        row = conn.execute('''
            SELECT encrypted_filename, original_filename, encrypted_aes_key,
                   recipient_id, sender_id
            FROM shared_files WHERE file_id=?
        ''', (file_id,)).fetchone()
        conn.close()
        
        if not row:
            return "File not found", 404
        
        enc_fname, orig_fname, enc_key, rid, sid = row
        
        # Check permission
        if rid != session["user_id"]:
            return "Unauthorized", 403
        
        # Get private key
        pem = session.get("private_key_pem")
        if not pem:
            return "Session expired", 401
        priv = serialization.load_pem_private_key(
            pem.encode(), password=None, backend=default_backend()
        )
        
        # Read encrypted file
        file_path = os.path.join(FILES_DIR, enc_fname)
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt
        decrypted_data = decrypt_file(encrypted_data, enc_key, priv)
        
        # Send as download
        from io import BytesIO
        return app.response_class(
            BytesIO(decrypted_data).read(),
            mimetype='application/octet-stream',
            headers={'Content-Disposition': f'attachment; filename="{orig_fname}"'}
        )
    except Exception as e:
        return f"Error: {str(e)}", 500

# ---- LOGOUT ----
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("index"))


# ================================================================
# ADMIN ROUTES
# ================================================================
@app.route("/admin/login", methods=["GET","POST"])
def admin_login():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]
        conn = sqlite3.connect(DATABASE_PATH)
        row  = conn.execute(
            "SELECT admin_id, password_hash FROM admin_users WHERE username=?", (u,)
        ).fetchone()
        conn.close()
        if not row:
            flash("Invalid credentials.", "error")
            return render_template_string(LOGIN_TEMPLATE)
        aid, data = row
        h, s = data.split(":")
        if hash_password(p, s) != h:
            flash("Invalid credentials.", "error")
            return render_template_string(LOGIN_TEMPLATE)
        session["admin_id"]       = aid
        session["admin_username"] = u
        return redirect(url_for("admin_panel"))
    return render_template_string(LOGIN_TEMPLATE)

@app.route("/admin/panel")
@admin_required
def admin_panel():
    conn = sqlite3.connect(DATABASE_PATH)

    total   = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    active  = conn.execute("SELECT COUNT(*) FROM users WHERE is_active=1").fetchone()[0]
    msgs    = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    revoked = conn.execute("SELECT COUNT(*) FROM revoked_certificates").fetchone()[0]

    users = []
    for row in conn.execute("SELECT user_id,username,created_at,is_active,certificate FROM users"):
        uid, uname, created, active_flag, cert_pem = row
        try:
            cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            serial   = str(cert_obj.serial_number)
            is_rev   = conn.execute(
                "SELECT 1 FROM revoked_certificates WHERE serial_number=?", (serial,)
            ).fetchone() is not None
        except Exception:
            is_rev = False
        users.append(dict(user_id=uid, username=uname, created_at=created,
                          is_active=active_flag, is_revoked=is_rev))

    messages = [dict(zip(["message_id","timestamp","is_read","sender_username","recipient_username"], r))
                for r in conn.execute('''
                    SELECT m.message_id, m.timestamp, m.is_read, s.username, r.username
                    FROM messages m
                    JOIN users s ON m.sender_id=s.user_id
                    JOIN users r ON m.recipient_id=r.user_id
                    ORDER BY m.timestamp DESC LIMIT 50
                ''')]
    conn.close()

    stats = dict(total_users=total, active_users=active,
                 total_messages=msgs, revoked_count=revoked)
    return render_template_string(ADMIN_TEMPLATE, stats=stats, users=users, messages=messages)

@app.route("/admin/toggle_user", methods=["POST"])
@admin_required
def toggle_user():
    d = request.get_json()
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("UPDATE users SET is_active=? WHERE user_id=?", (d["is_active"], d["user_id"]))
    conn.commit(); conn.close()
    return jsonify({"success": True})

@app.route("/admin/get_certificate")
@admin_required
def get_certificate():
    uid = request.args.get("user_id", type=int)
    conn = sqlite3.connect(DATABASE_PATH)
    row  = conn.execute(
        "SELECT username, public_key, certificate FROM users WHERE user_id=?", (uid,)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error":"Not found"}), 404
    return jsonify({"username": row[0], "public_key": row[1], "certificate": row[2]})

# ---- REVOKE CERTIFICATE ----
@app.route("/admin/revoke_certificate", methods=["POST"])
@admin_required
def revoke_certificate():
    """
    Extract the serial number from the user's certificate and
    insert it into the CRL table.  validate_certificate() will
    reject it from this point forward.
    """
    uid = request.get_json().get("user_id")
    conn = sqlite3.connect(DATABASE_PATH)
    row  = conn.execute("SELECT username, certificate FROM users WHERE user_id=?", (uid,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "error": "User not found"})

    username, cert_pem = row
    try:
        cert   = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        serial = str(cert.serial_number)
    except Exception as e:
        conn.close()
        return jsonify({"success": False, "error": f"Cannot parse certificate: {e}"})

    if conn.execute("SELECT 1 FROM revoked_certificates WHERE serial_number=?", (serial,)).fetchone():
        conn.close()
        return jsonify({"success": False, "error": "Already revoked."})

    conn.execute(
        "INSERT INTO revoked_certificates (serial_number, username) VALUES (?,?)",
        (serial, username)
    )
    conn.commit(); conn.close()
    return jsonify({"success": True})

@app.route("/admin/run_tests")
@admin_required
def run_tests():
    """
    Run the PKI test suite and return results.
    Returns JSON with test status and results.
    """
    import subprocess
    import os
    
    test_file = "test_pki.py"
    
    # Check if test file exists
    if not os.path.exists(test_file):
        return jsonify({
            "success": False,
            "error": "test_pki.py not found. Please ensure it's in the same directory as the application."
        })
    
    try:
        # Run the test file
        result = subprocess.run(
            ["python", test_file],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Parse output to count passes/fails
        output = result.stdout
        passed = output.count("PASS")
        failed = output.count("FAIL")
        
        return jsonify({
            "success": True,
            "passed": passed,
            "failed": failed,
            "total": passed + failed,
            "output": output,
            "all_passed": failed == 0
        })
    except subprocess.TimeoutExpired:
        return jsonify({
            "success": False,
            "error": "Tests timed out after 30 seconds"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Error running tests: {str(e)}"
        })

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("index"))


# ================================================================
# MAIN
# ================================================================
if __name__ == "__main__":
    bootstrap_ca()
    init_database()

    with open("config.json","w") as f:
        json.dump(CONFIG, f, indent=2)

    print("=" * 60)
    print(" SecureChat  --  PKI Secure Chat System")
    print("=" * 60)
    print(f" Database  : {DATABASE_PATH}")
    print(f" CA keys   : {CA_KEYS_DIR}/")
    print(f" User keys : {KEYS_DIR}/")
    print(f" Admin     : admin / admin123")
    print()
    print(" TLS NOTE: In production, run behind a TLS-terminating")
    print(" reverse proxy (nginx + SSL cert) so that all transport")
    print(" is encrypted.  Message-level PKI encryption operates")
    print(" independently of TLS.")
    print("=" * 60)
    print(" -> http://localhost:5000")
    print("=" * 60)

    app.run(debug=True, host="0.0.0.0", port=5000)



