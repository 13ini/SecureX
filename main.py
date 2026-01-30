import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import json
import hashlib
import base64
import os
import sqlite3
import time
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import secrets
import queue
import threading

# ====================== DATABASE SETUP ======================
class Database:
    def __init__(self, db_file="securechat.db"):
        self.db_file = db_file
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                encrypted_private_key TEXT NOT NULL,
                salt TEXT NOT NULL,
                iv TEXT NOT NULL,
                public_key TEXT NOT NULL,
                certificate TEXT NOT NULL,
                security_questions TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Messages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                message TEXT NOT NULL,
                encrypted INTEGER DEFAULT 1,
                signed INTEGER DEFAULT 1,
                signature TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Admin credentials
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        ''')
        
        # Insert default admin if not exists
        admin_salt = os.urandom(16)
        admin_password = "admin123@"
        admin_hash = hashlib.pbkdf2_hmac(
            'sha256',
            admin_password.encode(),
            admin_salt,
            100000
        )
        
        cursor.execute('''
            INSERT OR IGNORE INTO admin (id, email, password_hash, salt)
            VALUES (1, ?, ?, ?)
        ''', ("admin@gmail.com", 
              base64.b64encode(admin_hash).decode(),
              base64.b64encode(admin_salt).decode()))
        
        conn.commit()
        conn.close()
    
    def save_user(self, username, encrypted_private_key, salt, iv, public_key, certificate, security_questions):
        """Save user to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO users 
            (username, encrypted_private_key, salt, iv, public_key, certificate, security_questions)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (username, encrypted_private_key, salt, iv, public_key, 
              json.dumps(certificate), json.dumps(security_questions)))
        
        conn.commit()
        conn.close()
    
    def get_user(self, username):
        """Get user from database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return {
                'username': user[1],
                'encrypted_private_key': user[2],
                'salt': user[3],
                'iv': user[4],
                'public_key': user[5],
                'certificate': json.loads(user[6]),
                'security_questions': json.loads(user[7])
            }
        return None
    
    def get_all_users(self):
        """Get all registered users from database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('SELECT username FROM users')
        users = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        return users
    
    def save_message(self, sender, receiver, message, encrypted=True, signed=True, signature=None):
        """Save message to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO messages (sender, receiver, message, encrypted, signed, signature)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (sender, receiver, message, 1 if encrypted else 0, 1 if signed else 0, signature))
        
        conn.commit()
        conn.close()
    
    def get_messages(self, user1, user2):
        """Get conversation between two users"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM messages 
            WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
            ORDER BY timestamp
        ''', (user1, user2, user2, user1))
        
        messages = cursor.fetchall()
        conn.close()
        return messages
    
    def verify_admin(self, email, password):
        """Verify admin credentials"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('SELECT password_hash, salt FROM admin WHERE email = ?', (email,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            stored_hash = base64.b64decode(result[0])
            salt = base64.b64decode(result[1])
            
            computed_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode(),
                salt,
                100000
            )
            
            return stored_hash == computed_hash
        
        return False

# ====================== JSON STORAGE ======================
class JSONStorage:
    def __init__(self, filename="users.json"):
        self.filename = filename
        self.data = self.load_data()
    
    def load_data(self):
        """Load data from JSON file"""
        if os.path.exists(self.filename):
            try:
                with open(self.filename, 'r') as f:
                    return json.load(f)
            except:
                return {"users": {}, "admin": {"email": "admin@gmail.com", "password": "admin123@"}}
        return {"users": {}, "admin": {"email": "admin@gmail.com", "password": "admin123@"}}
    
    def save_data(self):
        """Save data to JSON file"""
        with open(self.filename, 'w') as f:
            json.dump(self.data, f, indent=4)
    
    def save_user(self, username, user_data):
        """Save user to JSON"""
        self.data["users"][username] = user_data
        self.save_data()
    
    def get_user(self, username):
        """Get user from JSON"""
        return self.data["users"].get(username)

# ====================== STYLES AND COLORS ======================
class Styles:
    # Color Scheme
    PRIMARY = "#2C3E50"      # Dark blue
    SECONDARY = "#3498DB"    # Blue
    SUCCESS = "#2ECC71"      # Green
    DANGER = "#E74C3C"       # Red
    WARNING = "#F39C12"      # Orange
    INFO = "#9B59B6"         # Purple
    LIGHT = "#ECF0F1"        # Light gray
    DARK = "#2C3E50"         # Dark
    BG = "#34495E"           # Background
    CARD_BG = "#2C3E50"      # Card background
    
    # Fonts
    TITLE_FONT = ("Segoe UI", 24, "bold")
    HEADING_FONT = ("Segoe UI", 16, "bold")
    SUBHEADING_FONT = ("Segoe UI", 12, "bold")
    BODY_FONT = ("Segoe UI", 10)
    MONO_FONT = ("Consolas", 9)
    
    # Button Styles
    BTN_PRIMARY = {"bg": SECONDARY, "fg": "white", "font": ("Segoe UI", 10, "bold")}
    BTN_SUCCESS = {"bg": SUCCESS, "fg": "white", "font": ("Segoe UI", 10, "bold")}
    BTN_DANGER = {"bg": DANGER, "fg": "white", "font": ("Segoe UI", 10, "bold")}
    BTN_WARNING = {"bg": WARNING, "fg": "white", "font": ("Segoe UI", 10, "bold")}
    BTN_INFO = {"bg": INFO, "fg": "white", "font": ("Segoe UI", 10, "bold")}
    
    @staticmethod
    def create_rounded_button(parent, text, command, style="primary", width=15):
        """Create a styled rounded button"""
        styles = {
            "primary": Styles.BTN_PRIMARY,
            "success": Styles.BTN_SUCCESS,
            "danger": Styles.BTN_DANGER,
            "warning": Styles.BTN_WARNING,
            "info": Styles.BTN_INFO
        }
        
        btn_style = styles.get(style, Styles.BTN_PRIMARY)
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            **btn_style,
            relief="flat",
            bd=0,
            padx=20,
            pady=8,
            cursor="hand2",
            width=width
        )
        btn.config(activebackground=btn_style["bg"], activeforeground=btn_style["fg"])
        return btn

# ====================== CORE SECURITY CLASSES ======================
class CertificateAuthority:
    def __init__(self):
        self.ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.ca_public_key = self.ca_private_key.public_key()
        self.certificates = {}
        self.revoked_certificates = set()
    
    def issue_certificate(self, user_id, public_key):
        """Issue a digital certificate for a user"""
        cert_data = {
            'user_id': user_id,
            'public_key': public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8'),
            'issue_date': datetime.now().isoformat(),
            'expiry_date': (datetime.now() + timedelta(days=365)).isoformat(),
            'ca_signature': None,
            'serial_number': secrets.token_hex(16)
        }
        
        # Sign the certificate
        data_to_sign = json.dumps({
            'user_id': cert_data['user_id'],
            'public_key': cert_data['public_key'],
            'issue_date': cert_data['issue_date'],
            'expiry_date': cert_data['expiry_date'],
            'serial_number': cert_data['serial_number']
        }, sort_keys=True).encode('utf-8')
        
        signature = self.ca_private_key.sign(
            data_to_sign,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        cert_data['ca_signature'] = base64.b64encode(signature).decode('utf-8')
        self.certificates[user_id] = cert_data
        return cert_data
    
    def verify_certificate(self, cert_data):
        """Verify certificate signature"""
        if cert_data['user_id'] not in self.certificates:
            return False
        
        # Check if revoked
        if cert_data['serial_number'] in self.revoked_certificates:
            return False
        
        # Check expiry
        expiry_date = datetime.fromisoformat(cert_data['expiry_date'])
        if datetime.now() > expiry_date:
            return False
        
        # Verify signature
        data_to_verify = json.dumps({
            'user_id': cert_data['user_id'],
            'public_key': cert_data['public_key'],
            'issue_date': cert_data['issue_date'],
            'expiry_date': cert_data['expiry_date'],
            'serial_number': cert_data['serial_number']
        }, sort_keys=True).encode('utf-8')
        
        signature = base64.b64decode(cert_data['ca_signature'])
        
        try:
            self.ca_public_key.verify(
                signature,
                data_to_verify,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

class SecureUser:
    def __init__(self, username):
        self.username = username
        self.private_key = None
        self.public_key = None
        self.certificate = None
        self.security_questions = {}
        self.encrypted_private_key = None
        self.salt = None
        self.iv = None
    
    def generate_key_pair(self, password):
        """Generate RSA key pair and encrypt private key with password"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Serialize private key
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Encrypt private key
        self.encrypted_private_key, self.salt, self.iv = self._encrypt_with_password(
            private_key_pem, password
        )
        
        return self.public_key
    
    def _encrypt_with_password(self, data, password):
        """Encrypt data with password using AES-CBC"""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        
        # Pad the data
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        return (
            base64.b64encode(encrypted).decode('utf-8'),
            base64.b64encode(salt).decode('utf-8'),
            base64.b64encode(iv).decode('utf-8')
        )
    
    def load_private_key(self, password):
        """Load private key from encrypted storage"""
        try:
            encrypted_bytes = base64.b64decode(self.encrypted_private_key)
            salt_bytes = base64.b64decode(self.salt)
            iv_bytes = base64.b64decode(self.iv)
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt_bytes,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv_bytes), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()
            
            # Unpad the data
            unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
            private_key_pem = unpadder.update(decrypted_padded) + unpadder.finalize()
            
            self.private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
            return True
        except:
            return False
    
    def set_security_questions(self, question, answer):
        """Set one security question and answer (hashed)"""
        if question and answer:
            # Add salt to answer before hashing
            salt = os.urandom(16)
            salted_answer = salt + answer.encode()
            hashed_answer = hashlib.sha256(salted_answer).hexdigest()
            self.security_questions = {
                'question': question,
                'hash': hashed_answer,
                'salt': base64.b64encode(salt).decode('utf-8')
            }
    
    def verify_security_answer(self, answer):
        """Verify security question answer"""
        if not self.security_questions:
            return False
        
        stored_data = self.security_questions
        salt = base64.b64decode(stored_data['salt'])
        salted_answer = salt + answer.encode()
        hashed_answer = hashlib.sha256(salted_answer).hexdigest()
        
        return stored_data['hash'] == hashed_answer
    
    def sign_document(self, document):
        """Sign a document with private key"""
        signature = self.private_key.sign(
            document.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    
    def encrypt_message(self, message, recipient_public_key):
        """Encrypt message for recipient"""
        # For simplicity, we'll encrypt with hybrid encryption
        # Generate a random symmetric key
        symmetric_key = os.urandom(32)
        
        # Encrypt message with symmetric key
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(os.urandom(16)), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encrypt symmetric key with recipient's public key
        encrypted_key = recipient_public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return {
            'encrypted_message': base64.b64encode(encrypted_message).decode('utf-8'),
            'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8')
        }

class SecureChatSystem:
    def __init__(self):
        self.ca = CertificateAuthority()
        self.users = {}
        self.online_users = set()
        self.message_queue = queue.Queue()
        self.db = Database()
        self.json_storage = JSONStorage()
    
    def register_user(self, username, password, security_question, security_answer):
        """Register a new user"""
        if username in self.users:
            return False, "Username already exists"
        
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        
        user = SecureUser(username)
        public_key = user.generate_key_pair(password)
        user.set_security_questions(security_question, security_answer)
        
        # Issue certificate
        certificate = self.ca.issue_certificate(username, public_key)
        user.certificate = certificate
        
        # Save to memory
        self.users[username] = user
        
        # Save to database
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        self.db.save_user(
            username,
            user.encrypted_private_key,
            user.salt,
            user.iv,
            public_key_pem,
            certificate,
            user.security_questions
        )
        
        # Save to JSON
        self.json_storage.save_user(username, {
            'encrypted_private_key': user.encrypted_private_key,
            'salt': user.salt,
            'iv': user.iv,
            'public_key': public_key_pem,
            'certificate': certificate,
            'security_questions': user.security_questions
        })
        
        return True, "Registration successful. Digital certificate issued."
    
    def authenticate_user(self, username, password):
        """Authenticate user with password and certificate"""
        # Try to load from memory first
        if username not in self.users:
            # Load from database
            user_data = self.db.get_user(username)
            if not user_data:
                return False, "User not found"
            
            # Create user object
            user = SecureUser(username)
            user.encrypted_private_key = user_data['encrypted_private_key']
            user.salt = user_data['salt']
            user.iv = user_data['iv']
            user.certificate = user_data['certificate']
            user.security_questions = user_data['security_questions']
            
            # Load public key
            user.public_key = serialization.load_pem_public_key(
                user_data['public_key'].encode(),
                backend=default_backend()
            )
            
            self.users[username] = user
        
        user = self.users[username]
        
        # Load private key with password
        if not user.load_private_key(password):
            return False, "Invalid password"
        
        # Verify certificate
        if not self.ca.verify_certificate(user.certificate):
            return False, "Invalid or revoked certificate"
        
        return True, "Authentication successful. Certificate verified."
    
    def forgot_password(self, username, security_answer):
        """Reset password using security question"""
        if username not in self.users:
            # Load from database
            user_data = self.db.get_user(username)
            if not user_data:
                return False, "User not found"
            
            user = SecureUser(username)
            user.security_questions = user_data['security_questions']
        else:
            user = self.users[username]
        
        if not user.verify_security_answer(security_answer):
            return False, "Incorrect security answer"
        
        return True, "Security answer verified. You can now reset your password."
    
    def reset_password(self, username, new_password):
        """Reset user password"""
        if username not in self.users:
            return False, "User not found"
        
        user = self.users[username]
        
        # Generate new encrypted private key with new password
        private_key_pem = user.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        user.encrypted_private_key, user.salt, user.iv = user._encrypt_with_password(
            private_key_pem, new_password
        )
        
        # Update in database
        public_key_pem = user.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        self.db.save_user(
            username,
            user.encrypted_private_key,
            user.salt,
            user.iv,
            public_key_pem,
            user.certificate,
            user.security_questions
        )
        
        return True, "Password reset successful"
    
    def send_message(self, sender, receiver, message, encrypt=True, sign=True):
        """Send message from sender to receiver"""
        if receiver not in self.users:
            return False, "Receiver not found"
        
        # Sign the message if requested
        signature = None
        if sign:
            signature = self.users[sender].sign_document(message)
        
        # Encrypt the message if requested
        encrypted_message = message
        if encrypt:
            # Get receiver's public key
            receiver_public_key = self.users[receiver].public_key
            encrypted_data = self.users[sender].encrypt_message(message, receiver_public_key)
            encrypted_message = json.dumps(encrypted_data)
        
        # Save to database
        self.db.save_message(sender, receiver, encrypted_message, encrypt, sign, signature)
        
        # Add to message queue for real-time delivery
        self.message_queue.put({
            'sender': sender,
            'receiver': receiver,
            'message': encrypted_message,
            'encrypted': encrypt,
            'signed': sign,
            'signature': signature,
            'timestamp': datetime.now()
        })
        
        return True, "Message sent successfully"

# ====================== GUI APPLICATION ======================
class SecureChatApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SecureChat Pro - PKI Secure Messaging")
        self.root.geometry("1200x800")
        self.root.configure(bg=Styles.BG)
        
        # System
        self.chat_system = SecureChatSystem()
        self.current_user = None
        
        # Create a container for all pages
        self.container = tk.Frame(self.root, bg=Styles.BG)
        self.container.pack(fill="both", expand=True)
        
        # Initialize all frames
        self.frames = {}
        self.create_welcome_page()
        self.create_admin_login_page()
        self.create_admin_panel()
        self.create_registration_page()
        self.create_login_page()
        self.create_forgot_password_page()
        self.create_dashboard_page()
        
        # Show welcome page first
        self.show_frame("WelcomePage")
        
        # Center window
        self.center_window()
    
    def create_welcome_page(self):
        """Create the welcome/intro page"""
        frame = tk.Frame(self.container, bg=Styles.BG)
        self.frames["WelcomePage"] = frame
        
        # Main content
        content_frame = tk.Frame(frame, bg=Styles.BG)
        content_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Logo/Title
        title_label = tk.Label(
            content_frame,
            text="🔒 SecureChat Pro",
            font=Styles.TITLE_FONT,
            bg=Styles.BG,
            fg=Styles.LIGHT
        )
        title_label.pack(pady=(0, 10))
        
        subtitle_label = tk.Label(
            content_frame,
            text="PKI-Based Secure Messaging System",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.BG,
            fg=Styles.SECONDARY
        )
        subtitle_label.pack(pady=(0, 30))
        
        # Features
        features = [
            "✓ Military-Grade Encryption",
            "✓ Digital Certificates",
            "✓ End-to-End Encryption",
            "✓ Secure Document Signing",
            "✓ Password Recovery",
            "✓ Audit Trail"
        ]
        
        for feature in features:
            feature_label = tk.Label(
                content_frame,
                text=feature,
                font=Styles.BODY_FONT,
                bg=Styles.BG,
                fg=Styles.LIGHT
            )
            feature_label.pack(pady=5)
        
        # Buttons
        button_frame = tk.Frame(content_frame, bg=Styles.BG)
        button_frame.pack(pady=30)
        
        admin_btn = Styles.create_rounded_button(
            button_frame,
            "👨‍💼 Admin Login",
            lambda: self.show_frame("AdminLoginPage"),
            "warning",
            20
        )
        admin_btn.pack(side="left", padx=10)
        
        register_btn = Styles.create_rounded_button(
            button_frame,
            "📝 Create Account",
            lambda: self.show_frame("RegistrationPage"),
            "primary",
            20
        )
        register_btn.pack(side="left", padx=10)
        
        login_btn = Styles.create_rounded_button(
            button_frame,
            "🔐 Login",
            lambda: self.show_frame("LoginPage"),
            "success",
            20
        )
        login_btn.pack(side="left", padx=10)
    
    def create_admin_login_page(self):
        """Create admin login page"""
        frame = tk.Frame(self.container, bg=Styles.BG)
        self.frames["AdminLoginPage"] = frame
        
        # Header
        header_frame = tk.Frame(frame, bg=Styles.PRIMARY, height=80)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)
        
        tk.Label(
            header_frame,
            text="Admin Login",
            font=Styles.HEADING_FONT,
            bg=Styles.PRIMARY,
            fg=Styles.LIGHT
        ).pack(pady=20)
        
        # Back button
        back_btn = tk.Button(
            header_frame,
            text="← Back",
            command=lambda: self.show_frame("WelcomePage"),
            font=Styles.BODY_FONT,
            bg=Styles.PRIMARY,
            fg=Styles.LIGHT,
            bd=0,
            cursor="hand2"
        )
        back_btn.place(x=20, y=25)
        
        # Main form
        main_frame = tk.Frame(frame, bg=Styles.BG)
        main_frame.pack(fill="both", expand=True)
        
        # Center container
        center_frame = tk.Frame(main_frame, bg=Styles.BG)
        center_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Login card
        login_card = tk.Frame(center_frame, bg=Styles.CARD_BG, padx=40, pady=40)
        login_card.pack()
        
        # Title
        tk.Label(
            login_card,
            text="👨‍💼 Admin Panel",
            font=Styles.HEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(pady=(0, 30))
        
        # Email
        tk.Label(
            login_card,
            text="Admin Email:",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(anchor="w", pady=(0, 5))
        
        self.admin_email = tk.Entry(
            login_card,
            font=Styles.BODY_FONT,
            width=30,
            bg="#3C4B5D",
            fg=Styles.LIGHT,
            insertbackground=Styles.LIGHT,
            relief="flat"
        )
        self.admin_email.insert(0, "admin@gmail.com")
        self.admin_email.pack(pady=(0, 15), fill="x")
        
        # Password
        tk.Label(
            login_card,
            text="Password:",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(anchor="w", pady=(0, 5))
        
        self.admin_password = tk.Entry(
            login_card,
            font=Styles.BODY_FONT,
            width=30,
            show="•",
            bg="#3C4B5D",
            fg=Styles.LIGHT,
            insertbackground=Styles.LIGHT,
            relief="flat"
        )
        self.admin_password.insert(0, "admin123@")
        self.admin_password.pack(pady=(0, 30), fill="x")
        
        # Login button
        login_btn = Styles.create_rounded_button(
            login_card,
            "🔑 Login as Admin",
            self.admin_login,
            "warning",
            20
        )
        login_btn.pack(pady=(0, 20))
    
    def create_admin_panel(self):
        """Create admin panel page"""
        frame = tk.Frame(self.container, bg=Styles.BG)
        self.frames["AdminPanel"] = frame
        
        # Header
        header_frame = tk.Frame(frame, bg=Styles.WARNING, height=80)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)
        
        tk.Label(
            header_frame,
            text="🔧 Admin Control Panel",
            font=Styles.HEADING_FONT,
            bg=Styles.WARNING,
            fg="white"
        ).pack(pady=20)
        
        # Back button
        back_btn = tk.Button(
            header_frame,
            text="← Back",
            command=lambda: self.show_frame("WelcomePage"),
            font=Styles.BODY_FONT,
            bg=Styles.WARNING,
            fg="white",
            bd=0,
            cursor="hand2"
        )
        back_btn.place(x=20, y=25)
        
        # Main content
        main_frame = tk.Frame(frame, bg=Styles.BG)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Left panel - User Management
        left_panel = tk.Frame(main_frame, bg=Styles.CARD_BG, width=300)
        left_panel.pack(side="left", fill="y", padx=(0, 20))
        left_panel.pack_propagate(False)
        
        tk.Label(
            left_panel,
            text="👥 User Management",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(pady=20)
        
        # Users list
        self.admin_users_list = tk.Listbox(
            left_panel,
            font=Styles.BODY_FONT,
            bg="#3C4B5D",
            fg=Styles.LIGHT,
            selectbackground=Styles.WARNING,
            selectforeground=Styles.LIGHT,
            relief="flat",
            height=15
        )
        self.admin_users_list.pack(fill="both", expand=True, padx=10, pady=(0, 20))
        
        # Right panel - Statistics and Actions
        right_panel = tk.Frame(main_frame, bg=Styles.BG)
        right_panel.pack(side="right", fill="both", expand=True)
        
        # Stats frame
        stats_frame = tk.Frame(right_panel, bg=Styles.CARD_BG, padx=20, pady=20)
        stats_frame.pack(fill="x", pady=(0, 20))
        
        tk.Label(
            stats_frame,
            text="📊 System Statistics",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(anchor="w", pady=(0, 15))
        
        self.stats_label = tk.Label(
            stats_frame,
            text="Total Users: 0\nTotal Messages: 0\nOnline Users: 0",
            font=Styles.BODY_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT,
            justify="left"
        )
        self.stats_label.pack(anchor="w")
        
        # Actions frame
        actions_frame = tk.Frame(right_panel, bg=Styles.CARD_BG, padx=20, pady=20)
        actions_frame.pack(fill="both", expand=True)
        
        tk.Label(
            actions_frame,
            text="⚡ Quick Actions",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(anchor="w", pady=(0, 15))
        
        # Action buttons
        refresh_btn = Styles.create_rounded_button(
            actions_frame,
            "🔄 Refresh Data",
            self.refresh_admin_data,
            "primary",
            25
        )
        refresh_btn.pack(fill="x", pady=5)
        
        view_cert_btn = Styles.create_rounded_button(
            actions_frame,
            "📜 View Certificate",
            self.view_user_certificate,
            "info",
            25
        )
        view_cert_btn.pack(fill="x", pady=5)
        
        revoke_cert_btn = Styles.create_rounded_button(
            actions_frame,
            "🚫 Revoke Certificate",
            self.revoke_certificate,
            "danger",
            25
        )
        revoke_cert_btn.pack(fill="x", pady=5)
        
        export_btn = Styles.create_rounded_button(
            actions_frame,
            "💾 Export User Data",
            self.export_user_data,
            "success",
            25
        )
        export_btn.pack(fill="x", pady=5)
    
    def create_registration_page(self):
        """Create the registration page"""
        frame = tk.Frame(self.container, bg=Styles.BG)
        self.frames["RegistrationPage"] = frame
        
        # Header
        header_frame = tk.Frame(frame, bg=Styles.PRIMARY, height=80)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)
        
        tk.Label(
            header_frame,
            text="Create New Account",
            font=Styles.HEADING_FONT,
            bg=Styles.PRIMARY,
            fg=Styles.LIGHT
        ).pack(pady=20)
        
        # Back button
        back_btn = tk.Button(
            header_frame,
            text="← Back",
            command=lambda: self.show_frame("WelcomePage"),
            font=Styles.BODY_FONT,
            bg=Styles.PRIMARY,
            fg=Styles.LIGHT,
            bd=0,
            cursor="hand2"
        )
        back_btn.place(x=20, y=25)
        
        # Main form
        main_frame = tk.Frame(frame, bg=Styles.BG)
        main_frame.pack(fill="both", expand=True, padx=50, pady=30)
        
        # Form container
        form_container = tk.Frame(main_frame, bg=Styles.CARD_BG, padx=30, pady=30)
        form_container.pack(fill="both", expand=True)
        
        # Username
        tk.Label(
            form_container,
            text="Username:",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(anchor="w", pady=(0, 5))
        
        self.reg_username = tk.Entry(
            form_container,
            font=Styles.BODY_FONT,
            width=40,
            bg="#3C4B5D",
            fg=Styles.LIGHT,
            insertbackground=Styles.LIGHT,
            relief="flat"
        )
        self.reg_username.pack(pady=(0, 15), fill="x")
        
        # Password
        tk.Label(
            form_container,
            text="Password (min 8 characters):",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(anchor="w", pady=(0, 5))
        
        self.reg_password = tk.Entry(
            form_container,
            font=Styles.BODY_FONT,
            width=40,
            show="•",
            bg="#3C4B5D",
            fg=Styles.LIGHT,
            insertbackground=Styles.LIGHT,
            relief="flat"
        )
        self.reg_password.pack(pady=(0, 15), fill="x")
        
        # Confirm Password
        tk.Label(
            form_container,
            text="Confirm Password:",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(anchor="w", pady=(0, 5))
        
        self.reg_confirm_password = tk.Entry(
            form_container,
            font=Styles.BODY_FONT,
            width=40,
            show="•",
            bg="#3C4B5D",
            fg=Styles.LIGHT,
            insertbackground=Styles.LIGHT,
            relief="flat"
        )
        self.reg_confirm_password.pack(pady=(0, 25), fill="x")
        
        # Security Question
        tk.Label(
            form_container,
            text="Select Security Question:",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(anchor="w", pady=(0, 10))
        
        self.security_questions = [
            "What is your mother's maiden name?",
            "What was the name of your first pet?",
            "What city were you born in?",
            "What is the name of your elementary school?",
            "What was your childhood nickname?"
        ]
        
        self.security_question_var = tk.StringVar(value=self.security_questions[0])
        security_combo = ttk.Combobox(
            form_container,
            textvariable=self.security_question_var,
            values=self.security_questions,
            font=Styles.BODY_FONT,
            state="readonly"
        )
        security_combo.pack(pady=(0, 10), fill="x")
        
        # Security Answer
        tk.Label(
            form_container,
            text="Your Answer:",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(anchor="w", pady=(0, 5))
        
        self.security_answer = tk.Entry(
            form_container,
            font=Styles.BODY_FONT,
            width=40,
            bg="#3C4B5D",
            fg=Styles.LIGHT,
            insertbackground=Styles.LIGHT,
            relief="flat"
        )
        self.security_answer.pack(pady=(0, 25), fill="x")
        
        # Register button
        register_btn = Styles.create_rounded_button(
            form_container,
            "🎯 Register & Generate Certificate",
            self.register_user,
            "success",
            30
        )
        register_btn.pack(pady=20)
    
    def create_login_page(self):
        """Create the login page"""
        frame = tk.Frame(self.container, bg=Styles.BG)
        self.frames["LoginPage"] = frame
        
        # Header
        header_frame = tk.Frame(frame, bg=Styles.PRIMARY, height=80)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)
        
        tk.Label(
            header_frame,
            text="Secure Login",
            font=Styles.HEADING_FONT,
            bg=Styles.PRIMARY,
            fg=Styles.LIGHT
        ).pack(pady=20)
        
        # Back button
        back_btn = tk.Button(
            header_frame,
            text="← Back",
            command=lambda: self.show_frame("WelcomePage"),
            font=Styles.BODY_FONT,
            bg=Styles.PRIMARY,
            fg=Styles.LIGHT,
            bd=0,
            cursor="hand2"
        )
        back_btn.place(x=20, y=25)
        
        # Main form
        main_frame = tk.Frame(frame, bg=Styles.BG)
        main_frame.pack(fill="both", expand=True)
        
        # Center container
        center_frame = tk.Frame(main_frame, bg=Styles.BG)
        center_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Login card
        login_card = tk.Frame(center_frame, bg=Styles.CARD_BG, padx=40, pady=40)
        login_card.pack()
        
        # Title
        tk.Label(
            login_card,
            text="🔐 PKI Authentication",
            font=Styles.HEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(pady=(0, 30))
        
        # Username
        tk.Label(
            login_card,
            text="Username:",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(anchor="w", pady=(0, 5))
        
        self.login_username = tk.Entry(
            login_card,
            font=Styles.BODY_FONT,
            width=30,
            bg="#3C4B5D",
            fg=Styles.LIGHT,
            insertbackground=Styles.LIGHT,
            relief="flat"
        )
        self.login_username.pack(pady=(0, 15), fill="x")
        
        # Password
        tk.Label(
            login_card,
            text="Password:",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(anchor="w", pady=(0, 5))
        
        self.login_password = tk.Entry(
            login_card,
            font=Styles.BODY_FONT,
            width=30,
            show="•",
            bg="#3C4B5D",
            fg=Styles.LIGHT,
            insertbackground=Styles.LIGHT,
            relief="flat"
        )
        self.login_password.pack(pady=(0, 30), fill="x")
        
        # Login button
        login_btn = Styles.create_rounded_button(
            login_card,
            "🚀 Login with PKI",
            self.login_user,
            "primary",
            20
        )
        login_btn.pack(pady=(0, 10))
        
        # Forgot password button
        forgot_btn = Styles.create_rounded_button(
            login_card,
            "🔓 Forgot Password?",
            lambda: self.show_frame("ForgotPasswordPage"),
            "warning",
            20
        )
        forgot_btn.pack(pady=(0, 20))
        
        # Register link
        register_link = tk.Label(
            login_card,
            text="Don't have an account? Register here",
            font=Styles.BODY_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.SECONDARY,
            cursor="hand2"
        )
        register_link.pack()
        register_link.bind("<Button-1>", lambda e: self.show_frame("RegistrationPage"))
    
    def create_forgot_password_page(self):
        """Create forgot password page"""
        frame = tk.Frame(self.container, bg=Styles.BG)
        self.frames["ForgotPasswordPage"] = frame
        
        # Header
        header_frame = tk.Frame(frame, bg=Styles.PRIMARY, height=80)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)
        
        tk.Label(
            header_frame,
            text="Password Recovery",
            font=Styles.HEADING_FONT,
            bg=Styles.PRIMARY,
            fg=Styles.LIGHT
        ).pack(pady=20)
        
        # Back button
        back_btn = tk.Button(
            header_frame,
            text="← Back",
            command=lambda: self.show_frame("LoginPage"),
            font=Styles.BODY_FONT,
            bg=Styles.PRIMARY,
            fg=Styles.LIGHT,
            bd=0,
            cursor="hand2"
        )
        back_btn.place(x=20, y=25)
        
        # Main form
        main_frame = tk.Frame(frame, bg=Styles.BG)
        main_frame.pack(fill="both", expand=True, padx=50, pady=30)
        
        # Form container
        form_container = tk.Frame(main_frame, bg=Styles.CARD_BG, padx=30, pady=30)
        form_container.pack(fill="both", expand=True)
        
        # Username
        tk.Label(
            form_container,
            text="Enter Username:",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(anchor="w", pady=(0, 5))
        
        self.forgot_username = tk.Entry(
            form_container,
            font=Styles.BODY_FONT,
            width=40,
            bg="#3C4B5D",
            fg=Styles.LIGHT,
            insertbackground=Styles.LIGHT,
            relief="flat"
        )
        self.forgot_username.pack(pady=(0, 15), fill="x")
        
        # Security Question
        self.forgot_question_var = tk.StringVar()
        self.forgot_question_label = tk.Label(
            form_container,
            text="Security Question:",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        )
        self.forgot_question_label.pack(anchor="w", pady=(15, 5))
        
        self.forgot_question_display = tk.Label(
            form_container,
            text="",
            font=Styles.BODY_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.WARNING,
            wraplength=500
        )
        self.forgot_question_display.pack(anchor="w", pady=(0, 10), fill="x")
        
        # Security Answer
        tk.Label(
            form_container,
            text="Your Answer:",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(anchor="w", pady=(10, 5))
        
        self.forgot_answer = tk.Entry(
            form_container,
            font=Styles.BODY_FONT,
            width=40,
            bg="#3C4B5D",
            fg=Styles.LIGHT,
            insertbackground=Styles.LIGHT,
            relief="flat"
        )
        self.forgot_answer.pack(pady=(0, 15), fill="x")
        
        # New Password
        tk.Label(
            form_container,
            text="New Password (min 8 characters):",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(anchor="w", pady=(15, 5))
        
        self.new_password = tk.Entry(
            form_container,
            font=Styles.BODY_FONT,
            width=40,
            show="•",
            bg="#3C4B5D",
            fg=Styles.LIGHT,
            insertbackground=Styles.LIGHT,
            relief="flat"
        )
        self.new_password.pack(pady=(0, 15), fill="x")
        
        # Confirm New Password
        tk.Label(
            form_container,
            text="Confirm New Password:",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(anchor="w", pady=(0, 5))
        
        self.confirm_new_password = tk.Entry(
            form_container,
            font=Styles.BODY_FONT,
            width=40,
            show="•",
            bg="#3C4B5D",
            fg=Styles.LIGHT,
            insertbackground=Styles.LIGHT,
            relief="flat"
        )
        self.confirm_new_password.pack(pady=(0, 25), fill="x")
        
        # Buttons
        button_frame = tk.Frame(form_container, bg=Styles.CARD_BG)
        button_frame.pack(pady=10)
        
        check_btn = Styles.create_rounded_button(
            button_frame,
            "🔍 Check Security Question",
            self.check_security_question,
            "info",
            25
        )
        check_btn.pack(side="left", padx=5)
        
        reset_btn = Styles.create_rounded_button(
            button_frame,
            "🔄 Reset Password",
            self.reset_password,
            "success",
            25
        )
        reset_btn.pack(side="left", padx=5)
    
    def create_dashboard_page(self):
        """Create the main dashboard/chat page"""
        frame = tk.Frame(self.container, bg=Styles.BG)
        self.frames["DashboardPage"] = frame
        
        # Header
        header_frame = tk.Frame(frame, bg=Styles.PRIMARY, height=60)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)
        
        # Left: App name and user info
        left_header = tk.Frame(header_frame, bg=Styles.PRIMARY)
        left_header.pack(side="left", padx=20)
        
        tk.Label(
            left_header,
            text="SecureChat Pro",
            font=("Segoe UI", 14, "bold"),
            bg=Styles.PRIMARY,
            fg=Styles.LIGHT
        ).pack(side="left", padx=(0, 20))
        
        self.user_label = tk.Label(
            left_header,
            text="Not logged in",
            font=Styles.BODY_FONT,
            bg=Styles.PRIMARY,
            fg=Styles.WARNING
        )
        self.user_label.pack(side="left")
        
        # Right: Logout button
        logout_btn = tk.Button(
            header_frame,
            text="Logout",
            command=self.logout,
            font=Styles.BODY_FONT,
            bg=Styles.DANGER,
            fg=Styles.LIGHT,
            relief="flat",
            padx=15,
            pady=5,
            cursor="hand2"
        )
        logout_btn.pack(side="right", padx=20, pady=10)
        
        # Main content area
        main_content = tk.Frame(frame, bg=Styles.BG)
        main_content.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Left sidebar (25%)
        sidebar = tk.Frame(main_content, bg=Styles.CARD_BG, width=250)
        sidebar.pack(side="left", fill="y", padx=(0, 20))
        sidebar.pack_propagate(False)
        
        # Sidebar content
        tk.Label(
            sidebar,
            text="👥 All Users",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(pady=20)
        
        # Online users list
        self.online_users_list = tk.Listbox(
            sidebar,
            font=Styles.BODY_FONT,
            bg="#3C4B5D",
            fg=Styles.LIGHT,
            selectbackground=Styles.SECONDARY,
            selectforeground=Styles.LIGHT,
            relief="flat",
            height=15
        )
        self.online_users_list.pack(fill="both", expand=True, padx=10, pady=(0, 20))
        
        # Chat controls
        control_frame = tk.Frame(sidebar, bg=Styles.CARD_BG)
        control_frame.pack(pady=10, padx=10, fill="x")
        
        self.encrypt_var = tk.BooleanVar(value=True)
        encrypt_check = tk.Checkbutton(
            control_frame,
            text="🔒 Encrypt Messages",
            variable=self.encrypt_var,
            font=Styles.BODY_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT,
            selectcolor=Styles.CARD_BG,
            activebackground=Styles.CARD_BG,
            activeforeground=Styles.LIGHT
        )
        encrypt_check.pack(anchor="w", pady=5)
        
        self.sign_var = tk.BooleanVar(value=True)
        sign_check = tk.Checkbutton(
            control_frame,
            text="📝 Sign Messages",
            variable=self.sign_var,
            font=Styles.BODY_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT,
            selectcolor=Styles.CARD_BG,
            activebackground=Styles.CARD_BG,
            activeforeground=Styles.LIGHT
        )
        sign_check.pack(anchor="w", pady=5)
        
        # Right content area (75%)
        right_content = tk.Frame(main_content, bg=Styles.BG)
        right_content.pack(side="right", fill="both", expand=True)
        
        # Chat display
        chat_frame = tk.Frame(right_content, bg=Styles.BG)
        chat_frame.pack(fill="both", expand=True, pady=(0, 20))
        
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame,
            font=Styles.MONO_FONT,
            bg="#2A3B4C",
            fg=Styles.LIGHT,
            insertbackground=Styles.LIGHT,
            wrap="word",
            relief="flat"
        )
        self.chat_display.pack(fill="both", expand=True)
        self.chat_display.config(state="disabled")
        
        # Message input area
        input_frame = tk.Frame(right_content, bg=Styles.BG)
        input_frame.pack(fill="x")
        
        # Recipient
        tk.Label(
            input_frame,
            text="To:",
            font=Styles.BODY_FONT,
            bg=Styles.BG,
            fg=Styles.LIGHT
        ).pack(side="left", padx=(0, 10))
        
        self.recipient_var = tk.StringVar()
        self.recipient_combo = ttk.Combobox(
            input_frame,
            textvariable=self.recipient_var,
            font=Styles.BODY_FONT,
            width=20,
            state="readonly"
        )
        self.recipient_combo.pack(side="left", padx=(0, 20))
        
        # Message input
        self.message_entry = tk.Entry(
            input_frame,
            font=Styles.BODY_FONT,
            bg="#3C4B5D",
            fg=Styles.LIGHT,
            insertbackground=Styles.LIGHT,
            relief="flat"
        )
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.message_entry.bind("<Return>", lambda e: self.send_message())
        
        # Send button
        send_btn = Styles.create_rounded_button(
            input_frame,
            "🚀 Send",
            self.send_message,
            "success",
            10
        )
        send_btn.pack(side="right")
        
        # Status bar at bottom
        self.status_bar = tk.Label(
            frame,
            text="Ready",
            font=Styles.BODY_FONT,
            bg=Styles.PRIMARY,
            fg=Styles.LIGHT,
            anchor="w",
            padx=20
        )
        self.status_bar.pack(side="bottom", fill="x")
    
    def show_frame(self, frame_name):
        """Show a specific frame"""
        frame = self.frames[frame_name]
        frame.tkraise()
        frame.pack(fill="both", expand=True)
        
        # Hide other frames
        for name, f in self.frames.items():
            if name != frame_name:
                f.pack_forget()
    
    def center_window(self):
        """Center the window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def admin_login(self):
        """Handle admin login"""
        email = self.admin_email.get().strip()
        password = self.admin_password.get()
        
        if not email or not password:
            messagebox.showerror("Error", "Please enter email and password")
            return
        
        if self.chat_system.db.verify_admin(email, password):
            self.show_frame("AdminPanel")
            self.refresh_admin_data()
            messagebox.showinfo("Success", "Admin login successful!")
        else:
            messagebox.showerror("Error", "Invalid admin credentials")
    
    def refresh_admin_data(self):
        """Refresh admin panel data"""
        # Get user list from JSON storage
        users = list(self.chat_system.json_storage.data["users"].keys())
        
        self.admin_users_list.delete(0, tk.END)
        for user in users:
            self.admin_users_list.insert(tk.END, user)
        
        # Update stats
        conn = sqlite3.connect(self.chat_system.db.db_file)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM messages")
        total_messages = cursor.fetchone()[0]
        
        conn.close()
        
        self.stats_label.config(
            text=f"Total Users: {total_users}\n"
                 f"Total Messages: {total_messages}\n"
                 f"Online Users: {len(self.chat_system.online_users)}"
        )
    
    def view_user_certificate(self):
        """View selected user's certificate"""
        selection = self.admin_users_list.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a user")
            return
        
        username = self.admin_users_list.get(selection[0])
        user_data = self.chat_system.json_storage.get_user(username)
        
        if user_data:
            cert = user_data['certificate']
            cert_info = f"""
User: {cert['user_id']}
Serial Number: {cert['serial_number']}
Issued: {cert['issue_date'][:19]}
Expires: {cert['expiry_date'][:19]}
Certificate Status: {'✓ Valid' if self.chat_system.ca.verify_certificate(cert) else '✗ Invalid'}
"""
            messagebox.showinfo("Certificate Details", cert_info)
    
    def revoke_certificate(self):
        """Revoke selected user's certificate"""
        selection = self.admin_users_list.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a user")
            return
        
        username = self.admin_users_list.get(selection[0])
        user_data = self.chat_system.json_storage.get_user(username)
        
        if user_data:
            cert = user_data['certificate']
            self.chat_system.ca.revoked_certificates.add(cert['serial_number'])
            messagebox.showinfo("Success", f"Certificate for {username} has been revoked")
    
    def export_user_data(self):
        """Export user data to file"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(self.chat_system.json_storage.data, f, indent=4)
            messagebox.showinfo("Success", f"Data exported to {file_path}")
    
    def register_user(self):
        """Handle user registration"""
        username = self.reg_username.get().strip()
        password = self.reg_password.get()
        confirm_password = self.reg_confirm_password.get()
        security_question = self.security_question_var.get()
        security_answer = self.security_answer.get().strip()
        
        # Validation
        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters")
            return
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        if not security_answer:
            messagebox.showerror("Error", "Please answer the security question")
            return
        
        # Register user
        success, message = self.chat_system.register_user(
            username, password, security_question, security_answer
        )
        
        if success:
            # Show success message with certificate details
            user = self.chat_system.users[username]
            cert_info = f"""
✅ Registration Successful!

Username: {username}
Certificate Serial: {user.certificate['serial_number'][:16]}...
Issued: {user.certificate['issue_date'][:10]}
Expires: {user.certificate['expiry_date'][:10]}

Your digital certificate has been issued and your private key is securely stored.
You can now login with your credentials.
"""
            messagebox.showinfo("Registration Complete", cert_info)
            
            # Clear form and go to login page
            self.reg_username.delete(0, tk.END)
            self.reg_password.delete(0, tk.END)
            self.reg_confirm_password.delete(0, tk.END)
            self.security_answer.delete(0, tk.END)
            
            self.show_frame("LoginPage")
        else:
            messagebox.showerror("Registration Failed", message)
    
    def login_user(self):
        """Handle user login"""
        username = self.login_username.get().strip()
        password = self.login_password.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        
        success, message = self.chat_system.authenticate_user(username, password)
        
        if success:
            self.current_user = username
            self.chat_system.online_users.add(username)
            
            # Load ALL registered users from database into chat system
            all_users = self.chat_system.db.get_all_users()
            
            # Ensure all users are loaded in the system (not just authenticated ones)
            for user in all_users:
                if user not in self.chat_system.users:
                    # Load user data from database
                    user_data = self.chat_system.db.get_user(user)
                    if user_data:
                        secure_user = SecureUser(user)
                        secure_user.encrypted_private_key = user_data['encrypted_private_key']
                        secure_user.salt = user_data['salt']
                        secure_user.iv = user_data['iv']
                        secure_user.certificate = user_data['certificate']
                        secure_user.security_questions = user_data['security_questions']
                        
                        # Load public key
                        secure_user.public_key = serialization.load_pem_public_key(
                            user_data['public_key'].encode(),
                            backend=default_backend()
                        )
                        
                        self.chat_system.users[user] = secure_user
            
            # Update UI
            self.user_label.config(
                text=f"👤 {username} | ✅ Certificate Verified",
                fg=Styles.SUCCESS
            )
            self.update_online_users()
            self.update_status(f"Welcome {username}!")
            
            # Load previous messages
            self.load_previous_messages()
            
            # Show dashboard
            self.show_frame("DashboardPage")
            
            # Start periodic updates
            self.schedule_online_users_update()
            
            # Add welcome message to chat
            self.add_chat_message("System", f"User '{username}' logged in with valid PKI certificate")
            
            messagebox.showinfo("Login Successful", "PKI authentication successful!\nYour digital certificate has been verified.")
        else:
            messagebox.showerror("Login Failed", message)
    
    def update_online_users(self):
        """Update online users list"""
        if not self.current_user:
            return
        
        # Get ALL users from database (not just online ones)
        all_users = self.chat_system.db.get_all_users()
        
        # Update listbox
        self.online_users_list.delete(0, tk.END)
        
        # Add online users first
        online_users = sorted(self.chat_system.online_users)
        for user in online_users:
            if user != self.current_user:
                self.online_users_list.insert(tk.END, f"🟢 {user}")
        
        # Add offline users
        offline_users = [user for user in all_users if user not in self.chat_system.online_users]
        for user in offline_users:
            if user != self.current_user:
                self.online_users_list.insert(tk.END, f"⚫ {user}")
        
        # Update combobox with ALL users (for messaging)
        all_users_for_combo = sorted([user for user in all_users if user != self.current_user])
        self.recipient_combo['values'] = all_users_for_combo
        
        # If there are users, select the first one by default
        if all_users_for_combo:
            self.recipient_var.set(all_users_for_combo[0])
    
    def schedule_online_users_update(self):
        """Schedule periodic update of online users list"""
        if self.current_user and "DashboardPage" in self.frames:
            self.update_online_users()
            # Update every 5 seconds
            self.root.after(5000, self.schedule_online_users_update)
    
    def check_security_question(self):
        """Check user's security question"""
        username = self.forgot_username.get().strip()
        
        if not username:
            messagebox.showerror("Error", "Please enter username")
            return
        
        # Get user from database
        user_data = self.chat_system.db.get_user(username)
        if not user_data:
            messagebox.showerror("Error", "User not found")
            return
        
        # Display security question
        security_question = user_data['security_questions']['question']
        self.forgot_question_display.config(text=security_question)
        messagebox.showinfo("Security Question", f"Please answer your security question:\n\n{security_question}")
    
    def reset_password(self):
        """Reset user password"""
        username = self.forgot_username.get().strip()
        answer = self.forgot_answer.get().strip()
        new_password = self.new_password.get()
        confirm_password = self.confirm_new_password.get()
        
        # Validation
        if not username or not answer or not new_password or not confirm_password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        if len(new_password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters")
            return
        
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        # Verify security answer
        success, message = self.chat_system.forgot_password(username, answer)
        if not success:
            messagebox.showerror("Error", message)
            return
        
        # Reset password
        success, message = self.chat_system.reset_password(username, new_password)
        if success:
            messagebox.showinfo("Success", "Password reset successfully!\nYou can now login with your new password.")
            self.show_frame("LoginPage")
            
            # Clear form
            self.forgot_username.delete(0, tk.END)
            self.forgot_answer.delete(0, tk.END)
            self.new_password.delete(0, tk.END)
            self.confirm_new_password.delete(0, tk.END)
            self.forgot_question_display.config(text="")
        else:
            messagebox.showerror("Error", message)
    
    def logout(self):
        """Handle user logout"""
        if self.current_user:
            self.chat_system.online_users.remove(self.current_user)
            self.current_user = None
        
        self.show_frame("WelcomePage")
    
    def send_message(self):
        """Send a chat message"""
        if not self.current_user:
            messagebox.showerror("Error", "Please login first")
            return
        
        recipient = self.recipient_var.get()
        message = self.message_entry.get().strip()
        
        if not recipient or not message:
            messagebox.showerror("Error", "Please select recipient and enter message")
            return
        
        if recipient == self.current_user:
            messagebox.showerror("Error", "Cannot send message to yourself")
            return
        
        # Send message through chat system
        encrypt = self.encrypt_var.get()
        sign = self.sign_var.get()
        
        success, result = self.chat_system.send_message(
            self.current_user, recipient, message, encrypt, sign
        )
        
        if success:
            timestamp = datetime.now().strftime("%H:%M:%S")
            icon = "🔒" if encrypt else "📝"
            status = ""
            if encrypt:
                status += " [ENCRYPTED]"
            if sign:
                status += " [SIGNED]"
            
            self.add_chat_message(
                self.current_user,
                f"[{timestamp}] To {recipient}: {message}{status}"
            )
            
            self.message_entry.delete(0, tk.END)
            self.update_status(f"Message sent to {recipient}")
        else:
            messagebox.showerror("Error", result)
    
    def load_previous_messages(self):
        """Load previous messages for the current user"""
        if not self.current_user:
            return
        
        # Clear chat display
        self.chat_display.config(state="normal")
        self.chat_display.delete(1.0, tk.END)
        
        # Get all users
        all_users = self.chat_system.db.get_all_users()
        
        for user in all_users:
            if user != self.current_user:
                messages = self.chat_system.db.get_messages(self.current_user, user)
                if messages:
                    self.add_chat_message("System", f"Previous conversation with {user}:")
                    for msg in messages:
                        sender = msg[1]
                        message = msg[3]
                        timestamp = msg[7][:19]
                        
                        if sender == self.current_user:
                            prefix = f"[{timestamp}] You: "
                        else:
                            prefix = f"[{timestamp}] {sender}: "
                        
                        self.chat_display.insert("end", f"{prefix}{message}\n")
        
        self.chat_display.config(state="disabled")
        self.chat_display.see("end")
    
    def add_chat_message(self, sender, message):
        """Add message to chat display"""
        self.chat_display.config(state="normal")
        
        # Color coding
        if sender == "System":
            tag = "system"
            prefix = "🔔 SYSTEM: "
            color = Styles.WARNING
        elif sender == self.current_user:
            tag = "you"
            prefix = "👤 YOU: "
            color = Styles.SECONDARY
        else:
            tag = "other"
            prefix = f"👤 {sender}: "
            color = Styles.SUCCESS
        
        # Insert message
        self.chat_display.insert("end", f"{prefix}{message}\n", tag)
        
        # Apply color
        self.chat_display.tag_config(tag, foreground=color)
        
        self.chat_display.config(state="disabled")
        self.chat_display.see("end")
    
    def update_status(self, message):
        """Update status bar"""
        self.status_bar.config(text=f"📢 {message}")
    
    def run(self):
        """Run the application"""
        self.root.mainloop()

# ====================== MAIN EXECUTION ======================
if __name__ == "__main__":
    print("Starting SecureChat Pro...")
    print("Admin Credentials: admin@gmail.com / admin123@")
    app = SecureChatApp()
    app.run()
