import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import json
import hashlib
import base64
import os
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
    
    def set_security_questions(self, questions_answers):
        """Set security questions and answers (hashed)"""
        for question, answer in questions_answers.items():
            # Add salt to answer before hashing
            salt = os.urandom(16)
            salted_answer = salt + answer.encode()
            hashed_answer = hashlib.sha256(salted_answer).hexdigest()
            self.security_questions[question] = {
                'hash': hashed_answer,
                'salt': base64.b64encode(salt).decode('utf-8')
            }
    
    def verify_security_answer(self, question, answer):
        """Verify security question answer"""
        if question not in self.security_questions:
            return False
        
        stored_data = self.security_questions[question]
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

class SecureChatSystem:
    def __init__(self):
        self.ca = CertificateAuthority()
        self.users = {}
        self.online_users = set()
        self.message_queue = queue.Queue()
    
    def register_user(self, username, password, security_questions):
        """Register a new user"""
        if username in self.users:
            return False, "Username already exists"
        
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        
        user = SecureUser(username)
        public_key = user.generate_key_pair(password)
        user.set_security_questions(security_questions)
        
        # Issue certificate
        certificate = self.ca.issue_certificate(username, public_key)
        user.certificate = certificate
        
        self.users[username] = user
        return True, "Registration successful. Digital certificate issued."
    
    def authenticate_user(self, username, password):
        """Authenticate user with password and certificate"""
        if username not in self.users:
            return False, "User not found"
        
        user = self.users[username]
        
        # Load private key with password
        if not user.load_private_key(password):
            return False, "Invalid password"
        
        # Verify certificate
        if not self.ca.verify_certificate(user.certificate):
            return False, "Invalid or revoked certificate"
        
        return True, "Authentication successful. Certificate verified."

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
        self.create_registration_page()
        self.create_login_page()
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
        
        # Security Questions
        tk.Label(
            form_container,
            text="Security Questions (Answer at least 2):",
            font=Styles.SUBHEADING_FONT,
            bg=Styles.CARD_BG,
            fg=Styles.LIGHT
        ).pack(anchor="w", pady=(0, 10))
        
        self.security_entries = {}
        questions = [
            "What is your mother's maiden name?",
            "What was the name of your first pet?",
            "What city were you born in?"
        ]
        
        for question in questions:
            tk.Label(
                form_container,
                text=f"• {question}",
                font=Styles.BODY_FONT,
                bg=Styles.CARD_BG,
                fg=Styles.LIGHT,
                wraplength=500
            ).pack(anchor="w", pady=(5, 0))
            
            entry = tk.Entry(
                form_container,
                font=Styles.BODY_FONT,
                width=40,
                bg="#3C4B5D",
                fg=Styles.LIGHT,
                insertbackground=Styles.LIGHT,
                relief="flat"
            )
            entry.pack(pady=(0, 10), fill="x")
            self.security_entries[question] = entry
        
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
        login_btn.pack(pady=(0, 20))
        
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
            text="👥 Online Users",
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
    
    def register_user(self):
        """Handle user registration"""
        username = self.reg_username.get().strip()
        password = self.reg_password.get()
        confirm_password = self.reg_confirm_password.get()
        
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
        
        # Collect security answers
        security_answers = {}
        for question, entry in self.security_entries.items():
            answer = entry.get().strip()
            if answer:
                security_answers[question] = answer
        
        if len(security_answers) < 2:
            messagebox.showerror("Error", "Please answer at least 2 security questions")
            return
        
        # Register user
        success, message = self.chat_system.register_user(username, password, security_answers)
        
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
            for entry in self.security_entries.values():
                entry.delete(0, tk.END)
            
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
            
            # Update UI
            self.user_label.config(
                text=f"👤 {username} | ✅ Certificate Verified",
                fg=Styles.SUCCESS
            )
            self.update_online_users()
            self.update_status(f"Welcome {username}!")
            
            # Show dashboard
            self.show_frame("DashboardPage")
            
            # Add welcome message to chat
            self.add_chat_message("System", f"User '{username}' logged in with valid PKI certificate")
            
            messagebox.showinfo("Login Successful", "PKI authentication successful!\nYour digital certificate has been verified.")
        else:
            messagebox.showerror("Login Failed", message)
    
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
        
        # For demo purposes, we'll simulate sending
        timestamp = datetime.now().strftime("%H:%M:%S")
        encrypt = self.encrypt_var.get()
        sign = self.sign_var.get()
        
        # Display in chat
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
        start_pos = self.chat_display.index("end")
        self.chat_display.insert("end", f"{prefix}{message}\n", tag)
        end_pos = self.chat_display.index("end")
        
        # Apply color
        self.chat_display.tag_config(tag, foreground=color)
        
        self.chat_display.config(state="disabled")
        self.chat_display.see("end")
    
    def update_online_users(self):
        """Update online users list"""
        if not self.current_user:
            return
        
        # Update listbox
        self.online_users_list.delete(0, tk.END)
        
        # Update combobox
        users = sorted(self.chat_system.online_users)
        self.recipient_combo['values'] = users
        
        for user in users:
            if user == self.current_user:
                self.online_users_list.insert(tk.END, f"👤 {user} (You)")
            else:
                self.online_users_list.insert(tk.END, f"👤 {user}")
    
    def update_status(self, message):
        """Update status bar"""
        self.status_bar.config(text=f"📢 {message}")
    
    def run(self):
        """Run the application"""
        self.root.mainloop()

# ====================== MAIN EXECUTION ======================
if __name__ == "__main__":
    print("Starting SecureChat Pro...")
    app = SecureChatApp()
    app.run()
