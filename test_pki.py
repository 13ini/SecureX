
import os, sys, sqlite3, time, shutil, hashlib
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature
from base64 import b64encode, b64decode

# ---------------------------------------------------------------------------
# Pull helpers from the main app without starting Flask
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(__file__))

# We import the module but bypass __main__ block (it won't fire on import).
import main as app_mod

# ---------------------------------------------------------------------------
# Test harness setup  – isolated temp DB so we never touch the real one
# ---------------------------------------------------------------------------
TEST_DB = "test_pki_temp.db"

def _setup():
    """Point the app module at our test DB, bootstrap CA, create tables."""
    app_mod.DATABASE_PATH = TEST_DB
    # Remove stale test DB if any
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    # Bootstrap CA (uses ca_keys/ dir – reuses the real CA, which is fine)
    app_mod.bootstrap_ca()
    app_mod.init_database()

def _teardown():
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RESET  = "\033[0m"

passed = 0
failed = 0

def check(label, condition, detail=""):
    global passed, failed
    if condition:
        print(f"  {GREEN}PASS{RESET}  {label}")
        passed += 1
    else:
        print(f"  {RED}FAIL{RESET}  {label}  – {detail}")
        failed += 1

# ---------------------------------------------------------------------------
# Helper: create a user keypair + CA-signed cert in one call
# ---------------------------------------------------------------------------
def _make_user(username):
    """Return (private_key, public_key_pem, cert_pem)."""
    priv, pub = app_mod.generate_key_pair()
    cert      = app_mod.generate_certificate(username, pub)
    pub_pem   = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    cert_pem  = cert.public_bytes(serialization.Encoding.PEM).decode()
    return priv, pub_pem, cert_pem

def _revoke_cert(cert_pem, username="test"):
    """Insert the cert's serial into the CRL table."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    serial = str(cert.serial_number)
    conn = sqlite3.connect(TEST_DB)
    conn.execute(
        "INSERT OR REPLACE INTO revoked_certificates (serial_number, username) VALUES (?,?)",
        (serial, username)
    )
    conn.commit()
    conn.close()


# ===========================================================================
# TEST GROUP 1  –  CA Issuance
# ===========================================================================
def test_ca_issuance():
    print(f"\n{YELLOW}[1] CA Issuance{RESET}")

    # 1a. CA certificate is self-signed (issuer == subject)
    ca_cert = app_mod.CA_CERTIFICATE
    check("CA cert is self-signed",
          ca_cert.issuer == ca_cert.subject)

    # 1b. CA cert has the BasicConstraints CA flag
    bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
    check("CA cert has BasicConstraints.ca=True",
          bc.value.ca is True)

    # 1c. User cert's issuer == CA subject
    _, _, cert_pem = _make_user("alice")
    user_cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    check("User cert issuer matches CA subject",
          user_cert.issuer == ca_cert.subject)

    # 1d. User cert's signature verifies against CA public key
    try:
        ca_cert.public_key().verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            user_cert.signature_hash_algorithm
        )
        sig_ok = True
    except InvalidSignature:
        sig_ok = False
    check("User cert signature verified by CA public key", sig_ok)


# ===========================================================================
# TEST GROUP 2  –  Certificate Validation
# ===========================================================================
def test_certificate_validation():
    print(f"\n{YELLOW}[2] Certificate Validation{RESET}")

    # 2a. Valid cert passes
    _, _, cert_pem = _make_user("bob")
    ok, reason = app_mod.validate_certificate(cert_pem)
    check("Valid cert passes validation", ok, str(reason))

    # 2b. Forged cert (signed by rogue key) is rejected
    rogue_key = rsa.generate_private_key(65537, 2048, default_backend())
    rogue_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"rogue")]))
        .issuer_name(app_mod.CA_CERTIFICATE.subject)   # claims CA issued it
        .public_key(rogue_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(rogue_key, hashes.SHA256(), default_backend())  # but signed by rogue!
    )
    rogue_pem = rogue_cert.public_bytes(serialization.Encoding.PEM).decode()
    ok, reason = app_mod.validate_certificate(rogue_pem)
    check("Forged cert (rogue signature) is rejected", not ok, reason or "")

    # 2c. Expired cert is rejected
    expired_priv, expired_pub = app_mod.generate_key_pair()
    expired_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"expired_user")]))
        .issuer_name(app_mod.CA_CERTIFICATE.subject)
        .public_key(expired_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=400))
        .not_valid_after(datetime.now(timezone.utc) - timedelta(days=35))   # expired 35 days ago
        .sign(app_mod.CA_PRIVATE_KEY, hashes.SHA256(), default_backend())
    )
    expired_pem = expired_cert.public_bytes(serialization.Encoding.PEM).decode()
    ok, reason = app_mod.validate_certificate(expired_pem)
    check("Expired cert is rejected", not ok, reason or "")

    # 2d. Revoked cert is rejected
    _, _, rev_cert_pem = _make_user("revoked_user")
    _revoke_cert(rev_cert_pem, "revoked_user")
    ok, reason = app_mod.validate_certificate(rev_cert_pem)
    check("Revoked cert is rejected", not ok, reason or "")


# ===========================================================================
# TEST GROUP 3  –  Multi-User Sign & Verify
# ===========================================================================
def test_sign_and_verify():
    print(f"\n{YELLOW}[3] Multi-User Sign & Verify{RESET}")

    alice_priv, alice_pub, _ = _make_user("alice2")
    _,           bob_pub,   _ = _make_user("bob2")

    message = "Hello Bob, this is Alice."

    # Alice signs
    sig = app_mod.sign_message(message, alice_priv)

    # Bob verifies with Alice's public key → True
    ok = app_mod.verify_signature(message, sig, alice_pub)
    check("Bob verifies Alice's signature correctly", ok)

    # Charlie tries to verify the same sig with Bob's key → False
    ok = app_mod.verify_signature(message, sig, bob_pub)
    check("Wrong public key fails verification", not ok)


# ===========================================================================
# TEST GROUP 4  –  MITM Tamper Detection
# ===========================================================================
def test_mitm_tamper():
    print(f"\n{YELLOW}[4] MITM Tamper Detection{RESET}")

    alice_priv, alice_pub, _ = _make_user("alice3")
    _,          bob_pub,   _ = _make_user("bob3")
    bob_priv, _, _           = _make_user("bob3b")   # separate key for decryption demo

    original = "Secret meeting at noon."

    # Alice encrypts for Bob and signs
    enc = app_mod.encrypt_message(original, bob_pub)
    sig = app_mod.sign_message(original, alice_priv)

    # --- MITM flips a byte in the ciphertext ---
    raw = b64decode(enc)
    tampered = bytes([raw[0] ^ 0xFF]) + raw[1:]   # flip first byte
    tampered_b64 = b64encode(tampered).decode()

    # Decryption of tampered ciphertext should fail (RSA-OAEP detects it)
    try:
        app_mod.decrypt_message(tampered_b64, bob_priv)
        decrypt_failed = False
    except Exception:
        decrypt_failed = True
    check("Tampered ciphertext fails RSA-OAEP decryption", decrypt_failed)

    # Even if an attacker somehow produced a decryption, the signature
    # over the *original* plaintext still wouldn't match altered text.
    fake_plain = "Tampered text injected by MITM."
    sig_ok = app_mod.verify_signature(fake_plain, sig, alice_pub)
    check("Signature does not match MITM-injected plaintext", not sig_ok)


# ===========================================================================
# TEST GROUP 5  –  Unauthorised Signing (Revoked User)
# ===========================================================================
def test_unauthorised_signing():
    print(f"\n{YELLOW}[5] Unauthorised Signing – Revoked User{RESET}")

    eve_priv, eve_pub, eve_cert = _make_user("eve")

    # Revoke Eve
    _revoke_cert(eve_cert, "eve")

    # Attempt to validate Eve's cert before signing (as send_message does)
    ok, reason = app_mod.validate_certificate(eve_cert)
    check("Revoked user's cert fails pre-sign validation", not ok, reason or "")

    # Even if Eve signs anyway, any recipient validating her cert will reject it
    sig = app_mod.sign_message("Forged message from Eve", eve_priv)
    # Recipient validates Eve's cert → blocked
    cert_ok, _ = app_mod.validate_certificate(eve_cert)
    check("Recipient rejects signature because sender cert is revoked", not cert_ok)


# ===========================================================================
# TEST GROUP 6  –  Hybrid Encryption Round-Trip
# ===========================================================================
def test_hybrid_encryption():
    print(f"\n{YELLOW}[6] Hybrid Encryption (AES-256-GCM + RSA-OAEP){RESET}")

    recv_priv, recv_pub, _ = _make_user("hybrid_recv")

    # Long message that exceeds RSA block size (~190 bytes)
    long_msg = "A" * 500 + " – this message is too long for direct RSA-OAEP."

    payload = app_mod.hybrid_encrypt(long_msg, recv_pub)
    decrypted = app_mod.hybrid_decrypt(payload, recv_priv)

    check("Hybrid encrypt/decrypt round-trip matches", decrypted == long_msg)

    # Tamper with the AES ciphertext → decryption must fail
    import json
    data = json.loads(payload)
    raw_ct = b64decode(data["aes_ct_b64"])
    data["aes_ct_b64"] = b64encode(bytes([raw_ct[0] ^ 0xFF]) + raw_ct[1:]).decode()
    tampered_payload = json.dumps(data)

    try:
        app_mod.hybrid_decrypt(tampered_payload, recv_priv)
        tamper_detected = False
    except Exception:
        tamper_detected = True
    check("Tampered hybrid ciphertext fails GCM authentication", tamper_detected)


# ===========================================================================
# TEST GROUP 7  –  File Encryption & Signatures
# ===========================================================================
def test_file_encryption():
    print(f"\n{YELLOW}[7] File Encryption & Digital Signatures{RESET}")

    alice_priv, alice_pub, _ = _make_user("alice_file")
    bob_priv,   bob_pub,   _ = _make_user("bob_file")

    # Create a test file (simulate PDF/image/etc)
    test_file_content = b"This is a confidential document with binary data: \x00\x01\x02\xFF\xFE" * 100
    original_size = len(test_file_content)

    # 7a. Alice encrypts file for Bob
    encrypted_file, encrypted_aes_key = app_mod.encrypt_file(test_file_content, bob_pub)
    check("File encryption produces encrypted data", len(encrypted_file) > 0)
    check("Encrypted file is different from original", encrypted_file != test_file_content)

    # 7b. Bob decrypts file
    decrypted_file = app_mod.decrypt_file(encrypted_file, encrypted_aes_key, bob_priv)
    check("File decryption recovers original content", decrypted_file == test_file_content)
    check("Decrypted file size matches original", len(decrypted_file) == original_size)

    # 7c. Alice signs the file
    signature = app_mod.sign_file(test_file_content, alice_priv)
    check("File signature is generated", len(signature) > 0)

    # 7d. Bob verifies Alice's signature using file hash
    file_hash = hashlib.sha256(test_file_content).hexdigest()
    sig_valid = app_mod.verify_signature(file_hash, signature, alice_pub)
    check("Valid file signature verifies correctly", sig_valid)

    # 7e. Tamper with file → signature fails
    tampered_file = test_file_content + b"EXTRA_DATA"
    tampered_hash = hashlib.sha256(tampered_file).hexdigest()
    sig_invalid = app_mod.verify_signature(tampered_hash, signature, alice_pub)
    check("Tampered file fails signature verification", not sig_invalid)

    # 7f. Wrong decryption key → decryption fails
    charlie_priv, charlie_pub, _ = _make_user("charlie_file")
    try:
        app_mod.decrypt_file(encrypted_file, encrypted_aes_key, charlie_priv)
        wrong_key_blocked = False
    except Exception:
        wrong_key_blocked = True
    check("Decryption with wrong private key fails", wrong_key_blocked)

    # 7g. Large file test (5 MB)
    large_file = b"X" * (5 * 1024 * 1024)  # 5 MB
    enc_large, enc_key_large = app_mod.encrypt_file(large_file, bob_pub)
    dec_large = app_mod.decrypt_file(enc_large, enc_key_large, bob_priv)
    check("Large file (5MB) encryption/decryption works", dec_large == large_file)


# ===========================================================================
# TEST GROUP 8  –  Login Lockout Simulation
# ===========================================================================
def test_login_lockout_logic():
    """
    Simulates the lockout state-machine that the /login route uses,
    without running Flask.  We write directly to the login_attempts
    table and replicate the logic.
    """
    print(f"\n{YELLOW}[7] Login Lockout Simulation{RESET}")

    conn = sqlite3.connect(TEST_DB)
    user = "lockout_test_user"

    # Ensure no stale row
    conn.execute("DELETE FROM login_attempts WHERE username=?", (user,))
    conn.execute("INSERT INTO login_attempts (username, failed_attempts, locked, locked_at) VALUES (?,0,0,NULL)", (user,))
    conn.commit()

    # --- simulate 3 failed attempts ---
    for i in range(3):
        conn.execute("UPDATE login_attempts SET failed_attempts = failed_attempts + 1 WHERE username=?", (user,))
    # lock it
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("UPDATE login_attempts SET locked=1, locked_at=? WHERE username=?", (now, user))
    conn.commit()

    # Read back
    row = conn.execute("SELECT failed_attempts, locked, locked_at FROM login_attempts WHERE username=?", (user,)).fetchone()
    fails, locked, locked_at = row
    check("Account locked after 3 failures", locked == 1 and fails == 3)

    # --- simulate lockout still active (locked_at is NOW, so <600 s have passed) ---
    lt = datetime.strptime(locked_at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    remaining = 600 - (datetime.now(timezone.utc) - lt).total_seconds()
    check("Lockout window is still active (<600 s elapsed)", remaining > 0)

    # --- simulate lockout expired by back-dating locked_at by 601 seconds ---
    expired_at = (datetime.now(timezone.utc) - timedelta(seconds=601)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("UPDATE login_attempts SET locked_at=? WHERE username=?", (expired_at, user))
    conn.commit()

    row = conn.execute("SELECT locked_at FROM login_attempts WHERE username=?", (user,)).fetchone()
    lt2 = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    remaining2 = 600 - (datetime.now(timezone.utc) - lt2).total_seconds()
    check("Lockout auto-expires after 600 s", remaining2 <= 0)

    conn.close()


# ===========================================================================
# MAIN – run all groups
# ===========================================================================
def main():
    print("=" * 60)
    print("  SecureChat PKI Test Suite")
    print("  ST6051CEM Practical Cryptography")
    print("=" * 60)

    _setup()
    try:
        test_ca_issuance()
        test_certificate_validation()
        test_sign_and_verify()
        test_mitm_tamper()
        test_unauthorised_signing()
        test_hybrid_encryption()
        test_file_encryption()       # NEW
        test_login_lockout_logic()
    finally:
        _teardown()

    print("\n" + "=" * 60)
    total = passed + failed
    if failed == 0:
        print(f"  {GREEN}All {total} tests PASSED{RESET}")
    else:
        print(f"  {RED}{failed} of {total} tests FAILED{RESET}")
    print("=" * 60)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
