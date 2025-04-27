import os
import hashlib
import hmac

def hash_password(password: str, salt: bytes = None) -> str:
    """
    Hash a password with a randomly‑generated salt (if none provided),
    using PBKDF2‑HMAC‑SHA256.
    Returns a string of the form: salt_hex$hash_hex
    """
    if salt is None:
        salt = os.urandom(16)  # 128‑bit random salt
    # Derive a 256‑bit key from the password
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100_000  # number of iterations
    )
    return salt.hex() + '$' + dk.hex()

def verify_password(stored: str, provided_password: str) -> bool:
    """
    Verify a provided password against the stored salt$hash.
    Uses constant‑time comparison to prevent timing attacks.
    """
    salt_hex, hash_hex = stored.split('$')
    salt = bytes.fromhex(salt_hex)
    expected_hash = bytes.fromhex(hash_hex)
    # Re‑derive key from the provided password+salt
    test_hash = hashlib.pbkdf2_hmac(
        'sha256',
        provided_password.encode('utf-8'),
        salt,
        100_000
    )
    # hmac.compare_digest does a constant‑time comparison
    return hmac.compare_digest(test_hash, expected_hash)

if __name__ == '__main__':
    # --- Demo of usage ---
    pwd = input("Create a password: ")
    stored_value = hash_password(pwd)
    print(f"Store this string in your database:\n  {stored_value}\n")

    attempt = input("Re‑enter your password to log in: ")
    if verify_password(stored_value, attempt):
        print("✅ Login successful!")
    else:
        print("❌ Invalid password.")
