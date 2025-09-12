from cryptography.fernet import Fernet
import os

def get_key_path(config_dir):
    return os.path.join(config_dir, "secret.key")

def ensure_key(config_dir):
    key_path = get_key_path(config_dir)
    if not os.path.exists(key_path):
        key = Fernet.generate_key()
        with open(key_path, "wb") as f:
            f.write(key)
    return key_path

def _load_fernet():
    config_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config"))
    key_path = ensure_key(config_dir)
    with open(key_path, "rb") as f:
        key = f.read()
    return Fernet(key)

def encrypt_str(plaintext: str) -> str:
    f = _load_fernet()
    token = f.encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")

def decrypt_str(token_str: str) -> str:
    if not token_str:
        return ""
    f = _load_fernet()
    return f.decrypt(token_str.encode("utf-8")).decode("utf-8")
