"""
Secure Password Vault Generator for CipherGuard AI.
Generates cryptographically strong passwords using AES-256-GCM encryption
and stores them in an encrypted local vault file.
"""

import base64
import json
import os
import secrets
import string
import time
from pathlib import Path
from typing import Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from .config import VAULT_DIR


class SecureVaultGenerator:
    """AES-256-GCM encrypted password vault with strong password generation."""

    CHARSET_FULL    = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    CHARSET_SAFE    = string.ascii_letters + string.digits + "!@#$%-_."
    CHARSET_LETTERS = string.ascii_letters + string.digits

    def generate_password(
        self,
        length: int = 16,
        use_symbols: bool = True,
        use_digits: bool = True,
        use_upper: bool = True,
        avoid_ambiguous: bool = True,
    ) -> str:
        """
        Generates a cryptographically secure random password.
        Guarantees at least one character from each requested class.
        """
        charset = string.ascii_lowercase
        required = [secrets.choice(string.ascii_lowercase)]

        if use_upper:
            charset += string.ascii_uppercase
            required.append(secrets.choice(string.ascii_uppercase))
        if use_digits:
            charset += string.digits
            required.append(secrets.choice(string.digits))
        if use_symbols:
            sym = "!@#$%^&*()-_=+[]{}|;:,.<>?"
            charset += sym
            required.append(secrets.choice(sym))

        if avoid_ambiguous:
            for ch in "0O1lI|`":
                charset = charset.replace(ch, "")

        # Fill remaining length with random chars
        remaining = length - len(required)
        remaining_chars = [secrets.choice(charset) for _ in range(max(0, remaining))]

        password_list = required + remaining_chars
        secrets.SystemRandom().shuffle(password_list)
        return "".join(password_list)

    def generate_passphrase(self, word_count: int = 4, separator: str = "-") -> str:
        """Generates a memorable but strong diceware-style passphrase."""
        # Compact wordlist (BIP-39 style subset)
        words = [
            "apple","river","storm","castle","silver","planet","frozen","bridge",
            "ocean","thunder","diamond","forest","rocket","shadow","crystal","dragon",
            "falcon","golden","harbor","island","jungle","knight","lemon","mountain",
            "nebula","orange","pepper","quartz","rabbit","sunset","tiger","umbrella",
            "violet","winter","xenon","yellow","zombie","anchor","butter","cinder",
            "desert","engine","flower","gravel","hunter","igloo","jasper","kernel",
            "lantern","marble","noodle","oyster","pickle","quiver","rudder","salmon",
            "temple","uptown","valley","walnut","xyster","yarrow","zipper","anvil",
            "bison","cobra","dagger","eagle","flask","goblin","heron","ivory",
        ]
        return separator.join(secrets.choice(words) for _ in range(word_count))

    # ─── AES-256-GCM Vault ────────────────────────────────────────────────────

    def _derive_key(self, master_password: str, salt: bytes) -> bytes:
        """Derives a 256-bit AES key from master password using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480_000,  # OWASP 2023 recommended minimum
        )
        return kdf.derive(master_password.encode("utf-8"))

    def create_vault(self, vault_name: str, master_password: str) -> Path:
        """Creates a new empty encrypted vault file."""
        salt      = os.urandom(32)
        key       = self._derive_key(master_password, salt)
        aesgcm    = AESGCM(key)
        nonce     = os.urandom(12)

        empty_data = json.dumps({"entries": [], "created": time.time()}).encode()
        ciphertext = aesgcm.encrypt(nonce, empty_data, None)

        vault_data = {
            "salt":       base64.b64encode(salt).decode(),
            "nonce":      base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "version":    "CipherGuard-AES256-GCM-v1",
        }

        vault_path = VAULT_DIR / f"{vault_name}.cgvault"
        with open(vault_path, "w") as f:
            json.dump(vault_data, f, indent=2)
        return vault_path

    def add_entry(
        self,
        vault_path: Path,
        master_password: str,
        site: str,
        username: str,
        password: str,
        notes: str = ""
    ) -> bool:
        """Decrypts vault, appends entry, re-encrypts and saves."""
        try:
            data  = self._load_vault(vault_path, master_password)
            entry = {
                "site":      site,
                "username":  username,
                "password":  password,
                "notes":     notes,
                "added":     time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            data["entries"].append(entry)
            self._save_vault(vault_path, master_password, data)
            return True
        except Exception:
            return False

    def read_vault(self, vault_path: Path, master_password: str) -> Optional[Dict]:
        """Decrypts and returns vault contents."""
        try:
            return self._load_vault(vault_path, master_password)
        except Exception:
            return None

    def _load_vault(self, vault_path: Path, master_password: str) -> Dict:
        with open(vault_path, "r") as f:
            raw = json.load(f)
        salt       = base64.b64decode(raw["salt"])
        nonce      = base64.b64decode(raw["nonce"])
        ciphertext = base64.b64decode(raw["ciphertext"])
        key        = self._derive_key(master_password, salt)
        aesgcm     = AESGCM(key)
        plaintext  = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode())

    def _save_vault(self, vault_path: Path, master_password: str, data: Dict):
        with open(vault_path, "r") as f:
            raw = json.load(f)
        salt       = base64.b64decode(raw["salt"])
        key        = self._derive_key(master_password, salt)
        aesgcm     = AESGCM(key)
        nonce      = os.urandom(12)
        plaintext  = json.dumps(data).encode()
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        raw["nonce"]      = base64.b64encode(nonce).decode()
        raw["ciphertext"] = base64.b64encode(ciphertext).decode()
        with open(vault_path, "w") as f:
            json.dump(raw, f, indent=2)
