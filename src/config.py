"""
CipherGuard AI — Global Configuration
"""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
WORDLISTS_DIR = DATA_DIR / "wordlists"
VAULT_DIR = DATA_DIR / "vaults"
REPORTS_DIR = DATA_DIR / "reports"

for d in [DATA_DIR, WORDLISTS_DIR, VAULT_DIR, REPORTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Password Strength Thresholds
STRENGTH_LEVELS = {
    0: ("CRITICAL", "#ef4444"),
    1: ("WEAK",     "#f97316"),
    2: ("FAIR",     "#eab308"),
    3: ("STRONG",   "#22c55e"),
    4: ("FORTRESS", "#3b82f6"),
}

# Hash algorithms supported
SUPPORTED_HASHES = ["MD5", "SHA1", "SHA256", "SHA512", "BCRYPT"]

# Brute-force / dictionary limits (demo safe)
MAX_BRUTE_FORCE_LEN = 5
DICT_ATTACK_LIMIT   = 100_000

# HaveIBeenPwned API
HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

# Gemini model
GEMINI_MODEL = "gemini-2.5-flash"
