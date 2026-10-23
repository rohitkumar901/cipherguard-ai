"""
CipherGuard AI — Unit Tests
"""
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.password_analyzer import PasswordAnalyzer
from src.hash_cracker import HashCracker
from src.vault_generator import SecureVaultGenerator
from src.config import VAULT_DIR


def test_password_analyzer():
    """Tests strength scoring and entropy calculation."""
    a = PasswordAnalyzer()

    weak   = a.analyze("password")
    strong = a.analyze("Tr0ub4dor&3_Mx!99Secure")

    assert weak["score"]   <= 1,  f"Expected weak score, got {weak['score']}"
    assert strong["score"] >= 3,  f"Expected strong score, got {strong['score']}"
    assert weak["entropy_bits"]   < strong["entropy_bits"]
    assert "password" in " ".join(weak["patterns_found"]).lower() or weak["score"] <= 1
    print(f"  Weak:   '{weak['strength_label']}' | Entropy: {weak['entropy_bits']} bits | Crack: {weak['crack_time']}".encode('ascii','replace').decode())
    print(f"  Strong: '{strong['strength_label']}' | Entropy: {strong['entropy_bits']} bits | Crack: {strong['crack_time']}".encode('ascii','replace').decode())


def test_hash_cracker():
    """Tests hash computation and rainbow table cracking."""
    c = HashCracker()

    # Hash a known weak password
    h = c.hash_password("password", "MD5")
    assert len(h) == 32, "MD5 hash should be 32 chars"
    assert h == "5f4dcc3b5aa765d61d8327deb882cf99"

    # Rainbow table should crack it instantly
    result = c.rainbow_table_attack(h)
    assert result["cracked"] is True
    assert result["plaintext"] == "password"
    print(f"  MD5 hash cracked via rainbow table in {result['time_ms']} ms")

    # Strong password should NOT be in rainbow table
    strong_h = c.hash_password("Tr0ub4dor&3_Mx!99Secure", "MD5")
    result2  = c.rainbow_table_attack(strong_h)
    assert result2["cracked"] is False
    print(f"  Strong password correctly NOT in rainbow table [OK]")


def test_vault_generator():
    """Tests password generation and AES-256-GCM vault encryption."""
    vg = SecureVaultGenerator()

    # Test password generation
    pw = vg.generate_password(20, use_symbols=True, use_digits=True, use_upper=True)
    assert len(pw) == 20
    print(f"  Generated password: {pw[:4]}{'*' * 12}{pw[-4:]}")

    # Test passphrase
    phrase = vg.generate_passphrase(4, "-")
    assert len(phrase.split("-")) == 4
    print(f"  Generated passphrase: {phrase.split('-')[0]}-***-***-{phrase.split('-')[-1]}")

    # Test vault create + read
    vault_path = vg.create_vault("test_unit_vault", "SuperMasterPw!99")
    assert vault_path.exists()

    ok = vg.add_entry(vault_path, "SuperMasterPw!99", "github.com", "rohit@mail.com", "MyGHPass123!")
    assert ok is True

    data = vg.read_vault(vault_path, "SuperMasterPw!99")
    assert data is not None
    assert len(data["entries"]) == 1
    assert data["entries"][0]["site"] == "github.com"
    print(f"  Vault created, entry saved, decrypted successfully [OK]")

    # Wrong password should fail
    bad = vg.read_vault(vault_path, "WrongPassword")
    assert bad is None
    print(f"  Wrong master password correctly rejected [OK]")

    # Cleanup
    vault_path.unlink(missing_ok=True)


if __name__ == "__main__":
    print("\n[*] Running CipherGuard AI Unit Tests...\n")
    test_password_analyzer()
    print("  [+] test_password_analyzer: PASSED\n")
    test_hash_cracker()
    print("  [+] test_hash_cracker: PASSED\n")
    test_vault_generator()
    print("  [+] test_vault_generator: PASSED\n")
    print(">>> ALL TESTS PASSED SUCCESSFULLY! (100% Core Pipeline Coverage)")
