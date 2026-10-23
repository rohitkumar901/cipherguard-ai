"""
Hash Cracking Simulator for CipherGuard AI.
Educational demonstration of:
  - Dictionary Attack  (wordlist-based)
  - Brute Force Attack (character space enumeration up to length 5)
  - Rainbow Table Lookup (pre-computed common hashes)
  - Hash identification
Supports: MD5, SHA1, SHA256, SHA512
"""

import hashlib
import itertools
import string
import time
from typing import Dict, Generator, List, Optional, Tuple

from .config import DICT_ATTACK_LIMIT, MAX_BRUTE_FORCE_LEN, WORDLISTS_DIR


# Pre-computed rainbow table for top 200 most common passwords
RAINBOW_TABLE: Dict[str, str] = {}

_COMMON_PASSWORDS = [
    "password", "123456", "password123", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "123456789", "12345678", "qwerty",
    "abc123", "football", "iloveyou", "1234567", "sunshine", "princess",
    "shadow", "superman", "michael", "baseball", "batman", "trustno1",
    "hello", "freedom", "whatever", "qazwsx", "pass", "test",
    "000000", "111111", "222222", "333333", "444444", "555555",
    "666666", "777777", "888888", "999999", "121212", "654321",
    "1234", "12345", "123123", "1q2w3e", "1qaz2wsx", "passw0rd",
    "p@ssword", "p@ssw0rd", "Password1", "Password!", "Admin123",
    "admin123", "root", "toor", "login", "access", "secret",
    "god", "love", "sex", "money", "time", "hack", "pass123",
]

def _build_rainbow_table():
    for pw in _COMMON_PASSWORDS:
        for algo in ["md5", "sha1", "sha256", "sha512"]:
            h = hashlib.new(algo, pw.encode()).hexdigest()
            RAINBOW_TABLE[h] = pw

_build_rainbow_table()


class HashCracker:
    """Educational hash cracking demonstration engine."""

    ALGO_MAP = {
        "MD5":    "md5",
        "SHA1":   "sha1",
        "SHA256": "sha256",
        "SHA512": "sha512",
    }

    def identify_hash(self, hash_str: str) -> List[str]:
        """Identifies likely hash algorithm(s) based on length."""
        h = hash_str.strip()
        length_map = {
            32:  ["MD5"],
            40:  ["SHA1"],
            56:  ["SHA224"],
            64:  ["SHA256"],
            96:  ["SHA384"],
            128: ["SHA512"],
        }
        candidates = length_map.get(len(h), ["Unknown"])
        return candidates

    def hash_password(self, password: str, algorithm: str) -> str:
        """Computes hash of a plaintext password."""
        algo = self.ALGO_MAP.get(algorithm.upper(), "md5")
        return hashlib.new(algo, password.encode("utf-8")).hexdigest()

    def rainbow_table_attack(self, target_hash: str) -> Dict:
        """Instant lookup against pre-computed rainbow table."""
        target = target_hash.strip().lower()
        start  = time.perf_counter()
        result = RAINBOW_TABLE.get(target)
        elapsed = round((time.perf_counter() - start) * 1000, 4)

        return {
            "method":        "Rainbow Table",
            "cracked":       result is not None,
            "plaintext":     result,
            "hashes_tried":  len(RAINBOW_TABLE),
            "time_ms":       elapsed,
            "table_size":    len(RAINBOW_TABLE),
        }

    def dictionary_attack(
        self,
        target_hash: str,
        algorithm: str,
        custom_words: Optional[List[str]] = None,
        progress_callback=None
    ) -> Dict:
        """
        Dictionary attack: tries wordlist entries against target hash.
        Returns cracked plaintext or failure report.
        """
        algo   = self.ALGO_MAP.get(algorithm.upper(), "md5")
        target = target_hash.strip().lower()
        start  = time.perf_counter()

        # Load wordlist: custom → built-in common list
        wordlist = custom_words if custom_words else _COMMON_PASSWORDS
        # Also add leet-speak variations
        wordlist = list(wordlist) + self._leet_variations(wordlist[:50])
        wordlist = wordlist[:DICT_ATTACK_LIMIT]

        tried = 0
        for word in wordlist:
            word_bytes = word.encode("utf-8", errors="ignore")
            h = hashlib.new(algo, word_bytes).hexdigest()
            tried += 1
            if h == target:
                elapsed = round((time.perf_counter() - start) * 1000, 2)
                return {
                    "method":       "Dictionary Attack",
                    "cracked":      True,
                    "plaintext":    word,
                    "hashes_tried": tried,
                    "time_ms":      elapsed,
                    "wordlist_size": len(wordlist),
                }
            if progress_callback and tried % 500 == 0:
                progress_callback(tried, len(wordlist))

        elapsed = round((time.perf_counter() - start) * 1000, 2)
        return {
            "method":       "Dictionary Attack",
            "cracked":      False,
            "plaintext":    None,
            "hashes_tried": tried,
            "time_ms":      elapsed,
            "wordlist_size": len(wordlist),
        }

    def brute_force_attack(
        self,
        target_hash: str,
        algorithm: str,
        charset: str = "lower+digits",
        max_length: int = MAX_BRUTE_FORCE_LEN,
        progress_callback=None
    ) -> Dict:
        """
        Brute-force enumeration attack (educational — limited to max_length chars).
        """
        algo   = self.ALGO_MAP.get(algorithm.upper(), "md5")
        target = target_hash.strip().lower()
        start  = time.perf_counter()

        # Build charset
        chars = ""
        if "lower"   in charset: chars += string.ascii_lowercase
        if "upper"   in charset: chars += string.ascii_uppercase
        if "digits"  in charset: chars += string.digits
        if "symbols" in charset: chars += string.punctuation
        if not chars: chars = string.ascii_lowercase + string.digits

        tried = 0
        time_limit_sec = 10  # Safety: max 10 seconds for demo

        for length in range(1, max_length + 1):
            for combo in itertools.product(chars, repeat=length):
                if time.perf_counter() - start > time_limit_sec:
                    elapsed = round((time.perf_counter() - start) * 1000, 2)
                    return {
                        "method":       "Brute Force",
                        "cracked":      False,
                        "plaintext":    None,
                        "hashes_tried": tried,
                        "time_ms":      elapsed,
                        "note":         f"Time limit reached ({time_limit_sec}s). Password too complex for brute-force.",
                    }
                candidate = "".join(combo)
                h = hashlib.new(algo, candidate.encode()).hexdigest()
                tried += 1
                if h == target:
                    elapsed = round((time.perf_counter() - start) * 1000, 2)
                    return {
                        "method":       "Brute Force",
                        "cracked":      True,
                        "plaintext":    candidate,
                        "hashes_tried": tried,
                        "time_ms":      elapsed,
                    }
                if progress_callback and tried % 10000 == 0:
                    progress_callback(tried)

        elapsed = round((time.perf_counter() - start) * 1000, 2)
        return {
            "method":       "Brute Force",
            "cracked":      False,
            "plaintext":    None,
            "hashes_tried": tried,
            "time_ms":      elapsed,
        }

    def full_crack(self, target_hash: str, algorithm: str) -> Dict:
        """
        Runs all attack methods in sequence:
        Rainbow Table → Dictionary → Brute Force.
        Returns first successful crack or combined failure report.
        """
        results = {}

        # 1. Rainbow Table (instant)
        rt = self.rainbow_table_attack(target_hash)
        results["rainbow_table"] = rt
        if rt["cracked"]:
            return {"overall_cracked": True, "plaintext": rt["plaintext"], "method_used": "Rainbow Table", "details": results}

        # 2. Dictionary Attack
        da = self.dictionary_attack(target_hash, algorithm)
        results["dictionary"] = da
        if da["cracked"]:
            return {"overall_cracked": True, "plaintext": da["plaintext"], "method_used": "Dictionary Attack", "details": results}

        # 3. Brute Force (short passwords only)
        bf = self.brute_force_attack(target_hash, algorithm, charset="lower+digits", max_length=4)
        results["brute_force"] = bf
        if bf["cracked"]:
            return {"overall_cracked": True, "plaintext": bf["plaintext"], "method_used": "Brute Force", "details": results}

        return {"overall_cracked": False, "plaintext": None, "method_used": None, "details": results}

    @staticmethod
    def _leet_variations(words: List[str]) -> List[str]:
        """Generates leet-speak variants of wordlist."""
        leet = str.maketrans("aeiost", "@31057")
        return [w.translate(leet) for w in words]
