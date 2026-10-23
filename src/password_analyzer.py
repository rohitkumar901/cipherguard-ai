"""
AI-Powered Password Strength Analyzer for CipherGuard AI.
Uses entropy calculation, ML-style rule-based scoring, pattern detection,
character diversity analysis and crack-time estimation.
"""

import math
import re
import string
from typing import Dict, List, Tuple

from .config import STRENGTH_LEVELS


class PasswordAnalyzer:
    """Comprehensive password strength analyzer with entropy + pattern intelligence."""

    # Common weak patterns
    KEYBOARD_WALKS = ["qwerty", "qwer", "asdf", "zxcv", "1234", "4321", "abcd", "abcde",
                      "12345", "123456", "654321", "password", "pass", "admin", "login",
                      "welcome", "letmein", "monkey", "dragon", "master", "shadow"]

    LEET_MAP = str.maketrans("@!13045$", "aileoass")

    def analyze(self, password: str) -> Dict:
        """
        Full password strength analysis.
        Returns structured dict with score, entropy, crack time, suggestions.
        """
        if not password:
            return self._empty_result()

        entropy       = self._calculate_entropy(password)
        score         = self._calculate_score(password, entropy)
        crack_time    = self._estimate_crack_time(entropy)
        patterns      = self._detect_patterns(password)
        suggestions   = self._generate_suggestions(password, patterns)
        char_analysis = self._char_diversity(password)

        level_name, level_color = STRENGTH_LEVELS.get(score, ("UNKNOWN", "#6b7280"))

        return {
            "password":       password,
            "length":         len(password),
            "score":          score,
            "strength_label": level_name,
            "strength_color": level_color,
            "entropy_bits":   round(entropy, 2),
            "crack_time":     crack_time,
            "patterns_found": patterns,
            "char_analysis":  char_analysis,
            "suggestions":    suggestions,
            "is_safe":        score >= 3,
        }

    def _calculate_entropy(self, password: str) -> float:
        """Shannon entropy based on character pool size × length."""
        pool = 0
        if re.search(r"[a-z]", password): pool += 26
        if re.search(r"[A-Z]", password): pool += 26
        if re.search(r"[0-9]", password): pool += 10
        if re.search(r"[^a-zA-Z0-9]", password): pool += 32
        pool = max(pool, 1)
        return len(password) * math.log2(pool)

    def _calculate_score(self, password: str, entropy: float) -> int:
        """Scoring 0-4 based on entropy, patterns, and character diversity."""
        score = 0

        # Entropy thresholds
        if entropy >= 28:  score += 1
        if entropy >= 50:  score += 1
        if entropy >= 72:  score += 1
        if entropy >= 100: score += 1

        # Penalize weak patterns
        lower_pw = password.lower()
        leet_normalized = lower_pw.translate(self.LEET_MAP)

        for walk in self.KEYBOARD_WALKS:
            if walk in lower_pw or walk in leet_normalized:
                score = max(0, score - 1)
                break

        # Penalize short passwords
        if len(password) < 8:
            score = min(score, 1)
        elif len(password) < 12:
            score = min(score, 2)

        # Penalize repeated chars (e.g., "aaaa", "1111")
        if re.search(r"(.)\1{2,}", password):
            score = max(0, score - 1)

        return min(score, 4)

    def _estimate_crack_time(self, entropy: float) -> str:
        """Estimates offline brute-force crack time at 10B guesses/sec (modern GPU)."""
        guesses_per_sec = 10_000_000_000  # 10 billion (GPU hashcat)
        total_guesses   = 2 ** entropy
        seconds         = total_guesses / guesses_per_sec

        if seconds < 1:          return "Instantly"
        elif seconds < 60:       return f"{int(seconds)} seconds"
        elif seconds < 3600:     return f"{int(seconds/60)} minutes"
        elif seconds < 86400:    return f"{int(seconds/3600)} hours"
        elif seconds < 2592000:  return f"{int(seconds/86400)} days"
        elif seconds < 31536000: return f"{int(seconds/2592000)} months"
        elif seconds < 3.15e9:   return f"{int(seconds/31536000)} years"
        elif seconds < 3.15e12:  return f"{int(seconds/3.15e9)} thousand years"
        elif seconds < 3.15e15:  return f"{int(seconds/3.15e12)} million years"
        else:                    return "Heat death of universe 🔒"

    def _detect_patterns(self, password: str) -> List[str]:
        """Detects dangerous patterns in password."""
        patterns = []
        lower = password.lower()
        leet  = lower.translate(self.LEET_MAP)

        if len(password) < 8:
            patterns.append("Too short (< 8 characters)")
        if re.search(r"(.)\1{2,}", password):
            patterns.append("Repeated characters (e.g. aaa, 111)")
        if re.match(r"^\d+$", password):
            patterns.append("Numbers only")
        if re.match(r"^[a-zA-Z]+$", password):
            patterns.append("Letters only — no digits/symbols")
        for walk in self.KEYBOARD_WALKS:
            if walk in lower or walk in leet:
                patterns.append(f"Common word/pattern detected: '{walk}'")
                break
        if re.search(r"(012|123|234|345|456|567|678|789|890|987|876)", password):
            patterns.append("Sequential number run detected")
        if re.search(r"(abc|bcd|cde|def|efg|fgh|ghi)", lower):
            patterns.append("Sequential alphabet run detected")
        return patterns

    def _char_diversity(self, password: str) -> Dict:
        """Character class breakdown."""
        return {
            "uppercase":  len(re.findall(r"[A-Z]", password)),
            "lowercase":  len(re.findall(r"[a-z]", password)),
            "digits":     len(re.findall(r"[0-9]", password)),
            "symbols":    len(re.findall(r"[^a-zA-Z0-9]", password)),
            "length":     len(password),
        }

    def _generate_suggestions(self, password: str, patterns: List[str]) -> List[str]:
        """Generates actionable improvement suggestions."""
        sug = []
        if len(password) < 12:
            sug.append("📏 Increase length to at least 12 characters")
        if not re.search(r"[A-Z]", password):
            sug.append("🔠 Add uppercase letters (A-Z)")
        if not re.search(r"[0-9]", password):
            sug.append("🔢 Add numbers (0-9)")
        if not re.search(r"[^a-zA-Z0-9]", password):
            sug.append("Add special symbols (!@#%^&*)")
        if re.search(r"(.)\1{2,}", password):
            sug.append("🚫 Remove repeated character sequences")
        if patterns:
            sug.append("❌ Avoid common words, keyboard walks, or dictionary words")
        if not sug:
            sug.append("✅ Great password! Consider using a password manager to store it.")
        return sug

    def _empty_result(self) -> Dict:
        return {
            "password": "", "length": 0, "score": 0,
            "strength_label": "NONE", "strength_color": "#6b7280",
            "entropy_bits": 0.0, "crack_time": "Instantly",
            "patterns_found": [], "char_analysis": {},
            "suggestions": ["Enter a password to analyze."], "is_safe": False,
        }
