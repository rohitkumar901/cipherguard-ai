"""
HaveIBeenPwned Breach Checker for CipherGuard AI.
Uses k-Anonymity model — only first 5 chars of SHA1 hash sent to API.
Your actual password is NEVER transmitted.
"""

import hashlib
import time
from typing import Dict

import requests

from .config import HIBP_API_URL


class BreachChecker:
    """Checks passwords against HaveIBeenPwned database using k-Anonymity."""

    def check_password(self, password: str) -> Dict:
        """
        Checks if password appears in known data breaches.
        Uses k-Anonymity: only first 5 hex chars of SHA1 are sent to HIBP API.
        The full hash NEVER leaves this device.
        """
        sha1_hash  = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix     = sha1_hash[:5]
        suffix     = sha1_hash[5:]

        try:
            start    = time.perf_counter()
            response = requests.get(
                f"{HIBP_API_URL}{prefix}",
                headers={"User-Agent": "CipherGuard-AI-BreachChecker"},
                timeout=5
            )
            elapsed  = round((time.perf_counter() - start) * 1000, 2)

            if response.status_code != 200:
                return self._api_error(response.status_code, elapsed)

            # Parse HIBP response (SUFFIX:COUNT per line)
            breach_count = 0
            for line in response.text.splitlines():
                parts = line.split(":")
                if len(parts) == 2 and parts[0].upper() == suffix:
                    breach_count = int(parts[1])
                    break

            return {
                "checked":       True,
                "pwned":         breach_count > 0,
                "breach_count":  breach_count,
                "risk_level":    self._risk_level(breach_count),
                "hash_prefix":   prefix,
                "response_ms":   elapsed,
                "message":       self._pwned_message(breach_count),
                "privacy_note":  "✅ k-Anonymity used — your password was never sent to any server.",
            }

        except requests.exceptions.ConnectionError:
            return self._offline_result()
        except requests.exceptions.Timeout:
            return self._offline_result("API timeout — check your internet connection.")

    def _risk_level(self, count: int) -> str:
        if count == 0:      return "SAFE"
        elif count < 10:    return "LOW"
        elif count < 1000:  return "MEDIUM"
        elif count < 100000:return "HIGH"
        else:               return "CRITICAL"

    def _pwned_message(self, count: int) -> str:
        if count == 0:
            return "✅ Good news! This password was NOT found in any known data breach."
        elif count < 10:
            return f"⚠️ This password appeared {count:,} times in breach databases. Change it!"
        elif count < 1000:
            return f"🔴 HIGH RISK: Found {count:,} times in breaches. Change immediately!"
        else:
            return f"💀 CRITICAL: This password appeared {count:,} times! Never use it!"

    def _api_error(self, status_code: int, elapsed: float) -> Dict:
        return {
            "checked": False, "pwned": None, "breach_count": 0,
            "risk_level": "UNKNOWN", "hash_prefix": None,
            "response_ms": elapsed,
            "message": f"⚠️ HIBP API error (HTTP {status_code}). Try again later.",
            "privacy_note": "API call failed.",
        }

    def _offline_result(self, msg: str = "No internet connection.") -> Dict:
        return {
            "checked": False, "pwned": None, "breach_count": 0,
            "risk_level": "UNKNOWN", "hash_prefix": None,
            "response_ms": 0,
            "message": f"🔌 Offline: {msg}",
            "privacy_note": "Could not reach HIBP API.",
        }
