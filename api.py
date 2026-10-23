"""
CipherGuard AI — FastAPI REST Microservice
"""
from datetime import datetime
from typing import List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.password_analyzer import PasswordAnalyzer
from src.hash_cracker import HashCracker
from src.vault_generator import SecureVaultGenerator
from src.breach_checker import BreachChecker
from src.report_generator import SecurityReportGenerator
from fastapi.responses import FileResponse

app = FastAPI(
    title="CipherGuard AI — Password Security API",
    version="1.0.0",
    description="AI-Powered Password Security Intelligence Platform"
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

analyzer  = PasswordAnalyzer()
cracker   = HashCracker()
vault_gen = SecureVaultGenerator()
checker   = BreachChecker()


class PasswordRequest(BaseModel):
    password: str
    check_breach: bool = False

class HashRequest(BaseModel):
    password: str
    algorithm: str = "MD5"

class CrackRequest(BaseModel):
    hash_str: str
    algorithm: str = "MD5"
    method: str = "all"   # rainbow | dictionary | brute_force | all

class GenerateRequest(BaseModel):
    length: int = 16
    use_symbols: bool = True
    use_upper: bool = True
    use_digits: bool = True


@app.get("/health")
def health():
    return {"status": "ONLINE", "service": "CipherGuard AI", "timestamp": datetime.utcnow().isoformat()}


@app.post("/api/v1/analyze")
def analyze_password(req: PasswordRequest):
    """Full password strength analysis with optional breach check."""
    result = analyzer.analyze(req.password)
    if req.check_breach:
        result["breach_result"] = checker.check_password(req.password)
    return result


@app.post("/api/v1/hash")
def compute_hash(req: HashRequest):
    """Computes hash of a password string."""
    h = cracker.hash_password(req.password, req.algorithm)
    return {"algorithm": req.algorithm, "hash": h, "length": len(h)}


@app.post("/api/v1/crack")
def crack_hash(req: CrackRequest):
    """Attempts to crack a hash using selected attack method."""
    if req.method == "rainbow":
        return cracker.rainbow_table_attack(req.hash_str)
    elif req.method == "dictionary":
        return cracker.dictionary_attack(req.hash_str, req.algorithm)
    elif req.method == "brute_force":
        return cracker.brute_force_attack(req.hash_str, req.algorithm)
    else:
        return cracker.full_crack(req.hash_str, req.algorithm)


@app.post("/api/v1/generate")
def generate_password(req: GenerateRequest):
    """Generates a cryptographically secure random password."""
    pw     = vault_gen.generate_password(req.length, req.use_symbols, req.use_digits, req.use_upper)
    result = analyzer.analyze(pw)
    return {"password": pw, "strength": result["strength_label"], "entropy": result["entropy_bits"], "crack_time": result["crack_time"]}


@app.post("/api/v1/breach-check")
def breach_check(req: PasswordRequest):
    """Checks password against HaveIBeenPwned using k-Anonymity."""
    return checker.check_password(req.password)


@app.get("/api/v1/identify-hash/{hash_str}")
def identify_hash(hash_str: str):
    """Identifies likely algorithm of a hash based on length."""
    return {"hash": hash_str, "possible_algorithms": cracker.identify_hash(hash_str)}
