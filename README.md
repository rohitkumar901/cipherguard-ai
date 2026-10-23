<div align="center">

<img src="https://img.icons8.com/color/144/lock-2.png" width="100" alt="CipherGuard AI"/>

# 🔐 CipherGuard AI
### AI-Powered Password Security Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-FF4B4B?logo=streamlit)](https://streamlit.io)
[![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![Cryptography](https://img.shields.io/badge/Encryption-AES--256--GCM-green)](https://cryptography.io)
[![HIBP](https://img.shields.io/badge/Breach%20DB-HaveIBeenPwned-red)](https://haveibeenpwned.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> **Final Year B.Tech / MCA Cybersecurity Project** — Production-grade, GitHub-ready, LinkedIn-worthy.

</div>

---

## 🎯 What is CipherGuard AI?

**CipherGuard AI** is a comprehensive, production-grade password security intelligence platform that combines **AI-powered analysis**, **hash cracking simulation**, **AES-256-GCM encryption**, and **real breach intelligence** into a single unified system.

---

## ✨ Features

| Module | Technology | Description |
|---|---|---|
| 🧠 **Password Analyzer** | Entropy + ML Scoring | Strength score, entropy bits, GPU crack-time estimate, pattern detection |
| 💀 **Hash Cracker Simulator** | Hashlib + Rainbow Tables | MD5/SHA1/SHA256/SHA512 — Rainbow, Dictionary, Brute-Force attacks |
| 🔑 **Vault Generator** | `secrets` + AES-256-GCM | Cryptographically secure passwords + PBKDF2 encrypted local vault |
| 🌐 **Breach Checker** | HaveIBeenPwned k-Anonymity | Real breach database — your password is NEVER transmitted |
| 📄 **PDF Audit Report** | ReportLab | Professional security audit dossier |
| 🖥️ **Mission Control UI** | Streamlit | Dark cyber dashboard |
| ⚙️ **REST API** | FastAPI | 6 production endpoints |

---

## 🚀 Quickstart

```bash
git clone https://github.com/rohitkumar901/cipherguard-ai.git
cd cipherguard-ai
pip install -r requirements.txt
python -m streamlit run app.py
```
Open: **http://localhost:8501** 🎉

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET`  | `/health` | System health check |
| `POST` | `/api/v1/analyze` | Full password strength analysis |
| `POST` | `/api/v1/hash` | Compute MD5/SHA1/SHA256/SHA512 hash |
| `POST` | `/api/v1/crack` | Hash cracking simulation |
| `POST` | `/api/v1/generate` | Generate secure random password |
| `POST` | `/api/v1/breach-check` | HaveIBeenPwned breach check |

---

## 🔒 Security Features

- **AES-256-GCM** encryption with **PBKDF2-HMAC-SHA256** key derivation (480,000 iterations)
- **k-Anonymity** breach checking — password never leaves device
- **`secrets`** module for cryptographically secure password generation
- Educational hash cracking — Rainbow Table + Dictionary + Brute Force demonstration

---

## 📂 Project Structure

```
cipherguard-ai/
├── app.py                    🖥️  Streamlit Dashboard
├── api.py                    ⚙️  FastAPI REST API
├── requirements.txt
├── src/
│   ├── password_analyzer.py  🧠  Entropy + Pattern Analysis Engine
│   ├── hash_cracker.py       💀  Hash Cracking Simulator
│   ├── vault_generator.py    🔑  AES-256-GCM Secure Vault
│   ├── breach_checker.py     🌐  HaveIBeenPwned k-Anonymity
│   └── report_generator.py   📄  PDF Audit Report
└── tests/
    └── test_pipeline.py      ✅  3/3 Tests Passing
```

---

## 👤 Author

Built with ❤️ as a Final Year Cybersecurity + AI/ML Engineering Project.

**⭐ Star this repo if it helped you!**
