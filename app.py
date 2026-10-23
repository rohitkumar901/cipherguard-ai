"""
CipherGuard AI — Streamlit Mission Control Dashboard
AI-Powered Password Security Intelligence Platform
"""

import json
import time
from datetime import datetime
from pathlib import Path

import streamlit as st

from src.password_analyzer import PasswordAnalyzer
from src.hash_cracker import HashCracker
from src.vault_generator import SecureVaultGenerator
from src.breach_checker import BreachChecker
from src.report_generator import SecurityReportGenerator
from src.config import VAULT_DIR

# ── Page Config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CipherGuard AI // Security Intelligence",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;700&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
.stApp { background-color: #0b0f19; color: #f1f5f9; }

.metric-card {
    background: linear-gradient(135deg, #131b2e, #1e293b);
    border: 1px solid #334155; border-radius: 10px;
    padding: 16px 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.4);
}
.metric-val  { font-family: 'JetBrains Mono', monospace; font-size: 26px; font-weight: 800; color: #38bdf8; }
.metric-label{ font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing:.05em; }

.result-card {
    background: #162032; border-radius: 8px; padding: 16px;
    border: 1px solid #1e293b; margin-bottom: 10px;
}
.strength-bar-wrap { background:#1e293b; border-radius:4px; height:10px; margin:8px 0; }
.strength-bar       { height:10px; border-radius:4px; transition: width 0.5s; }

.stButton>button {
    background: linear-gradient(90deg, #2563eb, #3b82f6);
    color: white; border: none; border-radius: 6px;
    font-weight: 600; padding: 8px 20px;
}
.stButton>button:hover { background: linear-gradient(90deg,#1d4ed8,#2563eb); }

div[data-testid="stTab"] button { color: #94a3b8 !important; }
div[data-testid="stTab"] button[aria-selected="true"] { color: #38bdf8 !important; border-bottom: 2px solid #38bdf8; }
</style>
""", unsafe_allow_html=True)

# ── Init ─────────────────────────────────────────────────────────────────────
if "analyzer"  not in st.session_state: st.session_state.analyzer  = PasswordAnalyzer()
if "cracker"   not in st.session_state: st.session_state.cracker   = HashCracker()
if "vault_gen" not in st.session_state: st.session_state.vault_gen = SecureVaultGenerator()
if "checker"   not in st.session_state: st.session_state.checker   = BreachChecker()
if "audit_log" not in st.session_state: st.session_state.audit_log = []

# ── Header ───────────────────────────────────────────────────────────────────
st.title("🔐 CIPHERGUARD AI // SECURITY INTELLIGENCE")
st.markdown("AI-powered password analysis, hash cracking simulation, vault generation & breach intelligence.")

# ── Top Metrics ──────────────────────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)
log = st.session_state.audit_log
safe_cnt     = sum(1 for r in log if r.get("is_safe"))
pwned_cnt    = sum(1 for r in log if r.get("breach_result", {}).get("pwned"))
critical_cnt = sum(1 for r in log if r.get("score", 4) == 0)

with c1:
    st.markdown(f'<div class="metric-card"><div class="metric-label">Passwords Analyzed</div>'
                f'<div class="metric-val">{len(log)}</div></div>', unsafe_allow_html=True)
with c2:
    st.markdown(f'<div class="metric-card"><div class="metric-label">Secure Passwords</div>'
                f'<div class="metric-val" style="color:#22c55e">{safe_cnt}</div></div>', unsafe_allow_html=True)
with c3:
    st.markdown(f'<div class="metric-card"><div class="metric-label">Found in Breaches</div>'
                f'<div class="metric-val" style="color:#ef4444">{pwned_cnt}</div></div>', unsafe_allow_html=True)
with c4:
    st.markdown(f'<div class="metric-card"><div class="metric-label">Critical Weak</div>'
                f'<div class="metric-val" style="color:#f97316">{critical_cnt}</div></div>', unsafe_allow_html=True)

st.markdown("<br/>", unsafe_allow_html=True)

# ── Tabs ─────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🧠 Password Analyzer",
    "💀 Hash Cracker",
    "🔑 Vault Generator",
    "🌐 Breach Checker",
    "📄 Security Report",
])


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1 — PASSWORD ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════
with tab1:
    st.subheader("🧠 AI Password Strength Analyzer")
    st.caption("Real-time entropy scoring, pattern detection, crack-time estimation & improvement suggestions.")

    col_inp, col_res = st.columns([1, 1])

    with col_inp:
        show_pw   = st.checkbox("👁 Show password", value=False)
        pw_input  = st.text_input(
            "Enter password to analyze",
            type="default" if show_pw else "password",
            placeholder="Type your password here…",
        )
        also_check_breach = st.checkbox("🌐 Also check HaveIBeenPwned breach database", value=True)
        analyze_btn       = st.button("🔍 Analyze Password", use_container_width=True)

    with col_res:
        if analyze_btn and pw_input:
            result = st.session_state.analyzer.analyze(pw_input)
            score  = result["score"]
            label  = result["strength_label"]
            color  = result["strength_color"]
            pct    = (score + 1) * 20

            # Strength bar
            st.markdown(f"""
            <div class="result-card">
              <div style="font-size:22px;font-weight:800;color:{color}">
                {label}
              </div>
              <div class="strength-bar-wrap">
                <div class="strength-bar" style="width:{pct}%;background:{color}"></div>
              </div>
              <div style="color:#94a3b8;font-size:12px">Score: {score}/4 &nbsp;|&nbsp;
                Entropy: <b style="color:#38bdf8">{result['entropy_bits']} bits</b> &nbsp;|&nbsp;
                Length: <b>{result['length']} chars</b>
              </div>
            </div>
            """, unsafe_allow_html=True)

            # Crack time badge
            ct_color = "#22c55e" if score >= 3 else "#ef4444"
            st.markdown(f"**⏱ GPU Crack Time:** <span style='color:{ct_color};font-weight:700'>{result['crack_time']}</span>",
                        unsafe_allow_html=True)

            # Char breakdown
            ca = result["char_analysis"]
            st.markdown(f"""
            | Uppercase | Lowercase | Digits | Symbols |
            |:---------:|:---------:|:------:|:-------:|
            | {ca.get('uppercase',0)} | {ca.get('lowercase',0)} | {ca.get('digits',0)} | {ca.get('symbols',0)} |
            """)

            # Patterns
            if result["patterns_found"]:
                st.error("⚠️ Weak Patterns Detected:")
                for p in result["patterns_found"]:
                    st.markdown(f"  • {p}")

            # Suggestions
            if result["suggestions"]:
                st.info("💡 Improvement Suggestions:")
                for s in result["suggestions"]:
                    st.markdown(f"  {s}")

            # Breach check
            breach_result = {}
            if also_check_breach:
                with st.spinner("🌐 Checking breach database…"):
                    breach_result = st.session_state.checker.check_password(pw_input)
                if breach_result.get("checked"):
                    if breach_result["pwned"]:
                        st.error(breach_result["message"])
                    else:
                        st.success(breach_result["message"])
                    st.caption(breach_result["privacy_note"])
                else:
                    st.warning(breach_result["message"])

            result["breach_result"] = breach_result
            st.session_state.audit_log.insert(0, result)

        elif analyze_btn:
            st.warning("Please enter a password first.")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2 — HASH CRACKER
# ═══════════════════════════════════════════════════════════════════════════════
with tab2:
    st.subheader("💀 Hash Cracking Simulator")
    st.caption("⚠️ **Educational only.** Demonstrates why weak passwords are dangerous. Never use against unauthorized systems.")

    st.markdown("### 🔢 Compute Hash")
    col_h1, col_h2 = st.columns(2)
    with col_h1:
        pw_to_hash = st.text_input("Plaintext password to hash", type="password", key="hash_input")
        algo_hash  = st.selectbox("Algorithm", ["MD5", "SHA1", "SHA256", "SHA512"], key="algo_hash")
    with col_h2:
        if st.button("⚙️ Generate Hash", use_container_width=True) and pw_to_hash:
            h = st.session_state.cracker.hash_password(pw_to_hash, algo_hash)
            st.code(h, language=None)
            st.caption(f"Algorithm: {algo_hash} | Length: {len(h)} chars")

    st.markdown("---")
    st.markdown("### 🔓 Crack a Hash")
    col_c1, col_c2 = st.columns([1.5, 1])
    with col_c1:
        target_hash  = st.text_input("Paste target hash here", placeholder="e.g. 5f4dcc3b5aa765d61d8327deb882cf99")
        algo_crack   = st.selectbox("Hash algorithm", ["MD5", "SHA1", "SHA256", "SHA512"], key="algo_crack")
        attack_mode  = st.radio("Attack Method", ["🌈 Rainbow Table (Instant)", "📖 Dictionary Attack", "💥 Brute Force (≤4 chars)"], horizontal=True)

    with col_c2:
        if target_hash:
            ids = st.session_state.cracker.identify_hash(target_hash)
            st.info(f"🔎 Detected hash type: **{', '.join(ids)}**")

    if st.button("🚀 Launch Attack", use_container_width=True) and target_hash:
        cracker = st.session_state.cracker
        with st.spinner("⚡ Running attack simulation…"):
            if "Rainbow" in attack_mode:
                res = cracker.rainbow_table_attack(target_hash)
            elif "Dictionary" in attack_mode:
                res = cracker.dictionary_attack(target_hash, algo_crack)
            else:
                res = cracker.brute_force_attack(target_hash, algo_crack, max_length=4)

        if res.get("cracked"):
            st.success(f"✅ **CRACKED!** Plaintext: `{res['plaintext']}`")
        else:
            st.error("❌ Password not cracked — it appears sufficiently complex!")

        col_r1, col_r2, col_r3 = st.columns(3)
        col_r1.metric("Method", res.get("method", "—"))
        col_r2.metric("Hashes Tried", f"{res.get('hashes_tried', 0):,}")
        col_r3.metric("Time Taken", f"{res.get('time_ms', 0)} ms")

        if res.get("cracked"):
            st.warning("⚠️ This password is dangerously weak. Use CipherGuard Vault Generator to create a secure one!")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3 — VAULT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.subheader("🔑 Secure Password & Vault Generator")
    st.caption("Cryptographically strong passwords using Python `secrets` module + AES-256-GCM encrypted vault.")

    st.markdown("### ⚡ Generate Strong Password")
    col_g1, col_g2 = st.columns([1, 1])
    with col_g1:
        pw_length    = st.slider("Password Length", 8, 64, 20)
        use_symbols  = st.checkbox("Include Symbols (!@#…)", value=True)
        use_upper    = st.checkbox("Include Uppercase (A-Z)",  value=True)
        use_digits   = st.checkbox("Include Digits (0-9)",     value=True)
        avoid_ambig  = st.checkbox("Avoid Ambiguous Chars (0, O, l, 1)", value=True)
    with col_g2:
        if st.button("🎲 Generate Password", use_container_width=True):
            vg = st.session_state.vault_gen
            pw = vg.generate_password(pw_length, use_symbols, use_digits, use_upper, avoid_ambig)
            st.code(pw, language=None)
            strength = st.session_state.analyzer.analyze(pw)
            st.success(f"💪 Strength: **{strength['strength_label']}** | Entropy: {strength['entropy_bits']} bits | Crack Time: {strength['crack_time']}")

        st.markdown("**— or —**")
        wc = st.slider("Passphrase Word Count", 3, 6, 4)
        sep = st.selectbox("Separator", ["-", ".", "_", " ", "~"])
        if st.button("🎲 Generate Passphrase", use_container_width=True):
            phrase = st.session_state.vault_gen.generate_passphrase(wc, sep)
            st.code(phrase, language=None)

    st.markdown("---")
    st.markdown("### 🗄️ AES-256-GCM Encrypted Vault")
    vault_col1, vault_col2 = st.columns(2)

    with vault_col1:
        st.markdown("**Create New Vault**")
        v_name    = st.text_input("Vault Name", placeholder="my_vault")
        v_master  = st.text_input("Master Password", type="password", key="v_master_create")
        if st.button("🔒 Create Vault", use_container_width=True):
            if v_name and v_master:
                path = st.session_state.vault_gen.create_vault(v_name, v_master)
                st.success(f"✅ Vault created: `{path.name}`")
            else:
                st.warning("Enter vault name and master password.")

    with vault_col2:
        st.markdown("**Add Entry to Vault**")
        vaults = list(VAULT_DIR.glob("*.cgvault"))
        if vaults:
            sel_vault  = st.selectbox("Select Vault", [v.name for v in vaults])
            v_master2  = st.text_input("Master Password", type="password", key="v_master_open")
            e_site     = st.text_input("Website / App")
            e_user     = st.text_input("Username / Email")
            e_pass     = st.text_input("Password", type="password")
            if st.button("💾 Save Entry", use_container_width=True):
                vault_path = VAULT_DIR / sel_vault
                ok = st.session_state.vault_gen.add_entry(vault_path, v_master2, e_site, e_user, e_pass)
                st.success("✅ Entry saved!") if ok else st.error("❌ Wrong master password!")
        else:
            st.info("Create a vault first.")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 4 — BREACH CHECKER
# ═══════════════════════════════════════════════════════════════════════════════
with tab4:
    st.subheader("🌐 HaveIBeenPwned Breach Intelligence")
    st.caption("Check if your password appears in known data breaches using **k-Anonymity** — your password never leaves your device.")

    st.info("🔒 **Privacy First:** Only the first 5 characters of your password's SHA1 hash are sent to the HIBP API. Your actual password is NEVER transmitted.")

    breach_pw  = st.text_input("Enter password to check", type="password", key="breach_input")
    if st.button("🔍 Check for Breaches", use_container_width=True) and breach_pw:
        with st.spinner("🌐 Querying HaveIBeenPwned database…"):
            br = st.session_state.checker.check_password(breach_pw)

        if br.get("checked"):
            if br["pwned"]:
                st.error(br["message"])
                st.metric("Times Found in Breaches", f"{br['breach_count']:,}")
                st.metric("Risk Level", br["risk_level"])
            else:
                st.success(br["message"])
            st.caption(f"⚡ API Response: {br['response_ms']} ms | {br['privacy_note']}")
        else:
            st.warning(br["message"])


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 5 — SECURITY REPORT
# ═══════════════════════════════════════════════════════════════════════════════
with tab5:
    st.subheader("📄 Security Audit Report Generator")

    if not st.session_state.audit_log:
        st.info("Analyze some passwords in the **Password Analyzer** tab first, then come back here to generate your report.")
    else:
        st.success(f"✅ {len(st.session_state.audit_log)} passwords ready for report.")
        st.markdown(f"**Critical Weak:** {critical_cnt} | **Breached:** {pwned_cnt} | **Secure:** {safe_cnt}")

        if st.button("📄 Generate PDF Security Audit Report", use_container_width=True):
            with st.spinner("Compiling forensic dossier…"):
                gen      = SecurityReportGenerator()
                pdf_path = gen.generate(st.session_state.audit_log)

            st.success("✅ Report generated!")
            with open(pdf_path, "rb") as f:
                st.download_button(
                    "⬇️ Download PDF Security Report",
                    data=f,
                    file_name=pdf_path.name,
                    mime="application/pdf",
                    use_container_width=True,
                )

        if st.button("🗑️ Clear Audit Log", use_container_width=True):
            st.session_state.audit_log = []
            st.rerun()
