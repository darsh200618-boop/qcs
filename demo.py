# app.py
# Professional BB84 Streamlit app with animations, AES-GCM encryption, Qiskit circuit visualization (optional),
# file upload/encrypt/decrypt, live chat demo, and analysis dashboard.

import streamlit as st
import numpy as np
import pandas as pd
import plotly.graph_objs as go
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image
import io
import os
import base64
import time
from typing import Dict, Any

# Optional Qiskit import (graceful fallback)
try:
    from qiskit import QuantumCircuit
    from qiskit.visualization import circuit_drawer
    QISKIT_AVAILABLE = True
except Exception:
    QISKIT_AVAILABLE = False

# -------------------------
# Utility & BB84 core
# -------------------------
def simulate_bb84(num_bits: int, p_noise: float, p_eve: float, seed: int | None = None) -> Dict[str, Any]:
    """Simulate BB84. Returns lots of arrays & stats for UI."""
    rng = np.random.default_rng(seed)
    alice_bits = rng.integers(0, 2, size=num_bits, dtype=np.int8)
    alice_bases = rng.integers(0, 2, size=num_bits, dtype=np.int8)  # 0=Z,1=X
    bob_bases = rng.integers(0, 2, size=num_bits, dtype=np.int8)
    bob_results = np.empty(num_bits, dtype=np.int8)

    eve_flags = np.zeros(num_bits, dtype=np.int8)  # whether Eve intercepted

    for i in range(num_bits):
        if rng.random() < p_eve:
            eve_flags[i] = 1
            eve_basis = rng.integers(0, 2)
            eve_bit = alice_bits[i] if eve_basis == alice_bases[i] else rng.integers(0, 2)
            sender_basis = eve_basis
            sender_bit = eve_bit
        else:
            sender_basis = alice_bases[i]
            sender_bit = alice_bits[i]

        if bob_bases[i] == sender_basis:
            bob_bit = sender_bit
        else:
            bob_bit = rng.integers(0, 2)

        if rng.random() < p_noise:
            bob_bit ^= 1

        bob_results[i] = bob_bit

    sift_mask = alice_bases == bob_bases
    alice_sift = alice_bits[sift_mask]
    bob_sift = bob_results[sift_mask]
    sift_len = int(sift_mask.sum())
    qber = (np.count_nonzero(alice_sift != bob_sift) / sift_len) if sift_len > 0 else float("nan")

    return {
        "alice_bits": alice_bits,
        "alice_bases": alice_bases,
        "bob_bases": bob_bases,
        "bob_results": bob_results,
        "eve_flags": eve_flags,
        "sift_mask": sift_mask,
        "alice_sift": alice_sift,
        "bob_sift": bob_sift,
        "sift_len": sift_len,
        "qber": qber,
    }

def derive_key_from_bits(bit_arr: np.ndarray) -> bytes:
    """SHA-256 of bits string -> 32 byte key"""
    if len(bit_arr) == 0:
        return get_random_bytes(32)
    s = "".join(map(str, bit_arr.tolist()))
    return hashlib.sha256(s.encode()).digest()

# AES-GCM helpers (authenticating)
def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    # store nonce(16) + tag(16) + ciphertext
    return cipher.nonce + tag + ciphertext

def aes_gcm_decrypt(key: bytes, blob: bytes) -> bytes:
    nonce = blob[:16]
    tag = blob[16:32]
    ciphertext = blob[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# Helper to get default image in repo
def load_default_image():
    p = "images/windows.png"
    if os.path.exists(p):
        return Image.open(p).convert("RGB")
    return None

def pil_to_bytes(img: Image.Image, fmt="PNG") -> bytes:
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()

# -------------------------
# Streamlit UI (layout + features)
# -------------------------
st.set_page_config(page_title="Quantum Crypto Simulator — BB84 (Pro)", layout="wide", page_icon="🔐")

st.header("🔐 Quantum Cryptography Simulator — BB84 (Professional Demo)")
st.write(
    "Interactive, presentation-ready demo: Alice → (Eve) → Bob. "
    "Key derived from BB84 is used to encrypt files via AES-GCM (confidentiality + integrity)."
)

# Sidebar controls
with st.sidebar:
    st.markdown("## Simulation Controls")
    num_bits = st.slider("Number of transmitted qubits", 100, 10000, 2000, step=100)
    p_noise = st.slider("Channel noise (flip probability)", 0.0, 0.5, 0.03, step=0.01)
    p_eve = st.slider("Eve intercept probability", 0.0, 1.0, 0.05, step=0.01)
    seed = st.number_input("Random seed (for reproducibility)", value=42, step=1)
    st.markdown("---")
    st.markdown("## Demo Options")
    uploaded = st.file_uploader("Upload a file to send (image/pdf/txt). Leave empty for default image.", type=None)
    use_default_image = False
    if uploaded is None:
        default_img = load_default_image()
        if default_img is not None:
            use_default_image = st.checkbox("Use default sample image (images/windows.png)", value=True)
    st.markdown("---")
    st.caption("Advanced features: step-through storytelling, animated qubit travel, Qiskit circuits (if installed).")

# Main multi-tab UI
tabs = st.tabs(["🎬 Storyline", "🔬 Simulation & Encrypt", "📊 Analysis", "💬 Chat Demo", "ℹ️ About / Help"])

# -------------------------
# Tab: Storyline (step-by-step)
# -------------------------
with tabs[0]:
    st.subheader("Storyline Mode — Step through BB84")
    st.write("Click **Next** to step through the protocol. You can replay or step back.")
    if "step_idx" not in st.session_state:
        st.session_state.step_idx = 0
    max_steps = 5

    cols = st.columns([3, 1, 1])
    with cols[0]:
        st.write("### Narrative")
        narratives = [
            "Alice prepares random bits and random bases. She encodes qubits accordingly.",
            "Alice sends qubits to Bob across the quantum channel.",
            "Eve may intercept some qubits (intercept-resend) which can introduce errors.",
            "Bob measures the incoming qubits with random bases.",
            "Alice & Bob publicly compare bases and sift matching positions — derive key & compute QBER."
        ]
        st.info(narratives[st.session_state.step_idx])

    with cols[1]:
        if st.button("⏮ Back"):
            st.session_state.step_idx = max(0, st.session_state.step_idx - 1)
    with cols[2]:
        if st.button("Next ⏭"):
            st.session_state.step_idx = min(max_steps - 1, st.session_state.step_idx + 1)

    st.markdown("---")
    st.write("Below is a small animated preview of qubits traveling (visual only).")
    # Simple animated visualization: small fixed example to keep it snappy
    small_num = 12
    small_res = simulate_bb84(small_num, p_noise, p_eve, seed)
    # Prepare frames: qubits move from x=0 (Alice) to x=1 (Bob). If Eve intercepted, show marker.
    frames = []
    for t in range(0, 11):
        xs = np.full(small_num, t / 10)
        ys = np.linspace(0, 1, small_num)
        marker_colors = ["red" if small_res["eve_flags"][i] else "blue" for i in range(small_num)]
        frame = go.Frame(data=[go.Scatter(x=xs, y=ys, mode="markers", marker=dict(size=12, color=marker_colors))])
        frames.append(frame)
    fig = go.Figure(
        data=[go.Scatter(x=[0], y=[0], mode="markers")],
        layout=go.Layout(xaxis=dict(range=[0, 1], showgrid=False, title="Channel (Alice -> Bob)"),
                         yaxis=dict(range=[0, 1], showgrid=False, showticklabels=False),
                         height=350),
        frames=frames
    )
    # Play controls
    fig.update_layout(updatemenus=[dict(type="buttons", showactive=False,
                                       y=1.05, x=1.15,
                                       xanchor="right", yanchor="top",
                                       buttons=[dict(label="Play",
                                                     method="animate",
                                                     args=[None, {"frame": {"duration": 200, "redraw": True},
                                                                  "fromcurrent": True, "transition": {"duration": 0}}])])])
    st.plotly_chart(fig, use_container_width=True)

# -------------------------
# Tab: Simulation & Encrypt
# -------------------------
with tabs[1]:
    st.subheader("Run BB84 (Alice → Bob) and Encrypt/Decrypt Files")
    colA, colB = st.columns([1, 1])
    with colA:
        st.markdown("**Sender (Alice)**")
        if uploaded is not None:
            # read bytes for display
            uploaded_bytes = uploaded.getvalue()
            st.markdown(f"**Uploaded file:** {uploaded.name} — {len(uploaded_bytes)} bytes")
            # if image, display thumbnail
            try:
                img = Image.open(io.BytesIO(uploaded_bytes)).convert("RGB")
                st.image(img, caption="Uploaded (Alice's file)", use_container_width=False, width=300)
            except Exception:
                st.info("Uploaded file is not an image — will be encrypted as binary.")
        elif use_default_image and default_img is not None:
            img = default_img
            st.image(img, caption="Default sample image (Alice)", use_container_width=False, width=300)
            uploaded_bytes = pil_to_bytes(img, fmt="PNG")
        else:
            uploaded_bytes = None
            st.warning("No file provided. Upload a file or enable default image in the sidebar.")

    with colB:
        st.markdown("**Receiver (Bob)**")
        st.write("Bob will attempt to recover the file after BB84-derived key encryption.")

    run_col1, run_col2 = st.columns([1, 1])
    run_now = run_col1.button("Run BB84 & Encrypt")
    if run_now:
        with st.spinner("Running BB84 simulation..."):
            res = simulate_bb84(num_bits, p_noise, p_eve, seed)
            qber = res["qber"]
            sift_len = res["sift_len"]
            alice_sift = res["alice_sift"]
            bob_sift = res["bob_sift"]

            # UI metrics
            m1, m2, m3 = st.columns(3)
            m1.metric("Sifted key length", sift_len)
            m2.metric("QBER (%)", f"{qber*100:.3f}" if not np.isnan(qber) else "N/A")
            m3.metric("Agreement (%)", f"{(1-qber)*100:.3f}" if not np.isnan(qber) else "N/A")

            # show sample of keys
            if sift_len > 0:
                preview_n = min(60, sift_len)
                dfp = pd.DataFrame({
                    "idx": np.arange(preview_n),
                    "Alice": alice_sift[:preview_n].astype(int),
                    "Bob": bob_sift[:preview_n].astype(int)
                })
                st.subheader("Sample sifted bits (Alice vs Bob)")
                st.dataframe(dfp, use_container_width=True)
            else:
                st.info("Sifted key length is 0 — increase num_bits.")

            # derive AES key
            derived_key = derive_key_from_bits(alice_sift)  # 32 bytes
            st.subheader("Derived Key (SHA-256 of sifted bits)")
            st.code(derived_key.hex(), language="text")
            # warnings
            st.warning("The shown key is for demo only. In real QKD you would NOT reveal key material.")

            # perform encryption if file present
            if uploaded_bytes is not None:
                st.info("Encrypting uploaded file using AES-GCM with derived key...")
                enc_blob = aes_gcm_encrypt(derived_key, uploaded_bytes)
                # verify
                try:
                    dec = aes_gcm_decrypt(derived_key, enc_blob)
                    verified = dec == uploaded_bytes
                except Exception:
                    verified = False

                # Downloads
                st.success(f"Encryption done — ciphertext {len(enc_blob)} bytes.")
                st.download_button("Download Encrypted Blob (.bin)", data=enc_blob, file_name="encrypted_blob.bin")
                if verified:
                    st.success("Decryption verification OK — decrypted equals original.")
                    st.download_button("Download Decrypted File (verified)", data=dec, file_name=f"decrypted_{uploaded.name if uploaded else 'file'}")
                else:
                    st.error("Decryption verification FAILED (integrity failure or wrong key).")

                # show ciphertext size and a small hex preview
                hexd = enc_blob[:64].hex()
                st.text(f"Ciphertext (first 32 bytes hex): {hexd} ...")
            else:
                st.info("No file to encrypt. Upload a file and re-run.")

            # Save last run artifacts to session_state for use in other tabs
            st.session_state["last_run"] = {
                "res": res,
                "derived_key": derived_key,
                "enc_blob": enc_blob if uploaded_bytes is not None else None,
                "orig_bytes": uploaded_bytes,
                "uploaded_name": uploaded.name if uploaded else "default_image.png" if use_default_image else None,
            }

# -------------------------
# Tab: Analysis
# -------------------------
with tabs[2]:
    st.subheader("Analysis Dashboard")
    st.write("Explore how Accuracy / QBER depend on noise and Eve probability.")
    analysis_col1, analysis_col2 = st.columns([1, 1])
    # sliders for analysis
    na = analysis_col1.slider("Sweep: max noise", 0.0, 0.5, 0.5, step=0.01)
    steps = analysis_col1.slider("Resolution (steps)", 5, 60, 21, step=1)
    p_eve_for_analysis = analysis_col2.slider("Fix Eve probability for this plot", 0.0, 1.0, p_eve, step=0.01)
    # compute
    noise_range = np.linspace(0.0, na, steps)
    accs = []
    qbers = []
    for n in noise_range:
        rr = simulate_bb84(num_bits, float(n), float(p_eve_for_analysis), seed)
        q = rr["qber"]
        qbers.append(q*100 if not np.isnan(q) else None)
        accs.append((1-q)*100 if not np.isnan(q) else None)

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=noise_range, y=accs, mode="lines+markers", name="Accuracy (%)"))
    fig.add_trace(go.Scatter(x=noise_range, y=qbers, mode="lines+markers", name="QBER (%)"))
    fig.update_layout(title=f"Accuracy & QBER vs Noise (Eve p={p_eve_for_analysis})", xaxis_title="Noise prob", yaxis_title="Percent", template="plotly_white")
    st.plotly_chart(fig, use_container_width=True)

    # optionally show table of last run
    st.markdown("### Last Simulation Summary (if available)")
    if "last_run" in st.session_state:
        lr = st.session_state["last_run"]
        r = lr["res"]
        st.write(f"Sifted length: {r['sift_len']}, QBER: {r['qber']:.4f}")
        if r['sift_len'] > 0:
            df_summary = pd.DataFrame({
                "Alice_sift": r["alice_sift"].astype(int),
                "Bob_sift": r["bob_sift"].astype(int)
            })
            st.dataframe(df_summary.head(50), use_container_width=True)
    else:
        st.info("Run a simulation (Simulation & Encrypt tab) to populate analysis artifacts.")

# -------------------------
# Tab: Chat Demo (live key usage)
# -------------------------
with tabs[3]:
    st.subheader("Live Chat Demo — use the derived key to encrypt messages")
    st.write("This simulates Alice typing a message, encrypting with the QKD key, and Bob decrypting it.")
    if "last_run" not in st.session_state:
        st.info("Run a simulation first (Run BB84 & Encrypt) to create a derived key.")
    else:
        key = st.session_state["last_run"]["derived_key"]
        chat_col1, chat_col2 = st.columns([2, 1])
        with chat_col1:
            user_msg = st.text_area("Alice: Type a message to send to Bob", value="Hello Bob, this is Alice.")
            if st.button("Send (encrypt & deliver)"):
                plaintext = user_msg.encode("utf-8")
                blob = aes_gcm_encrypt(key, plaintext)
                # deliver and decrypt
                try:
                    dec = aes_gcm_decrypt(key, blob)
                    dec_text = dec.decode("utf-8")
                    st.success("Bob decrypted the message successfully:")
                    st.write(f"**Bob receives:** {dec_text}")
                    st.download_button("Download Encrypted Message (.bin)", data=blob, file_name="chat_encrypted.bin")
                except Exception as e:
                    st.error(f"Decryption failed: {e}")
        with chat_col2:
            st.markdown("**Key snippet (demo only)**")
            st.code(key.hex()[:64] + "...", language="text")
            st.caption("Don't reveal keys in real systems — this is for demo purposes only.")

# -------------------------
# Tab: About / Help
# -------------------------
with tabs[4]:
    st.subheader("About this Professional BB84 Demo")
    st.markdown("""
    **What this demo shows**
    - Simulation of BB84 (Alice prepares qubits in random bases; Bob measures in random bases).
    - Optional Eve intercept-resend model and channel noise.
    - Sifting (Alice & Bob keep positions where bases matched) and QBER calculation.
    - Key derivation from sifted bits (SHA-256) and AES-GCM encryption for files/messages.
    - Interactive visuals, analysis dashboard, and a live chat demonstration.

    **Notes & disclaimers**
    - This is an educational demo. Real QKD systems have many more safeguards.
    - The derived key is displayed for demonstration; in practice, keys should remain secret.
    - Qiskit circuit visualization is optional — the app will work without Qiskit.
    """)
    st.markdown("### Qiskit availability")
    if QISKIT_AVAILABLE:
        st.success("Qiskit is installed — you can add circuit visualizations in future improvements.")
    else:
        st.warning("Qiskit is not installed. Circuit visualizations will be skipped. Install `qiskit` in requirements.txt if you want them.")

    st.markdown("---")
    st.write("### Next-level improvements (optional)")
    st.write("""
    - Animated webgl visuals with more polish (e.g., manim, three.js).
    - Multiple protocols (E91, B92), hardware interfacing (IBM Q), authenticated classical channel simulation.
    - User accounts, session persistence, and presentation theme customizations.
    """)

# -------------------------
# Footer
# -------------------------
st.markdown("---")
st.caption("Prepared as a professional demo. Keep key material secret in real applications.")


