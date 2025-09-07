# app.py
import streamlit as st
import numpy as np
import pandas as pd
import plotly.graph_objs as go
from PIL import Image
import io
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from typing import Dict, Any

# ---------------------------
# Utility / BB84 core
# ---------------------------
def simulate_bb84(num_bits: int, p_noise: float, p_eve: float, seed: int | None = None) -> Dict[str, Any]:
    """
    Simulate BB84 with intercept-resend Eve model.
    Returns arrays for Alice, Bob and Eve and statistics including QBER and sifted keys.
    """
    rng = np.random.default_rng(seed)

    alice_bits = rng.integers(0, 2, size=num_bits, dtype=np.int8)
    alice_bases = rng.integers(0, 2, size=num_bits, dtype=np.int8)  # 0=Z, 1=X
    bob_bases = rng.integers(0, 2, size=num_bits, dtype=np.int8)
    bob_results = np.empty(num_bits, dtype=np.int8)

    # Eve behavior: intercept with probability p_eve per qubit
    eve_intercepted = rng.random(num_bits) < p_eve
    eve_bases = rng.integers(0, 2, size=num_bits, dtype=np.int8)
    eve_results = np.empty(num_bits, dtype=np.int8)

    for i in range(num_bits):
        if eve_intercepted[i]:
            # Eve measures in eve_bases
            if eve_bases[i] == alice_bases[i]:
                eve_results[i] = alice_bits[i]
            else:
                eve_results[i] = rng.integers(0, 2)
            # Eve resends using her measured bit & basis
            sender_basis = eve_bases[i]
            sender_bit = int(eve_results[i])
        else:
            # no Eve: Alice sends original
            sender_basis = alice_bases[i]
            sender_bit = int(alice_bits[i])

        # Bob measures
        if bob_bases[i] == sender_basis:
            bob_bit = sender_bit
        else:
            bob_bit = rng.integers(0, 2)

        # Channel noise (bit flip)
        if rng.random() < p_noise:
            bob_bit ^= 1

        bob_results[i] = int(bob_bit)

    # Sifting: keep positions where Alice and Bob used same basis
    sift_mask = (alice_bases == bob_bases)
    alice_sift = alice_bits[sift_mask]
    bob_sift = bob_results[sift_mask]

    sift_len = int(sift_mask.sum())
    qber = (np.count_nonzero(alice_sift != bob_sift) / sift_len) if sift_len > 0 else float("nan")

    # For Eve: her sifted key is positions where her basis matched Alice's (but she doesn't know which are kept)
    eve_sift_mask = (eve_bases == alice_bases) & eve_intercepted
    eve_sift = eve_results[eve_sift_mask]

    return {
        "alice_bits": alice_bits,
        "alice_bases": alice_bases,
        "bob_bases": bob_bases,
        "bob_results": bob_results,
        "eve_intercepted": eve_intercepted,
        "eve_bases": eve_bases,
        "eve_results": eve_results,
        "sift_mask": sift_mask,
        "alice_sift": alice_sift,
        "bob_sift": bob_sift,
        "eve_sift": eve_sift,
        "sift_len": sift_len,
        "qber": qber,
    }

def derive_key_from_bits(bit_arr: np.ndarray) -> bytes:
    """Derive a 256-bit (32 byte) key by SHA-256 hashing the bit string."""
    if len(bit_arr) == 0:
        # fallback random key to avoid empty-key errors
        return get_random_bytes(32)
    s = "".join(map(str, bit_arr.tolist()))
    return hashlib.sha256(s.encode("utf-8")).digest()

# AES-GCM helpers (authenticated encryption)
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

# Image / file helpers
def load_default_image() -> Image.Image | None:
    p = "images/windows.png"
    if os.path.exists(p):
        return Image.open(p).convert("RGB")
    return None

def pil_to_bytes(img: Image.Image, fmt: str = "PNG") -> bytes:
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()

def bytes_to_pil(b: bytes) -> Image.Image:
    return Image.open(io.BytesIO(b)).convert("RGB")

# Eve's "view" reconstruction:
def eve_reconstruct_bytes(original_bytes: bytes, alice_bits: np.ndarray, eve_results: np.ndarray) -> bytes:
    """
    Make a simple *visual* reconstruction of what Eve 'sees':
    - Build a bit-difference mask between Alice's bits and Eve's measured bits
    - Repeat the mask across the bytes and XOR with original_bytes to create a corrupted image that
      visually shows the effect of intercept-resend measurements.
    This is a pedagogical visualization, not a physical exact model.
    """
    if len(alice_bits) == 0 or len(eve_results) == 0:
        return original_bytes

    # Build a bit mask: 1 where Alice != Eve (error introduced), else 0
    # To keep it simple, compare over min length
    min_len = min(len(alice_bits), len(eve_results))
    diff_bits = (alice_bits[:min_len] != eve_results[:min_len]).astype(np.uint8)

    # Expand bit array to bytes: pack bits into a repeated pattern across file length
    # create a byte mask by repeating each bit 8 times then tiling
    bit_string = "".join(map(str, diff_bits.tolist()))
    if len(bit_string) == 0:
        return original_bytes
    # create a repeating pattern long enough
    rep = (bit_string * ((len(original_bytes) * 8) // len(bit_string) + 1))[:len(original_bytes) * 8]
    # pack into bytes
    mask_bytes = bytearray()
    for i in range(0, len(rep), 8):
        byte = int(rep[i:i+8], 2)
        mask_bytes.append(byte)
    # XOR original with mask -> corrupted bytes
    ob = bytearray(original_bytes)
    for i in range(min(len(ob), len(mask_bytes))):
        ob[i] ^= mask_bytes[i]
    return bytes(ob)

# ---------------------------
# Streamlit UI
# ---------------------------
st.set_page_config(page_title="Quantum Crypto Simulator — BB84 (Pro)", layout="wide", page_icon="🔐")

st.title("🔐 Quantum Crypto Simulator — BB84 (Professional)")
st.markdown(
    "Two-tab professional demo. **Simulation**: Alice sends a file → BB84 runs → derive key → if QBER ≤ 11% Bob encrypts the file. "
    "**Graphs & Analysis**: advanced sweeps and summaries."
)

# Sidebar controls (global)
with st.sidebar:
    st.header("Simulation Controls")
    num_bits = st.slider("Number of transmitted qubits (Alice → Bob)", 200, 10000, 2000, step=100)
    p_noise = st.slider("Channel noise (flip probability)", 0.0, 0.5, 0.03, step=0.01)
    p_eve = st.slider("Eve interception probability", 0.0, 1.0, 0.05, step=0.01)
    seed = st.number_input("Random seed (for reproducibility)", value=42, step=1)
    st.markdown("---")
    st.markdown("File to send (Alice)")
    uploaded_file = st.file_uploader("Choose an image (png/jpg) or any file (will be encrypted as bytes)", type=None)
    if uploaded_file is None:
        st.markdown("No upload — default sample image will be used if available in `images/`.")
    st.markdown("---")
    st.caption("QBER threshold: if QBER > 11% the run will be aborted to preserve security (as in BB84 theory).")

# Two main tabs
tabs = st.tabs(["🛰️ Simulation", "📈 Graphs & Analysis"])

# ---------------------------
# Tab 1: Simulation
# ---------------------------
with tabs[0]:
    st.header("Simulation — Alice sends file, BB84 runs, Bob encrypts (if secure)")
    col_left, col_right = st.columns([1, 1])

    # Load image or file bytes
    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        file_name = uploaded_file.name
        # attempt to show thumbnail if image
        try:
            preview_img = Image.open(io.BytesIO(file_bytes)).convert("RGB")
            st.sidebar.success(f"Loaded upload: {file_name} ({len(file_bytes)} bytes)")
        except Exception:
            preview_img = None
            st.sidebar.success(f"Loaded upload (non-image): {file_name} ({len(file_bytes)} bytes)")
    else:
        default_img = load_default_image()
        if default_img is not None:
            preview_img = default_img
            file_bytes = pil_to_bytes(default_img, fmt="PNG")
            file_name = "windows.png"
            st.sidebar.info("Using default sample image `images/windows.png`")
        else:
            preview_img = None
            file_bytes = None
            file_name = None

    with col_left:
        st.subheader("Alice (Sender)")
        if preview_img is not None:
            st.image(preview_img, caption=f"Alice's file: {file_name}", use_container_width=True)
            st.write(f"File size: {len(file_bytes)} bytes")
        else:
            st.warning("No file is provided. Upload a file or add `images/windows.png` to the repo.")

    with col_right:
        st.subheader("BB84 Controls & Run")
        st.write("Adjust parameters in the sidebar, then click **Run BB84**.")
        run_btn = st.button("▶ Run BB84 & Attempt Encrypt")
        if run_btn:
            if file_bytes is None:
                st.error("No file available to send. Upload or add default image.")
            else:
                # Run simulation
                with st.spinner("Running BB84 simulation..."):
                    res = simulate_bb84(num_bits=num_bits, p_noise=p_noise, p_eve=p_eve, seed=int(seed))

                qber = res["qber"]
                sift_len = res["sift_len"]
                st.success("BB84 simulation completed")

                # Metrics
                mcol1, mcol2, mcol3 = st.columns(3)
                mcol1.metric("Sifted key length", sift_len)
                mcol2.metric("QBER (%)", f"{qber*100:.3f}" if not np.isnan(qber) else "N/A")
                mcol3.metric("Agreement (%)", f"{(1-qber)*100:.3f}" if not np.isnan(qber) else "N/A")

                # Show small table of sifted bits
                if sift_len > 0:
                    preview_n = min(60, sift_len)
                    df_preview = pd.DataFrame({
                        "index": np.arange(preview_n),
                        "Alice": res["alice_sift"][:preview_n].astype(int),
                        "Bob": res["bob_sift"][:preview_n].astype(int)
                    })
                    st.subheader("Sample of sifted key (Alice vs Bob)")
                    st.dataframe(df_preview, use_container_width=True)
                else:
                    st.info("Sifted key length is zero. Increase number of qubits.")

                # QBER threshold check
                QBER_THRESHOLD = 0.11  # 11%
                if np.isnan(qber):
                    st.error("QBER undefined (no sifted bits). Aborting.")
                    aborted = True
                elif qber > QBER_THRESHOLD:
                    st.error(f"QBER = {qber*100:.3f}% > 11%: ABORTING transfer for security. No encryption will be done.")
                    aborted = True
                else:
                    st.success(f"QBER = {qber*100:.3f}% ≤ 11% → Proceeding to derive key & encrypt.")
                    aborted = False

                # Derive keys
                alice_key = derive_key_from_bits(res["alice_sift"])
                bob_key = derive_key_from_bits(res["bob_sift"])
                # Note: In practice they would perform error correction & privacy amplification; here we use raw sifted bits

                st.subheader("Derived Key (demo only)")
                st.code(f"Alice key (SHA-256 of sifted bits): {alice_key.hex()}", language="text")
                # In real system you would not reveal this. Keep as demo.

                # Create Eve's reconstructed file (visualization)
                eve_recon_bytes = eve_reconstruct_bytes(original_bytes=file_bytes,
                                                        alice_bits=res["alice_bits"],
                                                        eve_results=res["eve_results"])
                try:
                    eve_img_preview = Image.open(io.BytesIO(eve_recon_bytes)).convert("RGB")
                except Exception:
                    eve_img_preview = None

                # If not aborted, encrypt with Bob's key (or Alice's agreed key)
                encrypted_blob = None
                decrypted_blob = None
                if not aborted:
                    with st.spinner("Encrypting file with derived key (AES-GCM)..."):
                        encrypted_blob = aes_gcm_encrypt(bob_key, file_bytes)
                        try:
                            decrypted_blob = aes_gcm_decrypt(bob_key, encrypted_blob)
                            verified = decrypted_blob == file_bytes
                        except Exception:
                            verified = False
                    if verified:
                        st.success("Encryption + decryption verification OK — Bob can recover the file.")
                    else:
                        st.error("Verification FAILED — decryption mismatch (this is unexpected if QBER low).")

                # Display results & downloads
                st.markdown("---")
                col_o, col_e, col_b = st.columns([1, 1, 1])
                with col_o:
                    st.write("**Original (Alice)**")
                    if preview_img:
                        st.image(preview_img, use_container_width=True)
                    else:
                        st.write(f"File: {file_name} ({len(file_bytes)} bytes)")
                    if not aborted:
                        st.download_button("Download Original (Alice)", data=file_bytes, file_name=f"alice_{file_name}")

                with col_e:
                    st.write("**Eve's View (reconstructed / corrupted)**")
                    if eve_img_preview is not None:
                        st.image(eve_img_preview, use_container_width=True, caption="Eve's reconstructed image (visualized corruption)")
                    else:
                        st.write(f"Eve's reconstructed bytes preview: {len(eve_recon_bytes)} bytes")
                    st.download_button("Download Eve's blob (.bin)", data=eve_recon_bytes, file_name="eve_reconstruction.bin")

                with col_b:
                    st.write("**Bob (Receiver)**")
                    if not aborted and decrypted_blob is not None:
                        try:
                            bob_img = Image.open(io.BytesIO(decrypted_blob)).convert("RGB")
                            st.image(bob_img, use_container_width=True, caption="Bob's recovered image (after decrypt)")
                        except Exception:
                            st.write(f"Recovered file bytes: {len(decrypted_blob)}")
                        st.download_button("Download Encrypted Blob (.bin)", data=encrypted_blob, file_name="encrypted_blob.bin")
                        st.download_button("Download Decrypted (Bob) file", data=decrypted_blob, file_name=f"bob_decrypted_{file_name}")
                    else:
                        st.info("Bob did not receive a decryptable file (transfer aborted or missing).")

                # Save last run artifacts for the Analysis tab
                st.session_state["last_run"] = {
                    "params": {"num_bits": num_bits, "p_noise": p_noise, "p_eve": p_eve, "seed": seed},
                    "res": res,
                    "alice_key": alice_key,
                    "bob_key": bob_key,
                    "encrypted_blob": encrypted_blob,
                    "decrypted_blob": decrypted_blob,
                    "file_name": file_name,
                }

# ---------------------------
# Tab 2: Graphs & Analysis
# ---------------------------
with tabs[1]:
    st.header("Graphs & Advanced Analysis")
    st.markdown("Interactive sweeps to explore how QBER and accuracy depend on channel noise and Eve activity.")

    # allow interactive sweep settings
    col1, col2, col3 = st.columns([1, 1, 1])
    with col1:
        sweep_num_bits = st.number_input("Bits used for analysis (per simulation)", min_value=200, max_value=10000, value=2000, step=100)
        sweep_seed = st.number_input("Seed for sweeps", value=1234, step=1)
    with col2:
        noise_max = st.slider("Noise sweep max", 0.0, 0.5, 0.5, step=0.01)
        noise_steps = st.slider("Noise steps", 5, 60, 21, step=1)
    with col3:
        eve_max = st.slider("Eve sweep max", 0.0, 1.0, 1.0, step=0.01)
        eve_steps = st.slider("Eve steps", 5, 41, 21, step=1)

    do_sweep = st.button("Run Analysis Sweeps")
    if do_sweep:
        with st.spinner("Running sweeps (this may take a few seconds)..."):
            noise_vals = np.linspace(0.0, noise_max, noise_steps)
            accs = []
            qbers = []
            for n in noise_vals:
                r = simulate_bb84(num_bits=sweep_num_bits, p_noise=float(n), p_eve=float(p_eve), seed=int(sweep_seed))
                q = r["qber"]
                qbers.append(q*100 if not np.isnan(q) else None)
                accs.append((1-q)*100 if not np.isnan(q) else None)

            fig1 = go.Figure()
            fig1.add_trace(go.Scatter(x=noise_vals, y=accs, mode="lines+markers", name="Accuracy (%)"))
            fig1.add_trace(go.Scatter(x=noise_vals, y=qbers, mode="lines+markers", name="QBER (%)"))
            fig1.update_layout(title="Accuracy & QBER vs Noise (fixed Eve)", xaxis_title="Noise prob", yaxis_title="Percent", template="plotly_white", height=420)
            st.plotly_chart(fig1, use_container_width=True)

            # Eve sweep for fixed noise = current p_noise control
            eve_vals = np.linspace(0.0, eve_max, eve_steps)
            qbers_eve = []
            for e in eve_vals:
                r2 = simulate_bb84(num_bits=sweep_num_bits, p_noise=float(p_noise), p_eve=float(e), seed=int(sweep_seed))
                q2 = r2["qber"]
                qbers_eve.append(q2*100 if not np.isnan(q2) else None)

            fig2 = go.Figure()
            fig2.add_trace(go.Scatter(x=eve_vals, y=qbers_eve, mode="lines+markers", name="QBER (%) vs Eve"))
            fig2.update_layout(title=f"QBER vs Eve probability (noise fixed at {p_noise})", xaxis_title="Eve intercept prob", yaxis_title="QBER (%)", template="plotly_white", height=420)
            st.plotly_chart(fig2, use_container_width=True)

            st.success("Sweeps complete — explore the plots above.")
    else:
        st.info("Run sweeps to see interactive plots. You can also run a Simulation first to populate 'Last run' summary.")

    # Last run summary table
    st.markdown("---")
    st.subheader("Last Simulation Summary")
    if "last_run" in st.session_state:
        last = st.session_state["last_run"]
        params = last["params"]
        st.write("Parameters:", params)
        r = last["res"]
        st.write(f"Sifted length: {r['sift_len']}, QBER: {r['qber']:.4f}")
        if r['sift_len'] > 0:
            df_summary = pd.DataFrame({
                "Alice_sift": r["alice_sift"].astype(int),
                "Bob_sift": r["bob_sift"].astype(int)
            })
            st.dataframe(df_summary.head(200), use_container_width=True)
    else:
        st.info("No simulation run stored yet. Run a simulation in the Simulation tab first.")

# Footer
st.markdown("---")
st.caption("Educational demo. The app reveals keys and artifacts for demonstration; in real QKD, keys and raw data are handled confidentially.")

