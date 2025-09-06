# app.py
import streamlit as st
import numpy as np
import plotly.graph_objs as go
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image
import io
import os
import base64
import pandas as pd

# ------------------------
# Utilities / BB84 core
# ------------------------
def simulate_bb84_return_bits(num_bits: int, p_noise: float, p_eve: float, seed: int | None = None):
    """
    Simulate BB84 and return sifted key bits for Alice and Bob (as numpy arrays of 0/1),
    plus QBER and sifted length.
    """
    rng = np.random.default_rng(seed)

    alice_bits = rng.integers(0, 2, size=num_bits, dtype=np.int8)
    alice_bases = rng.integers(0, 2, size=num_bits, dtype=np.int8)  # 0=Z,1=X
    bob_bases = rng.integers(0, 2, size=num_bits, dtype=np.int8)
    bob_results = np.empty(num_bits, dtype=np.int8)

    for i in range(num_bits):
        # Eve intercept-resend with probability p_eve
        if rng.random() < p_eve:
            eve_basis = rng.integers(0, 2)
            # Eve measures
            if eve_basis == alice_bases[i]:
                eve_bit = alice_bits[i]
            else:
                eve_bit = rng.integers(0, 2)
            sender_basis = eve_basis
            sender_bit = eve_bit
        else:
            sender_basis = alice_bases[i]
            sender_bit = alice_bits[i]

        # Bob measures (if same basis -> same bit, else random)
        if bob_bases[i] == sender_basis:
            bob_bit = sender_bit
        else:
            bob_bit = rng.integers(0, 2)

        # Channel noise flips bit with prob p_noise
        if rng.random() < p_noise:
            bob_bit ^= 1

        bob_results[i] = bob_bit

    # Sift by matching bases
    sift_mask = alice_bases == bob_bases
    alice_sift = alice_bits[sift_mask]
    bob_sift = bob_results[sift_mask]

    sift_len = int(sift_mask.sum())
    if sift_len > 0:
        errors = np.count_nonzero(alice_sift != bob_sift)
        qber = errors / sift_len
    else:
        qber = float("nan")

    return {
        "alice_sift": alice_sift,
        "bob_sift": bob_sift,
        "qber": qber,
        "sift_len": sift_len,
        "alice_bases": alice_bases,
        "bob_bases": bob_bases,
        "alice_bits": alice_bits,
        "bob_results": bob_results,
    }

def bits_to_hexkey(bit_arr: np.ndarray) -> bytes:
    """Derive a 256-bit key (32 bytes) by hashing the bit string (SHA-256)."""
    if len(bit_arr) == 0:
        # fallback: random key
        return get_random_bytes(32)
    bit_str = "".join(map(str, bit_arr.tolist()))
    h = hashlib.sha256(bit_str.encode("utf-8")).digest()  # 32 bytes
    return h

# AES-CTR encryption / decryption helpers
def aes_ctr_encrypt(key: bytes, plaintext_bytes: bytes):
    # PyCryptodome AES CTR: produce nonce, then ciphertext
    # Use a 16-byte nonce by generating 8-byte nonce (nonce param) and letting counter fill rest (library-specific)
    nonce = get_random_bytes(8)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext_bytes)
    # store nonce + ciphertext for easy transfer
    return nonce + ciphertext

def aes_ctr_decrypt(key: bytes, nonce_and_cipher: bytes):
    nonce = nonce_and_cipher[:8]
    ciphertext = nonce_and_cipher[8:]
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)

# Helper: get default sample image from repo if exists
def load_default_image():
    local_path = "images/windows.png"
    if os.path.exists(local_path):
        return Image.open(local_path)
    return None

# Helper: convert PIL image to bytes (PNG)
def pil_to_bytes(img: Image.Image, fmt="PNG"):
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()

# Helper: friendly bytes -> downloadable name conversion
def make_download_button_bytes(data_bytes: bytes, filename: str, label: str):
    return st.download_button(label=label, data=data_bytes, file_name=filename)

# ------------------------
# Streamlit UI
# ------------------------
st.set_page_config(page_title="Quantum Crypto Simulator — BB84", layout="wide", page_icon="🔐")

st.header("🔐 Quantum Cryptography Simulator — BB84 (Alice → Bob demo)")
st.write(
    "A polished demo: Alice sends an image to Bob. BB84 runs (with optional Eve & channel noise), "
    "Alice & Bob derive a shared key. Bob encrypts the image with the derived key (AES-CTR)."
)

# Sidebar controls
with st.sidebar:
    st.markdown("## Simulation Controls")
    num_bits = st.slider("Number of transmitted qubits (Alice → Bob)", min_value=100, max_value=10000, value=2000, step=100)
    p_noise = st.slider("Channel noise (flip probability)", 0.0, 0.5, 0.03, 0.01)
    p_eve = st.slider("Eve interception probability", 0.0, 1.0, 0.05, 0.01)
    seed = st.number_input("Random seed (for reproducibility)", value=42, step=1)
    st.markdown("---")
    st.markdown("## Image / Output")
    uploaded_file = st.file_uploader("Upload an image (Alice's message). Leave empty to use default.", type=["png", "jpg", "jpeg"])
    auto_encrypt = st.checkbox("Auto-run encryption after simulation", value=True)
    st.markdown("---")
    st.markdown("Developed for presentation — you can download encrypted/decrypted images and logs.")

# Load image (uploaded or default)
image_pil = None
if uploaded_file is not None:
    try:
        image_pil = Image.open(uploaded_file).convert("RGB")
    except Exception as e:
        st.error(f"Could not open uploaded image: {e}")
else:
    image_pil = load_default_image()

if image_pil is None:
    st.warning("No default image found in repo and no upload provided. Please upload an image to continue.")
    st.stop()

# App layout
left, right = st.columns([1, 1])

with left:
    st.subheader("Alice (Sender)")
    st.image(image_pil, caption="Alice's original image", use_container_width=True)
    st.write(f"Image size: {image_pil.size[0]} x {image_pil.size[1]} — mode: {image_pil.mode}")

with right:
    st.subheader("Simulation Controls (quick run)")
    if st.button("Run BB84 (Alice → Bob)"):
        # run and display below via st.session_state
        st.session_state["run_now"] = True

# allow also auto-run if checked
if "run_now" not in st.session_state:
    st.session_state["run_now"] = False

if st.session_state["run_now"] or auto_encrypt:
    # Run simulation
    with st.spinner("Running BB84 simulation..."):
        res = simulate_bb84_return_bits(num_bits=num_bits, p_noise=p_noise, p_eve=p_eve, seed=int(seed))
    qber = res["qber"]
    sift_len = res["sift_len"]
    alice_sift = res["alice_sift"]
    bob_sift = res["bob_sift"]

    st.success("BB84 simulation finished ✅")
    # Show metrics
    c1, c2, c3 = st.columns(3)
    c1.metric("Sifted key length", sift_len)
    c2.metric("QBER (%)", f"{qber*100:.3f}" if not np.isnan(qber) else "N/A")
    c3.metric("Agreement (%)", f"{(1-qber)*100:.3f}" if not np.isnan(qber) else "N/A")

    # Show a small table of the first 30 sifted bits to look professional
    preview_n = min(40, sift_len)
    if preview_n > 0:
        df_preview = pd.DataFrame({
            "Index": np.arange(preview_n),
            "Alice bit": alice_sift[:preview_n].astype(int),
            "Bob bit": bob_sift[:preview_n].astype(int),
        })
        st.subheader("Sample of sifted key (Alice vs Bob)")
        st.dataframe(df_preview, use_container_width=True)
    else:
        st.info("Sifted key length is 0 — increase num_bits.")

    # Derive AES key from sifted bits (hash)
    key_bytes = bits_to_hexkey(alice_sift)
    st.subheader("Derived Key")
    # show a human-friendly hex snippet (not the full key in production)
    st.code(f"SHA-256(keybits) = {key_bytes.hex()}", language="text")

    # Encrypt the image using AES-CTR with derived key
    img_bytes = pil_to_bytes(image_pil, fmt="PNG")  # bytes
    encrypted_blob = aes_ctr_encrypt(key_bytes, img_bytes)
    decrypted_blob = aes_ctr_decrypt(key_bytes, encrypted_blob)

    # Verify decrypt matches original
    ok = decrypted_blob == img_bytes
    if ok:
        st.success("Encrypted & decrypted verification OK — decryption matches original image ✅")
    else:
        st.error("Decryption verification failed (this should not happen).")

    # Display encrypted "before/after" using thumbnails (we can't display binary ciphertext as image,
    # but we can display the decrypted/roundtrip or display encrypted bytes size)
    st.subheader("Encryption Results")
    col_a, col_b = st.columns([1, 1])
    with col_a:
        st.write("Original (Alice → to send)")
        st.image(image_pil, caption="Original image (to be sent)", use_container_width=True)

    with col_b:
        st.write("Encrypted (binary) — not displayable as image")
        st.info(f"Encrypted bytes: {len(encrypted_blob)} bytes\nNonce included (first 8 bytes).")
        st.download_button(label="Download Encrypted Blob (.bin)", data=encrypted_blob, file_name="encrypted_image.bin")

    # Also provide decrypted download to prove it works
    st.download_button(label="Download Decrypted Image (after Bob decrypt)", data=decrypted_blob, file_name="decrypted_image.png")

    # Provide logs and full key download (careful with key security)
    st.subheader("Artifacts & Logs")
    log_text = (
        f"BB84 simulation log\n"
        f"num_bits={num_bits} p_noise={p_noise} p_eve={p_eve} seed={seed}\n"
        f"sift_len={sift_len} qber={qber}\n"
        f"derived_key_hex={key_bytes.hex()}\n"
    )
    st.download_button("Download Simulation Log", data=log_text, file_name="bb84_log.txt")

    # ACCURACY vs Noise interactive plot (Plotly)
    st.subheader("Accuracy vs Noise (interactive)")
    noise_range = np.linspace(0.0, 0.5, 21)
    accuracies = []
    for n in noise_range:
        rr = simulate_bb84_return_bits(num_bits=num_bits, p_noise=float(n), p_eve=p_eve, seed=int(seed))
        q = rr["qber"]
        acc = (1 - q) * 100.0 if not np.isnan(q) else np.nan
        accuracies.append(acc)

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=noise_range, y=accuracies, mode="lines+markers", name="Accuracy (%)"))
    fig.update_layout(xaxis_title="Noise Probability", yaxis_title="Accuracy (%)", template="plotly_white", height=420)
    st.plotly_chart(fig, use_container_width=True)

    # Optional: show a small timeline of first 20 transmissions for a visual step-through
    st.subheader("Transmission step-by-step (first 20 qubits)")
    Nstep = min(20, num_bits)
    df_steps = pd.DataFrame({
        "i": np.arange(Nstep),
        "Alice bit": res["alice_bits"][:Nstep].astype(int),
        "Alice basis": res["alice_bases"][:Nstep].astype(int),
        "Bob basis": res["bob_bases"][:Nstep].astype(int),
        "Bob result (raw)": res["bob_results"][:Nstep].astype(int),
    })
    st.table(df_steps)

    # Reset run flag so repeated button presses behave well
    st.session_state["run_now"] = False

# Footer / About
st.markdown("---")
st.caption("This demo is educational. The derived key is shown for demo purposes only; in real QKD, key material is handled carefully and not revealed.")


