import streamlit as st
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from PIL import Image
import io, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib

# ---------------------------
# Utility functions
# ---------------------------

def load_default_image():
    """Load default image from repo/images/windows.png if exists"""
    default_path = os.path.join("images", "windows.png")
    if os.path.exists(default_path):
        return Image.open(default_path).convert("RGB")
    return None

def pil_to_bytes(img: Image.Image, fmt="PNG") -> bytes:
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()

def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct

def aes_gcm_decrypt(key: bytes, blob: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce, ct = blob[:12], blob[12:]
    return aesgcm.decrypt(nonce, ct, None)

def derive_key_from_bits(bits: np.ndarray) -> bytes:
    bitstring = "".join(str(b) for b in bits)
    return hashlib.sha256(bitstring.encode()).digest()

# ---------------------------
# BB84 Simulation
# ---------------------------

def simulate_bb84(num_bits=1000, p_noise=0.05, p_eve=0.0, seed=None):
    rng = np.random.default_rng(seed)

    alice_bits = rng.integers(0, 2, size=num_bits, dtype=np.int8)
    alice_bases = rng.integers(0, 2, size=num_bits, dtype=np.int8)
    bob_bases = rng.integers(0, 2, size=num_bits, dtype=np.int8)
    bob_results = np.empty(num_bits, dtype=np.int8)

    for i in range(num_bits):
        if rng.random() < p_eve:  # Eve intercepts
            eve_basis = rng.integers(0, 2)
            eve_bit = alice_bits[i] if eve_basis == alice_bases[i] else rng.integers(0, 2)
            sender_basis, sender_bit = eve_basis, eve_bit
        else:
            sender_basis, sender_bit = alice_bases[i], alice_bits[i]

        # Bob measures
        bob_bit = sender_bit if bob_bases[i] == sender_basis else rng.integers(0, 2)
        if rng.random() < p_noise:
            bob_bit ^= 1
        bob_results[i] = bob_bit

    sift_mask = alice_bases == bob_bases
    alice_sift = alice_bits[sift_mask]
    bob_sift = bob_results[sift_mask]
    sift_len = int(sift_mask.sum())

    if sift_len == 0:
        qber, accuracy = np.nan, np.nan
    else:
        errors = np.count_nonzero(alice_sift != bob_sift)
        qber = errors / sift_len
        accuracy = 1.0 - qber

    return {
        "qber": qber,
        "accuracy": accuracy,
        "sift_len": sift_len,
        "alice_sift": alice_sift,
        "bob_sift": bob_sift,
    }

# ---------------------------
# Streamlit App
# ---------------------------

st.set_page_config(page_title="Quantum Cryptography Simulator", layout="wide")
st.title("🔐 Quantum Cryptography Simulator — BB84 Protocol")

# Sidebar controls
st.sidebar.header("Controls")
num_bits = st.sidebar.slider("Number of qubits sent", 100, 5000, 1000, step=100)
p_noise = st.sidebar.slider("Noise probability", 0.0, 0.5, 0.05, 0.01)
p_eve = st.sidebar.slider("Eavesdrop probability", 0.0, 1.0, 0.1, 0.05)
seed = st.sidebar.number_input("Random Seed", value=42, step=1)
uploaded_file = st.sidebar.file_uploader("Upload file/image", type=["png", "jpg", "jpeg"])

# Tabs
tabs = st.tabs(["Simulation", "Graphs & Analysis"])

# ---------------------------
# Tab 1: Simulation
# ---------------------------
with tabs[0]:
    st.header("Simulation — Alice sends file, BB84 runs, Bob encrypts (if secure)")

    # Load input file
    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        file_name = uploaded_file.name
        try:
            preview_img = Image.open(io.BytesIO(file_bytes)).convert("RGB")
        except Exception:
            preview_img = None
    else:
        default_img = load_default_image()
        if default_img is not None:
            preview_img = default_img
            file_bytes = pil_to_bytes(default_img, "PNG")
            file_name = "windows.png"
            st.sidebar.info("Using default sample image `images/windows.png`")
        else:
            preview_img = None
            file_bytes = None
            file_name = None

    st.subheader("Alice (Sender)")
    if preview_img is not None:
        st.image(preview_img, caption=f"Alice's file: {file_name}", use_container_width=True)
        st.write(f"File size: {len(file_bytes)} bytes")
    elif file_bytes is not None:
        st.write(f"Alice's file: {file_name} ({len(file_bytes)} bytes)")
    else:
        st.warning("No file provided.")

    st.subheader("Run BB84")
    run_btn = st.button("▶ Run BB84 & Encrypt")

    if run_btn and file_bytes is not None:
        res = simulate_bb84(num_bits=num_bits, p_noise=p_noise, p_eve=p_eve, seed=int(seed))
        qber, sift_len = res["qber"], res["sift_len"]

        # Metrics
        mcol1, mcol2, mcol3 = st.columns(3)
        mcol1.metric("Sifted key length", sift_len)
        mcol2.metric("QBER (%)", f"{qber*100:.3f}" if not np.isnan(qber) else "N/A")
        mcol3.metric("Agreement (%)", f"{(1-qber)*100:.3f}" if not np.isnan(qber) else "N/A")

        if sift_len > 0:
            df_preview = pd.DataFrame({
                "Index": np.arange(min(40, sift_len)),
                "Alice": res["alice_sift"][:40].astype(int),
                "Bob": res["bob_sift"][:40].astype(int),
            })
            st.dataframe(df_preview, use_container_width=True)

        # Threshold check
        QBER_THRESHOLD = 0.11
        if np.isnan(qber) or qber > QBER_THRESHOLD:
            st.error(f"QBER {qber*100:.2f}% exceeds threshold → Transmission aborted.")
            aborted = True
        else:
            st.success(f"QBER {qber*100:.2f}% within safe range → Transmission continues.")
            aborted = False

        # Keys
        alice_key = derive_key_from_bits(res["alice_sift"])
        bob_key = derive_key_from_bits(res["bob_sift"])
        st.code(f"Alice key (SHA256): {alice_key.hex()}")

        # Eve’s corrupted view (pixelated image if possible)
        eve_img = None
        if preview_img is not None:
            eve_img = preview_img.copy()
            small = eve_img.resize((max(1, eve_img.width//12), max(1, eve_img.height//12)))
            eve_img = small.resize(preview_img.size, Image.NEAREST)

        # Encrypt/Decrypt if not aborted
        decrypted_blob = None
        if not aborted:
            encrypted_blob = aes_gcm_encrypt(bob_key, file_bytes)
            try:
                decrypted_blob = aes_gcm_decrypt(bob_key, encrypted_blob)
                ok = decrypted_blob == file_bytes
            except Exception:
                ok = False
            if ok:
                st.success("Encryption & decryption verified ✅")
            else:
                st.error("Decryption failed ❌")

        # Show results
        st.markdown("---")
        st.subheader("Transmission Results")

        st.write("**Alice's Original**")
        if preview_img:
            st.image(preview_img, use_container_width=True)
        if file_bytes:
            st.download_button("⬇ Download Original", file_bytes, file_name=file_name)

        st.write("**Eve’s Corrupted View**")
        if eve_img:
            st.image(eve_img, caption="Pixelated corruption", use_container_width=True)
        else:
            st.info("Eve sees meaningless corrupted data.")

        st.write("**Bob’s Received**")
        if decrypted_blob:
            try:
                bob_img = Image.open(io.BytesIO(decrypted_blob)).convert("RGB")
                st.image(bob_img, caption="Bob's recovered image", use_container_width=True)
            except Exception:
                st.write(f"Recovered file size: {len(decrypted_blob)} bytes")
            st.download_button("⬇ Download Decrypted", decrypted_blob, file_name=f"bob_{file_name}")
        else:
            st.info("Bob did not receive a usable file.")

        # Save for analysis tab
        st.session_state["last_run"] = {
            "params": {"num_bits": num_bits, "p_noise": p_noise, "p_eve": p_eve},
            "res": res,
        }

# ---------------------------
# Tab 2: Graphs & Analysis
# ---------------------------
with tabs[1]:
    st.header("Graphs & Analysis")
    last = st.session_state.get("last_run")

    if last:
        res = last["res"]
        st.write("### Last Run Parameters")
        st.json(last["params"])

        # Accuracy vs Noise
        noise_range = np.linspace(0, 0.5, 11)
        accs = [simulate_bb84(num_bits, n, p_eve, seed)["accuracy"]*100 for n in noise_range]
        fig, ax = plt.subplots()
        ax.plot(noise_range, accs, marker="o")
        ax.set_xlabel("Noise Level")
        ax.set_ylabel("Accuracy (%)")
        ax.set_title("Accuracy vs Noise")
        st.pyplot(fig)

        # QBER vs Eve
        eve_range = np.linspace(0, 1.0, 11)
        qbers = [simulate_bb84(num_bits, p_noise, e, seed)["qber"]*100 for e in eve_range]
        fig2, ax2 = plt.subplots()
        ax2.plot(eve_range, qbers, marker="x", color="red")
        ax2.set_xlabel("Eavesdrop Probability")
        ax2.set_ylabel("QBER (%)")
        ax2.set_title("QBER vs Eve Probability")
        st.pyplot(fig2)
    else:
        st.info("Run a simulation first in the Simulation tab.")
