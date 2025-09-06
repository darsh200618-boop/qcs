import streamlit as st
import numpy as np
import matplotlib.pyplot as plt
from PIL import Image
import io

# =====================
# BB84 Simulator
# =====================
def simulate_bb84(num_bits: int = 1000, p_noise: float = 0.05, p_eve: float = 0.0, seed: int | None = None):
    rng = np.random.default_rng(seed)

    alice_bits = rng.integers(0, 2, size=num_bits, dtype=np.int8)
    alice_bases = rng.integers(0, 2, size=num_bits, dtype=np.int8)
    bob_bases = rng.integers(0, 2, size=num_bits, dtype=np.int8)
    bob_results = np.empty(num_bits, dtype=np.int8)

    for i in range(num_bits):
        if rng.random() < p_eve:
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

    sift_mask = (alice_bases == bob_bases)
    alice_sift = alice_bits[sift_mask]
    bob_sift = bob_results[sift_mask]

    sift_len = int(sift_mask.sum())
    if sift_len == 0:
        qber = np.nan
        accuracy = np.nan
    else:
        errors = np.count_nonzero(alice_sift != bob_sift)
        qber = errors / sift_len
        accuracy = 1.0 - qber

    return qber, accuracy, sift_len, alice_sift, bob_sift


# =====================
# Streamlit UI
# =====================
st.set_page_config(page_title="Quantum Cryptography Simulator", page_icon="🔐", layout="wide")

st.title("🔐 Quantum Cryptography Simulator (BB84)")
st.write("An advanced interactive demo of **Quantum Key Distribution** with noise and eavesdropping.")

tabs = st.tabs(["⚡ Simulation", "📊 Graphs", "ℹ️ About"])

# =====================
# Tab 1: Simulation
# =====================
with tabs[0]:
    st.subheader("⚡ Run BB84 Simulation")

    col1, col2 = st.columns(2)

    with col1:
        num_bits = st.slider("Number of bits", 100, 5000, 1000, 100)
        p_noise = st.slider("Noise level", 0.0, 0.5, 0.05, 0.01)
        p_eve = st.slider("Eavesdrop probability", 0.0, 1.0, 0.1, 0.05)
        seed = st.number_input("Random Seed", value=42, step=1)

        if st.button("Run Simulation"):
            qber, accuracy, sift_len, alice_sift, bob_sift = simulate_bb84(num_bits, p_noise, p_eve, seed)

            st.success("Simulation Completed ✅")
            st.metric("Sifted Key Length", sift_len)
            st.metric("QBER (%)", f"{qber*100:.2f}")
            st.metric("Accuracy (%)", f"{accuracy*100:.2f}")

            st.write("🔑 Sample of Final Shared Key:")
            st.code("".join(map(str, alice_sift[:50])), language="text")

    with col2:
        st.image("windows.png", caption="Original Image", use_container_width=True)
        st.info("This image could be encrypted using the secret key derived from BB84.")


# =====================
# Tab 2: Graphs
# =====================
with tabs[1]:
    st.subheader("📊 Accuracy vs Noise")

    noise_range = np.linspace(0, 0.5, 11)
    accuracies = []
    for noise in noise_range:
        _, acc, _, _, _ = simulate_bb84(num_bits, noise, p_eve, seed)
        accuracies.append(acc * 100)

    fig, ax = plt.subplots()
    ax.plot(noise_range, accuracies, marker="o", label=f"Eavesdrop p={p_eve}")
    ax.set_xlabel("Noise Level")
    ax.set_ylabel("Key Accuracy (%)")
    ax.set_title("BB84 Accuracy vs Noise")
    ax.legend()
    st.pyplot(fig)


# =====================
# Tab 3: About
# =====================
with tabs[2]:
    st.subheader("ℹ️ About This Project")
    st.markdown("""
    This **Quantum Cryptography Simulator** demonstrates the **BB84 protocol** for Quantum Key Distribution (QKD).  

    - **Alice** encodes qubits in random bases.  
    - **Bob** measures them with his own random bases.  
    - **Eve** may try to intercept (introducing errors).  
    - Alice and Bob compare bases, sift out mismatches, and estimate **QBER (Quantum Bit Error Rate)**.  

    If QBER is below a threshold, the final secret key can be used for **secure encryption** (like hiding your image 🔒).  

    ---
    **Tools Used:**  
    - Python, Numpy  
    - Streamlit (interactive UI)  
    - Matplotlib (visualization)  
    """)

    st.info("Developed as an advanced demo for Quantum Key Distribution 🔐✨")


