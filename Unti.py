import streamlit as st
import numpy as np
import matplotlib.pyplot as plt

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

    return qber, accuracy, sift_len


# =====================
# Streamlit UI
# =====================
st.title("🔐 Quantum Key Distribution Simulator (BB84)")
st.write("Demo of BB84 protocol with noise and eavesdropping.")

# Sidebar controls
num_bits = st.sidebar.slider("Number of bits", 100, 5000, 1000, 100)
p_noise = st.sidebar.slider("Noise level", 0.0, 0.5, 0.05, 0.01)
p_eve = st.sidebar.slider("Eavesdrop probability", 0.0, 1.0, 0.1, 0.05)
seed = st.sidebar.number_input("Random Seed", value=42, step=1)

# Run simulation
qber, accuracy, sift_len = simulate_bb84(num_bits, p_noise, p_eve, seed)

# Show results
st.metric("Sifted Key Length", sift_len)
st.metric("QBER (%)", f"{qber*100:.2f}")
st.metric("Accuracy (%)", f"{accuracy*100:.2f}")

# Plot Accuracy vs Noise
noise_range = np.linspace(0, 0.5, 11)
accuracies = []
for noise in noise_range:
    _, acc, _ = simulate_bb84(num_bits, noise, p_eve, seed)
    accuracies.append(acc * 100)

fig, ax = plt.subplots()
ax.plot(noise_range, accuracies, marker="o", label=f"Eavesdrop p={p_eve}")
ax.set_xlabel("Noise Level")
ax.set_ylabel("Key Accuracy (%)")
ax.set_title("BB84 Accuracy vs Noise")
ax.legend()
st.pyplot(fig)
