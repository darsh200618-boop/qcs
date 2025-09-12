import streamlit as st
import numpy as np

st.title("Quantum Cryptography Simulator (BB84 Protocol)")

# Helper functions
def random_bits(n):
    return np.random.randint(0, 2, n)

def random_bases(n):
    # 0: Rectilinear (+), 1: Diagonal (x)
    return np.random.randint(0, 2, n)

def encode_qubits(bits, bases):
    # Simulate encoding: just a tuple (bit, basis)
    return list(zip(bits, bases))

def measure_qubits(qubits, bases):
    measured = []
    for (bit, basis), meas_basis in zip(qubits, bases):
        if basis == meas_basis:
            measured.append(bit)
        else:
            measured.append(np.random.randint(0, 2))
    return measured

def sift_key(alice_bases, bob_bases, bits):
    return [b for a_base, b_base, b in zip(alice_bases, bob_bases, bits) if a_base == b_base]

# App controls
st.header("Step 1: Generate Alice's Bits and Bases")
n = st.slider("Number of Qubits", min_value=10, max_value=100, value=20)
alice_bits = random_bits(n)
alice_bases = random_bases(n)

st.write("Alice's bits:", alice_bits)
st.write("Alice's bases:", ['+' if b==0 else 'x' for b in alice_bases])

st.header("Step 2: Encode and Send Qubits")
qubits = encode_qubits(alice_bits, alice_bases)
st.write("Encoded qubits (bit, basis):", qubits)

st.header("Step 3: Bob Chooses Measurement Bases")
bob_bases = random_bases(n)
st.write("Bob's bases:", ['+' if b==0 else 'x' for b in bob_bases])

st.header("Step 4: Bob Measures Qubits")
bob_results = measure_qubits(qubits, bob_bases)
st.write("Bob's measurement results:", bob_results)

st.header("Step 5: Sift Key")
alice_key = sift_key(alice_bases, bob_bases, alice_bits)
bob_key = sift_key(alice_bases, bob_bases, bob_results)
st.write("Sifted Key (Alice):", alice_key)
st.write("Sifted Key (Bob):", bob_key)

st.header("Step 6: Compare Keys for Eavesdropping Detection")
if alice_key == bob_key:
    st.success("Keys match! No eavesdropper detected.")
else:
    st.error("Keys do not match! Eavesdropper may be present.")

st.caption("This is a basic BB84 simulator. For more advanced quantum cryptography protocols, let me know!")
