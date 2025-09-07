"""
Streamlit BB84 Quantum Cryptography Simulator
Single-file Streamlit app that:
 - Converts an uploaded image to a bitstream
 - Simulates BB84 transmission from Alice -> Bob with optional Eve
 - Shows Original vs Bob (no Eve) vs Bob (with Eve) images
 - Generates a quantum-derived AES-256 key (via SHA-256 of sifted bits)
 - Encrypts image with: Random key and Quantum key (AES-GCM)
 - Displays QBER, sifted/key lengths, and ability to download results

Dependencies:
 - streamlit
 - pillow (PIL)
 - numpy
 - pycryptodome (Crypto)

Run:
 streamlit run bb84_streamlit_app.py

"""

import streamlit as st
from PIL import Image, ImageOps
import numpy as np
import io
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# ----------------- Helper functions -----------------

def image_to_bits(img: Image.Image) -> (np.ndarray, tuple):
    # Resize to manageable size (max 128x128) while keeping aspect ratio
    max_dim = 128
    w, h = img.size
    scale = min(max_dim/w, max_dim/h, 1.0)
    if scale < 1.0:
        img = img.resize((int(w*scale), int(h*scale)), Image.LANCZOS)
    img = img.convert('RGB')
    arr = np.array(img)
    flat = arr.flatten()
    bits = np.unpackbits(flat)
    return bits, arr.shape


def bits_to_image(bits: np.ndarray, shape: tuple) -> Image.Image:
    total_bytes = (bits.size + 7) // 8
    padded = np.zeros(total_bytes * 8, dtype=np.uint8)
    padded[:bits.size] = bits
    bytes_arr = np.packbits(padded).reshape(-1)
    # Trim to required length
    expected_len = np.prod(shape)
    bytes_arr = bytes_arr[:expected_len]
    arr = bytes_arr.reshape(shape)
    return Image.fromarray(arr.astype(np.uint8))


def generate_random_bases(n):
    return np.random.randint(2, size=n)  # 0 = computational, 1 = diagonal


def measure(bits, bases_sent, bases_meas):
    # If bases match, measurement equals sent bit. If not, random bit.
    same = bases_sent == bases_meas
    measured = np.where(same, bits, np.random.randint(2, size=bits.size))
    return measured


def simulate_bb84(bitstream, p_eve=0.0, p_noise=0.0):
    n = bitstream.size
    alice_bases = generate_random_bases(n)
    bob_bases = generate_random_bases(n)

    # Eve intercept-resend model: with probability p_eve, Eve measures in random basis and resends
    eve_mask = np.random.random(n) < p_eve
    eve_bases = generate_random_bases(n)

    # Start with Alice sending the bits
    sent_bits = bitstream.copy()

    # Eve's action: when she intercepts, she measures and resends the measured bit
    measured_by_eve = np.empty(n, dtype=np.uint8)
    measured_by_eve[:] = sent_bits
    if eve_mask.any():
        measured_by_eve[eve_mask] = measure(sent_bits[eve_mask], alice_bases[eve_mask], eve_bases[eve_mask])
    # After Eve (or not), the bits that Bob receives are:
    received_before_noise = measured_by_eve

    # Add channel noise: flip some bits according to p_noise
    noise_mask = np.random.random(n) < p_noise
    received_after_noise = received_before_noise.copy()
    received_after_noise[noise_mask] ^= 1

    # Bob measures according to his bases
    bob_measured = measure(received_after_noise, alice_bases, bob_bases)  # note: if Eve resent, the "sent" basis for re-prepared qubit is eve_bases where intercepted

    # Sifting: positions where alice_bases == bob_bases are kept
    sift_mask = alice_bases == bob_bases

    alice_sifted = sent_bits[sift_mask]
    bob_sifted = bob_measured[sift_mask]

    # QBER: fraction of disagreed bits in sifted
    if sift_mask.sum() > 0:
        qber = np.mean(alice_sifted != bob_sifted)
    else:
        qber = 0.0

    results = {
        'alice_bases': alice_bases,
        'bob_bases': bob_bases,
        'eve_bases': eve_bases,
        'eve_mask': eve_mask,
        'sent_bits': sent_bits,
        'received_bits': received_after_noise,
        'bob_measured': bob_measured,
        'sift_mask': sift_mask,
        'alice_sifted': alice_sifted,
        'bob_sifted': bob_sifted,
        'qber': qber
    }
    return results


def derive_key_from_bits(bits, key_bytes=32):
    # Hash the bits into key_bytes using SHA-256/512 as needed
    b = np.packbits(bits).tobytes()
    digest = hashlib.sha256(b).digest()
    if key_bytes <= len(digest):
        return digest[:key_bytes]
    else:
        # extend using repeated hashing
        cur = digest
        out = bytearray(cur)
        while len(out) < key_bytes:
            cur = hashlib.sha256(cur).digest()
            out.extend(cur)
        return bytes(out[:key_bytes])


def aes_gcm_encrypt(data: bytes, key: bytes):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce + tag + ciphertext


def aes_gcm_decrypt(blob: bytes, key: bytes):
    nonce = blob[:12]
    tag = blob[12:28]
    ciphertext = blob[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def pil_image_to_bytes(img: Image.Image, fmt='PNG'):
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()


def make_eve_visual(img: Image.Image, seed=None):
    # Return a pixelated, corrupted version of the image to represent Eve's visual
    if seed is not None:
        np.random.seed(seed)
    small = img.resize((max(8, img.width//16), max(8, img.height//16)), Image.NEAREST)
    # Add random noise to the small image
    arr = np.array(small).astype(np.int32)
    noise = (np.random.randn(*arr.shape) * 50).astype(np.int32)
    arr = np.clip(arr + noise, 0, 255).astype(np.uint8)
    pixelated = Image.fromarray(arr).resize(img.size, Image.NEAREST)
    # Add blocky mosaic overlay
    overlay = pixelated.filter(ImageFilterBox(3)) if 'ImageFilterBox' in globals() else pixelated
    return overlay

# small compatibility filter if Pillow has ImageFilter.BoxBlur missing etc
try:
    from PIL import ImageFilter
    def ImageFilterBox(r):
        return ImageFilter.BoxBlur(r)
except Exception:
    def ImageFilterBox(r):
        return ImageFilter.BLUR

# ----------------- Streamlit UI -----------------

st.set_page_config(layout='wide', page_title='BB84 Simulator')

st.title('BB84 Quantum Cryptography Simulator — Streamlit')
st.write('Simulate BB84, produce a quantum key and use it to AES-GCM encrypt an image. Compare results with a random key.')

# Sidebar controls
with st.sidebar:
    st.header('Simulation Controls')
    p_eve = st.slider('Eavesdropper probability (p_eve)', min_value=0.0, max_value=1.0, value=0.05, step=0.01)
    p_noise = st.slider('Channel noise probability (p_noise)', min_value=0.0, max_value=0.1, value=0.01, step=0.001)
    reveal_sample_frac = st.slider('Fraction of sifted bits revealed for QBER estimate', 0.0, 0.5, 0.1, step=0.01)
    key_bytes = st.selectbox('AES key length (bytes)', [16, 24, 32], index=2)
    st.markdown('---')
    uploaded = st.file_uploader('Upload an image (PNG/JPEG). If none uploaded, a sample will be used.', type=['png','jpg','jpeg'])
    run_button = st.button('Run Simulation')

# Load sample image if none
if uploaded is None:
    try:
        sample_img = Image.open(io.BytesIO(base64.b64decode(SAMPLE_IMAGE_BASE64)))
    except Exception:
        # fallback: generate small gradient
        arr = np.zeros((64,64,3), dtype=np.uint8)
        for i in range(64):
            for j in range(64):
                arr[i,j] = [(i*4)%256,(j*4)%256,((i+j)*2)%256]
        sample_img = Image.fromarray(arr)
    img = sample_img
else:
    img = Image.open(uploaded).convert('RGB')

# show original on left
col1, col2 = st.columns([1,1])
with col1:
    st.subheader('Original Image')
    st.image(img, use_container_width=True)

# Process image to bits
bits, shape = image_to_bits(img)
st.write(f'Image converted → {bits.size} bits ({np.prod(shape)} bytes, shape={shape})')

if run_button:
    st.info('Running BB84 simulation...')
    # run two simulations: without Eve and with Eve
    res_no_eve = simulate_bb84(bits, p_eve=0.0, p_noise=p_noise)
    res_with_eve = simulate_bb84(bits, p_eve=p_eve, p_noise=p_noise)

    # Reconstruct Bob images from measured bits (use bob_measured aligned to Alice? We will take bob_measured and reconstruct bytes in original layout)
    bob_bits_no_eve = res_no_eve['bob_measured']
    bob_bits_with_eve = res_with_eve['bob_measured']

    img_bob_no_eve = bits_to_image(bob_bits_no_eve, shape)
    img_bob_with_eve = bits_to_image(bob_bits_with_eve, shape)

    # Sifted keys
    alice_sifted = res_with_eve['alice_sifted']
    bob_sifted = res_with_eve['bob_sifted']
    sift_len = alice_sifted.size

    # Reveal sample for QBER estimation
    sample_n = int(sift_len * reveal_sample_frac)
    if sample_n > 0 and sift_len > 0:
        sample_idx = np.random.choice(sift_len, size=sample_n, replace=False)
        revealed_a = alice_sifted[sample_idx]
        revealed_b = bob_sifted[sample_idx]
        est_qber = np.mean(revealed_a != revealed_b)
        # remove revealed bits from final key (simulate sacrifice)
        mask = np.ones(sift_len, dtype=bool)
        mask[sample_idx] = False
        final_alice = alice_sifted[mask]
        final_bob = bob_sifted[mask]
    else:
        est_qber = res_with_eve['qber']
        final_alice = alice_sifted
        final_bob = bob_sifted

    # Privacy check + key derivation (we will simply derive key and compare lengths)
    usable_key_len_bits = final_alice.size
    key_bytes_available = usable_key_len_bits // 8
    if key_bytes_available >= key_bytes:
        quantum_key = derive_key_from_bits(final_alice, key_bytes=key_bytes)
    else:
        # pad/truncate: if not enough bits, fallback to hashing whatever is there + random
        quantum_key = derive_key_from_bits(final_alice, key_bytes=key_bytes)

    random_key = get_random_bytes(key_bytes)

    # Encrypt original image bytes
    orig_bytes = pil_image_to_bytes(img, fmt='PNG')
    encrypted_random = aes_gcm_encrypt(orig_bytes, random_key)
    encrypted_quantum = aes_gcm_encrypt(orig_bytes, quantum_key)

    # Show images and stats
    left, mid, right = st.columns([1,1,1])
    with left:
        st.subheader('Bob receives (no Eve)')
        st.image(img_bob_no_eve, use_column_width=True)
    with mid:
        st.subheader('Bob receives (with Eve)')
        st.image(img_bob_with_eve, use_column_width=True)
    with right:
        st.subheader("Eve's visual (corrupted)")
        eve_visual = make_eve_visual(img, seed=42)
        st.image(eve_visual, use_column_width=True)

    st.markdown('---')
    st.subheader('Key and QBER Statistics (using simulation with Eve)')
    st.write(f'Sifted key length: {sift_len} bits')
    st.write(f'Estimated QBER (revealed sample): {est_qber:.4f}')
    st.write(f'Final usable key length (after revealing sample): {final_alice.size} bits → {final_alice.size//8} bytes')
    st.write(f'Requested AES key length: {key_bytes} bytes')

    if final_alice.size//8 < key_bytes:
        st.warning('Not enough secret bits to securely derive the requested AES key length — using hashed/padded value instead (insecure).')

    # Show download buttons
    st.markdown('---')
    st.subheader('Encrypted Outputs')
    col_a, col_b = st.columns(2)
    with col_a:
        st.caption('Image AES-GCM encrypted with RANDOM key')
        st.download_button('Download encrypted (random)', data=encrypted_random, file_name='encrypted_random.bin')
        st.download_button('Download random key (hex)', data=random_key.hex(), file_name='random_key.hex')
    with col_b:
        st.caption('Image AES-GCM encrypted with QUANTUM-derived key')
        st.download_button('Download encrypted (quantum)', data=encrypted_quantum, file_name='encrypted_quantum.bin')
        st.download_button('Download quantum key (hex)', data=quantum_key.hex(), file_name='quantum_key.hex')

    st.markdown('---')
    st.subheader('Extra: Debug / Lower-level Data')
    st.write('QBER (full sift):', res_with_eve['qber'])
    st.write('Number of bits Alice sent:', bits.size)
    st.write('Number of sifted bits (Alice==Bob bases):', sift_len)
    st.write('Number of bits revealed for sample:', sample_n)

    st.success('Simulation complete — download the encrypted blobs or keys from above.')

else:
    st.info('Upload an image (or use the sample) and click *Run Simulation* in the sidebar.')

# Footer
st.markdown('---')
st.caption('This demo is a simulation — it uses a simplified intercept-resend Eve model and does not implement full error-correction or privacy-amplification protocols. Use for educational/demonstration purposes only.')

