# ---------------------------
# Tab 1: Simulation
# ---------------------------
with tabs[0]:
    st.header("Simulation — Alice sends file, BB84 runs, Bob encrypts (if secure)")
    tabs = st.tabs(["Simulation", "Graphs & Analysis"])

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

    st.subheader("Alice (Sender)")
    if preview_img is not None:
        st.image(preview_img, caption=f"Alice's file: {file_name}", use_container_width=True)
        st.write(f"File size: {len(file_bytes)} bytes")
    else:
        st.warning("No file is provided. Upload a file or add `images/windows.png` to the repo.")

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

            # Metrics (left aligned)
            st.subheader("Results")
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
            QBER_THRESHOLD = 0.11
            if np.isnan(qber):
                st.error("QBER undefined (no sifted bits). Aborting.")
                aborted = True
            elif qber > QBER_THRESHOLD:
                st.error(f"QBER = {qber*100:.3f}% > 11%: ABORTING transfer for security.")
                aborted = True
            else:
                st.success(f"QBER = {qber*100:.3f}% ≤ 11% → Proceeding to derive key & encrypt.")
                aborted = False

            # Derive keys
            alice_key = derive_key_from_bits(res["alice_sift"])
            bob_key = derive_key_from_bits(res["bob_sift"])

            st.subheader("Derived Key (demo only)")
            st.code(f"Alice key (SHA-256 of sifted bits): {alice_key.hex()}", language="text")

            # Eve’s corrupted view (static pixelation for images)
            eve_img_preview = None
            if preview_img is not None:
                eve_img_preview = preview_img.copy()
                # Apply random pixelation
                small = eve_img_preview.resize((eve_img_preview.width // 12, eve_img_preview.height // 12))
                eve_img_preview = small.resize(preview_img.size, Image.NEAREST)

            # Encrypt if not aborted
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
                    st.error("Verification FAILED — decryption mismatch.")

            # Display results (all left aligned)
            st.markdown("---")
            st.subheader("Transmission Results")

            st.write("**Original (Alice)**")
            if preview_img:
                st.image(preview_img, use_column_width=True)
            if not aborted:
                st.download_button("Download Original", data=file_bytes, file_name=f"alice_{file_name}")

            st.write("**Eve's View (Corrupted)**")
            if eve_img_preview is not None:
                st.image(eve_img_preview, use_column_width=True, caption="Eve's pixelated corruption")
            else:
                st.write("Corrupted data (non-image file).")

            st.write("**Bob (Receiver)**")
            if not aborted and decrypted_blob is not None:
                try:
                    bob_img = Image.open(io.BytesIO(decrypted_blob)).convert("RGB")
                    st.image(bob_img, use_column_width=True, caption="Bob's recovered image")
                except Exception:
                    st.write(f"Recovered file bytes: {len(decrypted_blob)}")
                st.download_button("Download Encrypted Blob", data=encrypted_blob, file_name="encrypted_blob.bin")
                st.download_button("Download Decrypted (Bob)", data=decrypted_blob, file_name=f"bob_{file_name}")
            else:
                st.info("Bob did not receive a decryptable file.")

            # Save last run artifacts
            st.session_state["last_run"] = {
                "params": {"num_bits": num_bits, "p_noise": p_noise, "p_eve": p_eve, "seed": seed},
                "res": res,
                "alice_key": alice_key,
                "bob_key": bob_key,
                "encrypted_blob": encrypted_blob,
                "decrypted_blob": decrypted_blob,
                "file_name": file_name,
            }

