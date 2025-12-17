import streamlit as st
import time
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from tinyec import registry
import secrets

# -----------------------------
# STREAMLIT CONFIG
# -----------------------------
st.set_page_config(
    page_title="WBAN-SHIELD",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ WBAN-SHIELD")
st.subheader("Real-Time Security Simulator for Wireless Body Area Networks")
st.caption("Subject: FI 9049 – Security Issues in WBANs | Anna University (R2021)")

# -----------------------------
# WBAN SENSOR SIMULATION (UNIT I)
# -----------------------------
def generate_sensor_data():
    return {
        "ECG (bpm)": round(random.uniform(60, 100), 2),
        "Body Temperature (°C)": round(random.uniform(36.0, 38.0), 2),
        "SpO2 (%)": random.randint(95, 100)
    }

# -----------------------------
# TEA LIGHTWEIGHT ENCRYPTION (UNIT III)
# -----------------------------
def tea_encrypt(data, key=b"0123456789ABCDEF"):
    v0 = int.from_bytes(data[:4], 'big')
    v1 = int.from_bytes(data[4:], 'big')

    k = [int.from_bytes(key[i:i+4], 'big') for i in range(0, 16, 4)]

    delta = 0x9E3779B9
    sum = 0

    for _ in range(32):
        sum = (sum + delta) & 0xFFFFFFFF
        v0 = (v0 + (((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF

    return v0.to_bytes(4, 'big') + v1.to_bytes(4, 'big')

# -----------------------------
# AES-CTR ENCRYPTION (UNIT II)
# -----------------------------
def aes_ctr_encrypt(data):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(data)
    return ciphertext, key

# -----------------------------
# ECDH KEY EXCHANGE (UNIT II)
# -----------------------------
def ecdh_key_exchange():
    curve = registry.get_curve("brainpoolP256r1")
    private_key = secrets.randbelow(curve.field.n)
    public_key = private_key * curve.g
    shared_secret = hashlib.sha256(str(public_key.x).encode()).digest()
    return shared_secret

# -----------------------------
# ATTACK SIMULATIONS (UNIT I)
# -----------------------------
def replay_attack(packet):
    return packet

def tampering_attack(packet):
    return packet[:-1] + b'\x00'

# -----------------------------
# UI LAYOUT
# -----------------------------
col1, col2, col3 = st.columns(3)

with col1:
    st.header("📡 WBAN Sensor Node")
    if st.button("Generate Sensor Data"):
        sensor_data = generate_sensor_data()
        st.json(sensor_data)

with col2:
    st.header("🔐 Cryptography Engine")
    encryption_method = st.selectbox(
        "Select Encryption Algorithm",
        [
            "AES-CTR (UNIT II – Secure)",
            "TEA (UNIT III – Lightweight)"
        ]
    )

with col3:
    st.header("⚠️ Security Threat Simulation")
    attack_type = st.selectbox(
        "Select Attack",
        [
            "None",
            "Replay Attack",
            "Data Tampering Attack"
        ]
    )

st.divider()

# -----------------------------
# TRANSMISSION PROCESS
# -----------------------------
if st.button("🚀 Transmit Secure WBAN Packet"):
    sensor_payload = str(generate_sensor_data()).encode()

    start_time = time.time()

    if encryption_method.startswith("AES"):
        encrypted_data, secret_key = aes_ctr_encrypt(sensor_payload)
        algorithm_used = "AES-CTR"
    else:
        padded = sensor_payload.ljust(8, b'\0')[:8]
        encrypted_data = tea_encrypt(padded)
        algorithm_used = "TEA"

    if attack_type == "Replay Attack":
        encrypted_data = replay_attack(encrypted_data)
    elif attack_type == "Data Tampering Attack":
        encrypted_data = tampering_attack(encrypted_data)

    shared_key = ecdh_key_exchange()

    latency_ms = round((time.time() - start_time) * 1000, 2)
    energy_cost = round(len(encrypted_data) * 0.05, 2)

    st.success("✅ Secure Packet Transmission Completed")

    st.markdown("### 📦 Transmission Metrics")
    st.write("**Encryption Algorithm:**", algorithm_used)
    st.write("**Encrypted Packet (Bytes):**", encrypted_data)
    st.write("**ECDH Shared Key (SHA-256, truncated):**", shared_key.hex()[:32])
    st.write("**Latency:**", latency_ms, "ms")
    st.write("**Estimated Energy Consumption:**", energy_cost, "µJ")

st.divider()
