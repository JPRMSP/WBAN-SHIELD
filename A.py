import streamlit as st
import time
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from tinyec import registry
import secrets

st.set_page_config(page_title="WBAN-SHIELD", layout="wide")

st.title("🛡️ WBAN-SHIELD")
st.subheader("Real-Time Security Simulator for Wireless Body Area Networks")

# -----------------------------
# WBAN SENSOR SIMULATION
# -----------------------------
def generate_sensor_data():
    return {
        "ECG": round(random.uniform(60, 100), 2),
        "Temperature": round(random.uniform(36.0, 38.0), 2),
        "SpO2": random.randint(95, 100)
    }

# -----------------------------
# LIGHTWEIGHT TEA ENCRYPTION
# -----------------------------
def tea_encrypt(data, key=b"0123456789ABCDEF"):
    v0, v1 = int.from_bytes(data[:4], 'big'), int.from_bytes(data[4:], 'big')
    k = [int.from_bytes(key[i:i+4], 'big') for i in range(0, 16, 4)]
    delta = 0x9e3779b9
    sum = 0
    for _ in range(32):
        sum += delta
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1])
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3])
    return v0.to_bytes(4, 'big') + v1.to_bytes(4, 'big')

# -----------------------------
# AES-CTR ENCRYPTION
# -----------------------------
def aes_encrypt(data):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(data)
    return ciphertext, key

# -----------------------------
# ECDH KEY EXCHANGE
# -----------------------------
def ecdh_key_exchange():
    curve = registry.get_curve('brainpoolP256r1')
    priv_key = secrets.randbelow(curve.field.n)
    pub_key = priv_key * curve.g
    shared_key = hashlib.sha256(str(pub_key.x).encode()).digest()
    return shared_key

# -----------------------------
# ATTACK SIMULATION
# -----------------------------
def replay_attack(packet):
    return packet

def tamper_attack(packet):
    return packet[:-1] + b'\x00'

# -----------------------------
# STREAMLIT UI
# -----------------------------
col1, col2, col3 = st.columns(3)

with col1:
    st.header("📡 WBAN Sensor Node")
    if st.button("Generate Sensor Data"):
        sensor_data = generate_sensor_data()
        st.json(sensor_data)

with col2:
    st.header("🔐 Security Engine")
    encryption = st.selectbox(
        "Choose Encryption Algorithm",
        ["AES-CTR (UNIT II)", "TEA (UNIT III)"]
    )

with col3:
    st.header("⚠️ Attack Simulation")
    attack = st.selectbox(
        "Choose Attack",
        ["None", "Replay Attack", "Data Tampering"]
    )

st.divider()

if st.button("🚀 Transmit Secure Packet"):
    data = str(generate_sensor_data()).encode()

    start_time = time.time()

    if encryption == "AES-CTR (UNIT II)":
        encrypted, key = aes_encrypt(data)
        algo_used = "AES-CTR"
    else:
        padded = data.ljust(8, b'\0')[:8]
        encrypted = tea_encrypt(padded)
        algo_used = "TEA"

    if attack == "Replay Attack":
        encrypted = replay_attack(encrypted)
    elif attack == "Data Tampering":
        encrypted = tamper_attack(encrypted)

    shared_key = ecdh_key_exchange()

    latency = round((time.time() - start_time) * 1000, 2)
    energy = round(len(encrypted) * 0.05, 2)

    st.success("Packet Successfully Transmitted!")

    st.markdown("### 📦 Transmission Details")
    st.write("**Algorithm Used:**", algo_used)
    st.write("**Encrypted Packet:**", encrypted)
    st.write("**ECDH Shared Key (Hash):**", shared_key.hex()[:32])
    st.write("**Latency (ms):**", latency)
    st.write("**Estimated Energy Cost (µJ):**", energy)

st.divider()
