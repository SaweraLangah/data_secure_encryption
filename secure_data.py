import streamlit as st
import sqlite3
import hashlib
import os
from cryptography.fernet import Fernet
import base64

# Generate Fernet key from password
def password_to_fernet_key(password):
    sha256 = hashlib.sha256(password.encode()).digest()
    key = base64.urlsafe_b64encode(sha256)  # Make it Fernet compatible
    return key

# Encrypt message
def encrypt_message(key, message):
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())

# Decrypt message
def decrypt_message(key, encrypted_message):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()

# Initialize the database
def create_table():
    conn = sqlite3.connect('encrypted_data.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS secure_data(id INTEGER PRIMARY KEY, data BLOB)')
    conn.commit()
    conn.close()

# Save encrypted data
def save_encrypted_data(data):
    conn = sqlite3.connect('encrypted_data.db')
    c = conn.cursor()
    c.execute('INSERT INTO secure_data(data) VALUES (?)', (data,))
    conn.commit()
    conn.close()

# Retrieve all encrypted data
def get_all_encrypted_data():
    conn = sqlite3.connect('encrypted_data.db')
    c = conn.cursor()
    c.execute('SELECT id, data FROM secure_data')
    rows = c.fetchall()
    conn.close()
    return rows

# Streamlit UI
def main():
    st.markdown(
        """
        <style>
            .stApp {
                background: linear-gradient(135deg, #ffc0cb, #ffe4e1);
                color: #4a148c;
            }
            .stTextInput > div > div > input {
                background-color: #ffe4e1;
                border: 1px solid #f06292;
            }
            .stTextArea > div > textarea {
                background-color: #ffe4e1;
                border: 1px solid #f06292;
            }
            .stButton>button {
                background-color: #f06292;
                color: white;
                border-radius: 10px;
                padding: 8px 16px;
            }
            .stButton>button:hover {
                background-color: #ec407a;
            }
        </style>
        """,
        unsafe_allow_html=True
    )

    st.markdown("<h1 style='color: #880e4f;'>💖 Secure Data Encryption App</h1>", unsafe_allow_html=True)
    st.markdown("<p style='color: #4a148c;'>Encrypt and store your secret text safely! Powered by Python 🐍 + Streamlit 🚀</p>", unsafe_allow_html=True)

    create_table()

    password = st.text_input("🔑 Enter your secret password:", type="password")

    if password:
        key = password_to_fernet_key(password)  # Now password creates the same key every time!

        menu = st.sidebar.radio("📋 **Choose Action:**", ["Encrypt & Save", "Show Encrypted Data", "Decrypt Text"])

        if menu == "Encrypt & Save":
            st.markdown("### 💌 Enter Message to Encrypt")
            message = st.text_area("Type your secret message here:")

            if st.button("🔒 Encrypt & Save"):
                encrypted_message = encrypt_message(key, message)
                save_encrypted_data(encrypted_message)
                st.success("✅ Your data is now encrypted and saved to the database!")
                st.text_area("🧾 Encrypted Result:", encrypted_message.decode())

        elif menu == "Show Encrypted Data":
            st.markdown("### 📦 Stored Encrypted Data")
            data_list = get_all_encrypted_data()
            if data_list:
                for row in data_list:
                    st.markdown(f"<p style='color:#4a148c;'>🆔 ID: {row[0]} | 🔐 Data: {row[1].decode()}</p>", unsafe_allow_html=True)
            else:
                st.warning("⚠️ No encrypted data found in the database!")

        elif menu == "Decrypt Text":
            st.markdown("### 🔓 Decrypt Your Encrypted Text")
            encrypted_input = st.text_area("Paste the encrypted text here:")

            if st.button("🧪 Decrypt"):
                try:
                    decrypted_text = decrypt_message(key, encrypted_input.encode())
                    st.success("🎉 Successfully Decrypted!")
                    st.text_area("📜 Decrypted Message:", decrypted_text)
                except Exception as e:
                    st.error(f"❌ Decryption failed: {e}")

if __name__ == "__main__":
    main()



