import os
import base64
import hashlib
import hmac

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import padding as sym_padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20

# ------------------ Integrity Functions ------------------
def integrity_encrypt(data: bytes, pwd: str) -> bytes:
    tag = hmac.new(pwd.encode(), data, hashlib.sha512).digest()
    return tag + data

def integrity_decrypt(data: bytes, pwd: str) -> bytes:
    tag, plain = data[:64], data[64:]
    if hmac.new(pwd.encode(), plain, hashlib.sha512).digest() != tag:
        raise ValueError("Integrity check failed")
    return plain

# ------------------ AES CBC Functions ------------------
def aes_cbc_encrypt(data: bytes, pwd: str) -> bytes:
    key = hashlib.sha256((pwd + "AES_CBC").encode()).digest()
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return iv + ct

def aes_cbc_decrypt(data: bytes, pwd: str) -> bytes:
    key = hashlib.sha256((pwd + "AES_CBC").encode()).digest()
    iv, ct = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

# ------------------ AES GCM Functions ------------------
def aes_gcm_encrypt(data: bytes, pwd: str) -> bytes:
    key = hashlib.sha256((pwd + "AES_GCM").encode()).digest()
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    return iv + encryptor.tag + ct

def aes_gcm_decrypt(data: bytes, pwd: str) -> bytes:
    key = hashlib.sha256((pwd + "AES_GCM").encode()).digest()
    iv, tag, ct = data[:12], data[12:28], data[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def aes_gcm_encrypt_raw(data: bytes, key: bytes) -> bytes:
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    return iv + encryptor.tag + ct

def aes_gcm_decrypt_raw(data: bytes, key: bytes) -> bytes:
    iv, tag, ct = data[:12], data[12:28], data[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

# ------------------ Fernet Functions ------------------
def fernet_encrypt(data: bytes, pwd: str) -> bytes:
    # Derive a Fernet key from the password.
    fkey = base64.urlsafe_b64encode(hashlib.sha256((pwd + "Fernet").encode()).digest())
    return Fernet(fkey).encrypt(data)

def fernet_decrypt(data: bytes, pwd: str) -> bytes:
    fkey = base64.urlsafe_b64encode(hashlib.sha256((pwd + "Fernet").encode()).digest())
    return Fernet(fkey).decrypt(data)

# ------------------ ChaCha20 Functions ------------------
def chacha20_encrypt(data: bytes, pwd: str) -> bytes:
    key = hashlib.sha256((pwd + "ChaCha20").encode()).digest()[:32]
    nonce = os.urandom(16)  # Requires 16 bytes (128-bit) nonce per cryptography library
    cipher = Cipher(ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    ct = encryptor.update(data)
    return nonce + ct

def chacha20_decrypt(data: bytes, pwd: str) -> bytes:
    key = hashlib.sha256((pwd + "ChaCha20").encode()).digest()[:32]
    nonce, ct = data[:16], data[16:]
    cipher = Cipher(ChaCha20(key, nonce), mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(ct)

# ------------------ RSA Functions ------------------
def rsa_encrypt(data: bytes, pwd: str, rsa_pub) -> bytes:
    sym_key = os.urandom(32)
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(sym_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    enc_sym = rsa_pub.encrypt(
        sym_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return b"RSA:" + base64.urlsafe_b64encode(enc_sym) + b"||" + \
           base64.urlsafe_b64encode(iv) + b"||" + \
           base64.urlsafe_b64encode(ct)

def rsa_decrypt(data: bytes, pwd: str, rsa_priv) -> bytes:
    parts = data.split(b"||")
    if not parts[0].startswith(b"RSA:"):
        raise ValueError("RSA header error")
    enc_sym = base64.urlsafe_b64decode(parts[0][4:])
    iv = base64.urlsafe_b64decode(parts[1])
    ct = base64.urlsafe_b64decode(parts[2])
    sym_key = rsa_priv.decrypt(
        enc_sym,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    cipher = Cipher(algorithms.AES(sym_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

# ------------------ Envelope Functions ------------------
def make_envelope(rsa_priv, ecc_priv, pwd: str) -> bytes:
    rsa_bytes = rsa_priv.private_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    ecc_bytes = ecc_priv.private_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    env = b"RSAKEY:" + rsa_bytes + b"||ECCKEY:" + ecc_bytes
    fkey = base64.urlsafe_b64encode(hashlib.sha256((pwd + "ENVELOPE").encode()).digest())
    return Fernet(fkey).encrypt(env)

def parse_envelope(env_encrypted: bytes, pwd: str):
    fkey = base64.urlsafe_b64encode(hashlib.sha256((pwd + "ENVELOPE").encode()).digest())
    env = Fernet(fkey).decrypt(env_encrypted)
    parts = env.split(b"||ECCKEY:")
    rsa_part = parts[0][len(b"RSAKEY:"):]
    ecc_part = parts[1]
    rsa_priv = serialization.load_pem_private_key(rsa_part, password=None)
    ecc_priv = serialization.load_pem_private_key(ecc_part, password=None)
    return rsa_priv, ecc_priv

# ------------------ Final Encoding/Decoding ------------------
def final_encrypt(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()

def final_decrypt(token: str) -> bytes:
    return base64.urlsafe_b64decode(token.encode())

# ------------------ Ultimate Encrypt/Decrypt ------------------
def ultimate_encrypt(plaintext: str, pwd: str) -> str:
    data = plaintext.encode("utf-8")
    data = integrity_encrypt(data, pwd)
    data = aes_cbc_encrypt(data, pwd)
    data = aes_gcm_encrypt(data, pwd)
    data = fernet_encrypt(data, pwd)
    data = chacha20_encrypt(data, pwd)
    
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    rsa_pub = rsa_priv.public_key()
    ecc_priv = ec.generate_private_key(ec.SECP384R1())
    
    ecc_key = hashlib.sha256(
        ecc_priv.private_bytes(
            encoding=serialization.Encoding.DER, 
            format=serialization.PrivateFormat.PKCS8, 
            encryption_algorithm=serialization.NoEncryption()
        )
    ).digest()
    
    data = aes_gcm_encrypt_raw(data, ecc_key)
    data = rsa_encrypt(data, pwd, rsa_pub)
    envelope = make_envelope(rsa_priv, ecc_priv, pwd)
    combined = envelope + b"||" + data
    final_data = final_encrypt(combined)
    return final_data

def ultimate_decrypt(token: str, pwd: str) -> str:
    combined = final_decrypt(token)
    parts = combined.split(b"||", 1)
    if len(parts) != 2:
        raise ValueError("Invalid combined message format")
    envelope, data = parts[0], parts[1]
    
    rsa_priv, ecc_priv = parse_envelope(envelope, pwd)
    data = rsa_decrypt(data, pwd, rsa_priv)
    
    ecc_key = hashlib.sha256(
        ecc_priv.private_bytes(
            encoding=serialization.Encoding.DER, 
            format=serialization.PrivateFormat.PKCS8, 
            encryption_algorithm=serialization.NoEncryption()
        )
    ).digest()
    
    data = aes_gcm_decrypt_raw(data, ecc_key)
    data = chacha20_decrypt(data, pwd)
    data = fernet_decrypt(data, pwd)
    data = aes_gcm_decrypt(data, pwd)
    data = aes_cbc_decrypt(data, pwd)
    data = integrity_decrypt(data, pwd)
    return data.decode("utf-8")

# ------------------ Flask App Setup ------------------
app = Flask(__name__)

@app.route('/')
def home():
    return "Ultimate Encryption API is running!"

# Note: The API now expects a JSON with keys "data" and "key"
@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    try:
        # Use same variable names as before
        plaintext = request.json.get('data', '')
        secret_key = request.json.get('key', '')
        if not plaintext or not secret_key:
            return jsonify({'error': "Missing 'data' or 'key' field"}), 400
        
        encrypted = ultimate_encrypt(plaintext, secret_key)
        return jsonify({'encrypted': encrypted})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    try:
        token = request.json.get('data', '')
        secret_key = request.json.get('key', '')
        if not token or not secret_key:
            return jsonify({'error': "Missing 'data' or 'key' field"}), 400
        
        decrypted = ultimate_decrypt(token, secret_key)
        return jsonify({'decrypted': decrypted})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)