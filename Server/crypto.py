"""
Cryptographic module for End-to-End Hybrid Encryption:
- RSA-3072 + PKCS1_OAEP for asymmetric key exchange and AES key encryption
- AES-256-GCM for symmetric authenticated payload encryption
"""

import os
from typing import Tuple
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

IV_LENGTH = 12  # 96-bit IV recommended for AES-GCM


def generate_rsa_keypair(key_size: int = 3072) -> Tuple[str, str]:
    """
    Generates a new RSA key pair.
    Returns: (private_pem, public_pem) strings.
    """
    key_pair = RSA.generate(key_size)
    private_pem = key_pair.export_key().decode("utf-8")
    public_pem = key_pair.publickey().export_key().decode("utf-8")
    return private_pem, public_pem


def encrypt_hybrid(
    recipient_public_pem: str,
    plaintext: bytes,
    associated_data: bytes = b"",
) -> Tuple[str, bytes]:
    """
    Performs Hybrid Encryption:
    1. Generates ephemeral 256-bit AES key.
    2. Encrypts payload with AES-GCM (prepends 12-byte IV to ciphertext).
    3. Encrypts the AES key using recipient's RSA public key (PKCS1_OAEP).
    
    Returns:
        (encrypted_aes_key_hex, iv_plus_ciphertext_bytes)
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")

    # 1. Generate 256-bit AES key & 12-byte IV
    aes_key = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(IV_LENGTH)

    # 2. Encrypt payload with AES-GCM
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(iv, plaintext, associated_data)
    payload_with_iv = iv + ciphertext

    # 3. Encrypt ephemeral AES key with recipient's RSA public key
    rsa_pub = RSA.import_key(recipient_public_pem)
    encryptor = PKCS1_OAEP.new(rsa_pub)
    encrypted_aes_key = encryptor.encrypt(aes_key)

    # Return the encrypted AES key as a hex string (for JSON header) and combined payload
    return encrypted_aes_key.hex(), payload_with_iv


def decrypt_hybrid(
    recipient_private_pem: str,
    encrypted_aes_key_hex: str,
    payload_with_iv: bytes,
    associated_data: bytes = b"",
) -> bytes:
    """
    Performs Hybrid Decryption:
    1. Decrypts the ephemeral AES key using recipient's RSA private key.
    2. Decrypts the payload with AES-GCM using extracted IV and recovered AES key.
    
    Returns:
        decrypted_plaintext (bytes)
    """
    if len(payload_with_iv) < IV_LENGTH:
        raise ValueError("Payload too short to contain IV")

    # 1. Decrypt ephemeral AES key with RSA private key
    encrypted_aes_key = bytes.fromhex(encrypted_aes_key_hex)
    rsa_priv = RSA.import_key(recipient_private_pem)
    decryptor = PKCS1_OAEP.new(rsa_priv)
    aes_key = decryptor.decrypt(encrypted_aes_key)

    # 2. Extract IV and ciphertext
    iv = payload_with_iv[:IV_LENGTH]
    ciphertext = payload_with_iv[IV_LENGTH:]

    # 3. Decrypt ciphertext with AES-GCM
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(iv, ciphertext, associated_data)
    return plaintext
