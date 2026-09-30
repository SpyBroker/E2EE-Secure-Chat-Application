"""
Local Device Cryptographic Engine for Smartphone Application.
Handles:
- Local RSA key generation (3072-bit or configurable).
- Ephemeral AES-256-GCM key generation and payload encryption.
- RSA PKCS1_OAEP encryption of AES key with recipient's public key.
- Local decryption using device's cached private key.
"""

import os
from typing import Tuple
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

IV_LENGTH = 12  # 96-bit standard nonce for AES-GCM


def generate_rsa_keypair(key_size: int = 3072) -> Tuple[str, str]:
    """
    Generates a new RSA key pair locally on the smartphone.
    Private key NEVER leaves device storage.
    Returns: (private_pem, public_pem)
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
    Client-side Hybrid Encryption:
    1. Generates ephemeral 256-bit AES key.
    2. Encrypts payload with AES-GCM (12-byte IV + ciphertext).
    3. Encrypts AES key using recipient's RSA public key (PKCS1_OAEP).
    
    Returns:
        (encrypted_aes_key_hex, payload_with_iv)
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")

    aes_key = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(IV_LENGTH)

    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(iv, plaintext, associated_data)
    payload_with_iv = iv + ciphertext

    rsa_pub = RSA.import_key(recipient_public_pem)
    encryptor = PKCS1_OAEP.new(rsa_pub)
    encrypted_aes_key = encryptor.encrypt(aes_key)

    return encrypted_aes_key.hex(), payload_with_iv


def decrypt_hybrid(
    recipient_private_pem: str,
    encrypted_aes_key_hex: str,
    payload_with_iv: bytes,
    associated_data: bytes = b"",
) -> bytes:
    """
    Client-side Hybrid Decryption:
    Uses the device's cached private key to recover the AES key, then decrypts the payload.
    """
    if len(payload_with_iv) < IV_LENGTH:
        raise ValueError("Payload too short to contain IV")

    encrypted_aes_key = bytes.fromhex(encrypted_aes_key_hex)
    rsa_priv = RSA.import_key(recipient_private_pem)
    decryptor = PKCS1_OAEP.new(rsa_priv)
    aes_key = decryptor.decrypt(encrypted_aes_key)

    iv = payload_with_iv[:IV_LENGTH]
    ciphertext = payload_with_iv[IV_LENGTH:]

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(iv, ciphertext, associated_data)
    return plaintext
