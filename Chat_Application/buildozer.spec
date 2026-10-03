"""
Drop-in replacement for crypto.py that uses ONLY pycryptodome (no `cryptography` package).
Wire format is identical to the original: payload = 12-byte IV + ciphertext + 16-byte GCM tag,
so desktop clients using the old crypto.py and this phone app can still talk to each other.
Reason: `cryptography` is hard to build for Android; pycryptodome has a ready recipe.
"""
import os
from typing import Tuple
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

IV_LENGTH = 12
TAG_LENGTH = 16


def generate_rsa_keypair(key_size: int = 3072) -> Tuple[str, str]:
    key_pair = RSA.generate(key_size)
    return (key_pair.export_key().decode("utf-8"),
            key_pair.publickey().export_key().decode("utf-8"))


def encrypt_hybrid(recipient_public_pem: str, plaintext: bytes,
                   associated_data: bytes = b"") -> Tuple[str, bytes]:
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    aes_key = os.urandom(32)
    iv = os.urandom(IV_LENGTH)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv, mac_len=TAG_LENGTH)
    if associated_data:
        cipher.update(associated_data)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    payload_with_iv = iv + ciphertext + tag
    encrypted_aes_key = PKCS1_OAEP.new(RSA.import_key(recipient_public_pem)).encrypt(aes_key)
    return encrypted_aes_key.hex(), payload_with_iv


def decrypt_hybrid(recipient_private_pem: str, encrypted_aes_key_hex: str,
                   payload_with_iv: bytes, associated_data: bytes = b"") -> bytes:
    if len(payload_with_iv) < IV_LENGTH + TAG_LENGTH:
        raise ValueError("Payload too short")
    aes_key = PKCS1_OAEP.new(RSA.import_key(recipient_private_pem)).decrypt(
        bytes.fromhex(encrypted_aes_key_hex))
    iv = payload_with_iv[:IV_LENGTH]
    tag = payload_with_iv[-TAG_LENGTH:]
    ciphertext = payload_with_iv[IV_LENGTH:-TAG_LENGTH]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv, mac_len=TAG_LENGTH)
    if associated_data:
        cipher.update(associated_data)
    return cipher.decrypt_and_verify(ciphertext, tag)