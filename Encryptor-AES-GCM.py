# Fix the "RSA can't encrypt bulk data" issue from earlier by doing hybrid encryption, which is the standard technique worth implementing for a networks lab: each message gets a fresh random AES key, the message is AES-GCM encrypted, and only that small AES key gets RSA-encrypted with the recipient's public key. That's genuinely instructive — it's exactly what TLS does internally, and it's the "real" version of the design you described (RSA encrypts data directly), just corrected.

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

print("--- Generating RSA Key Pair ---")
key_pair = RSA.generate(3072)
public_key = key_pair.publickey() # memory location of the key
public_pem = public_key.export_key().decode('utf-8') # reading public key from memory location
print(f"RSA Public Key (PEM):\n{public_pem}\n")
print("DONE\n")

# 1. Generate a secure 256-bit (32-byte) key
# In real applications, securely store and load this key.
print("--- Generating AESGCM Key Pair ---")
aes_key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(aes_key)
print(aesgcm)
print("DONE\n")

# 2. Generate a unique 96-bit (12-byte) nonce/IV (Initialization Vector)
# Never reuse the same IV with the same key!
iv = os.urandom(12)

# 3. Define plaintext and optional additional authenticated data (AAD)
plaintext = b"Secret message for AES-GCM demo"
associated_data = b"metadata-header"


# 4. Encrypt the data (returns ciphertext combined with the authentication tag)
ciphertext = aesgcm.encrypt(iv, plaintext, associated_data)
print(f"Ciphertext encrypted by AESGCM (Hex): {ciphertext.hex()}")
print()

print("----Encrypted_aes_key---")
encryptor = PKCS1_OAEP.new(public_key)
encrypted_aes_key = encryptor.encrypt(aes_key)
print(encrypted_aes_key)

print("\n--- Decrypting AESGCM key---\n")
private_pem = key_pair.export_key().decode('utf-8')
private_key = RSA.import_key(private_pem)

decryptor = PKCS1_OAEP.new(private_key) # Uses the private key data
decrypted_AESGCM_key = decryptor.decrypt(encrypted_aes_key)
print("AES key recovered!\n")

# Reconstruct AES-GCM cipher from the recovered key
decrypted_aesgcm = AESGCM(decrypted_AESGCM_key)

# 5. Decrypt the data back to plaintext
decrypted_plaintext = decrypted_aesgcm.decrypt(iv, ciphertext, associated_data)
print(f"Decrypted: {decrypted_plaintext.decode()}")
