from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

# 1. Generate an RSA Key Pair (3072-bit for strong security)
print("--- Generating Key Pair ---")
key_pair = RSA.generate(3072)

# Extract Public Key
public_key = key_pair.publickey() # memory location of the key
public_pem = public_key.export_key().decode('utf-8') # reading public key from memory location
print(f"Public Key (PEM):\n{public_pem}\n")

# Extract Private Key
private_pem = key_pair.export_key().decode('utf-8') # reading private key from memory location for decryption
print(f"Private Key (PEM): [Hidden for brevity]\n")

# 2. Encrypt a message using the Public Key
message = b"Secret data to protect!"
print(f"Original Message: {message.decode('utf-8')}")

# Instantiate the cipher using OAEP(Optimal Asymmetric Encryption Padding) padding
# OAEP transforms your plain text into an unpredictable, random-looking block of data right before the RSA math takes over. It uses a structure called a Feistel Network
encryptor = PKCS1_OAEP.new(public_key)
ciphertext = encryptor.encrypt(message)


# Convert ciphertext to Hex format just to print it cleanly
hex_ciphertext = binascii.hexlify(ciphertext).decode('utf-8')
print(f"Encrypted Ciphertext (Hex):\n{hex_ciphertext}\n")


# 3. Decrypt the message using the Private Key
print("--- Decrypting ---")
private_key = RSA.import_key(private_pem)
decryptor = PKCS1_OAEP.new(private_key) # Uses the private key data
decrypted_message = decryptor.decrypt(ciphertext)

print(f"Decrypted Message: {decrypted_message.decode('utf-8')}\n")
