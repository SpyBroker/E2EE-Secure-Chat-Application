from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


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



import socket
import ssl

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_verify_locations(cafile="server.crt") # Trust the server's cert

# 1. Load the client certificate (which holds the public key) and private key
context.load_cert_chain(certfile="client.crt", keyfile="client.key")

raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
secure_socket = context.wrap_socket(raw_socket, server_hostname='localhost')

secure_socket.connect(('localhost', 8443))
data = secure_socket.recv(1024)
print("Received from server:", data.decode())

secure_socket.close()



# 3. Decrypt the message using the Private Key
print("--- Decrypting ---")
private_key = RSA.import_key(private_pem)
decryptor = PKCS1_OAEP.new(private_key) # Uses the private key data
decrypted_message = decryptor.decrypt(ciphertext)

print(f"Decrypted Message: {decrypted_message.decode('utf-8')}\n")



