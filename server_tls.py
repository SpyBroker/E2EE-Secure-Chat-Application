import socket
import ssl

# 1. Create a secure context for the server
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")
context.load_verify_locations(cafile="client.crt") # Trust the client's cert

# Enforce mutual authentication
context.verify_mode = ssl.CERT_REQUIRED

bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
bind_socket.bind(('localhost', 8443))
bind_socket.listen(5)

print("Server listening for secure client connections...")

while True:
    newsocket, fromaddr = bind_socket.accept()
    # Perform the secure handshake
    conn = context.wrap_socket(newsocket, server_side=True)
    
    try:
        # 2. Automatically retrieve the client's certificate and public key
        client_cert = conn.getpeercert()
        print(f"Connection established! Secured with client: {client_cert['subject']}")
        
        # You can now send encrypted messages securely over this stream
        conn.sendall(b"Hello secure client! Your identity is verified.")
    finally:
        conn.close()
