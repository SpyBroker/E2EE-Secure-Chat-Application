"""
Client implementation for Client-to-Client Relay with End-to-End Hybrid Encryption.
Features:
- Generates/manages RSA-3072 key pair.
- Registers public key with server on connect (stored in database).
- Queries server for peer's RSA public key.
- Hybrid encryption:
    1. Generates ephemeral AES-256 key.
    2. Encrypts message payload with AES-GCM (prepends 12-byte IV).
    3. Encrypts AES key with recipient's RSA public key (PKCS1_OAEP).
    4. Places encrypted AES key in the JSON header ("encryption key").
- Hybrid decryption:
    1. Decrypts AES key using local RSA private key.
    2. Decrypts payload using recovered AES key and IV.
- Background listening thread for incoming real-time messages and files.
- Interactive CLI chat interface.
"""

import sys
import os
import socket
import threading
import json
import time
from typing import Callable, Optional, Dict, Any

# Local imports
import protocol
import crypto


class RelayClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 65432, rsa_key_size: int = 3072):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.phone_number: Optional[str] = None
        self.parser = protocol.StreamParser()
        self._running = False
        self._listen_thread: Optional[threading.Thread] = None

        # RSA Keys for E2EE
        self.rsa_key_size = rsa_key_size
        self.private_key_pem: str = ""
        self.public_key_pem: str = ""
        self._init_keys()

        # Cache of peer public keys: phone_number -> public_pem
        self.peer_public_keys: Dict[str, str] = {}
        self._key_events: Dict[str, threading.Event] = {}

        # Callbacks
        self.on_message_callback: Optional[Callable[[str, str, str, bool], None]] = None
        self.on_file_callback: Optional[Callable[[str, str, bytes, bool], None]] = None
        self.on_status_callback: Optional[Callable[[Dict[str, Any]], None]] = None

    def _init_keys(self):
        """Generates or loads client's RSA key pair."""
        self.private_key_pem, self.public_key_pem = crypto.generate_rsa_keypair(self.rsa_key_size)

    def connect(self, phone_number: str, username: str = "") -> bool:
        """Connects to relay server and authenticates with phone number and public key."""
        self.phone_number = str(phone_number).strip()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((self.host, self.port))
        except Exception as e:
            print(f"[CLIENT] Connection failed: {e}")
            return False

        self._running = True
        self._listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._listen_thread.start()

        # Send login 'connect' packet containing public key for DB storage
        payload_data = json.dumps({
            "username": username or self.phone_number,
            "public_key": self.public_key_pem,
        }).encode("utf-8")

        login_packet = protocol.create_packet(
            sender_id=self.phone_number,
            receiver_id="server",
            content_type="connect",
            payload=payload_data,
            content_encoding="utf-8",
        )
        self.sock.sendall(login_packet)
        return True

    def _listen_loop(self):
        """Continuously listens for incoming TCP stream packets from the server."""
        while self._running:
            try:
                data = self.sock.recv(4096)
                if not data:
                    print("\n[CLIENT] Disconnected from server.")
                    break

                for header, payload in self.parser.feed(data):
                    self._dispatch_packet(header, payload)
            except Exception as e:
                if self._running:
                    print(f"\n[CLIENT] Read error: {e}")
                break

        self._running = False

    def _dispatch_packet(self, header: dict, payload: bytes):
        content_type = header.get("content-type")
        sender_id = header.get("senderID")
        enc_key = header.get("encryption key", "")

        # 1. Received Text Message
        if content_type == "send message":
            is_encrypted = bool(enc_key)
            if is_encrypted:
                try:
                    # Decrypt AES key with client's RSA private key, then decrypt payload with AES-GCM
                    decrypted_bytes = crypto.decrypt_hybrid(
                        recipient_private_pem=self.private_key_pem,
                        encrypted_aes_key_hex=enc_key,
                        payload_with_iv=payload,
                    )
                    text = decrypted_bytes.decode(header.get("content-encoding", "utf-8"))
                except Exception as e:
                    text = f"[E2EE Decryption Failed: {e}]"
            else:
                try:
                    text = payload.decode(header.get("content-encoding", "utf-8"))
                except Exception:
                    text = repr(payload)

            if self.on_message_callback:
                self.on_message_callback(sender_id, text, enc_key, is_encrypted)
            else:
                tag = "[E2EE]" if is_encrypted else "[Plain]"
                print(f"\n{tag} [MSG from {sender_id}]: {text}\n> ", end="", flush=True)

        # 2. Received File
        elif content_type == "file":
            is_encrypted = bool(enc_key)
            if is_encrypted:
                try:
                    file_bytes = crypto.decrypt_hybrid(
                        recipient_private_pem=self.private_key_pem,
                        encrypted_aes_key_hex=enc_key,
                        payload_with_iv=payload,
                    )
                except Exception as e:
                    file_bytes = b""
                    print(f"\n[E2EE File Decryption Failed: {e}]")
            else:
                file_bytes = payload

            if self.on_file_callback:
                self.on_file_callback(sender_id, enc_key, file_bytes, is_encrypted)
            else:
                tag = "[E2EE]" if is_encrypted else "[Plain]"
                print(f"\n{tag} [FILE from {sender_id}]: {len(file_bytes)} bytes\n> ", end="", flush=True)

        # 3. Public Key Response from Server
        elif content_type == "public_key_response":
            try:
                info = json.loads(payload.decode("utf-8"))
                target_user = info.get("receiverID")
                pub_key = info.get("public_key", "")
                if target_user and pub_key:
                    self.peer_public_keys[target_user] = pub_key
                    if target_user in self._key_events:
                        self._key_events[target_user].set()
            except Exception as e:
                print(f"[CLIENT] Error processing public key response: {e}")

        # 4. Status / ACK
        elif content_type == "status":
            try:
                status_info = json.loads(payload.decode("utf-8"))
            except Exception:
                status_info = {"raw": payload.decode("utf-8", errors="ignore")}

            if self.on_status_callback:
                self.on_status_callback(status_info)
            else:
                print(f"\n[STATUS]: {status_info}\n> ", end="", flush=True)

    def get_peer_public_key(self, receiver_id: str, timeout: float = 3.0) -> Optional[str]:
        """Fetches the recipient's RSA public key from local cache or queries the relay server."""
        receiver_id = str(receiver_id).strip()
        if receiver_id in self.peer_public_keys:
            return self.peer_public_keys[receiver_id]

        if not self.sock or not self._running:
            return None

        # Request public key from server
        evt = threading.Event()
        self._key_events[receiver_id] = evt

        req_packet = protocol.create_packet(
            sender_id=self.phone_number,
            receiver_id=receiver_id,
            content_type="get_public_key",
            payload=b"",
        )
        self.sock.sendall(req_packet)

        # Wait for server's public_key_response
        if evt.wait(timeout=timeout):
            return self.peer_public_keys.get(receiver_id)
        return None

    def send_secure_message(self, receiver_id: str, message_text: str):
        """
        Sends an End-to-End Encrypted (E2EE) message to receiverID.
        Uses recipient's RSA public key to encrypt an ephemeral AES-256 key,
        and AES-GCM to encrypt the message text.
        """
        receiver_id = str(receiver_id).strip()
        pub_key = self.get_peer_public_key(receiver_id)
        if not pub_key:
            raise RuntimeError(f"Could not retrieve RSA public key for recipient {receiver_id}")

        plaintext_bytes = message_text.encode("utf-8")
        encrypted_aes_key_hex, ciphertext_with_iv = crypto.encrypt_hybrid(
            recipient_public_pem=pub_key,
            plaintext=plaintext_bytes,
        )

        packet = protocol.create_packet(
            sender_id=self.phone_number,
            receiver_id=receiver_id,
            content_type="send message",
            payload=ciphertext_with_iv,
            content_encoding="utf-8",
            encryption_key=encrypted_aes_key_hex,
        )
        self.sock.sendall(packet)

    def send_secure_file(self, receiver_id: str, file_path: str):
        """
        Sends a file encrypted with End-to-End Hybrid Encryption.
        """
        receiver_id = str(receiver_id).strip()
        pub_key = self.get_peer_public_key(receiver_id)
        if not pub_key:
            raise RuntimeError(f"Could not retrieve RSA public key for recipient {receiver_id}")

        with open(file_path, "rb") as f:
            file_bytes = f.read()

        encrypted_aes_key_hex, ciphertext_with_iv = crypto.encrypt_hybrid(
            recipient_public_pem=pub_key,
            plaintext=file_bytes,
        )

        packet = protocol.create_packet(
            sender_id=self.phone_number,
            receiver_id=receiver_id,
            content_type="file",
            payload=ciphertext_with_iv,
            content_encoding="binary",
            encryption_key=encrypted_aes_key_hex,
        )
        self.sock.sendall(packet)
        print(f"[CLIENT] Sent encrypted file '{os.path.basename(file_path)}' ({len(ciphertext_with_iv)} B) to {receiver_id}")

    def send_plain_message(self, receiver_id: str, message_text: str):
        """Sends an unencrypted text message (fallback / status)."""
        payload = message_text.encode("utf-8")
        packet = protocol.create_packet(
            sender_id=self.phone_number,
            receiver_id=str(receiver_id).strip(),
            content_type="send message",
            payload=payload,
            content_encoding="utf-8",
            encryption_key="",
        )
        self.sock.sendall(packet)

    def close(self):
        self._running = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass


def interactive_cli():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 65432
    phone_number = sys.argv[3] if len(sys.argv) > 3 else input("Enter your phone number (e.g., +1111111111): ").strip()

    print("[CLIENT] Generating RSA key pair (3072-bit)...")
    client = RelayClient(host, port)
    if not client.connect(phone_number):
        print("Failed to connect.")
        return

    print("=" * 65)
    print(f"🔒 E2EE Chat Client active for {phone_number} on {host}:{port}")
    print("Commands:")
    print("  /msg <receiver_phone> <message>    Send E2EE message")
    print("  /file <receiver_phone> <filepath>   Send E2EE file")
    print("  /exit                              Quit")
    print("=" * 65)

    try:
        while client._running:
            cmd = input("> ").strip()
            if not cmd:
                continue
            if cmd == "/exit":
                break
            elif cmd.startswith("/msg "):
                parts = cmd[5:].split(" ", 1)
                if len(parts) == 2:
                    recv_id, msg = parts[0], parts[1]
                    try:
                        client.send_secure_message(recv_id, msg)
                    except Exception as e:
                        print(f"[Error]: {e}")
                else:
                    print("Usage: /msg <receiver_phone> <message>")
            elif cmd.startswith("/file "):
                parts = cmd[6:].split(" ", 1)
                if len(parts) == 2:
                    recv_id, fpath = parts[0], parts[1]
                    if os.path.exists(fpath):
                        try:
                            client.send_secure_file(recv_id, fpath)
                        except Exception as e:
                            print(f"[Error]: {e}")
                    else:
                        print(f"File not found: {fpath}")
                else:
                    print("Usage: /file <receiver_phone> <filepath>")
            else:
                print("Unknown command. Use /msg, /file, or /exit")
    except KeyboardInterrupt:
        pass
    finally:
        client.close()
        print("Goodbye!")


if __name__ == "__main__":
    interactive_cli()
