"""
Mobile Chat Client SDK for Smartphone Application.
Designed to be bound to any Mobile UI framework (Flutter, React Native, Kivy, PyQt, etc.).
Features:
- Enforces 10-digit phone number validation.
- Secure local key caching (RSA Private key stays strictly on device).
- Zero-knowledge end-to-end hybrid encryption (AES-256-GCM + RSA-OAEP).
- Local decrypted chat history caching.
- Event-driven callback architecture.
"""

import sys
import os
import socket
import threading
import json
import time
from typing import Callable, Optional, Dict, Any, List

import protocol
import crypto
from storage import validate_phone_number, DeviceKeyStore, DeviceChatDatabase


class MobileChatClient:
    def __init__(self, host: Any = "127.0.0.1", port: int = 65432, cache_dir: Optional[str] = None):
        # host can be a single IP string or a list/tuple of candidate Wi-Fi IPs
        if isinstance(host, (list, tuple)):
            self.candidate_hosts = list(host)
        else:
            self.candidate_hosts = [host]

        self.port = port
        self.connected_host: Optional[str] = None
        self.cache_dir = cache_dir or os.path.join(os.path.dirname(__file__), "device_cache")
        self.keystore = DeviceKeyStore(self.cache_dir)
        
        self.phone_number: Optional[str] = None
        self.private_key_pem: str = ""
        self.public_key_pem: str = ""
        self.chat_db: Optional[DeviceChatDatabase] = None

        self.sock: Optional[socket.socket] = None
        self.parser = protocol.StreamParser()
        self._running = False
        self._listen_thread: Optional[threading.Thread] = None

        # Cached peer public keys: phone_number -> public_pem
        self.peer_public_keys: Dict[str, str] = {}
        self._key_events: Dict[str, threading.Event] = {}

        # Callbacks for Mobile UI Binding
        self.on_message_received: Optional[Callable[[str, str, bool], None]] = None
        self.on_file_received: Optional[Callable[[str, bytes, bool], None]] = None
        self.on_connection_status: Optional[Callable[[Dict[str, Any]], None]] = None

    def login_and_connect(self, phone_number: str, username: str = "") -> bool:
        """
        1. Validates 10-digit phone number.
        2. Retrieves existing RSA keys from local device cache OR generates new ones locally.
        3. Attempts connection through candidate Wi-Fi host IPs until one succeeds.
        4. Transmits only the public key to the server.
        """
        clean_phone = validate_phone_number(phone_number)
        self.phone_number = clean_phone

        # 1. Local Device Key Cache check
        print(f"[DEVICE] Loading/Generating cryptographic keys locally for {clean_phone}...")
        self.private_key_pem, self.public_key_pem = self.keystore.get_or_create_keys(clean_phone)
        self.chat_db = DeviceChatDatabase(clean_phone, self.cache_dir)

        # 2. Try candidate Wi-Fi IPs
        connected = False
        for target_ip in self.candidate_hosts:
            print(f"[DEVICE] Attempting connection to {target_ip}:{self.port}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)  # Quick 2-second timeout per network
            try:
                sock.connect((target_ip, self.port))
                sock.settimeout(None)  # Back to non-blocking stream
                self.sock = sock
                self.connected_host = target_ip
                connected = True
                print(f"[DEVICE] Successfully connected to server on {target_ip}:{self.port}!")
                break
            except Exception as e:
                sock.close()
                print(f"[DEVICE] Failed to connect to {target_ip}: {e}")

        if not connected:
            print("[DEVICE] Could not connect to any candidate server IPs.")
            return False

        self._running = True
        self._listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._listen_thread.start()

        # 3. Transmit login packet to server (Notice: only public_key is transmitted!)
        payload = json.dumps({
            "username": username or clean_phone,
            "public_key": self.public_key_pem,
        }).encode("utf-8")

        login_packet = protocol.create_packet(
            sender_id=self.phone_number,
            receiver_id="server",
            content_type="connect",
            payload=payload,
            content_encoding="utf-8",
        )
        self.sock.sendall(login_packet)
        return True

    def _listen_loop(self):
        while self._running:
            try:
                data = self.sock.recv(4096)
                if not data:
                    print("\n[DEVICE] Server connection closed.")
                    break
                for header, payload in self.parser.feed(data):
                    self._dispatch_packet(header, payload)
            except Exception as e:
                if self._running:
                    print(f"\n[DEVICE] Socket receive error: {e}")
                break
        self._running = False

    def _dispatch_packet(self, header: dict, payload: bytes):
        content_type = header.get("content-type")
        sender_id = header.get("senderID")
        enc_key = header.get("encryption key", "")

        # A. Received Text Message
        if content_type == "send message":
            is_e2ee = bool(enc_key)
            if is_e2ee:
                try:
                    decrypted_bytes = crypto.decrypt_hybrid(
                        recipient_private_pem=self.private_key_pem,
                        encrypted_aes_key_hex=enc_key,
                        payload_with_iv=payload,
                    )
                    text = decrypted_bytes.decode(header.get("content-encoding", "utf-8"))
                except Exception as e:
                    text = f"[Decryption Failed: {e}]"
            else:
                try:
                    text = payload.decode(header.get("content-encoding", "utf-8"))
                except Exception:
                    text = repr(payload)

            # Save in local device database
            if self.chat_db:
                self.chat_db.save_message(peer_phone=sender_id, direction="incoming", body=text, is_e2ee=is_e2ee)

            # Trigger UI callback
            if self.on_message_received:
                self.on_message_received(sender_id, text, is_e2ee)
            else:
                tag = "[E2EE]" if is_e2ee else "[Plain]"
                print(f"\n{tag} [From {sender_id}]: {text}\n> ", end="", flush=True)

        # B. Received File
        elif content_type == "file":
            is_e2ee = bool(enc_key)
            if is_e2ee:
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

            if self.on_file_received:
                self.on_file_received(sender_id, file_bytes, is_e2ee)
            else:
                print(f"\n[File from {sender_id}]: {len(file_bytes)} bytes (E2EE={is_e2ee})\n> ", end="", flush=True)

        # C. Public Key Response from Server
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
                print(f"[DEVICE] Error parsing public key response: {e}")

        # D. Status Notification
        elif content_type == "status":
            try:
                status_info = json.loads(payload.decode("utf-8"))
            except Exception:
                status_info = {"raw": payload.decode("utf-8", errors="ignore")}

            if self.on_connection_status:
                self.on_connection_status(status_info)
            else:
                print(f"\n[STATUS]: {status_info}\n> ", end="", flush=True)

    def get_peer_public_key(self, receiver_phone: str, timeout: float = 3.0) -> Optional[str]:
        clean_receiver = validate_phone_number(receiver_phone)
        if clean_receiver in self.peer_public_keys:
            return self.peer_public_keys[clean_receiver]

        if not self.sock or not self._running:
            return None

        evt = threading.Event()
        self._key_events[clean_receiver] = evt

        req_packet = protocol.create_packet(
            sender_id=self.phone_number,
            receiver_id=clean_receiver,
            content_type="get_public_key",
            payload=b"",
        )
        self.sock.sendall(req_packet)

        if evt.wait(timeout=timeout):
            return self.peer_public_keys.get(clean_receiver)
        return None

    def send_secure_message(self, receiver_phone: str, message_text: str):
        """Validates 10-digit phone number and sends E2EE message."""
        clean_receiver = validate_phone_number(receiver_phone)
        pub_key = self.get_peer_public_key(clean_receiver)
        if not pub_key:
            raise RuntimeError(f"Could not retrieve public key for recipient {clean_receiver}")

        encrypted_aes_key_hex, ciphertext_with_iv = crypto.encrypt_hybrid(
            recipient_public_pem=pub_key,
            plaintext=message_text.encode("utf-8"),
        )

        packet = protocol.create_packet(
            sender_id=self.phone_number,
            receiver_id=clean_receiver,
            content_type="send message",
            payload=ciphertext_with_iv,
            content_encoding="utf-8",
            encryption_key=encrypted_aes_key_hex,
        )
        self.sock.sendall(packet)

        # Cache outgoing message in local device database
        if self.chat_db:
            self.chat_db.save_message(clean_receiver, direction="outgoing", body=message_text, is_e2ee=True)

    def send_secure_file(self, receiver_phone: str, file_path: str):
        """Sends encrypted file to 10-digit phone number."""
        clean_receiver = validate_phone_number(receiver_phone)
        pub_key = self.get_peer_public_key(clean_receiver)
        if not pub_key:
            raise RuntimeError(f"Could not retrieve public key for recipient {clean_receiver}")

        with open(file_path, "rb") as f:
            file_bytes = f.read()

        encrypted_aes_key_hex, ciphertext_with_iv = crypto.encrypt_hybrid(
            recipient_public_pem=pub_key,
            plaintext=file_bytes,
        )

        packet = protocol.create_packet(
            sender_id=self.phone_number,
            receiver_id=clean_receiver,
            content_type="file",
            payload=ciphertext_with_iv,
            content_encoding="binary",
            encryption_key=encrypted_aes_key_hex,
        )
        self.sock.sendall(packet)

    def get_local_history(self, peer_phone: str) -> List[Dict[str, Any]]:
        """Retrieves locally cached conversation history."""
        if self.chat_db:
            return self.chat_db.get_messages(peer_phone)
        return []

    def close(self):
        self._running = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass


def mobile_cli():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 65432
    phone_input = sys.argv[3] if len(sys.argv) > 3 else input("Enter your 10-digit phone number: ").strip()

    client = MobileChatClient(host, port)
    try:
        if not client.login_and_connect(phone_input):
            return
    except ValueError as e:
        print(f"[Error]: {e}")
        return

    print("=" * 65)
    print(f"Mobile E2EE Client: {client.phone_number} on {host}:{port}")
    print("Commands:")
    print("  /msg <10-digit-phone> <text>      Send E2EE message")
    print("  /file <10-digit-phone> <filepath> Send E2EE file")
    print("  /history <10-digit-phone>         View local device chat history")
    print("  /exit                             Quit")
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
                    try:
                        client.send_secure_message(parts[0], parts[1])
                    except Exception as e:
                        print(f"[Error]: {e}")
                else:
                    print("Usage: /msg <10-digit-phone> <text>")
            elif cmd.startswith("/file "):
                parts = cmd[6:].split(" ", 1)
                if len(parts) == 2:
                    try:
                        client.send_secure_file(parts[0], parts[1])
                    except Exception as e:
                        print(f"[Error]: {e}")
                else:
                    print("Usage: /file <10-digit-phone> <filepath>")
            elif cmd.startswith("/history "):
                target_peer = cmd[9:].strip()
                try:
                    history = client.get_local_history(target_peer)
                    print(f"\n--- Chat History with {target_peer} ({len(history)} messages) ---")
                    for m in history:
                        direction = "->" if m["direction"] == "outgoing" else "<-"
                        print(f"[{direction}] {m['body']}")
                    print("--- End History ---\n")
                except Exception as e:
                    print(f"[Error]: {e}")
            else:
                print("Unknown command.")
    except KeyboardInterrupt:
        pass
    finally:
        client.close()
        print("Goodbye!")


if __name__ == "__main__":
    mobile_cli()
