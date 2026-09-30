"""
Relay Server for Client-to-Client Communication.
Operates on the Application Header framing:
- 2-byte header length
- JSON header (byteorder, senderID, receiverID, content-type, content-encoding, encryption key, content-length)
- Content payload

Routes messages and files between clients based on senderID and receiverID (phone numbers).
Persists offline messages if the recipient is not currently connected.
"""

import sys
import socket
import selectors
import traceback
import json
from typing import Dict, Optional

# Import local protocol and database
import protocol
from database import ChatDatabase


class ClientSession:
    def __init__(self, selector: selectors.BaseSelector, sock: socket.socket, addr):
        self.selector = selector
        self.sock = sock
        self.addr = addr
        self.phone_number: Optional[str] = None
        self.parser = protocol.StreamParser()
        self.outb = bytearray()

    def queue_packet(self, packet: bytes):
        """Queues a raw protocol packet to be sent to this client."""
        self.outb.extend(packet)
        self.set_events("rw")

    def set_events(self, mode: str):
        if mode == "r":
            events = selectors.EVENT_READ
        elif mode == "w":
            events = selectors.EVENT_WRITE
        elif mode == "rw":
            events = selectors.EVENT_READ | selectors.EVENT_WRITE
        else:
            raise ValueError(f"Invalid mode: {mode}")
        try:
            self.selector.modify(self.sock, events, data=self)
        except (KeyError, OSError):
            pass


class RelayServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 65432, db_path: Optional[str] = None):
        self.host = host
        self.port = port
        self.db = ChatDatabase(db_path) if db_path else ChatDatabase()
        self.selector = selectors.DefaultSelector()
        self.active_users: Dict[str, ClientSession] = {}  # phone_number -> ClientSession
        self.sessions: Dict[socket.socket, ClientSession] = {}
        self._running = False

    def start(self):
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind((self.host, self.port))
        lsock.listen()
        lsock.setblocking(False)
        self.selector.register(lsock, selectors.EVENT_READ, data=None)
        self.lsock = lsock
        self._running = True
        print(f"[RELAY SERVER] Listening on {self.host}:{self.port}")

    def accept_wrapper(self, sock: socket.socket):
        conn, addr = sock.accept()
        print(f"[RELAY SERVER] Accepted connection from {addr}")
        conn.setblocking(False)
        session = ClientSession(self.selector, conn, addr)
        self.sessions[conn] = session
        self.selector.register(conn, selectors.EVENT_READ, data=session)

    def close_session(self, session: ClientSession):
        conn = session.sock
        addr = session.addr
        phone = session.phone_number

        print(f"[RELAY SERVER] Closing session for {phone or addr}")
        if phone and phone in self.active_users:
            del self.active_users[phone]
            self.db.set_user_offline(phone)

        if conn in self.sessions:
            del self.sessions[conn]

        try:
            self.selector.unregister(conn)
        except Exception:
            pass

        try:
            conn.close()
        except OSError:
            pass

    def handle_packet(self, session: ClientSession, header: dict, payload: bytes):
        content_type = header.get("content-type")
        sender_id = header.get("senderID")
        receiver_id = header.get("receiverID")
        content_encoding = header.get("content-encoding", "utf-8")
        encryption_key = header.get("encryption key", "")

        print(f"[RELAY SERVER] Received '{content_type}' from {sender_id} to {receiver_id} (len={len(payload)}B)")

        # Case 1: Connect / Login
        if content_type == "connect":
            session.phone_number = sender_id
            self.active_users[sender_id] = session
            # Extract optional username or public key from payload if provided
            username = ""
            pub_key = ""
            if payload:
                try:
                    info = json.loads(payload.decode("utf-8"))
                    username = info.get("username", "")
                    pub_key = info.get("public_key", "")
                except Exception:
                    pass

            self.db.register_or_login_user(sender_id, username=username, public_key=pub_key)
            print(f"[RELAY SERVER] User {sender_id} registered/logged in.")

            # Send welcome ACK packet
            ack_data = json.dumps({"status": "connected", "phone_number": sender_id, "message": "Login successful"}).encode("utf-8")
            ack_packet = protocol.create_packet(
                sender_id="server",
                receiver_id=sender_id,
                content_type="status",
                payload=ack_data,
            )
            session.queue_packet(ack_packet)

            # Check and deliver queued offline messages
            offline_packets = self.db.fetch_and_clear_offline_messages(sender_id)
            if offline_packets:
                print(f"[RELAY SERVER] Delivering {len(offline_packets)} pending offline messages to {sender_id}")
                for queued_packet in offline_packets:
                    session.queue_packet(queued_packet)

        # Case 2: Client-to-Client Relay (send message or file)
        elif content_type in ("send message", "file"):
            # Check receiver existence in DB
            if not self.db.is_valid_user(receiver_id):
                print(f"[RELAY SERVER] Recipient {receiver_id} not recognized in database.")
                err_data = json.dumps({"status": "error", "message": f"Receiver ID {receiver_id} not registered"}).encode("utf-8")
                err_packet = protocol.create_packet(
                    sender_id="server",
                    receiver_id=sender_id,
                    content_type="status",
                    payload=err_data,
                )
                session.queue_packet(err_packet)
                return

            # Retrieve sender and receiver usernames from DB
            sender_user = self.db.get_user(sender_id)
            sender_name = sender_user.get("username", sender_id) if sender_user else sender_id

            receiver_user = self.db.get_user(receiver_id)
            receiver_name = receiver_user.get("username", receiver_id) if receiver_user else receiver_id

            # 1. Log encrypted message to database (phone number, name, encrypted key, ciphertext)
            ciphertext_hex = payload.hex()
            self.db.log_encrypted_message(
                sender_phone=sender_id,
                sender_name=sender_name,
                receiver_phone=receiver_id,
                receiver_name=receiver_name,
                content_type=content_type,
                encryption_key=encryption_key,
                ciphertext_hex=ciphertext_hex,
                payload_size_bytes=len(payload),
            )

            # 2. Display intercepted encrypted payload and keys on server console
            print("\n" + "=" * 70)
            print("[RELAY SERVER - ENCRYPTED PAYLOAD INTERCEPTED]")
            print(f"  * Sender:        {sender_name} ({sender_id})")
            print(f"  * Receiver:      {receiver_name} ({receiver_id})")
            print(f"  * Type:          {content_type}")
            print(f"  * Payload Size:  {len(payload)} bytes")
            if encryption_key:
                key_display = encryption_key if len(encryption_key) <= 80 else (encryption_key[:40] + "..." + encryption_key[-40:])
                print(f"  * Encrypted Key: {key_display} ({len(encryption_key)//2} bytes)")
            else:
                print("  * Encrypted Key: [None - Plain message]")
            cipher_display = ciphertext_hex if len(ciphertext_hex) <= 120 else (ciphertext_hex[:60] + "..." + ciphertext_hex[-60:])
            print(f"  * Ciphertext:    {cipher_display}")
            print(f"  * Database Log:  Stored in 'encrypted_messages' table (Record ID logged)")
            print("=" * 70 + "\n")

            # Prepare the forward packet preserving all header specs
            forward_packet = protocol.create_packet(
                sender_id=sender_id,
                receiver_id=receiver_id,
                content_type=content_type,
                payload=payload,
                content_encoding=content_encoding,
                encryption_key=encryption_key,
            )

            # Check if receiver is online
            if receiver_id in self.active_users:
                target_session = self.active_users[receiver_id]
                target_session.queue_packet(forward_packet)
                print(f"[RELAY SERVER] Relayed directly to {receiver_id} online")

                # Send delivery confirmation to sender
                confirm_data = json.dumps({"status": "delivered", "receiverID": receiver_id}).encode("utf-8")
                confirm_packet = protocol.create_packet(
                    sender_id="server",
                    receiver_id=sender_id,
                    content_type="status",
                    payload=confirm_data,
                )
                session.queue_packet(confirm_packet)
            else:
                # Recipient is offline -> Store in database
                print(f"[RELAY SERVER] Recipient {receiver_id} is offline. Saving to offline queue in database.")
                self.db.store_offline_message(sender_id, receiver_id, forward_packet)

                # Send queued confirmation to sender
                queued_data = json.dumps({"status": "queued", "receiverID": receiver_id, "message": "User offline. Queued for delivery."}).encode("utf-8")
                queued_packet = protocol.create_packet(
                    sender_id="server",
                    receiver_id=sender_id,
                    content_type="status",
                    payload=queued_data,
                )
                session.queue_packet(queued_packet)

        # Case 3: Public Key Request (for E2EE key exchange)
        elif content_type == "get_public_key":
            target_user = self.db.get_user(receiver_id)
            pub_key = target_user.get("public_key", "") if target_user else ""
            resp_data = json.dumps({"receiverID": receiver_id, "public_key": pub_key}).encode("utf-8")
            resp_packet = protocol.create_packet(
                sender_id="server",
                receiver_id=sender_id,
                content_type="public_key_response",
                payload=resp_data,
            )
            session.queue_packet(resp_packet)

        else:
            print(f"[RELAY SERVER] Unhandled content-type: {content_type}")

    def service_connection(self, key: selectors.SelectorKey, mask: int):
        session: ClientSession = key.data
        sock = session.sock

        # Handle incoming reads
        if mask & selectors.EVENT_READ:
            try:
                recv_data = sock.recv(4096)
            except (ConnectionResetError, BlockingIOError, OSError):
                recv_data = b""

            if recv_data:
                for header, payload in session.parser.feed(recv_data):
                    self.handle_packet(session, header, payload)
            else:
                self.close_session(session)
                return

        # Handle outgoing writes
        if mask & selectors.EVENT_WRITE:
            if session.outb:
                try:
                    sent = sock.send(session.outb)
                    session.outb = session.outb[sent:]
                except (BlockingIOError, OSError):
                    pass

            if not session.outb:
                session.set_events("r")

    def run(self):
        self.start()
        try:
            while self._running:
                events = self.selector.select(timeout=1.0)
                for key, mask in events:
                    if key.data is None:
                        self.accept_wrapper(key.fileobj)
                    else:
                        self.service_connection(key, mask)
        except KeyboardInterrupt:
            print("\n[RELAY SERVER] Stopping server...")
        finally:
            self.stop()

    def stop(self):
        self._running = False
        for session in list(self.sessions.values()):
            self.close_session(session)
        try:
            self.selector.close()
        except Exception:
            pass


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 65432
    server = RelayServer(host, port)
    server.run()
