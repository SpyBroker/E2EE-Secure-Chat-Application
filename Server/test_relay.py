"""
End-to-End Automated Test Suite for Hybrid E2EE Chat Relay.
Tests:
1. Protocol packing & streaming parser verification (conformance to the Application Header diagram).
2. End-to-End Hybrid Encryption (RSA-OAEP + AES-GCM):
   - Alice (+1111111111) requests Bob's (+2222222222) RSA public key.
   - Alice encrypts fresh AES key with Bob's public key.
   - Alice encrypts message with AES-GCM.
   - Server relays ciphertext (server has no access to plaintext).
   - Bob decrypts AES key with his private key and decrypts the message.
3. Bidirectional E2EE reply from Bob to Alice.
4. E2EE encrypted file transfer.
5. E2EE offline queued message delivery & decryption.
"""

import sys
import os
import time
import threading
import struct
import json

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

import protocol
from database import ChatDatabase
from relay_server import RelayServer
from relay_client import RelayClient


def test_protocol_serialization():
    print("\n--- TEST 1: Protocol Serialization & Conformance to Diagram ---")
    payload = b"Hello Secure E2EE Chat World!"
    packet = protocol.create_packet(
        sender_id="+1111111111",
        receiver_id="+2222222222",
        content_type="send message",
        payload=payload,
        content_encoding="utf-8",
        encryption_key="encrypted_aes_key_hex_abc123",
    )

    hdr_size = struct.unpack(">H", packet[:2])[0]
    print(f"2-byte size header: {hdr_size} bytes")

    json_bytes = packet[2: 2 + hdr_size]
    header = json.loads(json_bytes.decode("utf-8"))
    print(f"Parsed JSON Header:\n{json.dumps(header, indent=2)}")

    assert "byteorder" in header, "Missing byteorder"
    assert header["senderID"] == "+1111111111", "senderID mismatch"
    assert header["receiverID"] == "+2222222222", "receiverID mismatch"
    assert header["content-type"] == "send message", "content-type mismatch"
    assert header["content-encoding"] == "utf-8", "content-encoding mismatch"
    assert header["encryption key"] == "encrypted_aes_key_hex_abc123", "encryption key mismatch"
    assert header["content-length"] == len(payload), "content-length mismatch"

    parser = protocol.StreamParser()
    parsed_messages = []
    for chunk in (packet[:5], packet[5:20], packet[20:]):
        for h, p in parser.feed(chunk):
            parsed_messages.append((h, p))

    assert len(parsed_messages) == 1
    assert parsed_messages[0][1] == payload
    print("[PASS] Test 1: Protocol packet creation and chunked stream parsing passed.")


def test_e2ee_hybrid_relay():
    print("\n--- TEST 2: End-to-End Hybrid Encryption (RSA + AES-GCM) Relay ---")
    test_db_path = os.path.join(CURRENT_DIR, "test_chat.db")
    if os.path.exists(test_db_path):
        try:
            os.remove(test_db_path)
        except OSError:
            pass

    test_port = 65498
    server = RelayServer(host="127.0.0.1", port=test_port, db_path=test_db_path)

    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    # Fast 2048-bit RSA keys for test execution
    alice = RelayClient(port=test_port, rsa_key_size=2048)
    bob = RelayClient(port=test_port, rsa_key_size=2048)

    bob_messages = []
    bob_files = []
    alice_messages = []

    def on_bob_msg(sender_id, text, enc_key, is_e2ee):
        bob_messages.append((sender_id, text, enc_key, is_e2ee))

    def on_bob_file(sender_id, enc_key, data, is_e2ee):
        bob_files.append((sender_id, enc_key, data, is_e2ee))

    def on_alice_msg(sender_id, text, enc_key, is_e2ee):
        alice_messages.append((sender_id, text, enc_key, is_e2ee))

    bob.on_message_callback = on_bob_msg
    bob.on_file_callback = on_bob_file
    alice.on_message_callback = on_alice_msg

    # 1. Connect both clients and register their public keys in the DB
    assert alice.connect("+1111111111", username="Alice")
    assert bob.connect("+2222222222", username="Bob")
    time.sleep(0.4)

    # 2. Alice sends E2EE message to Bob
    secret_text_1 = "Top secret message: Alice and Bob have E2EE active!"
    print("\n-> Alice sending E2EE encrypted message to Bob...")
    alice.send_secure_message(receiver_id="+2222222222", message_text=secret_text_1)
    time.sleep(0.5)

    assert len(bob_messages) == 1, f"Bob did not receive message: {bob_messages}"
    b_sender, b_text, b_key, b_is_e2ee = bob_messages[0]
    assert b_sender == "+1111111111"
    assert b_text == secret_text_1
    assert b_is_e2ee is True
    assert len(b_key) > 50  # RSA encrypted AES key in hex
    print(f"[PASS] Bob decrypted E2EE message successfully: '{b_text}'")
    print(f"       Encrypted AES Key length in header: {len(b_key)//2} bytes")

    # 3. Bob sends E2EE reply to Alice
    secret_text_2 = "Acknowledged Alice. AES-GCM authenticated payload received!"
    print("\n-> Bob replying to Alice with E2EE encryption...")
    bob.send_secure_message(receiver_id="+1111111111", message_text=secret_text_2)
    time.sleep(0.5)

    assert len(alice_messages) == 1
    a_sender, a_text, a_key, a_is_e2ee = alice_messages[0]
    assert a_sender == "+2222222222"
    assert a_text == secret_text_2
    assert a_is_e2ee is True
    print(f"[PASS] Alice decrypted E2EE reply successfully: '{a_text}'")

    # 4. E2EE encrypted file transfer
    print("\n-> Alice sending E2EE encrypted file to Bob...")
    dummy_file = os.path.join(CURRENT_DIR, "secure_doc.bin")
    dummy_bytes = b"CONFIDENTIAL_PAYLOAD_" + os.urandom(128)
    with open(dummy_file, "wb") as f:
        f.write(dummy_bytes)

    alice.send_secure_file(receiver_id="+2222222222", file_path=dummy_file)
    time.sleep(0.5)

    assert len(bob_files) == 1
    f_sender, f_key, f_data, f_is_e2ee = bob_files[0]
    assert f_sender == "+1111111111"
    assert f_is_e2ee is True
    assert f_data == dummy_bytes
    print(f"[PASS] Bob received and decrypted E2EE file ({len(f_data)} bytes) with exact match!")

    # 5. Offline E2EE message queueing & delivery
    print("\n-> Testing Offline E2EE Message Queueing...")
    bob.close()
    time.sleep(0.4)

    offline_secret = "Confidential memo sent while Bob was offline."
    print("-> Alice sending E2EE message to offline Bob...")
    alice.send_secure_message(receiver_id="+2222222222", message_text=offline_secret)
    time.sleep(0.4)

    # Bob reconnects using his existing RSA key pair
    bob_reconnected = RelayClient(port=test_port, rsa_key_size=2048)
    bob_reconnected.private_key_pem = bob.private_key_pem
    bob_reconnected.public_key_pem = bob.public_key_pem

    reconnected_msgs = []
    bob_reconnected.on_message_callback = lambda s, t, k, e: reconnected_msgs.append((s, t, k, e))
    bob_reconnected.connect("+2222222222", username="Bob")
    time.sleep(0.5)

    assert len(reconnected_msgs) == 1, f"Expected 1 offline message, got: {reconnected_msgs}"
    assert reconnected_msgs[0][1] == offline_secret
    assert reconnected_msgs[0][3] is True
    print(f"[PASS] Bob reconnected and successfully decrypted offline E2EE message: '{reconnected_msgs[0][1]}'")

    # Cleanup
    alice.close()
    bob_reconnected.close()
    server.stop()
    if os.path.exists(dummy_file):
        os.remove(dummy_file)
    print("\n[ALL E2EE HYBRID ENCRYPTION TESTS PASSED!]")


if __name__ == "__main__":
    test_protocol_serialization()
    test_e2ee_hybrid_relay()
