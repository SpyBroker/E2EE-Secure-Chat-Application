"""
Comprehensive Automated Test for Smartphone Chat Application:
1. 10-digit phone number validation & normalization.
2. Local device key caching and zero-knowledge verification (server NEVER receives private key).
3. E2EE message exchange between mobile clients.
4. Local device chat history caching.
"""

import sys
import os
import time
import shutil
import threading
import json

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from storage import validate_phone_number, DeviceKeyStore, DeviceChatDatabase
from database import ServerDatabase
from server import RelayServer
from mobile_client import MobileChatClient


def test_10_digit_phone_validation():
    print("\n--- TEST 1: 10-Digit Phone Number Validation ---")
    # Valid formats
    assert validate_phone_number("9876543210") == "9876543210"
    assert validate_phone_number("+919876543210") == "9876543210"
    assert validate_phone_number("+19876543210") == "9876543210"
    assert validate_phone_number("987-654-3210") == "9876543210"
    assert validate_phone_number("09876543210") == "9876543210"
    print("[PASS] Valid 10-digit phone numbers normalized correctly.")

    # Invalid formats
    invalid_cases = ["12345", "9876543210123", "abcdefghij", "", "987654321a"]
    for inv in invalid_cases:
        try:
            validate_phone_number(inv)
            assert False, f"Expected ValueError for '{inv}'"
        except ValueError:
            pass
    print("[PASS] Invalid phone numbers correctly rejected.")


def test_local_device_key_cache_and_zero_knowledge():
    print("\n--- TEST 2: Device Key Cache & Server Zero-Knowledge Verification ---")
    test_device_cache = os.path.join(CURRENT_DIR, "test_device_cache")
    if os.path.exists(test_device_cache):
        shutil.rmtree(test_device_cache)

    keystore = DeviceKeyStore(test_device_cache)
    phone = "9876543210"

    # 1. Generate keys locally on device
    priv_1, pub_1 = keystore.get_or_create_keys(phone, key_size=1024)
    assert keystore.has_keys(phone)
    assert "BEGIN RSA PRIVATE KEY" in priv_1
    assert "BEGIN PUBLIC KEY" in pub_1

    # 2. Re-loading loads from local cache without re-generation
    priv_2, pub_2 = keystore.get_or_create_keys(phone, key_size=1024)
    assert priv_1 == priv_2
    assert pub_1 == pub_2
    print("[PASS] Keys successfully cached on device and reloaded.")

    # 3. Server Database check (Zero-knowledge verification)
    test_server_db = os.path.join(CURRENT_DIR, "test_server.db")
    if os.path.exists(test_server_db):
        os.remove(test_server_db)

    server_db = ServerDatabase(test_server_db)
    server_db.register_or_login_user(phone, username="Alice", public_key=pub_1)

    user_record = server_db.get_user(phone)
    assert user_record is not None
    assert user_record["public_key"] == pub_1
    assert "private_key" not in user_record
    assert priv_1 not in json.dumps(user_record)
    print("[PASS] Zero-knowledge verified: Server DB stores only public key, private key is strictly on device.")

    # Cleanup
    if os.path.exists(test_device_cache):
        try:
            shutil.rmtree(test_device_cache)
        except OSError:
            pass
    if os.path.exists(test_server_db):
        try:
            os.remove(test_server_db)
        except OSError:
            pass


def test_mobile_e2ee_relay():
    print("\n--- TEST 3: Mobile E2EE Live Chat & Local History ---")
    test_cache_alice = os.path.join(CURRENT_DIR, "cache_alice")
    test_cache_bob = os.path.join(CURRENT_DIR, "cache_bob")
    test_server_db = os.path.join(CURRENT_DIR, "test_srv_relay.db")

    for path in (test_cache_alice, test_cache_bob, test_server_db):
        if os.path.exists(path):
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)

    test_port = 65495
    server = RelayServer(host="127.0.0.1", port=test_port, db_path=test_server_db)
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    alice = MobileChatClient(port=test_port, cache_dir=test_cache_alice)
    bob = MobileChatClient(port=test_port, cache_dir=test_cache_bob)

    bob_received = []
    alice_received = []

    bob.on_message_received = lambda sender, text, e2ee: bob_received.append((sender, text, e2ee))
    alice.on_message_received = lambda sender, text, e2ee: alice_received.append((sender, text, e2ee))

    # 1. Login with 10-digit phone numbers
    assert alice.login_and_connect("9876543210", username="Alice")
    assert bob.login_and_connect("9123456780", username="Bob")
    time.sleep(0.5)

    # 2. Alice sends E2EE message to Bob
    msg_alice = "Mobile E2EE message from Alice's smartphone!"
    alice.send_secure_message(receiver_phone="9123456780", message_text=msg_alice)
    time.sleep(0.5)

    assert len(bob_received) == 1
    assert bob_received[0][0] == "9876543210"
    assert bob_received[0][1] == msg_alice
    assert bob_received[0][2] is True
    print(f"[PASS] Bob's mobile client decrypted E2EE message: '{msg_alice}'")

    # 3. Bob replies to Alice
    msg_bob = "Reply from Bob's smartphone with AES-GCM encryption."
    bob.send_secure_message(receiver_phone="9876543210", message_text=msg_bob)
    time.sleep(0.5)

    assert len(alice_received) == 1
    assert alice_received[0][1] == msg_bob
    print(f"[PASS] Alice's mobile client decrypted E2EE reply: '{msg_bob}'")

    # 4. Verify local chat history cache on device
    alice_history = alice.get_local_history("9123456780")
    bob_history = bob.get_local_history("9876543210")

    assert len(alice_history) == 2  # 1 outgoing, 1 incoming
    assert len(bob_history) == 2    # 1 incoming, 1 outgoing
    print(f"[PASS] Local device chat history verified on both mobile devices ({len(alice_history)} messages cached).")

    # Cleanup
    alice.close()
    bob.close()
    server.stop()
    for path in (test_cache_alice, test_cache_bob, test_server_db):
        if os.path.exists(path):
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
            except OSError:
                pass

    print("\n[ALL MOBILE FLOW TESTS PASSED!]")


if __name__ == "__main__":
    test_10_digit_phone_validation()
    test_local_device_key_cache_and_zero_knowledge()
    test_mobile_e2ee_relay()
