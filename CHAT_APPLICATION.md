# Technical Documentation: Chat_Application

## 1. Overview & Architecture

The `Chat_Application` directory provides a **zero-knowledge, smartphone-ready End-to-End Encrypted (E2EE) chat client and SDK**. It is designed to be easily bound to any modern mobile user interface (such as Flutter, React Native, Kivy, or Android Kotlin) while ensuring that cryptographic private keys **never leave the user's physical device**.

### High-Level Architecture Diagram

```
+-----------------------------------------------------------------------------------+
|                            MOBILE CLIENT (Smart Device)                           |
|                                                                                   |
|   +-----------------------+     +-----------------------+     +---------------+   |
|   | 10-Digit Phone Input  | --> |  Phone Validator &    | --> | Mobile Client |   |
|   | (e.g. 9876543210)     |     |  Normalizer (storage) |     |  Controller   |   |
|   +-----------------------+     +-----------------------+     +-------+-------+   |
|                                                                       |           |
|   +-------------------------------------------------------------+     |           |
|   | Local Device Secure Cache (device_cache/)                   |     |           |
|   |  • <phone>_keys.json (RSA Private & Public Key, chmod 0600) | <---+           |
|   |  • <phone>_chat_history.db (Decrypted local messages)       |     |           |
|   +-------------------------------------------------------------+     |           |
|                                                                       |           |
|   +-------------------------------------------------------------+     |           |
|   | Local Cryptographic Engine (crypto.py)                      |     |           |
|   |  • Fresh Ephemeral 256-bit AES-GCM Key per message          | <---+           |
|   |  • RSA-3072 + PKCS1_OAEP Key Encapsulation                  |                 |
|   +-------------------------------------------------------------+                 |
+-----------------------------------------------------------------------|-----------+
                                                                        |
                                              TCP Application Stream    |
                                              [2-Byte Size][JSON][Data] |
                                                                        v
                                                         +----------------------+
                                                         | Relay Server         |
                                                         | (Zero-Knowledge)     |
                                                         +----------------------+
```

---

## 2. Directory Structure

```text
Chat_Application/
├── crypto.py             # Client-side cryptographic operations (RSA-3072 + AES-256-GCM)
├── storage.py            # 10-digit validation, local device key store, and local chat DB
├── protocol.py           # TCP application header stream framing & parser
├── mobile_client.py      # Mobile chat client controller, background worker, and CLI
├── server.py             # Dedicated relay server with 10-digit enforcement & payload display
├── database.py           # Server database (public keys, offline queue, encrypted message log)
├── test_mobile_flow.py   # Automated test suite for the complete mobile workflow
├── requirements.txt      # Python dependencies (cryptography, pycryptodome)
├── Dockerfile            # Container definition for deploying the server to cloud
└── docker-compose.yml    # Docker Compose deployment definition
```

---

## 3. Core Modules & Inner Workings

### A. Phone Number Validation & Normalization (`storage.py`)

Mobile telecom standards and authentication require consistent phone numbers. The `validate_phone_number()` function enforces strict 10-digit validation:

1. **Stripping Separators**: Removes all spaces, hyphens (`-`), parentheses (`()`), and extraneous symbols.
2. **Country Code Handling**:
   - Supports international prefixes (e.g., `+91`, `+1`). Validates that the country code is 1–3 digits and extracts the core 10-digit national number.
   - Handles domestic trunk prefixes (e.g., leading `0` in `09876543210` is stripped to `9876543210`).
3. **Strict Length Check**: Enforces `^[0-9]{10}$`. Rejects arbitrary strings, short codes, or over-length numbers with a descriptive `ValueError`.

### B. Local Device Key Cache & Zero-Knowledge Security (`storage.py`)

A fundamental rule of End-to-End Encryption is: **Private keys must never touch the network or the server.**

* **`DeviceKeyStore`**:
  - Operates inside the device's sandboxed storage (`device_cache/`).
  - Filename format: `device_cache/<10_digit_phone>_keys.json`.
  - When a user logs in:
    1. Checks if cached keys exist on this device for the phone number.
    2. If found, loads `private_key` and `public_key` locally without regenerating.
    3. If new, generates a fresh **RSA-3072** key pair locally, saves it with restricted file permissions (`chmod 0600`), and exports **only the public key** to the server.
  - The server database receives and stores **only the RSA Public Key**.

### C. Local Chat History Database (`storage.py`)

Because the server is zero-knowledge and forwards encrypted packets without retaining plaintext, smartphone applications must store their own conversation history locally:

* **`DeviceChatDatabase`**:
  - Implemented with SQLite per user: `device_cache/<10_digit_phone>_chat_history.db`.
  - Schema:
    ```sql
    CREATE TABLE messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        peer_phone TEXT NOT NULL,
        direction TEXT NOT NULL,        -- 'incoming' or 'outgoing'
        content_type TEXT NOT NULL,     -- 'text' or 'file'
        body TEXT NOT NULL,             -- Plaintext message (decrypted locally)
        is_e2ee INTEGER DEFAULT 1,
        timestamp REAL NOT NULL
    );
    ```
  - Provides `save_message()` and `get_messages()` for viewing past chats.

### D. Cryptographic Subsystem (`crypto.py`)

Implements **Hybrid Encryption** combining the speed of symmetric encryption with the key distribution of asymmetric encryption:

1. **Message Encryption (`encrypt_hybrid`)**:
   - Generates an ephemeral **256-bit AES key** (`AESGCM.generate_key(bit_length=256)`).
   - Generates a cryptographically secure **12-byte (96-bit) Initialization Vector (IV)** (`os.urandom(12)`).
   - Encrypts the payload with **AES-256-GCM** (authenticated encryption).
   - Prepends the 12-byte IV to the ciphertext: `payload_with_iv = iv + ciphertext`.
   - Encrypts the ephemeral AES key with the recipient's **RSA-3072 public key** using **PKCS1_OAEP** padding.
   - Returns `(encrypted_aes_key.hex(), payload_with_iv)`.

2. **Message Decryption (`decrypt_hybrid`)**:
   - Uses the recipient device's locally cached **RSA private key** to decrypt the AES key via **PKCS1_OAEP**.
   - Extracts the first 12 bytes as the IV and the remainder as ciphertext.
   - Decrypts and authenticates the ciphertext using **AES-256-GCM**.

### E. Wire Framing Protocol (`protocol.py`)

Conforms to the 3-part Application Header byte stream:

```
+-------------------+---------------------------------------------------------+--------------------+
| 2-byte Size       | JSON Header                                             | Content            |
| (Big Endian '>H') | {                                                       | (Binary Payload)   |
|                   |   "byteorder": "little",                                |                    |
|                   |   "senderID": "9876543210",                             |                    |
|                   |   "receiverID": "9123456780",                           |                    |
|                   |   "content-type": "send message" | "file" | "connect", |                    |
|                   |   "content-encoding": "utf-8" | "binary",               |                    |
|                   |   "encryption key": "<RSA-encrypted AES key hex>",      |                    |
|                   |   "content-length": <payload length in bytes>           |                    |
|                   | }                                                       |                    |
+-------------------+---------------------------------------------------------+--------------------+
```

* **`StreamParser`**: A stateful streaming buffer parser that handles TCP fragmentation, chunked packets, and partial socket reads without data loss.

### F. Mobile Client Controller (`mobile_client.py`)

The primary SDK class `MobileChatClient` manages the client lifecycle:

1. **Multi-Host Network Discovery & Failover**:
   - `host` parameter accepts a string or a list of candidate IPs:
     ```python
     client = MobileChatClient(host=["10.222.77.80", "192.168.1.15", "127.0.0.1"], port=65432)
     ```
   - Automatically attempts each network with a 2-second timeout until it connects.
2. **Background Listening Thread (`_listen_loop`)**:
   - Continuously receives packets and parses them asynchronously.
   - Keeps connection alive while the user types or performs other actions.
3. **Public Key Discovery (`get_peer_public_key`)**:
   - Caches peer public keys in memory (`peer_public_keys`).
   - If missing, sends a `"get_public_key"` packet to the server and waits on a synchronization event (`threading.Event`).
4. **UI Event Hooks**:
   - `on_message_received(sender_phone, text, is_e2ee)`
   - `on_file_received(sender_phone, file_bytes, is_e2ee)`
   - `on_connection_status(status_dict)`

---

## 4. Security Guarantees

* **Zero-Knowledge Server**: The server never has access to private keys or plaintext data.
* **Forward Secrecy at Message Level**: Every individual message generates a fresh, unique 256-bit AES key. Compromising one AES key does not compromise past or future messages.
* **Tamper-Proof Authenticated Ciphertext**: AES-GCM includes a 128-bit authentication tag. If an attacker modifies even a single bit in the relayed ciphertext, decryption fails immediately.
