# Technical Documentation: Server Directory

## 1. Overview & Architecture

The `Server` directory contains the **Zero-Knowledge Multi-Connection Relay Server and Database Engine**. Its primary responsibility is routing encrypted packets, caching public keys, and queuing messages for offline clients **without ever being able to read or decrypt the message payloads**.

### Server Architecture Diagram

```
                             +-------------------------------+
                             |    DefaultSelector Event Loop  |
                             +---------------+---------------+
                                             |
                     +-----------------------+-----------------------+
                     |                                               |
         [EVENT_READ on Listening Socket]             [EVENT_READ / EVENT_WRITE on Clients]
                     |                                               |
                     v                                               v
             accept_wrapper()                               service_connection()
                     |                                               |
         +-----------+-----------+                     +-------------+-------------+
         | Create ClientSession  |                     |  StreamParser (protocol)  |
         | Register with Selector|                     +-------------+-------------+
         +-----------------------+                                   |
                                                                     v
                                                          handle_packet(header, payload)
                                                                     |
                     +-----------------------------------------------+--------------------------------+
                     |                                               |                                |
                     v                                               v                                v
         content-type: "connect"                       content-type: "send message" / "file"     content-type: "get_public_key"
                     |                                               |                                |
          • Map Phone -> Session                          • Lookup Sender & Receiver Names         • Query Public Key
          • Store Public Key in DB                        • Log Encrypted Packet to DB               from DB
          • Flush Offline Messages                        • Print Intercepted Hex to Console       • Return to Requester
                                                          • Relay directly (if online) OR
                                                          • Store in offline_messages (if offline)
```

---

## 2. Directory Structure

```text
Server/
├── relay_server.py      # Selector-based non-blocking relay server with intercepted payload display
├── database.py          # SQLite database (users, offline queue, and encrypted message audit log)
├── protocol.py          # Application header byte stream packing and chunked streaming parser
├── crypto.py            # RSA and AES-GCM primitives (for server-side tests & verification)
├── relay_client.py      # Reference client implementation matching the Server package
├── test_relay.py        # Automated test suite for protocol, relay, and offline delivery
└── test_chat.db         # Default SQLite database file
```

---

## 3. Core Modules & Inner Workings

### A. Non-Blocking Multiplexed I/O (`relay_server.py`)

The server uses Python's standard `selectors.DefaultSelector` (which selects `epoll` on Linux, `kqueue` on macOS, or `select`/`IOCP` on Windows):

1. **Listening Socket Initialization**:
   ```python
   lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
   lsock.bind((self.host, self.port))
   lsock.listen()
   lsock.setblocking(False)
   self.selector.register(lsock, selectors.EVENT_READ, data=None)
   ```
2. **`accept_wrapper(sock)`**:
   - Accepts new incoming connections without blocking.
   - Sets `conn.setblocking(False)`.
   - Wraps the socket in a `ClientSession` object containing:
     - Socket object and remote IP/port address.
     - Instance of `protocol.StreamParser`.
     - Output write buffer (`outb`).
     - Associated phone number (assigned upon login).
   - Registers the connection for `EVENT_READ`.
3. **`service_connection(key, mask)`**:
   - **`EVENT_READ`**: Receives data into the session's stream parser. Feeds chunked bytes and calls `handle_packet()` for each fully framed packet.
   - **`EVENT_WRITE`**: If data exists in the output buffer `outb`, flushes it out over the socket. When drained, switches the socket mask back to `EVENT_READ`.

---

### B. Packet Routing & Message Handling (`handle_packet`)

The server processes three primary message types defined in the application header:

#### 1. Login & Connection (`content-type: "connect"`)
* Triggered when a client connects:
  - Registers the socket session in `self.active_users[phone_number] = session`.
  - Saves/updates the user's phone number, username, and **RSA Public Key** in the database.
  - Sends a `status` confirmation packet back to the client (`{"status": "connected"}`).
  - **Offline Message Flush**: Checks if any messages were queued while this user was offline. If so, immediately pushes them to the client's output buffer.

#### 2. E2EE Message & File Relay (`content-type: "send message"` or `"file"`)
* When client A sends an encrypted message or file to client B:
  1. **Validation**: Verifies that the recipient phone number exists in the database.
  2. **Audit Logging**: Looks up sender and recipient usernames and permanently logs the encrypted record in the `encrypted_messages` table.
  3. **Console Visualization**: Displays the intercepted encrypted payload hex and the encrypted AES key in the server terminal.
  4. **Relay Decision**:
     - **If Recipient is Online (`receiver_id in self.active_users`)**:
       The packet is immediately appended to the recipient's output buffer `target_session.queue_packet(forward_packet)`.
       Sends delivery confirmation ACK back to sender (`{"status": "delivered"}`).
     - **If Recipient is Offline**:
       Stores the raw packet in `offline_messages` in the database.
       Sends queued ACK back to sender (`{"status": "queued", "message": "User offline. Queued for delivery."}`).

#### 3. Public Key Exchange (`content-type: "get_public_key"`)
* Used during E2EE session setup:
  - Looks up the recipient's phone number in the database.
  - Returns the recipient's registered RSA Public Key in a `public_key_response` packet.

---

### C. Database Engine (`database.py`)

The database subsystem uses SQLite with `Row` factory support and thread-safe connection handling:

```sql
-- 1. Registered Users Table (Public Keys Only)
CREATE TABLE IF NOT EXISTS users (
    phone_number TEXT PRIMARY KEY,
    username     TEXT,
    public_key   TEXT DEFAULT '',     -- RSA-3072 Public Key in PEM format
    is_online    INTEGER DEFAULT 0,
    last_seen    REAL
);

-- 2. Offline Message Queue Table (Store-and-Forward)
CREATE TABLE IF NOT EXISTS offline_messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id    TEXT NOT NULL,
    receiver_id  TEXT NOT NULL,
    raw_packet   BLOB NOT NULL,       -- Complete binary protocol packet
    created_at   REAL NOT NULL,
    FOREIGN KEY (receiver_id) REFERENCES users (phone_number)
);

-- 3. Encrypted Message Audit Table (Zero-Knowledge Record)
CREATE TABLE IF NOT EXISTS encrypted_messages (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_phone       TEXT NOT NULL,
    sender_name        TEXT,
    receiver_phone     TEXT NOT NULL,
    receiver_name      TEXT,
    content_type       TEXT NOT NULL,
    encryption_key     TEXT,          -- RSA-OAEP encrypted AES key in hex
    ciphertext_hex     TEXT NOT NULL, -- AES-256-GCM ciphertext in hex
    payload_size_bytes INTEGER NOT NULL,
    timestamp          REAL NOT NULL
);
```

---

## 4. Visualizing Zero-Knowledge Relaying

Whenever traffic passes through the server, the server console prints a detailed inspection block:

```text
======================================================================
[RELAY SERVER - ENCRYPTED PAYLOAD INTERCEPTED]
  * Sender:        Alice (+1111111111)
  * Receiver:      Bob (+2222222222)
  * Type:          send message
  * Payload Size:  79 bytes
  * Encrypted Key: d46c73a09a0cd52c4cc3313c6740b112ae3b1a43... (256 bytes)
  * Ciphertext:    c20960ece7c15fdb0246541ff249e38672ded23c5d... (AES-GCM Hex)
  * Database Log:  Stored in 'encrypted_messages' table (Record ID logged)
======================================================================
```

### Why This Matters:
1. **Verifiable Privacy**: Network administrators or server operators can clearly see that the payload is indecipherable ciphertext.
2. **Auditability**: Organizations can audit metadata (who messaged whom and when) without violating the confidentiality of the communications.
3. **No Private Keys Stored**: The server database only contains public keys and ciphertext. A full server breach compromises zero plaintext messages.
