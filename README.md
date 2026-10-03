# E2EE Secure Chat Application

An end-to-end encrypted (E2EE) chat system with a Python relay server and an Android/desktop client built with Kivy. Messages and files are encrypted on the sender's device and can only be decrypted on the recipient's device. The relay server only forwards ciphertext and never holds a private key.

## Features

- **End-to-end encryption**: hybrid scheme with a fresh AES-256-GCM key per message, wrapped with the recipient's RSA-3072 public key (PKCS1-OAEP).
- **Private keys stay on the device**: they are generated locally and never sent to the server. Only the public key is registered.
- **Text and file messaging** between 10-digit phone numbers.
- **Offline store-and-forward**: messages for offline users are queued on the server (still encrypted) and delivered at next login.
- **Local chat history**: decrypted history lives only on each device, because the server cannot read it.
- **Three clients**: Android app (Kivy), the same app on desktop, and a terminal client.
- **Multi-host failover**: the client accepts a comma-separated list of server addresses and tries each in turn.

## Repository layout

```text
.
├── Chat_Application/          # Client app + the relay server used by the app
│   ├── app_main.py            # Kivy UI (login, chats, Config screen)
│   ├── main.py                # App launcher (shows crash errors on screen, saves crash_log.txt)
│   ├── mobile_client.py       # Client SDK + terminal client
│   ├── server.py              # Relay server
│   ├── database.py            # Server database (public keys, offline queue, encrypted-message log)
│   ├── storage.py             # Phone-number validation, device key store, local chat history DB
│   ├── crypto.py              # RSA-3072 + AES-256-GCM (pycryptodome only)
│   ├── protocol.py            # Wire framing and stream parser
│   ├── buildozer.spec         # Android build configuration
│   ├── Build_E2EE_Chat_APK.ipynb  # Notebook for building the APK
│   ├── test_mobile_flow.py    # Automated end-to-end test
│   ├── requirements.txt
│   ├── Dockerfile             # Optional: container for the server
│   └── docker-compose.yml     # Optional: container deployment
├── Server/                    # Standalone reference relay server, client and tests
├── test_demo/                 # Small demos (AES-GCM, RSA, custom header)
├── CHAT_APPLICATION.md        # Original client documentation
├── SERVER.md                  # Original server documentation
└── STARTUP_GUIDE.md           # Original walkthrough
```

## How it works

```text
  Alice's device                    Relay server                     Bob's device
 +-----------------+           +-------------------+            +-----------------+
 | RSA private key |           | public keys only  |            | RSA private key |
 | local chat DB   |           | offline queue     |            | local chat DB   |
 +--------+--------+           +---------+---------+            +--------+--------+
          | 1. get Bob's public key      |                               |
          |----------------------------->|                               |
          | 2. encrypt locally           |                               |
          |    (AES-GCM + RSA-OAEP)      |                               |
          | 3. send ciphertext --------->| 4. forward (or queue) ------->| 5. decrypt locally
```

1. **Login**: the client validates the 10-digit number, loads or creates its RSA key pair in `device_cache/`, connects, and sends its **public key** to the server.
2. **Sending**: the client asks the server for the recipient's public key, generates a random 256-bit AES key and 12-byte IV, encrypts the message with AES-GCM, and encrypts the AES key with the recipient's RSA public key. Payload format: `IV (12) + ciphertext + GCM tag (16)`.
3. **Relay**: the server forwards the packet if the recipient is online, or stores it in `offline_messages` until they log in. It sends the sender a `delivered` or `queued` status.
4. **Receiving**: the recipient decrypts the AES key with their private key, then decrypts and authenticates the message. Any tampering makes GCM verification fail.

### Wire protocol

Each packet is a byte stream of three parts: `[2-byte big-endian header size][JSON header][payload]`.

```json
{
  "byteorder": "little",
  "senderID": "9876543210",
  "receiverID": "9123456780",
  "content-type": "send message | file | connect | get_public_key | public_key_response | status",
  "content-encoding": "utf-8 | binary",
  "encryption key": "<RSA-encrypted AES key, hex>",
  "content-length": 72
}
```

`protocol.StreamParser` handles TCP fragmentation and partial reads.

### Phone-number rules

`storage.validate_phone_number()` strips spaces, dashes and brackets, accepts `+<country code>` prefixes (1-3 digits) and a leading trunk `0`, and requires exactly 10 national digits. For example, `+91 98765-43210` becomes `9876543210`.

### Server database

| Table | Contents |
| :--- | :--- |
| `users` | phone number, username, **public key**, online flag, last seen |
| `offline_messages` | queued packets for offline recipients |
| `encrypted_messages` | log of relayed packets (metadata, wrapped key, ciphertext) |

## Requirements

- Python 3.10 or newer
- `pycryptodome` (required)
- `kivy` (only for the graphical app)

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1          # Windows PowerShell
# source venv/bin/activate           # Linux / macOS
pip install -r Chat_Application\requirements.txt
pip install kivy                     # only for the GUI client
```

If PowerShell blocks the activation script, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first.

## Quick start (everything on one computer)

**Terminal 1: server**
```powershell
python Chat_Application\server.py 0.0.0.0 65432
```
You should see `[RELAY SERVER] Listening on 0.0.0.0:65432`. Allow it through Windows Firewall on Private networks if prompted.

**Terminal 2 and 3: two terminal clients**
```powershell
python Chat_Application\mobile_client.py 127.0.0.1 65432 9876543210
python Chat_Application\mobile_client.py 127.0.0.1 65432 9123456780
```

If you omit the arguments, the client defaults to `127.0.0.1:65432` and asks for your number.

### Terminal client commands

| Command | Action |
| :--- | :--- |
| `/msg <phone> <text>` | Send an E2EE message |
| `/file <phone> <path>` | Send an E2EE file |
| `/history <phone>` | Show locally stored history with that contact |
| `/exit` | Quit |

### Try it

1. In Alice's terminal: `/msg 9123456780 Hello Bob!`
2. Bob's terminal shows `[E2EE] [From 9876543210]: Hello Bob!`
3. The server console prints the intercepted packet. It only shows the wrapped AES key and ciphertext hex, which the server cannot read.
4. **Offline test**: `/exit` Bob, send Alice's message, then reconnect Bob. The queued message arrives on login.

> Each recipient must log in **at least once** so the server has their public key. Otherwise sending fails with "Could not retrieve public key for recipient".

## Using the graphical app

Desktop:
```powershell
pip install kivy
python Chat_Application\main.py
```

Android: build the APK with `buildozer` (see `buildozer.spec`) or the `Build_E2EE_Chat_APK.ipynb` notebook, then install it.

In the app:

1. Tap the three-dot menu, then **Config**.
2. Enter the **Server IP** (or hostname) and **Port** (`65432`), then Save. Use `127.0.0.1` if the server runs on the same computer. You can enter several addresses separated by commas.
3. Enter your 10-digit number and tap **Connect**. The status should read "Connected as ...".
4. Use **New chat**, enter the other person's number, and start messaging.

## Connecting devices on different networks

The server address is not built into the app, so the same APK works with any server.

### Option 1: Same Wi-Fi

Run `ipconfig` on the server computer, find the IPv4 address (for example `192.168.1.15`), and use it in the app's Config. Allow inbound TCP 65432 in Windows Firewall:

```powershell
netsh advfirewall firewall add rule name="E2EE Chat" dir=in action=allow protocol=TCP localport=65432
```
Run that in PowerShell as Administrator.

### Option 2: Tailscale (different networks, free)

Tailscale puts devices on one private network wherever they are, with no router changes.

1. Install Tailscale on the server computer and the phone, and sign in with the **same account**.
2. On the server computer run `tailscale ip -4` to get its `100.x.x.x` address.
3. Start the server with `python Chat_Application\server.py 0.0.0.0 65432` and add the firewall rule above.
4. In the app, set Config to the `100.x.x.x` address and port `65432`.

To let a friend join, they install Tailscale with **their own account**, and you share your server computer with them from the Tailscale admin console (Machines, then the menu next to your computer, then "Share this machine"). They accept the invite and use the server's Tailscale address in Config. Sharing only exposes that one computer.

### Option 3: Phone hotspot (quick test)

Turn on a phone's hotspot, connect the server computer to it, and use that computer's IPv4 address in Config.

### Option 4: Cloud server (optional)

The server can run on any VM with a public IP. The `Dockerfile` and `docker-compose.yml` are provided for this. You must open inbound TCP 65432 in the provider's firewall, and use the VM's IP in the app's Config. Make sure the compose file keeps its data in a separate volume and does not mount a host folder over `/app`, which would hide the server code.

## Notes

- The server computer must stay on and keep `server.py` running while people chat.
- One number maps to one connection. Do not log in with the same number on two devices at once.
- Keys are created and stored on the device where a number first logs in. Logging in as the same number on a new device creates new keys, and old messages cannot be decrypted there.
- Switching to a new server means a fresh database. Every user must log in once to register their public key again.

## Tests

```powershell
python Chat_Application\test_mobile_flow.py   # client workflow
python Server\test_relay.py                   # standalone server package
```

## Security notes and limitations

What this design provides:

- The server never has private keys or plaintext.
- Each message uses its own random AES key, and AES-GCM detects tampering.

What it does not provide (this is a learning/test project):

- **No user authentication.** Anyone who can reach the server can connect as any number, and a `connect` replaces that number's stored public key. A malicious user could take over a number or intercept messages meant for it. Add phone verification (OTP) before wider use.
- **No TLS.** Message content is end-to-end encrypted, but the connection is plain TCP, so metadata (who talks to whom, when, and message sizes) is visible to the network and the server operator.
- **No forward secrecy.** Per-message AES keys limit the damage of one leaked AES key, but they are wrapped with a long-term RSA key. If a user's RSA private key is stolen, every message ever sent to them can be decrypted.
- **No key verification.** There is no safety-number or fingerprint check, so the server could substitute a public key undetected.
- The server logs relayed ciphertext in `encrypted_messages`, which grows with file transfers.
- **Never commit** `device_cache/`, `cache_*/` or `*.db` files. They contain private keys and chat data, and are listed in `.gitignore`.

## Original documentation

For module-level detail, see `CHAT_APPLICATION.md`, `SERVER.md` and `STARTUP_GUIDE.md`.