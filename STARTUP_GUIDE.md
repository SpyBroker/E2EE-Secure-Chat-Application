# Complete Application Walkthrough & User Guide

This guide walks you step-by-step through setting up, configuring, and running the End-to-End Encrypted (E2EE) Chat Application.

---

## 1. Prerequisites & System Requirements

* **Operating System**: Windows 10/11, Linux, or macOS.
* **Python**: Python 3.10 or higher installed.
* **Network**: Works locally on one PC (`127.0.0.1`) or across multiple computers/smartphones connected to the same Wi-Fi network.

---

## 2. Virtual Environment Setup & Activation

Your workspace already includes a configured virtual environment in the `venv/` folder.

### Activate the Virtual Environment:

* **On Windows (PowerShell)**:
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
  *(If you get an execution policy error, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

* **On Windows (Command Prompt)**:
  ```cmd
  venv\Scripts\activate.bat
  ```

* **On Linux / macOS**:
  ```bash
  source venv/bin/activate
  ```

Once activated, your terminal prompt will show `(venv)`.

---

## 3. Install Requirements

The application requires two cryptographic libraries:
* `cryptography` (for authenticated AES-256-GCM symmetric encryption)
* `pycryptodome` (for RSA-3072 key generation and PKCS1_OAEP padding)

To install or verify them:
```powershell
pip install -r Chat_Application\requirements.txt
```

---

## 4. Starting the Relay Server

Open your **first terminal window**, activate your virtual environment, and start the server:

### For Localhost & Local Wi-Fi Access:
```powershell
python Chat_Application\server.py 0.0.0.0 65432
```

* **`0.0.0.0`**: Listens on all network adapters (both localhost and your Wi-Fi IP).
* **`65432`**: The port number.

You will see:
```text
[RELAY SERVER] Listening on 0.0.0.0:65432
```

> **Firewall Tip**: If Windows Defender Firewall shows a popup, click **"Allow access"** on Private networks.

---

## 5. Starting the Clients

### Scenario A: Running on the Same PC (Testing with Multiple Terminals)

#### Terminal 2 – Alice:
```powershell
python Chat_Application\mobile_client.py 127.0.0.1 65432 9876543210
```

#### Terminal 3 – Bob:
```powershell
python Chat_Application\mobile_client.py 127.0.0.1 65432 9123456780
```

*(If you run `python Chat_Application\mobile_client.py` without arguments, it defaults to `127.0.0.1:65432` and interactively prompts for your 10-digit phone number).*

---

### Scenario B: Running Across Two Computers or Smartphones on Local Wi-Fi

1. **Find your Server PC's Wi-Fi IP address**:
   - Run `ipconfig` in PowerShell on the server PC.
   - Look for `Wireless LAN adapter Wi-Fi -> IPv4 Address` (e.g., `10.222.77.80` or `192.168.1.15`).

2. **Connect from Laptop 2 / Smartphone**:
   - Ensure the second device is connected to the **same Wi-Fi network**.
   - Launch the client targeting the Server's Wi-Fi IP:
     ```powershell
     python Chat_Application\mobile_client.py 10.222.77.80 65432 9123456780
     ```

---

## 6. Available Commands in the Client Terminal

Once logged in, the client provides an interactive shell with the following commands:

| Command | Action | Example |
| :--- | :--- | :--- |
| **`/msg <10-digit-phone> <text>`** | Encrypts with AES-256-GCM + RSA-OAEP and sends an E2EE message | `/msg 9123456780 Hello Bob!` |
| **`/file <10-digit-phone> <filepath>`** | Encrypts and transmits a binary file | `/file 9123456780 document.pdf` |
| **`/history <10-digit-phone>`** | Displays locally decrypted conversation history from device database | `/history 9123456780` |
| **`/exit`** | Closes socket connection and exits the application cleanly | `/exit` |

---

## 7. Step-by-Step Live Chat Demonstration

### 1. Alice Sends an E2EE Message:
In Alice's terminal (`9876543210`), type:
```text
> /msg 9123456780 Top secret message for your eyes only!
```

Alice sees:
```text
[STATUS]: {'status': 'delivered', 'receiverID': '9123456780'}
```

### 2. Bob Receives and Decrypts:
In Bob's terminal (`9123456780`), the incoming message appears in real time:
```text
[E2EE] [From 9876543210]: Top secret message for your eyes only!
```

### 3. Server Console Observation:
Look at the **Server terminal**. The server displays the intercepted packet:
```text
======================================================================
[RELAY SERVER - ENCRYPTED PAYLOAD INTERCEPTED]
  * Sender:        Alice (9876543210)
  * Receiver:      Bob (9123456780)
  * Type:          send message
  * Payload Size:  72 bytes
  * Encrypted Key: 4634894dcc8b8f75b5be67cd36db3bcf95b7d675... (384 bytes)
  * Ciphertext:    12173b1af659c8a73f0add57afb96e142dcd1a3d2f... (AES-GCM Hex)
  * Database Log:  Stored in 'encrypted_messages' table (Zero-Knowledge Audit)
======================================================================
```
> **Proof of E2EE**: The server intercepted the communication, but only sees the **RSA-encrypted AES session key** and the **AES-GCM ciphertext hex**. The server cannot read the secret message.

### 4. Viewing Local Chat History:
In Bob's terminal, type:
```text
> /history 9876543210
```
Output:
```text
--- Chat History with 9876543210 (1 messages) ---
[<-] Top secret message for your eyes only!
--- End History ---
```

---

## 8. Testing Offline Store-and-Forward

The application includes an offline message queue:

1. In Bob's terminal, type `/exit` to disconnect Bob.
2. In Alice's terminal, send a message to offline Bob:
   ```text
   > /msg 9123456780 Are you there? Leaving this while you are away.
   ```
   Alice receives:
   ```text
   [STATUS]: {'status': 'queued', 'receiverID': '9123456780', 'message': 'User offline. Queued for delivery.'}
   ```
3. Reconnect Bob:
   ```powershell
   python Chat_Application\mobile_client.py 127.0.0.1 65432 9123456780
   ```
4. As soon as Bob logs in, the server flushes the queue, and Bob immediately receives:
   ```text
   [E2EE] [From 9876543210]: Are you there? Leaving this while you are away.
   ```

---

## 9. Automated Test Suites

You can run automated end-to-end tests anytime to verify that protocol framing, cryptographic primitives, and offline queueing pass:

### Test the Mobile Architecture:
```powershell
python Chat_Application\test_mobile_flow.py
```

### Test the Server Architecture:
```powershell
python Server\test_relay.py
```

---

## 10. Troubleshooting & FAQ

* **Issue: `RuntimeError: Could not retrieve public key for recipient`**
  - **Reason**: The recipient has not logged in at least once, so their public key is not yet in the server database.
  - **Fix**: Connect the recipient client once so their public key is cataloged.

* **Issue: `Connection refused` when connecting from a second device on Wi-Fi**
  - **Reason**: Windows Defender Firewall is blocking inbound connections on port 65432, or the wrong IP address was entered.
  - **Fix**: Verify your server's Wi-Fi IP using `ipconfig`. In Windows Defender Firewall with Advanced Security, create an **Inbound Rule** allowing TCP port **65432**.

* **Issue: `Invalid phone number: A phone number must contain exactly 10 digits`**
  - **Reason**: The phone number entered does not contain 10 numeric digits.
  - **Fix**: Enter standard 10-digit numbers like `9876543210` or with country code like `+919876543210`.
