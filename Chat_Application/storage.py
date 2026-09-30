"""
Local Device Storage and Key Cache for Smartphone Client.
Features:
- Strict 10-digit phone number validation.
- Secure local device key cache:
    * RSA Private key is stored locally on the device (chmod 600).
    * Private key NEVER leaves device or touches the network.
- Local chat history cache (since server is zero-knowledge and has no plaintext history).
"""

import os
import re
import json
import sqlite3
import time
from typing import Tuple, Optional, List, Dict, Any

from crypto import generate_rsa_keypair

DEFAULT_CACHE_DIR = os.path.join(os.path.dirname(__file__), "device_cache")


def validate_phone_number(phone_raw: str) -> str:
    """
    Validates that the input phone number contains exactly 10 digits.
    Strips country code prefixes (+91, +1, etc.), spaces, and dashes.
    Returns: Cleaned 10-digit string (e.g. '9876543210').
    Raises: ValueError if the number is not exactly 10 digits.
    """
    if not phone_raw or not isinstance(phone_raw, str):
        raise ValueError("Phone number must be a non-empty string.")

    cleaned = re.sub(r"[\s\-\(\)]", "", phone_raw.strip())

    # Handle optional country prefix (+ followed by 1 to 3 country digits)
    if cleaned.startswith("+"):
        digits_only = cleaned[1:]
        # Valid country codes are 1-3 digits, leaving 10 digits (e.g., +1XXXXXXXXXX, +91XXXXXXXXXX)
        if 11 <= len(digits_only) <= 13:
            cleaned = digits_only[-10:]
        else:
            raise ValueError(f"Phone number with country code must contain 10 national digits: '{phone_raw}'")
    elif cleaned.startswith("0") and len(cleaned) == 11:
        # Domestic trunk prefix: 0 followed by 10 digits
        cleaned = cleaned[1:]

    # Enforce strictly 10 digits
    if not re.fullmatch(r"^[0-9]{10}$", cleaned):
        raise ValueError(
            f"Invalid phone number '{phone_raw}'. A phone number must contain exactly 10 digits."
        )

    return cleaned


class DeviceKeyStore:
    """
    Manages cryptographic key storage strictly within the local device cache.
    The private key is cached locally and NEVER transmitted to the server.
    """

    def __init__(self, cache_dir: str = DEFAULT_CACHE_DIR):
        self.cache_dir = cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)

    def _get_key_filepath(self, phone_number: str) -> str:
        clean_phone = validate_phone_number(phone_number)
        return os.path.join(self.cache_dir, f"{clean_phone}_keys.json")

    def has_keys(self, phone_number: str) -> bool:
        return os.path.exists(self._get_key_filepath(phone_number))

    def save_keys(self, phone_number: str, private_pem: str, public_pem: str):
        filepath = self._get_key_filepath(phone_number)
        data = {
            "phone_number": validate_phone_number(phone_number),
            "private_key": private_pem,
            "public_key": public_pem,
            "created_at": time.time(),
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        # Set strict permissions on POSIX systems (chmod 600)
        try:
            os.chmod(filepath, 0o600)
        except Exception:
            pass

    def load_keys(self, phone_number: str) -> Tuple[str, str]:
        """Loads (private_pem, public_pem) from local device cache."""
        filepath = self._get_key_filepath(phone_number)
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"No cached keys found for phone number {phone_number} on this device.")

        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        return data["private_key"], data["public_key"]

    def get_or_create_keys(self, phone_number: str, key_size: int = 3072) -> Tuple[str, str]:
        """
        Retrieves existing keys from device cache if present.
        If not found, generates a new RSA key pair locally, caches it, and returns the pair.
        """
        clean_phone = validate_phone_number(phone_number)
        if self.has_keys(clean_phone):
            return self.load_keys(clean_phone)

        # Generate on device
        private_pem, public_pem = generate_rsa_keypair(key_size)
        self.save_keys(clean_phone, private_pem, public_pem)
        return private_pem, public_pem


class DeviceChatDatabase:
    """
    Local SQLite database on the smartphone to store contacts and decrypted chat history.
    Since the relay server is zero-knowledge, local device storage is the source of truth for chat history.
    """

    def __init__(self, phone_number: str, cache_dir: str = DEFAULT_CACHE_DIR):
        clean_phone = validate_phone_number(phone_number)
        os.makedirs(cache_dir, exist_ok=True)
        self.db_path = os.path.join(cache_dir, f"{clean_phone}_chat_history.db")
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    peer_phone TEXT NOT NULL,
                    direction TEXT NOT NULL,  -- 'incoming' or 'outgoing'
                    content_type TEXT NOT NULL,
                    body TEXT NOT NULL,
                    is_e2ee INTEGER DEFAULT 1,
                    timestamp REAL NOT NULL
                )
            """)
            conn.commit()

    def save_message(self, peer_phone: str, direction: str, body: str, content_type: str = "text", is_e2ee: bool = True):
        clean_peer = validate_phone_number(peer_phone)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO messages (peer_phone, direction, content_type, body, is_e2ee, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (clean_peer, direction, content_type, body, 1 if is_e2ee else 0, time.time()))
            conn.commit()

    def get_messages(self, peer_phone: str, limit: int = 50) -> List[Dict[str, Any]]:
        clean_peer = validate_phone_number(peer_phone)
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM messages 
                WHERE peer_phone = ? 
                ORDER BY timestamp ASC 
                LIMIT ?
            """, (clean_peer, limit))
            return [dict(row) for row in cursor.fetchall()]
