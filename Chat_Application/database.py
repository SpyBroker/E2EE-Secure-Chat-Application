"""
Server-side database for user authentication, public key registry, and offline message queue.
Only stores the 10-digit phone number and RSA PUBLIC key.
The server NEVER has access to any client's private key.
"""

import sqlite3
import os
import time
from typing import Optional, List, Dict, Any
from storage import validate_phone_number

DEFAULT_SERVER_DB = os.path.join(os.path.dirname(__file__), "server_chat.db")


class ServerDatabase:
    def __init__(self, db_path: str = DEFAULT_SERVER_DB):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Registered users table (Only public_key is stored!)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    phone_number TEXT PRIMARY KEY,
                    username TEXT,
                    public_key TEXT DEFAULT '',
                    is_online INTEGER DEFAULT 0,
                    last_seen REAL
                )
            """)
            # Offline messages queue table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS offline_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id TEXT NOT NULL,
                    receiver_id TEXT NOT NULL,
                    raw_packet BLOB NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY (receiver_id) REFERENCES users (phone_number)
                )
            """)
            # Persistent log of all relayed encrypted messages
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS encrypted_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_phone TEXT NOT NULL,
                    sender_name TEXT,
                    receiver_phone TEXT NOT NULL,
                    receiver_name TEXT,
                    content_type TEXT NOT NULL,
                    encryption_key TEXT,
                    ciphertext_hex TEXT NOT NULL,
                    payload_size_bytes INTEGER NOT NULL,
                    timestamp REAL NOT NULL
                )
            """)
            conn.commit()

            # Seed demo 10-digit users if empty
            cursor.execute("SELECT COUNT(*) AS count FROM users")
            if cursor.fetchone()["count"] == 0:
                demo_users = [
                    ("9876543210", "Alice"),
                    ("9123456780", "Bob"),
                    ("9988776655", "Charlie"),
                ]
                now = time.time()
                cursor.executemany(
                    "INSERT INTO users (phone_number, username, last_seen) VALUES (?, ?, ?)",
                    [(phone, name, now) for phone, name in demo_users],
                )
                conn.commit()

    def register_or_login_user(self, phone_number: str, username: str = "", public_key: str = "") -> bool:
        clean_phone = validate_phone_number(phone_number)
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE phone_number = ?", (clean_phone,))
            user = cursor.fetchone()
            if user:
                cursor.execute("""
                    UPDATE users 
                    SET is_online = 1, last_seen = ?, 
                        username = CASE WHEN ? != '' THEN ? ELSE username END,
                        public_key = CASE WHEN ? != '' THEN ? ELSE public_key END
                    WHERE phone_number = ?
                """, (now, username, username, public_key, public_key, clean_phone))
            else:
                cursor.execute("""
                    INSERT INTO users (phone_number, username, public_key, is_online, last_seen)
                    VALUES (?, ?, ?, 1, ?)
                """, (clean_phone, username or clean_phone, public_key, now))
            conn.commit()
            return True

    def set_user_offline(self, phone_number: str):
        clean_phone = validate_phone_number(phone_number)
        now = time.time()
        with self._get_connection() as conn:
            conn.execute("UPDATE users SET is_online = 0, last_seen = ? WHERE phone_number = ?", (now, clean_phone))
            conn.commit()

    def is_valid_user(self, phone_number: str) -> bool:
        try:
            clean_phone = validate_phone_number(phone_number)
        except ValueError:
            return False
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM users WHERE phone_number = ?", (clean_phone,))
            return cursor.fetchone() is not None

    def get_user(self, phone_number: str) -> Optional[Dict[str, Any]]:
        clean_phone = validate_phone_number(phone_number)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT phone_number, username, public_key, is_online, last_seen FROM users WHERE phone_number = ?", (clean_phone,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def store_offline_message(self, sender_id: str, receiver_id: str, raw_packet: bytes):
        clean_sender = validate_phone_number(sender_id)
        clean_receiver = validate_phone_number(receiver_id)
        now = time.time()
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO offline_messages (sender_id, receiver_id, raw_packet, created_at)
                VALUES (?, ?, ?, ?)
            """, (clean_sender, clean_receiver, raw_packet, now))
            conn.commit()

    def fetch_and_clear_offline_messages(self, receiver_id: str) -> List[bytes]:
        clean_receiver = validate_phone_number(receiver_id)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, raw_packet FROM offline_messages 
                WHERE receiver_id = ? 
                ORDER BY id ASC
            """, (clean_receiver,))
            rows = cursor.fetchall()
            if not rows:
                return []

            ids = [row["id"] for row in rows]
            packets = [row["raw_packet"] for row in rows]

            cursor.execute(f"DELETE FROM offline_messages WHERE id IN ({','.join(['?']*len(ids))})", ids)
            conn.commit()
            return packets

    def log_encrypted_message(
        self,
        sender_phone: str,
        sender_name: str,
        receiver_phone: str,
        receiver_name: str,
        content_type: str,
        encryption_key: str,
        ciphertext_hex: str,
        payload_size_bytes: int,
    ):
        """Stores the encrypted message in the database along with sender/receiver phone and name."""
        clean_sender = validate_phone_number(sender_phone)
        clean_receiver = validate_phone_number(receiver_phone)
        now = time.time()
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO encrypted_messages (
                    sender_phone, sender_name, receiver_phone, receiver_name,
                    content_type, encryption_key, ciphertext_hex, payload_size_bytes, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                clean_sender, sender_name, clean_receiver, receiver_name,
                content_type, encryption_key, ciphertext_hex, payload_size_bytes, now
            ))
            conn.commit()

    def get_logged_encrypted_messages(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves stored encrypted messages from the database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM encrypted_messages ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]
