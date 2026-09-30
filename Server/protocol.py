"""
Protocol implementation for TCP Byte Stream based on the Application Header specification:
-----------------------------------------------------------------------------------------
| 2-byte size | JSON Header                                                   | Content  |
| (Big Endian)| - byteorder (big/little endian)                               | (Payload)|
|             | - senderID (phone number)                                     |          |
|             | - receiverID (phone number)                                   |          |
|             | - content-type (connect / send message / file / status)       |          |
|             | - content-encoding (utf-8 / binary)                           |          |
|             | - encryption key (hex / base64 or string key)                  |          |
|             | - content-length (integer length of payload)                  |          |
-----------------------------------------------------------------------------------------
"""

import io
import json
import struct
import sys
from typing import Dict, Any, Tuple, Optional, Generator

HEADER_SIZE_LEN = 2  # 2-byte unsigned short (>H)


def create_packet(
    sender_id: str,
    receiver_id: str,
    content_type: str,
    payload: bytes,
    content_encoding: str = "utf-8",
    encryption_key: str = "",
) -> bytes:
    """
    Creates a full TCP byte stream packet:
    [2-byte JSON header size][JSON header bytes][Payload content bytes]
    """
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")

    json_header: Dict[str, Any] = {
        "byteorder": sys.byteorder,
        "senderID": str(sender_id),
        "receiverID": str(receiver_id),
        "content-type": content_type,
        "content-encoding": content_encoding,
        "encryption key": encryption_key,
        "content-length": len(payload),
    }

    # Encode JSON header to UTF-8
    json_header_bytes = json.dumps(json_header, ensure_ascii=False).encode("utf-8")
    header_len = len(json_header_bytes)

    if header_len > 65535:
        raise ValueError(f"JSON header exceeds maximum 2-byte length (65535 bytes): {header_len}")

    # Pack 2-byte big-endian size
    size_prefix = struct.pack(">H", header_len)

    return size_prefix + json_header_bytes + payload


class StreamParser:
    """
    Streaming buffer parser for TCP streams that incrementally collects bytes
    and yields complete (header_dict, payload_bytes) tuples.
    Handles TCP segmentation, chunking, and multiple packets arriving together.
    """

    def __init__(self):
        self._recv_buffer = bytearray()
        self._expected_header_len: Optional[int] = None
        self._current_header: Optional[Dict[str, Any]] = None

    def feed(self, data: bytes) -> Generator[Tuple[Dict[str, Any], bytes], None, None]:
        """
        Feeds incoming bytes into the parser buffer and yields parsed packets.
        """
        if data:
            self._recv_buffer.extend(data)

        while True:
            # 1. Read 2-byte header size
            if self._expected_header_len is None:
                if len(self._recv_buffer) >= HEADER_SIZE_LEN:
                    self._expected_header_len = struct.unpack(">H", self._recv_buffer[:HEADER_SIZE_LEN])[0]
                    del self._recv_buffer[:HEADER_SIZE_LEN]
                else:
                    break

            # 2. Read JSON header
            if self._expected_header_len is not None and self._current_header is None:
                if len(self._recv_buffer) >= self._expected_header_len:
                    header_bytes = self._recv_buffer[:self._expected_header_len]
                    del self._recv_buffer[:self._expected_header_len]

                    header_text = header_bytes.decode("utf-8")
                    self._current_header = json.loads(header_text)
                    self._validate_header(self._current_header)
                else:
                    break

            # 3. Read Content (payload)
            if self._current_header is not None:
                content_len = self._current_header.get("content-length", 0)
                if len(self._recv_buffer) >= content_len:
                    payload = bytes(self._recv_buffer[:content_len])
                    del self._recv_buffer[:content_len]

                    completed_header = self._current_header
                    # Reset parser state for the next packet
                    self._expected_header_len = None
                    self._current_header = None

                    yield (completed_header, payload)
                else:
                    break

    @staticmethod
    def _validate_header(header: Dict[str, Any]):
        required_fields = (
            "byteorder",
            "senderID",
            "receiverID",
            "content-type",
            "content-encoding",
            "content-length",
        )
        for field in required_fields:
            if field not in header:
                raise ValueError(f"Malformed packet: Missing required header field '{field}'")
