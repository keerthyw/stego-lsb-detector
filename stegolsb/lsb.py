"""Least-significant-bit (LSB) steganography: hide bytes in an image and get them back.

Every pixel has a red, green and blue value from 0-255. Changing the last bit of a value
changes it by at most 1, which the eye cannot see, so each colour value can carry one
hidden bit. A 1000x1000 image therefore holds about 375 KB.

Hidden data layout:  MAGIC (4 bytes) | length (4 bytes, big-endian) | payload

Without a password the bits are written in order, starting at the top-left pixel.
With a password they are scattered over the image in a pseudo-random order and XORed
with a keystream, both derived from the password. This is obfuscation for a demo, not
audited encryption: use real encryption (e.g. AES-GCM) for anything sensitive.
"""

from __future__ import annotations

import hashlib
import struct

import numpy as np
from PIL import Image

MAGIC = b"LSB1"
HEADER_LEN = len(MAGIC) + 4


class StegoError(Exception):
    pass


def load_image(path: str) -> np.ndarray:
    """Load as an H x W x 3 (or x 4 with alpha) uint8 array."""
    img = Image.open(path)
    has_alpha = img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info)
    return np.array(img.convert("RGBA" if has_alpha else "RGB"))


def save_image(arr: np.ndarray, path: str) -> None:
    if not path.lower().endswith((".png", ".bmp", ".tif", ".tiff")):
        raise StegoError("Save as PNG (or BMP/TIFF). JPEG compression would destroy the hidden bits.")
    Image.fromarray(arr).save(path)


def capacity(arr: np.ndarray) -> int:
    """How many payload bytes fit in the image."""
    slots = arr.shape[0] * arr.shape[1] * 3
    return max(0, slots // 8 - HEADER_LEN)


def _seed(password: str, purpose: bytes) -> bytes:
    return hashlib.sha256(purpose + password.encode()).digest()


def _positions(n_slots: int, n_bits: int, password: str | None) -> np.ndarray:
    if not password:
        return np.arange(n_bits)
    rng = np.random.default_rng(int.from_bytes(_seed(password, b"order:")[:8], "big"))
    return rng.permutation(n_slots)[:n_bits]


def _keystream(password: str, n: int) -> bytes:
    key, out, counter = _seed(password, b"key:"), bytearray(), 0
    while len(out) < n:
        out += hashlib.sha256(key + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:n])


def _xor(data: bytes, password: str | None) -> bytes:
    if not password:
        return data
    return bytes(a ^ b for a, b in zip(data, _keystream(password, len(data))))


def hide(arr: np.ndarray, payload: bytes, password: str | None = None) -> np.ndarray:
    """Return a copy of `arr` with `payload` hidden in the LSBs of its RGB channels."""
    if len(payload) > capacity(arr):
        raise StegoError(f"Payload is {len(payload)} bytes but the image only holds {capacity(arr)} bytes.")

    out = arr.copy()
    rgb = out[..., :3]                     # never touch the alpha channel
    flat = rgb.reshape(-1).copy()          # R,G,B,R,G,B,... pixel by pixel

    data = _xor(MAGIC + struct.pack(">I", len(payload)) + payload, password)
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    pos = _positions(flat.size, bits.size, password)

    flat[pos] = (flat[pos] & 0xFE) | bits  # clear the last bit, then set it to our bit
    out[..., :3] = flat.reshape(rgb.shape)
    return out


def reveal(arr: np.ndarray, password: str | None = None) -> bytes:
    """Recover the payload hidden by `hide`. Raises StegoError if there is none."""
    flat = arr[..., :3].reshape(-1)
    order = _positions(flat.size, flat.size, password) if password else None

    def read_bytes(start_bit: int, n_bytes: int) -> bytes:
        idx = np.arange(start_bit, start_bit + n_bytes * 8)
        if order is not None:
            idx = order[idx]
        return np.packbits(flat[idx] & 1).tobytes()

    if flat.size < HEADER_LEN * 8:
        raise StegoError("Image is too small to contain hidden data.")
    header = _xor(read_bytes(0, HEADER_LEN), password)
    if header[:4] != MAGIC:
        raise StegoError("No hidden data found" + (" (or the password is wrong)." if password else
                                                   ". If a password was used, pass it with --password."))
    length = struct.unpack(">I", header[4:])[0]
    if length > capacity(arr):
        raise StegoError("Header is corrupt: claimed length is larger than the image can hold.")

    # The keystream for the payload continues where the header's ended, so XOR them together.
    raw = read_bytes(0, HEADER_LEN + length)
    return _xor(raw, password)[HEADER_LEN:]
