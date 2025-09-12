"""Storage and encryption utilities for Crypto List.

File format (v1):

    MAGIC(5 bytes) = b'CLST1'
    SALT(16 bytes)
    FERNET_TOKEN (base64 urlsafe bytes produced by cryptography.Fernet)

The salt is stored inside the file (improving usability). Master password is
never stored. Old format compatibility: if the file does not start with MAGIC
it's treated as legacy (whole file is the Fernet token) and the user will be
asked for a separate salt file as previously. Saving re-writes in the new
format.
"""
from __future__ import annotations

import json
from base64 import urlsafe_b64encode
from dataclasses import dataclass
from os import urandom
from pathlib import Path
from typing import Callable, Dict, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"CLST1"
SALT_LEN = 16
ITERATIONS = 200_000  # Current format iterations
LEGACY_ITERATIONS = 100_000  # Legacy original iteration count


class DecryptionError(Exception):
    """Raised when decryption fails (wrong password or corrupt file)."""


@dataclass
class LoadedData:
    entries: Dict[str, str]
    salt: bytes
    legacy: bool


def derive_key(password: str, salt: bytes, *, iterations: int = ITERATIONS) -> bytes:
    if not password:
        raise ValueError("Password must not be empty")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_entries(entries: Dict[str, str], password: str, salt: Optional[bytes] = None) -> bytes:
    if salt is None:
        salt = urandom(SALT_LEN)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    payload = json.dumps({"version": 1, "entries": entries}).encode("utf-8")
    token = fernet.encrypt(payload)
    return MAGIC + salt + token


def decrypt_file(data: bytes, password: str, get_legacy_salt: Callable[[], bytes]) -> LoadedData:
    # New format
    if data.startswith(MAGIC):
        salt = data[len(MAGIC): len(MAGIC) + SALT_LEN]
        token = data[len(MAGIC) + SALT_LEN:]
        key = derive_key(password, salt, iterations=ITERATIONS)
        fernet = Fernet(key)
        try:
            decrypted = fernet.decrypt(token)
        except InvalidToken as ex:  # Wrong password or corruption
            raise DecryptionError("Incorrect password or corrupt file") from ex
        try:
            obj = json.loads(decrypted.decode("utf-8"))
        except json.JSONDecodeError as ex:
            raise DecryptionError("Decrypted content not valid JSON") from ex
        entries = obj.get("entries", {})
        if not isinstance(entries, dict):
            raise DecryptionError("Entries content invalid")
        # Coerce to str->str
        entries = {str(k): str(v) for k, v in entries.items()}
        return LoadedData(entries=entries, salt=salt, legacy=False)

    # Legacy format (pickle + external salt). Basic heuristic: if file seems too small it may be a salt file.
    if len(data) < 60:  # Fernet tokens (even for empty dict) are larger than this.
        raise DecryptionError(
            "File is too small to be a valid encrypted list. Did you select a .salt file instead of the .crypto_list?"
        )
    salt = get_legacy_salt()
    key = derive_key(password, salt, iterations=LEGACY_ITERATIONS)
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(data)
    except InvalidToken as ex:
        raise DecryptionError(
            "Incorrect password, salt, or corrupt legacy file (or mismatched salt file)."
        ) from ex
    # Use pickle inside a restricted namespace risk; safer to block but we maintain compat.
    import pickle  # local import to highlight restricted scope
    try:
        entries = pickle.loads(decrypted)
    except Exception as ex:  # noqa: BLE001 broad for legacy compat
        raise DecryptionError("Legacy file content invalid") from ex
    if not isinstance(entries, dict):
        raise DecryptionError("Legacy entries not a mapping")
    entries = {str(k): str(v) for k, v in entries.items()}
    return LoadedData(entries=entries, salt=salt, legacy=True)


def load_file(path: Path, password: str, get_legacy_salt: Callable[[], bytes]) -> LoadedData:
    data = path.read_bytes()
    return decrypt_file(data, password, get_legacy_salt)


def save_file(path: Path, entries: Dict[str, str], password: str, existing_salt: Optional[bytes]) -> None:
    # existing_salt only used if the file was previously opened (keep same salt).
    data = encrypt_entries(entries, password, salt=existing_salt)
    path.write_bytes(data)
