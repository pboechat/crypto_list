"""Crypto List password manager package.

This version (2.x) introduces a new encrypted file format that embeds the salt
directly into the encrypted file and replaces the previous pickle-based
serialization with JSON for safety. The application keeps backward
compatibility for reading the old format (*.crypto_list paired with an external
*.salt file). Once an old-format file is saved again, it is migrated to the new
format automatically.
"""

__all__ = [
    "main",
]

from .app import main  # noqa: E402
