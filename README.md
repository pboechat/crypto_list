# crypto_list

<img src="https://github.com/pboechat/crypto_list/blob/master/crypto_list/images/logo.png" alt="crypto_list" height="128px"></img>

A straight-forward secret manager with an easy-to-use Tkinter UI.

## Highlights (new vs legacy)

- Single encrypted file now embeds the salt (no separate *.salt management).
- JSON-based storage inside encryption (replaces pickle for safety).
- Backward compatible reading of old files (legacy files + external salt). When you save them they are migrated automatically to the new format.
- Faster everyday workflow: toolbar buttons, inline search, instant filtering, auto-saving of modified entries on focus change.
- Change master password from the UI (generates a new salt upon save).

## Requirements

- Python 3.9+ (earlier may work but is untested)
- Standard library Tkinter (usually included with Python; install system package if missing)
- cryptography (see pyproject.toml)

## Installation

Clone the repo and install:

```bash
pip install .
```

Or run in editable/development mode:

```bash
pip install -e .
```

## Running

```bash
crypto-list
```

## Usage Overview

1. New: Click "New" (or Ctrl+N) to start a list.
2. Add: Click "Add" to create a new empty entry, then fill Key/Value.
3. Save: Click "Save" (or Ctrl+S). You'll be asked to create & confirm a password the first time. A single `.crypto_list` file is written (salt embedded).
4. Open: Click "Open" (or Ctrl+O) and provide the password. Legacy files (pre v2) will still prompt you to choose the original salt file once.
5. Edit/Rename: Select an entry, change fields, focus elsewhere or click "Save Entry" to persist.
6. Filter: Type in the Search box to instantly filter keys.
7. Copy: Select an entry and press "Copy" to put its value on the clipboard.
8. Change Password: Use the toolbar button—file is re-encrypted with new salt.

Unsaved changes trigger a confirmation dialog if you attempt to close or open another file.

## File Format (v2)

```
MAGIC 5 bytes:  'CLST1'
SALT  16 bytes:  random per file
TOKEN Fernet:    encryption of JSON {"version":1, "entries":{...}}
```

Salt is not secret; embedding eliminates user error. Password derivation uses PBKDF2-HMAC-SHA256 with 200k iterations.

## Legacy Support

If the file does not start with the magic header it is treated as legacy. The app will ask for the legacy salt file; after a successful save the file migrates to the new format automatically.

## Security Notes

- Your master password is never stored. If you forget it *there is no recovery*.
- Clipboard operations may leave sensitive data accessible to other processes—clear clipboard manually if required.
- Consider using a strong password (lengthy passphrase). Longer is better.

## Disclaimer

Software is provided "AS IS" without warranty of any kind. Use at your own risk.

