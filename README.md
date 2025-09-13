# crypto_list

<img src="https://github.com/pboechat/crypto_list/blob/master/crypto_list/images/logo.png" alt="crypto_list" height="128px"></img>

A straight-forward, file-based secret manager with easy-to-use Tkinter and web interfaces. It keeps your data in a single encrypted file that you control and sync or back up as you like!

## Cryptography overview

- Format (v2): MAGIC `CLST1` + 16-byte random salt + Fernet token (base64url ASCII) containing a JSON payload `{ "version": 1, "entries": { ... } }`.
- Key derivation: PBKDF2-HMAC-SHA256 with 200,000 iterations derives a 32-byte key from your password and the per-file salt. Fernet splits this into two 16-byte keys: one for AES-CBC encryption and one for HMAC-SHA256 authentication.
- Integrity and authenticity: Fernet authenticates the ciphertext (and header fields) with HMAC-SHA256, so any tampering is detected before decryption.
- Embedded salt: The salt is not secret and is stored in the file header to avoid separate ".salt" file handling and reduce user error.
- Legacy compatibility: Pre-v2 files are PBKDF2-HMAC-SHA256 at 100,000 iterations with an external `.salt`, and the payload is typically a Python pickle. They can still be opened; on save they are migrated to v2 (JSON payload + embedded salt).

Security notes and safety features:
- Your master password is never stored or transmitted. It is also non-recoverable (meaning: less changes of being hacked!).
- Authenticated encryption prevents silent corruption or tampering.
- JSON payload in v2 avoids the risks of deserializing arbitrary pickles.
- Desktop app: Secrets are decrypted only in memory. Clipboard operations may expose data to other processes—clear your clipboard as needed.
- Web app: All crypto is performed locally in your browser using WebCrypto; the server never receives your password, entries, or files. "Save" triggers a local file download; nothing is uploaded.

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

### Running the web app

You can run a local FastAPI server that serves a single-page web client. All encryption/decryption happens in your browser; the server only serves static files.

```bash
crypto-list-webapp
```

Then open http://127.0.0.1:8000/

In VS Code, there’s also a launch config named "Run Crypto List (Web)" that starts the server with auto-reload.

### Docker

A ready-to-run Dockerfile is included. It builds an Ubuntu-based image, installs Python (and Tkinter), installs this package, and serves the web app with uvicorn. All encryption still happens in the browser—no secrets or files leave your machine.

Build the image:

```bash
docker build -t crypto-list-web .
```

Run the container and open the app:

```bash
docker run --rm -p 8000:8000 crypto-list-web
# Then visit http://127.0.0.1:8000/
```

The web app supports both v2 and legacy files. For legacy files, you’ll be prompted for the matching `.salt` file—everything stays local in your browser.

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

The web app also supports opening legacy files: when you open a legacy `.crypto_list`, it will prompt you to select the matching `.salt` file. On save, it migrates to v2 and offers the new file as a download.

## Security Notes

- Your master password is never stored. If you forget it *there is no recovery*.
- Clipboard operations may leave sensitive data accessible to other processes—clear clipboard manually if required.
- Consider using a strong password (lengthy passphrase). Longer is better.

## Disclaimer

Software is provided "AS IS" without warranty of any kind. Use at your own risk.

