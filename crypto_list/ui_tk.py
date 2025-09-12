from __future__ import annotations

import os
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Dict, List, Optional

from crypto_list.storage import DecryptionError, load_file, save_file

from .dialogs import askstring, askyesno, showerror, showinfo


class CryptoListApp(ttk.Frame):
    def __init__(self, master: tk.Misc):  # master is root window
        super().__init__(master)
        self.master.title("crypto_list")
        self.pack(fill=tk.BOTH, expand=True)

        # State
        self._entries: Dict[str, str] = {}
        self._filtered_keys: List[str] = []
        self._current_file: Optional[Path] = None
        self._current_password: Optional[str] = None
        self._current_salt: Optional[bytes] = None  # For new format persists
        self._legacy_file: bool = False
        self._dirty: bool = False

        self._build_ui()
        self._refresh_list()

    def _build_ui(self) -> None:
        self.master.protocol("WM_DELETE_WINDOW", self._on_close)
        self.master.bind("<Control-s>", lambda e: self.save_file())
        self.master.bind("<Control-o>", lambda e: self.open_file())
        self.master.bind("<Control-n>", lambda e: self.new_file())
        self.master.bind(
            "<Control-f>", lambda e: self._search_entry.focus_set())
        self.master.bind("<Control-q>", lambda e: self._on_close())

        # Create and use a custom dark theme (default)
        style = ttk.Style()
        bg = "#1e1e1e"
        surface = "#252526"
        fg = "#e6e6e6"
        border = "#3c3c3c"
        accent = "#569cd6"
        entry_bg = "#2d2d30"
        select_bg = "#094771"
        select_fg = "#ffffff"

        if "cryptodark" not in style.theme_names():
            style.theme_create(
                "cryptodark",
                parent="clam",
                settings={
                    "TFrame": {"configure": {"background": bg}},
                    "Toolbar.TFrame": {"configure": {"background": surface}},
                    "TLabel": {"configure": {"background": bg, "foreground": fg}},
                    "Status.TLabel": {
                        "configure": {
                            "background": surface,
                            "foreground": fg,
                            "relief": "sunken",
                            "padding": (6, 3),
                        }
                    },
                    "TButton": {
                        "configure": {
                            "background": "#333333",
                            "foreground": fg,
                            "bordercolor": border,
                            "focuscolor": border,
                            "padding": (6, 4),
                        },
                        "map": {
                            "background": [("active", "#3a3a3a")],
                            "foreground": [("disabled", "#888888")],
                        },
                    },
                    "TEntry": {
                        "configure": {
                            "fieldbackground": entry_bg,
                            "foreground": fg,
                            "insertcolor": fg,
                            "bordercolor": border,
                            "lightcolor": border,
                            "darkcolor": border,
                        }
                    },
                    "TPanedwindow": {"configure": {"background": bg}},
                    "TScrollbar": {"configure": {"background": bg, "troughcolor": surface}},
                },
            )
        style.theme_use("cryptodark")

        # Toolbar
        toolbar = ttk.Frame(self, style="Toolbar.TFrame")
        toolbar.pack(fill=tk.X, padx=4, pady=4)

        # Load toolbar images (.png)
        icons_dir = os.path.join(os.path.dirname(__file__), 'icons')

        def load_ico(name: str):
            path = os.path.join(icons_dir, f"{name}.png")
            try:
                img = tk.PhotoImage(file=path)
            except Exception as e:
                img = None
            return img

        self._img_new = load_ico('new')
        self._img_open = load_ico('open')
        self._img_save = load_ico('save')
        self._img_add = load_ico('add')
        self._img_delete = load_ico('delete')
        self._img_copy = load_ico('copy')
        self._img_pw = load_ico('change_password')

        def add_btn(text: str, cmd, tooltip: str, img):
            b = ttk.Button(
                toolbar,
                image=img,
                text=text if img is None else '',
                compound=tk.LEFT,
                command=cmd,
            )
            b._icon_ref = img  # type: ignore[attr-defined]
            b.pack(side=tk.LEFT, padx=2)
            b.bind("<Enter>", lambda e, t=tooltip: self._set_status(t))
            b.bind("<Leave>", lambda e: self._set_status())
            return b

        add_btn("New", self.new_file,
                "Create a new password list", self._img_new)
        add_btn("Open", self.open_file,
                "Open an encrypted list (*.crypto_list)", self._img_open)
        add_btn("Save", self.save_file, "Save current list", self._img_save)
        add_btn("Add", self.add_entry, "Add a new entry", self._img_add)
        add_btn("Delete", self.delete_entry,
                "Delete selected entry", self._img_delete)
        add_btn("Copy", self.copy_value,
                "Copy value to clipboard", self._img_copy)
        add_btn("Change PW", self.change_password,
                "Change master password", self._img_pw)

        # Main Paned layout
        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Left - search & list
        left = ttk.Frame(paned)
        paned.add(left, weight=1)

        search_frame = ttk.Frame(left)
        search_frame.pack(fill=tk.X, padx=4, pady=(4, 0))
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._refresh_list())
        self._search_entry = ttk.Entry(
            search_frame, textvariable=self._search_var)
        self._search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        clear_btn = ttk.Button(
            search_frame, text="×", width=3, command=lambda: self._search_var.set(""))
        clear_btn.pack(side=tk.LEFT)

        list_frame = ttk.Frame(left)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self._listbox = tk.Listbox(list_frame, activestyle="dotbox")
        self._listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(
            list_frame, orient=tk.VERTICAL, command=self._listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self._listbox.configure(yscrollcommand=scrollbar.set)
        self._listbox.bind("<<ListboxSelect>>", lambda e: self._on_select())

        # Right - details
        right = ttk.Frame(paned)
        paned.add(right, weight=3)

        form = ttk.Frame(right)
        form.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        ttk.Label(form, text="Key:").grid(row=0, column=0, sticky="w")
        self._key_var = tk.StringVar()
        self._key_entry = ttk.Entry(form, textvariable=self._key_var)
        self._key_entry.grid(row=1, column=0, sticky="ew")
        self._key_entry.bind("<FocusOut>", lambda e: self._autosave())

        ttk.Label(form, text="Value:").grid(
            row=2, column=0, sticky="w", pady=(8, 0))
        self._value = tk.Text(form, height=12, wrap="word")
        self._value.grid(row=3, column=0, sticky="nsew")
        self._value.bind("<KeyRelease>", lambda e: self._mark_dirty())
        self._value.bind("<FocusOut>", lambda e: self._autosave())

        btn_frame = ttk.Frame(form)
        btn_frame.grid(row=4, column=0, sticky="e", pady=(8, 0))
        ttk.Button(btn_frame, text="Save Entry",
                   command=self.save_entry).pack(side=tk.RIGHT, padx=2)
        ttk.Button(btn_frame, text="New Entry",
                   command=self.new_entry).pack(side=tk.RIGHT, padx=2)

        form.columnconfigure(0, weight=1)
        form.rowconfigure(3, weight=1)

        # Status bar
        self._status_var = tk.StringVar()
        status = ttk.Label(self, textvariable=self._status_var,
                           anchor="w", style="Status.TLabel")
        status.pack(fill=tk.X, side=tk.BOTTOM)
        self._set_status("Ready")

        # Apply dark colors to non-ttk widgets
        self._apply_dark_to_native(bg, fg, select_bg, select_fg, entry_bg)

    def _apply_dark_to_native(self, bg: str, fg: str, select_bg: str, select_fg: str, entry_bg: str) -> None:
        # Listbox styling
        try:
            self._listbox.configure(
                background=bg,
                foreground=fg,
                selectbackground=select_bg,
                selectforeground=select_fg,
                highlightthickness=0,
                bd=0,
                relief=tk.FLAT,
            )
        except Exception:
            pass
        # Text widget styling
        try:
            self._value.configure(
                background=entry_bg,
                foreground=fg,
                insertbackground=fg,
                selectbackground=select_bg,
                selectforeground=select_fg,
                highlightthickness=1,
                highlightbackground="#2a2a2a",
                bd=0,
                relief=tk.FLAT,
            )
        except Exception:
            pass

    def _set_status(self, text: str | None = None) -> None:
        if text is None:
            if self._current_file:
                mode = "LEGACY" if self._legacy_file else "v1"
                text = f"{self._current_file} ({mode})"
            else:
                text = "No file"
        self._status_var.set(text)

    def _confirm_discard(self) -> bool:
        if not self._dirty:
            return True
        return askyesno(self, "Unsaved Changes", "Discard unsaved changes?")

    def _refresh_list(self) -> None:
        needle = self._search_var.get().lower().strip()
        keys = sorted(self._entries.keys())
        if needle:
            keys = [k for k in keys if needle in k.lower()]
        self._filtered_keys = keys
        self._listbox.delete(0, tk.END)
        for k in keys:
            self._listbox.insert(tk.END, k)

    def _current_selected_key(self) -> Optional[str]:
        sel = self._listbox.curselection()
        if not sel:
            return None
        idx = sel[0]
        if idx >= len(self._filtered_keys):
            return None
        return self._filtered_keys[idx]

    def _load_entry_to_form(self, key: Optional[str]) -> None:
        self._key_var.set(key or "")
        self._value.delete("1.0", tk.END)
        if key and key in self._entries:
            self._value.insert(tk.END, self._entries[key])
        self._dirty = False

    def _on_select(self) -> None:
        key = self._current_selected_key()
        self._load_entry_to_form(key)

    def _mark_dirty(self):
        self._dirty = True

    def _autosave(self):
        if self._dirty:
            self.save_entry()

    def new_file(self):
        if not self._confirm_discard():
            return
        self._entries.clear()
        self._current_file = None
        self._current_password = None
        self._current_salt = None
        self._legacy_file = False
        self._load_entry_to_form(None)
        self._refresh_list()
        self._set_status("New list (unsaved)")

    def open_file(self):
        if not self._confirm_discard():
            return
        path_str = filedialog.askopenfilename(parent=self, title="Open list", filetypes=[
            ("Crypto List", "*.crypto_list"), ("All", "*.*")])
        if not path_str:
            return
        path = Path(path_str)
        if path.suffix.lower() == ".salt":
            showerror(self,
                      "Not a list file",
                      "You selected a .salt file. Please choose the encrypted list (*.crypto_list) first.",
                      )
            return
        password = askstring(self, "Master Password",
                             "Enter password", show="*")
        if password is None:
            return

        def legacy_salt_provider():
            salt_path = filedialog.askopenfilename(
                parent=self, title="Legacy salt file", filetypes=[("Salt", "*.salt")])
            if not salt_path:
                raise RuntimeError("Salt required for legacy file")
            return Path(salt_path).read_bytes()

        try:
            loaded = load_file(path, password, legacy_salt_provider)
        except DecryptionError as ex:
            showerror(self, "Decryption Failed", str(ex))
            return
        except Exception as ex:  # noqa: BLE001
            showerror(self, "Error", f"Failed to open: {ex}")
            return
        self._entries = loaded.entries
        self._current_file = path
        self._current_password = password
        self._current_salt = loaded.salt
        self._legacy_file = loaded.legacy
        self._load_entry_to_form(None)
        self._refresh_list()
        self._set_status()

    def save_file(self):
        if self._current_file is None:
            path_str = filedialog.asksaveasfilename(
                parent=self, title="Save list", defaultextension=".crypto_list", filetypes=[("Crypto List", "*.crypto_list")])
            if not path_str:
                return
            self._current_file = Path(path_str)
            if self._current_password is None:
                while True:
                    pw1 = askstring(self, "Set Password",
                                    "Master password", show="*")
                    if pw1 is None:
                        self._current_file = None
                        return
                    pw2 = askstring(self, "Set Password",
                                    "Confirm password", show="*")
                    if pw2 is None:
                        self._current_file = None
                        return
                    if pw1 != pw2:
                        showerror(self, "Mismatch", "Passwords do not match")
                        continue
                    self._current_password = pw1
                    break
        if not self._current_password:
            showerror(self, "Error", "Password not set")
            return
        try:
            save_file(self._current_file, self._entries, self._current_password,
                      existing_salt=None if self._legacy_file else self._current_salt)
        except Exception as ex:  # noqa: BLE001
            showerror(self, "Save Error", str(ex))
            return
        self._legacy_file = False  # After save it's migrated
        self._set_status("Saved")

    def add_entry(self):
        key = askstring(self, "Add Entry", "Key")
        if not key:
            return
        if key in self._entries:
            showerror(self, "Exists", "Key already exists")
            return
        self._entries[key] = ""
        self._refresh_list()
        # Select new entry
        idx = self._filtered_keys.index(key)
        self._listbox.selection_clear(0, tk.END)
        self._listbox.selection_set(idx)
        self._load_entry_to_form(key)

    def delete_entry(self):
        key = self._current_selected_key()
        if not key:
            return
        if not askyesno(self, "Delete", f"Delete entry '{key}'?"):
            return
        del self._entries[key]
        self._refresh_list()
        self._load_entry_to_form(None)

    def copy_value(self):
        key = self._current_selected_key()
        if not key:
            return
        value = self._entries.get(key, "")
        self.clipboard_clear()
        self.clipboard_append(value)
        self._set_status("Copied value to clipboard")

    def save_entry(self):
        key = self._key_var.get().strip()
        if not key:
            return
        value = self._value.get("1.0", tk.END).rstrip("\n")
        sel_key = self._current_selected_key()
        if sel_key and sel_key != key and key in self._entries:
            if not askyesno(self, "Overwrite", f"Key '{key}' exists. Overwrite?"):
                return
        if sel_key and sel_key != key:
            # rename
            del self._entries[sel_key]
        self._entries[key] = value
        self._dirty = False
        self._refresh_list()
        if key in self._filtered_keys:
            idx = self._filtered_keys.index(key)
            self._listbox.selection_clear(0, tk.END)
            self._listbox.selection_set(idx)
        self._set_status("Entry saved")

    def new_entry(self):
        self._listbox.selection_clear(0, tk.END)
        self._load_entry_to_form(None)

    def change_password(self):
        if self._current_file is None:
            showinfo(self, "Change Password", "Save the file first.")
            return
        while True:
            pw1 = askstring(self, "Change Password", "New password", show="*")
            if pw1 is None:
                return
            pw2 = askstring(self, "Change Password",
                            "Confirm new password", show="*")
            if pw2 is None:
                return
            if pw1 != pw2:
                showerror(self, "Mismatch", "Passwords do not match")
                continue
            self._current_password = pw1
            self._current_salt = None  # Will create new salt on save
            self.save_file()
            break

    def _on_close(self):
        if not self._confirm_discard():
            return
        self.master.destroy()


def run_app():
    root = tk.Tk()
    # Set application icon (best-effort, platform dependent)
    try:
        icon_path = os.path.join(os.path.dirname(
            __file__), 'icons', 'crypto_list.png')
        if os.path.exists(icon_path):
            icon_img = tk.PhotoImage(file=icon_path)
            root.iconphoto(True, icon_img)
            root._app_icon_ref = icon_img  # keep ref
    except Exception:
        pass
    root.minsize(720, 480)
    app = CryptoListApp(root)
    app.mainloop()
    app.mainloop()
