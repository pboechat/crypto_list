from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Optional


def _center_window(win: tk.Toplevel, parent: tk.Misc) -> None:
    win.update_idletasks()
    try:
        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
    except Exception:
        px = py = 100
        pw = ph = 400
    ww = win.winfo_width()
    wh = win.winfo_height()
    x = px + max(0, (pw - ww) // 2)
    y = py + max(0, (ph - wh) // 2)
    win.geometry(f"+{x}+{y}")


class BaseDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, title: str):
        super().__init__(parent)
        self.withdraw()  # show after layout
        self.transient(parent)
        self.title(title)
        self.resizable(False, False)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.bind("<Escape>", lambda e: self._on_cancel())
        # Set toplevel background to match theme frame background
        try:
            bg = ttk.Style().lookup("TFrame", "background") or "#1e1e1e"
            self.configure(background=bg)
        except Exception:
            pass

    def _on_cancel(self) -> None:
        self.result = None
        self.destroy()


class MessageDialog(BaseDialog):
    def __init__(self, parent: tk.Misc, title: str, message: str, buttons: list[tuple[str, str]], default: Optional[str] = None):
        super().__init__(parent, title)
        container = ttk.Frame(self)
        container.pack(fill=tk.BOTH, expand=True, padx=16, pady=12)

        lbl = ttk.Label(container, text=message, anchor="w",
                        justify="left", wraplength=420)
        lbl.pack(fill=tk.X, expand=True)

        btn_row = ttk.Frame(container)
        btn_row.pack(fill=tk.X, pady=(12, 0))

        self.result = None

        def on_click(val: str):
            self.result = val
            self.destroy()

        for text, val in buttons:
            b = ttk.Button(btn_row, text=text,
                           command=lambda v=val: on_click(v))
            b.pack(side=tk.RIGHT, padx=4)
            if default is not None and val == default:
                self.bind("<Return>", lambda e, v=val: on_click(v))
                b.focus_set()

        self.deiconify()
        _center_window(self, parent)


def askyesno(parent: tk.Misc, title: str, message: str) -> bool:
    dlg = MessageDialog(parent, title, message, buttons=[
                        ["No", "no"], ["Yes", "yes"]], default="yes")
    parent.wait_window(dlg)
    return dlg.result == "yes"


def showinfo(parent: tk.Misc, title: str, message: str) -> None:
    dlg = MessageDialog(parent, title, message, buttons=[
                        ["OK", "ok"]], default="ok")
    parent.wait_window(dlg)


def showerror(parent: tk.Misc, title: str, message: str) -> None:
    # Same look as info; could be styled differently if desired
    dlg = MessageDialog(parent, title, message, buttons=[
                        ["OK", "ok"]], default="ok")
    parent.wait_window(dlg)


class AskStringDialog(BaseDialog):
    def __init__(self, parent: tk.Misc, title: str, prompt: str, show: Optional[str] = None, initialvalue: str = ""):
        super().__init__(parent, title)
        self.value: Optional[str] = None

        container = ttk.Frame(self)
        container.pack(fill=tk.BOTH, expand=True, padx=16, pady=12)

        ttk.Label(container, text=prompt, anchor="w",
                  justify="left").pack(fill=tk.X)

        self._var = tk.StringVar(value=initialvalue)
        entry = ttk.Entry(container, textvariable=self._var, show=show)
        entry.pack(fill=tk.X, pady=(6, 0))
        entry.icursor(tk.END)
        entry.focus_set()

        btn_row = ttk.Frame(container)
        btn_row.pack(fill=tk.X, pady=(12, 0))

        def ok():
            self.value = self._var.get()
            self.destroy()

        def cancel():
            self.value = None
            self.destroy()

        ttk.Button(btn_row, text="Cancel", command=cancel).pack(
            side=tk.RIGHT, padx=4)
        ttk.Button(btn_row, text="OK", command=ok).pack(side=tk.RIGHT, padx=4)

        self.bind("<Return>", lambda e: ok())
        self.bind("<Escape>", lambda e: cancel())

        self.deiconify()
        _center_window(self, parent)


def askstring(parent: tk.Misc, title: str, prompt: str, show: Optional[str] = None, initialvalue: str = "") -> Optional[str]:
    dlg = AskStringDialog(parent, title, prompt,
                          show=show, initialvalue=initialvalue)
    parent.wait_window(dlg)
    return dlg.value
