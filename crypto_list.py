from os import urandom
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tkinter import *
from tkinter.filedialog import askopenfilename, asksaveasfilename
from tkinter.simpledialog import askstring
from tkinter.messagebox import showerror, askquestion, WARNING, YES
from base64 import urlsafe_b64encode
from pickle import *


class Application(Frame):
    def __init__(self, master=None):
        super().__init__(master=master)
        self.master.title('Crypto List')
        self.pack(fill=BOTH, expand=YES)
        self._create_widgets()
        self._entries = {}

    def _new_list(self, event=None):
        self._entries = {}
        self._entries_list.delete(0, END)
        self._key_entry.delete(0, END)
        self._value_entry.delete('1.0', END)

    def _open_list(self, event=None):
        filename = askopenfilename(parent=self.master, filetypes=[('CRYPTO_LIST', '*.crypto_list')])
        if not filename:
            return
        with open(filename, 'rb') as crypto_list_file:
            crypto_list_content = crypto_list_file.read()
        fernet = Fernet(self._get_master_key())
        try:
            self._entries = loads(fernet.decrypt(crypto_list_content))
        except InvalidToken:
            showerror('Error', 'Invalid master key')
        self._update_entries_list()

    def _update_entries_list(self):
        self._entries_list.delete(0, END)
        for key in self._entries.keys():
            self._entries_list.insert(END, key)

    def _get_salt(self):
        if askquestion('Salt', 'Load salt?', icon=WARNING) == YES:
            filename = ''
            while not filename:
                filename = askopenfilename(parent=self.master, filetypes=[('SALT', '*.salt')])
            with open(filename, 'rb') as salt_file:
                salt = salt_file.read()
        else:
            salt = urandom(16)
            filename = ''
            while not filename:
                filename = asksaveasfilename(parent=self.master, filetypes=[('SALT', '*.salt')])
            with open(filename, 'wb') as salt_file:
                salt_file.write(salt)
        return salt

    def _get_master_key(self):
        salt = self._get_salt()
        master_key = bytes(askstring('Master Key', 'Master Key', parent=self, show="*"), 'utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend())
        return urlsafe_b64encode(kdf.derive(master_key))

    def _save_list(self, event=None):
        filename = asksaveasfilename(parent=self.master, filetypes=[('CRYPTO_LIST', '*.crypto_list')])
        if not filename:
            return
        fernet = Fernet(self._get_master_key())
        crypto_list_content = fernet.encrypt(dumps(self._entries))
        with open(filename, 'wb') as crypto_list_file:
            crypto_list_file.write(crypto_list_content)

    def _select_entry(self, key):
        idx = self._get_entry_index(key)
        if idx < 0:
            return
        self._entries_list.select_set(idx)
        self._on_entry_select()

    def _add_entry(self, event=None):
        key = askstring('Add Entry', 'Key', parent=self)
        if not key:
            return
        value = askstring('Add Entry', 'Value', parent=self)
        if not value:
            return
        self._entries[key] = value
        self._update_entries_list()
        self._select_entry(key)

    def _get_current_entry_idx(self):
        selection = self._entries_list.curselection()
        if len(selection) == 0:
            return -1
        else:
            return selection[0]

    def _get_current_entry(self):
        idx = self._get_current_entry_idx()
        if idx < 0:
            return None
        else:
            return self._entries_list.get(idx)

    def _get_entry_index(self, key):
        return self._entries_list.get(0, END).index(key)

    def _save_entry(self, event=None):
        key = self._key_entry.get()
        old_key = self._get_current_entry()
        if old_key is not None:
            del self._entries[old_key]
        value = self._value_entry.get('1.0', END)
        self._entries[key] = value
        self._update_entries_list()
        self._entries_list.select_set(self._get_entry_index(key))

    def _delete_entry(self, event=None):
        key = self._get_current_entry()
        if key is None:
            return
        if askquestion('Delete Entry', 'Are you sure?', icon=WARNING) == YES:
            del self._entries[key]
            self._update_entries_list()

    def _new_entry(self, event=None):
        self._entries_list.selection_clear(0, END)
        self._key_entry.delete(0, END)
        self._value_entry.delete('1.0', END)

    def _find_entry(self, event=None):
        key = askstring('Find', 'Key', parent=self)
        if not key:
            return
        entries = self._entries_list.get(0, END)
        idx = -1
        for i, entry in enumerate(entries):
            if key in entry:
                idx = i
                break
        if idx < 0:
            return
        self._entries_list.selection_clear(0, END)
        self._entries_list.select_set(idx)
        self._on_entry_select()

    def _on_entry_select(self, event=None):
        key = self._get_current_entry()
        if key is None:
            return
        self._key_entry.delete(0, END)
        self._key_entry.insert(END, key)
        value = self._entries[key]
        self._value_entry.delete('1.0', END)
        self._value_entry.insert(END, value)

    def _create_widgets(self):
        menu_bar = Menu(self.master)

        list_menu = Menu(menu_bar, tearoff=0)
        list_menu.add_command(label='New', command=self._new_list)
        list_menu.add_command(label='Open', command=self._open_list)
        list_menu.add_command(label='Save', command=self._save_list)
        list_menu.add_separator()
        list_menu.add_command(label='Exit', command=self.master.quit)

        entry_menu = Menu(menu_bar, tearoff=0)
        entry_menu.add_command(label='Find', command=self._find_entry)
        entry_menu.add_separator()
        entry_menu.add_command(label='Add', command=self._add_entry)
        entry_menu.add_command(label='Save', command=self._save_entry)
        entry_menu.add_command(label='Delete', command=self._delete_entry)

        menu_bar.add_cascade(label='List', menu=list_menu)
        menu_bar.add_cascade(label='Entry', menu=entry_menu)
        self.master.config(menu=menu_bar)

        left_frame = Frame(master=self)
        left_frame.pack(side=LEFT, fill=BOTH, expand=YES)
        left_frame.grid_propagate(False)
        left_frame.grid_rowconfigure(0, weight=1)
        left_frame.grid_columnconfigure(0, weight=1)

        self._entries_list = Listbox(left_frame, borderwidth=3, relief='sunken')
        self._entries_list.pack(fill=BOTH, expand=YES)

        scroll_bar = Scrollbar(left_frame, command=self._entries_list.yview)
        scroll_bar.grid(row=0, column=1, sticky='nsew')

        self._entries_list.configure(yscrollcommand=scroll_bar.set)
        self._entries_list.bind('<<ListboxSelect>>', self._on_entry_select)

        right_frame = Frame(master=self)
        right_frame.pack(side=RIGHT, fill=BOTH, expand=YES)

        key_label = Label(right_frame, text='Key')
        key_label.pack(anchor=W)

        self._key_entry = Entry(right_frame)
        self._key_entry.pack(fill=X)

        value_label = Label(right_frame, text='Value')
        value_label.pack(anchor=W)

        self._value_entry = Text(right_frame, borderwidth=3, relief='sunken')
        self._value_entry.pack(fill=BOTH, expand=YES)

        save_entry_button = Button(right_frame, text='Save', command=self._save_entry)
        save_entry_button.pack(anchor=SW, side=RIGHT)
        delete_entry_button = Button(right_frame, text='Delete', command=self._delete_entry)
        delete_entry_button.pack(anchor=SW, side=RIGHT)
        new_entry_button = Button(right_frame, text='New', command=self._new_entry)
        new_entry_button.pack(anchor=SW, side=RIGHT)

        self.master.bind('<Control-n>', self._new_list)
        self.master.bind('<Control-o>', self._open_list)
        self.master.bind('<Control-s>', self._save_list)
        self.master.bind('<Control-w>', lambda event: self.master.quit())
        self.master.bind('<Control-a>', self._add_entry)
        self.master.bind('<Control-f>', self._find_entry)


if __name__ == '__main__':
    root = Tk()
    app = Application(master=root)
    app.mainloop()
