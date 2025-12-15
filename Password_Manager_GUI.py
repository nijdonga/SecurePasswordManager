# Password_Manager_GUI.py
import os
import json
import secrets
import string
import base64
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, simpledialog
import pyperclip

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DB_FILE = os.path.join(os.path.dirname(__file__), "passwords.json")
AUTO_LOCK_MS = 2 * 60 * 1000  # 2 minutes

# ---------- Utilities ----------
def generate_salt() -> bytes:
    return os.urandom(16)

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def generate_strong_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"
    return "".join(secrets.choice(alphabet) for _ in range(length))

# ---------- Password Manager ----------
class PasswordManager:
    def __init__(self):
        self.salt = None
        self.fernet = None
        self.passwords = {}

    def setup_master_password(self, master: str):
        self.salt = generate_salt()
        self.fernet = Fernet(derive_key(master, self.salt))
        self.passwords = {}
        self.save_database()

    def load_database(self, master: str):
        if not os.path.exists(DB_FILE):
            self.setup_master_password(master)
            return True
        try:
            with open(DB_FILE) as f:
                raw = json.load(f)
            self.salt = base64.b64decode(raw["salt"])
            self.fernet = Fernet(derive_key(master, self.salt))
            encrypted = base64.b64decode(raw["data"])
            self.passwords = json.loads(self.fernet.decrypt(encrypted).decode())
            return True
        except Exception:
            return False

    def save_database(self):
        encrypted = self.fernet.encrypt(json.dumps(self.passwords).encode())
        data = {
            "salt": base64.b64encode(self.salt).decode(),
            "data": base64.b64encode(encrypted).decode()
        }
        with open(DB_FILE, "w") as f:
            json.dump(data, f)

    def add_or_update_password(self, site, username, password):
        self.passwords[site.lower()] = {"username": username, "password": password}
        self.save_database()

    def delete_password(self, site):
        if site in self.passwords:
            del self.passwords[site]
            self.save_database()
            return True
        return False

    def backup_database(self):
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        backup_file = f"passwords_backup_{ts}.json"
        with open(DB_FILE, "r") as f:
            data = f.read()
        with open(backup_file, "w") as f:
            f.write(data)
        return backup_file

# ---------- GUI ----------
class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.configure(bg="#2b2b2b")

        self.pm = PasswordManager()
        self.last_activity = None
        self.lock_job = None

        self.master_password_dialog()
        self.create_widgets()
        self.refresh_listbox()
        self.reset_auto_lock()

        self.root.bind_all("<Any-KeyPress>", self.reset_auto_lock)
        self.root.bind_all("<Any-Button>", self.reset_auto_lock)

    # ---------- Security ----------
    def reset_auto_lock(self, event=None):
        if self.lock_job:
            self.root.after_cancel(self.lock_job)
        self.lock_job = self.root.after(AUTO_LOCK_MS, self.auto_lock)

    def auto_lock(self):
        messagebox.showwarning("Locked", "Session locked due to inactivity.")
        self.master_password_dialog()

    def master_password_dialog(self):
        while True:
            master = simpledialog.askstring(
                "Master Password",
                "Enter master password:",
                show="*"
            )
            if not master:
                self.root.destroy()
                exit()
            if self.pm.load_database(master):
                messagebox.showinfo("Unlocked", "Database unlocked!")
                break
            else:
                retry = messagebox.askretrycancel("Error", "Wrong password.")
                if not retry:
                    self.root.destroy()
                    exit()

    # ---------- UI ----------
    def create_widgets(self):
        fg = "white"
        bg = "#2b2b2b"

        tk.Label(self.root, text="Search:", fg=fg, bg=bg).grid(row=0, column=0, sticky="w")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.refresh_listbox())
        tk.Entry(self.root, textvariable=self.search_var).grid(row=1, column=0, padx=5, pady=5)

        self.site_listbox = tk.Listbox(self.root, height=12, width=30)
        self.site_listbox.grid(row=2, column=0, rowspan=6, padx=5)
        self.site_listbox.bind("<<ListboxSelect>>", self.load_selected_site)

        tk.Label(self.root, text="Username:", fg=fg, bg=bg).grid(row=2, column=1, sticky="w")
        self.user_entry = tk.Entry(self.root, width=30)
        self.user_entry.grid(row=3, column=1)

        tk.Label(self.root, text="Password:", fg=fg, bg=bg).grid(row=4, column=1, sticky="w")
        self.pwd_entry = tk.Entry(self.root, width=30, show="*")
        self.pwd_entry.grid(row=5, column=1)

        buttons = [
            ("Add / Update", self.add_password),
            ("Delete", self.delete_password),
            ("Copy Password", self.copy_password),
            ("Reveal Password", self.reveal_password),
            ("Generate Password", self.generate_password),
            ("Backup Database", self.backup_database),
        ]

        for i, (text, cmd) in enumerate(buttons):
            tk.Button(self.root, text=text, command=cmd).grid(row=6 + i, column=1, pady=2)

        self.output = tk.Text(self.root, height=8, width=60)
        self.output.grid(row=14, column=0, columnspan=2, pady=10)

    # ---------- Actions ----------
    def refresh_listbox(self):
        query = self.search_var.get().lower()
        self.site_listbox.delete(0, tk.END)
        for site in sorted(self.pm.passwords):
            if query in site:
                self.site_listbox.insert(tk.END, site.title())

    def load_selected_site(self, event=None):
        sel = self.site_listbox.curselection()
        if not sel:
            return
        site = self.site_listbox.get(sel[0]).lower()
        entry = self.pm.passwords[site]
        self.user_entry.delete(0, tk.END)
        self.user_entry.insert(0, entry["username"])
        self.pwd_entry.delete(0, tk.END)
        self.pwd_entry.insert(0, entry["password"])

    def add_password(self):
        site = simpledialog.askstring("Site", "Enter site name:")
        if not site:
            return
        self.pm.add_or_update_password(
            site,
            self.user_entry.get(),
            self.pwd_entry.get()
        )
        self.refresh_listbox()
        self.output.insert(tk.END, f"Saved {site}\n")

    def delete_password(self):
        sel = self.site_listbox.curselection()
        if not sel:
            return
        site = self.site_listbox.get(sel[0]).lower()
        if messagebox.askyesno("Confirm", f"Delete {site}?"):
            self.pm.delete_password(site)
            self.refresh_listbox()

    def copy_password(self):
        pyperclip.copy(self.pwd_entry.get())
        self.output.insert(tk.END, "Password copied\n")

    def reveal_password(self):
        messagebox.showinfo("Password", self.pwd_entry.get())

    def generate_password(self):
        pwd = generate_strong_password()
        self.pwd_entry.delete(0, tk.END)
        self.pwd_entry.insert(0, pwd)

    def backup_database(self):
        file = self.pm.backup_database()
        self.output.insert(tk.END, f"Backup: {file}\n")

# ---------- Run ----------
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()
