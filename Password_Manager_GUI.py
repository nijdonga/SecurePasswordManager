# Password_Manager_Week4_Listbox.py
import os
import json
import secrets
import string
import base64
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
import pyperclip

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DB_FILE = os.path.join(os.path.dirname(__file__), "passwords.json")

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
        key = site.lower()
        if key in self.passwords:
            del self.passwords[key]
            self.save_database()
            return True
        return False

    def backup_database(self):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        backup_file = f"passwords_backup_{timestamp}.json"
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
        self.pm = PasswordManager()
        self.master_password_dialog()
        self.create_widgets()
        self.refresh_listbox()

    def master_password_dialog(self):
        while True:
            master = simpledialog.askstring("Master Password", "Enter master password:", show="*")
            if not master:
                self.root.destroy()
                exit()
            if self.pm.load_database(master):
                messagebox.showinfo("Success", "Database unlocked!")
                break
            else:
                retry = messagebox.askretrycancel("Error", "Wrong master password or corrupted file.")
                if not retry:
                    self.root.destroy()
                    exit()

    def create_widgets(self):
        # Listbox for sites
        tk.Label(self.root, text="Stored Sites:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.site_listbox = tk.Listbox(self.root, height=10, width=30)
        self.site_listbox.grid(row=1, column=0, rowspan=6, padx=5, pady=5)
        self.site_listbox.bind("<<ListboxSelect>>", self.load_selected_site)

        # Username & Password Entries
        tk.Label(self.root, text="Username:").grid(row=1, column=1, sticky="w")
        self.user_entry = tk.Entry(self.root, width=30)
        self.user_entry.grid(row=2, column=1, pady=2)

        tk.Label(self.root, text="Password:").grid(row=3, column=1, sticky="w")
        self.pwd_entry = tk.Entry(self.root, width=30, show="*")
        self.pwd_entry.grid(row=4, column=1, pady=2)

        # Buttons
        tk.Button(self.root, text="Add / Update", command=self.add_password).grid(row=5, column=1, pady=2)
        tk.Button(self.root, text="Delete", command=self.delete_password).grid(row=6, column=1, pady=2)
        tk.Button(self.root, text="Copy Password", command=self.copy_password).grid(row=7, column=1, pady=2)
        tk.Button(self.root, text="Reveal Password", command=self.reveal_password).grid(row=8, column=1, pady=2)
        tk.Button(self.root, text="Generate Strong Password", command=self.generate_password).grid(row=9, column=1, pady=2)
        tk.Button(self.root, text="Backup Database", command=self.backup_database).grid(row=10, column=1, pady=2)

        # Output Box
        self.output = tk.Text(self.root, height=10, width=60)
        self.output.grid(row=11, column=0, columnspan=2, pady=5)

    # ---------- Actions ----------
    def refresh_listbox(self):
        self.site_listbox.delete(0, tk.END)
        for site in sorted(self.pm.passwords.keys()):
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
        site_idx = self.site_listbox.curselection()
        site = self.site_listbox.get(site_idx[0]) if site_idx else simpledialog.askstring("Site", "Enter site name:")
        username = self.user_entry.get().strip()
        password = self.pwd_entry.get().strip()
        if not site or not username or not password:
            messagebox.showwarning("Input Error", "Fill all fields.")
            return
        self.pm.add_or_update_password(site, username, password)
        self.refresh_listbox()
        self.output.insert(tk.END, f"Saved '{site}'\n")

    def delete_password(self):
        sel = self.site_listbox.curselection()
        if not sel:
            messagebox.showwarning("Delete", "Select a site first.")
            return
        site = self.site_listbox.get(sel[0]).lower()
        confirm = messagebox.askyesno("Confirm Delete", f"Delete '{site.title()}'?")
        if confirm:
            self.pm.delete_password(site)
            self.refresh_listbox()
            self.output.insert(tk.END, f"Deleted '{site}'\n")

    def copy_password(self):
        pwd = self.pwd_entry.get()
        if not pwd:
            return
        try:
            pyperclip.copy(pwd)
            self.output.insert(tk.END, "Password copied to clipboard!\n")
        except:
            self.output.insert(tk.END, "Clipboard copy failed.\n")

    def reveal_password(self):
        pwd = self.pwd_entry.get()
        if not pwd:
            return
        messagebox.showinfo("Password", pwd)

    def generate_password(self):
        pwd = generate_strong_password(16)
        self.pwd_entry.delete(0, tk.END)
        self.pwd_entry.insert(0, pwd)
        self.output.insert(tk.END, f"Generated password: {pwd}\n")

    def backup_database(self):
        backup_file = self.pm.backup_database()
        self.output.insert(tk.END, f"Backup created: {backup_file}\n")

# ---------- Run ----------
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()
