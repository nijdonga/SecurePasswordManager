# Secure Password Manager

A **local, encrypted password manager** built in Python with a **Tkinter GUI**.  
All passwords are stored **encrypted on disk** using AES-256 (Fernet) and protected by a master password.

## Features

- Add / update passwords for websites or services
- Search and select sites from a **Listbox**
- Copy password to clipboard
- Reveal password in a messagebox
- Generate strong passwords
- Delete passwords with confirmation
- Backup database with timestamped JSON
- Fully encrypted passwords.json on disk
- Master password authentication

## Installation

1. Clone this repository:

```bash
git clone https://github.com/nijdonga/SecurePasswordManager.git
cd SecurePasswordManager
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the application:

```bash
python Password_Manager_GUI.py
```

The first time you run it, you’ll be prompted to create a master password.

## Usage

Select a site from the Listbox to view/edit credentials.

Use buttons to copy, reveal, generate, or backup passwords.

Use "Add/Update" to save a new entry or modify an existing one.

"Delete" asks for confirmation before removing an entry.

## Security

Passwords are encrypted on disk using AES-256 + HMAC-SHA256.

Master password protects access to the database.

Clipboard copy is temporary; passwords are not stored in plaintext anywhere.

