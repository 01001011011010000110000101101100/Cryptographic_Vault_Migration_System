import json
import os
import sys
import base64
import secrets
import getpass  # Added to securely hide password input
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

BASE_DIR = os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__))
OLD_JSON_FILE = os.path.join(BASE_DIR, 'old_passwords.json')

# Path must match the location configured in the main password creator application
NEW_JSON_FILE = os.path.join(os.path.expanduser('~'), '.secure_vault_data.dat')

# Key derivation function now takes the salt as a dynamic parameter
def derive_key(master_password: str, salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=400_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return Fernet(key)

def migrate_passwords():
    print("=== Password Migration Tool (Random Salt Version) ===")
    
    # 1. Check for old plain text file existence
    if not os.path.exists(OLD_JSON_FILE):
        print(f"Error: Plain text file not found at: {OLD_JSON_FILE}")
        return

    # 2. Read the unencrypted data
    try:
        with open(OLD_JSON_FILE, 'r', encoding='utf-8') as f:
            old_data = json.load(f)
        print("Success: Unencrypted data loaded successfully.")
    except Exception as e:
        print(f"Error reading old data file: {e}")
        return

    # 3. Prompt for the new Master Password securely using getpass
    master_password = getpass.getpass("Create your Master Password for encryption => ").strip()
    if not master_password:
        print("Master Password cannot be empty.")
        return

    # 4. Generate a new random salt (16 bytes) and derive the key based on it
    new_salt = secrets.token_bytes(16)
    fernet = derive_key(master_password, new_salt)

    # 5. Check if a secure database already exists to prevent accidental overwrites
    if os.path.exists(NEW_JSON_FILE):
        confirm_overwrite = input("Warning: A secure file already exists. Overwrite it? (Y/N) => ").strip().lower()
        if confirm_overwrite != 'y':
            print("Migration canceled. Existing database was preserved.")
            return

    # 6. Encrypt and save data to the new secure destination path
    try:
        json_string = json.dumps(old_data, ensure_ascii=False, indent=4)
        encrypted_data = fernet.encrypt(json_string.encode('utf-8'))
        
        # Write the random salt first (16 bytes), then append the encrypted data directly after it
        with open(NEW_JSON_FILE, 'wb') as f:
            f.write(new_salt + encrypted_data)
            
        print(f"\nSuccess: Data migrated and encrypted successfully to: {NEW_JSON_FILE}")
        print("Warning: Please delete 'old_passwords.json' and this script manually to secure your machine.")
    except Exception as e:
        print(f"An error occurred during encryption and saving: {e}")

if __name__ == '__main__':
    migrate_passwords()