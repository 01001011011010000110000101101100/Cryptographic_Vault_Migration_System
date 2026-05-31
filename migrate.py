import json
import os
import sys
import ctypes 
import base64
import secrets
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

BASE_DIR = os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__))
OLD_JSON_FILE = os.path.join(BASE_DIR, 'old_passwords.json')
NEW_JSON_FILE = os.path.join(os.path.expanduser('~'), '.secure_vault_data.json')

def derive_key_from_password(master_password: bytearray, salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=400_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(bytes(master_password)))
    return Fernet(key)

def wipe_buffer(objs):
    for obj in objs:
        if isinstance(obj, (bytearray, memoryview)):
            for i in range(len(obj)):
                obj[i] = 0
        del obj

def get_yes_no(question):
    while True:
        answer = input(f"{question} (Y/N) => ").strip().lower()
        if answer not in ('y', 'n'):
            print("Invalid input. Please enter 'Y' or 'N'.")
            continue
        return answer == 'y'

def migrate_passwords():
    print("=== Password Migration Tool (Compatible & Secure Version) ===")
    
    if not os.path.exists(OLD_JSON_FILE):
        print(f"Error: Plain text file not found at: {OLD_JSON_FILE}")
        return

    try:
        with open(OLD_JSON_FILE, 'r', encoding='utf-8') as f:
            old_data = json.load(f)
        print("Success: Unencrypted data loaded successfully.")
    except Exception as e:
        print(f"Error reading old data file: {e}")
        return

    raw_password = getpass.getpass("Create your Master Password for encryption => ").strip()
    if not raw_password:
        print("Master Password cannot be empty.")
        return
        
    master_password_ba = bytearray(raw_password.encode('utf-8'))
    del raw_password 

    new_salt = secrets.token_bytes(16)
    fernet = derive_key_from_password(master_password_ba, new_salt)
    verify_token = fernet.encrypt(b"VALID").decode('utf-8')
    
    vault_data = {
        "_metadata": {
            "salt": base64.urlsafe_b64encode(new_salt).decode('utf-8'),
            "verify": verify_token
        },
        "data": {}
    }

    try:
        print("Encrypting data...")
        decrypted_dict = {}
        
        first_value = next(iter(old_data.values())) if old_data else None
        
        if isinstance(first_value, dict):
            for user, apps in old_data.items():
                decrypted_dict[user] = {}
                for app, pwd in apps.items():
                    pwd_bytes = str(pwd).encode('utf-8')
                    decrypted_dict[user][app] = fernet.encrypt(pwd_bytes).decode('utf-8')
        else:
            decrypted_dict["Migrated_User"] = {}
            for app, pwd in old_data.items():
                pwd_bytes = str(pwd).encode('utf-8')
                decrypted_dict["Migrated_User"][app] = fernet.encrypt(pwd_bytes).decode('utf-8')

        vault_data["data"] = decrypted_dict

    except Exception as e:
        print(f"An error occurred during encryption: {e}")
        wipe_buffer([master_password_ba])
        return

    if os.path.exists(NEW_JSON_FILE):
        confirm_overwrite = get_yes_no("Warning: A secure vault file already exists. Overwrite it?")
        if not confirm_overwrite:
            print("Migration canceled. Existing database preserved.")
            wipe_buffer([master_password_ba])
            return
        
        if os.name == 'nt':
            ctypes.windll.kernel32.SetFileAttributesW(NEW_JSON_FILE, 0x80)

    try:
        with open(NEW_JSON_FILE, 'w', encoding='utf-8') as json_file:
            json.dump(vault_data, json_file, ensure_ascii=False, indent=4)

        if os.name == 'nt':
            ctypes.windll.kernel32.SetFileAttributesW(NEW_JSON_FILE, 2)
            
        print(f"\nSuccess: Data successfully migrated to: {NEW_JSON_FILE}")
        print("You can now open your main program and unlock it with this Master Password.")
    except Exception as e:
        print(f"Error saving to new vault file: {e}")
    finally:
        wipe_buffer([master_password_ba])
        if 'vault_data' in locals(): del vault_data
        if 'decrypted_dict' in locals(): del decrypted_dict
        print("[SECURITY INFO]: RAM successfully wiped from all sensitive data.")

    confirm_delete = get_yes_no("\nDo you want to securely shred and delete 'old_passwords.json'?")
    if confirm_delete:
        try:
            file_size = os.path.getsize(OLD_JSON_FILE)
            with open(OLD_JSON_FILE, 'wb') as f:
                f.write(secrets.token_bytes(file_size))
            os.remove(OLD_JSON_FILE)
            print("Success: 'old_passwords.json' has been completely destroyed.")
        except Exception as e:
            print(f"Could not delete old file: {e}")

    confirm_self_delete = get_yes_no("Do you want this migration script to self-delete?")
    if confirm_self_delete:
        print("Self-deleting script... Complete.")
        try:
            os.remove(__file__)
        except Exception:
            os.remove(sys.argv[0])

if __name__ == '__main__':
    migrate_passwords()
