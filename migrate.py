# Bilt-in modules
import os
import sys
from json import load, dump
from base64 import urlsafe_b64encode, urlsafe_b64decode
from secrets import token_bytes
from getpass import getpass
# External modules
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# OS built-in modules
if os.name == 'nt':
    from ctypes.windll.kernel32 import SetFileAttributesW # type: ignore

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
    key = urlsafe_b64encode(kdf.derive(bytes(master_password)))
    return Fernet(key)

def wipe_buffer(objs):
    for obj in objs:
        if isinstance(obj, (bytearray, memoryview)):
            for i in range(len(obj)):
                obj[i] = 0
        del obj

def get_fernet_instance(vault_data, MASTER_PASSWORD):
    salt = urlsafe_b64decode(vault_data["_metadata"]["salt"])
    return derive_key_from_password(MASTER_PASSWORD, salt) # Git value in the main function 

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
            old_data = load(f)
        print("Success: Unencrypted data loaded successfully.")
    except Exception as e:
        print(f"Error reading old data file: {e}")
        return

    main_password = bytearray(getpass("Create your Master Password for encryption => ").strip().encode('utf-8'))
    if not main_password:
        print("Master Password cannot be empty.")
        return

    MASTER_PASSWORD = main_password

    new_salt = token_bytes(16)
    fernet = derive_key_from_password(MASTER_PASSWORD, new_salt)
    verify_token = fernet.encrypt(b"VALID").decode('utf-8')
    
    vault_data = {
        "_metadata": {
            "salt": urlsafe_b64encode(new_salt).decode('utf-8'),
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
                    pwd_bytes = bytearray(pwd.encode('utf-8'))
                    decrypted_dict[user][app] = fernet.encrypt(pwd_bytes).decode('utf-8')
                    wipe_buffer([pwd_bytes])
        else:
            decrypted_dict["Migrated_User"] = {}
            for app, pwd in old_data.items():
                pwd_bytes = bytearray(pwd.encode('utf-8'))
                decrypted_dict["Migrated_User"][app] = fernet.encrypt(pwd_bytes).decode('utf-8')
                wipe_buffer([pwd_bytes])

        vault_data["data"] = decrypted_dict

    except Exception as e:
        print(f"\n[CRITICAL ERROR] Encryption failed midway: {e}")
        print("Migration aborted automatically to prevent permanent data loss!")
        wipe_buffer([MASTER_PASSWORD])
        return
    
    if os.path.exists(NEW_JSON_FILE):

        if os.name == 'nt' :
            SetFileAttributesW(NEW_JSON_FILE, 0x80)

        with open(NEW_JSON_FILE, 'r', encoding='utf-8') as f :
            secret_vault = load(f)
            if secret_vault :
                try :
                    old_fernet = get_fernet_instance(secret_vault, MASTER_PASSWORD=MASTER_PASSWORD)
                    old_fernet.decrypt(secret_vault["_metadata"]["verify"].encode('utf-8'))
                    print(f"A secure vault file exists gitting access...")

                except InvalidToken:
                    print("Secret file found and the main password is uncorrect. Can not overwrite on it")
                    print("Lossing of access privileges....")
                    wipe_buffer([MASTER_PASSWORD])
                    return

        confirm_overwrite = get_yes_no("Warning: A secure vault file already exists. Overwrite it?")
        if not confirm_overwrite:
            print("Migration canceled. Existing database preserved.")
            wipe_buffer([MASTER_PASSWORD])
            return

    try:
        with open(NEW_JSON_FILE, 'w', encoding='utf-8') as json_file:
            dump(vault_data, json_file, ensure_ascii=False, indent=4)

        if os.name == 'nt':
            SetFileAttributesW(NEW_JSON_FILE, 0x06)
            
        print(f"\nSuccess: Data successfully migrated to: {NEW_JSON_FILE}")
        print("You can now open your main program and unlock it with this Master Password.")
    except Exception as e:
        print(f"Error saving to new vault file: {e}")
    finally:
        wipe_buffer([MASTER_PASSWORD])
        print("[SECURITY INFO]: RAM successfully wiped from all sensitive data.")

    confirm_delete = get_yes_no("\nDo you want to securely shred and delete 'old_passwords.json'?")
    if confirm_delete:
        try:
            file_size = os.path.getsize(OLD_JSON_FILE)
            with open(OLD_JSON_FILE, 'wb') as f:
                f.write(token_bytes(file_size))
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
