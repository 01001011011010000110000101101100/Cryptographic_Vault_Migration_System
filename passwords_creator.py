# Built-in modules
import os
import secrets
from json import load, dump
from string import ascii_letters, digits, punctuation, ascii_uppercase, ascii_lowercase
from sys import exit
from base64 import urlsafe_b64encode, urlsafe_b64decode
from getpass import getpass
# External modules
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# OS bulit-in modules
if os.name == 'nt':
    from ctypes.windll.kernel32 import SetFileAttributesW # type: ignore

JSON_FILE = os.path.join(os.path.expanduser('~'), '.secure_vault_data.json')

MASTER_PASSWORD: bytearray = bytearray()

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
            obj[:] = b'\x00' * len(obj)
        del obj

def read_vault():
    if not os.path.exists(JSON_FILE):
        return None
    with open(JSON_FILE, 'r', encoding='utf-8') as json_file:
        return load(json_file)

def write_vault(vault_data):
    if os.path.exists(JSON_FILE) and os.name == 'nt':
       SetFileAttributesW(JSON_FILE, 0x80)

    with open(JSON_FILE, 'w', encoding='utf-8') as json_file:
        dump(vault_data, json_file, ensure_ascii=False, indent=4)

    if os.name == 'nt':
       SetFileAttributesW(JSON_FILE, 0x06)

def init_vault():
    new_salt = secrets.token_bytes(16)
    fernet = derive_key_from_password(MASTER_PASSWORD, new_salt)
    verify_token = fernet.encrypt(b"VALID").decode('utf-8')
    
    vault_data = {
        "_metadata": {
            "salt": urlsafe_b64encode(new_salt).decode('utf-8'),
            "verify": verify_token
        },
        "data": {}
    }
    write_vault(vault_data)
    return vault_data

def get_fernet_instance(vault_data):
    salt = urlsafe_b64decode(vault_data["_metadata"]["salt"])
    return derive_key_from_password(MASTER_PASSWORD, salt)

def view_passwords():
    print("\n--- Saved Passwords ---")
    vault = read_vault()
    if not vault or not vault.get("data"):
        print("No passwords saved yet.")
        return

    fernet = get_fernet_instance(vault)

    for user, apps in vault["data"].items():
        print(f"\nUser: {user}")
        for app, enc_pwd_str in apps.items():
            try:
                decrypted_bytes = bytearray(fernet.decrypt(enc_pwd_str.encode('utf-8')))
                pwd_ba = decrypted_bytes
                print(f"   - {app}: ", end="")
                for byte in pwd_ba:
                    print(chr(byte), end="")
                print()
                wipe_buffer([pwd_ba])
            except Exception:
                print(f"   - {app}: [DECRYPTION FAILED - Data Corrupted]")
    print("\n-----------------------------\n")

def delete_user():
    print("\n--- Delete User ---")
    vault = read_vault()
    if not vault or not vault.get("data"):
        print("No data available to delete.")
        return

    user_to_delete = input("Enter the username you want to delete => ").strip()
    
    if user_to_delete in vault["data"]:
        confirm = get_yes_no(f"Are you sure you want to delete user '{user_to_delete}' and all their passwords?")
        if confirm:
            del vault["data"][user_to_delete]
            write_vault(vault)
            print(f"User '{user_to_delete}' has been deleted successfully.")
        else:
            print("Deletion canceled.")
    else:
        print(f"User '{user_to_delete}' not found.")

input_message = '''
    How you want your password be ?

"p" = with punctuation and other matters (e.g., M9$vp),
"n" = with numbers and other matters unless punctuation (e.g., Lo89N),
"c" = with capital letters without numbers and punctuation (e.g., LobyJ),
"s" = standard which means only small letters (e.g., syboq),
"e" = exit
=> '''

valid_inputs = ('p', 'n', 'c', 's', 'e')

def get_int_input(question):
    while True:
        try:
            value = int(input(question).strip())
            return value
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

def get_yes_no(question):
    while True:
        print(question)
        answer = input("('Y' or 'N') => ").strip().lower()
        if answer not in ('y', 'n'):
            print("Please write 'Y' or 'N'")
            continue
        return answer == 'y'
    
def take_inputs():
    name =input("User name that use the password => ").strip()
    app = input("The password for what (e.g., Google) => ").strip()
    count = get_int_input("Password Length (integer) => ")
    choice = input(input_message).strip().lower()
    return name, app, count, choice

def load_to_json(user_name, app_name, password_ba):
    vault = read_vault()
    if not vault:
        vault = init_vault()

    fernet = get_fernet_instance(vault)
    
    enc_pwd_str = fernet.encrypt(bytes(password_ba)).decode('utf-8')

    if user_name not in vault["data"]:
        vault["data"][user_name] = {}
    vault["data"][user_name][app_name] = enc_pwd_str

    try:
        write_vault(vault)
        print('The password saved and encrypted successfully.')
    except OSError as e:
        print(f'An error occurred info: {e}')
    
    wipe_buffer([password_ba])

def with_punctuation(count):
    all_char = (ascii_letters + digits + punctuation).encode('utf-8')
    pwd_bytes = bytearray(count)
    for i in range(count):
        pwd_bytes[i] = (secrets.choice(all_char))
    return pwd_bytes

def with_number(count):
    all_char = (ascii_letters + digits).encode('utf-8')
    pwd_bytes = bytearray(count)
    for i in range(count):
        pwd_bytes[i] = (secrets.choice(all_char))
    return pwd_bytes

def with_capital(count):
    all_char = (ascii_uppercase + ascii_lowercase).encode('utf-8')
    pwd_bytes = bytearray(count)
    for i in range(count):
        pwd_bytes[i] = (secrets.choice(all_char))
    return pwd_bytes

def stander(count):
    all_char = (ascii_lowercase).encode('utf-8')
    pwd_bytes = bytearray(count)
    for i in range(count):
        pwd_bytes[i] = (secrets.choice(all_char))
    return pwd_bytes

def exit_app():
    global MASTER_PASSWORD
    wipe_buffer([MASTER_PASSWORD])
    print("Exiting the app...")
    exit(0)

def creat_password(func, *args, **kwargs):
    while True:
        password = bytearray(func(*args, **kwargs)) 
        print(f'The password is : {password.decode("utf-8")}\n')
        if get_yes_no('Do you want a new password ?'):
            wipe_buffer([password])
            continue
        return password

actions = {
    'p' : with_punctuation,
    'n' : with_number,
    'c' : with_capital,
    's': stander,
    'e' : exit_app
}

def run_password_creator():
    while True:
        name, app, count, choice = take_inputs()

        if choice not in valid_inputs:
            print("Invalid input please try again")
            continue

        if choice == 'e':
            return

        act = actions[choice]
        password = creat_password(act, count)
        print(f"\nName : {name}, App : {app}, Password : ", end="")

        for byte in password:
            print(chr(byte), end="")
        print("\n")
        
        save_json = get_yes_no('Do you want save it in JSON file ?')
        if save_json:
            load_to_json(name, app, password)
        else:
            print('The password has not saved')
            wipe_buffer([password])

        want_con = get_yes_no("Do you want continue making passwords ?")
        if not want_con:
            break

def start():
    global MASTER_PASSWORD
    print("<< Passwords Creator & Manager >>")
    
    master_password = bytearray(getpass("Enter your Master Password to unlock (Input will be hidden): ").strip().encode('utf-8'))
    
    if not master_password:
        print("Master Password cannot be empty. Exiting...")
        return
        
    MASTER_PASSWORD = master_password

    vault = read_vault()
    if vault:
        try:
            fernet = get_fernet_instance(vault)
            fernet.decrypt(vault["_metadata"]["verify"].encode('utf-8'))
            print("Access Granted. Database unlocked successfully.")
        except InvalidToken:
            print("\n[ACCESS DENIED]: Incorrect Master Password! Exiting to protect data integrity.")
            wipe_buffer([MASTER_PASSWORD])
            exit(1)
        except Exception as e:
            print(f"Error accessing database: {e}")
            wipe_buffer([MASTER_PASSWORD])
            exit(1)
    else:
        print("No existing database found. A new one will be created upon saving your first password.")

    while True:
        print("\n--- Main Menu ---")
        print("1. Create a new password")
        print("2. View saved passwords")
        print("3. Delete a user")
        print("4. Exit")
        
        main_choice = input("Choose an option (1, 2, 3, or 4) => ").strip()
        
        if main_choice == '1':
            run_password_creator()
        elif main_choice == '2':
            view_passwords()
        elif main_choice == '3':
            delete_user()
        elif main_choice == '4':
            exit_app()
        else:
            print("Invalid choice, please enter 1, 2, 3, or 4.")

if __name__ == '__main__':
    start()
