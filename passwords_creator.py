import json
import string
import os
import sys
import base64
import secrets
import getpass  # Imported to hide password input during typing
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Using a hidden file name and path in the user directory to improve security
JSON_FILE = os.path.join(os.path.expanduser('~'), '.secure_vault_data.dat')

# Global variable to store the master password string
# This allows dynamic key derivation using the unique salt found in the file
MASTER_PASSWORD: str = "" 

# --- Key Derivation Function ---
def derive_key_from_password(master_password: str, salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=400_000, # High iteration count to prevent brute-force attacks
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return Fernet(key)

# --- Helper Functions to Read and Write with Dynamic Salt ---
def read_encrypted_vault():
    """Reads the file, extracts the salt, decrypts and returns the database dictionary."""
    if not os.path.exists(JSON_FILE):
        return {}

    with open(JSON_FILE, 'rb') as json_file:
        file_content = json_file.read()

    if not file_content:
        return {}

    # The first 16 bytes represent the unique random salt
    salt = file_content[:16]
    encrypted_data = file_content[16:]

    # Derive the specific key using the extracted salt
    fernet = derive_key_from_password(MASTER_PASSWORD, salt)
    decrypted_data = fernet.decrypt(encrypted_data)
    return json.loads(decrypted_data.decode('utf-8'))

def write_encrypted_vault(all_data):
    """Generates a new random salt, encrypts the dictionary, and writes [salt + ciphertext] to disk."""
    # Generate a cryptographically secure 16-byte random salt
    new_salt = secrets.token_bytes(16)
    fernet = derive_key_from_password(MASTER_PASSWORD, new_salt)

    json_string = json.dumps(all_data, ensure_ascii=False, indent=4)
    encrypted_data = fernet.encrypt(json_string.encode('utf-8'))

    # Concatenate salt and encrypted data before writing
    with open(JSON_FILE, 'wb') as json_file:
        json_file.write(new_salt + encrypted_data)

# --- View Saved Passwords Function ---
def view_passwords():
    print("\n--- Saved Passwords ---")
    try:
        all_data = read_encrypted_vault()
        if not all_data:
            print("No passwords saved yet.")
            return
            
        for user, apps in all_data.items():
            print(f"\nUser: {user}")
            for app, pwd in apps.items():
                print(f"   - {app}: {pwd}")
                
    except InvalidToken:
        print("\n[SECURITY WARNING]:")
        print("The database file has been altered, corrupted, or an incorrect Master Password was entered!")
        print("Decryption is blocked to protect data integrity.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    print("\n-----------------------------\n")

# --- Delete User Function ---
def delete_user():
    print("\n--- Delete User ---")
    if not os.path.exists(JSON_FILE):
        print("No data available to delete.")
        return

    user_to_delete = input("Enter the username you want to delete => ").strip()

    try:
        all_data = read_encrypted_vault()
            
        if user_to_delete in all_data:
            confirm = get_yes_no(f"Are you sure you want to delete user '{user_to_delete}' and all their passwords?")
            if confirm:
                del all_data[user_to_delete]
                write_encrypted_vault(all_data)
                print(f"User '{user_to_delete}' has been deleted successfully.")
            else:
                print("Deletion canceled.")
        else:
            print(f"User '{user_to_delete}' not found.")
            
    except InvalidToken:
        print("\n[SECURITY WARNING]: Cannot modify the file because it has been altered or corrupted externally.")
    except Exception as e:
        print(f"Error updating the file during deletion: {e}")

# Inputs and UI messages
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
    name = input("User name that use the password => ").strip()
    app = input("The password for what (e.g., Google) => ").strip()
    count = get_int_input("Password Length (integer) => ")
    choice = input(input_message).strip().lower()
    return name, app, count, choice

def load_to_json(user_name, app_name, password):
    try:
        all_data = read_encrypted_vault()
    except Exception:
        all_data = {}

    if user_name in all_data:
        all_data[user_name][app_name] = password
    else:
        all_data[user_name] = {app_name: password}

    try:
        write_encrypted_vault(all_data)
        print('The password saved and encrypted successfully.')
    except OSError as e:
        print(f'An error occurred info: {e}')

# --- Cryptographically secure password generation functions using secrets module ---
def with_punctuation(count):
    all_char = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(all_char) for _ in range(count))

def with_number(count):
    all_char = string.ascii_letters + string.digits
    return ''.join(secrets.choice(all_char) for _ in range(count))

def with_capital(count):
    all_char = string.ascii_letters
    return ''.join(secrets.choice(all_char) for _ in range(count))

def stander(count):
    all_char = string.ascii_lowercase
    return ''.join(secrets.choice(all_char) for _ in range(count))

def exit_app():
    print("Exiting the app...")
    sys.exit(0)

def creat_password(func, *args, **kwargs):
    while True:
        password = func(*args, **kwargs)
        print(f'The password is : {password}\n')
        if get_yes_no('Do you want a new password ?'):
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
        print(f"\nName : {name}, App : {app}, Password : {password}\n")
        
        save_json = get_yes_no('Do you want save it in JSON file ?')
        if save_json:
            load_to_json(name, app, password)
        else:
            print('The password has not saved')

        want_con = get_yes_no("Do you want continue making passwords ?")
        if not want_con:
            break

# Main Menu
def start():
    global MASTER_PASSWORD
    print("<< Passwords Creator & Manager >>")
    
    # getpass.getpass hides the input completely for maximum privacy
    master_password = getpass.getpass("Enter your Master Password to unlock (Input will be hidden): ").strip()
    if not master_password:
        print("Master Password cannot be empty. Exiting...")
        return
        
    MASTER_PASSWORD = master_password

    if os.path.exists(JSON_FILE):
        try:
            # Attempt to read the vault to test if the master password is correct
            read_encrypted_vault()
            print("Access Granted. Database unlocked successfully.")
        except InvalidToken:
            print("\n[ACCESS DENIED]: Incorrect Master Password! Exiting to protect data integrity.")
            sys.exit(1)
        except Exception as e:
            print(f"Error accessing database: {e}")
            sys.exit(1)
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