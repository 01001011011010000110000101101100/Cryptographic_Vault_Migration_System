# Password Creator and Manager

A CLI utility for generating, managing, and locally storing passwords using symmetric encryption and active memory wiping.

## Technical Overview

* **Encryption:** Symmetric AES encryption via the `cryptography` library (Fernet).
* **Key Derivation:** PBKDF2HMAC (SHA-256) with a 16-byte salt and 400,000 iterations.
* **Memory Security:** Active RAM clearing. A custom `wipe_buffer` function overwrites sensitive `bytearray` variables with zeros before deletion.
* **File Security:** Legacy plain-text files are securely shredded before deletion. Output vaults are configured as hidden files via OS-level attributes.

## Installation

Requires Python 3.6+ and the `cryptography` package.

> pip install cryptography

## Quick Start

### 1. Legacy Data Migration
If migrating from an unencrypted `old_passwords.json` file, execute the migration script first. It encrypts existing data and securely shreds the plaintext file.

> python migrate.py

### 2. Main Application
Run the primary script to generate new passwords, view the decrypted vault, or delete records. 

> python passwords_creator.py

*Note: The encrypted database is stored locally at `~/.secure_vault_data.json`.*

## Password Generation Modes

During credential creation, input the corresponding letter to define the character set:

* **p**: Punctuation, numbers, and mixed-case letters.
* **n**: Numbers and mixed-case letters (no punctuation).
* **c**: Mixed-case letters only.
* **s**: Lowercase letters only.
