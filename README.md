# Enterprise Cryptographic Vault & Legacy Data Migration Subsystem

## 📌 Overview
An integrated local security system and data engineering solution featuring a production-grade credentials vault manager (`passwords_creator.py`) and an isolated, transactional data migration utility (`migrate.py`). The ecosystem is designed to ingest vulnerable plaintext configuration baselines, execute schema sanity validations, and migrate raw attributes into a hardened, sandboxed local binary store via symmetric encryption (AES-128 via Fernet) mixed with strict Key Derivation Functions (KDF).

## 🛠️ Architectural & Security Features

### 1. Hardened Key Derivation Function (KDF)
The core cryptographic routine integrates **PBKDF2HMAC** (Password-Based Key Derivation Function 2) backed by a high-performance **SHA-256** hashing engine. To neutralize offline brute-force computation or specialized hardware (ASIC/GPU) dictionary attacks, the key derivation routine enforces a strict runtime barrier of **400,000 algorithmic iterations** prior to emitting the safe symmetric execution key.

### 2. Dynamic Salt-Prepend Data Isolation
To prevent cross-session pattern recognition and precomputed rainbow-table analysis, the system implements a dynamic salting strategy:
* Uses an OS-level Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) via `secrets.token_bytes(16)` to produce a high-entropy 16-byte salt for every individual write operation.

* Prepends this raw 16-byte salt signature directly to the beginning of the ciphertext binary stream on disk.

* On execution, the reading stream slices the initial 16 bytes to dynamically reconstruct the exact Fernet cipher block mapping the target session's master passphrase.

### 3. Atomic ETL Migration Engine
The migration module acts as a formal Extract-Transform-Load (ETL) pipeline. It scans specific system environments for plain legacy JSON files, extracts configuration states, wraps file I/O streams inside failure-trapping logic to prevent state corruption, and loads the encrypted byte array safely into user home directory spaces while preserving execution continuity.

## 🚀 Technical Showcase (System Blueprint)

The system manages dynamic state evaluation and initialization gates directly using secure operating system abstractions:

```python
def derive_key(master_password: str, salt: bytes) -> Fernet:
    """
    Computes a cryptographically strong symmetric key from a raw master string
    by running a high-iteration PBKDF2 configuration.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=400_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return Fernet(key)
Operational Pipeline
Password Management Loop (passwords_creator.py): Drives interactive CRUD routines over local binary objects, handling account insertion, credential deletions, and automated CSPRNG-driven string generator selection safely in terminal buffers.

Schema Upgrade Loop (migrate.py): Acts as a migration gatekeeper, ensuring safe migration of legacy text data, intercepting potential binary collisions, and validating structural boundaries prior to file system writes.

📦 Requirements & Dependencies
Python 3.8+

cryptography library (Symmetric encryption block)

Operating system file access permissions over user home environments (~)