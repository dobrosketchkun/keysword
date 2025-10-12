# Keysword Enhancement Implementation Plan

This document outlines the plan for implementing major enhancements to the Keysword project. Features are organized into phases based on dependencies and logical grouping.

---

## Phase 1: Foundation & Infrastructure

### 1.1 Project Structure Refactoring
**Priority:** High | **Complexity:** Medium | **Estimated Time:** 2-4 hours

**Goal:** Reorganize code into a proper package structure to support library API and better maintainability.

**Implementation:**
```
keysword/
├── keysword/
│   ├── __init__.py          # Library API exports
│   ├── __main__.py          # CLI entry point
│   ├── core/
│   │   ├── __init__.py
│   │   ├── kdf.py           # Key derivation functions (sha000)
│   │   ├── generators.py    # Key generation functions
│   │   ├── formats.py       # Export format handlers
│   │   └── crypto_utils.py  # Deterministic random, etc.
│   ├── io/
│   │   ├── __init__.py
│   │   ├── readers.py       # Password/file input
│   │   ├── writers.py       # JSON/separated file writers
│   │   └── encryption.py    # Output encryption
│   ├── validation/
│   │   ├── __init__.py
│   │   ├── input_validators.py
│   │   └── key_validators.py
│   ├── ui/
│   │   ├── __init__.py
│   │   ├── cli.py           # Argument parsing
│   │   ├── display.py       # Progress bars, printing
│   │   └── interactive.py   # Interactive mode (Phase 6)
│   └── utils/
│       ├── __init__.py
│       └── helpers.py       # clear_screen, etc.
├── tests/
│   ├── __init__.py
│   ├── test_kdf.py
│   ├── test_generators.py
│   ├── test_formats.py
│   └── test_integration.py
├── setup.py or pyproject.toml
├── keysword.py              # Direct usage entry point (no installation needed)
└── README.md
```

**Steps:**
1. Create new directory structure
2. Move existing functions to appropriate modules
3. Update root `keysword.py` to be a thin wrapper
4. Update imports throughout

**Root `keysword.py` structure (for direct usage):**
```python
#!/usr/bin/env python3
"""
Direct usage entry point for Keysword.
Allows running without installation: python keysword.py [args]
"""
import sys
from keysword.__main__ import main

if __name__ == '__main__':
    sys.exit(main())
```

This allows both usage patterns:
- **Direct**: `python keysword.py -k RSA -b '[1,2,3]' -n 1`
- **Installed**: `keysword -k RSA -b '[1,2,3]' -n 1` (after `pip install .`)

**Dependencies:** None

---

### 1.2 Setup.py / Pyproject.toml
**Priority:** High | **Complexity:** Low | **Estimated Time:** 1 hour

**Goal:** Make Keysword pip-installable and properly packaged.

**Implementation:**

Use `pyproject.toml` (modern Python packaging):
```toml
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "keysword"
version = "2.0.0"
description = "Deterministic cryptographic key generation from passwords"
authors = [{name = "Your Name", email = "your.email@example.com"}]
license = {text = "LICENSE"}
readme = "README.md"
requires-python = ">=3.8"
classifiers = [
    "Programming Language :: Python :: 3",
    "License :: OSI Approved :: ...",
    "Operating System :: OS Independent",
]
dependencies = [
    "progressbar2",
    "argon2-cffi",
    "pycryptodome",
    "PyNaCl",
    "bitcoin",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "pytest-cov",
    "black",
    "flake8",
    "mypy",
]

[project.scripts]
keysword = "keysword.__main__:main"

[project.urls]
Homepage = "https://github.com/yourusername/keysword"
```

**Dependencies:** 1.1 (Project Structure)

---

### 1.3 Library API
**Priority:** High | **Complexity:** Low | **Estimated Time:** 1-2 hours

**Goal:** Allow Keysword to be imported and used as a library.

**Implementation:**

In `keysword/__init__.py`:
```python
"""Keysword - Deterministic cryptographic key generation."""

__version__ = "2.0.0"

from keysword.core.generators import (
    generate_curve25519_keys,
    generate_p256_keys,
    generate_rsa_keys,
    generate_bitcoin_keys,
)
from keysword.core.kdf import derive_key
from keysword.core.formats import export_keys

__all__ = [
    "generate_curve25519_keys",
    "generate_p256_keys",
    "generate_rsa_keys",
    "generate_bitcoin_keys",
    "derive_key",
    "export_keys",
]
```

**Example usage:**
```python
from keysword import generate_rsa_keys

keys = generate_rsa_keys(
    password="my_strong_password",
    branches=[410, 111, 123],
    key_number=1,
    key_amount=5,
    size=2048
)
```

**Dependencies:** 1.1 (Project Structure)

---

## Phase 2: Security & Validation

### 2.1 Output File Encryption
**Priority:** High | **Complexity:** Medium | **Estimated Time:** 3-4 hours

**Goal:** Optionally encrypt saved keys with a passphrase.

**Implementation:**

Add new module `keysword/io/encryption.py`:
```python
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import json

def encrypt_file(plaintext: bytes, passphrase: str) -> bytes:
    """Encrypt data using AES-256-GCM with scrypt KDF."""
    salt = get_random_bytes(32)
    key = scrypt(passphrase, salt, key_len=32, N=2**17, r=8, p=1)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    # Return: salt(32) + nonce(16) + tag(16) + ciphertext
    return salt + cipher.nonce + tag + ciphertext

def decrypt_file(encrypted: bytes, passphrase: str) -> bytes:
    """Decrypt AES-256-GCM encrypted data."""
    salt = encrypted[:32]
    nonce = encrypted[32:48]
    tag = encrypted[48:64]
    ciphertext = encrypted[64:]
    
    key = scrypt(passphrase, salt, key_len=32, N=2**17, r=8, p=1)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext
```

**CLI Changes:**
- Add `-e, --encrypt` flag to enable encryption
- Add `-d, --decrypt` flag for decryption mode
- Add `--decrypt-file FILE` to decrypt a previously encrypted output

**File format:**
- Encrypted files get `.enc` extension
- Unencrypted files remain as before

**Dependencies:** 1.1 (Project Structure)

---

### 2.2 Key Strength Validation
**Priority:** Medium | **Complexity:** Low | **Estimated Time:** 2 hours

**Goal:** Warn users about weak passwords and configurations.

**Implementation:**

Add `keysword/validation/input_validators.py`:
```python
import math
from typing import Tuple

def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy of password."""
    if not password:
        return 0.0
    
    entropy = 0
    for x in range(256):
        p_x = password.count(chr(x)) / len(password)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy * len(password)

def validate_password_strength(password: str) -> Tuple[bool, str, dict]:
    """
    Returns: (is_strong, warning_message, details)
    """
    details = {
        'length': len(password),
        'entropy': calculate_entropy(password),
        'has_upper': any(c.isupper() for c in password),
        'has_lower': any(c.islower() for c in password),
        'has_digit': any(c.isdigit() for c in password),
        'has_special': any(not c.isalnum() for c in password),
    }
    
    warnings = []
    
    if details['length'] < 16:
        warnings.append(f"Password is only {details['length']} characters (recommended: 20+)")
    
    if details['entropy'] < 50:
        warnings.append(f"Low entropy: {details['entropy']:.1f} bits (recommended: 80+)")
    
    if not (details['has_upper'] and details['has_lower'] and 
            details['has_digit'] and details['has_special']):
        warnings.append("Password should include uppercase, lowercase, digits, and special characters")
    
    is_strong = len(warnings) == 0
    message = "; ".join(warnings) if warnings else "Password strength is adequate"
    
    return is_strong, message, details

def validate_branches(branches: list) -> Tuple[bool, str]:
    """Validate branch configuration."""
    warnings = []
    
    if len(branches) == 1:
        warnings.append("Using only one branch reduces security")
    
    if branches == sorted(branches) or branches == sorted(branches, reverse=True):
        warnings.append("Sequential branches are predictable; use random values")
    
    if all(b < 1000 for b in branches):
        warnings.append("All branch values < 1000; consider using larger values")
    
    is_strong = len(warnings) == 0
    message = "; ".join(warnings) if warnings else "Branch configuration is adequate"
    
    return is_strong, message
```

**CLI Changes:**
- Add `--no-warnings` flag to suppress strength warnings
- Show warnings but allow user to proceed

**Dependencies:** 1.1 (Project Structure)

---

### 2.3 Output File Collision Detection
**Priority:** Medium | **Complexity:** Low | **Estimated Time:** 1 hour

**Goal:** Prevent accidental file overwrites.

**Implementation:**

In `keysword/io/writers.py`:
```python
import os
from pathlib import Path

def check_file_exists(filepath: str) -> bool:
    """Check if file exists."""
    return Path(filepath).exists()

def generate_safe_filename(base_filename: str, force: bool = False) -> str:
    """
    Generate a filename that doesn't exist, or raise error if force=False.
    """
    if not check_file_exists(base_filename):
        return base_filename
    
    if not force:
        raise FileExistsError(
            f"File {base_filename} already exists. "
            f"Use --force to overwrite or choose a different output."
        )
    
    # If force=True, allow overwrite
    return base_filename

def get_unique_filename(base_filename: str) -> str:
    """
    Generate a unique filename by appending counter if needed.
    Example: file.txt -> file_1.txt -> file_2.txt
    """
    if not check_file_exists(base_filename):
        return base_filename
    
    path = Path(base_filename)
    stem = path.stem
    suffix = path.suffix
    counter = 1
    
    while True:
        new_name = f"{stem}_{counter}{suffix}"
        if not check_file_exists(new_name):
            return new_name
        counter += 1
```

**CLI Changes:**
- Add `--force` flag to allow overwriting existing files
- Add `--auto-rename` flag to automatically generate unique filenames
- Default: raise error if file exists

**Dependencies:** 1.1 (Project Structure)

---

### 2.4 Verify Mode & Batch Verification
**Priority:** High | **Complexity:** Medium | **Estimated Time:** 3-4 hours

**Goal:** Allow verification of key generation and validation of generated keys.

**Implementation:**

Add `keysword/validation/key_validators.py`:
```python
from Crypto.PublicKey import RSA, ECC
from bitcoin import privkey_to_address, encode_privkey
import nacl.public

def verify_rsa_key(key) -> Tuple[bool, str]:
    """Verify RSA key is valid and has correct properties."""
    try:
        # Check if key can perform operations
        n = key.n
        e = key.e
        d = key.d
        
        # Basic primality checks
        if n < 2 or e < 2:
            return False, "Invalid key parameters"
        
        # Test encryption/decryption
        test_msg = 42
        encrypted = pow(test_msg, e, n)
        decrypted = pow(encrypted, d, n)
        
        if test_msg != decrypted:
            return False, "Key encryption/decryption test failed"
        
        return True, "RSA key is valid"
    except Exception as e:
        return False, f"RSA validation error: {e}"

def verify_ecc_key(key, curve='P-256') -> Tuple[bool, str]:
    """Verify ECC key is valid."""
    try:
        point = key.pointQ
        if not point:
            return False, "Invalid ECC point"
        
        # Check if point is on curve
        # This is automatically validated by pycryptodome
        
        return True, f"{curve} key is valid"
    except Exception as e:
        return False, f"ECC validation error: {e}"

def verify_bitcoin_key(privkey_hex: str) -> Tuple[bool, str]:
    """Verify Bitcoin key can generate valid address."""
    try:
        wif = encode_privkey(privkey_hex, 'wif_compressed')
        addr = privkey_to_address(privkey_hex)
        
        if not addr or not addr.startswith(('1', '3', 'bc1')):
            return False, "Invalid Bitcoin address format"
        
        return True, f"Bitcoin key is valid (address: {addr})"
    except Exception as e:
        return False, f"Bitcoin validation error: {e}"

def verify_curve25519_key(key) -> Tuple[bool, str]:
    """Verify Curve25519 key."""
    try:
        # Try to get public key
        pub = key.public_key
        
        # Keys are always 32 bytes
        if len(bytes(key)) != 32:
            return False, "Invalid key length"
        
        return True, "Curve25519 key is valid"
    except Exception as e:
        return False, f"Curve25519 validation error: {e}"
```

Add verify mode in CLI:
```python
# --verify mode: generate keys but don't save, just verify
# --verify-only: regenerate and compare with existing files
```

**CLI Changes:**
- Add `--verify` flag: Generate keys, verify them, show info, but don't save
- Add `--verify-files PATTERN` flag: Verify previously saved keys

**Dependencies:** 1.1 (Project Structure)

---

## Phase 3: Enhanced Key Generation

### 3.1 Configurable Argon2 Parameters
**Priority:** Medium | **Complexity:** Low | **Estimated Time:** 1-2 hours

**Goal:** Allow advanced users to tune KDF parameters.

**Implementation:**

Update `sha000()` function to accept parameters:
```python
def derive_key(
    password: bytes,
    iterations: int = 1,
    time_cost: int = 3,
    memory_cost: int = 102400,  # ~100 MB
    parallelism: int = 8,
    salt: bytes = None
) -> bytes:
    """
    Derive a key from password using Argon2.
    
    Args:
        password: Password bytes
        iterations: Number of times to apply Argon2
        time_cost: Argon2 time parameter (higher = slower, more secure)
        memory_cost: Argon2 memory in KiB (higher = more memory, more secure)
        parallelism: Number of parallel threads
        salt: Optional salt (default: derived from password)
    """
    if salt is None:
        salt = hashlib.sha256(password).digest()
    
    hash_result = argon2.low_level.hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost * iterations,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=argon2.low_level.Type.ID
    )
    return hash_result
```

**CLI Changes:**
- Add `--time-cost N` (default: 3)
- Add `--memory-cost N` (default: 102400, in KiB)
- Add `--parallelism N` (default: 8)
- Add presets: `--preset fast|balanced|paranoid`

**Presets:**
- `fast`: time=1, memory=32768 (32 MB)
- `balanced`: time=3, memory=102400 (100 MB) - default
- `paranoid`: time=10, memory=1048576 (1 GB)

**Dependencies:** 1.1 (Project Structure)

---

### 3.2 BIP39 Mnemonic Support
**Priority:** Medium | **Complexity:** Medium | **Estimated Time:** 3-4 hours

**Goal:** Accept BIP39 mnemonic phrases as password input.

**Implementation:**

Add new dependency: `mnemonic` (BIP39 implementation)

Add to `keysword/io/readers.py`:
```python
from mnemonic import Mnemonic

def read_mnemonic(language='english') -> bytes:
    """Read and validate BIP39 mnemonic phrase."""
    mnemo = Mnemonic(language)
    
    print("Enter your BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words):")
    phrase = input().strip()
    
    if not mnemo.check(phrase):
        raise ValueError("Invalid mnemonic phrase")
    
    # Convert mnemonic to seed (512 bits)
    seed = mnemo.to_seed(phrase, passphrase="")
    return seed

def generate_mnemonic(strength=256, language='english') -> str:
    """Generate a new BIP39 mnemonic phrase."""
    mnemo = Mnemonic(language)
    words = mnemo.generate(strength=strength)
    return words
```

**CLI Changes:**
- Add `--mnemonic` flag to use BIP39 mnemonic as input
- Add `--generate-mnemonic` to create a new mnemonic
- Add `--mnemonic-language LANG` (default: english)

**Dependencies:** 1.1 (Project Structure)

---

### 3.3 Additional Key Types
**Priority:** Medium | **Complexity:** Medium | **Estimated Time:** 4-6 hours

**Goal:** Support Ed25519, secp256k1, and Ethereum addresses.

**Implementation:**

Add to `keysword/core/generators.py`:

```python
# Ed25519 support
from nacl.signing import SigningKey

def generate_ed25519_keys(password, key_amount=1, branches=[410]):
    """Generate Ed25519 signing keys."""
    keys = []
    count = 200000
    password_bytes = password if isinstance(password, bytes) else password.encode()
    
    with progressbar.ProgressBar(max_value=key_amount) as bar:
        for index in range(key_amount):
            bar.update(index + 1)
            branch = str(branches[index % len(branches)]).encode()
            salt = password_bytes + branch
            seed = PBKDF2(password_bytes, salt=salt, dkLen=32, count=count, hmac_hash_module=SHA256)
            keys.append(SigningKey(seed))
            password_bytes = seed
    
    return list(enumerate(keys, start=1))

# secp256k1 support (Bitcoin curve, also used by Ethereum)
def generate_secp256k1_keys(password, key_amount=1, branches=[410]):
    """Generate secp256k1 keys (Bitcoin/Ethereum)."""
    keys = []
    count = 200000
    password_bytes = password if isinstance(password, bytes) else password.encode()
    
    with progressbar.ProgressBar(max_value=key_amount) as bar:
        for index in range(key_amount):
            bar.update(index + 1)
            branch = str(branches[index % len(branches)]).encode()
            salt = password_bytes + branch
            seed = PBKDF2(password_bytes, salt=salt, dkLen=32, count=count, hmac_hash_module=SHA256)
            int_seed = Integer.from_bytes(seed) % ECC._curves['secp256k1'].order
            keys.append(ECC.construct(curve='secp256k1', d=int_seed))
            password_bytes = seed
    
    return list(enumerate(keys, start=1))

# Ethereum address generation
def generate_ethereum_keys(password, key_amount=1, branches=[410]):
    """Generate Ethereum addresses from secp256k1 keys."""
    from Crypto.Hash import keccak
    
    keys = generate_secp256k1_keys(password, key_amount, branches)
    eth_keys = []
    
    for idx, key in keys:
        # Get public key point
        pub_key = key.public_key().export_key(format='DER')[26:]  # Remove header
        
        # Ethereum address is last 20 bytes of keccak256(public_key)
        k = keccak.new(digest_bits=256)
        k.update(pub_key)
        address = '0x' + k.hexdigest()[-40:]
        
        eth_keys.append((idx, {'key': key, 'address': address}))
    
    return eth_keys
```

**CLI Changes:**
- Update `--key-type` to support: `ed25519`, `secp256k1`, `ethereum`

**Dependencies:** 1.1 (Project Structure)

---

### 3.4 Additional Export Formats
**Priority:** Low | **Complexity:** Medium | **Estimated Time:** 4-5 hours

**Goal:** Support more export formats for different use cases.

**Implementation:**

Add to `keysword/core/formats.py`:

```python
from Crypto.PublicKey import RSA, ECC
from Crypto.IO import PEM, DER
import base64

class KeyFormatter:
    """Handle various key export formats."""
    
    @staticmethod
    def export_rsa_pkcs8(key) -> str:
        """Export RSA key in PKCS#8 format."""
        return key.export_key(format='PEM', pkcs=8).decode()
    
    @staticmethod
    def export_rsa_der(key) -> bytes:
        """Export RSA key in DER format."""
        return key.export_key(format='DER')
    
    @staticmethod
    def export_rsa_openssh(key) -> str:
        """Export RSA public key in OpenSSH format."""
        return key.publickey().export_key(format='OpenSSH').decode()
    
    @staticmethod
    def export_ecc_openssh(key) -> str:
        """Export ECC public key in OpenSSH format."""
        return key.public_key().export_key(format='OpenSSH').decode()
    
    @staticmethod
    def export_bitcoin_formats(privkey_hex: str) -> dict:
        """Export Bitcoin key in multiple formats."""
        from bitcoin import privkey_to_address, privkey_to_pubkey
        
        return {
            'wif': encode_privkey(privkey_hex, 'wif_compressed'),
            'wif_uncompressed': encode_privkey(privkey_hex, 'wif'),
            'hex': privkey_hex,
            'address_p2pkh': privkey_to_address(privkey_hex),
            'pubkey': privkey_to_pubkey(privkey_hex),
        }
```

**CLI Changes:**
- Add `--export-format FORMAT` for specifying format
- Options: `pem`, `der`, `pkcs8`, `openssh`, `json` (default based on key type)
- For Bitcoin: `--bitcoin-format` with options: `wif|wif_uncompressed|all`

**Dependencies:** 1.1 (Project Structure), 3.3 (Additional Key Types)

---

## Phase 4: Performance & Optimization

### 4.1 Parallelization for Multiple Keys
**Priority:** Medium | **Complexity:** High | **Estimated Time:** 5-6 hours

**Goal:** Use multiprocessing to speed up batch key generation.

**Implementation:**

Add to `keysword/core/generators.py`:

```python
from multiprocessing import Pool, cpu_count
from functools import partial

def generate_single_key(args):
    """Worker function for parallel key generation."""
    key_type, password, branches, key_number, rsa_size, index = args
    
    # Derive unique password for this key
    password_bytes = password if isinstance(password, bytes) else password.encode()
    from keysword.core.kdf import derive_key
    unique_password = derive_key(password_bytes + str(index).encode(), iterations=2)
    
    # Generate the key
    keys = make_me_keys(
        password=unique_password,
        key_type=key_type,
        key_amount=key_number,
        size_rsa=rsa_size,
        branches=branches
    )
    
    return dict(keys)[key_number]

def generate_keys_parallel(
    password,
    key_type,
    key_amount,
    branches,
    key_number,
    rsa_size=2048,
    num_workers=None
):
    """Generate multiple keys in parallel."""
    if num_workers is None:
        num_workers = min(cpu_count(), key_amount)
    
    # Prepare arguments for each worker
    args_list = [
        (key_type, password, branches, key_number, rsa_size, i)
        for i in range(key_amount)
    ]
    
    # Use multiprocessing pool
    with Pool(num_workers) as pool:
        keys = list(tqdm(
            pool.imap(generate_single_key, args_list),
            total=key_amount,
            desc="Generating keys"
        ))
    
    return keys
```

**CLI Changes:**
- Add `--parallel` flag to enable parallel generation
- Add `--workers N` to specify number of workers (default: CPU count)
- Automatic threshold: use parallel for `key_amount >= 10`

**Note:** Consider memory usage for RSA keys with many workers.

**Dependencies:** 1.1 (Project Structure)

---

### 4.2 Better Progress Information
**Priority:** Medium | **Complexity:** Low | **Estimated Time:** 2-3 hours

**Goal:** Show ETA, speed, and more detailed progress information.

**Implementation:**

Replace progressbar2 with tqdm for better features:

```python
from tqdm import tqdm
import time

class KeyGenerationProgress:
    """Enhanced progress tracking for key generation."""
    
    def __init__(self, total, desc="Generating keys"):
        self.total = total
        self.desc = desc
        self.pbar = None
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        self.pbar = tqdm(
            total=self.total,
            desc=self.desc,
            unit="key",
            bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]'
        )
        return self
    
    def __exit__(self, *args):
        self.pbar.close()
        elapsed = time.time() - self.start_time
        print(f"\nGeneration completed in {elapsed:.2f}s ({self.total/elapsed:.2f} keys/s)")
    
    def update(self, n=1):
        self.pbar.update(n)
    
    def set_postfix(self, **kwargs):
        """Add extra info to progress bar."""
        self.pbar.set_postfix(**kwargs)
```

**CLI Changes:**
- Add `--quiet` flag to suppress all progress output
- Add `--verbose` flag for detailed logging
- Show key type and parameters in progress description

**Dependencies:** Update requirements.txt to use `tqdm` instead of `progressbar2`

---

### 4.3 Deterministic Filenames (Optional Mode)
**Priority:** Low | **Complexity:** Low | **Estimated Time:** 1 hour

**Goal:** Use deterministic filenames for testing and reproducibility.

**Implementation:**

Add to `keysword/io/writers.py`:

```python
import hashlib

def generate_deterministic_filename(
    key_type: str,
    branches: list,
    key_number: int,
    key_amount: int,
    index: int = 1,
    suffix: str = ""
) -> str:
    """
    Generate a deterministic filename based on parameters.
    This makes it easy to verify regeneration produces same files.
    """
    # Create a hash of the configuration
    config = f"{key_type}_{branches}_{key_number}_{key_amount}_{index}"
    config_hash = hashlib.sha256(config.encode()).hexdigest()[:16]
    
    filename = f"{key_type}_{config_hash}"
    if suffix:
        filename += f"_{suffix}"
    
    return filename
```

**CLI Changes:**
- Add `--deterministic-names` flag to use deterministic filenames instead of timestamps

**Dependencies:** 1.1 (Project Structure)

---

## Phase 5: Testing & Quality

### 5.1 Unit Tests
**Priority:** High | **Complexity:** Medium | **Estimated Time:** 8-10 hours

**Goal:** Comprehensive unit tests for all core functionality.

**Implementation:**

Create test files in `tests/` directory:

**tests/test_kdf.py:**
```python
import pytest
from keysword.core.kdf import derive_key

class TestKDF:
    def test_deterministic_output(self):
        """Same input should produce same output."""
        password = b"test_password_123"
        key1 = derive_key(password)
        key2 = derive_key(password)
        assert key1 == key2
    
    def test_different_passwords(self):
        """Different passwords should produce different keys."""
        key1 = derive_key(b"password1")
        key2 = derive_key(b"password2")
        assert key1 != key2
    
    def test_key_length(self):
        """Output should be 32 bytes."""
        key = derive_key(b"password")
        assert len(key) == 32
    
    def test_custom_parameters(self):
        """Custom Argon2 parameters should work."""
        key = derive_key(
            b"password",
            time_cost=1,
            memory_cost=8192,
            parallelism=1
        )
        assert len(key) == 32
```

**tests/test_generators.py:**
```python
import pytest
from keysword.core.generators import (
    generate_curve25519_keys,
    generate_p256_keys,
    generate_rsa_keys,
    generate_bitcoin_keys,
)

class TestKeyGenerators:
    def test_curve25519_generation(self):
        """Test Curve25519 key generation."""
        keys = generate_curve25519_keys(
            password=b"test",
            key_amount=3,
            branches=[1, 2, 3]
        )
        assert len(keys) == 3
        assert all(len(bytes(key)) == 32 for _, key in keys)
    
    def test_deterministic_generation(self):
        """Same parameters should generate same keys."""
        keys1 = generate_rsa_keys(b"test", key_amount=2, branches=[410])
        keys2 = generate_rsa_keys(b"test", key_amount=2, branches=[410])
        
        # Compare key materials
        assert keys1[0][1].n == keys2[0][1].n
        assert keys1[1][1].n == keys2[1][1].n
    
    def test_different_branches(self):
        """Different branches should produce different keys."""
        keys1 = generate_p256_keys(b"test", branches=[1])
        keys2 = generate_p256_keys(b"test", branches=[2])
        assert keys1[0][1].d != keys2[0][1].d
```

**tests/test_validation.py:**
```python
import pytest
from keysword.validation.input_validators import (
    validate_password_strength,
    validate_branches,
)

class TestValidation:
    def test_weak_password_detection(self):
        """Weak passwords should be flagged."""
        is_strong, msg, _ = validate_password_strength("123")
        assert not is_strong
        assert "characters" in msg.lower()
    
    def test_strong_password(self):
        """Strong passwords should pass."""
        is_strong, msg, _ = validate_password_strength(
            "Th1s_is_4_Very!Strong#Password@2024"
        )
        assert is_strong
    
    def test_sequential_branches_warning(self):
        """Sequential branches should trigger warning."""
        is_strong, msg = validate_branches([1, 2, 3, 4, 5])
        assert not is_strong
        assert "sequential" in msg.lower()
```

**tests/test_integration.py:**
```python
import pytest
import tempfile
import os
from keysword.__main__ import main

class TestIntegration:
    def test_full_workflow_json(self):
        """Test complete workflow with JSON output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Simulate CLI call
            # This would require refactoring main() to accept args programmatically
            pass
    
    def test_full_workflow_separated(self):
        """Test complete workflow with separated files."""
        pass
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption."""
        pass
```

**Configure pytest:**

Create `pytest.ini`:
```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = 
    --verbose
    --cov=keysword
    --cov-report=html
    --cov-report=term-missing
```

**Dependencies:** 1.1-4.3 (All previous phases)

---

### 5.2 Integration Tests
**Priority:** Medium | **Complexity:** Medium | **Estimated Time:** 4-6 hours

**Goal:** Test real-world scenarios and key functionality.

**Implementation:**

**tests/test_key_operations.py:**
```python
import pytest
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from keysword.core.generators import generate_rsa_keys, generate_p256_keys

class TestKeyOperations:
    def test_rsa_encrypt_decrypt(self):
        """Test that generated RSA keys can encrypt/decrypt."""
        keys = generate_rsa_keys(b"test", key_amount=1, branches=[410])
        key = dict(keys)[1]
        
        # Encrypt with public key
        cipher = PKCS1_OAEP.new(key.publickey(), hashAlgo=SHA256)
        message = b"Hello, World!"
        ciphertext = cipher.encrypt(message)
        
        # Decrypt with private key
        decipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
        plaintext = decipher.decrypt(ciphertext)
        
        assert plaintext == message
    
    def test_ecc_sign_verify(self):
        """Test that generated ECC keys can sign/verify."""
        from Crypto.Signature import DSS
        
        keys = generate_p256_keys(b"test", key_amount=1, branches=[410])
        key = dict(keys)[1]
        
        # Sign message
        message = b"Test message"
        h = SHA256.new(message)
        signer = DSS.new(key, 'fips-186-3')
        signature = signer.sign(h)
        
        # Verify signature
        verifier = DSS.new(key.public_key(), 'fips-186-3')
        h = SHA256.new(message)
        verifier.verify(h, signature)  # Should not raise exception
    
    def test_bitcoin_address_generation(self):
        """Test Bitcoin address generation is valid."""
        from keysword.core.generators import generate_bitcoin_keys
        from bitcoin import privkey_to_address
        
        keys = generate_bitcoin_keys(b"test", key_amount=1, branches=[410])
        privkey = dict(keys)[1]
        
        # Generate address
        addr = privkey_to_address(privkey[:64])
        
        # Basic validation
        assert addr.startswith('1')  # P2PKH address
        assert len(addr) >= 26 and len(addr) <= 35
```

**Dependencies:** 5.1 (Unit Tests)

---

## Phase 6: User Interface

### 6.1 Interactive Mode
**Priority:** Medium | **Complexity:** Medium | **Estimated Time:** 6-8 hours

**Goal:** User-friendly interactive interface for those who don't want to use CLI flags.

**Implementation:**

Create `keysword/ui/interactive.py`:

```python
import getpass
from typing import Optional
from keysword.validation.input_validators import (
    validate_password_strength,
    validate_branches
)

class InteractiveSession:
    """Interactive mode for Keysword."""
    
    def __init__(self):
        self.config = {}
    
    def run(self):
        """Run interactive session."""
        self.print_welcome()
        self.select_key_type()
        self.select_password_source()
        self.configure_branches()
        self.configure_output()
        self.confirm_and_generate()
    
    def print_welcome(self):
        """Print welcome message."""
        print("=" * 60)
        print("  KEYSWORD - Interactive Key Generation")
        print("=" * 60)
        print("\nThis wizard will guide you through generating cryptographic keys.")
        print("Press Ctrl+C at any time to cancel.\n")
    
    def select_key_type(self):
        """Interactive key type selection."""
        print("What type of keys do you want to generate?")
        print("  1. Curve25519 (Fast, modern elliptic curve)")
        print("  2. P-256 (NIST standard elliptic curve)")
        print("  3. RSA (Traditional, widely supported)")
        print("  4. Ed25519 (Digital signatures)")
        print("  5. Bitcoin (BTC cryptocurrency)")
        print("  6. Ethereum (ETH cryptocurrency)")
        
        choice = input("\nEnter choice (1-6): ").strip()
        key_types = {
            '1': 'curve25519',
            '2': 'P-256',
            '3': 'RSA',
            '4': 'ed25519',
            '5': 'bitcoin',
            '6': 'ethereum'
        }
        
        self.config['key_type'] = key_types.get(choice, 'curve25519')
        
        if self.config['key_type'] == 'RSA':
            self.select_rsa_size()
        
        print(f"\n✓ Selected: {self.config['key_type']}")
    
    def select_rsa_size(self):
        """Select RSA key size."""
        print("\nRSA key size:")
        print("  1. 2048 bits (Fast, standard)")
        print("  2. 3072 bits (Better security)")
        print("  3. 4096 bits (Maximum security, slower)")
        
        choice = input("Enter choice (1-3, default 1): ").strip() or '1'
        sizes = {'1': 2048, '2': 3072, '3': 4096}
        self.config['rsa_size'] = sizes.get(choice, 2048)
    
    def select_password_source(self):
        """Select password input method."""
        print("\nPassword source:")
        print("  1. Type a password")
        print("  2. Use a file as password")
        print("  3. Generate BIP39 mnemonic")
        print("  4. Enter BIP39 mnemonic")
        
        choice = input("Enter choice (1-4): ").strip()
        
        if choice == '1':
            self.input_password()
        elif choice == '2':
            self.input_password_file()
        elif choice == '3':
            self.generate_mnemonic()
        elif choice == '4':
            self.input_mnemonic()
        else:
            print("Invalid choice, using password input")
            self.input_password()
    
    def input_password(self):
        """Interactive password input with validation."""
        while True:
            password = getpass.getpass("\nEnter password: ").encode()
            password2 = getpass.getpass("Confirm password: ").encode()
            
            if password != password2:
                print("✗ Passwords don't match. Try again.")
                continue
            
            # Validate strength
            is_strong, msg, details = validate_password_strength(password.decode())
            
            if not is_strong:
                print(f"\n⚠ Password strength warning: {msg}")
                print(f"  Length: {details['length']} characters")
                print(f"  Entropy: {details['entropy']:.1f} bits")
                
                proceed = input("\nProceed anyway? (y/N): ").strip().lower()
                if proceed != 'y':
                    continue
            else:
                print(f"✓ Strong password ({details['entropy']:.1f} bits entropy)")
            
            self.config['password'] = password
            break
    
    def input_password_file(self):
        """Input file path for password."""
        filepath = input("\nEnter file path: ").strip()
        try:
            with open(filepath, 'rb') as f:
                self.config['password'] = f.read()
            print(f"✓ Loaded {len(self.config['password'])} bytes from file")
        except Exception as e:
            print(f"✗ Error reading file: {e}")
            print("Falling back to password input")
            self.input_password()
    
    def configure_branches(self):
        """Configure branch policy."""
        print("\nBranch Configuration:")
        print("Branches enhance security by creating multiple key derivation paths.")
        print("\nExamples:")
        print("  Simple:   [410]")
        print("  Moderate: [410, 1337, 9999]")
        print("  Complex:  [1, 4333, 45453, 64, 99, 3245]")
        
        while True:
            branch_input = input("\nEnter branches (e.g., [1,2,3]): ").strip()
            
            try:
                # Remove quotes if present
                branch_input = branch_input.strip('"').strip("'")
                import ast
                branches = ast.literal_eval(branch_input)
                
                if not isinstance(branches, list):
                    print("✗ Must be a list")
                    continue
                
                # Validate
                is_strong, msg = validate_branches(branches)
                if not is_strong:
                    print(f"⚠ Warning: {msg}")
                    proceed = input("Proceed anyway? (y/N): ").strip().lower()
                    if proceed != 'y':
                        continue
                
                self.config['branches'] = branches
                print(f"✓ Configured {len(branches)} branch(es)")
                break
                
            except Exception as e:
                print(f"✗ Invalid format: {e}")
    
    def configure_output(self):
        """Configure key number and output options."""
        # Key number
        print("\nKey number to generate from branch tree:")
        key_number = input("Enter key number (default 1): ").strip() or "1"
        self.config['key_number'] = int(key_number)
        
        # Key amount
        print("\nHow many keys to generate?")
        key_amount = input("Enter amount (default 1): ").strip() or "1"
        self.config['key_amount'] = int(key_amount)
        
        # Save format
        print("\nOutput format:")
        print("  1. JSON (all keys in one file)")
        print("  2. Separated (private and public in separate files)")
        choice = input("Enter choice (1-2, default 1): ").strip() or '1'
        self.config['save_type'] = 'json' if choice == '1' else 'separated'
        
        # Encryption
        print("\nEncrypt output files?")
        choice = input("(y/N): ").strip().lower()
        if choice == 'y':
            enc_pass = getpass.getpass("Encryption password: ")
            enc_pass2 = getpass.getpass("Confirm encryption password: ")
            if enc_pass == enc_pass2:
                self.config['encrypt'] = True
                self.config['encryption_password'] = enc_pass
                print("✓ Output encryption enabled")
            else:
                print("✗ Passwords don't match, encryption disabled")
                self.config['encrypt'] = False
        else:
            self.config['encrypt'] = False
    
    def confirm_and_generate(self):
        """Show summary and confirm."""
        print("\n" + "=" * 60)
        print("Configuration Summary:")
        print("=" * 60)
        print(f"Key Type:     {self.config['key_type']}")
        if 'rsa_size' in self.config:
            print(f"RSA Size:     {self.config['rsa_size']} bits")
        print(f"Branches:     {self.config['branches']}")
        print(f"Key Number:   {self.config['key_number']}")
        print(f"Key Amount:   {self.config['key_amount']}")
        print(f"Output:       {self.config['save_type']}")
        print(f"Encryption:   {'Yes' if self.config.get('encrypt') else 'No'}")
        print("=" * 60)
        
        proceed = input("\nGenerate keys with this configuration? (Y/n): ").strip().lower()
        if proceed == 'n':
            print("Cancelled.")
            return
        
        # Call actual generation
        print("\nGenerating keys...")
        self.generate_keys()
    
    def generate_keys(self):
        """Call the actual key generation with configured parameters."""
        from keysword.core.generators import make_me_keys
        from keysword.core.kdf import derive_key
        from keysword.io.writers import save_keys
        
        # Implementation here would call the actual generation functions
        # This is where we integrate with the rest of the codebase
        pass
```

**CLI Changes:**
- Add `-i, --interactive` flag to launch interactive mode
- If no arguments provided, offer to launch interactive mode

**Dependencies:** ALL previous phases (1-5)

---

## Implementation Order Summary

1. **Week 1-2: Foundation**
   - 1.1 Project Structure Refactoring
   - 1.2 Setup.py / Pyproject.toml
   - 1.3 Library API

2. **Week 3: Security**
   - 2.1 Output File Encryption
   - 2.2 Key Strength Validation
   - 2.3 Output File Collision Detection
   - 2.4 Verify Mode & Batch Verification

3. **Week 4-5: Enhanced Generation**
   - 3.1 Configurable Argon2 Parameters
   - 3.2 BIP39 Mnemonic Support
   - 3.3 Additional Key Types
   - 3.4 Additional Export Formats

4. **Week 6: Performance**
   - 4.1 Parallelization
   - 4.2 Better Progress Information
   - 4.3 Deterministic Filenames

5. **Week 7-8: Testing**
   - 5.1 Unit Tests
   - 5.2 Integration Tests

6. **Week 9: Interactive Mode**
   - 6.1 Interactive Mode (last step)

---

## Testing Strategy

After each phase:
1. Run all existing tests
2. Add new tests for new features
3. Test on Windows, Linux, macOS
4. Verify backward compatibility
5. Update documentation

---

## Documentation Updates

As features are added, update:
- README.md with new examples and both usage methods (direct vs installed)
- API documentation (docstrings)
- CHANGELOG.md
- Security considerations section

**Usage Documentation Example:**
```markdown
## Installation & Usage

### Option 1: Direct Usage (No Installation)
Clone the repository and run directly:
```bash
git clone https://github.com/yourusername/keysword.git
cd keysword
pip install -r requirements.txt
python keysword.py -k RSA -b '[1,2,3]' -n 1
```

### Option 2: Install as Package
Install via pip:
```bash
pip install keysword
keysword -k RSA -b '[1,2,3]' -n 1
```

### Option 3: Use as Library
Import in your Python code:
```python
from keysword import generate_rsa_keys
keys = generate_rsa_keys(password=b"strong_pass", branches=[410], key_number=1)
```
```

---

## Breaking Changes & Migration

### Version 2.0.0

Breaking changes:
- Package structure changed
- Import paths changed
- Some CLI flags renamed for consistency

Migration guide needed for users upgrading from 1.x to 2.x.

---

## Future Considerations (Post-Implementation)

- Web interface (Flask/FastAPI)
- GUI application (PyQt/Tkinter)
- Hardware security module (HSM) integration
- Mobile app (using Kivy)
- Browser extension for web3 wallets

---

**Total Estimated Time: 9-12 weeks for full implementation**

This plan is aggressive but achievable with focused development. Each phase can be worked on somewhat independently, allowing for parallel work if multiple developers are involved.

