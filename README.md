# Keysword

## Description

Keysword is a comprehensive cryptographic key generation tool that generates key pairs deterministically from passwords, mnemonic phrases, or file data. Supports 7 key types (Curve25519, P-256, RSA, Bitcoin, Ed25519, secp256k1, Ethereum) with branching mechanism, optional encryption, and both CLI and interactive TUI modes.

---

      ___   _  _______  __   __  _______  _     _  _______  ______    ______  
     |   | | ||       ||  | |  ||       || | _ | ||       ||    _ |  |      | 
     |   |_| ||    ___||  |_|  ||  _____|| || || ||   _   ||   | ||  |  _    |
     |      _||   |___ |       || |_____ |       ||  | |  ||   |_||_ | | |   |
     |     |_ |    ___||_     _||_____  ||       ||  |_|  ||    __  || |_|   |
     |    _  ||   |___   |   |   _____| ||   _   ||       ||   |  | ||       |
     |___| |_||_______|  |___|  |_______||__| |__||_______||___|  |_||______| 

---

**Warning:** USE IT ONLY IF YOU KNOW WHAT YOU ARE DOING.

## Features

- **7 Key Types:** RSA, P-256, Curve25519, Ed25519, Bitcoin, secp256k1, Ethereum
- **Interactive TUI Mode:** Beautiful wizard with step-by-step guidance
- **CLI Mode:** Full command-line interface for advanced users
- **Deterministic Generation:** Same password + branches = same keys
- **Branching Security:** Hierarchical key derivation (BIP-0032-like)
- **BIP39 Mnemonic Support:** Generate and use mnemonic phrases
- **Encryption:** AES-256-GCM encryption for output files
- **Multiple Formats:** JSON or separated files
- **Export Formats:** PEM, DER, OpenSSH, Hex, Base64, WIF
- **Parallel Processing:** Fast multi-key generation
- **Password Validation:** Strength checking with warnings
- **Key Verification:** Validate generated keys
- **Argon2 KDF:** Configurable presets (Fast, Balanced, Paranoid)

## Requirements

- Python 3.x
- See `requirements.txt` for the list of dependencies.

## Installation

Install the required Python packages using pip:

```bash
pip install -r requirements.txt
```

## Usage

### Interactive Mode (Default)

Simply run Keysword without arguments to launch the beautiful TUI wizard:

```bash
python keysword.py
```

This provides a guided experience with step-by-step prompts (recommended for most users).

The interactive mode provides:
- 🎨 Beautiful terminal UI with rich formatting
- 🧙 Step-by-step guided wizard
- ✨ Real-time validation and helpful hints
- 🔐 Secure password input with confirmation
- 📊 Configuration summary before generation
- 🎲 Random branch generation option

### Command-Line Mode (Advanced)

Provide CLI arguments to prefill values in the interactive wizard:

```bash
python keysword.py -k KEY_TYPE -b BRANCHES -n NUMBER [options]
```

The TUI will launch with these values pre-filled, skipping those steps and only asking for what's missing (like password).

### Arguments

#### Optional (prefill values):
- `-k`, `--key-type`: Type of key - `curve25519`, `P-256`, `RSA`, `bitcoin`, `ed25519`, `secp256k1`, `ethereum`
- `-b`, `--branches`: Branching policy - `'[number1,number2,...]'`
- `-n`, `--number`: Key pair number from the branched tree
- `-a`, `--key-amount`: Number of final keys to generate (default: `1`)
- `-r`, `--rsa-size`: RSA key size in bits (default: `2048`)
- `-f`, `--save-type`: Save format - `json` or `separated` (default: `json`)
- `-pfile`, `--password-file`: Use file data as password
- `--encrypt`: Encrypt output files with AES-256-GCM
- `--mnemonic`: Use BIP39 mnemonic phrase as password
- `--mnemonic-language`: BIP39 language (default: english)
- `--generate-mnemonic`: Generate a new BIP39 mnemonic and exit
- `--list-languages`: List all supported BIP39 languages and exit
- `--verify`: Verify keys without saving
- `--export-format`: Export format - `default`, `all`, `pem`, `der`, `openssh`, `hex`, `base64`
- `--parallel`: Use parallel processing for multiple keys
- `--workers`: Number of parallel workers
- `--preset`: Argon2 preset - `fast`, `balanced`, `paranoid`
- `--no-warnings`: Suppress validation warnings

### Examples

#### Interactive Mode (Default)
```bash
python keysword.py
```

#### Basic Key Generation
```bash
# Curve25519 key
python keysword.py -k curve25519 -b '[1,4333,45453]' -n 77

# RSA 4096-bit key
python keysword.py -k RSA -r 4096 -b '[410,111,123]' -n 1

# Ethereum address
python keysword.py -k ethereum -b '[999,888,777]' -n 1
```

#### Advanced Usage
```bash
# Generate with encryption
python keysword.py -k P-256 -b '[1,2,3]' -n 1 --encrypt

# Use BIP39 mnemonic
python keysword.py -k bitcoin -b '[410]' -n 1 --mnemonic

# Generate from file with separated output
python keysword.py -k ed25519 -b '[111]' -n 1 -pfile myfile.bin -f separated

# Parallel generation of 100 Bitcoin keys
python keysword.py -k bitcoin -b '[410]' -n 1 -a 100 --parallel --workers 8

# Paranoid security settings
python keysword.py -k RSA -r 4096 -b '[9999,8888,7777]' -n 1 --preset paranoid --encrypt
```

#### Utility Commands
```bash
# List supported mnemonic languages
python keysword.py --list-languages

# Generate a BIP39 mnemonic phrase (English)
python keysword.py --generate-mnemonic

# Generate a BIP39 mnemonic in Chinese
python keysword.py --generate-mnemonic --mnemonic-language chinese_simplified

# Decrypt an encrypted file
python keysword.py --decrypt-file mykeys.json.enc

# Verify keys without saving
python keysword.py -k RSA -b '[1,2,3]' -n 1 --verify
```

## How It Works

The **Keysword** script generates cryptographic key pairs deterministically from either a user-provided password or raw file data by utilizing key derivation functions and a branching mechanism. Here's an overview of how it works:

### 1. Password Input

- You can provide a password by typing it, or you can use any file's raw data as the password by specifying `-pfile`.
- If a file is used, the script reads the file in binary mode and uses the raw data as the password.

### 2. Key Derivation

- **Argon2 KDF:** Memory-hard key derivation function
- **Presets:**
  - **Fast:** Quick generation for testing
  - **Balanced:** Good security/speed trade-off (default)
  - **Paranoid:** Maximum security, slower
  - **Custom:** Manual time_cost, memory_cost, parallelism
- **Salt:** Deterministically derived from password for reproducibility
- **Output:** 32-byte derived key

### 3. Branching Mechanism

- **Purpose:** To enhance security by generating multiple keys from the same password or file data.
- **Method:**
  - The user provides a list of branches (e.g., `[1,4100,4773]`).
  - For each key, the script combines the password with each branch value to create a unique salt for the PBKDF2 function.
  - This mechanism simulates hierarchical deterministic key generation (similar to BIP-0032 in Bitcoin).

### 4. Key Generation Functions

All keys are generated deterministically using PBKDF2 with branch-specific salts.

- **RSA:** Traditional public-key crypto (1024-4096 bits)
- **P-256:** NIST elliptic curve
- **Curve25519:** Modern X25519 encryption
- **Ed25519:** Fast digital signatures
- **Bitcoin:** BTC private keys, WIF, addresses (P2PKH)
- **secp256k1:** Bitcoin/Ethereum curve
- **Ethereum:** ETH addresses with checksums

### 5. Key Storage Options

- **Formats:**
  - **JSON:** All keys in one file
  - **Separated:** Private (`_secret_`) and public (`_public_` or `_address_`) in separate files
  
- **Encryption:**
  - Optional AES-256-GCM encryption with `--encrypt`
  - Separate encryption password
  - Scrypt KDF for encryption key derivation
  
- **Export Formats:**
  - PEM, DER, OpenSSH (RSA, P-256)
  - Hex, Base64 (Curve25519, Ed25519)
  - WIF, addresses (Bitcoin, Ethereum)

## Security Considerations

### Strengths
- ✅ Argon2 KDF (memory-hard, resistant to GPUs/ASICs)
- ✅ AES-256-GCM authenticated encryption
- ✅ Secure input validation (`ast.literal_eval`)
- ✅ Password strength checking
- ✅ Key verification system
- ✅ Branching adds additional security layer

### Important Warnings
- ⚠️ **Deterministic:** Same password + branches = same keys
- ⚠️ **Password Security:** Use 16+ character passwords with mixed case, numbers, symbols
- ⚠️ **Branch Privacy:** Keep branch configuration secret
- ⚠️ **Encryption:** Always use `--encrypt` for production
- ⚠️ **No Recovery:** Lost passwords cannot be recovered
- ⚠️ **File Permissions:** Secure your output files (chmod 600)
- ⚠️ **Backup:** Store passwords and configurations separately

### Best Practices
1. Use BIP39 mnemonic phrases for easier backup
2. Use Paranoid preset for long-term keys
3. Use random branches (3-6 large numbers)
4. Always encrypt output files
5. Store encryption password separately
6. Back up to offline/cold storage
7. Test key regeneration before deleting originals
8. Never commit keys to version control

### Disclaimer
This tool is for users who understand cryptographic key management. Use at your own risk. Not audited for production use.

## Converting PEM to OpenPGP Format

If you generate RSA keys using the Keysword script in PEM format, you might want to convert them to OpenPGP format for use with OpenPGP-compatible tools (such as GnuPG). One way to do this is by using the `pem2openpgp` tool.

### What is `pem2openpgp`?

`pem2openpgp` is a tool that allows you to convert RSA private keys in PEM format to OpenPGP format. This can be useful if you want to use the generated RSA key with GnuPG or any other system that works with OpenPGP keys.

### Steps to Convert a PEM RSA Key to OpenPGP

After generating an RSA key with Keysword in PEM format, follow these steps to convert it to OpenPGP format:

### 1. Install `pem2openpgp`

You can find `pem2openpgp` in several repositories or you can install it from source. Follow the instructions in the repository where it's hosted. Once installed, you can proceed to convert the PEM file.

### 2. Generate RSA Keys in PEM Format

Run the Keysword script to generate RSA keys in PEM format. Use the following command:

```bash
python keysword.py -k RSA -r 2048 -b '[1,2,3]' -n 1 -f separated
```

This will generate separate files containing the private and public RSA keys in PEM format.

### 3. Convert the Private Key to OpenPGP

`pem2openpgp` converts a **private RSA PEM key** to OpenPGP format. It automatically generates both public and private key components in the OpenPGP certificate.

**Important:** `pem2openpgp` only works with:
- RSA keys (not ECC/Ed25519/etc.)
- Unencrypted private keys (no passphrase)
- Private PEM keys only (it extracts the public key automatically)

```bash
pem2openpgp "Your Name <your@email.com>" < private_key_secret.txt > openpgp_key.gpg
```

Or with piping:

```bash
cat private_key_secret.txt | pem2openpgp "Your Name" | gpg --import
```

**Note:** You do NOT need to separately convert the public key - `pem2openpgp` generates the complete OpenPGP certificate (public + private) from just the private PEM key.

### 4. Import the OpenPGP Key to GnuPG

After converting, import it into GnuPG:

```bash
gpg --import openpgp_key.gpg
```

### 5. Verify the Keys

List your GnuPG keys to verify the import:

```bash
gpg --list-keys         # List public keys
gpg --list-secret-keys  # List private keys
```

Both should show your newly imported OpenPGP key.

### Notes:

- Ensure that `pem2openpgp` is properly installed and accessible from your command line.
- OpenPGP format is widely supported in many encryption and signing applications, so this conversion can make your Keysword-generated RSA keys more versatile.
- Be cautious when handling private keys and ensure they are stored securely.

By converting your RSA keys to OpenPGP format, you can use them in a wider variety of applications while still benefiting from the original key generation performed by the Keysword script.

## Library Usage

Keysword can be used as a Python library:

```python
from keysword import generate_rsa_keys, generate_ethereum_keys

# Generate RSA keys
rsa_keys = generate_rsa_keys(
    password=b"my_strong_password",
    branches=[410, 111, 123],
    key_number=1,
    key_amount=5,
    size=2048
)

# Generate Ethereum address
eth_keys = generate_ethereum_keys(
    password=b"my_strong_password",
    branches=[999, 888, 777],
    key_number=1,
    key_amount=1
)
```

See `keysword/__init__.py` for full API documentation.

## Testing

Run the test suite:

```bash
# Install test dependencies
pip install -r requirements.txt

# Run all tests
pytest

# Run with coverage
pytest --cov=keysword --cov-report=html

# Run specific test file
pytest tests/test_generators.py -v
```

## Package Installation

Install as a package:

```bash
# Development install
pip install -e .

# Then use as command
keysword 
```

## Project Structure

```
keysword/
├── keysword/           # Main package
│   ├── core/          # Key generation, KDF, crypto
│   ├── io/            # File I/O, encryption
│   ├── validation/    # Input/key validation
│   ├── ui/            # CLI and interactive TUI
│   └── utils/         # Helper functions
├── tests/             # Test suite (125 tests)
├── keysword.py        # Direct usage entry point
├── pyproject.toml     # Package configuration
└── requirements.txt   # Dependencies
```


## License

Use at your own risk. See LICENSE file for details.

## Conclusion

Keysword provides deterministic cryptographic key generation with branching security, encryption, and both CLI and interactive interfaces. Suitable for users who need reproducible keys from memorable passwords or mnemonic phrases, with proper security understanding.
