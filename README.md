# Keysword

## Description

Keysword is a Python script that generates cryptographic key pairs (Curve25519, P-256, RSA, or Bitcoin keys) derived deterministically from a user-provided password. By utilizing a branching mechanism and key indexing, it creates multiple keys to enhance security against attacks like rainbow tables.

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

- Generate key pairs deterministically from a strong password.
- Supports Curve25519, P-256, RSA, and Bitcoin keys.
- Implements a branching mechanism to enhance security.
- Keys can be saved in JSON format or as separate files.
- **Note:** Private keys are saved unencrypted. Ensure they are stored securely.

## Requirements

- Python 3.x
- See `requirements.txt` for the list of dependencies.

## Installation

Install the required Python packages using pip:

```bash
pip install -r requirements.txt
```

## Usage

Run the script using Python and provide the necessary arguments:

```bash
python keysword.py -k KEY_TYPE -b BRANCHES -n NUMBER [options]
```

### Arguments

- `-k`, `--key-type`: **Required.** Type of key to generate. Options: `curve25519`, `P-256`, `RSA`, `bitcoin`.
- `-b`, `--branches`: **Required.** Branching policy as a list in the format `'[number1,number2,...]'`.
- `-n`, `--number`: **Required.** Key pair number to use from the generated branched tree.
- `-r`, `--rsa-size`: RSA key size (default: `2048`).
- `-a`, `--key-amount`: Number of keys to generate (default: `1`).
- `-f`, `--save-type`: Save format. Options: `json` (default), `separated`.

### Examples

```bash
python keysword.py -k curve25519 -b '[1,4333,45453,64,99,3245]' -n 77
python keysword.py -k RSA -r 1024 -b '[410,111,123]' -n 12
python keysword.py -k P-256 -b '[1,4100,4773,199,7445]' -n 168 -a 1000
python keysword.py -k curve25519 -b '[111]' -n 77 -a 10 -f separated
```

## How It Works

The **Keysword** script generates cryptographic key pairs deterministically from a user-provided password by utilizing key derivation functions and a branching mechanism. Here's an overview of how it works:

### 1. Password Input

- The script prompts the user to enter a password twice to ensure accuracy.
- The `getpass` module is used to securely input the password without displaying it on the screen.

### 2. Key Derivation (`sha000` Function)

- **Purpose:** To derive a secure key from the user's password.
- **Method:**
  - Uses the **Argon2** key derivation function (KDF) from the `argon2` library.
  - **Parameters:**
    - `iterations`: Number of times the Argon2 function is applied (default is 1).
    - `time_cost`, `memory_cost`, `parallelism`: Parameters defining the computational expense of the function.
  - **Salt Generation:**
    - A salt is derived from the password using SHA-256 hashing (`hashlib.sha256(password.encode()).digest()`).
    - Note: While using a password-derived salt isn't ideal, it maintains the deterministic nature of the key generation.
- **Output:**
  - The function returns a hexadecimal representation of the derived key.

### 3. Branching Mechanism

- **Purpose:** To enhance security by generating multiple keys from the same password.
- **Method:**
  - The user provides a list of branches (e.g., `[1,4100,4773]`).
  - For each key, the script combines the password with each branch value to create a unique salt for the PBKDF2 function.
  - This mechanism simulates hierarchical deterministic key generation (similar to BIP-0032 in Bitcoin).

### 4. Key Generation Functions

- **General Approach:**
  - For each key type, a specific function generates keys deterministically using PBKDF2.
  - A fixed iteration count (`count = 200000`) ensures consistent security.

- **Key Types:**

  #### a. Curve25519 Keys (`make_curve25519_keys_pbkdf2_branched`)

  - **Process:**
    - Uses PBKDF2 with the derived password and branch-specific salt.
    - Generates a 32-byte key material used to create a Curve25519 private key.
    - Derives the public key from the private key.

  #### b. P-256 Keys (`make_p256_keys_pbkdf2_branched`)

  - **Process:**
    - Similar to Curve25519 key generation.
    - Constructs an ECC key using the derived seed modulo the curve order.

  #### c. RSA Keys (`make_rsa_keys_branched`)

  - **Process:**
    - Uses PBKDF2 to derive a seed for key generation.
    - The seed initializes a deterministic random number generator for RSA key creation.
    - Generates RSA key pairs with the specified key size.

  #### d. Bitcoin Keys (`make_bitcoin_keys_pbkdf2_branched`)

  - **Process:**
    - Generates a private key using PBKDF2.
    - Converts the private key to a Wallet Import Format (WIF) using `encode_privkey`.
    - Derives the corresponding Bitcoin address using `privkey_to_address`.

### 5. Key Storage Options

- **Formats:**
  - **JSON Format:**
    - All keys are saved in a single JSON file.
    - Useful for organizing and accessing multiple keys.
  - **Separated Files:**
    - Each key pair is saved in separate text files.
    - The private key and public key (or address) are stored together.
- **Note:**
  - Private keys are saved **unencrypted**.
  - Users must ensure these files are stored securely.

## Security Considerations

- **Deterministic Generation:**
  - Keys are generated deterministically from the password and branch values.
  - If someone knows your password and branching strategy, they can regenerate your keys.
- **Password Strength:**
  - Use a strong, unique password to prevent brute-force or dictionary attacks.
  - Longer passwords with a mix of characters increase security.
- **No External Salt:**
  - The script derives salts from the password to maintain determinism.
  - Be aware that this is less secure than using random, unique salts.
- **Private Key Safety:**
  - Private keys are saved in plaintext.
  - Immediately move them to a secure location and consider encrypting them.
- **Usage Warning:**
  - This script is intended for users who understand the security implications.
  - Not recommended for production environments without further security measures.
- **Disclaimer:**
  - This script is for experimental purposes. Use at your own risk.

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

### 3. Convert the Private Key

Once you have the private key in PEM format, you can use `pem2openpgp` to convert it to OpenPGP format.

```bash
pem2openpgp -i private_key.pem -o private_key.gpg
```

In this example:
- `-i` specifies the input PEM file (`private_key.pem`).
- `-o` specifies the output file in OpenPGP format (`private_key.gpg`).

### 4. Convert the Public Key

Similarly, you can convert the public key from PEM format to OpenPGP format:

```bash
pem2openpgp -i public_key.pem -o public_key.gpg
```

### 5. Import the OpenPGP Key to GnuPG

After converting the key, you can import it into GnuPG for use with OpenPGP:

```bash
gpg --import private_key.gpg
gpg --import public_key.gpg
```

### 6. Verify the Keys

After importing, you can list your GnuPG keys to verify that the conversion was successful:

```bash
gpg --list-keys
```

This should show your newly imported OpenPGP key.

### Notes:

- Ensure that `pem2openpgp` is properly installed and accessible from your command line.
- OpenPGP format is widely supported in many encryption and signing applications, so this conversion can make your Keysword-generated RSA keys more versatile.
- Be cautious when handling private keys and ensure they are stored securely.

By converting your RSA keys to OpenPGP format, you can use them in a wider variety of applications while still benefiting from the original key generation performed by the Keysword script.

## Conclusion

The **Keysword** script allows users to generate cryptographic key pairs solely from a password, using deterministic methods enhanced by a branching mechanism. This can be useful in scenarios where users need to recreate keys without storing them but comes with significant security considerations that must be carefully managed.
