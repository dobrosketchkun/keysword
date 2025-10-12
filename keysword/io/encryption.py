"""File encryption and decryption using AES-256-GCM."""

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes


def encrypt_data(plaintext, passphrase):
    """
    Encrypt data using AES-256-GCM with scrypt KDF.
    
    Args:
        plaintext: bytes or str - data to encrypt
        passphrase: str - encryption passphrase
    
    Returns:
        bytes: Encrypted data with salt, nonce, and tag prepended
        
    Format: salt(32) + nonce(16) + tag(16) + ciphertext
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    if isinstance(passphrase, bytes):
        passphrase = passphrase.decode('utf-8')
    
    # Generate random salt for key derivation
    salt = get_random_bytes(32)
    
    # Derive encryption key using scrypt
    # N=2^17 for good security/performance balance
    key = scrypt(passphrase, salt, key_len=32, N=2**17, r=8, p=1)
    
    # Create AES-GCM cipher
    cipher = AES.new(key, AES.MODE_GCM)
    
    # Encrypt and get authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    # Pack: salt + nonce + tag + ciphertext
    encrypted = salt + cipher.nonce + tag + ciphertext
    
    return encrypted


def decrypt_data(encrypted, passphrase):
    """
    Decrypt AES-256-GCM encrypted data.
    
    Args:
        encrypted: bytes - encrypted data with salt, nonce, tag
        passphrase: str - decryption passphrase
    
    Returns:
        bytes: Decrypted plaintext
        
    Raises:
        ValueError: If authentication fails (wrong password or corrupted data)
    """
    if isinstance(passphrase, bytes):
        passphrase = passphrase.decode('utf-8')
    
    # Unpack the data
    salt = encrypted[:32]
    nonce = encrypted[32:48]
    tag = encrypted[48:64]
    ciphertext = encrypted[64:]
    
    # Derive decryption key using scrypt with same parameters
    key = scrypt(passphrase, salt, key_len=32, N=2**17, r=8, p=1)
    
    # Create AES-GCM cipher
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    # Decrypt and verify authentication tag
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError as e:
        raise ValueError("Decryption failed. Wrong password or corrupted data.") from e


def encrypt_file(input_filepath, output_filepath, passphrase):
    """
    Encrypt a file and save to output path.
    
    Args:
        input_filepath: Path to file to encrypt
        output_filepath: Path where encrypted file will be saved
        passphrase: Encryption passphrase
    """
    with open(input_filepath, 'rb') as f:
        plaintext = f.read()
    
    encrypted = encrypt_data(plaintext, passphrase)
    
    with open(output_filepath, 'wb') as f:
        f.write(encrypted)


def decrypt_file(input_filepath, output_filepath, passphrase):
    """
    Decrypt a file and save to output path.
    
    Args:
        input_filepath: Path to encrypted file
        output_filepath: Path where decrypted file will be saved
        passphrase: Decryption passphrase
        
    Raises:
        ValueError: If decryption fails
    """
    with open(input_filepath, 'rb') as f:
        encrypted = f.read()
    
    plaintext = decrypt_data(encrypted, passphrase)
    
    with open(output_filepath, 'wb') as f:
        f.write(plaintext)

