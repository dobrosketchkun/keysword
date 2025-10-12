"""Validation functions for verifying generated cryptographic keys."""

from typing import Tuple
from Crypto.PublicKey import RSA, ECC
from bitcoin import privkey_to_address, encode_privkey
import nacl.public


def verify_rsa_key(key) -> Tuple[bool, str]:
    """
    Verify RSA key is valid and has correct properties.
    
    Args:
        key: RSA key object
        
    Returns:
        tuple: (is_valid, message)
    """
    try:
        # Check if key can perform operations
        n = key.n
        e = key.e
        d = key.d
        
        # Basic primality checks
        if n < 2 or e < 2:
            return False, "Invalid key parameters"
        
        # Test encryption/decryption with small message
        test_msg = 42
        encrypted = pow(test_msg, e, n)
        decrypted = pow(encrypted, d, n)
        
        if test_msg != decrypted:
            return False, "Key encryption/decryption test failed"
        
        # Check key size
        key_size = key.size_in_bits()
        
        return True, f"RSA key is valid ({key_size} bits)"
    except Exception as e:
        return False, f"RSA validation error: {e}"


def verify_ecc_key(key, curve='P-256') -> Tuple[bool, str]:
    """
    Verify ECC key is valid.
    
    Args:
        key: ECC key object
        curve: Curve name
        
    Returns:
        tuple: (is_valid, message)
    """
    try:
        point = key.pointQ
        if not point:
            return False, "Invalid ECC point"
        
        # Check if point is on curve
        # This is automatically validated by pycryptodome
        
        # Try to export public key (should work if valid)
        pub_key = key.public_key().export_key(format='PEM')
        
        return True, f"{curve} key is valid"
    except Exception as e:
        return False, f"ECC validation error: {e}"


def verify_bitcoin_key(privkey_hex: str) -> Tuple[bool, str]:
    """
    Verify Bitcoin key can generate valid address.
    
    Args:
        privkey_hex: Private key in hex format
        
    Returns:
        tuple: (is_valid, message)
    """
    try:
        wif = encode_privkey(privkey_hex, 'wif_compressed')
        addr = privkey_to_address(privkey_hex)
        
        if not addr or not addr.startswith(('1', '3', 'bc1')):
            return False, "Invalid Bitcoin address format"
        
        return True, f"Bitcoin key is valid (address: {addr})"
    except Exception as e:
        return False, f"Bitcoin validation error: {e}"


def verify_curve25519_key(key) -> Tuple[bool, str]:
    """
    Verify Curve25519 key.
    
    Args:
        key: Curve25519 private key object
        
    Returns:
        tuple: (is_valid, message)
    """
    try:
        # Try to get public key
        pub = key.public_key
        
        # Keys are always 32 bytes
        if len(bytes(key)) != 32:
            return False, "Invalid key length"
        
        # Try to encode
        from nacl.encoding import HexEncoder
        hex_key = HexEncoder.encode(bytes(key))
        
        return True, "Curve25519 key is valid"
    except Exception as e:
        return False, f"Curve25519 validation error: {e}"


def verify_key(key, key_type: str) -> Tuple[bool, str]:
    """
    Verify a key based on its type.
    
    Args:
        key: Key object
        key_type: Type of key ('curve25519', 'P-256', 'RSA', 'bitcoin')
        
    Returns:
        tuple: (is_valid, message)
    """
    if key_type == 'curve25519':
        return verify_curve25519_key(key)
    elif key_type == 'P-256':
        return verify_ecc_key(key, curve='P-256')
    elif key_type == 'RSA':
        return verify_rsa_key(key)
    elif key_type == 'bitcoin':
        return verify_bitcoin_key(key)
    else:
        return False, f"Unknown key type: {key_type}"

