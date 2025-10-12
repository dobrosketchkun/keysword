"""
Keysword - Deterministic cryptographic key generation from passwords.

This package allows you to generate cryptographic key pairs deterministically
from a password or file data, using branching for enhanced security.

Example usage as a library:
    >>> from keysword import generate_rsa_keys
    >>> keys = generate_rsa_keys(
    ...     password=b"my_strong_password",
    ...     branches=[410, 111, 123],
    ...     key_number=1,
    ...     key_amount=5,
    ...     size=2048
    ... )
"""

__version__ = "2.0.0"
__author__ = "Keysword Contributors"

# Import key generation functions for library API
from keysword.core.generators import (
    make_curve25519_keys_pbkdf2_branched as generate_curve25519_keys,
    make_p256_keys_pbkdf2_branched as generate_p256_keys,
    make_rsa_keys_branched as generate_rsa_keys,
    make_bitcoin_keys_branched as generate_bitcoin_keys,
    make_me_keys as generate_keys,
)

# Import key derivation function
from keysword.core.kdf import derive_key

# Import file I/O functions
from keysword.io.writers import jsoned as save_keys_json, separated as save_keys_separated
from keysword.io.readers import (
    read_password_from_file,
    read_password_with_confirmation,
    read_mnemonic,
    generate_mnemonic,
    get_supported_languages,
)

__all__ = [
    # Version info
    "__version__",
    
    # Key generation functions
    "generate_curve25519_keys",
    "generate_p256_keys",
    "generate_rsa_keys",
    "generate_bitcoin_keys",
    "generate_keys",
    
    # Key derivation
    "derive_key",
    
    # File I/O
    "save_keys_json",
    "save_keys_separated",
    "read_password_from_file",
    "read_password_with_confirmation",
    "read_mnemonic",
    "generate_mnemonic",
    "get_supported_languages",
]

