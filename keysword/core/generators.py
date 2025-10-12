"""Key generation functions for various cryptographic key types."""

import progressbar
from Crypto.PublicKey import ECC, RSA
from Crypto.Math.Numbers import Integer
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from nacl.public import PrivateKey

from keysword.core.crypto_utils import DeterministicRandom


def make_curve25519_keys_pbkdf2_branched(password, key_amount=1, branches=[410]):
    """
    Generate multiple Curve25519 key pairs deterministically from a password.
    
    Args:
        password: Password string or bytes
        key_amount: Number of keys to generate
        branches: List of branch values for key derivation
    
    Returns:
        list: Enumerated list of (index, PrivateKey) tuples starting from 1
    """
    keys = []
    # Fixed iteration count for consistent security
    count = 200000
    dkLen = 32
    if isinstance(password, str):
        password_bytes = password.encode()
    else:
        password_bytes = password
    with progressbar.ProgressBar(max_value=key_amount) as bar_small:
        for index in range(key_amount):
            bar_small.update(index + 1)
            branch = str(branches[index % len(branches)])
            if isinstance(branch, str):
                branch_bytes = branch.encode()
            else:
                branch_bytes = branch
            salt = password_bytes + branch_bytes
            key_material = PBKDF2(password_bytes, salt=salt, dkLen=dkLen, count=count, hmac_hash_module=SHA256)
            keys.append(PrivateKey(key_material))
            password_bytes = key_material
    return list(enumerate(keys, start=1))


def make_p256_keys_pbkdf2_branched(password, key_amount=1, branches=[410]):
    """
    Generate multiple P-256 key pairs deterministically from a password.
    
    Args:
        password: Password string or bytes
        key_amount: Number of keys to generate
        branches: List of branch values for key derivation
    
    Returns:
        list: Enumerated list of (index, ECC.EccKey) tuples starting from 1
    """
    keys = []
    count = 200000
    if isinstance(password, str):
        password_bytes = password.encode()
    else:
        password_bytes = password
    with progressbar.ProgressBar(max_value=key_amount) as bar_small:
        for index in range(key_amount):
            bar_small.update(index + 1)
            branch = str(branches[index % len(branches)])
            if isinstance(branch, str):
                branch_bytes = branch.encode()
            else:
                branch_bytes = branch
            salt = password_bytes + branch_bytes
            seed = PBKDF2(password_bytes, salt=salt, dkLen=32, count=count, hmac_hash_module=SHA256)
            int_seed = Integer.from_bytes(seed) % ECC._curves['P-256'].order
            keys.append(ECC.construct(curve='P-256', d=int_seed))
            password_bytes = seed
    return list(enumerate(keys, start=1))


def make_rsa_keys_branched(password, size=2048, key_amount=1, branches=[410]):
    """
    Generate multiple RSA key pairs deterministically from a password.
    
    Args:
        password: Password string or bytes
        size: RSA key size in bits (default: 2048)
        key_amount: Number of keys to generate
        branches: List of branch values for key derivation
    
    Returns:
        list: Enumerated list of (index, RSA.RsaKey) tuples starting from 1
    """
    keys = []
    count = 100000  # Reduced for performance considerations
    if isinstance(password, str):
        password_bytes = password.encode()
    else:
        password_bytes = password
    with progressbar.ProgressBar(max_value=key_amount) as bar_small:
        for index in range(key_amount):
            bar_small.update(index + 1)
            branch = str(branches[index % len(branches)])
            if isinstance(branch, str):
                branch_bytes = branch.encode()
            else:
                branch_bytes = branch
            salt = password_bytes + branch_bytes
            seed = PBKDF2(password_bytes, salt=salt, dkLen=64, count=count, hmac_hash_module=SHA256)

            # Initialize the deterministic random generator
            drbg = DeterministicRandom(seed)
            randfunc = drbg.read

            # Generate the RSA key using the deterministic randfunc
            keys.append(RSA.generate(size, randfunc=randfunc))
            password_bytes = seed
    return list(enumerate(keys, start=1))


def make_bitcoin_keys_branched(password, key_amount=1, branches=[410]):
    """
    Generate multiple Bitcoin private keys deterministically from a password.
    
    Args:
        password: Password string or bytes
        key_amount: Number of keys to generate
        branches: List of branch values for key derivation
    
    Returns:
        list: Enumerated list of (index, hex_string) tuples starting from 1
    """
    keys = []
    count = 200000
    if isinstance(password, str):
        password_bytes = password.encode()
    else:
        password_bytes = password
    with progressbar.ProgressBar(max_value=key_amount) as bar_small:
        for index in range(key_amount):
            bar_small.update(index + 1)
            branch = str(branches[index % len(branches)])
            if isinstance(branch, str):
                branch_bytes = branch.encode()
            else:
                branch_bytes = branch
            salt = password_bytes + branch_bytes
            key_material = PBKDF2(password_bytes, salt=salt, dkLen=32, count=count, hmac_hash_module=SHA256)
            keys.append(key_material.hex())
            password_bytes = key_material
    return list(enumerate(keys, start=1))


def make_me_keys(password, key_type, key_amount=1, size_rsa=2048, branches=[410]):
    """
    Generate key pairs for the specified key type deterministically from a password.
    
    Args:
        password: Password string or bytes
        key_type: Type of key ('P-256', 'curve25519', 'RSA', 'bitcoin')
        key_amount: Number of keys to generate
        size_rsa: RSA key size in bits (default: 2048)
        branches: List of branch values for key derivation
    
    Returns:
        list: Enumerated list of (index, key) tuples
        
    Raises:
        ValueError: If key_type is not supported
    """
    if key_type == 'P-256':
        return make_p256_keys_pbkdf2_branched(password=password, key_amount=key_amount, branches=branches)
    elif key_type == 'curve25519':
        return make_curve25519_keys_pbkdf2_branched(password=password, key_amount=key_amount, branches=branches)
    elif key_type == 'RSA':
        return make_rsa_keys_branched(password=password, size=size_rsa, key_amount=key_amount, branches=branches)
    elif key_type == 'bitcoin':
        return make_bitcoin_keys_branched(password=password, key_amount=key_amount, branches=branches)
    else:
        raise ValueError('Only P-256, curve25519, RSA, or bitcoin types are allowed.')

