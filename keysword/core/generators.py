"""Key generation functions for various cryptographic key types."""

import os
import progressbar
from Crypto.PublicKey import ECC, RSA
from Crypto.Math.Numbers import Integer
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from keysword.core.crypto_utils import DeterministicRandom

# Check if we should show progress bars (disable in tests or when TERM=dumb)
SHOW_PROGRESS = os.environ.get('TERM', '') != 'dumb' and os.environ.get('KEYSWORD_NO_PROGRESS', '') != '1'


def make_curve25519_keys_pbkdf2_branched(password, key_amount=1, branches=[410], show_progress=None):
    """
    Generate multiple Curve25519 key pairs deterministically from a password.
    
    Args:
        password: Password string or bytes
        key_amount: Number of keys to generate
        branches: List of branch values for key derivation
        show_progress: Whether to show progress bar (default: auto-detect)
    
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
    
    if show_progress is None:
        show_progress = SHOW_PROGRESS
    
    if show_progress and key_amount > 1:
        bar_small = progressbar.ProgressBar(max_value=key_amount)
        bar_small.start()
    else:
        bar_small = None
    
    try:
        for index in range(key_amount):
            if bar_small:
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
    finally:
        if bar_small:
            bar_small.finish()
    
    return list(enumerate(keys, start=1))


def make_p256_keys_pbkdf2_branched(password, key_amount=1, branches=[410], show_progress=None):
    """
    Generate multiple P-256 key pairs deterministically from a password.
    
    Args:
        password: Password string or bytes
        key_amount: Number of keys to generate
        branches: List of branch values for key derivation
        show_progress: Whether to show progress bar (default: auto-detect)
    
    Returns:
        list: Enumerated list of (index, ECC.EccKey) tuples starting from 1
    """
    keys = []
    count = 200000
    if isinstance(password, str):
        password_bytes = password.encode()
    else:
        password_bytes = password
    
    if show_progress is None:
        show_progress = SHOW_PROGRESS
    
    if show_progress and key_amount > 1:
        bar_small = progressbar.ProgressBar(max_value=key_amount)
        bar_small.start()
    else:
        bar_small = None
    
    try:
        for index in range(key_amount):
            if bar_small:
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
    finally:
        if bar_small:
            bar_small.finish()
    
    return list(enumerate(keys, start=1))


def make_rsa_keys_branched(password, size=2048, key_amount=1, branches=[410], show_progress=None):
    """
    Generate multiple RSA key pairs deterministically from a password.
    
    Args:
        password: Password string or bytes
        size: RSA key size in bits (default: 2048)
        key_amount: Number of keys to generate
        branches: List of branch values for key derivation
        show_progress: Whether to show progress bar (default: auto-detect)
    
    Returns:
        list: Enumerated list of (index, RSA.RsaKey) tuples starting from 1
    """
    keys = []
    count = 100000  # Reduced for performance considerations
    if isinstance(password, str):
        password_bytes = password.encode()
    else:
        password_bytes = password
    
    if show_progress is None:
        show_progress = SHOW_PROGRESS
    
    if show_progress and key_amount > 1:
        bar_small = progressbar.ProgressBar(max_value=key_amount)
        bar_small.start()
    else:
        bar_small = None
    
    try:
        for index in range(key_amount):
            if bar_small:
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
    finally:
        if bar_small:
            bar_small.finish()
    
    return list(enumerate(keys, start=1))


def make_bitcoin_keys_branched(password, key_amount=1, branches=[410], show_progress=None):
    """
    Generate multiple Bitcoin private keys deterministically from a password.
    
    Args:
        password: Password string or bytes
        key_amount: Number of keys to generate
        branches: List of branch values for key derivation
        show_progress: Whether to show progress bar (default: auto-detect)
    
    Returns:
        list: Enumerated list of (index, hex_string) tuples starting from 1
    """
    keys = []
    count = 200000
    if isinstance(password, str):
        password_bytes = password.encode()
    else:
        password_bytes = password
    
    if show_progress is None:
        show_progress = SHOW_PROGRESS
    
    if show_progress and key_amount > 1:
        bar_small = progressbar.ProgressBar(max_value=key_amount)
        bar_small.start()
    else:
        bar_small = None
    
    try:
        for index in range(key_amount):
            if bar_small:
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
    finally:
        if bar_small:
            bar_small.finish()
    
    return list(enumerate(keys, start=1))


def make_ed25519_keys_branched(password, key_amount=1, branches=[410], show_progress=None):
    """
    Generate multiple Ed25519 signing key pairs deterministically from a password.
    
    Args:
        password: Password string or bytes
        key_amount: Number of keys to generate
        branches: List of branch values for key derivation
        show_progress: Whether to show progress bar (default: auto-detect)
    
    Returns:
        list: Enumerated list of (index, SigningKey) tuples starting from 1
    """
    keys = []
    count = 200000
    if isinstance(password, str):
        password_bytes = password.encode()
    else:
        password_bytes = password
    
    if show_progress is None:
        show_progress = SHOW_PROGRESS
    
    if show_progress and key_amount > 1:
        bar_small = progressbar.ProgressBar(max_value=key_amount)
        bar_small.start()
    else:
        bar_small = None
    
    try:
        for index in range(key_amount):
            if bar_small:
                bar_small.update(index + 1)
            branch = str(branches[index % len(branches)])
            if isinstance(branch, str):
                branch_bytes = branch.encode()
            else:
                branch_bytes = branch
            salt = password_bytes + branch_bytes
            seed = PBKDF2(password_bytes, salt=salt, dkLen=32, count=count, hmac_hash_module=SHA256)
            keys.append(SigningKey(seed))
            password_bytes = seed
    finally:
        if bar_small:
            bar_small.finish()
    
    return list(enumerate(keys, start=1))


def make_secp256k1_keys_branched(password, key_amount=1, branches=[410], show_progress=None):
    """
    Generate multiple secp256k1 key pairs deterministically from a password.
    This is the curve used by Bitcoin and Ethereum.
    
    Note: pycryptodome doesn't support secp256k1, so we use the bitcoin library instead.
    
    Args:
        password: Password string or bytes
        key_amount: Number of keys to generate
        branches: List of branch values for key derivation
        show_progress: Whether to show progress bar (default: auto-detect)
    
    Returns:
        list: Enumerated list of (index, hex_string) tuples starting from 1
    """
    # secp256k1 is not in pycryptodome, use bitcoin library approach
    return make_bitcoin_keys_branched(password, key_amount, branches, show_progress)


def make_ethereum_keys_branched(password, key_amount=1, branches=[410], show_progress=None):
    """
    Generate multiple Ethereum addresses deterministically from a password.
    Uses secp256k1 curve and derives Ethereum addresses from public keys.
    
    Args:
        password: Password string or bytes
        key_amount: Number of keys to generate
        branches: List of branch values for key derivation
        show_progress: Whether to show progress bar (default: auto-detect)
    
    Returns:
        list: Enumerated list of (index, dict) tuples with 'key' (hex) and 'address'
    """
    from Crypto.Hash import keccak
    from bitcoin import privkey_to_pubkey
    
    # Get secp256k1 private keys (as hex strings)
    secp_keys = make_secp256k1_keys_branched(password, key_amount, branches, show_progress)
    eth_keys = []
    
    for idx, key_hex in secp_keys:
        # Get uncompressed public key from bitcoin library
        # privkey_to_pubkey returns bytes
        pubkey = privkey_to_pubkey(bytes.fromhex(key_hex))
        # Convert to hex if it's bytes, otherwise it's already hex
        if isinstance(pubkey, bytes):
            pubkey_hex = pubkey.hex()
        else:
            pubkey_hex = pubkey
        # Remove '04' prefix
        pubkey_bytes = bytes.fromhex(pubkey_hex[2:])
        
        # Ethereum address is last 20 bytes of keccak256(public_key)
        k = keccak.new(digest_bits=256)
        k.update(pubkey_bytes)
        address = '0x' + k.hexdigest()[-40:]
        
        eth_keys.append((idx, {'key': key_hex, 'address': address}))
    
    return eth_keys


def make_me_keys(password, key_type, key_amount=1, size_rsa=2048, branches=[410], show_progress=None):
    """
    Generate key pairs for the specified key type deterministically from a password.
    
    Args:
        password: Password string or bytes
        key_type: Type of key ('P-256', 'curve25519', 'RSA', 'bitcoin', 'ed25519', 'secp256k1', 'ethereum')
        key_amount: Number of keys to generate
        size_rsa: RSA key size in bits (default: 2048)
        branches: List of branch values for key derivation
        show_progress: Whether to show progress bar (default: auto-detect)
    
    Returns:
        list: Enumerated list of (index, key) tuples
        
    Raises:
        ValueError: If key_type is not supported
    """
    if key_type == 'P-256':
        return make_p256_keys_pbkdf2_branched(password=password, key_amount=key_amount, branches=branches, show_progress=show_progress)
    elif key_type == 'curve25519':
        return make_curve25519_keys_pbkdf2_branched(password=password, key_amount=key_amount, branches=branches, show_progress=show_progress)
    elif key_type == 'RSA':
        return make_rsa_keys_branched(password=password, size=size_rsa, key_amount=key_amount, branches=branches, show_progress=show_progress)
    elif key_type == 'bitcoin':
        return make_bitcoin_keys_branched(password=password, key_amount=key_amount, branches=branches, show_progress=show_progress)
    elif key_type == 'ed25519':
        return make_ed25519_keys_branched(password=password, key_amount=key_amount, branches=branches, show_progress=show_progress)
    elif key_type == 'secp256k1':
        return make_secp256k1_keys_branched(password=password, key_amount=key_amount, branches=branches, show_progress=show_progress)
    elif key_type == 'ethereum':
        return make_ethereum_keys_branched(password=password, key_amount=key_amount, branches=branches, show_progress=show_progress)
    else:
        raise ValueError(f'Unsupported key type: {key_type}. Supported types: P-256, curve25519, RSA, bitcoin, ed25519, secp256k1, ethereum')

