"""Key derivation functions using Argon2."""

import hashlib
import argon2


def derive_key(password, iterations=1, time_cost=3, memory_cost=102400, parallelism=8):
    """
    Derive a key from the password using Argon2.
    
    Args:
        password: Password string or bytes
        iterations: Number of times to apply Argon2 (default: 1)
        time_cost: Argon2 time parameter (default: 3)
        memory_cost: Argon2 memory in KiB (default: 102400 = ~100MB)
        parallelism: Number of parallel threads (default: 8)
    
    Returns:
        bytes: 32-byte derived key
    """
    # Since we can't use an external salt, we'll derive a salt from the password.
    # This is not ideal, but necessary given the constraints.
    if isinstance(password, str):
        password_bytes = password.encode()
    else:
        password_bytes = password
    
    salt = hashlib.sha256(password_bytes).digest()
    
    hash_result = argon2.low_level.hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=time_cost * iterations,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=argon2.low_level.Type.ID
    )
    return hash_result


# Legacy name for backward compatibility
sha000 = derive_key

