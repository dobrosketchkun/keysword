"""Key derivation functions using Argon2."""

import hashlib
import argon2


# Argon2 presets for different security/performance tradeoffs
ARGON2_PRESETS = {
    'fast': {
        'time_cost': 1,
        'memory_cost': 32768,  # 32 MB
        'parallelism': 4,
        'description': 'Fast generation, lower security'
    },
    'balanced': {
        'time_cost': 3,
        'memory_cost': 102400,  # 100 MB
        'parallelism': 8,
        'description': 'Balanced security and performance (default)'
    },
    'paranoid': {
        'time_cost': 10,
        'memory_cost': 1048576,  # 1 GB
        'parallelism': 8,
        'description': 'Maximum security, slow generation'
    }
}


def get_argon2_preset(preset_name):
    """
    Get Argon2 parameters for a given preset.
    
    Args:
        preset_name: Name of preset ('fast', 'balanced', 'paranoid')
        
    Returns:
        dict: Parameters for Argon2
        
    Raises:
        ValueError: If preset name is invalid
    """
    if preset_name not in ARGON2_PRESETS:
        raise ValueError(f"Invalid preset: {preset_name}. Choose from: {', '.join(ARGON2_PRESETS.keys())}")
    return ARGON2_PRESETS[preset_name].copy()


def derive_key(password, iterations=1, time_cost=3, memory_cost=102400, parallelism=8, preset=None):
    """
    Derive a key from the password using Argon2.
    
    Args:
        password: Password string or bytes
        iterations: Number of times to apply Argon2 (default: 1)
        time_cost: Argon2 time parameter (default: 3)
        memory_cost: Argon2 memory in KiB (default: 102400 = ~100MB)
        parallelism: Number of parallel threads (default: 8)
        preset: Use a preset ('fast', 'balanced', 'paranoid'). Overrides other params if set.
    
    Returns:
        bytes: 32-byte derived key
    """
    # Apply preset if specified
    if preset:
        preset_params = get_argon2_preset(preset)
        time_cost = preset_params['time_cost']
        memory_cost = preset_params['memory_cost']
        parallelism = preset_params['parallelism']
    
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

