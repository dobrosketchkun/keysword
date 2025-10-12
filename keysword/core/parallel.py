"""Parallel key generation using multiprocessing."""

import multiprocessing as mp
from functools import partial
from typing import List, Tuple, Any

from keysword.core.kdf import derive_key
from keysword.core.generators import make_me_keys


def generate_single_key_worker(args):
    """
    Worker function for parallel key generation.
    
    Args:
        args: Tuple of (key_type, password, branches, key_number, rsa_size, index, kdf_params)
        
    Returns:
        Generated key
    """
    key_type, password, branches, key_number, rsa_size, index, kdf_params = args
    
    # Derive unique password for this key using index
    password_bytes = password if isinstance(password, bytes) else password.encode()
    unique_password = derive_key(password_bytes + str(index).encode(), iterations=2, **kdf_params)
    
    # Generate the key
    keys = make_me_keys(
        password=unique_password,
        key_type=key_type,
        key_amount=key_number,
        size_rsa=rsa_size,
        branches=branches
    )
    
    # Return the specific key from the branched tree
    return dict(keys)[key_number]


def generate_keys_parallel(
    password,
    key_type: str,
    key_amount: int,
    branches: List,
    key_number: int,
    rsa_size: int = 2048,
    num_workers: int = None,
    kdf_params: dict = None,
    progress_callback=None
):
    """
    Generate multiple keys in parallel using multiprocessing.
    
    Args:
        password: Password bytes or string
        key_type: Type of key to generate
        key_amount: Number of keys to generate
        branches: Branch list for key derivation
        key_number: Specific key number to extract from each branch tree
        rsa_size: RSA key size (if generating RSA keys)
        num_workers: Number of parallel workers (default: CPU count)
        kdf_params: KDF parameters dict
        progress_callback: Optional callback function for progress updates
        
    Returns:
        List of generated keys
    """
    if kdf_params is None:
        kdf_params = {}
    
    if num_workers is None:
        num_workers = min(mp.cpu_count(), key_amount)
    
    # Prepare arguments for each worker
    args_list = [
        (key_type, password, branches, key_number, rsa_size, i, kdf_params)
        for i in range(key_amount)
    ]
    
    # Use multiprocessing pool
    keys = []
    with mp.Pool(num_workers) as pool:
        # Use imap for better progress tracking
        for i, key in enumerate(pool.imap(generate_single_key_worker, args_list)):
            keys.append(key)
            if progress_callback:
                progress_callback(i + 1, key_amount)
    
    return keys


def should_use_parallel(key_amount: int, key_type: str) -> bool:
    """
    Determine if parallel processing should be used based on key amount and type.
    
    Args:
        key_amount: Number of keys to generate
        key_type: Type of key
        
    Returns:
        bool: True if parallel processing is beneficial
    """
    # Parallel is beneficial for multiple keys, especially RSA
    if key_amount < 2:
        return False
    
    # RSA benefits greatly from parallelization even with few keys
    if key_type == 'RSA' and key_amount >= 2:
        return True
    
    # Other key types benefit with more keys
    if key_amount >= 4:
        return True
    
    return False

