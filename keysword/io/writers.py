"""Functions for writing keys to files."""

import json
import time
import random
import getpass
import hashlib
from pathlib import Path


def generate_deterministic_filename(key_type, branches, key_number, key_amount, index=1, suffix="", extension="json"):
    """
    Generate a deterministic filename based on configuration parameters.
    This allows for reproducible file naming for testing and verification.
    
    Args:
        key_type: Type of key
        branches: Branch list
        key_number: Key number selected
        key_amount: Number of keys generated
        index: Index of this specific key (for multiple keys)
        suffix: Additional suffix (e.g., 'secret', 'public')
        extension: File extension
        
    Returns:
        str: Deterministic filename
    """
    # Create a hash of the configuration for uniqueness
    config_str = f"{key_type}_{branches}_{key_number}_{key_amount}_{index}"
    config_hash = hashlib.sha256(config_str.encode()).hexdigest()[:12]
    
    # Build filename
    parts = [key_type, f"b{len(branches)}", f"n{key_number}", config_hash]
    if suffix:
        parts.append(suffix)
    if index > 1 or key_amount > 1:
        parts.append(f"i{index}")
    
    filename = "_".join(parts) + f".{extension}"
    return filename


def check_file_collision(filepath, force=False, auto_rename=False):
    """
    Check if file exists and handle collision.
    
    Args:
        filepath: Path to check
        force: If True, allow overwrite
        auto_rename: If True, generate unique filename
        
    Returns:
        str: Final filepath to use
        
    Raises:
        FileExistsError: If file exists and force=False, auto_rename=False
    """
    path = Path(filepath)
    
    if not path.exists():
        return filepath
    
    if force:
        return filepath
    
    if auto_rename:
        stem = path.stem
        suffix = path.suffix
        counter = 1
        while True:
            new_path = path.parent / f"{stem}_{counter}{suffix}"
            if not new_path.exists():
                return str(new_path)
            counter += 1
    
    raise FileExistsError(
        f"File {filepath} already exists. "
        f"Use --force to overwrite or --auto-rename for automatic renaming."
    )


def jsoned(decoded_keys_temp_list, key_type, encrypt=False, encryption_password=None, force=False, auto_rename=False, 
           deterministic_names=False, branches=None, key_number=None, key_amount=None):
    """
    Save keys in JSON format, optionally encrypted.
    
    Args:
        decoded_keys_temp_list: List of dictionaries containing key data
        key_type: Type of key being saved
        encrypt: Whether to encrypt the output file
        encryption_password: Password for encryption (will prompt if None and encrypt=True)
        force: Allow overwriting existing files
        auto_rename: Automatically rename if file exists
        deterministic_names: Use deterministic filenames
        branches: Branch list (for deterministic names)
        key_number: Key number (for deterministic names)
        key_amount: Key amount (for deterministic names)
    """
    from keysword.utils.helpers import printed
    from keysword.io.encryption import encrypt_data
    
    decoded_keys = dict(list(enumerate(decoded_keys_temp_list, start=1)))
    j_keys = json.dumps(decoded_keys, indent=2, sort_keys=True)
    
    printed('\nWriting your keys to the file...\n')
    
    # Generate filename
    if deterministic_names and branches and key_number and key_amount:
        if encrypt:
            filename = generate_deterministic_filename(key_type, branches, key_number, key_amount, 
                                                      index=1, suffix="", extension="json.enc")
        else:
            filename = generate_deterministic_filename(key_type, branches, key_number, key_amount,
                                                      index=1, suffix="", extension="json")
    else:
        time_add = str(int(time.time()))
        if encrypt:
            filename = f"{time_add}_{key_type}.json.enc"
        else:
            filename = f"{time_add}_{key_type}.json"
    
    if encrypt:
        if encryption_password is None:
            print("Enter encryption password for output file:")
            encryption_password = getpass.getpass('')
            print("Confirm encryption password:")
            encryption_password_confirm = getpass.getpass('')
            if encryption_password != encryption_password_confirm:
                print("Passwords don't match! Saving without encryption.")
                encrypt = False
        
        if encrypt:
            filename = check_file_collision(filename, force=force, auto_rename=auto_rename)
            encrypted_data = encrypt_data(j_keys, encryption_password)
            with open(filename, 'wb') as file:
                file.write(encrypted_data)
            printed(f'Keys encrypted and saved to {filename}\n')
            return
    
    # No encryption
    filename = check_file_collision(filename, force=force, auto_rename=auto_rename)
    with open(filename, 'w') as file:
        file.write(j_keys)


def separated(decoded_keys_temp_list, key_type, encrypt=False, encryption_password=None, force=False, auto_rename=False,
              deterministic_names=False, branches=None, key_number=None, key_amount=None):
    """
    Save keys in separate text files (private and public in different files), optionally encrypted.
    
    Args:
        decoded_keys_temp_list: List of dictionaries containing key data
        key_type: Type of key being saved
        encrypt: Whether to encrypt the output files
        encryption_password: Password for encryption (will prompt if None and encrypt=True)
        force: Allow overwriting existing files
        auto_rename: Automatically rename if file exists
        deterministic_names: Use deterministic filenames
        branches: Branch list (for deterministic names)
        key_number: Key number (for deterministic names)
        key_amount: Key amount (for deterministic names)
    """
    from keysword.io.encryption import encrypt_data
    
    if encrypt and encryption_password is None:
        print("Enter encryption password for output files:")
        encryption_password = getpass.getpass('')
        print("Confirm encryption password:")
        encryption_password_confirm = getpass.getpass('')
        if encryption_password != encryption_password_confirm:
            print("Passwords don't match! Saving without encryption.")
            encrypt = False
    
    for index, keys in enumerate(decoded_keys_temp_list, start=1):
        # Generate filenames
        if deterministic_names and branches and key_number and key_amount:
            ext = "txt.enc" if encrypt else "txt"
            secret_filename = generate_deterministic_filename(key_type, branches, key_number, key_amount,
                                                             index=index, suffix="secret", extension=ext)
            public_filename = generate_deterministic_filename(key_type, branches, key_number, key_amount,
                                                             index=index, suffix="public", extension=ext)
            address_filename = generate_deterministic_filename(key_type, branches, key_number, key_amount,
                                                              index=index, suffix="address", extension=ext)
        else:
            timestamp = int(time.time())
            rand = random.random()
            if encrypt:
                secret_filename = f"{timestamp}_{rand}_{key_type}_secret_{index}.txt.enc"
                public_filename = f"{timestamp}_{rand}_{key_type}_public_{index}.txt.enc"
                address_filename = f"{timestamp}_{rand}_{key_type}_address_{index}.txt.enc"
            else:
                secret_filename = f"{timestamp}_{rand}_{key_type}_secret_{index}.txt"
                public_filename = f"{timestamp}_{rand}_{key_type}_public_{index}.txt"
                address_filename = f"{timestamp}_{rand}_{key_type}_address_{index}.txt"
        
        # Save private/secret key
        if encrypt:
            secret_filename = check_file_collision(secret_filename, force=force, auto_rename=auto_rename)
            encrypted_data = encrypt_data(keys['secret'], encryption_password)
            with open(secret_filename, 'wb') as file:
                file.write(encrypted_data)
        else:
            secret_filename = check_file_collision(secret_filename, force=force, auto_rename=auto_rename)
            with open(secret_filename, 'w') as file:
                file.write(keys['secret'])
        
        # Save public key or address
        try:
            if encrypt:
                public_filename = check_file_collision(public_filename, force=force, auto_rename=auto_rename)
                encrypted_data = encrypt_data(keys['public'], encryption_password)
                with open(public_filename, 'wb') as file:
                    file.write(encrypted_data)
            else:
                public_filename = check_file_collision(public_filename, force=force, auto_rename=auto_rename)
                with open(public_filename, 'w') as file:
                    file.write(keys['public'])
        except KeyError:
            # For Bitcoin/Ethereum, save address instead
            if encrypt:
                address_filename = check_file_collision(address_filename, force=force, auto_rename=auto_rename)
                encrypted_data = encrypt_data(keys['address'], encryption_password)
                with open(address_filename, 'wb') as file:
                    file.write(encrypted_data)
            else:
                address_filename = check_file_collision(address_filename, force=force, auto_rename=auto_rename)
                with open(address_filename, 'w') as file:
                    file.write(keys['address'])

