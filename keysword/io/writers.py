"""Functions for writing keys to files."""

import json
import time
import random
import getpass
from pathlib import Path


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


def jsoned(decoded_keys_temp_list, key_type, encrypt=False, encryption_password=None, force=False, auto_rename=False):
    """
    Save keys in JSON format, optionally encrypted.
    
    Args:
        decoded_keys_temp_list: List of dictionaries containing key data
        key_type: Type of key being saved
        encrypt: Whether to encrypt the output file
        encryption_password: Password for encryption (will prompt if None and encrypt=True)
        force: Allow overwriting existing files
        auto_rename: Automatically rename if file exists
    """
    from keysword.utils.helpers import printed
    from keysword.io.encryption import encrypt_data
    
    decoded_keys = dict(list(enumerate(decoded_keys_temp_list, start=1)))
    j_keys = json.dumps(decoded_keys, indent=2, sort_keys=True)
    
    printed('\nWriting your keys to the file...\n')
    time_add = str(int(time.time()))
    
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
            filename = f"{time_add}_{key_type}.json.enc"
            filename = check_file_collision(filename, force=force, auto_rename=auto_rename)
            encrypted_data = encrypt_data(j_keys, encryption_password)
            with open(filename, 'wb') as file:
                file.write(encrypted_data)
            printed(f'Keys encrypted and saved to {filename}\n')
            return
    
    # No encryption
    filename = f"{time_add}_{key_type}.json"
    filename = check_file_collision(filename, force=force, auto_rename=auto_rename)
    with open(filename, 'w') as file:
        file.write(j_keys)


def separated(decoded_keys_temp_list, key_type, encrypt=False, encryption_password=None, force=False, auto_rename=False):
    """
    Save keys in separate text files (private and public in different files), optionally encrypted.
    
    Args:
        decoded_keys_temp_list: List of dictionaries containing key data
        key_type: Type of key being saved
        encrypt: Whether to encrypt the output files
        encryption_password: Password for encryption (will prompt if None and encrypt=True)
        force: Allow overwriting existing files
        auto_rename: Automatically rename if file exists
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
        timestamp = int(time.time())
        rand = random.random()
        
        # Save private/secret key
        if encrypt:
            secret_filename = f"{timestamp}_{rand}_{key_type}_secret_{index}.txt.enc"
            secret_filename = check_file_collision(secret_filename, force=force, auto_rename=auto_rename)
            encrypted_data = encrypt_data(keys['secret'], encryption_password)
            with open(secret_filename, 'wb') as file:
                file.write(encrypted_data)
        else:
            secret_filename = f"{timestamp}_{rand}_{key_type}_secret_{index}.txt"
            secret_filename = check_file_collision(secret_filename, force=force, auto_rename=auto_rename)
            with open(secret_filename, 'w') as file:
                file.write(keys['secret'])
        
        # Save public key or address
        try:
            if encrypt:
                public_filename = f"{timestamp}_{rand}_{key_type}_public_{index}.txt.enc"
                public_filename = check_file_collision(public_filename, force=force, auto_rename=auto_rename)
                encrypted_data = encrypt_data(keys['public'], encryption_password)
                with open(public_filename, 'wb') as file:
                    file.write(encrypted_data)
            else:
                public_filename = f"{timestamp}_{rand}_{key_type}_public_{index}.txt"
                public_filename = check_file_collision(public_filename, force=force, auto_rename=auto_rename)
                with open(public_filename, 'w') as file:
                    file.write(keys['public'])
        except KeyError:
            # For Bitcoin, save address instead
            if encrypt:
                address_filename = f"{timestamp}_{rand}_{key_type}_address_{index}.txt.enc"
                address_filename = check_file_collision(address_filename, force=force, auto_rename=auto_rename)
                encrypted_data = encrypt_data(keys['address'], encryption_password)
                with open(address_filename, 'wb') as file:
                    file.write(encrypted_data)
            else:
                address_filename = f"{timestamp}_{rand}_{key_type}_address_{index}.txt"
                address_filename = check_file_collision(address_filename, force=force, auto_rename=auto_rename)
                with open(address_filename, 'w') as file:
                    file.write(keys['address'])

