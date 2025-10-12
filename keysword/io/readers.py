"""Functions for reading passwords and input files."""

import getpass
import sys


def read_password_with_confirmation():
    """
    Read a password from user with confirmation.
    
    Returns:
        bytes: Password entered by user
    """
    while True:
        password = getpass.getpass('').encode()
        pass_second = getpass.getpass('').encode()
        if password == pass_second:
            return password
        else:
            print('Passwords do not match. Try again.\n')


def read_password_from_file(filepath):
    """
    Read password from a file (raw binary data).
    
    Args:
        filepath: Path to file
        
    Returns:
        bytes: File contents as password
        
    Raises:
        Exception: If file cannot be read
    """
    try:
        with open(filepath, 'rb') as f:
            return f.read()
    except Exception as e:
        raise Exception(f'Error reading password file: {e}')

