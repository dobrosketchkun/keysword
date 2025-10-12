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


def read_mnemonic(language='english'):
    """
    Read and validate BIP39 mnemonic phrase from user.
    
    Args:
        language: BIP39 language (default: 'english')
        
    Returns:
        bytes: 512-bit seed derived from mnemonic
        
    Raises:
        ValueError: If mnemonic is invalid
    """
    from mnemonic import Mnemonic
    
    mnemo = Mnemonic(language)
    
    print("Enter your BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words):")
    phrase = input().strip()
    
    if not mnemo.check(phrase):
        raise ValueError("Invalid mnemonic phrase. Please check your words and try again.")
    
    # Convert mnemonic to seed (512 bits / 64 bytes)
    # Using empty passphrase by default
    seed = mnemo.to_seed(phrase, passphrase="")
    return seed


def get_supported_languages():
    """
    Get list of supported BIP39 mnemonic languages.
    
    Returns:
        list: List of supported language codes
    """
    from mnemonic import Mnemonic
    return Mnemonic.list_languages()


def generate_mnemonic(strength=256, language='english'):
    """
    Generate a new BIP39 mnemonic phrase.
    
    Args:
        strength: Entropy strength in bits (128, 160, 192, 224, 256)
        language: BIP39 language (default: 'english', use get_supported_languages() for list)
        
    Returns:
        str: Generated mnemonic phrase
        
    Raises:
        ValueError: If language is not supported
    """
    from mnemonic import Mnemonic
    
    supported = get_supported_languages()
    if language not in supported:
        raise ValueError(
            f"Language '{language}' not supported. "
            f"Supported languages: {', '.join(sorted(supported))}"
        )
    
    mnemo = Mnemonic(language)
    words = mnemo.generate(strength=strength)
    return words

