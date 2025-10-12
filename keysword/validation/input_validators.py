"""Input validation functions for passwords and configuration."""

import math
from typing import Tuple, Dict


def calculate_entropy(password: str) -> float:
    """
    Calculate Shannon entropy of password.
    
    Args:
        password: Password string to analyze
        
    Returns:
        float: Entropy in bits
    """
    if not password:
        return 0.0
    
    entropy = 0
    for x in range(256):
        p_x = password.count(chr(x)) / len(password)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy * len(password)


def validate_password_strength(password: str) -> Tuple[bool, str, Dict]:
    """
    Validate password strength and return detailed analysis.
    
    Args:
        password: Password string to validate
        
    Returns:
        tuple: (is_strong, warning_message, details_dict)
    """
    if isinstance(password, bytes):
        password = password.decode('utf-8', errors='ignore')
    
    details = {
        'length': len(password),
        'entropy': calculate_entropy(password),
        'has_upper': any(c.isupper() for c in password),
        'has_lower': any(c.islower() for c in password),
        'has_digit': any(c.isdigit() for c in password),
        'has_special': any(not c.isalnum() for c in password),
    }
    
    warnings = []
    
    if details['length'] < 16:
        warnings.append(f"Password is only {details['length']} characters (recommended: 20+)")
    
    if details['entropy'] < 50:
        warnings.append(f"Low entropy: {details['entropy']:.1f} bits (recommended: 80+)")
    
    if not (details['has_upper'] and details['has_lower'] and 
            details['has_digit'] and details['has_special']):
        warnings.append("Password should include uppercase, lowercase, digits, and special characters")
    
    is_strong = len(warnings) == 0
    message = "; ".join(warnings) if warnings else "Password strength is adequate"
    
    return is_strong, message, details


def validate_branches(branches: list) -> Tuple[bool, str]:
    """
    Validate branch configuration for security.
    
    Args:
        branches: List of branch values
        
    Returns:
        tuple: (is_strong, warning_message)
    """
    warnings = []
    
    if len(branches) == 1:
        warnings.append("Using only one branch reduces security")
    
    # Check for sequential patterns
    if len(branches) > 2:
        if branches == sorted(branches) or branches == sorted(branches, reverse=True):
            warnings.append("Sequential branches are predictable; use random values")
    
    # Check if all values are too simple
    if all(b < 1000 for b in branches):
        warnings.append("All branch values < 1000; consider using larger values")
    
    # Check for repeated values
    if len(branches) != len(set(branches)):
        warnings.append("Duplicate branch values detected; use unique values")
    
    is_strong = len(warnings) == 0
    message = "; ".join(warnings) if warnings else "Branch configuration is adequate"
    
    return is_strong, message


def validate_key_number(key_number: int, branches: list) -> Tuple[bool, str]:
    """
    Validate key number selection.
    
    Args:
        key_number: Selected key number
        branches: Branch list
        
    Returns:
        tuple: (is_valid, message)
    """
    if key_number < 1:
        return False, "Key number must be at least 1"
    
    if key_number <= 10:
        return False, f"Key number {key_number} is predictable; use a larger value (e.g., > 50)"
    
    return True, "Key number is acceptable"

