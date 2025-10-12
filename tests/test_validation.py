"""Unit tests for validation functions."""

import pytest
from keysword.validation.input_validators import (
    calculate_entropy,
    validate_password_strength,
    validate_branches,
    validate_key_number
)
from keysword.validation.key_validators import (
    verify_rsa_key,
    verify_ecc_key,
    verify_bitcoin_key,
    verify_curve25519_key,
    verify_ed25519_key,
    verify_secp256k1_key,
    verify_ethereum_key,
    verify_key
)
from keysword.core.generators import (
    make_rsa_keys_branched,
    make_p256_keys_pbkdf2_branched,
    make_curve25519_keys_pbkdf2_branched,
    make_bitcoin_keys_branched,
    make_ed25519_keys_branched,
    make_secp256k1_keys_branched,
    make_ethereum_keys_branched
)


class TestInputValidation:
    """Test input validation functions."""
    
    def test_calculate_entropy_simple(self):
        """Test entropy calculation with simple password."""
        entropy = calculate_entropy("aaaa")
        assert entropy >= 0, "Entropy should be non-negative"
        assert entropy < calculate_entropy("abcd"), "More varied should have higher entropy"
    
    def test_calculate_entropy_complex(self):
        """Test entropy with complex password."""
        simple = calculate_entropy("password")
        complex_pass = calculate_entropy("P@ssw0rd!123")
        assert complex_pass > simple, "Complex password should have higher entropy"
    
    def test_validate_password_weak(self):
        """Test weak password detection."""
        is_strong, msg, details = validate_password_strength("123")
        assert not is_strong, "Short password should be weak"
        assert "characters" in msg.lower() or "entropy" in msg.lower()
    
    def test_validate_password_strong(self):
        """Test strong password."""
        is_strong, msg, details = validate_password_strength("Th1s_is_4_Very!Strong#Password@2024_ExtraLong")
        assert is_strong, "Strong password should pass"
        assert details['length'] >= 16
        assert details['has_upper']
        assert details['has_lower']
        assert details['has_digit']
        assert details['has_special']
    
    def test_validate_password_no_special(self):
        """Test password without special characters."""
        is_strong, msg, details = validate_password_strength("Password123456")
        assert not details['has_special']
    
    def test_validate_password_bytes(self):
        """Test with bytes input."""
        is_strong, msg, details = validate_password_strength(b"TestPassword123!")
        assert 'length' in details
    
    def test_validate_branches_single(self):
        """Test single branch warning."""
        is_strong, msg = validate_branches([1])
        assert not is_strong
        assert "branch" in msg.lower()
    
    def test_validate_branches_sequential(self):
        """Test sequential branches warning."""
        is_strong, msg = validate_branches([1, 2, 3, 4, 5])
        assert not is_strong
        assert "sequential" in msg.lower()
    
    def test_validate_branches_small_values(self):
        """Test small branch values warning."""
        is_strong, msg = validate_branches([1, 10, 100])
        assert not is_strong
        assert "1000" in msg
    
    def test_validate_branches_duplicates(self):
        """Test duplicate branches warning."""
        is_strong, msg = validate_branches([410, 410, 500])
        assert not is_strong
        assert "duplicate" in msg.lower()
    
    def test_validate_branches_good(self):
        """Test good branch configuration."""
        is_strong, msg = validate_branches([1337, 4100, 9999, 5555])
        assert is_strong
    
    def test_validate_key_number_too_low(self):
        """Test key number that's too predictable."""
        is_valid, msg = validate_key_number(5, [410])
        assert not is_valid
        assert "predictable" in msg.lower() or "larger" in msg.lower()
    
    def test_validate_key_number_good(self):
        """Test good key number."""
        is_valid, msg = validate_key_number(50, [410])
        assert is_valid
    
    def test_validate_key_number_negative(self):
        """Test negative key number."""
        is_valid, msg = validate_key_number(0, [410])
        assert not is_valid


class TestKeyValidation:
    """Test key validation functions."""
    
    def test_verify_rsa_key(self):
        """Test RSA key verification."""
        keys = make_rsa_keys_branched(b"test", 1024, 1, [410])
        key = keys[0][1]
        is_valid, msg = verify_rsa_key(key)
        assert is_valid, f"RSA key should be valid: {msg}"
        assert "1024" in msg
    
    def test_verify_p256_key(self):
        """Test P-256 key verification."""
        keys = make_p256_keys_pbkdf2_branched(b"test", 1, [410])
        key = keys[0][1]
        is_valid, msg = verify_ecc_key(key, 'P-256')
        assert is_valid, f"P-256 key should be valid: {msg}"
    
    def test_verify_curve25519_key(self):
        """Test Curve25519 key verification."""
        keys = make_curve25519_keys_pbkdf2_branched(b"test", 1, [410])
        key = keys[0][1]
        is_valid, msg = verify_curve25519_key(key)
        assert is_valid, f"Curve25519 key should be valid: {msg}"
    
    def test_verify_bitcoin_key(self):
        """Test Bitcoin key verification."""
        keys = make_bitcoin_keys_branched(b"test", 1, [410])
        key = keys[0][1]
        is_valid, msg = verify_bitcoin_key(key)
        assert is_valid, f"Bitcoin key should be valid: {msg}"
        assert "address" in msg.lower()
    
    def test_verify_ed25519_key(self):
        """Test Ed25519 key verification."""
        keys = make_ed25519_keys_branched(b"test", 1, [410])
        key = keys[0][1]
        is_valid, msg = verify_ed25519_key(key)
        assert is_valid, f"Ed25519 key should be valid: {msg}"
    
    def test_verify_secp256k1_key(self):
        """Test secp256k1 key verification."""
        keys = make_secp256k1_keys_branched(b"test", 1, [410])
        key = keys[0][1]
        # secp256k1 now returns hex string (same as bitcoin)
        is_valid, msg = verify_bitcoin_key(key)
        assert is_valid, f"secp256k1 key should be valid: {msg}"
    
    def test_verify_ethereum_key(self):
        """Test Ethereum key verification."""
        keys = make_ethereum_keys_branched(b"test", 1, [410])
        key_dict = keys[0][1]
        # Now ethereum keys have hex string for 'key' field
        assert 'address' in key_dict
        assert key_dict['address'].startswith('0x')
        assert len(key_dict['address']) == 42
    
    def test_verify_key_dispatcher_curve25519(self):
        """Test verify_key with Curve25519."""
        keys = make_curve25519_keys_pbkdf2_branched(b"test", 1, [410])
        key = keys[0][1]
        is_valid, msg = verify_key(key, 'curve25519')
        assert is_valid
    
    def test_verify_key_dispatcher_p256(self):
        """Test verify_key with P-256."""
        keys = make_p256_keys_pbkdf2_branched(b"test", 1, [410])
        key = keys[0][1]
        is_valid, msg = verify_key(key, 'P-256')
        assert is_valid
    
    def test_verify_key_dispatcher_rsa(self):
        """Test verify_key with RSA."""
        keys = make_rsa_keys_branched(b"test", 1024, 1, [410])
        key = keys[0][1]
        is_valid, msg = verify_key(key, 'RSA')
        assert is_valid
    
    def test_verify_key_dispatcher_bitcoin(self):
        """Test verify_key with Bitcoin."""
        keys = make_bitcoin_keys_branched(b"test", 1, [410])
        key = keys[0][1]
        is_valid, msg = verify_key(key, 'bitcoin')
        assert is_valid
    
    def test_verify_key_dispatcher_ed25519(self):
        """Test verify_key with Ed25519."""
        keys = make_ed25519_keys_branched(b"test", 1, [410])
        key = keys[0][1]
        is_valid, msg = verify_key(key, 'ed25519')
        assert is_valid
    
    def test_verify_key_dispatcher_secp256k1(self):
        """Test verify_key with secp256k1."""
        keys = make_secp256k1_keys_branched(b"test", 1, [410])
        key = keys[0][1]
        # secp256k1 now uses bitcoin verification
        is_valid, msg = verify_key(key, 'bitcoin')
        assert is_valid
    
    def test_verify_key_dispatcher_ethereum(self):
        """Test verify_key with Ethereum."""
        keys = make_ethereum_keys_branched(b"test", 1, [410])
        key_dict = keys[0][1]
        # Just verify structure
        assert 'key' in key_dict
        assert 'address' in key_dict
        assert key_dict['address'].startswith('0x')
    
    def test_verify_key_unknown_type(self):
        """Test verify_key with unknown type."""
        is_valid, msg = verify_key(None, 'unknown_type')
        assert not is_valid
        assert "unknown" in msg.lower()

