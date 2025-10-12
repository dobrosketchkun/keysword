"""Unit tests for key generation functions."""

import pytest
import os
# Disable progress bars for tests
os.environ['TERM'] = 'dumb'

from keysword.core.generators import (
    make_curve25519_keys_pbkdf2_branched,
    make_p256_keys_pbkdf2_branched,
    make_rsa_keys_branched,
    make_bitcoin_keys_branched,
    make_ed25519_keys_branched,
    make_secp256k1_keys_branched,
    make_ethereum_keys_branched,
    make_me_keys
)


class TestKeyGenerators:
    """Test key generation functions."""
    
    def test_curve25519_generation(self):
        """Test Curve25519 key generation."""
        keys = make_curve25519_keys_pbkdf2_branched(
            password=b"test",
            key_amount=3,
            branches=[1, 2, 3]
        )
        assert len(keys) == 3, "Should generate 3 keys"
        # Check key format
        for idx, key in keys:
            assert idx >= 1, "Index should start from 1"
            assert len(bytes(key)) == 32, "Curve25519 key should be 32 bytes"
    
    def test_curve25519_deterministic(self):
        """Test that Curve25519 generation is deterministic."""
        keys1 = make_curve25519_keys_pbkdf2_branched(b"test", 2, [410])
        keys2 = make_curve25519_keys_pbkdf2_branched(b"test", 2, [410])
        
        assert bytes(keys1[0][1]) == bytes(keys2[0][1]), "Keys should be deterministic"
        assert bytes(keys1[1][1]) == bytes(keys2[1][1]), "Keys should be deterministic"
    
    def test_p256_generation(self):
        """Test P-256 key generation."""
        keys = make_p256_keys_pbkdf2_branched(b"test", key_amount=2, branches=[1, 2])
        assert len(keys) == 2
        for idx, key in keys:
            assert key.has_private(), "Should have private key"
            assert 'P-256' in key.curve, "Should be P-256 curve"
    
    def test_p256_deterministic(self):
        """Test that P-256 generation is deterministic."""
        keys1 = make_p256_keys_pbkdf2_branched(b"test", 1, [410])
        keys2 = make_p256_keys_pbkdf2_branched(b"test", 1, [410])
        
        assert keys1[0][1].d == keys2[0][1].d, "Private keys should match"
    
    def test_rsa_generation(self):
        """Test RSA key generation."""
        keys = make_rsa_keys_branched(b"test", size=1024, key_amount=1, branches=[1])
        assert len(keys) == 1
        key = keys[0][1]
        assert key.has_private(), "Should have private key"
        assert key.size_in_bits() == 1024, "Should be 1024-bit key"
    
    def test_rsa_deterministic(self):
        """Test that RSA generation is deterministic."""
        keys1 = make_rsa_keys_branched(b"test", 1024, 1, [410])
        keys2 = make_rsa_keys_branched(b"test", 1024, 1, [410])
        
        assert keys1[0][1].n == keys2[0][1].n, "RSA modulus should match"
        assert keys1[0][1].e == keys2[0][1].e, "RSA exponent should match"
    
    def test_bitcoin_generation(self):
        """Test Bitcoin key generation."""
        keys = make_bitcoin_keys_branched(b"test", key_amount=2, branches=[1, 2])
        assert len(keys) == 2
        for idx, key in keys:
            assert isinstance(key, str), "Bitcoin key should be hex string"
            assert len(key) == 64, "Should be 64 hex chars (32 bytes)"
    
    def test_bitcoin_deterministic(self):
        """Test that Bitcoin generation is deterministic."""
        keys1 = make_bitcoin_keys_branched(b"test", 1, [410])
        keys2 = make_bitcoin_keys_branched(b"test", 1, [410])
        
        assert keys1[0][1] == keys2[0][1], "Bitcoin keys should match"
    
    def test_ed25519_generation(self):
        """Test Ed25519 key generation."""
        keys = make_ed25519_keys_branched(b"test", key_amount=2, branches=[1, 2])
        assert len(keys) == 2
        for idx, key in keys:
            assert len(bytes(key)) == 32, "Ed25519 key should be 32 bytes"
    
    def test_ed25519_deterministic(self):
        """Test that Ed25519 generation is deterministic."""
        keys1 = make_ed25519_keys_branched(b"test", 1, [410])
        keys2 = make_ed25519_keys_branched(b"test", 1, [410])
        
        assert bytes(keys1[0][1]) == bytes(keys2[0][1]), "Ed25519 keys should match"
    
    def test_secp256k1_generation(self):
        """Test secp256k1 key generation."""
        keys = make_secp256k1_keys_branched(b"test", key_amount=1, branches=[1])
        assert len(keys) == 1
        key = keys[0][1]
        # secp256k1 returns hex string (same as bitcoin)
        assert isinstance(key, str), "Should be hex string"
        assert len(key) == 64, "Should be 64 hex chars"
    
    def test_ethereum_generation(self):
        """Test Ethereum key generation."""
        keys = make_ethereum_keys_branched(b"test", key_amount=2, branches=[1, 2])
        assert len(keys) == 2
        # keys is [(idx, dict), (idx, dict), ...]
        # But make_ethereum_keys_branched already returns [(idx, (idx, dict))]
        # Let's check the actual structure
        for item in keys:
            # item should be (idx, dict)
            if len(item) == 2:
                idx, key_dict = item
                assert 'key' in key_dict, "Should have key"
                assert 'address' in key_dict, "Should have address"
                assert key_dict['address'].startswith('0x'), "Address should start with 0x"
                assert len(key_dict['address']) == 42, "Address should be 42 chars"
    
    def test_ethereum_deterministic(self):
        """Test that Ethereum generation is deterministic."""
        keys1 = make_ethereum_keys_branched(b"test", 1, [410])
        keys2 = make_ethereum_keys_branched(b"test", 1, [410])
        
        # keys1[0] is (index, dict) so keys1[0][1] is the dict
        dict1 = keys1[0][1]
        dict2 = keys2[0][1]
        assert dict1['address'] == dict2['address'], "Addresses should match"
    
    def test_different_branches(self):
        """Test that different branches produce different keys."""
        keys1 = make_curve25519_keys_pbkdf2_branched(b"test", 1, [1])
        keys2 = make_curve25519_keys_pbkdf2_branched(b"test", 1, [2])
        
        assert bytes(keys1[0][1]) != bytes(keys2[0][1]), "Different branches = different keys"
    
    def test_make_me_keys_curve25519(self):
        """Test make_me_keys with Curve25519."""
        keys = make_me_keys(b"test", 'curve25519', 1, branches=[410])
        assert len(keys) == 1
    
    def test_make_me_keys_p256(self):
        """Test make_me_keys with P-256."""
        keys = make_me_keys(b"test", 'P-256', 1, branches=[410])
        assert len(keys) == 1
    
    def test_make_me_keys_rsa(self):
        """Test make_me_keys with RSA."""
        keys = make_me_keys(b"test", 'RSA', 1, size_rsa=1024, branches=[410])
        assert len(keys) == 1
    
    def test_make_me_keys_bitcoin(self):
        """Test make_me_keys with Bitcoin."""
        keys = make_me_keys(b"test", 'bitcoin', 1, branches=[410])
        assert len(keys) == 1
    
    def test_make_me_keys_ed25519(self):
        """Test make_me_keys with Ed25519."""
        keys = make_me_keys(b"test", 'ed25519', 1, branches=[410])
        assert len(keys) == 1
    
    def test_make_me_keys_secp256k1(self):
        """Test make_me_keys with secp256k1."""
        keys = make_me_keys(b"test", 'secp256k1', 1, branches=[410])
        assert len(keys) == 1
    
    def test_make_me_keys_ethereum(self):
        """Test make_me_keys with Ethereum."""
        keys = make_me_keys(b"test", 'ethereum', 1, branches=[410])
        assert len(keys) == 1
    
    def test_make_me_keys_invalid_type(self):
        """Test that invalid key type raises ValueError."""
        with pytest.raises(ValueError):
            make_me_keys(b"test", 'invalid_type', 1, branches=[410])
    
    def test_string_password_conversion(self):
        """Test that string passwords are converted to bytes."""
        keys1 = make_curve25519_keys_pbkdf2_branched("password", 1, [410])
        keys2 = make_curve25519_keys_pbkdf2_branched(b"password", 1, [410])
        assert bytes(keys1[0][1]) == bytes(keys2[0][1]), "String should convert to bytes"
    
    def test_multiple_branches(self):
        """Test key generation with multiple branches."""
        branches = [1, 10, 100, 1000]
        keys = make_curve25519_keys_pbkdf2_branched(b"test", 4, branches)
        assert len(keys) == 4
        # All keys should be different
        key_bytes = [bytes(k[1]) for k in keys]
        assert len(set(key_bytes)) == 4, "All keys should be unique"

