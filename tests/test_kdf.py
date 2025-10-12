"""Unit tests for key derivation functions."""

import pytest
from keysword.core.kdf import derive_key, get_argon2_preset, ARGON2_PRESETS


class TestKDF:
    """Test key derivation functions."""
    
    def test_derive_key_deterministic(self):
        """Test that same input produces same output."""
        password = b"test_password_123"
        key1 = derive_key(password)
        key2 = derive_key(password)
        assert key1 == key2, "Same password should produce same key"
    
    def test_derive_key_different_passwords(self):
        """Test that different passwords produce different keys."""
        key1 = derive_key(b"password1")
        key2 = derive_key(b"password2")
        assert key1 != key2, "Different passwords should produce different keys"
    
    def test_derive_key_length(self):
        """Test that output is always 32 bytes."""
        key = derive_key(b"test")
        assert len(key) == 32, "Key should be 32 bytes"
    
    def test_derive_key_string_input(self):
        """Test that string input is converted to bytes."""
        key1 = derive_key("password")
        key2 = derive_key(b"password")
        assert key1 == key2, "String and bytes should produce same key"
    
    def test_derive_key_with_iterations(self):
        """Test custom iteration count."""
        key1 = derive_key(b"test", iterations=1)
        key2 = derive_key(b"test", iterations=2)
        assert key1 != key2, "Different iterations should produce different keys"
    
    def test_derive_key_with_custom_params(self):
        """Test custom Argon2 parameters."""
        key = derive_key(
            b"password",
            time_cost=1,
            memory_cost=8192,
            parallelism=1
        )
        assert len(key) == 32, "Custom params should still produce 32-byte key"
    
    def test_get_argon2_preset_fast(self):
        """Test fast preset."""
        preset = get_argon2_preset('fast')
        assert preset['time_cost'] == 1
        assert preset['memory_cost'] == 32768
        assert preset['parallelism'] == 4
    
    def test_get_argon2_preset_balanced(self):
        """Test balanced preset."""
        preset = get_argon2_preset('balanced')
        assert preset['time_cost'] == 3
        assert preset['memory_cost'] == 102400
        assert preset['parallelism'] == 8
    
    def test_get_argon2_preset_paranoid(self):
        """Test paranoid preset."""
        preset = get_argon2_preset('paranoid')
        assert preset['time_cost'] == 10
        assert preset['memory_cost'] == 1048576
        assert preset['parallelism'] == 8
    
    def test_get_argon2_preset_invalid(self):
        """Test that invalid preset raises ValueError."""
        with pytest.raises(ValueError):
            get_argon2_preset('invalid')
    
    def test_derive_key_with_preset(self):
        """Test using preset parameter."""
        key1 = derive_key(b"test", preset='fast')
        key2 = derive_key(b"test", preset='fast')
        assert key1 == key2, "Same preset should produce same key"
        assert len(key1) == 32
    
    def test_preset_overrides_params(self):
        """Test that preset overrides individual parameters."""
        # Use fast preset which has time_cost=1
        key_fast = derive_key(b"test", preset='fast')
        # Try to override with time_cost=10, but preset should win
        key_fast2 = derive_key(b"test", preset='fast', time_cost=10)
        assert key_fast == key_fast2, "Preset should override individual params"
    
    def test_empty_password(self):
        """Test with empty password."""
        key = derive_key(b"")
        assert len(key) == 32, "Empty password should still produce 32-byte key"
    
    def test_long_password(self):
        """Test with very long password."""
        long_pass = b"a" * 10000
        key = derive_key(long_pass)
        assert len(key) == 32, "Long password should produce 32-byte key"

