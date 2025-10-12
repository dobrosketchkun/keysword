"""Unit tests for input readers (mnemonic, files)."""

import pytest
import tempfile
import os

from keysword.io.readers import (
    read_password_from_file,
    generate_mnemonic,
    # read_mnemonic - interactive, can't test easily
    # read_password_with_confirmation - interactive
)


class TestReaders:
    """Test input reading functions."""
    
    def test_read_password_from_file(self):
        """Test reading password from file."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            test_password = b"test_file_password_123"
            f.write(test_password)
            temp_path = f.name
        
        try:
            password = read_password_from_file(temp_path)
            assert password == test_password
        finally:
            os.unlink(temp_path)
    
    def test_read_password_from_nonexistent_file(self):
        """Test reading from nonexistent file."""
        with pytest.raises(Exception):
            read_password_from_file("nonexistent_file_12345.txt")
    
    def test_generate_mnemonic_default(self):
        """Test BIP39 mnemonic generation with default strength."""
        mnemonic = generate_mnemonic()
        
        # Default is 256 bits = 24 words
        words = mnemonic.split()
        assert len(words) == 24, "Default should be 24 words"
        
        # Check it's valid English words
        assert all(isinstance(w, str) and len(w) > 0 for w in words)
    
    def test_generate_mnemonic_128_bits(self):
        """Test 128-bit mnemonic (12 words)."""
        mnemonic = generate_mnemonic(strength=128)
        words = mnemonic.split()
        assert len(words) == 12, "128 bits should be 12 words"
    
    def test_generate_mnemonic_160_bits(self):
        """Test 160-bit mnemonic (15 words)."""
        mnemonic = generate_mnemonic(strength=160)
        words = mnemonic.split()
        assert len(words) == 15
    
    def test_generate_mnemonic_192_bits(self):
        """Test 192-bit mnemonic (18 words)."""
        mnemonic = generate_mnemonic(strength=192)
        words = mnemonic.split()
        assert len(words) == 18
    
    def test_generate_mnemonic_224_bits(self):
        """Test 224-bit mnemonic (21 words)."""
        mnemonic = generate_mnemonic(strength=224)
        words = mnemonic.split()
        assert len(words) == 21
    
    def test_generate_mnemonic_256_bits(self):
        """Test 256-bit mnemonic (24 words)."""
        mnemonic = generate_mnemonic(strength=256)
        words = mnemonic.split()
        assert len(words) == 24
    
    def test_generate_mnemonic_randomness(self):
        """Test that different calls generate different mnemonics."""
        mnemonic1 = generate_mnemonic()
        mnemonic2 = generate_mnemonic()
        
        # Should be different (astronomically unlikely to be same)
        assert mnemonic1 != mnemonic2
    
    def test_generate_mnemonic_language(self):
        """Test mnemonic generation with different language."""
        # Just test it doesn't crash - actual validation requires language wordlist
        mnemonic = generate_mnemonic(language='english')
        assert len(mnemonic.split()) == 24

