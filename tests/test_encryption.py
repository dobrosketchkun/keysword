"""Unit tests for encryption and decryption."""

import pytest
import tempfile
import os
from keysword.io.encryption import encrypt_data, decrypt_data, encrypt_file, decrypt_file


class TestEncryption:
    """Test encryption and decryption functions."""
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test that encryption and decryption work together."""
        plaintext = b"This is a test message"
        passphrase = "strong_password_123"
        
        encrypted = encrypt_data(plaintext, passphrase)
        decrypted = decrypt_data(encrypted, passphrase)
        
        assert decrypted == plaintext, "Decrypted should match original"
    
    def test_encrypt_decrypt_string(self):
        """Test with string input."""
        plaintext = "This is a test string"
        passphrase = "password"
        
        encrypted = encrypt_data(plaintext, passphrase)
        decrypted = decrypt_data(encrypted, passphrase)
        
        assert decrypted.decode('utf-8') == plaintext, "String should work"
    
    def test_wrong_password(self):
        """Test that wrong password fails decryption."""
        plaintext = b"secret message"
        encrypted = encrypt_data(plaintext, "correct_password")
        
        with pytest.raises(ValueError):
            decrypt_data(encrypted, "wrong_password")
    
    def test_encrypted_format(self):
        """Test that encrypted data has correct format."""
        plaintext = b"test"
        encrypted = encrypt_data(plaintext, "password")
        
        # Format: salt(32) + nonce(16) + tag(16) + ciphertext
        assert len(encrypted) >= 64, "Should have at least salt+nonce+tag"
        
        # Salt should be 32 bytes
        salt = encrypted[:32]
        assert len(salt) == 32
        
        # Nonce should be 16 bytes
        nonce = encrypted[32:48]
        assert len(nonce) == 16
        
        # Tag should be 16 bytes
        tag = encrypted[48:64]
        assert len(tag) == 16
    
    def test_different_passwords_different_output(self):
        """Test that same plaintext with different passwords produces different ciphertexts."""
        plaintext = b"message"
        encrypted1 = encrypt_data(plaintext, "password1")
        encrypted2 = encrypt_data(plaintext, "password2")
        
        assert encrypted1 != encrypted2, "Different passwords should produce different ciphertext"
    
    def test_same_plaintext_different_salt(self):
        """Test that same plaintext+password produces different ciphertext (due to random salt)."""
        plaintext = b"message"
        passphrase = "password"
        encrypted1 = encrypt_data(plaintext, passphrase)
        encrypted2 = encrypt_data(plaintext, passphrase)
        
        # Different because of random salt
        assert encrypted1 != encrypted2, "Random salt should make ciphertext different"
        
        # But both should decrypt to same plaintext
        assert decrypt_data(encrypted1, passphrase) == plaintext
        assert decrypt_data(encrypted2, passphrase) == plaintext
    
    def test_empty_plaintext(self):
        """Test with empty plaintext."""
        plaintext = b""
        passphrase = "password"
        
        encrypted = encrypt_data(plaintext, passphrase)
        decrypted = decrypt_data(encrypted, passphrase)
        
        assert decrypted == plaintext, "Empty plaintext should work"
    
    def test_large_plaintext(self):
        """Test with large plaintext."""
        plaintext = b"x" * 1000000  # 1 MB
        passphrase = "password"
        
        encrypted = encrypt_data(plaintext, passphrase)
        decrypted = decrypt_data(encrypted, passphrase)
        
        assert decrypted == plaintext, "Large plaintext should work"
    
    def test_special_characters(self):
        """Test with special characters."""
        plaintext = "Hello 世界 🔑 \n\t\r".encode('utf-8')
        passphrase = "pássword123!@#"
        
        encrypted = encrypt_data(plaintext, passphrase)
        decrypted = decrypt_data(encrypted, passphrase)
        
        assert decrypted == plaintext, "Special chars should work"
    
    def test_file_encryption_roundtrip(self):
        """Test encrypt_file and decrypt_file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, "test.txt")
            encrypted_file = os.path.join(tmpdir, "test.txt.enc")
            output_file = os.path.join(tmpdir, "test_decrypted.txt")
            
            # Write test data
            test_data = b"This is test file content"
            with open(input_file, 'wb') as f:
                f.write(test_data)
            
            # Encrypt
            encrypt_file(input_file, encrypted_file, "password")
            
            # Decrypt
            decrypt_file(encrypted_file, output_file, "password")
            
            # Verify
            with open(output_file, 'rb') as f:
                decrypted_data = f.read()
            
            assert decrypted_data == test_data, "File roundtrip should work"
    
    def test_file_decryption_wrong_password(self):
        """Test that file decryption fails with wrong password."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, "test.txt")
            encrypted_file = os.path.join(tmpdir, "test.txt.enc")
            output_file = os.path.join(tmpdir, "test_decrypted.txt")
            
            with open(input_file, 'wb') as f:
                f.write(b"secret")
            
            encrypt_file(input_file, encrypted_file, "correct")
            
            with pytest.raises(ValueError):
                decrypt_file(encrypted_file, output_file, "wrong")
    
    def test_corrupted_data(self):
        """Test that corrupted encrypted data fails decryption."""
        plaintext = b"test"
        encrypted = encrypt_data(plaintext, "password")
        
        # Corrupt the ciphertext
        corrupted = encrypted[:-1] + b'X'
        
        with pytest.raises(ValueError):
            decrypt_data(corrupted, "password")
    
    def test_truncated_data(self):
        """Test that truncated data fails."""
        plaintext = b"test"
        encrypted = encrypt_data(plaintext, "password")
        
        # Truncate
        truncated = encrypted[:50]
        
        with pytest.raises((ValueError, IndexError)):
            decrypt_data(truncated, "password")

