"""Integration tests for end-to-end key generation workflows."""

import pytest
import tempfile
import os
import json

# Disable progress bars for tests
os.environ['TERM'] = 'dumb'

from keysword.core.generators import make_me_keys
from keysword.core.kdf import derive_key
from keysword.io.writers import jsoned, separated
from keysword.io.encryption import encrypt_file, decrypt_file
from keysword.validation.key_validators import verify_key


class TestIntegration:
    """Test complete workflows."""
    
    def test_full_workflow_rsa(self):
        """Test complete RSA key generation workflow."""
        # Generate password hash
        password = b"test_password_123"
        password_hash = derive_key(password, iterations=2)
        
        # Generate keys
        keys = make_me_keys(
            password=password_hash,
            key_type='RSA',
            key_amount=1,
            size_rsa=1024,
            branches=[410, 111]
        )
        
        assert len(keys) == 1
        key = dict(keys)[1]
        
        # Verify key
        is_valid, msg = verify_key(key, 'RSA')
        assert is_valid, f"Generated RSA key should be valid: {msg}"
    
    def test_full_workflow_ethereum(self):
        """Test complete Ethereum key generation workflow."""
        password = b"eth_password"
        password_hash = derive_key(password, iterations=1)
        
        keys = make_me_keys(
            password=password_hash,
            key_type='ethereum',
            key_amount=1,
            branches=[1, 2, 3]
        )
        
        # keys is [(1, {'key': ..., 'address': ...})]
        key_dict = keys[0][1]  # Get the dict from first tuple
        
        # Check structure
        assert 'key' in key_dict
        assert 'address' in key_dict
        
        # Check address format
        assert key_dict['address'].startswith('0x')
        assert len(key_dict['address']) == 42
    
    def test_full_workflow_multiple_keys(self):
        """Test generating multiple keys of same type."""
        password = b"multi_key_password"
        all_keys = []
        
        for i in range(3):
            password_hash = derive_key(password + str(i).encode(), iterations=2)
            keys = make_me_keys(password_hash, 'curve25519', 1, branches=[410])
            key = dict(keys)[1]
            all_keys.append(key)
        
        # All keys should be different
        key_bytes = [bytes(k) for k in all_keys]
        assert len(set(key_bytes)) == 3, "All keys should be unique"
        
        # All should be valid
        for key in all_keys:
            is_valid, _ = verify_key(key, 'curve25519')
            assert is_valid
    
    def test_json_save_and_load(self):
        """Test saving keys to JSON."""
        # Save current directory
        original_dir = os.getcwd()
        tmpdir = tempfile.mkdtemp()
        
        try:
            os.chdir(tmpdir)
            
            # Generate keys
            keys = make_me_keys(b"test", 'bitcoin', 1, branches=[410])
            key = dict(keys)[1]
            
            # Format key for saving
            from bitcoin import encode_privkey, privkey_to_address
            key_bytes = bytes.fromhex(key) if isinstance(key, str) else key
            sec = encode_privkey(key_bytes, 'wif_compressed')
            addr = privkey_to_address(key_bytes)
            decoded_keys = [{'secret': sec, 'address': addr}]
            
            # Save
            jsoned(decoded_keys, 'bitcoin', encrypt=False, force=True)
            
            # Find and load the JSON file
            files = [f for f in os.listdir('.') if f.endswith('_bitcoin.json')]
            assert len(files) == 1, "Should create one JSON file"
            
            with open(files[0], 'r') as f:
                loaded = json.load(f)
            
            assert '1' in loaded
            assert loaded['1']['secret'] == sec
            assert loaded['1']['address'] == addr
        
        finally:
            # Restore directory and clean up
            os.chdir(original_dir)
            import shutil
            try:
                shutil.rmtree(tmpdir)
            except:
                pass  # Ignore cleanup errors on Windows
    
    def test_separated_save(self):
        """Test saving keys in separated files."""
        original_dir = os.getcwd()
        tmpdir = tempfile.mkdtemp()
        
        try:
            os.chdir(tmpdir)
            
            # Generate key
            keys = make_me_keys(b"test", 'P-256', 1, branches=[410])
            key = keys[0][1]
            
            # Format for saving
            sec_bytes = key.export_key(format='PEM')
            pub_bytes = key.public_key().export_key(format='PEM')
            sec = sec_bytes.decode() if isinstance(sec_bytes, bytes) else sec_bytes
            pub = pub_bytes.decode() if isinstance(pub_bytes, bytes) else pub_bytes
            decoded_keys = [{'secret': sec, 'public': pub}]
            
            # Save
            separated(decoded_keys, 'P-256', encrypt=False, force=True)
            
            # Check files
            files = os.listdir('.')
            secret_files = [f for f in files if 'secret' in f]
            public_files = [f for f in files if 'public' in f]
            
            assert len(secret_files) == 1, "Should have one secret file"
            assert len(public_files) == 1, "Should have one public file"
            
            # Verify contents
            with open(secret_files[0], 'r') as f:
                saved_secret = f.read()
            assert saved_secret == sec
        
        finally:
            os.chdir(original_dir)
            import shutil
            try:
                shutil.rmtree(tmpdir)
            except:
                pass
    
    def test_deterministic_reproducibility(self):
        """Test that same inputs produce same keys."""
        password = b"deterministic_test"
        branches = [410, 111, 222]
        
        # Generate keys twice
        keys1 = make_me_keys(password, 'ed25519', 3, branches=branches)
        keys2 = make_me_keys(password, 'ed25519', 3, branches=branches)
        
        # Should be identical
        for i in range(1, 4):
            assert bytes(dict(keys1)[i]) == bytes(dict(keys2)[i]), f"Key {i} should be deterministic"
    
    def test_encryption_workflow(self):
        """Test complete encryption workflow."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plaintext_file = os.path.join(tmpdir, "keys.json")
            encrypted_file = os.path.join(tmpdir, "keys.json.enc")
            decrypted_file = os.path.join(tmpdir, "keys_decrypted.json")
            
            # Create test data
            test_data = {"1": {"secret": "test_secret", "public": "test_public"}}
            with open(plaintext_file, 'w') as f:
                json.dump(test_data, f)
            
            # Encrypt
            encrypt_file(plaintext_file, encrypted_file, "strong_password")
            
            # Verify encrypted file exists and is different
            assert os.path.exists(encrypted_file)
            with open(encrypted_file, 'rb') as f:
                encrypted_data = f.read()
            assert b"test_secret" not in encrypted_data, "Secret should be encrypted"
            
            # Decrypt
            decrypt_file(encrypted_file, decrypted_file, "strong_password")
            
            # Verify decrypted matches original
            with open(decrypted_file, 'r') as f:
                decrypted_data = json.load(f)
            
            assert decrypted_data == test_data
    
    def test_different_key_types_same_password(self):
        """Test generating different key types with same password."""
        password = b"shared_password"
        key_types = ['curve25519', 'P-256', 'ed25519', 'bitcoin']
        
        generated_keys = {}
        for key_type in key_types:
            keys = make_me_keys(password, key_type, 1, branches=[410])
            generated_keys[key_type] = keys[0][1]
            
            # Verify each key
            is_valid, msg = verify_key(generated_keys[key_type], key_type)
            assert is_valid, f"{key_type} should be valid: {msg}"
    
    def test_branch_isolation(self):
        """Test that different branches produce isolated keys."""
        password = b"branch_test"
        
        keys_branch1 = make_me_keys(password, 'curve25519', 1, branches=[1])
        keys_branch2 = make_me_keys(password, 'curve25519', 1, branches=[2])
        keys_branch3 = make_me_keys(password, 'curve25519', 2, branches=[1, 2])
        
        key1 = bytes(keys_branch1[0][1])
        key2 = bytes(keys_branch2[0][1])
        key3_first = bytes(keys_branch3[0][1])
        key3_second = bytes(keys_branch3[1][1])
        
        # Different single branches should produce different keys
        assert key1 != key2, "Different branches should produce different keys"
        # Multi-branch generation should produce different keys
        assert key3_first != key3_second, "Different keys in same generation"
    
    def test_key_number_selection(self):
        """Test selecting different key numbers from branch tree."""
        password = b"key_number_test"
        branches = [410, 111, 222]
        
        keys = make_me_keys(password, 'curve25519', 3, branches=branches)
        keys_dict = dict(keys)
        
        # Should have 3 keys
        assert len(keys_dict) == 3
        assert 1 in keys_dict
        assert 2 in keys_dict
        assert 3 in keys_dict
        
        # All should be different
        key_bytes = [bytes(keys_dict[i]) for i in [1, 2, 3]]
        assert len(set(key_bytes)) == 3, "All keys should be unique"

