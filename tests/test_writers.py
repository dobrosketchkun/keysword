"""Unit tests for file writers (collision detection, deterministic names)."""

import pytest
import tempfile
import os
import json

from keysword.io.writers import (
    check_file_collision,
    generate_deterministic_filename,
    jsoned,
    separated
)


class TestWriters:
    """Test file writing functions."""
    
    def test_check_file_collision_no_file(self):
        """Test collision check when file doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "nonexistent.txt")
            # Should return the same path (no collision)
            result = check_file_collision(filepath, force=False, auto_rename=False)
            assert result == filepath
    
    def test_check_file_collision_force(self):
        """Test force overwrite."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test.txt")
            # Create file
            with open(filepath, 'w') as f:
                f.write("existing")
            
            # Force should return same path
            result = check_file_collision(filepath, force=True, auto_rename=False)
            assert result == filepath
    
    def test_check_file_collision_auto_rename(self):
        """Test auto-rename on collision."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test.txt")
            # Create file
            with open(filepath, 'w') as f:
                f.write("existing")
            
            # Auto-rename should return different path
            result = check_file_collision(filepath, force=False, auto_rename=True)
            assert result != filepath
            assert "test" in result
            assert result.endswith(".txt")
    
    def test_check_file_collision_abort(self):
        """Test abort on collision."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test.txt")
            # Create file
            with open(filepath, 'w') as f:
                f.write("existing")
            
            # Should raise exception
            with pytest.raises(FileExistsError):
                check_file_collision(filepath, force=False, auto_rename=False)
    
    def test_generate_deterministic_filename(self):
        """Test deterministic filename generation."""
        filename = generate_deterministic_filename(
            key_type='RSA',
            branches=[410, 111, 222],
            key_number=1,
            key_amount=5
        )
        
        # Should contain key_type
        assert 'RSA' in filename
        # Should be deterministic (same inputs = same output)
        filename2 = generate_deterministic_filename(
            key_type='RSA',
            branches=[410, 111, 222],
            key_number=1,
            key_amount=5
        )
        assert filename == filename2
    
    def test_generate_deterministic_filename_different_inputs(self):
        """Test that different inputs produce different filenames."""
        filename1 = generate_deterministic_filename('RSA', [410], 1, 1)
        filename2 = generate_deterministic_filename('RSA', [411], 1, 1)
        filename3 = generate_deterministic_filename('P-256', [410], 1, 1)
        
        assert filename1 != filename2
        assert filename1 != filename3
    
    def test_jsoned_basic(self):
        """Test basic JSON writing."""
        original_dir = os.getcwd()
        tmpdir = tempfile.mkdtemp()
        
        try:
            os.chdir(tmpdir)
            
            test_keys = [{'secret': 'test_secret', 'public': 'test_public'}]
            jsoned(test_keys, 'test_type', encrypt=False, force=True)
            
            # Find the created file
            files = [f for f in os.listdir('.') if f.endswith('.json')]
            assert len(files) == 1
            
            # Load and verify
            with open(files[0], 'r') as f:
                data = json.load(f)
            
            assert '1' in data
            assert data['1']['secret'] == 'test_secret'
        
        finally:
            os.chdir(original_dir)
            import shutil
            try:
                shutil.rmtree(tmpdir)
            except:
                pass
    
    def test_separated_basic(self):
        """Test basic separated file writing."""
        original_dir = os.getcwd()
        tmpdir = tempfile.mkdtemp()
        
        try:
            os.chdir(tmpdir)
            
            test_keys = [{'secret': 'test_secret_data', 'public': 'test_public_data'}]
            separated(test_keys, 'test_type', encrypt=False, force=True)
            
            # Should create 2 files
            files = os.listdir('.')
            secret_files = [f for f in files if 'secret' in f]
            public_files = [f for f in files if 'public' in f]
            
            assert len(secret_files) == 1
            assert len(public_files) == 1
            
            # Verify contents
            with open(secret_files[0], 'r') as f:
                secret_data = f.read()
            assert 'test_secret_data' in secret_data
        
        finally:
            os.chdir(original_dir)
            import shutil
            try:
                shutil.rmtree(tmpdir)
            except:
                pass
    
    def test_jsoned_deterministic_names(self):
        """Test JSON with deterministic filenames."""
        original_dir = os.getcwd()
        tmpdir = tempfile.mkdtemp()
        
        try:
            os.chdir(tmpdir)
            
            test_keys = [{'secret': 'test', 'public': 'test'}]
            jsoned(
                test_keys, 
                'RSA', 
                encrypt=False, 
                force=True,
                deterministic_names=True,
                branches=[410],
                key_number=1,
                key_amount=1
            )
            
            files = [f for f in os.listdir('.') if f.endswith('.json')]
            assert len(files) == 1
            # Should have deterministic pattern
            assert 'RSA' in files[0]
        
        finally:
            os.chdir(original_dir)
            import shutil
            try:
                shutil.rmtree(tmpdir)
            except:
                pass

