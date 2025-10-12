"""Shared pytest configuration and fixtures."""

import pytest
import os
import tempfile
import shutil


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    tmpdir = tempfile.mkdtemp()
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def sample_password():
    """Standard test password."""
    return b"test_password_123"


@pytest.fixture
def sample_branches():
    """Standard test branches."""
    return [410, 111, 222]


@pytest.fixture
def chdir_temp(temp_dir):
    """Change to temporary directory and restore on cleanup."""
    original_dir = os.getcwd()
    os.chdir(temp_dir)
    yield temp_dir
    os.chdir(original_dir)


# Mark slow tests
def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "slow: mark test as slow to run"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )

