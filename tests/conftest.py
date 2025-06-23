import pytest
import tempfile
import os
import shutil
from pathlib import Path
from unittest.mock import Mock, MagicMock


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    shutil.rmtree(temp_path)


@pytest.fixture
def temp_file(temp_dir):
    """Create a temporary file in the temp directory."""
    def _create_temp_file(filename="test_file.txt", content=""):
        file_path = temp_dir / filename
        file_path.write_text(content)
        return file_path
    return _create_temp_file


@pytest.fixture
def mock_config():
    """Provide a mock configuration object."""
    config = Mock()
    config.debug = False
    config.output_dir = "/tmp/test_output"
    config.input_file = "test_input.txt"
    return config


@pytest.fixture
def sample_ntds_data():
    """Provide sample NTDS data for testing."""
    return [
        "domain.com\\user1:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
        "domain.com\\user2:1002:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::",
        "domain.com\\admin:1003:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::",
    ]


@pytest.fixture
def sample_hashcat_output():
    """Provide sample hashcat potfile data."""
    return [
        "31d6cfe0d16ae931b73c59d7e0c089c0:",
        "e19ccf75ee54e06b06a5907af13cef42:P@ssw0rd",
        "8846f7eaee8fb117ad06bdd830b7586c:password123",
    ]


@pytest.fixture
def mock_database():
    """Provide a mock database connection."""
    db = MagicMock()
    db.cursor.return_value = MagicMock()
    return db


@pytest.fixture(autouse=True)
def reset_environment():
    """Reset environment variables before and after each test."""
    original_env = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def capture_stdout(monkeypatch):
    """Capture stdout for testing print statements."""
    import io
    import sys
    
    captured_output = io.StringIO()
    monkeypatch.setattr(sys, 'stdout', captured_output)
    
    def get_output():
        return captured_output.getvalue()
    
    return get_output


@pytest.fixture
def mock_webbrowser(monkeypatch):
    """Mock webbrowser module to prevent opening actual browser windows."""
    mock_browser = Mock()
    monkeypatch.setattr('webbrowser.open', mock_browser)
    return mock_browser


@pytest.fixture
def mock_argparse_args():
    """Provide mock command line arguments."""
    args = Mock()
    args.ntdsfile = "test_ntds.txt"
    args.crackfile = "test_crack.txt"
    args.outputfile = "test_output.html"
    args.reportdirectory = "test_report"
    args.writedb = False
    args.sanitize = False
    args.grouplists = None
    args.machineaccts = False
    args.krbtgt = False
    return args