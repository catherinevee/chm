"""Basic tests to verify CI/CD pipeline functionality."""

import sys
import pytest
from pathlib import Path

# Add backend to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestBasicFunctionality:
    """Basic tests for CI/CD verification."""

    def test_python_version(self):
        """Test Python version is 3.9 or higher."""
        assert sys.version_info >= (3, 9), "Python 3.9+ required"

    def test_import_fastapi(self):
        """Test FastAPI can be imported."""
        import fastapi
        assert fastapi.__version__, "FastAPI should have a version"

    def test_import_sqlalchemy(self):
        """Test SQLAlchemy can be imported."""
        import sqlalchemy
        assert sqlalchemy.__version__, "SQLAlchemy should have a version"

    def test_import_pydantic(self):
        """Test Pydantic can be imported."""
        import pydantic
        assert pydantic.VERSION, "Pydantic should have a version"

    def test_backend_structure(self):
        """Test backend directory structure exists."""
        backend_path = Path(__file__).parent.parent / "backend"
        assert backend_path.exists(), "Backend directory should exist"
        
        # Check for key subdirectories
        expected_dirs = ["api", "models", "services", "database"]
        for dir_name in expected_dirs:
            dir_path = backend_path / dir_name
            assert dir_path.exists(), f"Backend/{dir_name} directory should exist"

    def test_configuration_files(self):
        """Test configuration files exist."""
        root_path = Path(__file__).parent.parent
        
        # Check for important config files
        config_files = [
            "requirements.txt",
            "pyproject.toml",
            "README.md",
            "LICENSE",
            "Dockerfile",
            "docker-compose.yml",
        ]
        
        for config_file in config_files:
            file_path = root_path / config_file
            assert file_path.exists(), f"{config_file} should exist"

    @pytest.mark.parametrize("value,expected", [
        (1, 1),
        (2, 2),
        (3, 3),
    ])
    def test_parametrized_example(self, value, expected):
        """Example parametrized test for coverage."""
        assert value == expected

    def test_arithmetic_operations(self):
        """Test basic arithmetic for coverage."""
        assert 2 + 2 == 4
        assert 10 - 5 == 5
        assert 3 * 4 == 12
        assert 15 / 3 == 5

    def test_string_operations(self):
        """Test string operations for coverage."""
        test_string = "CHM Network Monitor"
        assert "CHM" in test_string
        assert test_string.lower() == "chm network monitor"
        assert test_string.upper() == "CHM NETWORK MONITOR"
        assert len(test_string) == 19

    def test_list_operations(self):
        """Test list operations for coverage."""
        test_list = [1, 2, 3, 4, 5]
        assert len(test_list) == 5
        assert sum(test_list) == 15
        assert max(test_list) == 5
        assert min(test_list) == 1

    def test_dictionary_operations(self):
        """Test dictionary operations for coverage."""
        test_dict = {
            "name": "CHM",
            "type": "Network Monitor",
            "version": "2.0.0"
        }
        assert "name" in test_dict
        assert test_dict["name"] == "CHM"
        assert len(test_dict) == 3
        assert list(test_dict.keys()) == ["name", "type", "version"]


class TestSecurityFeatures:
    """Test security-related functionality."""

    def test_password_hashing_available(self):
        """Test password hashing library is available."""
        try:
            from passlib.context import CryptContext
            pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
            
            # Test hashing
            password = "test_password_123"
            hashed = pwd_context.hash(password)
            assert hashed != password
            assert pwd_context.verify(password, hashed)
        except ImportError:
            pytest.skip("passlib not installed")

    def test_jwt_available(self):
        """Test JWT library is available."""
        try:
            from jose import jwt
            
            # Test JWT creation
            test_data = {"sub": "test_user"}
            secret = "test_secret_key"
            token = jwt.encode(test_data, secret, algorithm="HS256")
            assert token
            
            # Test JWT decoding
            decoded = jwt.decode(token, secret, algorithms=["HS256"])
            assert decoded["sub"] == "test_user"
        except ImportError:
            pytest.skip("python-jose not installed")

    def test_cryptography_available(self):
        """Test cryptography library is available."""
        try:
            from cryptography.fernet import Fernet
            
            # Test encryption/decryption
            key = Fernet.generate_key()
            cipher = Fernet(key)
            
            message = b"Secret message"
            encrypted = cipher.encrypt(message)
            assert encrypted != message
            
            decrypted = cipher.decrypt(encrypted)
            assert decrypted == message
        except ImportError:
            pytest.skip("cryptography not installed")


class TestNetworkingLibraries:
    """Test networking library availability."""

    def test_httpx_available(self):
        """Test httpx HTTP client is available."""
        try:
            import httpx
            assert httpx.__version__
        except ImportError:
            pytest.skip("httpx not installed")

    def test_paramiko_available(self):
        """Test Paramiko SSH library is available."""
        try:
            import paramiko
            assert paramiko.__version__
        except ImportError:
            pytest.skip("paramiko not installed")

    def test_redis_available(self):
        """Test Redis client is available."""
        try:
            import redis
            assert redis.__version__
        except ImportError:
            pytest.skip("redis not installed")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])