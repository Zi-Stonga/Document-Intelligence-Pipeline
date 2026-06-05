"""Unit tests for src/utils/crypto.py"""

import pytest

from src.utils.crypto import sha256_hex


class TestSha256Hex:
    def test_returns_64_character_hex_string(self) -> None:
        # Arrange
        value = "incoming/report.pdf"
        # Act
        result = sha256_hex(value)
        # Assert
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_is_deterministic_for_same_input(self) -> None:
        # Arrange
        value = "incoming/report.pdf"
        # Act / Assert
        assert sha256_hex(value) == sha256_hex(value)

    def test_different_inputs_produce_different_hashes(self) -> None:
        # Arrange / Act / Assert
        assert sha256_hex("incoming/a.pdf") != sha256_hex("incoming/b.pdf")

    def test_raises_value_error_for_empty_string(self) -> None:
        # Arrange / Act
        with pytest.raises(ValueError) as exc_info:
            sha256_hex("")
        # Assert
        assert "empty" in str(exc_info.value).lower()

    def test_known_hash_value(self) -> None:
        # Arrange
        expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        # Act / Assert
        assert sha256_hex("hello") == expected
