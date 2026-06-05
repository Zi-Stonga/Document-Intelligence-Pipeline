"""Unit tests for src/utils/validation.py"""

import pytest

from src.utils.exceptions import ValidationError
from src.utils.validation import make_output_key, validate_inputs

VALID_BUCKET = "pii-pipeline-input-123456789012"
VALID_KEY = "incoming/test.pdf"


class TestValidateInputs:
    def test_passes_for_valid_bucket_and_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Arrange
        monkeypatch.setenv("INPUT_BUCKET", VALID_BUCKET)
        # Act / Assert
        validate_inputs(VALID_BUCKET, VALID_KEY)

    def test_passes_when_input_bucket_env_not_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Arrange
        monkeypatch.delenv("INPUT_BUCKET", raising=False)
        # Act / Assert
        validate_inputs("any-bucket", VALID_KEY)

    def test_raises_when_source_bucket_is_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Arrange
        monkeypatch.delenv("INPUT_BUCKET", raising=False)
        # Act
        with pytest.raises(ValidationError) as exc_info:
            validate_inputs("", VALID_KEY)
        # Assert
        assert "source_bucket" in str(exc_info.value).lower()

    def test_raises_when_bucket_does_not_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Arrange
        monkeypatch.setenv("INPUT_BUCKET", VALID_BUCKET)
        # Act
        with pytest.raises(ValidationError) as exc_info:
            validate_inputs("wrong-bucket", VALID_KEY)
        # Assert
        assert "wrong-bucket" in str(exc_info.value)

    def test_raises_when_key_missing_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Arrange
        monkeypatch.delenv("INPUT_BUCKET", raising=False)
        # Act
        with pytest.raises(ValidationError) as exc_info:
            validate_inputs(VALID_BUCKET, "uploads/test.pdf")
        # Assert
        assert "incoming/" in str(exc_info.value)

    def test_raises_when_key_contains_path_traversal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Arrange
        monkeypatch.delenv("INPUT_BUCKET", raising=False)
        # Act
        with pytest.raises(ValidationError) as exc_info:
            validate_inputs(VALID_BUCKET, "incoming/../secret.pdf")
        # Assert
        assert "traversal" in str(exc_info.value).lower()

    def test_raises_when_key_exceeds_max_length(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Arrange
        monkeypatch.delenv("INPUT_BUCKET", raising=False)
        long_key = "incoming/" + "a" * 1020
        # Act
        with pytest.raises(ValidationError) as exc_info:
            validate_inputs(VALID_BUCKET, long_key)
        # Assert
        assert "1024" in str(exc_info.value)

    def test_passes_for_key_at_exact_max_length(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Arrange
        monkeypatch.delenv("INPUT_BUCKET", raising=False)
        exact_key = "incoming/" + "a" * (1024 - len("incoming/"))
        # Act / Assert
        validate_inputs(VALID_BUCKET, exact_key)


class TestMakeOutputKey:
    def test_strips_incoming_prefix(self) -> None:
        assert make_output_key("incoming/report.pdf") == "processed/report.pdf"

    def test_preserves_subdirectory_structure(self) -> None:
        assert make_output_key("incoming/2025/01/report.pdf") == "processed/2025/01/report.pdf"

    def test_handles_key_without_incoming_prefix(self) -> None:
        assert make_output_key("report.pdf") == "processed/report.pdf"

    def test_does_not_produce_double_processed_prefix(self) -> None:
        result = make_output_key("incoming/report.pdf")
        assert not result.startswith("processed/processed/")
