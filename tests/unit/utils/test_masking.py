"""Unit tests for src/utils/masking.py"""

from src.models.pii_result import OtherPiiItem, PiiClassification
from src.utils.masking import mask_ssns


class TestMaskSSNs:
    def test_masks_formatted_ssn_keeping_last_four_digits(self) -> None:
        # Arrange
        classification = PiiClassification(ssns=["123-45-6789"])
        # Act
        result = mask_ssns(classification)
        # Assert
        assert result.ssns[0] == "XXX-XX-6789"

    def test_masks_unformatted_ssn(self) -> None:
        # Arrange
        classification = PiiClassification(ssns=["123456789"])
        # Act / Assert
        assert mask_ssns(classification).ssns[0] == "XXX-XX-6789"

    def test_returns_all_x_when_fewer_than_four_digits(self) -> None:
        # Arrange
        classification = PiiClassification(ssns=["123"])
        # Act / Assert
        assert mask_ssns(classification).ssns[0] == "XXX-XX-XXXX"

    def test_does_not_mutate_input(self) -> None:
        # Arrange
        original = "123-45-6789"
        classification = PiiClassification(ssns=[original])
        # Act
        mask_ssns(classification)
        # Assert
        assert classification.ssns[0] == original

    def test_returns_new_instance(self) -> None:
        # Arrange
        classification = PiiClassification(ssns=["123-45-6789"])
        # Act / Assert
        assert mask_ssns(classification) is not classification

    def test_masks_all_ssns_in_list(self) -> None:
        # Arrange
        classification = PiiClassification(ssns=["111-22-3333", "444-55-6666"])
        # Act
        result = mask_ssns(classification)
        # Assert
        assert result.ssns[0] == "XXX-XX-3333"
        assert result.ssns[1] == "XXX-XX-6666"

    def test_preserves_all_non_ssn_fields(self) -> None:
        # Arrange
        classification = PiiClassification(
            names=["Jane"],
            emails=["jane@example.com"],
            ssns=["123-45-6789"],
            other_pii=[OtherPiiItem(type="ID", value="X123")],
        )
        # Act
        result = mask_ssns(classification)
        # Assert
        assert result.names == ["Jane"]
        assert result.emails == ["jane@example.com"]
        assert result.other_pii[0].value == "X123"

    def test_handles_parse_error_classification(self) -> None:
        # Arrange
        classification = PiiClassification.parse_error_result()
        # Act
        result = mask_ssns(classification)
        # Assert
        assert result.parse_error is True
        assert result.ssns == []
