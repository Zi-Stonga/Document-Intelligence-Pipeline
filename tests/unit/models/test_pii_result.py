"""Unit tests for src/models/pii_result.py"""


from src.models.pii_result import OtherPiiItem, PiiClassification


class TestPiiClassificationCounts:
    def test_returns_correct_counts(self) -> None:
        # Arrange
        c = PiiClassification(
            names=["Jane", "John"],
            emails=["jane@example.com"],
            ssns=["XXX-XX-6789"],
            addresses=["123 Main St"],
            other_pii=[OtherPiiItem(type="ID", value="X")],
        )
        # Act / Assert
        assert c.counts() == {
            "names": 2,
            "emails": 1,
            "phones": 0,
            "ssns": 1,
            "addresses": 1,
            "dates_of_birth": 0,
            "other_pii": 1,
        }

    def test_returns_all_zeros_for_empty(self) -> None:
        # Arrange / Act / Assert
        assert all(v == 0 for v in PiiClassification().counts().values())

    def test_counts_does_not_expose_pii_values(self) -> None:
        # Arrange
        c = PiiClassification(names=["Jane Smith"])
        # Act / Assert
        assert "Jane Smith" not in str(c.counts())


class TestRoundTrip:
    def test_to_dict_then_from_dict(self) -> None:
        # Arrange
        original = PiiClassification(
            names=["Jane"],
            ssns=["XXX-XX-6789"],
            other_pii=[OtherPiiItem(type="ID", value="A123")],
        )
        # Act
        result = PiiClassification.from_dict(original.to_dict())
        # Assert
        assert result.names == original.names
        assert result.ssns == original.ssns
        assert result.other_pii[0].type == "ID"

    def test_from_dict_uses_empty_defaults_for_missing_fields(self) -> None:
        # Arrange / Act
        result = PiiClassification.from_dict({"names": ["Jane"]})
        # Assert
        assert result.emails == []
        assert result.ssns == []

    def test_from_dict_ignores_non_dict_other_pii_items(self) -> None:
        # Arrange
        data = {"other_pii": ["not-a-dict", {"type": "ID", "value": "X"}]}
        # Act
        result = PiiClassification.from_dict(data)
        # Assert
        assert len(result.other_pii) == 1


class TestParseErrorResult:
    def test_has_parse_error_true(self) -> None:
        assert PiiClassification.parse_error_result().parse_error is True

    def test_all_lists_are_empty(self) -> None:
        result = PiiClassification.parse_error_result()
        assert result.names == result.ssns == result.other_pii == []

    def test_counts_returns_all_zeros(self) -> None:
        assert all(v == 0 for v in PiiClassification.parse_error_result().counts().values())
