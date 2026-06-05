"""
Data model for the PII classification result returned by the Anthropic API.

PiiClassification is the typed representation of the JSON object the model
returns. It is populated by src/services/anthropic.py, masked by
src/utils/masking.py, and consumed by src/services/vault.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class OtherPiiItem:
    """
    A single non-standard PII item identified by the model.

    Used for categories that do not fit named fields: account numbers,
    passport numbers, driver licence numbers, etc.
    """

    type: str
    """Category label assigned by the model, e.g. ACCOUNT_NUMBER."""

    value: str
    """The identified value. Will not be masked. Stored as classified."""


@dataclass
class PiiClassification:
    """
    Structured PII classification result from the Anthropic Claude API.

    SSNs may be raw before mask_ssns() is called. After masking, ssns
    contains only XXX-XX-XXXX format values and is safe for storage.
    """

    names: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    ssns: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)
    dates_of_birth: list[str] = field(default_factory=list)
    other_pii: list[OtherPiiItem] = field(default_factory=list)
    parse_error: bool = False
    """True if the model returned non-JSON output. All arrays will be empty."""

    def counts(self) -> dict[str, int]:
        """
        Return a dict of category names to counts.

        Contains counts only, never raw PII values.

        Returns:
            Dict with keys for each PII category. Values are non-negative integers.
        """
        return {
            "names": len(self.names),
            "emails": len(self.emails),
            "phones": len(self.phones),
            "ssns": len(self.ssns),
            "addresses": len(self.addresses),
            "dates_of_birth": len(self.dates_of_birth),
            "other_pii": len(self.other_pii),
        }

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize to a plain dict for JSON encoding.

        Returns:
            Dict representation suitable for json.dumps and DynamoDB storage.
        """
        return {
            "names": self.names,
            "emails": self.emails,
            "phones": self.phones,
            "ssns": self.ssns,
            "addresses": self.addresses,
            "dates_of_birth": self.dates_of_birth,
            "other_pii": [{"type": item.type, "value": item.value} for item in self.other_pii],
            "parse_error": self.parse_error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PiiClassification:
        """
        Deserialize from a plain dict.

        Args:
            data: Dict produced by the Anthropic API or by to_dict().

        Returns:
            PiiClassification instance. Missing fields default to empty list.
        """
        raw_other = data.get("other_pii", [])
        other_items = [
            OtherPiiItem(type=item.get("type", ""), value=item.get("value", ""))
            for item in raw_other
            if isinstance(item, dict)
        ]
        return cls(
            names=data.get("names", []),
            emails=data.get("emails", []),
            phones=data.get("phones", []),
            ssns=data.get("ssns", []),
            addresses=data.get("addresses", []),
            dates_of_birth=data.get("dates_of_birth", []),
            other_pii=other_items,
            parse_error=data.get("parse_error", False),
        )

    @classmethod
    def parse_error_result(cls) -> PiiClassification:
        """
        Return a PiiClassification representing a model parse failure.

        Returns:
            PiiClassification with parse_error=True and all arrays empty.
        """
        return cls(parse_error=True)
