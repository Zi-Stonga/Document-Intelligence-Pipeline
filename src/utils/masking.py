"""
PII masking utilities for the PII processing pipeline.

All functions are pure: no side effects, no state mutation, no external calls.
Masking runs after classification and before any storage write. The model is
never trusted to redact. Masking is always enforced by this module.
"""

import re
from copy import deepcopy

from src.models.pii_result import PiiClassification

_DIGIT_PATTERN = re.compile(r"\D")
_MIN_SSN_DIGITS = 4


def mask_ssns(classification: PiiClassification) -> PiiClassification:
    """
    Return a new PiiClassification with all SSN values masked.

    Does not mutate the input. Caller can safely use the original
    classification after calling this function.

    Args:
        classification: PiiClassification returned by the Anthropic API.

    Returns:
        New PiiClassification with ssns replaced by masked values.
        All other fields are copied unchanged.
    """
    masked_ssns = [_mask_single_ssn(raw_ssn) for raw_ssn in classification.ssns]

    return PiiClassification(
        names=list(classification.names),
        emails=list(classification.emails),
        phones=list(classification.phones),
        ssns=masked_ssns,
        addresses=list(classification.addresses),
        dates_of_birth=list(classification.dates_of_birth),
        other_pii=deepcopy(classification.other_pii),
        parse_error=classification.parse_error,
    )


def _mask_single_ssn(raw_value: str) -> str:
    """
    Mask a single SSN string, retaining only the last 4 digits.

    Args:
        raw_value: Raw SSN string in any format.

    Returns:
        Masked SSN in XXX-XX-XXXX format.
    """
    digits_only = _DIGIT_PATTERN.sub("", str(raw_value))
    if len(digits_only) >= _MIN_SSN_DIGITS:
        return f"XXX-XX-{digits_only[-4:]}"
    return "XXX-XX-XXXX"
