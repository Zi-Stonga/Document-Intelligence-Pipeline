"""
Domain exception hierarchy for the PII processing pipeline.

All domain-specific errors inherit from PipelineError so callers
can catch the entire hierarchy with a single except clause when needed.
"""


class PipelineError(Exception):
    """Base class for all pipeline domain errors."""


class ValidationError(PipelineError):
    """
    Raised when an incoming SQS message fails input validation.

    Non-retryable. The message will be routed to the DLQ without consuming
    any of the SQS retry budget.
    """


class ConfigurationError(PipelineError):
    """
    Raised at startup when required environment variables are missing or invalid.

    Lambda will fail immediately on cold start. Check the Lambda configuration
    in the AWS console and verify all required environment variables are set.
    """


class TextractError(PipelineError):
    """
    Raised when Textract fails to extract text from a document after all retries.

    Check the source S3 object exists, is accessible, and is a supported format.
    """


class ClassificationError(PipelineError):
    """
    Raised when the Anthropic API call fails after all retries.

    Check status.anthropic.com for incidents and verify the API key in Secrets
    Manager is valid and not the placeholder value.
    """


class VaultWriteError(PipelineError):
    """
    Raised when the DynamoDB PutItem call fails after all retries.

    Check the pii-vault table exists, the Lambda IAM role has PutItem permission,
    and the KMS key policy allows DynamoDB to use the CMK.
    """


class StorageWriteError(PipelineError):
    """
    Raised when an S3 PutObject call fails after all retries.

    Check the target bucket exists, the Lambda IAM role has PutObject permission
    for the relevant prefix, and the KMS key policy is correct.
    """


class SecretRetrievalError(PipelineError):
    """
    Raised when the Anthropic API key cannot be retrieved from Secrets Manager.

    Check the secret name matches ANTHROPIC_SECRET_NAME, the Lambda IAM role
    has GetSecretValue on the exact secret ARN, and the key is not the
    placeholder value REPLACE_BEFORE_USE.
    """
