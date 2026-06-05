# Document Intelligence Pipeline

A production-grade serverless pipeline that ingests documents, extracts text
via Amazon Textract OCR, classifies personally identifiable information using
the Anthropic Claude API, and writes encrypted structured results to a DynamoDB
vault. Every byte at rest is protected by a customer-managed KMS key. Every API
call is captured in CloudTrail.All

**Python 3.12. AWS Lambda. Six security audits. Findings resolved.
83 tests passing. 96 percent coverage.**

---

## Table of Contents

- [Architecture](#architecture)
- [Data Flow](#data-flow)
- [Security Model](#security-model)
- [Prerequisites](#prerequisites)
- [Local Development](#local-development)
- [Running Tests](#running-tests)
- [Environment Variables](#environment-variables)
- [Project Structure](#project-structure)
- [AWS Infrastructure](#aws-infrastructure)
- [Deployment](#deployment)
- [Monitoring and Alarms](#monitoring-and-alarms)
- [Compliance](#compliance)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## Architecture

```
S3 input bucket/incoming/
        |
        | S3 ObjectCreated event
        v
SQS pii-pipeline-queue ---------> DLQ pii-pipeline-dlq
  (visibility: 720s)               (after 3 failed attempts)
        |
        v
Lambda pii-pipeline-processor
  (Python 3.12, 512 MB, 120s, X-Ray)
        |
        |-- Amazon Textract      OCR text extraction
        |-- Anthropic Claude     PII classification
        |-- AWS Secrets Manager  API key (15-min cache)
        |-- AWS KMS              Envelope encryption
        |
        |-> DynamoDB pii-vault       encrypted, TTL 365d, PITR
        |-> S3 output /processed/    counts only, KMS encrypted
        |-> S3 audit /lambda-audit/  counts and hashes, no pii_data
              |
              v
        CloudTrail pii-pipeline-trail
        (data events on all S3 buckets and DynamoDB)
```

**11 AWS services. 1 KMS CMK. Everything encrypted. Everything audited.**

---

## Data Flow

1. A document (PDF, image, or scanned file) is uploaded to
   `s3://pii-pipeline-input-{account}/incoming/filename.pdf`

2. S3 fires an ObjectCreated event to the SQS main queue

3. Lambda receives the SQS batch (up to 5 messages per invocation)

4. For each message, the handler:
   - Validates source bucket and key (fail-fast, no AWS calls yet)
   - Extracts text via Textract DetectDocumentText
   - Classifies PII via the Anthropic Claude API
   - Masks SSNs in code before any storage write (last 4 digits only)
   - Writes the masked result to DynamoDB with an idempotency condition
   - Writes a summary record to S3 output (counts only)
   - Writes an audit record to S3 audit (counts and hashes, never pii_data)

5. Failed records return in `batchItemFailures` so SQS retries only those
   messages. After 3 failures a message moves to the DLQ.

### SSN Masking

SSNs are masked in Lambda code before any storage write. The model is
explicitly instructed to return raw SSNs. The `mask_ssns()` function then
applies deterministic regex masking: `123-45-6789` becomes `XXX-XX-6789`.
This invariant is verified by unit tests on every commit.

### Idempotency

`document_id = SHA-256(source_key)`. `version = epoch_ms` at processing time.
DynamoDB writes use `ConditionExpression: attribute_not_exists(document_id) AND
attribute_not_exists(version)`. An exact message replay within the same
millisecond raises `ConditionalCheckFailedException` which is treated as a
success (idempotent skip), never as a failure that routes to the DLQ.

---

## Security Model

### Encryption

All storage is encrypted with a single customer-managed KMS key
(`alias/pii-pipeline`) with annual auto-rotation:

| Service | Encryption |
|---|---|
| S3 (all 4 buckets) | SSE-KMS with CMK + BucketKey |
| DynamoDB pii-vault | SSE-KMS with CMK |
| SQS (both queues) | SSE-KMS with CMK |
| Secrets Manager | SSE-KMS with CMK |
| CloudWatch Logs | SSE-KMS with CMK |
| SNS topic | SSE-KMS with CMK |
| CloudTrail logs | SSE-KMS with CMK |

All S3 operations enforce TLS via bucket policy. All service-to-service calls
require HTTPS via IAM conditions.

### IAM Least Privilege

The Lambda execution role (`pii-pipeline-lambda-role`) has 11 statements,
every resource scoped to a specific ARN:

- `ReadInputBucket`: `s3:GetObject` on `incoming/*` only
- `WriteOutputBucket`: `s3:PutObject` on `processed/*` only
- `WriteAuditBucket`: `s3:PutObject` on `lambda-audit/*` only
- `TextractSyncOCR`: sync Textract actions, region-locked to us-east-1
- `KMSDecryptAndDataKey`: `Decrypt` and `GenerateDataKey*` only, no Encrypt
- `DenyKMSDestructiveOps`: explicit Deny on Sign, Verify, CreateKey, ScheduleKeyDeletion
- `DynamoDBVaultAccess`: PutItem, GetItem, Query only, no UpdateItem, no DeleteItem
- `SQSConsume`: ReceiveMessage, DeleteMessage only, no SendMessage
- `SecretsManagerAPIKey`: GetSecretValue on exact secret ARN only
- `CloudWatchLogsWrite`: CreateLogStream, PutLogEvents on specific log group

The vault is **append-only**. No Lambda code path can modify or delete existing records.

### Audit Trail

- CloudTrail captures all management and data-plane events
- Data events enabled on all S3 buckets and the DynamoDB table
- CloudTrail Insights detects anomalous API call rates and error rates
- Log file validation (SHA-256 digest chain) prevents log tampering
- S3 server access logs provide a secondary audit trail

### PII in Logs

No raw PII values appear in any log field. CloudWatch logs contain:
`level`, `timestamp`, `message`, `document_id`, `pii_counts`, `duration_ms`.
Verified across all 6 audit passes.

---

## Prerequisites

- Python 3.10 or higher
- pip
- git
- AWS CLI v2 (for deployment and infrastructure only)
- An AWS account with appropriate permissions

---

## Local Development

```bash
git clone https://github.com/Zi-Stonga/Document-Intelligence-Pipeline.git
cd Document-Intelligence-Pipeline

python3 -m venv .venv

# Linux/macOS
source .venv/bin/activate

# Windows Git Bash
source .venv/Scripts/activate

pip install -r requirements-dev.txt
cp .env.example .env
```

Edit `.env` with your real values before running integration tests against
AWS. Unit tests use mocked AWS clients and do not require real credentials.

---

## Running Tests

All unit tests from the repo root:

```bash
# Linux/macOS
python3 -m pytest -v

# Windows Git Bash
.venv/Scripts/python -m pytest -v
```

With coverage report:

```bash
.venv/Scripts/python -m pytest -v --cov=src --cov-report=term-missing
```

Single test file:

```bash
.venv/Scripts/python -m pytest tests/unit/utils/test_masking.py -v
```

**Current status: 83 tests passing, 96 percent coverage.**

### Test Structure

Every test follows Arrange/Act/Assert. Every AWS client is injected as a
parameter and mocked in tests, no real AWS calls are made in the unit test
suite. Every mock has a comment explaining what it replaces and why.

| Test File | Coverage |
|---|---|
| tests/unit/utils/test_crypto.py | sha256_hex: 5 tests |
| tests/unit/utils/test_validation.py | validate_inputs, make_output_key: 13 tests |
| tests/unit/utils/test_masking.py | mask_ssns: 8 tests |
| tests/unit/models/test_pii_result.py | PiiClassification: 9 tests |
| tests/unit/config/test_settings.py | Settings, get_settings: 10 tests |
| tests/unit/services/test_secrets.py | get_api_key: 6 tests |
| tests/unit/services/test_textract.py | extract_text: 6 tests |
| tests/unit/services/test_vault.py | write_vault_record: 7 tests |
| tests/unit/services/test_storage.py | write_output, write_audit: 9 tests |
| tests/unit/services/test_anthropic.py | classify_pii: 7 tests |
| tests/unit/handler/test_processor.py | handler, _parse_s3_event: 8 tests |

---

## Environment Variables

All configuration is read from environment variables at Lambda cold start via
`pydantic-settings`. If any required variable is missing or empty, Lambda fails
immediately with a descriptive error naming the missing variable.

| Variable | Required | Default | Description |
|---|---|---|---|
| `DYNAMODB_TABLE` | Yes | | DynamoDB table name. Set to `pii-vault`. |
| `OUTPUT_BUCKET` | Yes | | S3 bucket for processed output summaries. |
| `AUDIT_BUCKET` | Yes | | S3 bucket for Lambda audit records. |
| `INPUT_BUCKET` | Yes | | S3 input bucket. Used to validate incoming SQS messages. |
| `ANTHROPIC_SECRET_NAME` | Yes | | Secrets Manager secret name for the Anthropic API key. |
| `KMS_KEY_ARN` | Yes | | Full ARN of the KMS CMK for S3 PutObject encryption. |
| `LAMBDA_TIMEOUT_MS` | No | `120000` | Lambda timeout in ms. Per-document timeout is 75 percent of this. |
| `ANTHROPIC_MODEL` | No | `claude-opus-4-5` | Anthropic model identifier. Change without a code deployment. |
| `AWS_REGION` | Auto | Set by runtime | Set automatically by Lambda. Do not set manually. |

To update a variable on a deployed Lambda:

```bash
aws lambda update-function-configuration \
    --function-name pii-pipeline-processor \
    --environment "Variables={ANTHROPIC_MODEL=claude-sonnet-4-5}" \
    --region us-east-1
```

---

## Project Structure

```
Document-Intelligence-Pipeline/
|
|-- src/
|   |-- config/
|   |   +-- settings.py         pydantic BaseSettings, validates all env vars at cold start
|   |-- handler/
|   |   +-- processor.py        Lambda entry point, SQS batch processor
|   |-- models/
|   |   |-- pii_record.py       PiiRecord dataclass, to_dynamodb_item()
|   |   +-- pii_result.py       PiiClassification dataclass, counts(), to_dict(), from_dict()
|   |-- services/
|   |   |-- anthropic.py        Anthropic Claude PII classifier, urllib only, retry logic
|   |   |-- secrets.py          Secrets Manager with 15-min TTL cache
|   |   |-- storage.py          S3 output and audit writes, audit excludes pii_data
|   |   |-- textract.py         Textract OCR with exponential backoff retry
|   |   +-- vault.py            DynamoDB idempotent write, conditional expression AND
|   +-- utils/
|       |-- crypto.py           sha256_hex pure function
|       |-- exceptions.py       PipelineError domain hierarchy (7 types)
|       |-- logger.py           Structured JSON logger, standard logging module
|       |-- masking.py          mask_ssns pure function, no mutation of input
|       +-- validation.py       validate_inputs, make_output_key pure functions
|
|-- tests/
|   |-- conftest.py             Shared fixtures: settings, classifications, cache clearing
|   +-- unit/
|       |-- config/             test_settings.py
|       |-- handler/            test_processor.py
|       |-- models/             test_pii_result.py
|       +-- services/           test_anthropic, test_secrets, test_storage,
|           utils/              test_textract, test_vault
|                               test_crypto, test_masking, test_validation
|
|-- docs/specs/
|   |-- 00_system_overview.md   What this is, code conventions
|   |-- 01_architecture.md      Components, data flow, design decisions
|   |-- 02_data_model.md        DynamoDB schema, pii_counts and pii_data structures
|   |-- 03_workflows_and_api.md Processing workflow, failure modes, retry policy
|   |-- 04_implementation_plan.md Build status, open items
|   |-- 05_local_development.md Setup and test instructions
|   |-- 06_result_schemas.md    All output and response schemas
|   +-- 07_cloud_deployment.md  Infrastructure, env vars, packaging, deployment
|
|-- infra/
|   |-- iam/                    Lambda execution policy, KMS admin trust policy
|   |-- kms/                    KMS key policy template
|   |-- s3/                     Bucket policies, lifecycle rules
|   |-- sqs/                    Queue resource policy
|   |-- dynamodb/               Table config
|   |-- cloudtrail/             Trail config
|   +-- monitoring/             CloudWatch alarm definitions
|
|-- scripts/
|   |-- deploy.sh               Rebuild and redeploy Lambda after code changes
|   |-- check_pipeline.sh       Health check for all pipeline resources
|   +-- teardown.sh             Delete all pipeline resources
|
|-- .github/workflows/
|   +-- ci.yml                  4 jobs: lint, test+coverage, JSON validation, secret scan
|
|-- pyproject.toml              Project metadata, dependencies, tool config
|-- ruff.toml                   Linter configuration
|-- .pre-commit-config.yaml     black, ruff, isort, mypy hooks
|-- requirements.txt            Production dependencies (pinned minor versions)
|-- requirements-dev.txt        Dev dependencies
|-- .env.example                All required variables with placeholder values
|-- CHANGELOG.md                Version history, 125 findings across 6 audit passes
|-- SECURITY.md                 Vulnerability reporting policy, known limitations
|-- CONTRIBUTING.md             Branch naming, PR requirements, security review gates
|-- ROADMAP.md                  P1/P2/P3 backlog with effort estimates
+-- LICENSE                     MIT
```

---

## AWS Infrastructure

### Required AWS Services

| Service | Resource Name | Purpose |
|---|---|---|
| Amazon S3 | pii-pipeline-input-{account} | Document ingestion |
| Amazon S3 | pii-pipeline-output-{account} | Processed summaries |
| Amazon S3 | pii-pipeline-audit-{account} | Audit records |
| Amazon S3 | pii-pipeline-access-logs-{account} | S3 server access logs |
| Amazon SQS | pii-pipeline-queue | Main processing queue |
| Amazon SQS | pii-pipeline-dlq | Dead letter queue |
| AWS Lambda | pii-pipeline-processor | Processing engine |
| Amazon DynamoDB | pii-vault | PII classification vault |
| AWS KMS | alias/pii-pipeline | Customer-managed encryption key |
| AWS Secrets Manager | pii-pipeline/anthropic-api-key | Anthropic API key |
| Amazon CloudWatch | /aws/lambda/pii-pipeline-processor | Application logs |
| AWS CloudTrail | pii-pipeline-trail | Compliance audit trail |
| Amazon SNS | pii-pipeline-ops-alerts | Alarm notifications |

### Build and Deploy Infrastructure

See `docs/specs/07_cloud_deployment.md` for the complete step-by-step
infrastructure build guide tested on Windows Git Bash.

**Critical for Windows Git Bash, run before every session:**

```bash
export MSYS_NO_PATHCONV=1
```

---

## Deployment

### Package the Lambda

```bash
pip install -r requirements.txt -t package/
cp -r src/ package/
cd package && zip -r ../function.zip . && cd ..
```

### Deploy Code Update

```bash
bash scripts/deploy.sh
```

Or manually:

```bash
aws lambda update-function-code\
    --function-name pii-pipeline-processor\
    --zip-file fileb://function.zip\
    --region us-east-1

aws lambda wait function-updated\
    --function-name pii-pipeline-processor\
    --region us-east-1
```

### Lambda Handler

```
src.handler.processor.handler
```

Set this as the handler in the Lambda function configuration.

### Verify the Pipeline

Upload a test document and watch logs:

```bash
aws s3 cp yourfile.pdf s3://pii-pipeline-input-YOUR_ACCOUNT_ID/incoming/test.pdf

export MSYS_NO_PATHCONV=1
aws logs tail /aws/lambda/pii-pipeline-processor --follow --region us-east-1
```

Query results in DynamoDB:

```bash
aws dynamodb query\
    --table-name pii-vault\
    --index-name source_key-index\
    --key-condition-expression "source_key = :k"\
    --expression-attribute-values '{":k":{"S":"incoming/test.pdf"}}'\
    --region us-east-1
```

Run the health check:

```bash
bash scripts/check_pipeline.sh
```

---

## Monitoring and Alarms

Three CloudWatch alarms route to the SNS topic `pii-pipeline-ops-alerts`:

| Alarm | Condition | What It Means |
|---|---|---|
| pii-pipeline-lambda-errors | Any error in 60s window | Lambda threw an unhandled exception |
| pii-pipeline-dlq-depth | Any message in DLQ | A document failed all 3 processing attempts |
| pii-pipeline-lambda-duration-high | P99 duration > 108s over 2x5min windows | Documents approaching the 120s timeout |

Subscribe your ops team to the SNS topic:

```bash
aws sns subscribe\
    --topic-arn arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:pii-pipeline-ops-alerts\
    --protocol email\
    --notification-endpoint your@email.com\
    --region us-east-1
```

See `docs/INCIDENT_RESPONSE.md` for the full runbook covering each alarm
with diagnostic commands and common fixes.

---

## Compliance

The pipeline addresses the following regulatory controls:

| Framework | Controls |
|---|---|
| HIPAA 45 CFR 164.312 | Encryption at rest and in transit, audit controls, integrity, transmission security |
| GDPR Art. 5, 25, 32 | Storage limitation (TTL 365d), data protection by design, technical measures |
| SOC 2 CC6, CC7, A1 | Logical access, monitoring, availability |

**Before processing real PHI:**

1. Sign a Business Associate Agreement with AWS
2. Sign a Business Associate Agreement with Anthropic
3. Set the real Anthropic API key in Secrets Manager
4. Recreate the audit bucket with S3 Object Lock (COMPLIANCE mode)
5. Extend retention to 7 years for HIPAA covered entities
6. Subscribe the ops team to the SNS alarm topic

See `docs/COMPLIANCE.md` for the full compliance matrix.

---

## Troubleshooting

### Common Issues

**`pydantic_settings` not found**

Install into the active venv Python directly:

```bash
.venv/Scripts/python -m pip install pydantic pydantic-settings boto3 botocore pytest
```

**`pytest: command not found` on Windows**

The venv Scripts folder is not in PATH. Use:

```bash
.venv/Scripts/python -m pytest -v
```

**`ConfigurationError: Configuration validation failed at startup`**

All required environment variables must be set before Lambda initialises.
In tests, use the `settings` fixture from `tests/conftest.py`. In Lambda,
verify all variables are set in the function configuration.

**S3 notification returns `InvalidArgument: Unable to validate destination`**

The SQS resource policy has not propagated yet. Wait 15 seconds and retry.

**`MalformedPolicyDocumentException` when applying KMS key policy**

An IAM role referenced in the policy does not exist yet or has not propagated.
Wait 15 seconds after creating roles before applying the key policy.

See `docs/TROUBLESHOOTING.md` for the full troubleshooting guide.

---

## Security Audits

This project was built through six sequential security audits. Each pass
reviewed prior-pass fixes alongside new code, a practice that surfaces
second and third-order issues invisible to single-pass review.

| Pass | Findings | Primary Category |
|---|---|---|
| 1 | 40 | Non-functional pipeline, raw PII in logs, CloudTrail off |
| 2 | 20 | SQS colon-in-ARN KMS bug, DLQ unencrypted, SSN masking in model |
| 3 | 20 | No API timeout, stale key cache, no piiData size guard |
| 4 | 25 | UpdateItem on append-only vault, S3 KMS logic error |
| 5 | 25 | DLQ alarm never fires, ConditionExpression OR not AND, AbortController reuse |
| 6 | 15 | SNS KMS bug (same as pass 2), ConditionalCheck to DLQ, missing INPUT_BUCKET |
| **Total** | **125** | **All resolved** |

The most instructive finding was the SNS KMS encryption failure in pass 6 —
the same colon-in-ARN bug fixed for SQS in pass 2, silently present in SNS
which was added later. Security fixes must be audited for applicability
across all similar components, not just where the issue was first found.

---

## Contributing

See `CONTRIBUTING.md` for branch naming conventions, PR requirements,
the two-reviewer gate for IAM and KMS changes, and the list of changes
that will not be merged.

---

## License

MIT. See `LICENSE`. LICENSE.
"""