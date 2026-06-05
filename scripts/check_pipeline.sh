#!/usr/bin/env bash
# check_pipeline.sh - Verify all pipeline resources exist and are healthy.
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail() { echo -e "${RED}[FAIL]${NC}  $*"; ISSUES=$((ISSUES+1)); }

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
REGION="us-east-1"
ISSUES=0

[ -z "$ACCOUNT_ID" ] && echo -e "${RED}[ERROR]${NC} Cannot get account ID." && exit 1

echo "============================================"
echo " PII Pipeline Health Check  Account: $ACCOUNT_ID"
echo "============================================"

KEY_STATE=$(aws kms describe-key --key-id alias/pii-pipeline --region $REGION \
  --query 'KeyMetadata.KeyState' --output text 2>/dev/null)
[ "$KEY_STATE" = "Enabled" ] && ok "KMS key: Enabled" || fail "KMS key: $KEY_STATE"

LAMBDA_STATE=$(aws lambda get-function-configuration \
  --function-name pii-pipeline-processor --region $REGION \
  --query 'State' --output text 2>/dev/null)
[ "$LAMBDA_STATE" = "Active" ] && ok "Lambda: Active" || fail "Lambda: $LAMBDA_STATE"

DLQ_DEPTH=$(aws sqs get-queue-attributes \
  --queue-url "https://sqs.$REGION.amazonaws.com/$ACCOUNT_ID/pii-pipeline-dlq" \
  --attribute-names ApproximateNumberOfMessages \
  --query 'Attributes.ApproximateNumberOfMessages' --output text 2>/dev/null)
[ "$DLQ_DEPTH" = "0" ] && ok "DLQ depth: 0" || warn "DLQ depth: $DLQ_DEPTH"

TABLE_STATUS=$(aws dynamodb describe-table --table-name pii-vault --region $REGION \
  --query 'Table.TableStatus' --output text 2>/dev/null)
[ "$TABLE_STATUS" = "ACTIVE" ] && ok "DynamoDB: ACTIVE" || fail "DynamoDB: $TABLE_STATUS"

SECRET_VAL=$(aws secretsmanager get-secret-value \
  --secret-id pii-pipeline/anthropic-api-key --region $REGION \
  --query 'SecretString' --output text 2>/dev/null)
echo "$SECRET_VAL" | grep -q "REPLACE_BEFORE_USE" \
  && warn "API key is still the placeholder" \
  || ok "API key: configured"

echo "============================================"
[ $ISSUES -eq 0 ] && ok "All checks passed." \
  || echo -e "${RED}[FAIL]${NC}  $ISSUES issue(s) found."
echo "============================================"
