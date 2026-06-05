#!/usr/bin/env bash
# deploy.sh - Rebuild and redeploy the Lambda function after code changes.
# Run from the repo root.
set -e

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
ok()  { echo -e "${GREEN}[OK]${NC}    $*"; }
die() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[ -d "src" ] || die "Run from the repo root."

echo "Installing production dependencies..."
rm -rf package/
pip install -r requirements.txt -t package/ -q
cp -r src/ package/
ok "Package built"

echo "Creating function.zip..."
cd package && zip -r ../function.zip . -q && cd ..
ok "function.zip created"

echo "Deploying to Lambda..."
aws lambda update-function-code \
  --function-name pii-pipeline-processor \
  --zip-file fileb://function.zip \
  --region us-east-1 > /dev/null

aws lambda wait function-updated \
  --function-name pii-pipeline-processor \
  --region us-east-1

ok "Lambda deployed: pii-pipeline-processor"
