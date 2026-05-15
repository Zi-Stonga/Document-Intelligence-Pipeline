'use strict';

const { TextractClient, DetectDocumentTextCommand }   = require('@aws-sdk/client-textract');
const { DynamoDBClient, PutItemCommand }              = require('@aws-sdk/client-dynamodb');
const { SecretsManagerClient, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
const { S3Client, PutObjectCommand }                  = require('@aws-sdk/client-s3');
const { createHash }                                  = require('crypto');

const REGION          = process.env.AWS_REGION || 'us-east-1';
const ANTHROPIC_MODEL = process.env.ANTHROPIC_MODEL || 'claude-opus-4-5';
const INPUT_BUCKET    = process.env.INPUT_BUCKET || '';
const MAX_TEXT_CHARS  = 180000;
const MAX_PII_BYTES   = 350000;
const FETCH_TIMEOUT   = 45000;
const KEY_CACHE_TTL   = 15 * 60000;
const PII_TTL_DAYS    = 365;

const textract = new TextractClient({ region: REGION });
const dynamo   = new DynamoDBClient({ region: REGION });
const sm       = new SecretsManagerClient({ region: REGION });
const s3       = new S3Client({ region: REGION });

let keyCache = { value: null, fetchedAt: 0 };

function log(level, data) {
  const { level: _l, timestamp: _t, ...safe } = data;
  console.log(JSON.stringify({ level, timestamp: new Date().toISOString(), ...safe }));
}

async function getApiKey() {
  const now = Date.now();
  if (keyCache.value && (now - keyCache.fetchedAt) < KEY_CACHE_TTL) return keyCache.value;
  const res = await sm.send(new GetSecretValueCommand({ SecretId: process.env.ANTHROPIC_SECRET_NAME }));
  const { api_key } = JSON.parse(res.SecretString);
  if (!api_key || api_key.startsWith('REPLACE_')) throw new Error('API key not configured');
  keyCache = { value: api_key, fetchedAt: now };
  return api_key;
}

async function withRetry(fn, max = 3, base = 500) {
  for (let i = 1; i <= max; i++) {
    try { return await fn(); }
    catch (err) {
      const retryable = err.status === 429 || err.status >= 500 ||
        ['ThrottlingException','ServiceUnavailableException','ProvisionedThroughputExceededException'].includes(err.name);
      if (!retryable || i === max) throw err;
      await new Promise(r => setTimeout(r, base * 2 ** (i - 1) + Math.random() * 150));
    }
  }
}

function validateInputs(bucket, key) {
  if (!bucket || typeof bucket !== 'string') throw new Error('Invalid bucket');
  if (INPUT_BUCKET && bucket !== INPUT_BUCKET) throw new Error('Unexpected bucket');
  if (!key || typeof key !== 'string') throw new Error('Invalid key');
  if (!key.startsWith('incoming/')) throw new Error('Key must start with incoming/');
  if (key.includes('..')) throw new Error('Path traversal detected');
  if (key.length > 1024) throw new Error('Key too long');
}

async function extractText(bucket, key) {
  const result = await withRetry(() =>
    textract.send(new DetectDocumentTextCommand({ Document: { S3Object: { Bucket: bucket, Name: key } } })));
  return (result.Blocks || []).filter(b => b.BlockType === 'LINE' && b.Text).map(b => b.Text).join('\n');
}

function maskSSNs(pii) {
  if (!Array.isArray(pii.ssns)) return pii;
  return { ...pii, ssns: pii.ssns.map(s => {
    const d = String(s).replace(/\D/g, '');
    return d.length >= 4 ? 'XXX-XX-' + d.slice(-4) : 'XXX-XX-XXXX';
  })};
}

async function classifyPII(text, apiKey) {
  const safe = text.length > MAX_TEXT_CHARS ? text.slice(0, MAX_TEXT_CHARS) + '\n[TRUNCATED]' : text;
  let r, lastErr;
  for (let attempt = 1; attempt <= 3; attempt++) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
    try {
      const res = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST', signal: ctrl.signal,
        headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
        body: JSON.stringify({
          model: ANTHROPIC_MODEL, max_tokens: 1024,
          system: 'You are a PII extraction engine. Respond only with a valid JSON object. No markdown fences.',
          messages: [{ role: 'user', content: 'Extract all PII. Return JSON with: names, emails, phones, ssns, addresses, dates_of_birth, other_pii.\n\nText:\n' + safe }]
        })
      });
      clearTimeout(timer);
      if (!res.ok) { const e = new Error('Anthropic ' + res.status); e.status = res.status; throw e; }
      r = await res.json();
      break;
    } catch (err) {
      clearTimeout(timer);
      lastErr = err;
      if (attempt === 3) throw err;
      await new Promise(resolve => setTimeout(resolve, 500 * 2 ** (attempt - 1)));
    }
  }
  if (!r || !r.content || !r.content[0]) throw new Error('Bad API response');
  const raw = r.content[0].text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim();
  try { return maskSSNs(JSON.parse(raw)); }
  catch { return { parse_error: true, names: [], emails: [], phones: [], ssns: [], addresses: [], dates_of_birth: [], other_pii: [] }; }
}

function sha256(s) { return createHash('sha256').update(s).digest('hex'); }
function makeOutputKey(k) { return 'processed/' + k.replace(/^incoming\//, ''); }

exports.handler = async (event) => {
  const failures = [];
  for (const record of event.Records) {
    try {
      const body = JSON.parse(record.body);
      let bucket, key;
      if (body.Records && body.Records[0] && body.Records[0].s3) {
        bucket = body.Records[0].s3.bucket.name;
        key = decodeURIComponent(body.Records[0].s3.object.key.replace(/\+/g, ' '));
      } else { bucket = body.bucket; key = body.key; }
      validateInputs(bucket, key);
      const docId = sha256(key);
      const ver = Date.now();
      const timeout = Math.floor(parseInt(process.env.LAMBDA_TIMEOUT_MS || '120000') * 0.75);
      await Promise.race([
        processDoc({ bucket, key, docId, ver }),
        new Promise((_, r) => setTimeout(() => r(new Error('Timeout')), timeout))
      ]);
    } catch (err) {
      log('ERROR', { message: err.message, messageId: record.messageId });
      failures.push({ itemIdentifier: record.messageId });
    }
  }
  return { batchItemFailures: failures };
};

async function processDoc({ bucket, key, docId, ver }) {
  const start = Date.now();
  const apiKey = await getApiKey();
  const text = await extractText(bucket, key);
  if (!text || !text.trim()) { log('WARN', { message: 'No text', docId }); return; }
  const pii = await classifyPII(text, apiKey);
  const counts = {
    names: pii.names ? pii.names.length : 0,
    emails: pii.emails ? pii.emails.length : 0,
    phones: pii.phones ? pii.phones.length : 0,
    ssns: pii.ssns ? pii.ssns.length : 0,
    addresses: pii.addresses ? pii.addresses.length : 0,
    dates_of_birth: pii.dates_of_birth ? pii.dates_of_birth.length : 0,
    other_pii: pii.other_pii ? pii.other_pii.length : 0
  };
  const keyHash = sha256(key);
  let piiToStore = pii;
  if (Buffer.byteLength(JSON.stringify(pii), 'utf8') > MAX_PII_BYTES) {
    piiToStore = { ...pii, other_pii: [{ type: 'TRUNCATED', value: 'Too large' }] };
  }
  const expiresAt = Math.floor(Date.now() / 1000) + (PII_TTL_DAYS * 86400);
  try {
    await withRetry(() => dynamo.send(new PutItemCommand({
      TableName: process.env.DYNAMODB_TABLE,
      ConditionExpression: 'attribute_not_exists(documentId) AND attribute_not_exists(#v)',
      ExpressionAttributeNames: { '#v': 'version' },
      Item: {
        documentId: { S: docId }, version: { N: String(ver) },
        sourceKey: { S: key }, sourceBucket: { S: bucket },
        sourceKeyHash: { S: keyHash }, piiCounts: { S: JSON.stringify(counts) },
        piiData: { S: JSON.stringify(piiToStore) }, processedAt: { S: new Date().toISOString() },
        durationMs: { N: String(Date.now() - start) }, expiresAt: { N: String(expiresAt) }
      }
    })));
  } catch (err) {
    if (err.name === 'ConditionalCheckFailedException') { log('INFO', { message: 'Duplicate skipped', docId }); return; }
    throw err;
  }
  await withRetry(() => s3.send(new PutObjectCommand({
    Bucket: process.env.OUTPUT_BUCKET, Key: makeOutputKey(key),
    Body: JSON.stringify({ docId, ver, counts }, null, 2),
    ContentType: 'application/json', ServerSideEncryption: 'aws:kms',
    SSEKMSKeyId: process.env.KMS_KEY_ARN
  })));
  await withRetry(() => s3.send(new PutObjectCommand({
    Bucket: process.env.AUDIT_BUCKET,
    Key: 'lambda-audit/' + new Date().toISOString().slice(0,10) + '/' + docId + '-' + ver + '.json',
    Body: JSON.stringify({ docId, ver, keyHash, bucket, counts, expiresAt, processedAt: new Date().toISOString(), durationMs: Date.now() - start }, null, 2),
    ContentType: 'application/json', ServerSideEncryption: 'aws:kms',
    SSEKMSKeyId: process.env.KMS_KEY_ARN
  })));
  log('INFO', { message: 'Done', docId, ver, counts, durationMs: Date.now() - start });
}
