import cors from 'cors';
import crypto from 'crypto';
import express from 'express';
import { execFile } from 'node:child_process';
import {
  Address,
  BASE_FEE,
  Contract,
  Keypair,
  nativeToScVal,
  TransactionBuilder,
  rpc,
  scValToNative,
} from '@stellar/stellar-sdk';
import { env, isDeepSeekConfigured } from './config/env.js';
import { isDatabaseConfigured, query as dbQuery } from './services/database.js';
import { createDeepSeekReply, getCoverFiResearchContext } from './services/deepseek.js';
import {
  DIDIT_KYB_WORKFLOW_ID,
  DIDIT_KYC_WORKFLOW_ID,
  createDiditKybSession,
  createDiditKycSession,
  getLatestUserKycSession,
  getLatestPartnerKybSession,
  isDiditConfigured,
  isDiditKycConfigured,
  isDiditWebhookConfigured,
  normalizeDiditStatus,
  processDiditWebhookEvent,
  saveUserKycSession,
  savePartnerKybSession,
  verifyDiditWebhookPayload,
} from './services/didit.js';
import {
  authenticatePartnerApiKey,
  authenticatePartnerSession,
  createPartnerApplication,
  createPartner,
  createPartnerKey,
  createPartnerPosition,
  createPartnerQuote,
  createPartnerSession,
  createPartnerWebhook,
  getPartnerOwnedByWallet,
  getPartnerMetrics,
  getPartnerPosition,
  getPartnerQuote,
  getProtocolMetrics,
  isPartnerAdminWallet,
  listPartnerApplications,
  listPartnerPositions,
  listPartners,
  listPartnersForWalletRef,
  logPartnerRequest,
  setPartnerStatus,
  validateApplicationEnvironment,
  validateKeyMode,
  validatePartnerSlug,
} from './services/partners.js';
import {
  fundTestnetWallet,
  listZkProofEvents,
  recordEmailWallet,
  recordZkProofEvent,
  saveZkCommitment,
  startEmailOtp,
  verifyEmailOtp,
  verifyEmailMfa,
  verifyEmailSessionToken,
  walletRef as onboardingWalletRef,
} from './services/onboarding.js';
import {
  getIndexerStatus,
  listWalletActivity,
  listWalletEvents,
} from './services/history.js';
import { getPortfolioMarkets, getSupportedPriceAssets, getUsdPriceForAsset } from './services/prices.js';

const app = express();
const usernamePattern = /^[a-zA-Z0-9_]{3,24}$/;
const walletAddressPattern = /^G[A-Z2-7]{55}$/;
const txHashPattern = /^[a-fA-F0-9]{64}$/;
const receiptHashPattern = /^[a-fA-F0-9]{64}$/;
const zkProofCircuitIds = new Set([
  'coverfi.email_wallet_ownership.v0',
  'coverfi.mfa.enabled.v1',
  'coverfi.profile.email.verified.v1',
  'coverfi.profile.mfa.enabled.v1',
  'coverfi.receipt_ownership.v0',
  'coverfi.partner_kyb.status.v0',
  'coverfi.user_kyc.status.v0',
]);
const reservedUsernames = new Set([
  'admin',
  'administrator',
  'airdrop',
  'coverfi',
  'help',
  'moderator',
  'official',
  'oracle',
  'root',
  'security',
  'staff',
  'support',
  'system',
  'team',
  'treasury',
  'verified',
]);

let httpServer;
const rateLimitBuckets = new Map();
const authChallenges = new Map();
const revokedSessionIds = new Map();
const ORACLE_PRICE_SCALE = 100_000_000;
let oracleRefreshInFlight = null;
let lastOracleRefreshResult = null;
let lastOracleRefreshAt = 0;
let reserveAttestationCache = null;
const oracleStatusHistory = [];

app.set('trust proxy', env.server.trustedProxyHops);

function isAllowedOrigin(origin) {
  if (!origin) {
    return true;
  }

  const configuredOrigins = new Set([
    env.server.clientOrigin,
    ...env.server.clientOrigins,
  ].filter(Boolean));

  if (configuredOrigins.has(origin)) {
    return true;
  }

  try {
    const url = new URL(origin);
    const localHosts = new Set(['localhost', '127.0.0.1', '[::1]']);
    const localDevPorts = new Set(['5173', '5174', '5175', '5176', '4173', '4175']);
    return !env.server.isProduction && localHosts.has(url.hostname) && localDevPorts.has(url.port);
  } catch {
    return false;
  }
}

app.use(cors({
  origin(origin, callback) {
    if (isAllowedOrigin(origin)) {
      callback(null, true);
      return;
    }

    callback(new Error(`CORS origin not allowed: ${origin}`));
  },
}));

// The API does not serve application HTML, so a restrictive response policy
// is safe here and limits the impact of accidental browser embedding.
app.use((request, response, next) => {
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('X-Frame-Options', 'DENY');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  response.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
  if (env.server.isProduction) {
    response.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

app.post('/api/webhooks/didit', express.raw({ type: 'application/json', limit: '256kb' }), async (request, response) => {
  try {
    if (!requireConfiguredDatabase(response)) return null;
    if (!isDiditWebhookConfigured()) {
      return response.status(503).send('didit webhook not configured');
    }

    const rawBody = Buffer.isBuffer(request.body)
      ? request.body.toString('utf8')
      : String(request.body || '');
    const payload = JSON.parse(rawBody);
    const verification = verifyDiditWebhookPayload({
      payload,
      signature: request.headers['x-signature-v2'],
      timestamp: request.headers['x-timestamp'],
    });

    if (!verification.ok) {
      return response.status(401).send(verification.code);
    }

    const result = await processDiditWebhookEvent(payload);
    if (
      result.processed &&
      result.partnerId &&
      normalizeDiditStatus(payload.status || '') === 'verified'
    ) {
      await recordZkProofEvent({
        subjectRef: `partner:${result.partnerId}`,
        circuitId: 'coverfi.partner_kyb.status.v0',
        proofSystem: 'didit-kyb-attestation',
        proof: {
          provider: 'didit',
          eventId: String(payload.event_id || ''),
          workflowId: String(payload.workflow_id || DIDIT_KYB_WORKFLOW_ID),
          providerSessionHash: crypto
            .createHash('sha256')
            .update(String(payload.session_id || payload.vendor_data || ''))
            .digest('hex'),
          status: normalizeDiditStatus(payload.status || ''),
        },
        publicSignals: {
          partnerId: result.partnerId,
          provider: 'didit',
          workflowId: String(payload.workflow_id || DIDIT_KYB_WORKFLOW_ID),
          kybStatus: 'verified',
        },
        verificationStatus: 'verified',
        verifierNotes: 'Didit webhook signature verified; partner KYB status attested without storing provider documents in the proof event.',
      });
    }
    if (
      result.processed &&
      result.userWalletRef &&
      normalizeDiditStatus(payload.status || '') === 'verified'
    ) {
      await recordZkProofEvent({
        subjectRef: `wallet:${result.userWalletRef}`,
        circuitId: 'coverfi.user_kyc.status.v0',
        proofSystem: 'didit-kyc-attestation',
        proof: {
          provider: 'didit',
          eventId: String(payload.event_id || ''),
          workflowId: String(payload.workflow_id || DIDIT_KYC_WORKFLOW_ID || ''),
          providerSessionHash: crypto
            .createHash('sha256')
            .update(String(payload.session_id || payload.vendor_data || ''))
            .digest('hex'),
          status: normalizeDiditStatus(payload.status || ''),
        },
        publicSignals: {
          walletRef: result.userWalletRef,
          provider: 'didit',
          workflowId: String(payload.workflow_id || DIDIT_KYC_WORKFLOW_ID || ''),
          kycStatus: 'verified',
        },
        verificationStatus: 'verified',
        verifierNotes: 'Didit webhook signature verified; user KYC status attested without storing identity documents in the proof event.',
      });
    }
    return response.status(200).send('ok');
  } catch (error) {
    writeLog('error', 'didit_webhook_error', {
      message: error.message,
      statusCode: error.statusCode || 500,
    });
    return response.status(error.statusCode || 500).send('didit webhook failed');
  }
});

app.use(express.json({ limit: '32kb' }));

function writeLog(level, event, details = {}) {
  const payload = {
    level,
    event,
    at: new Date().toISOString(),
    ...details,
  };
  const line = JSON.stringify(payload);
  if (level === 'error') {
    console.error(line);
    return;
  }
  if (level === 'warn') {
    console.warn(line);
    return;
  }
  console.log(line);
}

function getRequestId() {
  return crypto.randomUUID();
}

function hmacPrivacyValue(value, label = 'value') {
  const normalized = String(value || '').trim().toLowerCase();
  if (!normalized) {
    return '';
  }

  return crypto
    .createHmac('sha256', env.server.privacyHmacSecret)
    .update(`${label}:${normalized}`)
    .digest('hex');
}

function walletLogRef(value) {
  const hashed = hmacPrivacyValue(value, 'wallet');
  return hashed ? `hmac:${hashed.slice(0, 16)}` : undefined;
}

function redactLogPath(value) {
  return String(value || '')
    .replace(/G[A-Z2-7]{55}/g, '[wallet]')
    .replace(/[a-fA-F0-9]{64}/g, '[tx]');
}

function redactSensitiveText(value) {
  return String(value || '')
    .replace(/(DATABASE_URL=|postgres(?:ql)?:\/\/)[^\s]+/gi, '$1[redacted]')
    .replace(/(RESEND_API_KEY|DIDIT_API_KEY|DIDIT_WEBHOOK_SECRET|AUTH_SESSION_SECRET|PRIVACY_HMAC_SECRET|PARTNER_API_KEY_PEPPER|UPSTASH_REDIS_REST_TOKEN)=?[A-Za-z0-9_\-./+=:]+/gi, '$1=[redacted]')
    .replace(/cf_(?:test|live)_[A-Za-z0-9_-]{20,}/g, 'cf_[redacted]')
    .replace(/cfs_[A-Za-z0-9_-]{20,}/g, 'cfs_[redacted]')
    .replace(/Bearer\s+[A-Za-z0-9._~+/-]+=*/gi, 'Bearer [redacted]')
    .replace(/G[A-Z2-7]{55}/g, '[wallet]');
}

function getClientKey(request, bucketName) {
  // This middleware runs before authentication. A caller-controlled wallet
  // header must never create a separate rate-limit bucket.
  const identity = request.ip || request.socket?.remoteAddress || 'unknown';
  return `${bucketName}:ip:${hmacPrivacyValue(identity, 'rate-limit:ip')}`;
}

function rateLimitStorageKey(key) {
  return `coverfi:ratelimit:${base64UrlEncode(key).slice(0, 180)}`;
}

async function incrementUpstashRateLimit(key, windowMs) {
  if (
    env.rateLimit.backend !== 'upstash' ||
    !env.rateLimit.upstashRestUrl ||
    !env.rateLimit.upstashRestToken
  ) {
    return null;
  }

  const windowId = Math.floor(Date.now() / windowMs);
  const redisKey = rateLimitStorageKey(`${key}:${windowId}`);
  const ttlSeconds = Math.max(1, Math.ceil(windowMs / 1000) + 5);
  const url = `${env.rateLimit.upstashRestUrl.replace(/\/+$/, '')}/pipeline`;
  const upstream = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.rateLimit.upstashRestToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify([
      ['INCR', redisKey],
      ['EXPIRE', redisKey, ttlSeconds],
    ]),
  });

  if (!upstream.ok) {
    throw new Error(`Upstash rate limit request failed: ${upstream.status}`);
  }

  const body = await upstream.json();
  const count = Number(body?.[0]?.result);
  if (!Number.isFinite(count)) {
    throw new Error('Upstash rate limit response did not include a counter.');
  }

  return {
    count,
    resetAt: (windowId + 1) * windowMs,
  };
}

function incrementMemoryRateLimit(key, windowMs) {
  const now = Date.now();
  const current = rateLimitBuckets.get(key);
  const bucket = current && current.resetAt > now
    ? current
    : { count: 0, resetAt: now + windowMs };

  bucket.count += 1;
  rateLimitBuckets.set(key, bucket);
  return bucket;
}

function createRateLimiter(bucketName, maxRequests, windowMs = env.rateLimit.windowMs) {
  return async (request, response, next) => {
    const key = getClientKey(request, bucketName);
    let bucket;
    try {
      bucket = await incrementUpstashRateLimit(key, windowMs);
    } catch (error) {
      writeLog('warn', 'rate_limit_upstash_fallback', {
        bucketName,
        message: error?.message || String(error),
      });
    }
    if (!bucket) {
      bucket = incrementMemoryRateLimit(key, windowMs);
    }

    response.setHeader('RateLimit-Limit', String(maxRequests));
    response.setHeader('RateLimit-Remaining', String(Math.max(0, maxRequests - bucket.count)));
    response.setHeader('RateLimit-Reset', String(Math.ceil(bucket.resetAt / 1000)));

    if (bucket.count > maxRequests) {
      return response.status(429).json({
        message: 'Too many requests. Please wait a moment and try again.',
      });
    }

    return next();
  };
}

app.use((request, response, next) => {
  const requestId = getRequestId();
  request.requestId = requestId;
  response.setHeader('X-Request-Id', requestId);
  const startedAt = Date.now();

  response.on('finish', () => {
    writeLog(response.statusCode >= 500 ? 'error' : 'info', 'http_request', {
      requestId,
      method: request.method,
      path: redactLogPath(request.originalUrl),
      status: response.statusCode,
      durationMs: Date.now() - startedAt,
      walletRef: walletLogRef(request.headers['x-coverfi-wallet-address']),
    });
  });

  next();
});

app.use('/api', createRateLimiter('general', env.rateLimit.generalMax));
app.use('/api/auth', createRateLimiter('auth', env.rateLimit.authMax));
app.use('/api/users', createRateLimiter('users', env.rateLimit.authMax));
app.use('/api/wallets', createRateLimiter('wallets', env.rateLimit.authMax));
app.use('/api/payments', createRateLimiter('payments', env.rateLimit.paymentsMax));
app.use('/api/receipts', createRateLimiter('receipts', env.rateLimit.paymentsMax));
app.use('/api/privacy', createRateLimiter('privacy', env.rateLimit.authMax));
app.use('/api/ai', createRateLimiter('ai', env.rateLimit.aiMax));
app.use('/api/partners', createRateLimiter('partners', env.rateLimit.partnerMax));
app.use('/api/onboarding', createRateLimiter('onboarding', env.rateLimit.authMax));
app.use('/api/onboarding/testnet/cftusd/fund', createRateLimiter('testnet-cftusd-faucet', Math.min(10, env.rateLimit.authMax)));
app.use('/api/zk', createRateLimiter('zk', env.rateLimit.partnerMax));
app.use('/api/analytics', createRateLimiter('analytics', env.rateLimit.partnerMax));

const localOnlyStorageBoundary = 'CoverFi does not store product profiles, legal acceptance, payment history, receipt details, or AI history in a backend product database. Private convenience records live in wallet-unlocked encrypted browser storage; protocol state lives on Stellar/Soroban.';

function localOnlyStoragePayload(extra = {}) {
  return {
    storage: 'browser_encrypted_indexeddb',
    backendProductDatabase: false,
    authoritativeState: 'soroban_contracts',
    boundary: localOnlyStorageBoundary,
    ...extra,
  };
}

function cleanUsername(value) {
  return String(value || '').trim();
}

function cleanWalletAddress(value) {
  return String(value || '').trim();
}

function sanitizeAiAccountContext(value, walletAddress) {
  if (!isPlainObject(value)) return null;

  const text = (input, limit = 160) => String(input || '').trim().slice(0, limit);
  const positions = Array.isArray(value.positions)
    ? value.positions.slice(0, 25).map((position) => ({
      asset: text(position?.asset, 32),
      status: text(position?.status, 48),
      protectedAmount: Number.isFinite(Number(position?.protectedAmount)) ? Number(position.protectedAmount) : null,
      expiryTime: text(position?.expiryTime, 64),
    }))
    : [];

  return {
    username: text(value.username, 64),
    walletAddress,
    network: value.network === 'mainnet' ? 'mainnet' : 'testnet',
    currentPage: text(value.currentPage, 64),
    positions,
    activity: Array.isArray(value.activity)
      ? value.activity.slice(-8).map((item) => ({ label: text(item?.label, 160), createdAt: text(item?.createdAt, 64) }))
      : [],
  };
}

function execFileAsync(file, args, options = {}) {
  return new Promise((resolve, reject) => {
    execFile(file, args, options, (error, stdout, stderr) => {
      if (error) {
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

async function runStellarCli(args) {
  const result = await execFileAsync('stellar', args, {
    cwd: process.cwd(),
    timeout: 120_000,
    windowsHide: true,
    maxBuffer: 1024 * 1024 * 4,
  });
  return `${result.stdout || ''}${result.stderr || ''}`.trim();
}

async function getStellarIdentityAddress(identity) {
  return runStellarCli(['keys', 'address', identity]);
}

async function submitFallbackOracleObservation({
  oracleAdapter,
  network,
  sourceIdentity,
  publisherAddress,
  assetContractId,
  scaledPrice,
  timestamp,
}) {
  return runStellarCli([
    'contract',
    'invoke',
    '--id',
    oracleAdapter,
    '--source',
    sourceIdentity,
    '--network',
    network,
    '--',
    'submit_fallback',
    '--publisher',
    publisherAddress,
    '--asset',
    assetContractId,
    '--price',
    scaledPrice,
    '--timestamp',
    timestamp,
  ]);
}

async function refreshFallbackOracle({ assetLabel = 'XLM Stellar', assetContractId = env.contracts.xlmToken, network = env.contracts.network || 'testnet' } = {}) {
  const oracleAdapter = cleanShortString(env.contracts.oracleAdapter, 120);
  const cleanAssetContractId = cleanShortString(assetContractId, 120);
  if (!oracleAdapter) {
    const error = new Error('Oracle adapter contract is not configured.');
    error.statusCode = 503;
    throw error;
  }
  if (!cleanAssetContractId) {
    const error = new Error('Oracle refresh asset contract is not configured.');
    error.statusCode = 503;
    throw error;
  }

  const now = Date.now();
  if (lastOracleRefreshResult && now - lastOracleRefreshAt < 15_000) {
    return { ...lastOracleRefreshResult, cached: true };
  }

  if (oracleRefreshInFlight) {
    return oracleRefreshInFlight;
  }

  oracleRefreshInFlight = (async () => {
    const publisher1Identity = cleanShortString(process.env.ORACLE_FALLBACK_PUBLISHER1_IDENTITY || 'admin1', 80);
    const publisher2Identity = cleanShortString(process.env.ORACLE_FALLBACK_PUBLISHER2_IDENTITY || 'admin2', 80);
    const publisher1Address = cleanShortString(
      process.env.ORACLE_FALLBACK_PUBLISHER1_ADDRESS || await getStellarIdentityAddress(publisher1Identity),
      120,
    );
    const publisher2Address = cleanShortString(
      process.env.ORACLE_FALLBACK_PUBLISHER2_ADDRESS || await getStellarIdentityAddress(publisher2Identity),
      120,
    );
    const price = await getUsdPriceForAsset(assetLabel);
    const scaledPrice = String(Math.round(Number(price.price) * ORACLE_PRICE_SCALE));
    const timestamp = String(Math.floor(Date.now() / 1000));

    if (!Number.isFinite(Number(scaledPrice)) || BigInt(scaledPrice) <= 0n) {
      const error = new Error(`Invalid scaled oracle price for ${assetLabel}.`);
      error.statusCode = 502;
      throw error;
    }

    const firstSubmission = await submitFallbackOracleObservation({
      oracleAdapter,
      network,
      sourceIdentity: publisher1Identity,
      publisherAddress: publisher1Address,
      assetContractId: cleanAssetContractId,
      scaledPrice,
      timestamp,
    });
    const secondSubmission = await submitFallbackOracleObservation({
      oracleAdapter,
      network,
      sourceIdentity: publisher2Identity,
      publisherAddress: publisher2Address,
      assetContractId: cleanAssetContractId,
      scaledPrice,
      timestamp,
    });

    const result = {
      ok: true,
      mode: 'fallback-quorum',
      network,
      oracleAdapter,
      asset: assetLabel,
      assetContractId: cleanAssetContractId,
      priceUsd: price.price,
      scaledPrice,
      provider: price.provider,
      lastUpdatedAt: price.lastUpdatedAt,
      timestamp,
      publishers: [
        { identity: publisher1Identity, address: publisher1Address },
        { identity: publisher2Identity, address: publisher2Address },
      ],
      submissions: [
        String(firstSubmission || '').slice(-1200),
        String(secondSubmission || '').slice(-1200),
      ],
    };
    lastOracleRefreshResult = result;
    lastOracleRefreshAt = Date.now();
    return result;
  })();

  try {
    return await oracleRefreshInFlight;
  } finally {
    oracleRefreshInFlight = null;
  }
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function cleanShortString(value, maxLength = 160) {
  return String(value || '').trim().slice(0, maxLength);
}

function decimalToStroops(value) {
  const text = String(value ?? '').trim();
  if (!/^\d+(\.\d{1,7})?$/.test(text)) {
    return null;
  }
  const [whole, fraction = ''] = text.split('.');
  return BigInt(whole) * 10_000_000n + BigInt(fraction.padEnd(7, '0'));
}

function stroopsToDecimalString(value) {
  const raw = BigInt(String(value || '0'));
  const sign = raw < 0n ? '-' : '';
  const absolute = raw < 0n ? -raw : raw;
  const whole = absolute / 10_000_000n;
  const fraction = String(absolute % 10_000_000n).padStart(7, '0').replace(/0+$/, '');
  return `${sign}${whole}${fraction ? `.${fraction}` : ''}`;
}

function durationDaysToSeconds(value) {
  const days = Number(value);
  if (!Number.isSafeInteger(days) || ![1, 7, 14, 30].includes(days)) {
    return null;
  }
  return days * 24 * 60 * 60;
}

function cleanStringArray(value, maxItems = 20, maxLength = 160) {
  return Array.isArray(value)
    ? value.map((item) => cleanShortString(item, maxLength)).filter(Boolean).slice(0, maxItems)
    : [];
}

function cleanHttpsCallbackUrl(value) {
  const raw = cleanShortString(value, 240);
  if (!raw) return '';
  try {
    const url = new URL(raw);
    const localHttp = !env.server.isProduction
      && url.protocol === 'http:'
      && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
    if (url.protocol !== 'https:' && !localHttp) return '';
    return isAllowedOrigin(url.origin) ? url.toString() : '';
  } catch {
    return '';
  }
}

function defaultDiditCallbackUrl(request) {
  const origin = requestOrigin(request) || env.server.clientOrigin;
  try {
    return new URL('/app/partner-sdk', origin).toString();
  } catch {
    return '';
  }
}

function serializeQuote(value) {
  const quote = value && typeof value === 'object' ? value : {};
  return {
    entryPrice: quote.entry_price || null,
    notional: quote.notional || null,
    maximumPayout: quote.maximum_payout || null,
    basePremium: quote.base_premium || null,
    volatilitySurcharge: quote.volatility_surcharge || null,
    utilizationSurcharge: quote.utilization_surcharge || null,
    concentrationSurcharge: quote.concentration_surcharge || null,
    safetyMargin: quote.safety_margin || null,
    riskPremium: quote.risk_premium || null,
    protocolCommission: quote.protocol_commission || null,
    automationFee: quote.automation_fee || null,
    totalDue: quote.total_due || null,
    utilizationBps: quote.utilization_bps || null,
    concentrationBps: quote.concentration_bps || null,
    volatilityBps: quote.volatility_bps || null,
  };
}

function isValidUsername(value) {
  return usernamePattern.test(cleanUsername(value));
}

function isReservedUsername(value) {
  const username = cleanUsername(value).toLowerCase();
  return reservedUsernames.has(username) || username.startsWith('coverfi_');
}

function isValidWalletAddress(value) {
  return walletAddressPattern.test(cleanWalletAddress(value));
}

function getWalletHeader(request) {
  return cleanWalletAddress(request.headers['x-coverfi-wallet-address']);
}

function getBearerToken(request) {
  const authorization = String(request.headers.authorization || '').trim();
  if (authorization.toLowerCase().startsWith('bearer ')) {
    return authorization.slice(7).trim();
  }

  return String(request.headers['x-coverfi-session-token'] || '').trim();
}

function requireWalletHeader(request, response) {
  const walletAddress = getWalletHeader(request);

  if (!walletAddress) {
    response.status(401).json({ message: 'Wallet header is required.' });
    return null;
  }

  if (!isValidWalletAddress(walletAddress)) {
    response.status(400).json({ message: 'Wallet header is not a valid Stellar public key.' });
    return null;
  }

  return walletAddress;
}

function requireWalletMatch(request, response, walletAddress) {
  const headerWallet = requireWalletHeader(request, response);
  if (!headerWallet) return false;

  if (headerWallet !== cleanWalletAddress(walletAddress)) {
    response.status(403).json({ message: 'Wallet header does not match this resource.' });
    return false;
  }

  return true;
}

function base64UrlEncode(value) {
  return Buffer.from(value)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(value) {
  const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='), 'base64');
}

function signSessionPayload(payload) {
  return base64UrlEncode(
    crypto
      .createHmac('sha256', env.server.authSessionSecret)
      .update(payload)
      .digest(),
  );
}

function createSessionToken(walletAddress) {
  const now = Date.now();
  const payload = base64UrlEncode(JSON.stringify({
    iss: env.server.authIssuer,
    aud: env.server.authAudience,
    jti: crypto.randomUUID(),
    walletAddress,
    iat: now,
    exp: now + env.server.authSessionTtlMs,
    termsVersion: env.server.termsVersion,
  }));
  return `${payload}.${signSessionPayload(payload)}`;
}

function pruneRevokedSessions() {
  const now = Date.now();
  for (const [tokenId, expiresAt] of revokedSessionIds.entries()) {
    if (Number(expiresAt) <= now) {
      revokedSessionIds.delete(tokenId);
    }
  }
}

function verifySessionToken(token) {
  const [payload, signature] = String(token || '').split('.');
  if (!payload || !signature) {
    return null;
  }

  const expected = signSessionPayload(payload);
  const expectedBuffer = Buffer.from(expected);
  const signatureBuffer = Buffer.from(signature);

  if (
    expectedBuffer.length !== signatureBuffer.length ||
    !crypto.timingSafeEqual(expectedBuffer, signatureBuffer)
  ) {
    return null;
  }

  try {
    const parsed = JSON.parse(base64UrlDecode(payload).toString('utf8'));
    pruneRevokedSessions();
    if (
      parsed.iss !== env.server.authIssuer ||
      parsed.aud !== env.server.authAudience ||
      !parsed.jti ||
      revokedSessionIds.has(parsed.jti) ||
      !isValidWalletAddress(parsed.walletAddress) ||
      Number(parsed.exp) <= Date.now() ||
      parsed.termsVersion !== env.server.termsVersion
    ) {
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
}

function requireEmailSession(request, response) {
  const session = verifyEmailSessionToken(getBearerToken(request));
  if (!session) {
    response.status(401).json({ message: 'Verified email session is required.' });
    return null;
  }

  return session;
}

function requireWalletSession(request, response, walletAddress) {
  if (!requireWalletMatch(request, response, walletAddress)) {
    return false;
  }

  const token = getBearerToken(request);
  if (!token) {
    response.status(401).json({ message: 'Signed wallet session is required.' });
    return false;
  }

  const session = verifySessionToken(token);
  if (!session) {
    response.status(401).json({ message: 'Signed wallet session is invalid or expired.' });
    return false;
  }

  if (session.walletAddress !== cleanWalletAddress(walletAddress)) {
    response.status(403).json({ message: 'Signed wallet session does not match this resource.' });
    return false;
  }

  request.walletSession = session;
  return true;
}

function requireConfiguredDatabase(response) {
  if (isDatabaseConfigured()) {
    return true;
  }

  response.status(503).json({
    message: 'DATABASE_URL is not configured. Partner sandbox and analytics storage are disabled.',
  });
  return false;
}

function partnerApiError(response, status, code, message, requestId) {
  return response.status(status).json({
    error: {
      code,
      message,
      requestId,
    },
  });
}

function requestOrigin(request) {
  return String(request.headers.origin || '').trim();
}

function requestIp(request) {
  return String(request.ip || request.socket?.remoteAddress || '').replace(/^::ffff:/, '');
}

function requirePartnerAdminSession(request, response) {
  const walletAddress = requireWalletHeader(request, response);
  if (!walletAddress) return null;

  if (!requireWalletSession(request, response, walletAddress)) {
    return null;
  }

  if (!isPartnerAdminWallet(walletAddress)) {
    response.status(403).json({ message: 'This wallet is not configured as a partner administrator.' });
    return null;
  }

  return {
    walletAddress,
    walletRef: walletLogRef(walletAddress),
  };
}

async function requirePartnerApiSession(request, response, scope) {
  if (!requireConfiguredDatabase(response)) {
    return null;
  }

  const requestId = request.requestId || getRequestId();
  const credentialHeader = request.headers.authorization || request.headers['x-coverfi-partner-key'];
  const key = await authenticatePartnerApiKey(credentialHeader, scope)
    || await authenticatePartnerSession(credentialHeader, scope);
  if (!key) {
    partnerApiError(response, 401, 'invalid_api_key', 'The provided API key or session token is invalid.', requestId);
    return null;
  }

  const origin = requestOrigin(request);
  const ip = requestIp(request);
  const allowedOrigins = [
    ...(Array.isArray(key.allowed_origins) ? key.allowed_origins : []),
    ...(Array.isArray(key.application_allowed_origins) ? key.application_allowed_origins : []),
  ].filter(Boolean);
  if (origin && allowedOrigins.length && !allowedOrigins.includes(origin)) {
    partnerApiError(response, 403, 'origin_not_allowed', 'This origin is not allowed for the provided API key.', requestId);
    return null;
  }

  const allowedIps = [
    ...(Array.isArray(key.allowed_ip_addresses) ? key.allowed_ip_addresses : []),
    ...(Array.isArray(key.application_allowed_ip_addresses) ? key.application_allowed_ip_addresses : []),
  ].filter(Boolean);
  if (ip && allowedIps.length && !allowedIps.includes(ip)) {
    partnerApiError(response, 403, 'ip_not_allowed', 'This IP address is not allowed for the provided API key.', requestId);
    return null;
  }

  request.partnerApiKey = key;
  return key;
}

function challengeKey(walletAddress, nonce) {
  return `${walletAddress}:${nonce}`;
}

function createChallengeMessage(walletAddress, nonce, expiresAt, origin) {
  return [
    'CoverFi wallet authentication',
    `Wallet: ${walletAddress}`,
    `Nonce: ${nonce}`,
    `Origin: ${origin || 'unknown'}`,
    `Terms: ${env.server.termsVersion}`,
    `Expires: ${new Date(expiresAt).toISOString()}`,
  ].join('\n');
}

function decodeSignatureBuffer(signature) {
  let cleaned = String(signature || '').trim();
  cleaned = cleaned.replace(/^base64:/i, '').replace(/\s+/g, '');
  const withoutHexPrefix = cleaned.replace(/^0x/i, '');
  if (/^[a-fA-F0-9]+$/.test(withoutHexPrefix) && withoutHexPrefix.length % 2 === 0 && withoutHexPrefix.length >= 128) {
    return Buffer.from(withoutHexPrefix, 'hex');
  }

  cleaned = cleaned.replace(/-/g, '+').replace(/_/g, '/');
  while (cleaned.length % 4 !== 0) {
    cleaned += '=';
  }

  return Buffer.from(cleaned, 'base64');
}

function addSignatureCandidate(candidates, value) {
  if (!Buffer.isBuffer(value) || value.length !== 64) {
    return;
  }
  const key = value.toString('base64');
  if (!candidates.some((candidate) => candidate.toString('base64') === key)) {
    candidates.push(value);
  }
}

function getSignatureDebug(signature) {
  try {
    const raw = decodeSignatureBuffer(signature);
    return {
      encodedLength: String(signature || '').trim().length,
      decodedLength: raw.length,
      candidateLengths: decodeSignatureCandidates(signature).map((candidate) => candidate.length),
    };
  } catch {
    return {
      encodedLength: String(signature || '').trim().length,
      decodedLength: null,
      candidateLengths: [],
    };
  }
}

function decodeSignatureCandidates(signature) {
  const raw = decodeSignatureBuffer(signature);
  const candidates = [];
  addSignatureCandidate(candidates, raw);
  addSignatureCandidate(candidates, raw.subarray(4, 68));
  addSignatureCandidate(candidates, raw.subarray(8, 72));
  if (raw.length >= 64) {
    addSignatureCandidate(candidates, raw.subarray(raw.length - 64));
  }
  return candidates;
}

function getSep53MessageHash(message) {
  return crypto
    .createHash('sha256')
    .update(Buffer.from(`Stellar Signed Message:\n${message}`, 'utf8'))
    .digest();
}

function verifyWalletSignature(walletAddress, message, signature) {
  try {
    const keypair = Keypair.fromPublicKey(walletAddress);
    const messageBuffer = Buffer.from(message, 'utf8');
    const encodedMessageBuffer = Buffer.from(messageBuffer.toString('base64'), 'utf8');
    const messageHash = crypto.createHash('sha256').update(messageBuffer).digest();
    const encodedMessageHash = crypto.createHash('sha256').update(encodedMessageBuffer).digest();
    const sep53MessageHash = getSep53MessageHash(message);
    const sep53EncodedMessageHash = getSep53MessageHash(messageBuffer.toString('base64'));
    const payloads = [
      sep53MessageHash,
      messageBuffer,
      encodedMessageBuffer,
      messageHash,
      encodedMessageHash,
      sep53EncodedMessageHash,
    ];

    for (const signatureBuffer of decodeSignatureCandidates(signature)) {
      if (payloads.some((payload) => keypair.verify(payload, signatureBuffer))) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

function verifyWalletSignatureBuffer(walletAddress, messageBuffer, signature) {
  try {
    const keypair = Keypair.fromPublicKey(walletAddress);
    const messageHash = crypto.createHash('sha256').update(messageBuffer).digest();
    for (const signatureBuffer of decodeSignatureCandidates(signature)) {
      if (keypair.verify(messageBuffer, signatureBuffer) || keypair.verify(messageHash, signatureBuffer)) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

function validateZkProofSubmission({ subjectRef, circuitId, proofSystem, proof }) {
  const cleanSubjectRef = cleanShortString(subjectRef, 180);
  if (!zkProofCircuitIds.has(circuitId)) {
    const error = new Error('Unsupported ZK proof circuit.');
    error.statusCode = 400;
    throw error;
  }

  if (proofSystem !== 'stellar-ed25519') {
    const error = new Error('Only Stellar Ed25519 proof events are accepted by this backend path.');
    error.statusCode = 400;
    throw error;
  }

  if (!isPlainObject(proof)) {
    const error = new Error('Proof body is required.');
    error.statusCode = 400;
    throw error;
  }

  const signer = cleanWalletAddress(proof.signer);
  const signature = cleanShortString(proof.signature, 5000);
  const message = String(proof.message || '');
  const digest = cleanShortString(proof.digest, 128).toLowerCase();
  const scheme = cleanShortString(proof.scheme, 80);

  if (!isValidWalletAddress(signer) || !signature || !message || !/^[a-f0-9]{64}$/.test(digest)) {
    const error = new Error('Proof must include signer, message, digest, and signature.');
    error.statusCode = 400;
    throw error;
  }

  if (isValidWalletAddress(cleanSubjectRef) && cleanWalletAddress(cleanSubjectRef) !== signer) {
    const error = new Error('Proof signer does not match the proof subject.');
    error.statusCode = 403;
    throw error;
  }

  const expectedDigest = crypto
    .createHash('sha256')
    .update(Buffer.from(message, 'utf8'))
    .digest('hex');
  if (expectedDigest !== digest) {
    const error = new Error('Proof digest does not match the signed message.');
    error.statusCode = 400;
    throw error;
  }

  const valid = scheme === 'stellar-ed25519-sha256'
    ? verifyWalletSignatureBuffer(signer, Buffer.from(digest, 'hex'), signature)
    : verifyWalletSignature(signer, message, signature);

  if (!valid) {
    const error = new Error('Proof signature could not be verified.');
    error.statusCode = 401;
    throw error;
  }

  return {
    signer,
    subjectRef: cleanSubjectRef || signer,
  };
}

function sanitizeProfile(profile) {
  if (!isPlainObject(profile)) {
    return null;
  }

  return {
    fullName: cleanShortString(profile.fullName, 100),
    contact: cleanShortString(profile.contact, 120),
    city: cleanShortString(profile.city, 80),
    createdAt: cleanShortString(profile.createdAt, 80),
  };
}

function sanitizeAccountData(data) {
  if (!isPlainObject(data)) {
    return null;
  }

  const positions = Array.isArray(data.positions) ? data.positions.slice(0, 100) : [];
  const activity = Array.isArray(data.activity) ? data.activity.slice(0, 200) : [];

  return { positions, activity };
}

function sanitizeReceiptData(receiptData) {
  if (!isPlainObject(receiptData)) {
    return null;
  }

  const txHash = cleanShortString(receiptData.txHash, 80);
  if (!txHashPattern.test(txHash)) {
    return null;
  }

  return {
    status: cleanShortString(receiptData.status, 32),
    from: cleanShortString(receiptData.from, 120),
    to: cleanShortString(receiptData.to, 160),
    amount: cleanShortString(receiptData.amount, 80),
    fee: cleanShortString(receiptData.fee, 80),
    txHash,
    receiptHash: receiptHashPattern.test(cleanShortString(receiptData.receiptHash, 80))
      ? cleanShortString(receiptData.receiptHash, 80).toLowerCase()
      : '',
    date: cleanShortString(receiptData.date, 80),
  };
}

function redactPartnerLogValue(value, depth = 0) {
  if (depth > 5) return '[redacted-depth]';
  if (Array.isArray(value)) return value.slice(0, 25).map((item) => redactPartnerLogValue(item, depth + 1));
  if (!value || typeof value !== 'object') return value;

  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => {
      const normalized = key.toLowerCase();
      if (
        normalized.includes('wallet') ||
        normalized.includes('address') ||
        normalized.includes('signature') ||
        normalized.includes('token') ||
        normalized.includes('secret') ||
        normalized.includes('xdr') ||
        normalized.includes('payload')
      ) {
        return [key, '[redacted]'];
      }
      return [key, redactPartnerLogValue(item, depth + 1)];
    }),
  );
}

function toIsoTimestamp(value) {
  if (!value) {
    return null;
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (typeof value.toDate === 'function') {
    return value.toDate().toISOString();
  }

  return value;
}

function buildMarketContext(markets) {
  if (!markets?.coins?.length) {
    return null;
  }

  const importantSymbols = new Set(['XLM', 'USDC', 'USDT', 'PYUSD', 'EURC']);
  const coins = markets.coins
    .filter((coin, index) => index < 12 || importantSymbols.has(coin.symbol))
    .slice(0, 20)
    .map((coin) => ({
      symbol: coin.symbol,
      name: coin.name,
      priceUsd: coin.currentPrice,
      change1h: coin.priceChangePercentage1h,
      change24h: coin.priceChangePercentage24h,
      change7d: coin.priceChangePercentage7d,
      high24h: coin.high24h,
      low24h: coin.low24h,
      lastUpdated: coin.lastUpdated,
    }));

  return {
    provider: markets.provider,
    currency: markets.currency,
    lastFetchedAt: markets.lastFetchedAt,
    coins,
  };
}

function serializeNativeValue(value) {
  if (typeof value === 'bigint') {
    return value.toString();
  }

  if (Array.isArray(value)) {
    return value.map(serializeNativeValue);
  }

  if (value && typeof value === 'object') {
    if (typeof value.toString === 'function' && value.constructor?.name === 'Address') {
      return value.toString();
    }

    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, serializeNativeValue(item)]),
    );
  }

  return value;
}

async function simulateContractRead(contractId, method, args = []) {
  if (!contractId) {
    const error = new Error(`Contract ID is missing for ${method}.`);
    error.statusCode = 503;
    throw error;
  }
  if (!env.contracts.statusSourceAccount) {
    const error = new Error('STELLAR_STATUS_SOURCE_ACCOUNT is required for contract status reads.');
    error.statusCode = 503;
    throw error;
  }

  const server = new rpc.Server(env.contracts.rpcUrl, {
    allowHttp: env.contracts.rpcUrl.startsWith('http://'),
  });
  const source = await server.getAccount(env.contracts.statusSourceAccount);
  const contract = new Contract(contractId);
  const transaction = new TransactionBuilder(source, {
    fee: BASE_FEE,
    networkPassphrase: env.contracts.networkPassphrase,
  })
    .addOperation(contract.call(method, ...args))
    .setTimeout(30)
    .build();

  const result = await server.simulateTransaction(transaction);
  if (result.error) {
    throw new Error(String(result.error));
  }

  return result.result?.retval
    ? serializeNativeValue(scValToNative(result.result.retval))
    : null;
}

function recordOracleStatus(status) {
  const sample = {
    status: String(status.status || 'unknown'),
    lastUpdated: status.lastUpdated || null,
    ageSeconds: Number.isFinite(Number(status.ageSeconds)) ? Number(status.ageSeconds) : null,
    checkedAt: status.checkedAt,
  };
  const previous = oracleStatusHistory.at(-1);
  if (!previous || previous.status !== sample.status || previous.lastUpdated !== sample.lastUpdated) {
    oracleStatusHistory.push(sample);
  }
  const cutoff = Date.now() - (24 * 60 * 60 * 1000);
  while (oracleStatusHistory.length > 96 || (oracleStatusHistory[0] && Date.parse(oracleStatusHistory[0].checkedAt) < cutoff)) {
    oracleStatusHistory.shift();
  }
}

async function readReserveStatus() {
  const token = env.contracts.payoutToken || env.contracts.xlmToken;
  const tokenArg = Address.fromString(token).toScVal();
  const [pool, availableLiquidity, utilizationBps, providerNav] = await Promise.all([
    simulateContractRead(env.contracts.reserveVault, 'get_pool', [tokenArg]),
    simulateContractRead(env.contracts.reserveVault, 'get_available_liquidity', [tokenArg]),
    simulateContractRead(env.contracts.reserveVault, 'get_utilization_bps', [tokenArg]),
    simulateContractRead(env.contracts.reserveVault, 'get_provider_nav', [tokenArg]),
  ]);
  return {
    ok: true,
    status: Number(availableLiquidity || 0) > 0 ? 'funded' : 'empty',
    token,
    pool,
    // Promote critical fields so clients do not have to infer reserve accounting.
    collateral: pool?.total_assets ?? null,
    lockedLiabilities: pool?.locked_liabilities ?? null,
    reservedClaims: pool?.reserved_claims ?? null,
    availableLiquidity,
    utilizationBps,
    providerNav,
    checkedAt: new Date().toISOString(),
  };
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

async function createTestnetReserveAttestation() {
  if (env.contracts.network !== 'testnet' || !env.reserveAttestation.secret) {
    return { status: 'not_configured', message: 'A testnet reserve attestation signer is not configured.' };
  }
  if (reserveAttestationCache?.expiresAt > Date.now()) return reserveAttestationCache.value;

  let signer;
  try {
    signer = Keypair.fromSecret(env.reserveAttestation.secret);
  } catch {
    return { status: 'not_configured', message: 'The configured testnet reserve attestation signer is invalid.' };
  }
  if (env.reserveAttestation.publicKey && signer.publicKey() !== env.reserveAttestation.publicKey) {
    return { status: 'not_configured', message: 'The configured testnet reserve attestation public key does not match its signer.' };
  }

  const reserve = await readReserveStatus();
  const payload = canonicalJson({
    version: 'coverfi.reserve-attestation.v1',
    network: env.contracts.network,
    reserveVault: env.contracts.reserveVault,
    token: reserve.token,
    collateral: reserve.collateral === null ? null : String(reserve.collateral),
    lockedLiabilities: reserve.lockedLiabilities === null ? null : String(reserve.lockedLiabilities),
    reservedClaims: reserve.reservedClaims === null ? null : String(reserve.reservedClaims),
    availableLiquidity: reserve.availableLiquidity === null ? null : String(reserve.availableLiquidity),
    utilizationBps: reserve.utilizationBps === null ? null : String(reserve.utilizationBps),
    providerNav: reserve.providerNav === null ? null : String(reserve.providerNav),
    checkedAt: reserve.checkedAt,
  });
  const value = {
    status: 'signed_testnet_snapshot',
    algorithm: 'ed25519',
    publicKey: signer.publicKey(),
    payload,
    signature: Buffer.from(signer.sign(Buffer.from(payload, 'utf8'))).toString('base64'),
    checkedAt: reserve.checkedAt,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    disclaimer: 'Testnet operational attestation only; not an audit, custodial proof, or guarantee of payout.',
  };
  reserveAttestationCache = { expiresAt: Date.now() + 60_000, value };
  return value;
}

function usernameRecordToUser(record) {
  if (!record?.name || !record?.owner) {
    return null;
  }

  return {
    username: String(record.name),
    usernameLower: String(record.name).toLowerCase(),
    walletAddress: String(record.owner),
    registeredAt: record.registered_at ? new Date(Number(record.registered_at) * 1000).toISOString() : null,
    expiresAt: record.expires_at ? new Date(Number(record.expires_at) * 1000).toISOString() : null,
    source: 'soroban_username_registry',
  };
}

async function readUsernameRecord(username) {
  const record = await simulateContractRead(env.contracts.usernameRegistry, 'get_record', [
    nativeToScVal(username, { type: 'string' }),
  ]);

  return usernameRecordToUser(record);
}

async function readWalletUsername(walletAddress) {
  const username = await simulateContractRead(env.contracts.usernameRegistry, 'get_username', [
    Address.fromString(walletAddress).toScVal(),
  ]);
  if (!username) {
    return null;
  }

  return readUsernameRecord(String(username));
}

function normalizeExternalBaseUrl(value) {
  return String(value || '').trim().replace(/\/#?$/, '').replace(/\/+$/, '');
}

function statuspageComponentTargets() {
  return [
    ['dashboard', 'Dashboard', env.statuspage.components.dashboard],
    ['protect', 'Protect flow', env.statuspage.components.protect],
    ['payUsername', 'Pay username', env.statuspage.components.payUsername],
  ]
    .filter(([, , id]) => Boolean(id))
    .map(([key, label, id]) => ({ key, label, id }));
}

function sanitizeStatuspageComponent(component, fallback = {}) {
  return {
    key: fallback.key || '',
    id: String(component?.id || fallback.id || ''),
    name: String(component?.name || fallback.label || 'Statuspage component'),
    status: String(component?.status || 'unknown'),
    description: String(component?.description || ''),
    updatedAt: component?.updated_at || component?.updatedAt || null,
  };
}

function statuspageOverallOk(indicator, components) {
  const normalizedIndicator = String(indicator || '').toLowerCase();
  if (normalizedIndicator && normalizedIndicator !== 'none') {
    return false;
  }

  return components.every((component) => {
    const status = String(component.status || '').toLowerCase();
    return !status || status === 'operational' || status === 'under_maintenance';
  });
}

async function fetchStatuspageSummary() {
  const publicUrl = normalizeExternalBaseUrl(env.statuspage.publicUrl);
  let publicError = null;

  if (publicUrl) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), env.statuspage.timeoutMs);
    try {
      const [upstream, incidentsResponse, maintenancesResponse] = await Promise.all([
        fetch(`${publicUrl}/api/v2/summary.json`, {
          headers: { Accept: 'application/json' },
          signal: controller.signal,
        }),
        fetch(`${publicUrl}/api/v2/incidents.json`, {
          headers: { Accept: 'application/json' },
          signal: controller.signal,
        }),
        fetch(`${publicUrl}/api/v2/scheduled-maintenances.json`, {
          headers: { Accept: 'application/json' },
          signal: controller.signal,
        }),
      ]);
      const contentType = String(upstream.headers.get('content-type') || '');
      if (!upstream.ok) {
        const error = new Error(`Statuspage summary request failed with HTTP ${upstream.status}.`);
        error.statusCode = 502;
        throw error;
      }
      if (!contentType.includes('application/json')) {
        const error = new Error('Statuspage summary did not return JSON. Confirm the public Statuspage is published and the URL is correct.');
        error.statusCode = 502;
        throw error;
      }

      const summary = await upstream.json();
      const readOptionalHistory = async (response, key) => {
        if (!response.ok || !String(response.headers.get('content-type') || '').includes('application/json')) return [];
        try {
          const body = await response.json();
          return Array.isArray(body?.[key]) ? body[key].slice(0, 10) : [];
        } catch {
          return [];
        }
      };
      return {
        ...summary,
        incidents: await readOptionalHistory(incidentsResponse, 'incidents'),
        scheduled_maintenances: await readOptionalHistory(maintenancesResponse, 'scheduled_maintenances'),
      };
    } catch (error) {
      publicError = error;
    } finally {
      clearTimeout(timeout);
    }
  }

  if (!env.statuspage.apiKey || !env.statuspage.pageId) {
    if (publicError) throw publicError;
    const error = new Error('STATUSPAGE_PUBLIC_URL or STATUSPAGE_API_KEY plus STATUSPAGE_PAGE_ID must be configured.');
    error.statusCode = 501;
    throw error;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), env.statuspage.timeoutMs);
  try {
    const baseUrl = `https://api.statuspage.io/v1/pages/${encodeURIComponent(env.statuspage.pageId)}`;
    const headers = {
      Accept: 'application/json',
      Authorization: `OAuth ${env.statuspage.apiKey}`,
    };
    const [pageResponse, componentsResponse] = await Promise.all([
      fetch(baseUrl, { headers, signal: controller.signal }),
      fetch(`${baseUrl}/components`, { headers, signal: controller.signal }),
    ]);

    if (!pageResponse.ok || !componentsResponse.ok) {
      const error = new Error(`Statuspage API request failed with HTTP ${pageResponse.status}/${componentsResponse.status}.`);
      error.statusCode = 502;
      throw error;
    }

    const [page, components] = await Promise.all([
      pageResponse.json(),
      componentsResponse.json(),
    ]);

    return {
      page: {
        id: page.id || env.statuspage.pageId,
        name: page.name,
        url: page.url || publicUrl,
        updated_at: page.updated_at,
      },
      status: {
        indicator: page.status_indicator || 'unknown',
        description: page.status_description || '',
      },
      components: Array.isArray(components) ? components : [],
      incidents: [],
      scheduled_maintenances: [],
    };
  } finally {
    clearTimeout(timeout);
  }
}

function logApiError(context, error) {
  const detail = redactSensitiveText(error instanceof Error ? error.stack || error.message : String(error));
  writeLog('error', context, { detail });
}

function sendApiError(response, status, message, error, context) {
  logApiError(context, error);
  response.status(status).json({ message });
}

app.get('/api/health', async (_request, response) => {
  response.json({
    ok: true,
    aiConfigured: isDeepSeekConfigured(),
    accountStorage: 'browser_encrypted_indexeddb',
    receiptStorage: 'browser_encrypted_indexeddb',
    analyticsWalletStorage: 'hmac_only',
    backendProductDatabase: false,
    termsVersion: env.server.termsVersion,
  });
});

app.get('/api/legal/status', (_request, response) => {
  response.json({
    termsVersion: env.server.termsVersion,
    protectionDisclaimer: 'CoverFi protection is not insurance and does not guarantee a payout.',
  });
});

app.get('/api/status/contracts', (_request, response) => {
  response.json({
    network: env.contracts.network,
    rpcUrl: env.contracts.rpcUrl,
    networkPassphrase: env.contracts.networkPassphrase,
    sourceAccount: env.contracts.statusSourceAccount,
    contracts: {
      protectionEngine: env.contracts.protectionEngine,
      protectedBalanceVault: env.contracts.protectedBalanceVault,
      reserveVault: env.contracts.reserveVault,
      oracleAdapter: env.contracts.oracleAdapter,
      usernameRegistry: env.contracts.usernameRegistry,
      receiptRegistry: env.contracts.receiptRegistry,
      zkVerifier: env.contracts.zkVerifier,
    },
  });
});

app.get('/api/status/indexer', async (_request, response) => {
  try {
    const status = await getIndexerStatus();
    response.status(status.databaseConfigured ? 200 : 503).json({
      ...status,
      checkedAt: new Date().toISOString(),
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not read indexer status.', error, 'status/indexer');
  }
});

app.get('/api/status/readiness', async (_request, response) => {
  try {
    const [indexer] = await Promise.all([
      getIndexerStatus().catch((error) => ({
        ok: false,
        error: error.message || 'indexer status unavailable',
      })),
    ]);

    const contracts = {
      protectionEngine: env.contracts.protectionEngine,
      protectedBalanceVault: env.contracts.protectedBalanceVault,
      reserveVault: env.contracts.reserveVault,
      oracleAdapter: env.contracts.oracleAdapter,
      usernameRegistry: env.contracts.usernameRegistry,
      receiptRegistry: env.contracts.receiptRegistry,
      zkVerifier: env.contracts.zkVerifier,
    };
    const contractValues = Object.values(contracts);
    const contractsReady = contractValues.every(Boolean);
    const productionBlocked = env.contracts.network === 'mainnet';
    const checks = [
      {
        id: 'database',
        label: 'Database',
        ok: isDatabaseConfigured(),
        detail: isDatabaseConfigured() ? 'Configured' : 'DATABASE_URL missing',
      },
      {
        id: 'contracts',
        label: 'Contract registry',
        ok: contractsReady,
        detail: contractsReady ? 'All configured' : 'Missing one or more contract IDs',
      },
      {
        id: 'indexer',
        label: 'History indexer',
        ok: Boolean(indexer.ok),
        detail: indexer.ok ? `${indexer.eventCount24h || 0} events in 24h` : 'Not synced',
      },
      {
        id: 'email',
        label: 'Email OTP',
        ok: Boolean(env.onboarding.resendApiKey && env.onboarding.emailFrom),
        detail: env.onboarding.resendApiKey ? 'Resend configured' : 'RESEND_API_KEY missing',
      },
      {
        id: 'didit',
        label: 'KYC/KYB',
        ok: isDiditConfigured(),
        detail: isDiditConfigured() ? 'Didit configured' : 'Didit credentials missing',
      },
      {
        id: 'mainnet-gate',
        label: 'Mainnet gate',
        ok: !productionBlocked,
        detail: productionBlocked
          ? 'Mainnet should remain blocked until audit, multisig, legal, and production oracle are complete'
          : 'Testnet launch mode',
      },
    ];
    const score = Math.round((checks.filter((check) => check.ok).length / checks.length) * 100);

    response.json({
      ok: score >= 75 && !productionBlocked,
      score,
      launchTarget: 'testnet-product-hunt-beta',
      network: env.contracts.network,
      checks,
      contracts,
      indexer,
      checkedAt: new Date().toISOString(),
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not read readiness status.', error, 'status/readiness');
  }
});

app.get('/api/status/atlassian', async (_request, response) => {
  try {
    const summary = await fetchStatuspageSummary();
    const targets = statuspageComponentTargets();
    const upstreamComponents = Array.isArray(summary.components) ? summary.components : [];
    const byId = new Map(upstreamComponents.map((component) => [String(component.id), component]));
    const components = targets.length
      ? targets.map((target) => sanitizeStatuspageComponent(byId.get(target.id), target))
      : upstreamComponents.map((component) => sanitizeStatuspageComponent(component));
    const indicator = String(summary.status?.indicator || 'unknown');

    response.json({
      ok: statuspageOverallOk(indicator, components),
      status: indicator,
      description: String(summary.status?.description || ''),
      page: {
        id: summary.page?.id || env.statuspage.pageId || '',
        name: summary.page?.name || 'CoverFi Statuspage',
        url: summary.page?.url || normalizeExternalBaseUrl(env.statuspage.publicUrl),
        updatedAt: summary.page?.updated_at || null,
      },
      components,
      incidents: Array.isArray(summary.incidents) ? summary.incidents.slice(0, 5) : [],
      scheduledMaintenances: Array.isArray(summary.scheduled_maintenances)
        ? summary.scheduled_maintenances.slice(0, 5)
        : [],
      checkedAt: new Date().toISOString(),
    });
  } catch (error) {
    const status = Number(error?.statusCode || 502);
    return sendApiError(
      response,
      status,
      error.message || 'Could not read Atlassian Statuspage.',
      error,
      'status/atlassian',
    );
  }
});

app.get('/api/status/oracle', async (_request, response) => {
  try {
    const asset = env.contracts.xlmToken;
    const [latest, fresh, oracleConfig] = await Promise.all([
      simulateContractRead(env.contracts.oracleAdapter, 'get_latest', [
        Address.fromString(asset).toScVal(),
      ]),
      simulateContractRead(env.contracts.oracleAdapter, 'get_fresh_price', [
        Address.fromString(asset).toScVal(),
      ]),
      simulateContractRead(env.contracts.oracleAdapter, 'get_config'),
    ]);
    const now = Math.floor(Date.now() / 1000);
    const observation = fresh || latest;
    const lastUpdatedSeconds = Number(observation?.timestamp || 0);
    const maxAgeSeconds = Number(oracleConfig?.max_age_seconds || 0);
    const ageSeconds = lastUpdatedSeconds > 0 ? now - lastUpdatedSeconds : null;

    const status = {
      ok: Boolean(fresh),
      status: fresh ? 'fresh' : latest ? 'stale' : 'missing',
      asset,
      price: observation?.price || null,
      lastUpdated: observation?.timestamp || null,
      checkedAt: new Date().toISOString(),
      ageSeconds,
      maxAgeSeconds,
      fallbackEnabled: Boolean(oracleConfig?.fallback_enabled),
      source: oracleConfig?.source || null,
      sourceAsset: oracleConfig?.source_asset || null,
    };
    recordOracleStatus(status);
    response.json({
      ...status,
      // Volatile server-runtime observations, retained only for operational visibility.
      historyScope: 'runtime_24h_buffer',
      history: oracleStatusHistory,
    });
  } catch (error) {
    return sendApiError(response, 502, error.message || 'Could not read oracle status.', error, 'status/oracle');
  }
});

app.post('/api/status/oracle/refresh', async (request, response) => {
  try {
    if (!env.oracle.automaticRefreshEnabled) {
      return response.status(404).json({ message: 'Automatic oracle refresh is disabled.' });
    }
    const adminSession = requirePartnerAdminSession(request, response);
    if (!adminSession) return null;
    if (request.body && !isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }

    const assetLabel = cleanShortString(request.body?.asset || 'XLM Stellar', 80);
    const network = cleanShortString(request.body?.network || env.contracts.network || 'testnet', 40);
    if (!['testnet', 'mainnet'].includes(network)) {
      return response.status(400).json({ message: 'Use testnet or mainnet.' });
    }

    if (network === 'mainnet') {
      return response.status(409).json({
        message: 'Automatic fallback oracle publishing is disabled on mainnet. Configure a production oracle publisher before enabling this endpoint.',
      });
    }

    const result = await refreshFallbackOracle({
      assetLabel,
      assetContractId: env.contracts.xlmToken,
      network,
    });

    return response.status(result.cached ? 200 : 201).json({
      ...result,
      checkedAt: new Date().toISOString(),
    });
  } catch (error) {
    const detail = [
      error.message || 'Could not refresh oracle automatically.',
      error.stderr || '',
      error.stdout || '',
    ].filter(Boolean).join('\n').slice(0, 1800);
    return sendApiError(
      response,
      error.statusCode || 502,
      detail || 'Could not refresh oracle automatically.',
      error,
      'status/oracle/refresh',
    );
  }
});

app.get('/api/status/reserve', async (_request, response) => {
  try {
    response.json(await readReserveStatus());
  } catch (error) {
    const token = env.contracts.payoutToken || env.contracts.xlmToken;
    const message = error instanceof Error ? error.message : String(error || '');
    if (message.includes('MissingValue') || message.includes('non-existent contract function')) {
      return response.json({
        ok: false,
        status: 'legacy_mismatch',
        token,
        reserveVault: env.contracts.reserveVault,
        message: 'The configured reserve contract does not expose the V2 reserve status ABI. Redeploy, initialize, and fund the V2 reserve before enabling Protect.',
        checkedAt: new Date().toISOString(),
      });
    }
    return sendApiError(response, 502, error.message || 'Could not read reserve status.', error, 'status/reserve');
  }
});

app.get('/api/status/proof-of-reserve', async (_request, response) => {
  try {
    response.json(await createTestnetReserveAttestation());
  } catch (error) {
    return sendApiError(response, error.statusCode || 502, 'Could not create the testnet reserve attestation.', error, 'status/proof-of-reserve');
  }
});

app.get('/api/history/:walletAddress', async (request, response) => {
  try {
    const walletAddress = cleanWalletAddress(request.params.walletAddress);
    if (!isValidWalletAddress(walletAddress)) {
      return response.status(400).json({ message: 'A valid Stellar wallet address is required.' });
    }

    const limit = Number(request.query.limit || 50);
    const activity = await listWalletActivity(walletAddress, { limit });
    return response.json({
      walletRef: activity.walletRef,
      source: activity.source,
      events: activity.events,
      records: activity.records,
      checkedAt: new Date().toISOString(),
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not read wallet history.', error, 'history/wallet');
  }
});

app.get('/api/history/:walletAddress/events', async (request, response) => {
  try {
    const walletAddress = cleanWalletAddress(request.params.walletAddress);
    if (!isValidWalletAddress(walletAddress)) {
      return response.status(400).json({ message: 'A valid Stellar wallet address is required.' });
    }

    const result = await listWalletEvents(walletAddress, { limit: Number(request.query.limit || 100) });
    return response.json({
      walletRef: walletLogRef(walletAddress),
      ...result,
      checkedAt: new Date().toISOString(),
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not read wallet events.', error, 'history/events');
  }
});

app.post('/api/legal/accept', async (request, response) => {
  try {
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }

    const walletAddress = cleanWalletAddress(request.body.walletAddress);
    const termsVersion = cleanShortString(request.body.termsVersion || env.server.termsVersion, 64);

    if (!isValidWalletAddress(walletAddress)) {
      return response.status(400).json({ message: 'A valid Stellar wallet address is required.' });
    }

    if (termsVersion !== env.server.termsVersion) {
      return response.status(409).json({ message: `Current terms version is ${env.server.termsVersion}. Refresh and accept the latest notice.` });
    }

    if (!requireWalletSession(request, response, walletAddress)) {
      return null;
    }

    return response.json({
      walletRef: walletLogRef(walletAddress),
      termsVersion,
      acceptedAt: new Date().toISOString(),
      ...localOnlyStoragePayload({
        persistedByServer: false,
        message: 'Terms acceptance is kept by the app as a browser-local notice and may also be anchored through the receipt registry when the user signs that transaction.',
      }),
    });
  } catch (error) {
    return sendApiError(response, 500, error.message || 'Could not process terms acceptance.', error, 'legal/accept');
  }
});

app.post('/api/auth/challenge', (request, response) => {
  if (!isPlainObject(request.body)) {
    return response.status(400).json({ message: 'Request body must be a JSON object.' });
  }

  const walletAddress = cleanWalletAddress(request.body.walletAddress);
  if (!isValidWalletAddress(walletAddress)) {
    return response.status(400).json({ message: 'A valid Stellar wallet address is required.' });
  }

  const nonce = crypto.randomBytes(24).toString('base64url');
  const expiresAt = Date.now() + env.server.authChallengeTtlMs;
  const origin = cleanShortString(request.headers.origin || request.body.origin, 160);
  const message = createChallengeMessage(walletAddress, nonce, expiresAt, origin);

  authChallenges.set(challengeKey(walletAddress, nonce), {
    walletAddress,
    nonce,
    message,
    expiresAt,
  });

  return response.json({
    walletAddress,
    nonce,
    message,
    expiresAt: new Date(expiresAt).toISOString(),
    termsVersion: env.server.termsVersion,
  });
});

app.post('/api/auth/session', (request, response) => {
  if (!isPlainObject(request.body)) {
    return response.status(400).json({ message: 'Request body must be a JSON object.' });
  }

  const walletAddress = cleanWalletAddress(request.body.walletAddress);
  const nonce = cleanShortString(request.body.nonce, 120);
  const signature = cleanShortString(request.body.signature, 2000);

  if (!isValidWalletAddress(walletAddress) || !nonce || !signature) {
    return response.status(400).json({ message: 'Wallet, nonce, and signature are required.' });
  }

  const key = challengeKey(walletAddress, nonce);
  const challenge = authChallenges.get(key);
  authChallenges.delete(key);

  if (!challenge || challenge.expiresAt <= Date.now()) {
    return response.status(401).json({ message: 'Wallet challenge is missing or expired.' });
  }

  if (!verifyWalletSignature(walletAddress, challenge.message, signature)) {
    writeLog('warn', 'wallet_signature_rejected', {
      walletRef: walletLogRef(walletAddress),
      ...getSignatureDebug(signature),
    });
    return response.status(401).json({ message: 'Wallet signature could not be verified.' });
  }

  return response.json({
    walletAddress,
    token: createSessionToken(walletAddress),
    expiresAt: new Date(Date.now() + env.server.authSessionTtlMs).toISOString(),
  });
});

app.post('/api/auth/session/revoke', (request, response) => {
  const token = getBearerToken(request);
  const session = verifySessionToken(token);
  if (!session) {
    return response.status(401).json({ message: 'Signed wallet session is invalid or expired.' });
  }

  revokedSessionIds.set(session.jti, Number(session.exp));
  pruneRevokedSessions();
  return response.json({
    revoked: true,
    walletRef: walletLogRef(session.walletAddress),
  });
});

app.post('/api/onboarding/email/start', async (request, response) => {
  try {
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }

    const result = await startEmailOtp(request.body.email);
    return response.status(202).json({
      otpId: result.otpId,
      expiresAt: result.expiresAt,
      provider: result.provider.provider,
      sent: result.provider.sent,
      message: 'OTP sent to email.',
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not send OTP.', error, 'onboarding/email/start');
  }
});

app.post('/api/onboarding/email/verify', async (request, response) => {
  try {
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }

    const result = await verifyEmailOtp({
      email: request.body.email,
      otpId: cleanShortString(request.body.otpId, 120),
      otp: cleanShortString(request.body.otp, 12),
      network: cleanShortString(request.body.network, 16),
    });

    return response.json({
      token: result.token,
      expiresAt: result.expiresAt,
      mfaRequired: Boolean(result.mfaRequired),
      mfaSetupAvailable: Boolean(result.mfaSetupAvailable),
      challengeId: result.challengeId,
      secret: result.secret,
      otpauthUrl: result.otpauthUrl,
      mfaChallengeExpiresAt: result.mfaChallengeExpiresAt,
      existingWallet: result.existingWallet ? {
        walletAddress: result.existingWallet.wallet_address || '',
        walletRef: result.existingWallet.wallet_ref || '',
        network: result.existingWallet.network || '',
        fundingStatus: result.existingWallet.funding_status || '',
      } : null,
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not verify OTP.', error, 'onboarding/email/verify');
  }
});

app.post('/api/onboarding/email/mfa/verify', async (request, response) => {
  try {
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }

    const result = await verifyEmailMfa({
      email: request.body.email,
      challengeId: cleanShortString(request.body.challengeId, 1200),
      code: cleanShortString(request.body.code, 12),
      network: cleanShortString(request.body.network, 16),
    });

    return response.json({
      token: result.token,
      expiresAt: result.expiresAt,
      mfaEnabled: Boolean(result.mfaEnabled),
      mfaEnrollmentProof: result.mfaEnrollmentProof,
      existingWallet: result.existingWallet ? {
        walletAddress: result.existingWallet.wallet_address || '',
        walletRef: result.existingWallet.wallet_ref || '',
        network: result.existingWallet.network || '',
        fundingStatus: result.existingWallet.funding_status || '',
      } : null,
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not verify authenticator code.', error, 'onboarding/email/mfa/verify');
  }
});

app.post('/api/onboarding/wallets/register-or-fund', async (request, response) => {
  try {
    const emailSession = requireEmailSession(request, response);
    if (!emailSession) return null;
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }

    const walletAddress = cleanWalletAddress(request.body.walletAddress);
    const network = cleanShortString(request.body.network, 16).toLowerCase();
    if (!isValidWalletAddress(walletAddress)) {
      return response.status(400).json({ message: 'A valid Stellar wallet address is required.' });
    }
    if (!['testnet', 'mainnet'].includes(network)) {
      return response.status(400).json({ message: 'network must be testnet or mainnet.' });
    }

    let funding = {
      status: 'created_unfunded',
      source: network === 'mainnet' ? 'mainnet-user-funded' : 'none',
      transactionHash: '',
      raw: null,
    };

    if (network === 'testnet') {
      try {
        funding = await fundTestnetWallet(walletAddress);
      } catch (error) {
        await recordEmailWallet({
          emailHash: emailSession.emailHash,
          walletAddress,
          network,
          fundingStatus: 'friendbot_failed',
          fundingSource: 'stellar-friendbot',
          metadata: { error: error.message || 'Friendbot funding failed.' },
        });
        throw error;
      }
    }

    const account = await recordEmailWallet({
      emailHash: emailSession.emailHash,
      walletAddress,
      network,
      fundingStatus: funding.status,
      fundingSource: funding.source,
      fundingTransactionHash: funding.transactionHash,
      metadata: {
        onboarding: 'email-generated-browser-wallet',
      },
    });

    return response.status(network === 'testnet' ? 201 : 202).json({
      walletAddress,
      walletRef: onboardingWalletRef(walletAddress),
      network,
      fundingStatus: account.funding_status || funding.status,
      fundingSource: account.funding_source || funding.source,
      fundingTransactionHash: account.funding_transaction_hash || funding.transactionHash || '',
      mainnetFundingRequired: network === 'mainnet',
      message: network === 'mainnet'
        ? 'Mainnet wallet keypair created. The Stellar account will exist on-chain after it receives the minimum XLM reserve.'
        : 'Testnet wallet funded through Friendbot.',
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not register or fund wallet.', error, 'onboarding/wallets/register-or-fund');
  }
});

app.post('/api/onboarding/testnet/cftusd/fund', async (request, response) => {
  try {
    if (env.contracts.network === 'mainnet') {
      return response.status(404).json({ message: 'Test CFTUSD faucet is not available on mainnet.' });
    }
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }

    const walletAddress = cleanWalletAddress(request.body.walletAddress);
    if (!isValidWalletAddress(walletAddress)) {
      return response.status(400).json({ message: 'A valid Stellar wallet address is required.' });
    }
    if (!requireWalletSession(request, response, walletAddress)) {
      return null;
    }
    if (!env.contracts.payoutToken) {
      return response.status(503).json({ message: 'CFTUSD test token is not configured.' });
    }

    const requested = decimalToStroops(request.body.amount || '5');
    const maxAmount = 10n * 10_000_000n;
    const amount = requested && requested > 0n && requested <= maxAmount
      ? requested
      : 5n * 10_000_000n;
    const sourceAccount = cleanShortString(
      process.env.CFTUSD_TESTNET_MINT_SOURCE || 'admin2',
      80,
    );

    const result = await execFileAsync('stellar', [
      'contract',
      'invoke',
      '--id',
      env.contracts.payoutToken,
      '--source-account',
      sourceAccount,
      '--network',
      'testnet',
      '--',
      'mint',
      '--to',
      walletAddress,
      '--amount',
      amount.toString(),
    ], {
      cwd: process.cwd(),
      timeout: 60_000,
      windowsHide: true,
    });

    return response.status(201).json({
      ok: true,
      walletAddress,
      token: env.contracts.payoutToken,
      amount: amount.toString(),
      amountDisplay: stroopsToDecimalString(amount),
      sourceAccount,
      output: String(result.stdout || '').slice(-1200),
    });
  } catch (error) {
    const detail = [
      error.message || 'Could not fund test CFTUSD.',
      error.stderr || '',
      error.stdout || '',
    ].join('\n');
    return sendApiError(
      response,
      502,
      detail.includes('trustline entry is missing')
        ? 'Create the CFTUSD trustline first, then request test CFTUSD again.'
        : 'Could not fund test CFTUSD.',
      error,
      'onboarding/testnet/cftusd/fund',
    );
  }
});

app.get('/api/onboarding/kyc/status', async (request, response) => {
  try {
    if (!requireConfiguredDatabase(response)) return null;
    const walletAddress = requireWalletHeader(request, response);
    if (!walletAddress) return null;
    if (!requireWalletSession(request, response, walletAddress)) return null;

    const session = await getLatestUserKycSession(walletLogRef(walletAddress));
    return response.json({
      provider: 'didit',
      configured: isDiditKycConfigured(),
      workflowId: DIDIT_KYC_WORKFLOW_ID || '',
      thresholdUsd: env.business.highValueVerificationUsd,
      status: session?.normalized_status || 'not_started',
      verified: session?.normalized_status === 'verified',
      session: session
        ? {
            id: session.id,
            status: session.status,
            normalizedStatus: session.normalized_status,
            verificationUrl: session.verification_url,
            payoutUsd: session.payout_usd,
            createdAt: session.created_at,
            updatedAt: session.updated_at,
          }
        : null,
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not read KYC status.', error, 'onboarding/kyc/status');
  }
});

app.post('/api/onboarding/kyc/session', async (request, response) => {
  try {
    if (!requireConfiguredDatabase(response)) return null;
    const walletAddress = requireWalletHeader(request, response);
    if (!walletAddress) return null;
    if (!requireWalletSession(request, response, walletAddress)) return null;
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }
    if (!isDiditKycConfigured()) {
      return response.status(503).json({ message: 'DIDIT_API_KEY and DIDIT_KYC_WORKFLOW_ID are required for user KYC.' });
    }

    const payoutUsd = Number(request.body.payoutUsd || 0);
    if (!Number.isFinite(payoutUsd) || payoutUsd < 0) {
      return response.status(400).json({ message: 'payoutUsd must be a valid positive number.' });
    }
    const callbackUrl = cleanHttpsCallbackUrl(request.body.callbackUrl) || defaultDiditCallbackUrl(request);
    if (!callbackUrl) {
      return response.status(400).json({ message: 'A valid callback URL is required for Didit KYC.' });
    }

    const walletRef = walletLogRef(walletAddress);
    const vendorData = `user_kyc:${walletRef}:${crypto.randomBytes(8).toString('hex')}`;
    const diditSession = await createDiditKycSession({
      walletRef,
      vendorData,
      callbackUrl,
      payoutUsd,
    });
    const session = await saveUserKycSession({
      walletRef,
      providerSessionId: diditSession.session_id,
      vendorData,
      status: diditSession.status || 'Not Started',
      verificationUrl: diditSession.url,
      workflowId: diditSession.workflow_id || DIDIT_KYC_WORKFLOW_ID,
      callbackUrl,
      payoutUsd,
    });

    return response.status(201).json({
      url: diditSession.url,
      sessionId: diditSession.session_id,
      status: session.status,
      normalizedStatus: session.normalized_status,
      workflowId: session.workflow_id,
    });
  } catch (error) {
    const status = error.providerStatus ? 502 : error.statusCode || 500;
    return sendApiError(response, status, error.message || 'Could not create Didit KYC session.', error, 'onboarding/kyc/session');
  }
});

app.post('/api/zk/commitments/email-wallet', async (request, response) => {
  try {
    const emailSession = requireEmailSession(request, response);
    if (!emailSession) return null;
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }

    const walletAddress = cleanWalletAddress(request.body.walletAddress);
    const network = cleanShortString(request.body.network, 16).toLowerCase();
    const commitment = cleanShortString(request.body.commitment, 180);
    const circuitId = cleanShortString(request.body.circuitId || 'coverfi.email_wallet_ownership.v0', 120);
    if (!isValidWalletAddress(walletAddress) || !['testnet', 'mainnet'].includes(network)) {
      return response.status(400).json({ message: 'Valid walletAddress and network are required.' });
    }
    if (!/^[a-fA-F0-9]{64}$/.test(commitment)) {
      return response.status(400).json({ message: 'commitment must be a 32-byte hex value.' });
    }

    const saved = await saveZkCommitment({
      subjectRef: onboardingWalletRef(walletAddress),
      commitment: commitment.toLowerCase(),
      commitmentScheme: cleanShortString(request.body.commitmentScheme || 'sha256-v0', 80),
      circuitId,
      publicSignals: {
        network,
        walletRef: onboardingWalletRef(walletAddress),
        ...(isPlainObject(request.body.publicSignals) ? request.body.publicSignals : {}),
      },
      expiresAt: request.body.expiresAt || null,
    });

    return response.status(201).json({
      commitment: saved,
      warning: 'This stores a commitment for future ZK verification. Full Noir/Groth16 verification is a separate circuit-verifier step.',
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not save ZK commitment.', error, 'zk/commitments/email-wallet');
  }
});

app.post('/api/zk/proofs/record', async (request, response) => {
  try {
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }

    const proofSystem = cleanShortString(request.body.proofSystem || 'stellar-ed25519', 80);
    const circuitId = cleanShortString(request.body.circuitId || '', 120);
    const validated = validateZkProofSubmission({
      subjectRef: request.body.subjectRef,
      circuitId,
      proofSystem,
      proof: request.body.proof,
    });
    const event = await recordZkProofEvent({
      subjectRef: validated.subjectRef,
      commitmentId: cleanShortString(request.body.commitmentId, 120) || null,
      circuitId,
      proofSystem,
      proof: request.body.proof || {},
      publicSignals: isPlainObject(request.body.publicSignals) ? request.body.publicSignals : {},
      verificationStatus: 'verified',
      verifierNotes: `Stellar Ed25519 proof signature verified for ${validated.signer}.`,
    });

    return response.status(202).json({ proofEvent: event });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not record ZK proof event.', error, 'zk/proofs/record');
  }
});

app.get('/api/zk/proofs/status', async (request, response) => {
  try {
    const subjectRef = cleanShortString(request.query.subjectRef, 180);
    const circuitId = cleanShortString(request.query.circuitId, 120);
    const limit = Math.min(Math.max(Number(request.query.limit) || 20, 1), 50);

    if (!subjectRef) {
      return response.status(400).json({ message: 'subjectRef is required.' });
    }

    if (!isValidWalletAddress(subjectRef)) {
      return response.status(403).json({
        message: 'Only wallet proof status can be read from this endpoint.',
      });
    }

    if (circuitId && !zkProofCircuitIds.has(circuitId)) {
      return response.status(400).json({ message: 'Unsupported ZK proof circuit.' });
    }

    if (!requireWalletSession(request, response, subjectRef)) {
      return null;
    }

    const events = await listZkProofEvents({ subjectRef, circuitId, limit });
    const latest = events[0] || null;
    return response.json({
      subjectRef,
      circuitId: circuitId || null,
      verified: events.some((event) => event.verificationStatus === 'verified'),
      latest,
      events,
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not read ZK proof status.', error, 'zk/proofs/status');
  }
});

app.post('/api/auth/register', async (request, response) => {
  try {
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }

    const username = cleanUsername(request.body?.username).toLowerCase();
    const walletAddress = cleanWalletAddress(request.body?.walletAddress);

    if (!usernamePattern.test(username)) {
      return response.status(400).json({ message: 'Use 3-24 letters, numbers, or underscores.' });
    }

    if (isReservedUsername(username)) {
      return response.status(409).json({ message: 'That username is reserved for verified CoverFi operations.' });
    }

    if (walletAddress && !isValidWalletAddress(walletAddress)) {
      return response.status(400).json({ message: 'A valid Stellar wallet address is required.' });
    }

    return response.status(501).json({
      message: 'Backend username registration has been removed. Register usernames by signing the Soroban username-registry transaction from the app.',
      username,
      walletRef: walletLogRef(walletAddress),
      source: 'soroban_username_registry',
    });
  } catch (error) {
    return sendApiError(response, 500, error.message || 'Could not process username registration.', error, 'auth/register');
  }
});

app.get('/api/users/search', async (request, response) => {
  try {
    const q = cleanUsername(request.query.q).toLowerCase();
    if (!q || q.length < 2) {
      return response.json({ users: [], source: 'soroban_username_registry' });
    }

    if (!/^[a-z0-9_]{2,24}$/.test(q)) {
      return response.status(400).json({ message: 'Enter at least two valid username characters.' });
    }

    const names = await simulateContractRead(env.contracts.usernameRegistry, 'list_names', [
      nativeToScVal(0, { type: 'u32' }),
      nativeToScVal(50, { type: 'u32' }),
    ]);
    const users = (Array.isArray(names) ? names : [])
      .map(usernameRecordToUser)
      .filter(Boolean)
      .filter((user) => user.usernameLower.startsWith(q))
      .slice(0, 5);

    return response.json({ users, source: 'soroban_username_registry' });
  } catch (error) {
    return sendApiError(response, Number(error?.statusCode || 502), error.message || 'Could not search usernames on-chain.', error, 'users/search');
  }
});

app.post('/api/payments/save', async (request, response) => {
  if (!isPlainObject(request.body)) {
    return response.status(400).json({ message: 'Request body must be a JSON object.' });
  }

  const sender = cleanUsername(request.body.sender).toLowerCase();
  const recipient = cleanUsername(request.body.recipient).toLowerCase();
  const receiptData = sanitizeReceiptData(request.body.receiptData);

  if (!isValidUsername(sender) || !isValidUsername(recipient) || !receiptData) {
    return response.status(400).json({ message: 'Valid sender, recipient, and full transaction receipt data are required.' });
  }

  return response.json(localOnlyStoragePayload({
    saved: false,
    message: 'Payment history is saved only by the browser after wallet-signed transactions.',
  }));
});

app.get('/api/payments/:username', async (request, response) => {
  const username = cleanUsername(request.params.username).toLowerCase();
  if (!isValidUsername(username)) {
    return response.status(400).json({ message: 'Enter a valid username.' });
  }

  return response.json(localOnlyStoragePayload({
    payments: [],
    username,
    message: 'Server payment history has been removed. Read encrypted local history in the app.',
  }));
});

app.get('/api/users/:username', async (request, response) => {
  try {
    const usernameLower = cleanUsername(request.params.username).toLowerCase();

    if (!usernamePattern.test(usernameLower)) {
      return response.status(400).json({ message: 'Enter a valid username.' });
    }

    const user = await readUsernameRecord(usernameLower);
    if (!user) {
      return response.status(404).json({ message: 'No on-chain username record found.' });
    }

    return response.json(user);
  } catch (error) {
    return sendApiError(response, Number(error?.statusCode || 502), error.message || 'Could not look up username on-chain.', error, 'users/:username');
  }
});

app.get('/api/wallets/:walletAddress', async (request, response) => {
  try {
    const walletAddress = cleanWalletAddress(request.params.walletAddress);

    if (!isValidWalletAddress(walletAddress)) {
      return response.status(400).json({ message: 'A valid Stellar wallet address is required.' });
    }

    const user = await readWalletUsername(walletAddress);
    if (!user) {
      return response.status(404).json({ message: 'No username is registered for this wallet yet.' });
    }

    return response.json(user);
  } catch (error) {
    return sendApiError(response, Number(error?.statusCode || 502), error.message || 'Could not look up wallet username on-chain.', error, 'wallets/:walletAddress');
  }
});

app.get('/api/account/:walletAddress', async (request, response) => {
  try {
    const walletAddress = cleanWalletAddress(request.params.walletAddress);

    if (!isValidWalletAddress(walletAddress)) {
      return response.status(400).json({ message: 'A valid Stellar wallet address is required.' });
    }

    if (!requireWalletSession(request, response, walletAddress)) {
      return null;
    }

    return response.json(localOnlyStoragePayload({
      walletRef: walletLogRef(walletAddress),
      profile: null,
      data: null,
      network: env.contracts.network === 'mainnet' ? 'mainnet' : 'testnet',
    }));
  } catch (error) {
    return sendApiError(response, 500, error.message || 'Could not load account boundary.', error, 'account/get');
  }
});

app.put('/api/account/:walletAddress', async (request, response) => {
  try {
    const walletAddress = cleanWalletAddress(request.params.walletAddress);

    if (!isValidWalletAddress(walletAddress)) {
      return response.status(400).json({ message: 'A valid Stellar wallet address is required.' });
    }

    if (!requireWalletSession(request, response, walletAddress)) {
      return null;
    }

    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }

    return response.json(localOnlyStoragePayload({
      saved: false,
      walletRef: walletLogRef(walletAddress),
      message: 'Account profile and dashboard cache are stored only in wallet-unlocked encrypted browser storage.',
    }));
  } catch (error) {
    return sendApiError(response, 500, error.message || 'Could not process account boundary.', error, 'account/put');
  }
});

app.post('/api/receipts/save', async (request, response) => {
  if (!isPlainObject(request.body)) {
    return response.status(400).json({ message: 'Request body must be a JSON object.' });
  }

  const username = cleanUsername(request.body.username).toLowerCase();
  const receiptData = sanitizeReceiptData(request.body.receiptData);

  if (!isValidUsername(username) || !receiptData) {
    return response.status(400).json({ message: 'Valid username and receiptData are required.' });
  }

  return response.json(localOnlyStoragePayload({
    saved: false,
    username,
    message: 'Private receipt display data is saved only by the browser. Receipt hashes may be anchored on-chain by a wallet-signed transaction.',
  }));
});

app.get('/api/privacy/export/:walletAddress', async (request, response) => {
  try {
    const walletAddress = cleanWalletAddress(request.params.walletAddress);

    if (!isValidWalletAddress(walletAddress)) {
      return response.status(400).json({ message: 'A valid Stellar wallet address is required.' });
    }

    if (!requireWalletSession(request, response, walletAddress)) {
      return null;
    }

    return response.json(localOnlyStoragePayload({
      exportedAt: new Date().toISOString(),
      walletRef: walletLogRef(walletAddress),
      serverRecords: null,
      message: 'There are no backend account records to export. Use the app privacy export to decrypt and download browser-local records.',
    }));
  } catch (error) {
    return sendApiError(response, 500, error.message || 'Could not process privacy export.', error, 'privacy/export');
  }
});

app.delete('/api/privacy/:walletAddress', async (request, response) => {
  try {
    const walletAddress = cleanWalletAddress(request.params.walletAddress);

    if (!isValidWalletAddress(walletAddress)) {
      return response.status(400).json({ message: 'A valid Stellar wallet address is required.' });
    }

    if (!requireWalletSession(request, response, walletAddress)) {
      return null;
    }

    return response.json(localOnlyStoragePayload({
      walletRef: walletLogRef(walletAddress),
      deleted: {
        accounts: 0,
        users: 0,
        payments: 0,
        receipts: 0,
        chats: 0,
        legalAcceptances: 0,
      },
      message: 'No backend account records exist. Use the app clear-storage control to delete browser-local encrypted records; on-chain records remain immutable.',
    }));
  } catch (error) {
    return sendApiError(response, 500, error.message || 'Could not process privacy deletion.', error, 'privacy/delete');
  }
});

app.get('/api/analytics/protocol/daily', async (request, response) => {
  try {
    if (!requireConfiguredDatabase(response)) return null;
    const metrics = await getProtocolMetrics(request.query.days);
    return response.json({
      metrics,
      privacy: {
        rawWalletAddresses: false,
        walletIdentifier: 'hmac',
        smallCohortSuppression: true,
      },
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not read protocol metrics.', error, 'analytics/protocol');
  }
});

app.get('/api/partner-dashboard/me', async (request, response) => {
  try {
    if (!requireConfiguredDatabase(response)) return null;
    const walletAddress = requireWalletHeader(request, response);
    if (!walletAddress) return null;
    if (!requireWalletSession(request, response, walletAddress)) return null;
    const partners = await listPartnersForWalletRef(walletLogRef(walletAddress), walletAddress);
    return response.json({ partners });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not load partner account.', error, 'partner-dashboard/me');
  }
});

app.post('/api/partner-dashboard/register', async (request, response) => {
  try {
    if (!requireConfiguredDatabase(response)) return null;
    const walletAddress = requireWalletHeader(request, response);
    if (!walletAddress) return null;
    if (!requireWalletSession(request, response, walletAddress)) return null;
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }
    const slug = validatePartnerSlug(request.body.slug);
    const displayName = cleanShortString(request.body.displayName, 120);
    const websiteUrl = cleanShortString(request.body.websiteUrl, 240);
    const onchainPartnerAddress = cleanWalletAddress(request.body.onchainPartnerAddress || walletAddress);
    if (!slug || !displayName) {
      return response.status(400).json({ message: 'Valid slug and displayName are required.' });
    }
    if (onchainPartnerAddress && !isValidWalletAddress(onchainPartnerAddress)) {
      return response.status(400).json({ message: 'onchainPartnerAddress must be a valid Stellar public key.' });
    }
    const partner = await createPartner({
      slug,
      displayName,
      onchainPartnerAddress,
      websiteUrl,
      createdByWalletRef: walletLogRef(walletAddress),
    });
    return response.status(201).json({ partner });
  } catch (error) {
    const status = error.code === '23505' ? 409 : error.statusCode || 500;
    return sendApiError(response, status, error.code === '23505' ? 'Partner slug already exists.' : error.message || 'Could not register partner.', error, 'partner-dashboard/register');
  }
});

app.get('/api/partner-dashboard/:partnerId/applications', async (request, response) => {
  try {
    if (!requireConfiguredDatabase(response)) return null;
    const walletAddress = requireWalletHeader(request, response);
    if (!walletAddress) return null;
    if (!requireWalletSession(request, response, walletAddress)) return null;
    const partner = await getPartnerOwnedByWallet(cleanShortString(request.params.partnerId, 80), walletLogRef(walletAddress), walletAddress);
    if (!partner) return response.status(404).json({ message: 'Partner account not found for this wallet.' });
    if (partner.kyb_status !== 'verified') {
      return response.status(403).json({ message: 'Didit KYB must be verified before partner API keys can be created.' });
    }
    const applications = await listPartnerApplications(partner.id);
    return response.json({ partner, applications });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not list partner applications.', error, 'partner-dashboard/apps/list');
  }
});

app.post('/api/partner-dashboard/:partnerId/applications', async (request, response) => {
  try {
    if (!requireConfiguredDatabase(response)) return null;
    const walletAddress = requireWalletHeader(request, response);
    if (!walletAddress) return null;
    if (!requireWalletSession(request, response, walletAddress)) return null;
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }
    const partner = await getPartnerOwnedByWallet(cleanShortString(request.params.partnerId, 80), walletLogRef(walletAddress), walletAddress);
    if (!partner) return response.status(404).json({ message: 'Partner account not found for this wallet.' });
    const name = cleanShortString(request.body.name, 120);
    const slug = validatePartnerSlug(request.body.slug || name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''));
    if (!name || !slug) return response.status(400).json({ message: 'Valid application name and slug are required.' });
    const application = await createPartnerApplication({
      partnerId: partner.id,
      name,
      slug,
      description: cleanShortString(request.body.description, 240),
      websiteUrl: cleanShortString(request.body.websiteUrl, 240),
      logoUrl: cleanShortString(request.body.logoUrl, 240),
      environment: validateApplicationEnvironment(request.body.environment),
      allowedOrigins: cleanStringArray(request.body.allowedOrigins),
      allowedIpAddresses: cleanStringArray(request.body.allowedIpAddresses, 20, 80),
      webhookUrl: cleanShortString(request.body.webhookUrl, 240),
    });
    return response.status(201).json({
      application,
      warning: 'Store the publishable key if you use the browser widget. It is safe for frontend initialization but does not authorize sensitive API calls.',
    });
  } catch (error) {
    const status = error.code === '23505' ? 409 : error.statusCode || 500;
    return sendApiError(response, status, error.code === '23505' ? 'Application slug already exists for this partner.' : error.message || 'Could not create application.', error, 'partner-dashboard/apps/create');
  }
});

app.post('/api/partner-dashboard/:partnerId/applications/:applicationId/api-keys', async (request, response) => {
  try {
    if (!requireConfiguredDatabase(response)) return null;
    const walletAddress = requireWalletHeader(request, response);
    if (!walletAddress) return null;
    if (!requireWalletSession(request, response, walletAddress)) return null;
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }
    const partner = await getPartnerOwnedByWallet(cleanShortString(request.params.partnerId, 80), walletLogRef(walletAddress), walletAddress);
    if (!partner) return response.status(404).json({ message: 'Partner account not found for this wallet.' });
    const applications = await listPartnerApplications(partner.id);
    const application = applications.find((item) => item.id === cleanShortString(request.params.applicationId, 80));
    if (!application) return response.status(404).json({ message: 'Application not found for this partner.' });
    const key = await createPartnerKey({
      partnerId: partner.id,
      applicationId: application.id,
      label: cleanShortString(request.body.label, 80) || 'Default key',
      mode: validateKeyMode(request.body.mode || application.environment),
      scopes: cleanStringArray(request.body.scopes, 24, 64),
      allowedOrigins: cleanStringArray(request.body.allowedOrigins),
      allowedIpAddresses: cleanStringArray(request.body.allowedIpAddresses, 20, 80),
      expiresAt: request.body.expiresAt || null,
      rateLimitPerMinute: Number(request.body.rateLimitPerMinute) || undefined,
      createdByWalletRef: walletLogRef(walletAddress),
    });
    return response.status(201).json({
      apiKey: key,
      warning: 'Store this API key now. CoverFi stores only its keyed hash, prefix, and last four characters.',
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not create application API key.', error, 'partner-dashboard/key/create');
  }
});

app.get('/api/partner-dashboard/:partnerId/kyb', async (request, response) => {
  try {
    if (!requireConfiguredDatabase(response)) return null;
    const walletAddress = requireWalletHeader(request, response);
    if (!walletAddress) return null;
    if (!requireWalletSession(request, response, walletAddress)) return null;
    const partner = await getPartnerOwnedByWallet(cleanShortString(request.params.partnerId, 80), walletLogRef(walletAddress), walletAddress);
    if (!partner) return response.status(404).json({ message: 'Partner account not found for this wallet.' });
    const session = await getLatestPartnerKybSession(partner.id);
    return response.json({
      provider: 'didit',
      workflowId: DIDIT_KYB_WORKFLOW_ID,
      configured: isDiditConfigured(),
      partner: {
        id: partner.id,
        slug: partner.slug,
        kybStatus: partner.kyb_status || 'not_started',
      },
      session,
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not read partner KYB status.', error, 'partner-dashboard/kyb/read');
  }
});

app.post('/api/partner-dashboard/:partnerId/kyb/session', async (request, response) => {
  try {
    if (!requireConfiguredDatabase(response)) return null;
    const walletAddress = requireWalletHeader(request, response);
    if (!walletAddress) return null;
    if (!requireWalletSession(request, response, walletAddress)) return null;
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }
    if (!isDiditConfigured()) {
      return response.status(503).json({ message: 'DIDIT_API_KEY is not configured on the backend.' });
    }

    const partner = await getPartnerOwnedByWallet(cleanShortString(request.params.partnerId, 80), walletLogRef(walletAddress), walletAddress);
    if (!partner) return response.status(404).json({ message: 'Partner account not found for this wallet.' });
    const callbackUrl = cleanHttpsCallbackUrl(request.body.callbackUrl) || defaultDiditCallbackUrl(request);
    if (!callbackUrl) {
      return response.status(400).json({ message: 'A valid callback URL is required for Didit KYB.' });
    }

    const vendorData = `partner:${partner.id}`;
    const diditSession = await createDiditKybSession({
      partnerId: partner.id,
      partnerSlug: partner.slug,
      vendorData,
      callbackUrl,
    });
    const session = await savePartnerKybSession({
      partnerId: partner.id,
      providerSessionId: diditSession.session_id,
      providerBusinessSessionId: diditSession.business_session_id,
      vendorData,
      status: diditSession.status || 'Not Started',
      verificationUrl: diditSession.url,
      workflowId: diditSession.workflow_id || DIDIT_KYB_WORKFLOW_ID,
      callbackUrl,
      createdByWalletRef: walletLogRef(walletAddress),
    });

    return response.status(201).json({
      url: diditSession.url,
      sessionId: diditSession.session_id,
      status: session.status,
      normalizedStatus: session.normalized_status,
      workflowId: session.workflow_id,
    });
  } catch (error) {
    const status = error.providerStatus ? 502 : error.statusCode || 500;
    return sendApiError(response, status, error.message || 'Could not create Didit KYB session.', error, 'partner-dashboard/kyb/session');
  }
});

async function withPartnerRequestLog(request, response, partner, handler) {
  const startedAt = Date.now();
  const requestId = request.requestId || getRequestId();
  const idempotencyKey = cleanShortString(request.headers['idempotency-key'], 160);
  try {
    const body = await handler({ requestId, idempotencyKey });
    await logPartnerRequest({
      requestId,
      partnerId: partner.partner_id,
      applicationId: partner.application_id,
      apiKeyId: partner.credential_type === 'api_key' ? partner.id : null,
      method: request.method,
      path: request.originalUrl,
      statusCode: response.statusCode,
      latencyMs: Date.now() - startedAt,
      idempotencyKey,
      requestBody: isPlainObject(request.body) ? redactPartnerLogValue(request.body) : null,
      responseBody: body && typeof body === 'object' ? redactPartnerLogValue(body) : null,
    }).catch((error) => logApiError('partner/request-log', error));
    return body;
  } catch (error) {
    await logPartnerRequest({
      requestId,
      partnerId: partner?.partner_id,
      applicationId: partner?.application_id,
      apiKeyId: partner?.credential_type === 'api_key' ? partner.id : null,
      method: request.method,
      path: request.originalUrl,
      statusCode: error.statusCode || 500,
      errorCode: error.code || 'internal_error',
      latencyMs: Date.now() - startedAt,
      idempotencyKey,
      requestBody: isPlainObject(request.body) ? redactPartnerLogValue(request.body) : null,
    }).catch((logError) => logApiError('partner/request-log/error', logError));
    throw error;
  }
}

app.post('/api/partner/v1/protection/quotes', async (request, response) => {
  let partner = null;
  try {
    partner = await requirePartnerApiSession(request, response, 'protection.quotes.create');
    if (!partner) return null;
    if (!isPlainObject(request.body)) return partnerApiError(response, 400, 'invalid_request', 'Request body must be a JSON object.', request.requestId);
    const asset = cleanShortString(request.body.asset || 'XLM', 16).toUpperCase();
    const amount = decimalToStroops(request.body.amount);
    const durationSeconds = durationDaysToSeconds(request.body.durationDays);
    const protectionPercentage = Number(request.body.protectionPercentage || 100);
    if (asset !== 'XLM') return partnerApiError(response, 400, 'unsupported_asset', 'Only XLM protection is currently configured for Testnet.', request.requestId);
    if (!amount || amount <= 0n || !durationSeconds || !Number.isInteger(protectionPercentage) || protectionPercentage <= 0 || protectionPercentage > 100) {
      return partnerApiError(response, 400, 'invalid_request', 'asset, amount, durationDays, and protectionPercentage are required.', request.requestId);
    }
    if (!env.contracts.protectionEngine || !env.contracts.xlmToken || !env.contracts.payoutToken) {
      return partnerApiError(response, 503, 'provider_error', 'CoverFi Testnet contracts are not configured for partner quotes yet.', request.requestId);
    }
    const body = await withPartnerRequestLog(request, response, partner, async () => {
      const quote = serializeQuote(await simulateContractRead(env.contracts.protectionEngine, 'quote_position', [
        Address.fromString(env.contracts.xlmToken).toScVal(),
        Address.fromString(env.contracts.payoutToken).toScVal(),
        nativeToScVal(amount, { type: 'i128' }),
        nativeToScVal(BigInt(durationSeconds), { type: 'u64' }),
      ]));
      const record = await createPartnerQuote({
        partnerId: partner.partner_id,
        applicationId: partner.application_id,
        asset,
        amount: String(request.body.amount),
        durationDays: Number(request.body.durationDays),
        protectionPercentage,
        premiumAmount: stroopsToDecimalString(quote.totalDue),
        maximumPayout: stroopsToDecimalString(quote.maximumPayout),
        quotePayload: {
          quote,
          oracleTimestamp: null,
          network: env.contracts.network,
          protectedAssetContractId: env.contracts.xlmToken,
          payoutAssetContractId: env.contracts.payoutToken,
        },
      });
      response.status(201);
      return {
        id: record.id,
        asset: record.asset,
        amount: record.amount,
        durationDays: record.duration_days,
        protectionPercentage: record.protection_percentage,
        premiumAmount: record.premium_amount,
        maximumPayout: record.maximum_payout,
        expiresAt: record.expires_at,
        network: env.contracts.network,
        quote: record.quote_payload.quote,
        protectedAssetContractId: env.contracts.xlmToken,
        payoutAssetContractId: env.contracts.payoutToken,
      };
    });
    return response.json(body);
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not create quote.', request.requestId);
  }
});

app.post('/api/partner/v1/protection/positions', async (request, response) => {
  let partner = null;
  try {
    partner = await requirePartnerApiSession(request, response, 'protection.positions.create');
    if (!partner) return null;
    if (!isPlainObject(request.body)) return partnerApiError(response, 400, 'invalid_request', 'Request body must be a JSON object.', request.requestId);
    const quoteId = cleanShortString(request.body.quoteId, 80);
    const walletAddress = cleanWalletAddress(request.body.walletAddress);
    if (!quoteId || !isValidWalletAddress(walletAddress)) {
      return partnerApiError(response, 400, 'invalid_request', 'quoteId and a valid walletAddress are required.', request.requestId);
    }
    const quote = await getPartnerQuote(quoteId, partner.partner_id);
    if (!quote) return partnerApiError(response, 404, 'position_not_found', 'Quote was not found for this partner.', request.requestId);
    if (new Date(quote.expires_at).getTime() <= Date.now()) {
      return partnerApiError(response, 409, 'quote_expired', 'This quote has expired.', request.requestId);
    }
    const body = await withPartnerRequestLog(request, response, partner, async () => {
      const durationSeconds = durationDaysToSeconds(quote.duration_days);
      const amount = decimalToStroops(quote.amount);
      const walletRef = walletLogRef(walletAddress);
      const transactionPayload = {
        network: env.contracts.network,
        networkPassphrase: env.contracts.networkPassphrase,
        contractId: env.contracts.protectionEngine,
        method: 'create_position',
        args: [
          { type: 'address', value: walletAddress },
          { type: 'address', value: env.contracts.xlmToken },
          { type: 'address', value: env.contracts.payoutToken },
          { type: 'i128', value: amount?.toString() },
          { type: 'u64', value: String(durationSeconds) },
        ],
        submitter: 'user_wallet',
      };
      const position = await createPartnerPosition({
        partnerId: partner.partner_id,
        applicationId: partner.application_id,
        quoteId: quote.id,
        walletRef,
        status: 'awaiting_signature',
        network: env.contracts.network,
        transactionXdr: null,
        positionPayload: {
          draft: {
            network: env.contracts.network,
            networkPassphrase: env.contracts.networkPassphrase,
            contractId: env.contracts.protectionEngine,
            method: 'create_position',
            walletRef,
            protectedAssetContractId: env.contracts.xlmToken,
            payoutAssetContractId: env.contracts.payoutToken,
            amount: amount?.toString(),
            durationSeconds: String(durationSeconds),
            partnerAddress: null,
            submitter: 'user_wallet',
          },
        },
      });
      response.status(201);
      return {
        id: position.id,
        status: position.status,
        network: position.network,
        transactionXdr: null,
        transactionPayload,
        expiresAt: position.expires_at,
        warning: 'Partner attribution is recorded in CoverFi partner records. The current deployed protection contract draft uses the five-argument create_position ABI; on-chain partner address attribution requires the upgraded six-argument contract deployment.',
      };
    });
    return response.json(body);
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not create position.', request.requestId);
  }
});

app.get('/api/partner/v1/protection/positions/:positionId', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'protection.positions.read');
    if (!partner) return null;
    const position = await getPartnerPosition(cleanShortString(request.params.positionId, 80), partner.partner_id);
    if (!position) return partnerApiError(response, 404, 'position_not_found', 'Position was not found.', request.requestId);
    return response.json({ position });
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not read position.', request.requestId);
  }
});

app.get('/api/partner/v1/protection/positions', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'protection.positions.read');
    if (!partner) return null;
    return response.json({ positions: await listPartnerPositions(partner.partner_id, request.query.limit) });
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not list positions.', request.requestId);
  }
});

app.post('/api/partner/v1/protection/positions/:positionId/cancel', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'protection.positions.cancel');
    if (!partner) return null;
    const position = await getPartnerPosition(cleanShortString(request.params.positionId, 80), partner.partner_id);
    if (!position) return partnerApiError(response, 404, 'position_not_found', 'Position was not found.', request.requestId);
    if (!['quote_created', 'awaiting_signature'].includes(position.status)) {
      return partnerApiError(response, 409, 'invalid_request', 'Only unsigned partner positions can be cancelled through the API.', request.requestId);
    }
    const result = await dbQuery(
      `UPDATE partner_positions SET status = 'cancelled', updated_at = now()
       WHERE id = $1 AND partner_id = $2
       RETURNING id, status, updated_at`,
      [position.id, partner.partner_id],
    );
    return response.json({ position: result.rows[0] });
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not cancel position.', request.requestId);
  }
});

app.post('/api/partner/v1/sessions', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'protection.positions.create');
    if (!partner) return null;
    if (!isPlainObject(request.body)) return partnerApiError(response, 400, 'invalid_request', 'Request body must be a JSON object.', request.requestId);
    const walletAddress = cleanWalletAddress(request.body.walletAddress || '');
    if (walletAddress && !isValidWalletAddress(walletAddress)) {
      return partnerApiError(response, 400, 'invalid_request', 'walletAddress must be a valid Stellar public key.', request.requestId);
    }
    const session = await createPartnerSession({
      partnerId: partner.partner_id,
      applicationId: partner.application_id,
      customerReference: cleanShortString(request.body.customerReference, 120),
      walletRef: walletAddress ? walletLogRef(walletAddress) : null,
      scopes: cleanStringArray(request.body.scopes, 16, 64),
      expiresIn: request.body.expiresIn,
    });
    return response.status(201).json({
      id: session.id,
      token: session.token,
      expiresAt: session.expires_at,
      scopes: session.scopes,
    });
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not create partner session.', request.requestId);
  }
});

app.get('/api/partner/v1/assets', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'assets.read');
    if (!partner) return null;
    return response.json({
      assets: [
        {
          asset: 'XLM',
          network: env.contracts.network,
          protectedAssetContractId: env.contracts.xlmToken,
          payoutAsset: 'CFTUSD',
          payoutAssetContractId: env.contracts.payoutToken,
          testnetOnly: env.contracts.network !== 'mainnet',
        },
      ],
    });
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not list assets.', request.requestId);
  }
});

app.get('/api/partner/v1/pricing', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'pricing.read');
    if (!partner) return null;
    return response.json({
      durations: [
        { durationDays: 1, basePremiumBps: 30 },
        { durationDays: 7, basePremiumBps: 100 },
        { durationDays: 14, basePremiumBps: 150 },
        { durationDays: 30, basePremiumBps: 250 },
      ],
      routing: {
        underwritingBps: 7800,
        protocolBps: 1000,
        safetyBps: 700,
        automationBps: 500,
      },
      note: 'Final quote pricing is produced by the CoverFi protection engine, not by this static schedule.',
    });
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not read pricing.', request.requestId);
  }
});

app.get('/api/partner/v1/usage', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'usage.read');
    if (!partner) return null;
    const metrics = await getPartnerMetrics(partner.partner_id, request.query.days);
    const requests = await dbQuery(
      `SELECT count(*)::int AS total_requests,
        count(*) FILTER (WHERE status_code >= 200 AND status_code < 400)::int AS successful_requests,
        count(*) FILTER (WHERE status_code >= 400)::int AS failed_requests,
        coalesce(avg(latency_ms), 0)::int AS average_latency_ms
       FROM partner_requests
       WHERE partner_id = $1
         AND created_at >= now() - (($2::int) * interval '1 day')`,
      [partner.partner_id, Math.max(1, Math.min(365, Number(request.query.days) || 30))],
    );
    return response.json({ usage: requests.rows[0], metrics });
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not read usage.', request.requestId);
  }
});

app.get('/api/partner/v1/wallets/signing-payloads/:positionId', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'wallets.read');
    if (!partner) return null;
    const position = await getPartnerPosition(cleanShortString(request.params.positionId, 80), partner.partner_id);
    if (!position) return partnerApiError(response, 404, 'position_not_found', 'Position was not found.', request.requestId);
    const walletAddress = cleanWalletAddress(request.query.walletAddress);
    if (!isValidWalletAddress(walletAddress) || walletLogRef(walletAddress) !== position.wallet_ref) {
      return partnerApiError(response, 400, 'invalid_request', 'walletAddress is required and must match the position wallet reference.', request.requestId);
    }
    const draft = position.position_payload?.draft || null;
    if (!draft) return partnerApiError(response, 404, 'invalid_request', 'No signing payload draft is available for this position.', request.requestId);
    const payload = {
      network: draft.network,
      networkPassphrase: draft.networkPassphrase,
      contractId: draft.contractId,
      method: draft.method,
      args: [
        { type: 'address', value: walletAddress },
        { type: 'address', value: draft.protectedAssetContractId },
        { type: 'address', value: draft.payoutAssetContractId },
        { type: 'i128', value: draft.amount },
        { type: 'u64', value: draft.durationSeconds },
      ],
      submitter: draft.submitter,
    };
    return response.json({
      positionId: position.id,
      status: position.status,
      transactionXdr: position.transaction_xdr,
      transactionPayload: payload,
    });
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not read signing payload.', request.requestId);
  }
});

app.post('/api/partner/v1/wallets/signing-payloads/:positionId/submit', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'wallets.submit');
    if (!partner) return null;
    if (!isPlainObject(request.body)) return partnerApiError(response, 400, 'invalid_request', 'Request body must be a JSON object.', request.requestId);
    const position = await getPartnerPosition(cleanShortString(request.params.positionId, 80), partner.partner_id);
    if (!position) return partnerApiError(response, 404, 'position_not_found', 'Position was not found.', request.requestId);
    const transactionXdr = cleanShortString(request.body.transactionXdr, 20000);
    if (!transactionXdr) return partnerApiError(response, 400, 'invalid_request', 'transactionXdr is required.', request.requestId);
    return partnerApiError(response, 501, 'provider_error', 'Signed transaction submission is not enabled in this backend yet. Submit the XDR through a Stellar wallet or add the transaction submitter worker.', request.requestId);
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not submit signed transaction.', request.requestId);
  }
});

app.get('/api/partner/v1/wallets/linked/:customerReference', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'wallets.read');
    if (!partner) return null;
    return response.json({
      customerReference: cleanShortString(request.params.customerReference, 120),
      wallet: null,
      message: 'Partner wallet linking storage is not enabled yet.',
    });
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not read linked wallet.', request.requestId);
  }
});

app.get('/api/partner/v1/claims', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'claims.read');
    if (!partner) return null;
    return response.json({
      claims: [],
      message: 'Claim indexing will populate this collection after the partner worker is connected to contract events.',
    });
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not list claims.', request.requestId);
  }
});

app.get('/api/partner/v1/claims/:claimId', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'claims.read');
    if (!partner) return null;
    return partnerApiError(response, 404, 'claim_not_found', 'Claim was not found.', request.requestId);
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not read claim.', request.requestId);
  }
});

app.get('/api/partner/v1/payouts', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'payouts.read');
    if (!partner) return null;
    return response.json({
      payouts: [],
      message: 'Payout indexing will populate this collection after the partner worker is connected to contract events.',
    });
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not list payouts.', request.requestId);
  }
});

app.get('/api/partner/v1/payouts/:payoutId', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'payouts.read');
    if (!partner) return null;
    return partnerApiError(response, 404, 'payout_not_found', 'Payout was not found.', request.requestId);
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not read payout.', request.requestId);
  }
});

app.get('/api/partner/v1/receipts', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'receipts.read');
    if (!partner) return null;
    const limit = Math.max(1, Math.min(100, Number(request.query.limit) || 50));
    const result = await dbQuery(
      `SELECT id, transaction_hash, event_type, occurred_at, payload
       FROM contract_events
       WHERE partner_id = $1
         AND event_type ILIKE '%receipt%'
       ORDER BY occurred_at DESC
       LIMIT $2`,
      [partner.partner_id, limit],
    );
    return response.json({
      receipts: result.rows.map((row) => ({
        id: row.id,
        transactionHash: row.transaction_hash,
        status: row.event_type,
        createdAt: row.occurred_at,
        payload: row.payload || {},
      })),
    });
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not list receipts.', request.requestId);
  }
});

app.get('/api/partner/v1/receipts/:receiptId', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'receipts.read');
    if (!partner) return null;
    const result = await dbQuery(
      `SELECT id, transaction_hash, event_type, occurred_at, payload
       FROM contract_events
       WHERE partner_id = $1 AND id::text = $2
       LIMIT 1`,
      [partner.partner_id, cleanShortString(request.params.receiptId, 80)],
    );
    if (!result.rows[0]) return partnerApiError(response, 404, 'receipt_not_found', 'Receipt was not found.', request.requestId);
    const row = result.rows[0];
    return response.json({
      receipt: {
        id: row.id,
        transactionHash: row.transaction_hash,
        status: row.event_type,
        createdAt: row.occurred_at,
        payload: row.payload || {},
      },
    });
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not read receipt.', request.requestId);
  }
});

app.get('/api/partner/v1/webhooks', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'webhooks.manage');
    if (!partner) return null;
    const result = await dbQuery(
      `SELECT id, url, event_types, active, created_at
       FROM partner_webhooks
       WHERE partner_id = $1
       ORDER BY created_at DESC
       LIMIT 100`,
      [partner.partner_id],
    );
    return response.json({ webhooks: result.rows });
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not list webhooks.', request.requestId);
  }
});

app.post('/api/partner/v1/webhooks', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'webhooks.manage');
    if (!partner) return null;
    if (!isPlainObject(request.body)) return partnerApiError(response, 400, 'invalid_request', 'Request body must be a JSON object.', request.requestId);
    const webhook = await createPartnerWebhook({
      partnerId: partner.partner_id,
      url: cleanShortString(request.body.url, 400),
      eventTypes: cleanStringArray(request.body.eventTypes, 20, 100),
    });
    return response.status(201).json({ webhook });
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not create webhook.', request.requestId);
  }
});

app.get('/api/partner/v1/requests/:requestId', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'usage.read');
    if (!partner) return null;
    const result = await dbQuery(
      `SELECT request_id, method, path, status_code, error_code, latency_ms,
        idempotency_key, created_at
       FROM partner_requests
       WHERE partner_id = $1 AND request_id = $2`,
      [partner.partner_id, cleanShortString(request.params.requestId, 120)],
    );
    if (!result.rows[0]) return partnerApiError(response, 404, 'invalid_request', 'Request was not found.', request.requestId);
    return response.json({ request: result.rows[0] });
  } catch (error) {
    return partnerApiError(response, error.statusCode || 500, error.code || 'internal_error', error.message || 'Could not read request.', request.requestId);
  }
});

app.get('/api/partners/admin', async (request, response) => {
  try {
    if (!requireConfiguredDatabase(response)) return null;
    const adminSession = requirePartnerAdminSession(request, response);
    if (!adminSession) return null;
    return response.json({ partners: await listPartners() });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not list partners.', error, 'partners/admin/list');
  }
});

app.post('/api/partners/admin', async (request, response) => {
  try {
    if (!requireConfiguredDatabase(response)) return null;
    const adminSession = requirePartnerAdminSession(request, response);
    if (!adminSession) return null;
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }

    const slug = validatePartnerSlug(request.body.slug);
    const displayName = cleanShortString(request.body.displayName, 120);
    const onchainPartnerAddress = cleanWalletAddress(request.body.onchainPartnerAddress);
    const websiteUrl = cleanShortString(request.body.websiteUrl, 240);

    if (!slug || !displayName) {
      return response.status(400).json({ message: 'Valid slug and displayName are required.' });
    }
    if (onchainPartnerAddress && !isValidWalletAddress(onchainPartnerAddress)) {
      return response.status(400).json({ message: 'onchainPartnerAddress must be a valid Stellar public key.' });
    }

    const partner = await createPartner({
      slug,
      displayName,
      onchainPartnerAddress,
      websiteUrl,
      createdByWalletRef: adminSession.walletRef,
    });
    return response.status(201).json({ partner });
  } catch (error) {
    const status = error.code === '23505' ? 409 : error.statusCode || 500;
    return sendApiError(response, status, error.code === '23505' ? 'Partner slug already exists.' : error.message || 'Could not create partner.', error, 'partners/admin/create');
  }
});

app.patch('/api/partners/admin/:partnerId/status', async (request, response) => {
  try {
    if (!requireConfiguredDatabase(response)) return null;
    const adminSession = requirePartnerAdminSession(request, response);
    if (!adminSession) return null;
    const status = cleanShortString(request.body?.status, 24);
    if (!['pending', 'enabled', 'suspended', 'revoked'].includes(status)) {
      return response.status(400).json({ message: 'Status must be pending, enabled, suspended, or revoked.' });
    }
    const partner = await setPartnerStatus(cleanShortString(request.params.partnerId, 80), status);
    if (!partner) return response.status(404).json({ message: 'Partner not found.' });
    return response.json({ partner });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not update partner status.', error, 'partners/admin/status');
  }
});

app.post('/api/partners/admin/:partnerId/api-keys', async (request, response) => {
  try {
    if (!requireConfiguredDatabase(response)) return null;
    const adminSession = requirePartnerAdminSession(request, response);
    if (!adminSession) return null;
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }
    const label = cleanShortString(request.body.label, 80) || 'Default key';
    const scopes = Array.isArray(request.body.scopes)
      ? request.body.scopes.map((scope) => cleanShortString(scope, 40)).filter(Boolean).slice(0, 12)
      : undefined;
    const key = await createPartnerKey({
      partnerId: cleanShortString(request.params.partnerId, 80),
      label,
      scopes,
      rateLimitPerMinute: Number(request.body.rateLimitPerMinute) || undefined,
      createdByWalletRef: adminSession.walletRef,
    });
    return response.status(201).json({
      apiKey: key,
      warning: 'Store this partner API secret now. The server stores only a keyed hash and will not show the secret again.',
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not create partner API key.', error, 'partners/admin/key');
  }
});

app.get('/api/partners/market-config', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'quote:read');
    if (!partner) return null;
    return response.json({
      network: env.contracts.network,
      contracts: {
        protectionEngine: env.contracts.protectionEngine,
        reserveVault: env.contracts.reserveVault,
        oracleAdapter: env.contracts.oracleAdapter,
        protectedBalanceVault: env.contracts.protectedBalanceVault,
        usernameRegistry: env.contracts.usernameRegistry,
        receiptRegistry: env.contracts.receiptRegistry,
        zkVerifier: env.contracts.zkVerifier,
      },
      assets: {
        protected: env.contracts.xlmToken,
        payout: env.contracts.payoutToken,
        payoutSymbol: 'CFTUSD',
      },
      partner: {
        id: partner.partner_id,
        slug: partner.slug,
        displayName: partner.display_name,
      },
      limitations: {
        apiKeysAuthorizeTransactions: false,
        walletSignatureRequired: true,
        mainnetEnabled: env.contracts.network === 'mainnet',
      },
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not read partner market configuration.', error, 'partners/market-config');
  }
});

app.get('/api/partners/metrics', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'metrics:read');
    if (!partner) return null;
    const metrics = await getPartnerMetrics(partner.partner_id, request.query.days);
    return response.json({
      partner: {
        id: partner.partner_id,
        slug: partner.slug,
        displayName: partner.display_name,
      },
      metrics,
      privacy: {
        rawWalletAddresses: false,
        smallCohortSuppression: true,
      },
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not read partner metrics.', error, 'partners/metrics');
  }
});

app.post('/api/partners/quote', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'quote:read');
    if (!partner) return null;
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }
    const protectedAmount = decimalToStroops(request.body.protectedAmount);
    const durationSeconds = Number(request.body.durationSeconds);
    const protectedAsset = cleanShortString(request.body.protectedAssetContractId || env.contracts.xlmToken, 80);
    const payoutAsset = cleanShortString(request.body.payoutAssetContractId || env.contracts.payoutToken, 80);
    if (!protectedAmount || protectedAmount <= 0n || !Number.isSafeInteger(durationSeconds) || durationSeconds <= 0) {
      return response.status(400).json({ message: 'protectedAmount and durationSeconds are required.' });
    }
    if (!protectedAsset || !payoutAsset) {
      return response.status(503).json({ message: 'Protected and payout asset contract IDs are not configured.' });
    }

    const quote = await simulateContractRead(env.contracts.protectionEngine, 'quote_position', [
      Address.fromString(protectedAsset).toScVal(),
      Address.fromString(payoutAsset).toScVal(),
      nativeToScVal(protectedAmount, { type: 'i128' }),
      nativeToScVal(BigInt(durationSeconds), { type: 'u64' }),
    ]);

    return response.json({
      partner: {
        id: partner.partner_id,
        slug: partner.slug,
      },
      quote: serializeQuote(quote),
      assets: {
        protected: protectedAsset,
        payout: payoutAsset,
      },
      durationSeconds,
      walletSignatureRequired: true,
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 502, error.message || 'Could not quote partner protection.', error, 'partners/quote');
  }
});

app.post('/api/partners/transaction-drafts/protection', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'tx:build');
    if (!partner) return null;
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }
    const userAddress = cleanWalletAddress(request.body.userAddress);
    const protectedAmount = decimalToStroops(request.body.protectedAmount);
    const durationSeconds = Number(request.body.durationSeconds);
    const protectedAsset = cleanShortString(request.body.protectedAssetContractId || env.contracts.xlmToken, 80);
    const payoutAsset = cleanShortString(request.body.payoutAssetContractId || env.contracts.payoutToken, 80);
    const partnerAddress = cleanWalletAddress(request.body.partnerAddress || '');

    if (!isValidWalletAddress(userAddress)) {
      return response.status(400).json({ message: 'A valid userAddress is required.' });
    }
    if (!protectedAmount || protectedAmount <= 0n || !Number.isSafeInteger(durationSeconds) || durationSeconds <= 0) {
      return response.status(400).json({ message: 'protectedAmount and durationSeconds are required.' });
    }
    if (!protectedAsset || !payoutAsset) {
      return response.status(503).json({ message: 'Protected and payout asset contract IDs are not configured.' });
    }
    if (partnerAddress && !isValidWalletAddress(partnerAddress)) {
      return response.status(400).json({ message: 'partnerAddress must be a valid Stellar public key.' });
    }

    return response.json({
      draft: {
        network: env.contracts.network,
        networkPassphrase: env.contracts.networkPassphrase,
        contractId: env.contracts.protectionEngine,
        method: 'create_position',
        args: [
          { type: 'address', value: userAddress },
          { type: 'address', value: protectedAsset },
          { type: 'address', value: payoutAsset },
          { type: 'i128', value: protectedAmount.toString() },
          { type: 'u64', value: String(durationSeconds) },
        ],
        submitter: 'user_wallet',
      },
      partner: {
        id: partner.partner_id,
        slug: partner.slug,
      },
      warning: 'This endpoint does not authorize, sign, or submit transactions. The user wallet must simulate, review, sign, and submit. Partner attribution is recorded in CoverFi partner records; on-chain partner address attribution requires the upgraded six-argument protection contract deployment.',
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not build partner transaction draft.', error, 'partners/tx-draft');
  }
});

app.post('/api/partners/webhooks', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'webhooks:write');
    if (!partner) return null;
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }
    const targetUrl = cleanShortString(request.body.url, 240);
    if (!/^https:\/\/[^\s]+$/i.test(targetUrl)) {
      return response.status(400).json({ message: 'Webhook URL must be HTTPS.' });
    }
    const eventTypes = Array.isArray(request.body.eventTypes)
      ? request.body.eventTypes.map((eventType) => cleanShortString(eventType, 80)).filter(Boolean).slice(0, 20)
      : undefined;
    const webhook = await createPartnerWebhook({
      partnerId: partner.partner_id,
      url: targetUrl,
      eventTypes,
    });
    return response.status(201).json({
      webhook,
      warning: 'Store this webhook secret now. The server stores only a keyed hash and will not show the secret again.',
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not register webhook.', error, 'partners/webhooks/create');
  }
});

app.post('/api/partners/webhooks/test', async (request, response) => {
  try {
    const partner = await requirePartnerApiSession(request, response, 'webhooks:write');
    if (!partner) return null;
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }
    const targetUrl = cleanShortString(request.body.url, 240);
    if (!/^https:\/\/[^\s]+$/i.test(targetUrl)) {
      return response.status(400).json({ message: 'Webhook URL must be HTTPS.' });
    }
    return response.json({
      accepted: true,
      deliveryId: crypto.randomUUID(),
      event: {
        type: 'position.settled',
        createdAt: new Date().toISOString(),
        partnerId: partner.partner_id,
        test: true,
      },
      note: 'Webhook persistence and retry delivery use the webhook_deliveries table when worker delivery is enabled.',
    });
  } catch (error) {
    return sendApiError(response, error.statusCode || 500, error.message || 'Could not prepare webhook test.', error, 'partners/webhooks/test');
  }
});

app.get('/api/prices', (_request, response) => {
  response.json({ assets: getSupportedPriceAssets() });
});

app.get('/api/prices/:asset', async (request, response) => {
  try {
    const price = await getUsdPriceForAsset(request.params.asset);
    return response.json(price);
  } catch (error) {
    return response.status(error.statusCode || 500).json({ message: error.message || 'Could not fetch price.' });
  }
});

app.get('/api/portfolio/markets', async (request, response) => {
  try {
    const markets = await getPortfolioMarkets({
      perPage: request.query.perPage,
      page: request.query.page,
    });
    return response.json(markets);
  } catch (error) {
    return response.status(error.statusCode || 500).json({ message: error.message || 'Could not fetch market data.' });
  }
});

app.get('/api/ai/chat/:walletAddress', async (request, response) => {
  try {
    const walletAddress = cleanWalletAddress(request.params.walletAddress);

    if (!isValidWalletAddress(walletAddress)) {
      return response.status(400).json({ message: 'A valid Stellar wallet address is required.' });
    }

    return response.json(localOnlyStoragePayload({
      messages: [],
      walletRef: walletLogRef(walletAddress),
      message: 'AI history is not stored by the server.',
    }));
  } catch (error) {
    return sendApiError(response, 500, error.message || 'Could not load chat history boundary.', error, 'ai/chat/get');
  }
});

app.post('/api/ai/chat', async (request, response) => {
  try {
    if (!isPlainObject(request.body)) {
      return response.status(400).json({ message: 'Request body must be a JSON object.' });
    }

    const message = String(request.body?.message || '').trim();
    const walletAddress = cleanWalletAddress(request.body?.walletAddress || request.body?.accountContext?.walletAddress || '');
    const mode = request.body?.mode === 'research' ? 'research' : 'chat';
    const model = String(request.body?.model || '').trim();
    const accountContext = sanitizeAiAccountContext(request.body?.accountContext, walletAddress);

    if (!message) {
      return response.status(400).json({ message: 'Message is required.' });
    }

    if (message.length > 2000) {
      return response.status(400).json({ message: 'Message is too long. Please keep it under 2,000 characters.' });
    }

    if (walletAddress && !isValidWalletAddress(walletAddress)) {
      return response.status(400).json({ message: 'A valid Stellar wallet address is required.' });
    }

    let marketContext = null;
    try {
      marketContext = buildMarketContext(await getPortfolioMarkets({ perPage: 20, page: 1 }));
    } catch (error) {
      logApiError('ai/chat/markets', error);
      marketContext = {
        provider: 'CoinGecko',
        error: error?.message || 'Live prices are currently unavailable.',
      };
    }

    const researchContext = mode === 'research'
      ? await getCoverFiResearchContext()
      : null;

    const reply = await createDeepSeekReply(message, {
      mode,
      model,
      accountContext,
      marketContext,
      researchContext,
    });

    return response.json({
      reply,
      mode,
      model,
      marketContext,
      sources: researchContext?.map((source) => ({ label: source.label, url: source.url })) || [],
      historyPersistence: request.body?.persistHistory === true
        ? 'browser_encrypted_indexeddb_only'
        : 'not_requested',
    });
  } catch (error) {
    return response.status(error.statusCode || 500).json({
      message: error.message || 'AI chat failed.',
    });
  }
});

async function shutdown(signal) {
  console.log(`Received ${signal}. Closing Auth API...`);
  httpServer?.close();
  process.exit(0);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

process.on('uncaughtException', (error) => {
  console.error('Uncaught exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (error) => {
  console.error('Unhandled rejection:', error);
  process.exit(1);
});

export function startServer() {
  if (httpServer) {
    return httpServer;
  }

  httpServer = app.listen(env.server.port, env.server.host, async () => {
    writeLog('info', 'server_started', {
      url: `http://${env.server.host}:${env.server.port}`,
      aiConfigured: isDeepSeekConfigured(),
      backendProductDatabase: false,
    });
  });

  httpServer.on('close', () => {
    writeLog('info', 'server_closed');
  });

  httpServer.on('error', (error) => {
    writeLog('error', 'server_error', { detail: error.message || String(error) });
    process.exit(1);
  });

  return httpServer;
}

export { app };

if (process.env.NODE_ENV !== 'test') {
  startServer();
}
