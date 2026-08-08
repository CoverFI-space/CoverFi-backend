import dotenv from 'dotenv';
import crypto from 'crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const isProduction = process.env.NODE_ENV === 'production';
const isTest = process.env.NODE_ENV === 'test';
const oracleEntrypoints = new Set([
  'oracle-worker.js',
  'testnet-oracle-worker.js',
  'refresh-oracle.js',
  'validate-mainnet-oracle-config.js',
]);
const isOracleProcess = oracleEntrypoints.has(path.basename(process.argv[1] || ''));

// In development, a project .env should win over an old machine-level value.
// In production, platform-managed environment variables (for example Azure App
// Service settings) remain authoritative and are never overridden by a file.
// Tests must also remain isolated: an engineer's local .env cannot replace
// explicit test values or point a test suite at a real database.
if (!isTest) {
  dotenv.config({ override: !isProduction });
}

const shouldLoadFrontendEnv = !isProduction && !isTest && process.env.LOAD_FRONTEND_ENV !== 'false';

if (shouldLoadFrontendEnv) {
  dotenv.config({
    path: fileURLToPath(new URL('../../logic-pages/.env', import.meta.url)),
  });
}

function optionalString(name, fallback = '') {
  return String(process.env[name] || fallback).trim();
}

function optionalNumber(name, fallback) {
  const value = Number(process.env[name]);
  return Number.isFinite(value) ? value : fallback;
}

function optionalStringList(name, fallback = []) {
  const configured = optionalString(name);
  if (!configured) return fallback;
  return configured
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function getServerHost() {
  const host = optionalString('HOST', 'localhost');
  const isAzureAppService = Boolean(process.env.WEBSITE_SITE_NAME || process.env.WEBSITE_INSTANCE_ID);

  if (isAzureAppService && host === 'localhost') {
    return '0.0.0.0';
  }

  return host;
}

function getPasskeyRpId() {
  const configured = optionalString('PASSKEY_RP_ID');
  if (configured) return configured;
  try {
    return new URL(optionalString('CLIENT_ORIGIN', 'http://localhost:5173')).hostname;
  } catch {
    return 'localhost';
  }
}

const configuredAuthSessionSecret = optionalString('AUTH_SESSION_SECRET');
if (isProduction && !isOracleProcess && !configuredAuthSessionSecret) {
  throw new Error('AUTH_SESSION_SECRET is required in production.');
}

const authSessionSecret = configuredAuthSessionSecret
  || crypto.randomBytes(32).toString('hex');
const configuredPrivacyHmacSecret = optionalString('PRIVACY_HMAC_SECRET');
if (isProduction && !isOracleProcess && !configuredPrivacyHmacSecret) {
  throw new Error('PRIVACY_HMAC_SECRET is required in production.');
}
const privacyHmacSecret = configuredPrivacyHmacSecret || authSessionSecret;

export const env = {
  server: {
    isProduction,
    port: optionalNumber('PORT', 8890),
    host: getServerHost(),
    clientOrigin: optionalString('CLIENT_ORIGIN', 'http://localhost:5173'),
    clientOrigins: optionalStringList('CLIENT_ORIGINS'),
    termsVersion: optionalString('TERMS_VERSION', '2026-07-16'),
    mainnetPublicLaunchEnabled: optionalString('MAINNET_PUBLIC_LAUNCH_ENABLED', 'false').toLowerCase() === 'true',
    authSessionSecret,
    authIssuer: optionalString('AUTH_ISSUER', 'coverfi-api'),
    authAudience: optionalString('AUTH_AUDIENCE', 'coverfi-app'),
    authChallengeTtlMs: optionalNumber('AUTH_CHALLENGE_TTL_MS', 5 * 60 * 1000),
    // Optional SEP-10-style signer used only for wallets that cannot sign
    // arbitrary messages. It must be a dedicated Stellar key, never a treasury
    // or contract-admin key.
    authChallengeSignerSecret: optionalString('AUTH_CHALLENGE_SIGNER_SECRET'),
    authSessionTtlMs: optionalNumber('AUTH_SESSION_TTL_MS', 30 * 60 * 1000),
    privacyHmacSecret,
    trustedProxyHops: optionalNumber('TRUSTED_PROXY_HOPS', 0),
    requestTimeoutMs: optionalNumber('REQUEST_TIMEOUT_MS', 15_000),
    upstreamMaxBytes: optionalNumber('UPSTREAM_MAX_BYTES', 1_000_000),
  },
  azureOpenAi: {
    endpoint: optionalString('AZURE_OPENAI_ENDPOINT'),
    apiKey: optionalString('AZURE_OPENAI_API_KEY'),
    apiVersion: optionalString('AZURE_OPENAI_API_VERSION', '2024-10-21'),
    chatDeployment: optionalString('AZURE_OPENAI_CHAT_DEPLOYMENT', 'DeepSeek-V4-Flash'),
    researchDeployment: optionalString('AZURE_OPENAI_RESEARCH_DEPLOYMENT', 'DeepSeek-V4-Pro'),
    temperature: optionalNumber('AZURE_OPENAI_TEMPERATURE', 0.3),
    maxTokens: optionalNumber('AZURE_OPENAI_MAX_TOKENS', 700),
    timeoutMs: optionalNumber('AZURE_OPENAI_TIMEOUT_MS', 30000),
  },
  prices: {
    coingeckoBaseUrl: optionalString('COINGECKO_BASE_URL', 'https://api.coingecko.com'),
    coingeckoApiKey: optionalString('COINGECKO_API_KEY'),
    coingeckoApiTier: optionalString('COINGECKO_API_TIER', 'demo'),
    // Disabled for the CoinGecko-only temporary price flow:
    // cryptoCompareBaseUrl: optionalString('CRYPTOCOMPARE_BASE_URL', 'https://min-api.cryptocompare.com'),
    // cryptoCompareApiKey: optionalString('CRYPTOCOMPARE_API_KEY'),
    // coinbaseBaseUrl: optionalString('COINBASE_MARKET_DATA_BASE_URL', 'https://api.coinbase.com'),
    cacheMs: optionalNumber('PRICE_CACHE_MS', 30000),
    timeoutMs: optionalNumber('PRICE_TIMEOUT_MS', 12000),
  },
  oracle: {
    // Enables the bounded Testnet CoinGecko refresh route. The server fetches
    // the value itself and signs with the configured publisher keys.
    automaticRefreshEnabled: optionalString('ENABLE_TESTNET_ORACLE_REFRESH', 'false').toLowerCase() === 'true',
    publisher1Secret: optionalString('ORACLE_PUBLISHER_1_SECRET'),
    publisher2Secret: optionalString('ORACLE_PUBLISHER_2_SECRET'),
    publisher3Secret: optionalString('ORACLE_PUBLISHER_3_SECRET'),
    publisher1PublicKey: optionalString('ORACLE_PUBLISHER_1_PUBLIC_KEY'),
    publisher2PublicKey: optionalString('ORACLE_PUBLISHER_2_PUBLIC_KEY'),
    publisher3PublicKey: optionalString('ORACLE_PUBLISHER_3_PUBLIC_KEY'),
    quorumSourceContractId: optionalString('QUORUM_ORACLE_SOURCE_CONTRACT_ID'),
    // This is a separate, explicit production gate. A Mainnet worker cannot
    // start merely because the general Testnet switch was enabled.
    mainnetQuorumPublishingEnabled: optionalString('ENABLE_MAINNET_QUORUM_ORACLE_PUBLISHING', 'false').toLowerCase() === 'true',
    // Retained for the former multi-source implementation; the temporary
    // flow is always CoinGecko-only regardless of this setting.
    // mainnetSingleSourceDemoEnabled: optionalString('MAINNET_ORACLE_SINGLE_SOURCE_DEMO_MODE', 'false').toLowerCase() === 'true',
    // Enables bounded browser requests to the configured Mainnet refresh job.
    // The job is restored to publishing-disabled mode as soon as it starts.
    mainnetRefreshRequestEnabled: optionalString('ENABLE_MAINNET_ORACLE_REFRESH_REQUESTS', 'false').toLowerCase() === 'true',
    azureResourceGroup: optionalString('AZURE_ORACLE_RESOURCE_GROUP', 'coverfi_group'),
    azureJobName: optionalString('AZURE_ORACLE_JOB_NAME', 'coverfi-oracle-mainnet'),
    // Azure requires an image when a one-off execution overrides command/env.
    azureJobImage: optionalString('AZURE_ORACLE_JOB_IMAGE', 'coverfioraclecr.azurecr.io/coverfi-oracle-worker:20260726-10'),
    refreshAsset: optionalString('ORACLE_REFRESH_ASSET', 'XLM Stellar'),
    refreshAssetContractId: optionalString('ORACLE_REFRESH_ASSET_CONTRACT_ID'),
    maxPriceSourceAgeMs: optionalNumber('ORACLE_MAX_PRICE_SOURCE_AGE_MS', 5 * 60 * 1000),
    // Disabled because the active flow has one price source and therefore no
    // cross-source deviation check.
    // maxSourceDeviationBps: optionalNumber('ORACLE_MAX_SOURCE_DEVIATION_BPS', 300),
  },
  reserveAttestation: {
    // Optional, testnet-only off-chain signer for public reserve snapshots.
    // Keep this key in the deployment secret store; never expose it to a browser.
    secret: optionalString('TESTNET_RESERVE_ATTESTATION_SECRET'),
    publicKey: optionalString('TESTNET_RESERVE_ATTESTATION_PUBLIC_KEY'),
  },
  rateLimit: {
    backend: optionalString('RATE_LIMIT_BACKEND', 'memory'),
    upstashRestUrl: optionalString('UPSTASH_REDIS_REST_URL'),
    upstashRestToken: optionalString('UPSTASH_REDIS_REST_TOKEN'),
    redisUrl: optionalString('REDIS_URL'),
    windowMs: optionalNumber('RATE_LIMIT_WINDOW_MS', 60000),
    generalMax: optionalNumber('RATE_LIMIT_GENERAL_MAX', 180),
    authMax: optionalNumber('RATE_LIMIT_AUTH_MAX', 30),
    paymentsMax: optionalNumber('RATE_LIMIT_PAYMENTS_MAX', 60),
    aiMax: optionalNumber('RATE_LIMIT_AI_MAX', 20),
    partnerMax: optionalNumber('RATE_LIMIT_PARTNER_MAX', 120),
  },
  database: {
    url: optionalString('DATABASE_URL'),
    ssl: optionalString('DATABASE_SSL', 'false').toLowerCase() === 'true',
  },
  didit: {
    apiKey: optionalString('DIDIT_API_KEY'),
    webhookSecret: optionalString('DIDIT_WEBHOOK_SECRET'),
    kycWorkflowId: optionalString('DIDIT_KYC_WORKFLOW_ID'),
    kybWorkflowId: optionalString('DIDIT_KYB_WORKFLOW_ID'),
  },
  onboarding: {
    emailFrom: optionalString('ONBOARDING_EMAIL_FROM', 'CoverFi <donotreply@mail.coverfi.space>'),
    resendApiKey: optionalString('RESEND_API_KEY'),
    otpPepper: optionalString('ONBOARDING_OTP_PEPPER', authSessionSecret),
    otpTtlMs: optionalNumber('ONBOARDING_OTP_TTL_MS', 10 * 60 * 1000),
    otpMaxAttempts: optionalNumber('ONBOARDING_OTP_MAX_ATTEMPTS', 5),
    tokenTtlMs: optionalNumber('ONBOARDING_TOKEN_TTL_MS', 30 * 60 * 1000),
    friendbotUrl: optionalString('STELLAR_TESTNET_FRIENDBOT_URL', 'https://friendbot.stellar.org'),
  },
  passkeys: {
    // WebAuthn credentials are bound to this exact relying-party domain and
    // origin. Do not derive either from an incoming request header.
    rpId: getPasskeyRpId(),
    rpName: optionalString('PASSKEY_RP_NAME', 'CoverFi'),
    origin: optionalString('PASSKEY_ORIGIN', optionalString('CLIENT_ORIGIN', 'http://localhost:5173')),
    challengeTtlMs: optionalNumber('PASSKEY_CHALLENGE_TTL_MS', 5 * 60 * 1000),
  },
  partners: {
    adminWallets: optionalStringList('PARTNER_ADMIN_WALLETS'),
    apiKeyPepper: optionalString('PARTNER_API_KEY_PEPPER', privacyHmacSecret),
    defaultRateLimitPerMinute: optionalNumber('PARTNER_API_KEY_RATE_LIMIT_PER_MINUTE', 120),
  },
  business: {
    treasuryWallet: optionalString('COVERFI_TREASURY_WALLET', 'GAUA4NE5ELCWHHWNJSNJH3TRHAVZJPK3UMMVL6XSHAOTQQQ2PS2KV7YZ'),
    receiptPrintFeeXlm: optionalNumber('RECEIPT_PRINT_FEE_XLM', 0.1),
    highValueVerificationUsd: optionalNumber('HIGH_VALUE_VERIFICATION_USD', 100),
    targetProtocolFeeBps: optionalNumber('TARGET_PROTOCOL_FEE_BPS', 1200),
  },
  statuspage: {
    publicUrl: optionalString('STATUSPAGE_PUBLIC_URL'),
    pageId: optionalString('STATUSPAGE_PAGE_ID'),
    apiKey: optionalString('STATUSPAGE_API_KEY'),
    timeoutMs: optionalNumber('STATUSPAGE_TIMEOUT_MS', 10000),
    components: {
      dashboard: optionalString('STATUSPAGE_COMPONENT_DASHBOARD_ID'),
      protect: optionalString('STATUSPAGE_COMPONENT_PROTECT_ID'),
      payUsername: optionalString('STATUSPAGE_COMPONENT_PAY_USERNAME_ID'),
    },
  },
  contracts: {
    network: optionalString('STELLAR_NETWORK', 'testnet'),
    rpcUrl: optionalString('STELLAR_RPC_URL', 'https://soroban-testnet.stellar.org'),
    networkPassphrase: optionalString('STELLAR_NETWORK_PASSPHRASE', 'Test SDF Network ; September 2015'),
    statusSourceAccount: optionalString('STELLAR_STATUS_SOURCE_ACCOUNT', optionalString('VITE_DEPLOYMENT_SOURCE_ACCOUNT')),
    protectionEngine: optionalString('PROTECTION_ENGINE_CONTRACT_ID', optionalString('VITE_PROTECTION_ENGINE_CONTRACT_ID')),
    paymentLockEngine: optionalString('PAYMENT_LOCK_ENGINE_CONTRACT_ID', optionalString('VITE_PAYMENT_LOCK_ENGINE_CONTRACT_ID')),
    paymentLockReserveVault: optionalString('PAYMENT_LOCK_RESERVE_VAULT_CONTRACT_ID', optionalString('VITE_PAYMENT_LOCK_RESERVE_VAULT_CONTRACT_ID')),
    floorShieldEngine: optionalString('FLOOR_SHIELD_ENGINE_CONTRACT_ID', optionalString('VITE_FLOOR_SHIELD_ENGINE_CONTRACT_ID')),
    floorShieldReserveVault: optionalString('FLOOR_SHIELD_RESERVE_VAULT_CONTRACT_ID', optionalString('VITE_FLOOR_SHIELD_RESERVE_VAULT_CONTRACT_ID')),
    floorShieldProtectedVault: optionalString('FLOOR_SHIELD_PROTECTED_VAULT_CONTRACT_ID', optionalString('VITE_FLOOR_SHIELD_PROTECTED_VAULT_CONTRACT_ID')),
    protectedBalanceVault: optionalString('PROTECTED_BALANCE_VAULT_CONTRACT_ID', optionalString('VITE_PROTECTED_BALANCE_VAULT_CONTRACT_ID')),
    reserveVault: optionalString('RESERVE_VAULT_CONTRACT_ID', optionalString('VITE_RESERVE_VAULT_CONTRACT_ID')),
    oracleAdapter: optionalString('ORACLE_ADAPTER_CONTRACT_ID', optionalString('VITE_ORACLE_ADAPTER_CONTRACT_ID')),
    usernameRegistry: optionalString('USERNAME_REGISTRY_ID', optionalString('VITE_USERNAME_REGISTRY_ID')),
    receiptRegistry: optionalString('RECEIPT_REGISTRY_ID', optionalString('VITE_RECEIPT_REGISTRY_ID')),
    zkVerifier: optionalString('ZK_VERIFIER_CONTRACT_ID', optionalString('VITE_ZK_VERIFIER_CONTRACT_ID')),
    xlmToken: optionalString('XLM_CONTRACT_ID', optionalString('XLM_TESTNET_CONTRACT_ID', optionalString('VITE_XLM_TESTNET_CONTRACT_ID'))),
    payoutToken: optionalString('PAYOUT_TOKEN_CONTRACT_ID', optionalString('XLM_CONTRACT_ID', optionalString('XLM_TESTNET_CONTRACT_ID', optionalString('VITE_XLM_TESTNET_CONTRACT_ID')))),
  },
};

export function isAzureOpenAiConfigured() {
  return Boolean(env.azureOpenAi.endpoint && env.azureOpenAi.apiKey);
}
