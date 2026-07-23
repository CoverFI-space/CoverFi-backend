import dotenv from 'dotenv';
import crypto from 'crypto';
import { fileURLToPath } from 'node:url';

dotenv.config();

const isProduction = process.env.NODE_ENV === 'production';
const shouldLoadFrontendEnv = !isProduction && process.env.LOAD_FRONTEND_ENV !== 'false';

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

const configuredAuthSessionSecret = optionalString('AUTH_SESSION_SECRET');
if (isProduction && !configuredAuthSessionSecret) {
  throw new Error('AUTH_SESSION_SECRET is required in production.');
}

const authSessionSecret = configuredAuthSessionSecret
  || crypto.randomBytes(32).toString('hex');
const configuredPrivacyHmacSecret = optionalString('PRIVACY_HMAC_SECRET');
if (isProduction && !configuredPrivacyHmacSecret) {
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
    authSessionSecret,
    authIssuer: optionalString('AUTH_ISSUER', 'coverfi-api'),
    authAudience: optionalString('AUTH_AUDIENCE', 'coverfi-app'),
    authChallengeTtlMs: optionalNumber('AUTH_CHALLENGE_TTL_MS', 5 * 60 * 1000),
    authSessionTtlMs: optionalNumber('AUTH_SESSION_TTL_MS', 30 * 60 * 1000),
    privacyHmacSecret,
    trustedProxyHops: optionalNumber('TRUSTED_PROXY_HOPS', 0),
    requestTimeoutMs: optionalNumber('REQUEST_TIMEOUT_MS', 15_000),
    upstreamMaxBytes: optionalNumber('UPSTREAM_MAX_BYTES', 1_000_000),
  },
  deepseek: {
    apiKey: optionalString('DEEPSEEK_API_KEY'),
    baseUrl: optionalString('DEEPSEEK_BASE_URL', 'https://api.deepseek.com'),
    model: optionalString('DEEPSEEK_MODEL', 'deepseek-chat'),
    researchModel: optionalString('DEEPSEEK_RESEARCH_MODEL', 'deepseek-research'),
    temperature: optionalNumber('DEEPSEEK_TEMPERATURE', 0.3),
    maxTokens: optionalNumber('DEEPSEEK_MAX_TOKENS', 700),
    timeoutMs: optionalNumber('DEEPSEEK_TIMEOUT_MS', 30000),
  },
  prices: {
    coingeckoBaseUrl: optionalString('COINGECKO_BASE_URL', 'https://api.coingecko.com'),
    coingeckoApiKey: optionalString('COINGECKO_API_KEY'),
    coingeckoApiTier: optionalString('COINGECKO_API_TIER', 'demo'),
    cacheMs: optionalNumber('PRICE_CACHE_MS', 30000),
    timeoutMs: optionalNumber('PRICE_TIMEOUT_MS', 12000),
  },
  oracle: {
    // This can only enable a separately authenticated testnet maintenance route.
    // It must remain false for normal deployments and mainnet operations.
    automaticRefreshEnabled: optionalString('ENABLE_TESTNET_ORACLE_REFRESH', 'false').toLowerCase() === 'true',
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
  partners: {
    adminWallets: optionalStringList('PARTNER_ADMIN_WALLETS'),
    apiKeyPepper: optionalString('PARTNER_API_KEY_PEPPER', privacyHmacSecret),
    defaultRateLimitPerMinute: optionalNumber('PARTNER_API_KEY_RATE_LIMIT_PER_MINUTE', 120),
  },
  business: {
    treasuryWallet: optionalString('COVERFI_TREASURY_WALLET', 'GAUA4NE5ELCWHHWNJSNJH3TRHAVZJPK3UMMVL6XSHAOTQQQ2PS2KV7YZ'),
    receiptPrintFeeCftusd: optionalNumber('RECEIPT_PRINT_FEE_CFTUSD', 0.1),
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
    protectedBalanceVault: optionalString('PROTECTED_BALANCE_VAULT_CONTRACT_ID', optionalString('VITE_PROTECTED_BALANCE_VAULT_CONTRACT_ID')),
    reserveVault: optionalString('RESERVE_VAULT_CONTRACT_ID', optionalString('VITE_RESERVE_VAULT_CONTRACT_ID')),
    oracleAdapter: optionalString('ORACLE_ADAPTER_CONTRACT_ID', optionalString('VITE_ORACLE_ADAPTER_CONTRACT_ID')),
    usernameRegistry: optionalString('USERNAME_REGISTRY_ID', optionalString('VITE_USERNAME_REGISTRY_ID')),
    receiptRegistry: optionalString('RECEIPT_REGISTRY_ID', optionalString('VITE_RECEIPT_REGISTRY_ID')),
    zkVerifier: optionalString('ZK_VERIFIER_CONTRACT_ID', optionalString('VITE_ZK_VERIFIER_CONTRACT_ID')),
    xlmToken: optionalString('XLM_TESTNET_CONTRACT_ID', optionalString('VITE_XLM_TESTNET_CONTRACT_ID')),
    payoutToken: optionalString(
      'CFTUSD_TESTNET_CONTRACT_ID',
      optionalString('VITE_CFTUSD_TESTNET_CONTRACT_ID', optionalString('VITE_USDC_TESTNET_CONTRACT_ID')),
    ),
  },
};

export function isDeepSeekConfigured() {
  return Boolean(env.deepseek.apiKey);
}
