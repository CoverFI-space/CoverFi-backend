import dotenv from 'dotenv';

dotenv.config();

function optionalString(name, fallback = '') {
  return String(process.env[name] || fallback).trim();
}

function optionalNumber(name, fallback) {
  const value = Number(process.env[name]);
  return Number.isFinite(value) ? value : fallback;
}

function getServerHost() {
  const host = optionalString('HOST', 'localhost');
  const isAzureAppService = Boolean(process.env.WEBSITE_SITE_NAME || process.env.WEBSITE_INSTANCE_ID);

  if (isAzureAppService && host === 'localhost') {
    return '0.0.0.0';
  }

  return host;
}

export const env = {
  server: {
    port: optionalNumber('PORT', 8890),
    host: getServerHost(),
    clientOrigin: optionalString('CLIENT_ORIGIN', 'http://localhost:5173'),
  },
  firebase: {
    serviceAccountBase64: optionalString('FIREBASE_SERVICE_ACCOUNT_BASE64'),
    projectId: optionalString('FIREBASE_PROJECT_ID'),
  },
  deepseek: {
    apiKey: optionalString('DEEPSEEK_API_KEY'),
    baseUrl: optionalString('DEEPSEEK_BASE_URL', 'https://api.deepseek.com'),
    model: optionalString('DEEPSEEK_MODEL', 'deepseek-chat'),
    temperature: optionalNumber('DEEPSEEK_TEMPERATURE', 0.3),
    maxTokens: optionalNumber('DEEPSEEK_MAX_TOKENS', 700),
    timeoutMs: optionalNumber('DEEPSEEK_TIMEOUT_MS', 30000),
  },
  prices: {
    coingeckoBaseUrl: optionalString('COINGECKO_BASE_URL', 'https://api.coingecko.com'),
    cacheMs: optionalNumber('PRICE_CACHE_MS', 30000),
    timeoutMs: optionalNumber('PRICE_TIMEOUT_MS', 12000),
  },
};

export function isDeepSeekConfigured() {
  return Boolean(env.deepseek.apiKey);
}
