import { env } from '../config/env.js';

const priceCache = new Map();
const marketCache = new Map();

const assetFeeds = {
  USDC: { id: 'usd-coin', label: 'USDC on Stellar' },
  EURC: { id: 'euro-coin', label: 'EURC on Stellar' },
  PYUSD: { id: 'paypal-usd', label: 'PYUSD on Stellar' },
  XLM: { id: 'stellar', label: 'XLM Stellar' },
  AQUA: { id: 'aquarius', label: 'AQUA Stellar' },
  USDT: { id: 'tether', label: 'USDT Stellar' },
};

export class PriceFeedError extends Error {
  constructor(message, statusCode = 502) {
    super(message);
    this.name = 'PriceFeedError';
    this.statusCode = statusCode;
  }
}

function normalizeAsset(value) {
  const text = String(value || '').trim().toUpperCase();
  return text.split(/\s+/)[0];
}

export function getSupportedPriceAssets() {
  return Object.entries(assetFeeds).map(([symbol, feed]) => ({
    symbol,
    label: feed.label,
  }));
}

function coingeckoFetchOptions(signal) {
  const headers = {};
  if (env.prices.coingeckoApiKey) {
    const keyHeader = env.prices.coingeckoApiTier === 'pro'
      ? 'x-cg-pro-api-key'
      : 'x-cg-demo-api-key';
    headers[keyHeader] = env.prices.coingeckoApiKey;
  }

  return {
    signal,
    ...(Object.keys(headers).length ? { headers } : {}),
  };
}

export async function getUsdPriceForAsset(asset) {
  const symbol = normalizeAsset(asset);
  const feed = assetFeeds[symbol];

  if (!feed) {
    throw new PriceFeedError(`No live price feed is configured for ${asset}.`, 422);
  }

  const cached = priceCache.get(symbol);
  if (cached && Date.now() - cached.cachedAt < env.prices.cacheMs) {
    return cached.value;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), env.prices.timeoutMs);
  const url = new URL('/api/v3/simple/price', env.prices.coingeckoBaseUrl);
  url.searchParams.set('ids', feed.id);
  url.searchParams.set('vs_currencies', 'usd');
  url.searchParams.set('include_last_updated_at', 'true');
  url.searchParams.set('include_24hr_change', 'true');
  url.searchParams.set('precision', 'full');

  try {
    const apiResponse = await fetch(url, coingeckoFetchOptions(controller.signal));
    const data = await apiResponse.json().catch(() => null);

    if (!apiResponse.ok) {
      throw new PriceFeedError(data?.error || 'Price provider request failed.', apiResponse.status);
    }

    const record = data?.[feed.id];
    const price = Number(record?.usd);

    if (!Number.isFinite(price) || price <= 0) {
      throw new PriceFeedError(`Price provider did not return a usable USD price for ${feed.label}.`);
    }

    const value = {
      asset: feed.label,
      symbol,
      price,
      currency: 'USD',
      lastUpdatedAt: record?.last_updated_at ? Number(record.last_updated_at) * 1000 : null,
      change24h: Number.isFinite(Number(record?.usd_24h_change)) ? Number(record.usd_24h_change) : null,
      provider: 'CoinGecko',
    };

    priceCache.set(symbol, { cachedAt: Date.now(), value });
    return value;
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new PriceFeedError('Price request timed out.', 504);
    }

    if (error instanceof PriceFeedError) {
      throw error;
    }

    throw new PriceFeedError(error.message || 'Price request failed.');
  } finally {
    clearTimeout(timeout);
  }
}

function numberOrNull(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function normalizeMarketCoin(record) {
  return {
    id: String(record?.id || ''),
    symbol: String(record?.symbol || '').toUpperCase(),
    name: String(record?.name || ''),
    image: String(record?.image || ''),
    currentPrice: numberOrNull(record?.current_price),
    marketCap: numberOrNull(record?.market_cap),
    marketCapRank: numberOrNull(record?.market_cap_rank),
    totalVolume: numberOrNull(record?.total_volume),
    high24h: numberOrNull(record?.high_24h),
    low24h: numberOrNull(record?.low_24h),
    priceChange24h: numberOrNull(record?.price_change_24h),
    priceChangePercentage24h: numberOrNull(record?.price_change_percentage_24h),
    priceChangePercentage1h: numberOrNull(record?.price_change_percentage_1h_in_currency),
    priceChangePercentage7d: numberOrNull(record?.price_change_percentage_7d_in_currency),
    sparkline: Array.isArray(record?.sparkline_in_7d?.price)
      ? record.sparkline_in_7d.price.map(Number).filter(Number.isFinite)
      : [],
    lastUpdated: record?.last_updated || null,
  };
}

async function fetchMarkets(searchParams, signal) {
  const url = new URL('/api/v3/coins/markets', env.prices.coingeckoBaseUrl);
  Object.entries(searchParams).forEach(([key, value]) => {
    url.searchParams.set(key, String(value));
  });

  const apiResponse = await fetch(url, coingeckoFetchOptions(signal));
  const data = await apiResponse.json().catch(() => null);

  if (!apiResponse.ok) {
    throw new PriceFeedError(data?.error || 'Market provider request failed.', apiResponse.status);
  }

  if (!Array.isArray(data)) {
    throw new PriceFeedError('Market provider did not return a usable market list.');
  }

  return data;
}

export async function getPortfolioMarkets({ perPage = 150, page = 1 } = {}) {
  const safePerPage = Math.min(Math.max(Number(perPage) || 150, 101), 250);
  const safePage = Math.max(Number(page) || 1, 1);
  const cacheKey = `portfolio:${safePerPage}:${safePage}`;
  const cached = marketCache.get(cacheKey);

  if (cached && Date.now() - cached.cachedAt < env.prices.cacheMs) {
    return cached.value;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), env.prices.timeoutMs);

  try {
    const records = await fetchMarkets({
      vs_currency: 'usd',
      order: 'market_cap_desc',
      per_page: safePerPage,
      page: safePage,
      sparkline: 'true',
      price_change_percentage: '1h,24h,7d',
      precision: 'full',
    }, controller.signal);

    let coins = records.map(normalizeMarketCoin).filter((coin) => coin.id && coin.name && coin.symbol);

    if (!coins.some((coin) => coin.id === 'stellar')) {
      const stellarRecords = await fetchMarkets({
        vs_currency: 'usd',
        ids: 'stellar',
        sparkline: 'true',
        price_change_percentage: '1h,24h,7d',
        precision: 'full',
      }, controller.signal);
      coins = [...stellarRecords.map(normalizeMarketCoin), ...coins];
    }

    const stellarIndex = coins.findIndex((coin) => coin.id === 'stellar');
    if (stellarIndex > 0) {
      const [stellar] = coins.splice(stellarIndex, 1);
      coins.unshift(stellar);
    }

    const value = {
      provider: 'CoinGecko',
      currency: 'USD',
      count: coins.length,
      lastFetchedAt: Date.now(),
      coins,
    };

    marketCache.set(cacheKey, { cachedAt: Date.now(), value });
    return value;
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new PriceFeedError('Market request timed out.', 504);
    }

    if (error instanceof PriceFeedError) {
      throw error;
    }

    throw new PriceFeedError(error.message || 'Market request failed.');
  } finally {
    clearTimeout(timeout);
  }
}
