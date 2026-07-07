import cors from 'cors';
import express from 'express';
import admin from 'firebase-admin';
import { env, isDeepSeekConfigured } from './config/env.js';
import { createDeepSeekReply } from './services/deepseek.js';
import { getPortfolioMarkets, getSupportedPriceAssets, getUsdPriceForAsset } from './services/prices.js';

const app = express();
const usernamePattern = /^[a-zA-Z0-9_]{3,24}$/;

let db;
let httpServer;

function isAllowedOrigin(origin) {
  if (!origin) {
    return true;
  }

  if (origin === env.server.clientOrigin) {
    return true;
  }

  try {
    const url = new URL(origin);
    const localHosts = new Set(['localhost', '127.0.0.1', '[::1]']);
    return localHosts.has(url.hostname) && ['5173', '4173'].includes(url.port);
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
app.use(express.json({ limit: '32kb' }));

app.use((request, _response, next) => {
  console.log(`[request] ${request.method} ${request.originalUrl}`);
  next();
});

function getServiceAccount() {
  if (!env.firebase.serviceAccountBase64) {
    throw new Error('FIREBASE_SERVICE_ACCOUNT_BASE64 is missing. Put the base64-encoded Firebase service account JSON in server/.env.');
  }

  const decoded = Buffer.from(env.firebase.serviceAccountBase64, 'base64').toString('utf8');
  return JSON.parse(decoded);
}

async function ensureFirebase() {
  if (db) {
    return db;
  }

  if (!admin.apps.length) {
    const serviceAccount = getServiceAccount();
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      projectId: env.firebase.projectId || serviceAccount.project_id,
    });
  }

  db = admin.firestore();
  console.log('Firebase Firestore connected.');
  return db;
}

async function getUsersCollection() {
  const firestore = await ensureFirebase();
  return firestore.collection('users');
}

async function getAccountsCollection() {
  const firestore = await ensureFirebase();
  return firestore.collection('accounts');
}

async function getChatsCollection() {
  const firestore = await ensureFirebase();
  return firestore.collection('chats');
}

function cleanUsername(value) {
  return String(value || '').trim();
}

function cleanWalletAddress(value) {
  return String(value || '').trim();
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

function serializeUser(user) {
  return {
    username: user.username,
    usernameLower: user.usernameLower,
    walletAddress: user.walletAddress,
    createdAt: toIsoTimestamp(user.createdAt),
    updatedAt: toIsoTimestamp(user.updatedAt),
  };
}

function serializeChat(chat) {
  return {
    id: chat.id,
    walletAddress: chat.walletAddress,
    mode: chat.mode || 'chat',
    model: chat.model || '',
    message: chat.message,
    reply: chat.reply,
    createdAt: toIsoTimestamp(chat.createdAt),
  };
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

function logApiError(context, error) {
  const detail = error instanceof Error ? error.stack || error.message : String(error);
  console.error(`[${context}]`, detail);
}

function sendApiError(response, status, message, error, context) {
  logApiError(context, error);
  response.status(status).json({ message });
}

function getFirebaseErrorMessage(error, fallback) {
  const message = error?.message || '';

  if (String(error?.code) === '7' || message.includes('PERMISSION_DENIED')) {
    if (message.includes('firestore.googleapis.com')) {
      return 'Firebase credentials loaded, but the Cloud Firestore API is disabled for this Firebase project. Enable Firestore API for project coverfi, then retry after a few minutes.';
    }

    return 'Firebase credentials loaded, but this service account does not have permission to read Firestore.';
  }

  if (String(error?.code) === '5' || message.includes('NOT_FOUND')) {
    return 'Firebase credentials loaded, but the Firestore database was not found for project coverfi. Open Firebase Console, create a Cloud Firestore database in Native mode, then retry.';
  }

  return fallback;
}

app.get('/api/health', async (_request, response) => {
  try {
    const users = await getUsersCollection();
    await users.limit(1).get();
    response.json({ ok: true, aiConfigured: isDeepSeekConfigured() });
  } catch (error) {
    sendApiError(response, 500, getFirebaseErrorMessage(error, error.message || 'Database is not ready.'), error, 'health');
  }
});

app.post('/api/auth/register', async (request, response) => {
  try {
    const username = cleanUsername(request.body?.username);
    const walletAddress = cleanWalletAddress(request.body?.walletAddress);
    const usernameLower = username.toLowerCase();

    if (!usernamePattern.test(username)) {
      return response.status(400).json({ message: 'Use 3-24 letters, numbers, or underscores.' });
    }

    if (!walletAddress) {
      return response.status(400).json({ message: 'Wallet address is required.' });
    }

    const firestore = await ensureFirebase();
    const users = firestore.collection('users');
    const userRef = users.doc(usernameLower);

    const result = await firestore.runTransaction(async (transaction) => {
      const usernameDoc = await transaction.get(userRef);
      const walletSnapshot = await transaction.get(
        users.where('walletAddress', '==', walletAddress).limit(1),
      );

      if (!walletSnapshot.empty) {
        const existingWallet = walletSnapshot.docs[0].data();
        if (existingWallet.usernameLower !== usernameLower) {
          const error = new Error(`This wallet is already registered as ${existingWallet.username}.`);
          error.statusCode = 409;
          throw error;
        }

        return {
          status: 200,
          user: existingWallet,
        };
      }

      if (usernameDoc.exists) {
        const existingUsername = usernameDoc.data();
        if (existingUsername.walletAddress !== walletAddress) {
          const error = new Error('That username is already taken. Please choose another one.');
          error.statusCode = 409;
          throw error;
        }

        return {
          status: 200,
          user: existingUsername,
        };
      }

      const user = {
        username,
        usernameLower,
        walletAddress,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      };

      transaction.set(userRef, user);

      return {
        status: 201,
        user: {
          ...user,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      };
    });

    return response.status(result.status).json(serializeUser(result.user));
  } catch (error) {
    if (error?.statusCode) {
      return response.status(error.statusCode).json({ message: error.message });
    }

    return sendApiError(response, 500, getFirebaseErrorMessage(error, error.message || 'Could not save user.'), error, 'auth/register');
  }
});

app.get('/api/users/:username', async (request, response) => {
  try {
    const usernameLower = cleanUsername(request.params.username).toLowerCase();

    if (!usernamePattern.test(usernameLower)) {
      return response.status(400).json({ message: 'Enter a valid username.' });
    }

    const users = await getUsersCollection();
    const userDoc = await users.doc(usernameLower).get();
    const user = userDoc.exists ? userDoc.data() : null;

    if (!user) {
      return response.status(404).json({ message: 'No user found with that username.' });
    }

    return response.json(serializeUser(user));
  } catch (error) {
    return sendApiError(response, 500, getFirebaseErrorMessage(error, error.message || 'Could not look up username.'), error, 'users/:username');
  }
});

app.get('/api/wallets/:walletAddress', async (request, response) => {
  try {
    const walletAddress = cleanWalletAddress(request.params.walletAddress);

    if (!walletAddress) {
      return response.status(400).json({ message: 'Wallet address is required.' });
    }

    const users = await getUsersCollection();
    const walletSnapshot = await users.where('walletAddress', '==', walletAddress).limit(1).get();
    const user = walletSnapshot.empty ? null : walletSnapshot.docs[0].data();

    if (!user) {
      return response.status(404).json({ message: 'No username is registered for this wallet yet.' });
    }

    return response.json(serializeUser(user));
  } catch (error) {
    return sendApiError(response, 500, getFirebaseErrorMessage(error, error.message || 'Could not look up wallet.'), error, 'wallets/:walletAddress');
  }
});

app.get('/api/account/:walletAddress', async (request, response) => {
  try {
    const walletAddress = cleanWalletAddress(request.params.walletAddress);

    if (!walletAddress) {
      return response.status(400).json({ message: 'Wallet address is required.' });
    }

    const accounts = await getAccountsCollection();
    const accountDoc = await accounts.doc(walletAddress).get();
    const account = accountDoc.exists ? accountDoc.data() : null;

    if (!account) {
      return response.json({ profile: null, data: null, network: 'testnet' });
    }

    return response.json({
      walletAddress: account.walletAddress,
      profile: account.profile || null,
      data: account.data || null,
      network: account.network || 'testnet',
    });
  } catch (error) {
    return sendApiError(response, 500, getFirebaseErrorMessage(error, error.message || 'Could not load account data.'), error, 'account/get');
  }
});

app.put('/api/account/:walletAddress', async (request, response) => {
  try {
    const walletAddress = cleanWalletAddress(request.params.walletAddress);

    if (!walletAddress) {
      return response.status(400).json({ message: 'Wallet address is required.' });
    }

    const profile = request.body?.profile || null;
    const data = request.body?.data || null;
    const network = request.body?.network === 'mainnet' ? 'mainnet' : 'testnet';
    const firestore = await ensureFirebase();
    const accountRef = firestore.collection('accounts').doc(walletAddress);

    const saved = await firestore.runTransaction(async (transaction) => {
      const currentDoc = await transaction.get(accountRef);
      const now = admin.firestore.FieldValue.serverTimestamp();
      const next = {
        walletAddress,
        profile,
        data,
        network,
        updatedAt: now,
        ...(currentDoc.exists ? {} : { createdAt: now }),
      };

      transaction.set(accountRef, next, { merge: true });

      return {
        ...(currentDoc.exists ? currentDoc.data() : {}),
        ...next,
      };
    });

    return response.json({
      walletAddress: saved?.walletAddress || walletAddress,
      profile: saved?.profile || null,
      data: saved?.data || null,
      network: saved?.network || network,
    });
  } catch (error) {
    return sendApiError(response, 500, getFirebaseErrorMessage(error, error.message || 'Could not save account data.'), error, 'account/put');
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

    if (!walletAddress) {
      return response.status(400).json({ message: 'Wallet address is required.' });
    }

    const chats = await getChatsCollection();
    const snapshot = await chats
      .where('walletAddress', '==', walletAddress)
      .get();

    const messages = snapshot.docs
      .map((doc) => serializeChat({ id: doc.id, ...doc.data() }))
      .sort((left, right) => {
        const leftTime = left.createdAt ? new Date(left.createdAt).getTime() : 0;
        const rightTime = right.createdAt ? new Date(right.createdAt).getTime() : 0;
        return leftTime - rightTime;
      })
      .slice(-25);

    return response.json({ messages });
  } catch (error) {
    return sendApiError(response, 500, getFirebaseErrorMessage(error, error.message || 'Could not load chat history.'), error, 'ai/chat/get');
  }
});

app.post('/api/ai/chat', async (request, response) => {
  try {
    const message = String(request.body?.message || '').trim();
    const walletAddress = cleanWalletAddress(request.body?.walletAddress || '');
    const mode = request.body?.mode === 'research' ? 'research' : 'chat';
    const model = String(request.body?.model || '').trim();
    const accountContext = request.body?.accountContext || null;

    if (!message) {
      return response.status(400).json({ message: 'Message is required.' });
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

    const reply = await createDeepSeekReply(message, {
      mode,
      model,
      accountContext,
      marketContext,
    });

    if (walletAddress) {
      const chats = await getChatsCollection();
      await chats.add({
        walletAddress,
        mode,
        model,
        message,
        reply,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    }

    return response.json({ reply, mode, model, marketContext });
  } catch (error) {
    return response.status(error.statusCode || 500).json({
      message: getFirebaseErrorMessage(error, error.message || 'AI chat failed.'),
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

httpServer = app.listen(env.server.port, env.server.host, async () => {
  console.log(`Auth API listening on http://${env.server.host}:${env.server.port}`);
  console.log(`DeepSeek AI ${isDeepSeekConfigured() ? 'configured' : 'not configured'}.`);

  try {
    await ensureFirebase();
    console.log('Firebase Firestore connected successfully at startup.');
  } catch (error) {
    console.error('Firebase Firestore connection failed at startup:', error.message || error);
  }
});

httpServer.on('close', () => {
  console.log('Auth API server closed.');
});

httpServer.on('error', (error) => {
  console.error('Auth API server error:', error);
  process.exit(1);
});
