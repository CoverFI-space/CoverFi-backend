import cors from 'cors';
import express from 'express';
import { MongoClient } from 'mongodb';
import { env, isDeepSeekConfigured } from './config/env.js';
import { createDeepSeekReply } from './services/deepseek.js';
import { getPortfolioMarkets, getSupportedPriceAssets, getUsdPriceForAsset } from './services/prices.js';

const app = express();
const usernamePattern = /^[a-zA-Z0-9_]{3,24}$/;

let client;
let usersCollection;
let httpServer;

app.use(cors({ origin: env.server.clientOrigin }));
app.use(express.json({ limit: '32kb' }));

async function getUsersCollection() {
  if (!env.mongo.uri) {
    throw new Error('MONGODB_URI is missing. Add it to .env before starting the server.');
  }

  if (usersCollection) {
    return usersCollection;
  }

  client = new MongoClient(env.mongo.uri);
  await client.connect();

  const db = client.db(env.mongo.databaseName);
  usersCollection = db.collection('users');
  await usersCollection.createIndex({ usernameLower: 1 }, { unique: true });
  await usersCollection.createIndex({ walletAddress: 1 }, { unique: true });

  return usersCollection;
}

function cleanUsername(value) {
  return String(value || '').trim();
}

function cleanWalletAddress(value) {
  return String(value || '').trim();
}

app.get('/api/health', async (_request, response) => {
  try {
    await getUsersCollection();
    response.json({ ok: true, aiConfigured: isDeepSeekConfigured() });
  } catch (error) {
    response.status(500).json({ message: error.message || 'Database is not ready.' });
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

    const users = await getUsersCollection();
    const existingWallet = await users.findOne({ walletAddress });

    if (existingWallet) {
      if (existingWallet.usernameLower !== usernameLower) {
        return response.status(409).json({ message: `This wallet is already registered as ${existingWallet.username}.` });
      }

      return response.json({
        username: existingWallet.username,
        walletAddress: existingWallet.walletAddress,
      });
    }

    const now = new Date();

    await users.insertOne({
      username,
      usernameLower,
      walletAddress,
      createdAt: now,
      updatedAt: now,
    });

    return response.status(201).json({ username, walletAddress });
  } catch (error) {
    if (error?.code === 11000) {
      return response.status(409).json({ message: 'That username is already taken. Please choose another one.' });
    }

    return response.status(500).json({ message: error.message || 'Could not save user.' });
  }
});

app.get('/api/users/:username', async (request, response) => {
  try {
    const usernameLower = cleanUsername(request.params.username).toLowerCase();

    if (!usernamePattern.test(usernameLower)) {
      return response.status(400).json({ message: 'Enter a valid username.' });
    }

    const users = await getUsersCollection();
    const user = await users.findOne(
      { usernameLower },
      { projection: { _id: 0, username: 1, walletAddress: 1 } },
    );

    if (!user) {
      return response.status(404).json({ message: 'No user found with that username.' });
    }

    return response.json(user);
  } catch (error) {
    return response.status(500).json({ message: error.message || 'Could not look up username.' });
  }
});

app.get('/api/wallets/:walletAddress', async (request, response) => {
  try {
    const walletAddress = cleanWalletAddress(request.params.walletAddress);

    if (!walletAddress) {
      return response.status(400).json({ message: 'Wallet address is required.' });
    }

    const users = await getUsersCollection();
    const user = await users.findOne(
      { walletAddress },
      { projection: { _id: 0, username: 1, walletAddress: 1 } },
    );

    if (!user) {
      return response.status(404).json({ message: 'No username is registered for this wallet yet.' });
    }

    return response.json(user);
  } catch (error) {
    return response.status(500).json({ message: error.message || 'Could not look up wallet.' });
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

app.post('/api/ai/chat', async (request, response) => {
  try {
    const message = String(request.body?.message || '').trim();

    if (!message) {
      return response.status(400).json({ message: 'Message is required.' });
    }

    const reply = await createDeepSeekReply(message);
    return response.json({ reply });
  } catch (error) {
    return response.status(error.statusCode || 500).json({ message: error.message || 'AI chat failed.' });
  }
});

async function shutdown(signal) {
  console.log(`Received ${signal}. Closing Auth API...`);
  httpServer?.close();
  await client?.close();
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

httpServer = app.listen(env.server.port, env.server.host, () => {
  console.log(`Auth API listening on http://${env.server.host}:${env.server.port}`);
  console.log(`DeepSeek AI ${isDeepSeekConfigured() ? 'configured' : 'not configured'}.`);
});

httpServer.on('close', () => {
  console.log('Auth API server closed.');
});

httpServer.on('error', (error) => {
  console.error('Auth API server error:', error);
  process.exit(1);
});
