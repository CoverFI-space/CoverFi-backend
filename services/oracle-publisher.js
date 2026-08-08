import {
  Address,
  BASE_FEE,
  Contract,
  Keypair,
  TransactionBuilder,
  nativeToScVal,
  rpc,
  scValToNative,
} from '@stellar/stellar-sdk';
import { env } from '../config/env.js';
import { getUsdPriceForAsset } from './prices.js';
// Legacy multi-provider import, intentionally disabled for the temporary
// CoinGecko-only flow:
// import { getCoinbaseUsdPrice, getCryptoCompareUsdPrice, getUsdPriceForAsset } from './prices.js';

const PRICE_SCALE = 100_000_000;
const TESTNET_PASSPHRASE = 'Test SDF Network ; September 2015';

function required(value, label) {
  const clean = String(value || '').trim();
  if (!clean) throw new Error(`${label} is required for the testnet oracle worker.`);
  return clean;
}

function networkPassphrase() {
  if (env.contracts.network !== 'testnet') {
    throw new Error('Automatic fallback publishing is testnet-only. Mainnet requires a separately reviewed oracle operation.');
  }
  return env.contracts.networkPassphrase || TESTNET_PASSPHRASE;
}

function mainnetPassphrase() {
  if (env.contracts.network !== 'mainnet') {
    throw new Error('The quorum oracle worker is Mainnet-only.');
  }
  if (!env.oracle.mainnetQuorumPublishingEnabled) {
    throw new Error('ENABLE_MAINNET_QUORUM_ORACLE_PUBLISHING must be true before the Mainnet oracle worker can publish.');
  }
  return env.contracts.networkPassphrase || 'Public Global Stellar Network ; September 2015';
}

function oracleAssetSymbol(asset) {
  const symbol = String(asset || '').trim().split(/\s+/)[0].toUpperCase();
  if (!/^[A-Z0-9_]{1,32}$/.test(symbol)) throw new Error('ORACLE_REFRESH_ASSET must begin with a valid contract symbol.');
  return symbol;
}

function assertFreshSource(source) {
  const age = source.lastUpdatedAt ? Date.now() - Number(source.lastUpdatedAt) : 0;
  if (age > env.oracle.maxPriceSourceAgeMs) {
    throw new Error(`${source.provider} observation is too old (${age}ms).`);
  }
}

/* Legacy multi-source quorum helpers, retained for later restoration.
function pairDeviationBps(left, right) {
  const low = Math.min(left, right);
  const high = Math.max(left, right);
  return low > 0 ? ((high - low) / low) * 10_000 : Number.POSITIVE_INFINITY;
}

function findQuorumPair(sources) {
  let best = null;
  for (let left = 0; left < sources.length; left += 1) {
    for (let right = left + 1; right < sources.length; right += 1) {
      const deviationBps = pairDeviationBps(sources[left].price, sources[right].price);
      if (!best || deviationBps < best.deviationBps) best = { left: sources[left], right: sources[right], deviationBps };
    }
  }
  if (!best || best.deviationBps > env.oracle.maxSourceDeviationBps) {
    throw new Error(`No two oracle sources agree within ${env.oracle.maxSourceDeviationBps} bps; nothing was published.`);
  }
  return best;
}
*/

export function assertExpectedMainnetPublishers(actual, expected) {
  if (!Array.isArray(actual) || !Array.isArray(expected) || actual.length !== 3 || expected.length !== 3) {
    throw new Error('Exactly three Mainnet oracle publisher addresses are required.');
  }
  if (new Set(actual).size !== actual.length || new Set(expected).size !== expected.length) {
    throw new Error('Mainnet oracle publisher addresses must be distinct.');
  }
  actual.forEach((address, index) => {
    if (address !== expected[index]) {
      throw new Error(`ORACLE_PUBLISHER_${index + 1}_SECRET does not match ORACLE_PUBLISHER_${index + 1}_PUBLIC_KEY.`);
    }
  });
}

function publishOperation(contract, publisher, assetContractId, scaledPrice, timestamp) {
  return contract.call(
    'submit_fallback',
    Address.fromString(publisher.publicKey()).toScVal(),
    Address.fromString(assetContractId).toScVal(),
    nativeToScVal(BigInt(scaledPrice), { type: 'i128' }),
    nativeToScVal(BigInt(timestamp), { type: 'u64' }),
  );
}

function quorumPublishOperation(contract, publisher, assetSymbol, scaledPrice, timestamp) {
  return contract.call(
    'submit',
    Address.fromString(publisher.publicKey()).toScVal(),
    nativeToScVal(assetSymbol, { type: 'symbol' }),
    nativeToScVal(BigInt(scaledPrice), { type: 'i128' }),
    nativeToScVal(BigInt(timestamp), { type: 'u64' }),
  );
}

function refreshFromQuorumOperation(contract, caller, assetContractId) {
  return contract.call(
    'refresh',
    Address.fromString(caller.publicKey()).toScVal(),
    Address.fromString(assetContractId).toScVal(),
  );
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitForSuccessfulTransaction(server, hash, label, sourceAccount, sourceAccountSequence) {
  // Mainnet RPC can continue to return NOT_FOUND after a transaction has
  // already landed in a ledger. Horizon is the canonical transaction-history
  // API and has proved available from the worker, so use it for confirmation.
  //
  // Some RPC responses have supplied a hash that Horizon does not resolve
  // immediately even though the publisher's transaction has already reached
  // a ledger. The publisher accounts are dedicated to this worker, so the
  // exact source-account sequence is a safe, independent confirmation key.
  // This avoids treating a successfully submitted price update as a failure.
  const horizon = env.contracts.network === 'mainnet'
    ? 'https://horizon.stellar.org'
    : 'https://horizon-testnet.stellar.org';
  let lastStatus = 'NOT_FOUND';
  let lastError = null;
  for (let attempt = 0; attempt < 90; attempt += 1) {
    try {
      const response = await fetch(`${horizon}/transactions/${hash}`);
      if (response.status === 404) {
        lastStatus = 'NOT_FOUND';
      } else if (!response.ok) {
        lastStatus = `HORIZON_${response.status}`;
      } else {
        const transaction = await response.json();
        if (transaction.successful === true) return transaction;
        lastStatus = 'FAILED';
        throw new Error(`${label} failed on-chain.`);
      }

      // Fall back to the source account's recent transaction history. This
      // retains the hash lookup above and only accepts the precise sequence
      // number allocated to this submitted transaction.
      if (sourceAccount && sourceAccountSequence) {
        const historyResponse = await fetch(`${horizon}/accounts/${sourceAccount}/transactions?order=desc&limit=5`);
        if (historyResponse.ok) {
          const history = await historyResponse.json();
          const transaction = history?._embedded?.records?.find((record) => (
            record.hash === hash || String(record.source_account_sequence) === String(sourceAccountSequence)
          ));
          if (transaction?.successful === true) return transaction;
          if (transaction && transaction.successful === false) {
            lastStatus = 'FAILED';
            throw new Error(`${label} failed on-chain.`);
          }
        } else {
          lastStatus = `HORIZON_ACCOUNT_${historyResponse.status}`;
        }
      }
    } catch (error) {
      if (lastStatus === 'FAILED') throw error;
      lastError = error;
    }
    await sleep(1000);
  }
  const detail = lastError instanceof Error ? ` (${lastError.message})` : '';
  throw new Error(`${label} did not confirm within 90 seconds: ${lastStatus}${detail}`);
}

async function submitObservation(server, contract, publisher, passphrase, assetContractId, scaledPrice, timestamp) {
  const account = await server.getAccount(publisher.publicKey());
  const sourceAccountSequence = (BigInt(account.sequence) + 1n).toString();
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: passphrase,
  })
    .addOperation(publishOperation(contract, publisher, assetContractId, scaledPrice, timestamp))
    .setTimeout(60)
    .build();
  const prepared = await server.prepareTransaction(transaction);
  prepared.sign(publisher);
  const sent = await server.sendTransaction(prepared);
  if (sent.status !== 'PENDING') {
    throw new Error(`Oracle publisher transaction was rejected before confirmation: ${sent.status}`);
  }
  await waitForSuccessfulTransaction(server, sent.hash, 'Oracle publisher transaction', publisher.publicKey(), sourceAccountSequence);
  return sent.hash;
}

async function submitQuorumObservation(server, contract, publisher, passphrase, assetSymbol, scaledPrice, timestamp) {
  const account = await server.getAccount(publisher.publicKey());
  const sourceAccountSequence = (BigInt(account.sequence) + 1n).toString();
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: passphrase,
  })
    .addOperation(quorumPublishOperation(contract, publisher, assetSymbol, scaledPrice, timestamp))
    .setTimeout(60)
    .build();
  const prepared = await server.prepareTransaction(transaction);
  prepared.sign(publisher);
  const sent = await server.sendTransaction(prepared);
  if (sent.status !== 'PENDING') throw new Error(`Quorum publisher transaction was rejected before confirmation: ${sent.status}`);
  await waitForSuccessfulTransaction(server, sent.hash, 'Quorum publisher transaction', publisher.publicKey(), sourceAccountSequence);
  return sent.hash;
}

async function refreshFromQuorum(server, adapter, publisher, passphrase, assetContractId) {
  const account = await server.getAccount(publisher.publicKey());
  const sourceAccountSequence = (BigInt(account.sequence) + 1n).toString();
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: passphrase,
  })
    .addOperation(refreshFromQuorumOperation(adapter, publisher, assetContractId))
    .setTimeout(60)
    .build();
  const prepared = await server.prepareTransaction(transaction);
  prepared.sign(publisher);
  const sent = await server.sendTransaction(prepared);
  if (sent.status !== 'PENDING') throw new Error(`Oracle refresh transaction was rejected before confirmation: ${sent.status}`);
  await waitForSuccessfulTransaction(server, sent.hash, 'Oracle refresh transaction', publisher.publicKey(), sourceAccountSequence);
  return sent.hash;
}

async function readFreshObservation(server, contract, sourceAddress, passphrase, assetContractId) {
  const account = await server.getAccount(sourceAddress);
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: passphrase,
  })
    .addOperation(contract.call('get_fresh_price', Address.fromString(assetContractId).toScVal()))
    .setTimeout(30)
    .build();
  const result = await server.simulateTransaction(transaction);
  if ('error' in result && result.error) throw new Error(`Oracle verification failed: ${result.error}`);
  const native = result.result?.retval ? scValToNative(result.result.retval) : null;
  if (!native || typeof native !== 'object') throw new Error('Oracle did not return a fresh observation after quorum publishing.');
  return native;
}

async function waitForFreshObservation(server, contract, sourceAddress, passphrase, assetContractId) {
  let lastError = null;
  // A successful adapter-refresh transaction can be visible to the ledger
  // before the RPC simulation observes its new storage footprint. Polling
  // prevents that ordinary propagation delay from failing an otherwise valid
  // publisher run.
  for (let attempt = 0; attempt < 18; attempt += 1) {
    try {
      return await readFreshObservation(server, contract, sourceAddress, passphrase, assetContractId);
    } catch (error) {
      lastError = error;
      await sleep(2_000);
    }
  }
  throw lastError || new Error('Oracle did not return a fresh observation after publishing.');
}

export async function publishFreshTestnetOracleObservation() {
  if (!env.oracle.automaticRefreshEnabled) {
    throw new Error('ENABLE_TESTNET_ORACLE_REFRESH must be true before the oracle worker can publish.');
  }
  const passphrase = networkPassphrase();
  const oracleAdapter = required(env.contracts.oracleAdapter, 'ORACLE_ADAPTER_CONTRACT_ID');
  const assetContractId = required(env.oracle.refreshAssetContractId || env.contracts.xlmToken, 'ORACLE_REFRESH_ASSET_CONTRACT_ID');
  const publisher1 = Keypair.fromSecret(required(env.oracle.publisher1Secret, 'ORACLE_PUBLISHER_1_SECRET'));
  const publisher2 = Keypair.fromSecret(required(env.oracle.publisher2Secret, 'ORACLE_PUBLISHER_2_SECRET'));
  if (publisher1.publicKey() === publisher2.publicKey()) throw new Error('Oracle publisher keys must be distinct.');

  // Temporary single-source mode: CoinGecko is the only market-price input.
  // The two authorized submitters are retained because the already-deployed
  // adapter requires their attestations; no contract interface is changed.
  const price = await getUsdPriceForAsset(env.oracle.refreshAsset);
  /* Legacy optional second-source validation, disabled:
  const coingecko = await getUsdPriceForAsset(env.oracle.refreshAsset);
  const sources = [coingecko];
  if (env.prices.cryptoCompareApiKey) {
    const cryptoCompare = await getCryptoCompareUsdPrice(env.oracle.refreshAsset);
    const low = Math.min(coingecko.price, cryptoCompare.price);
    const high = Math.max(coingecko.price, cryptoCompare.price);
    const deviationBps = ((high - low) / low) * 10_000;
    if (deviationBps > env.oracle.maxSourceDeviationBps) throw new Error(`Oracle sources disagree by ${Math.round(deviationBps)} bps; no observation was published.`);
    sources.push(cryptoCompare);
  }
  const price = sources.length === 2
    ? { ...coingecko, price: (sources[0].price + sources[1].price) / 2, provider: 'CoinGecko + CryptoCompare' }
    : coingecko;
  */
  const sourceAgeMs = price.lastUpdatedAt ? Date.now() - Number(price.lastUpdatedAt) : 0;
  if (sourceAgeMs > env.oracle.maxPriceSourceAgeMs) {
    throw new Error(`Price provider observation is too old (${sourceAgeMs}ms). No oracle update was published.`);
  }
  const scaledPrice = Math.round(Number(price.price) * PRICE_SCALE);
  if (!Number.isSafeInteger(scaledPrice) || scaledPrice <= 0) throw new Error('Price provider returned an invalid oracle price.');

  const timestamp = Math.floor(Date.now() / 1000);
  const server = new rpc.Server(env.contracts.rpcUrl, { allowHttp: false });
  const contract = new Contract(oracleAdapter);
  const firstTransactionHash = await submitObservation(server, contract, publisher1, passphrase, assetContractId, scaledPrice, timestamp);
  const secondTransactionHash = await submitObservation(server, contract, publisher2, passphrase, assetContractId, scaledPrice, timestamp);
  const observation = await waitForFreshObservation(server, contract, publisher1.publicKey(), passphrase, assetContractId);

  return {
    ok: true,
    network: env.contracts.network,
    asset: env.oracle.refreshAsset,
    assetContractId,
    oracleAdapter,
    priceUsd: price.price,
    scaledPrice: String(scaledPrice),
    source: price.provider,
    sources: [{ provider: price.provider, priceUsd: price.price, updatedAt: price.lastUpdatedAt }],
    sourceUpdatedAt: price.lastUpdatedAt,
    timestamp,
    publisherAddresses: [publisher1.publicKey(), publisher2.publicKey()],
    transactionHashes: [firstTransactionHash, secondTransactionHash],
    observation,
  };
}

export async function publishFreshMainnetQuorumOracleObservation() {
  const passphrase = mainnetPassphrase();
  const oracleAdapter = required(env.contracts.oracleAdapter, 'ORACLE_ADAPTER_CONTRACT_ID');
  const quorumSource = required(env.oracle.quorumSourceContractId, 'QUORUM_ORACLE_SOURCE_CONTRACT_ID');
  const assetContractId = required(env.oracle.refreshAssetContractId || env.contracts.xlmToken, 'ORACLE_REFRESH_ASSET_CONTRACT_ID');
  const publisher1 = Keypair.fromSecret(required(env.oracle.publisher1Secret, 'ORACLE_PUBLISHER_1_SECRET'));
  const publisher2 = Keypair.fromSecret(required(env.oracle.publisher2Secret, 'ORACLE_PUBLISHER_2_SECRET'));
  const publisher3 = Keypair.fromSecret(required(env.oracle.publisher3Secret, 'ORACLE_PUBLISHER_3_SECRET'));
  const publisherAddresses = [publisher1.publicKey(), publisher2.publicKey(), publisher3.publicKey()];
  const expectedPublisherAddresses = [
    required(env.oracle.publisher1PublicKey, 'ORACLE_PUBLISHER_1_PUBLIC_KEY'),
    required(env.oracle.publisher2PublicKey, 'ORACLE_PUBLISHER_2_PUBLIC_KEY'),
    required(env.oracle.publisher3PublicKey, 'ORACLE_PUBLISHER_3_PUBLIC_KEY'),
  ];
  assertExpectedMainnetPublishers(publisherAddresses, expectedPublisherAddresses);
  /* Legacy Mainnet source guards and aggregation, disabled:
  if (!env.prices.coingeckoApiKey) throw new Error('Mainnet requires a configured CoinGecko API key.');
  const singleSourceDemo = env.oracle.mainnetSingleSourceDemoEnabled;
  if (!singleSourceDemo && !env.prices.cryptoCompareApiKey) {
    throw new Error('Mainnet requires a CryptoCompare API key unless single-source demo mode is explicitly enabled.');
  }
  const sources = singleSourceDemo
    ? [await getUsdPriceForAsset(env.oracle.refreshAsset)]
    : await Promise.all([
      getUsdPriceForAsset(env.oracle.refreshAsset),
      getCryptoCompareUsdPrice(env.oracle.refreshAsset),
      getCoinbaseUsdPrice(env.oracle.refreshAsset),
    ]);
  const acceptedPair = singleSourceDemo ? null : findQuorumPair(sources);
  */
  // Temporary single-source mode: each existing authorized publisher attests
  // to one CoinGecko value. The on-chain quorum wiring remains unchanged.
  const sources = [await getUsdPriceForAsset(env.oracle.refreshAsset)];
  sources.forEach(assertFreshSource);
  const timestamp = Math.floor(Date.now() / 1000);
  const singleScaledPrice = Math.round(Number(sources[0].price) * PRICE_SCALE);
  if (!Number.isSafeInteger(singleScaledPrice) || singleScaledPrice <= 0) {
    throw new Error(`${sources[0].provider} returned an invalid oracle price.`);
  }
  const scaledPrices = [singleScaledPrice, singleScaledPrice, singleScaledPrice];

  const server = new rpc.Server(env.contracts.rpcUrl, { allowHttp: false });
  const sourceContract = new Contract(quorumSource);
  const adapterContract = new Contract(oracleAdapter);
  const assetSymbol = oracleAssetSymbol(env.oracle.refreshAsset);
  // Prepare each transaction only after the prior publisher has committed.
  // A later submit can discover a quorum and access Latest(asset), a ledger
  // key that was absent from a concurrently simulated footprint.
  const publisherTransactions = [];
  publisherTransactions.push(
    await submitQuorumObservation(server, sourceContract, publisher1, passphrase, assetSymbol, scaledPrices[0], timestamp),
  );
  publisherTransactions.push(
    await submitQuorumObservation(server, sourceContract, publisher2, passphrase, assetSymbol, scaledPrices[1], timestamp),
  );

  // The deployed quorum source reaches consensus with any two matching
  // publishers. Give the RPC a short ledger-propagation window before
  // simulating the adapter refresh, and use a separate publisher account as
  // its source so its sequence number is not the one just consumed above.
  await sleep(12_000);
  const refreshTransaction = await refreshFromQuorum(
    server,
    adapterContract,
    publisher3,
    passphrase,
    assetContractId,
  );
  const observation = await waitForFreshObservation(server, adapterContract, publisher1.publicKey(), passphrase, assetContractId);

  return {
    ok: true,
    network: 'mainnet',
    asset: env.oracle.refreshAsset,
    assetContractId,
    quorumSource,
    oracleAdapter,
    timestamp,
    mode: 'single-source',
    sources: sources.map((source) => ({ provider: source.provider, priceUsd: source.price, updatedAt: source.lastUpdatedAt })),
    acceptedQuorum: {
      providers: [sources[0].provider],
      deviationBps: 0,
    },
    publisherAddresses,
    publisherTransactions,
    refreshTransaction,
    observation,
  };
}
