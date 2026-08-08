import { Keypair } from '@stellar/stellar-sdk';
import { env } from '../config/env.js';
import { assertExpectedMainnetPublishers } from '../services/oracle-publisher.js';

function required(value, name) {
  const clean = String(value || '').trim();
  if (!clean) throw new Error(`${name} is missing.`);
  return clean;
}

try {
  if (env.contracts.network !== 'mainnet') throw new Error('STELLAR_NETWORK must be mainnet.');

  const secrets = [
    required(env.oracle.publisher1Secret, 'ORACLE_PUBLISHER_1_SECRET'),
    required(env.oracle.publisher2Secret, 'ORACLE_PUBLISHER_2_SECRET'),
    required(env.oracle.publisher3Secret, 'ORACLE_PUBLISHER_3_SECRET'),
  ];
  const expected = [
    required(env.oracle.publisher1PublicKey, 'ORACLE_PUBLISHER_1_PUBLIC_KEY'),
    required(env.oracle.publisher2PublicKey, 'ORACLE_PUBLISHER_2_PUBLIC_KEY'),
    required(env.oracle.publisher3PublicKey, 'ORACLE_PUBLISHER_3_PUBLIC_KEY'),
  ];
  const actual = secrets.map((secret, index) => {
    try {
      return Keypair.fromSecret(secret).publicKey();
    } catch {
      throw new Error(`ORACLE_PUBLISHER_${index + 1}_SECRET is not a valid Stellar secret seed.`);
    }
  });

  assertExpectedMainnetPublishers(actual, expected);
  // Legacy second-source requirement, disabled for the current
  // CoinGecko-only mode:
  // required(env.prices.coingeckoApiKey, 'COINGECKO_API_KEY');
  // required(env.prices.cryptoCompareApiKey, 'CRYPTOCOMPARE_API_KEY');
  required(env.oracle.quorumSourceContractId, 'QUORUM_ORACLE_SOURCE_CONTRACT_ID');
  required(env.contracts.oracleAdapter, 'ORACLE_ADAPTER_CONTRACT_ID');
  required(env.oracle.refreshAssetContractId, 'ORACLE_REFRESH_ASSET_CONTRACT_ID');

  console.log(JSON.stringify({
    ok: true,
    mode: 'validation-only',
    network: env.contracts.network,
    publishingEnabled: env.oracle.mainnetQuorumPublishingEnabled,
    publisherPublicKeys: actual,
    priceProvider: 'CoinGecko',
    // Legacy validation output: priceApiKeysConfigured: { coinGecko: true, cryptoCompare: true },
  }, null, 2));
} catch (error) {
  console.error(JSON.stringify({
    ok: false,
    mode: 'validation-only',
    message: error instanceof Error ? error.message : String(error),
  }, null, 2));
  process.exitCode = 1;
}
