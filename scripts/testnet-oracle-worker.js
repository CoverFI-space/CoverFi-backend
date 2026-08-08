// Dedicated Testnet publisher entrypoint. Public deployment values are pinned
// here while publisher secrets continue to come from server/.env.
process.env.NODE_ENV = 'production';
process.env.STELLAR_NETWORK = 'testnet';
process.env.STELLAR_RPC_URL = 'https://soroban-testnet.stellar.org';
process.env.STELLAR_NETWORK_PASSPHRASE = 'Test SDF Network ; September 2015';
process.env.ENABLE_TESTNET_ORACLE_REFRESH = 'true';
process.env.ENABLE_MAINNET_QUORUM_ORACLE_PUBLISHING = 'false';
// CoinGecko is the only market-price source; the adapter still requires its
// two distinct authorized publisher accounts to attest the value.
// Legacy testnet override: process.env.CRYPTOCOMPARE_API_KEY = '';
process.env.ORACLE_ADAPTER_CONTRACT_ID = 'CBAEBBX6ZJGQDWJ4HW2OXJWVGVTQ2THCVFV3O4L3UK3VFDBYW656OV47';
process.env.ORACLE_REFRESH_ASSET_CONTRACT_ID = 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC';
process.env.ORACLE_REFRESH_INTERVAL_MS = process.env.TESTNET_ORACLE_REFRESH_INTERVAL_MS || '240000';

await import('./oracle-worker.js');
