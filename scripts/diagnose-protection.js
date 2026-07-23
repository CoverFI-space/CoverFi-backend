import {
  Address,
  BASE_FEE,
  Contract,
  TransactionBuilder,
  nativeToScVal,
  rpc,
  scValToNative,
  xdr,
} from '@stellar/stellar-sdk';
import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const STROOPS_PER_UNIT = 10_000_000n;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
let env;

function normalize(value) {
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === 'object') {
    if (typeof value.toString === 'function' && value.constructor?.name === 'Address') {
      return value.toString();
    }
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, normalize(item)]),
    );
  }
  return value;
}

function amountToStroops(amount) {
  return BigInt(Math.round(Number(amount) * Number(STROOPS_PER_UNIT)));
}

function requiredConfig() {
  const missing = Object.entries({
    STELLAR_STATUS_SOURCE_ACCOUNT: env.contracts.statusSourceAccount,
    PROTECTION_ENGINE_CONTRACT_ID: env.contracts.protectionEngine,
    RESERVE_VAULT_CONTRACT_ID: env.contracts.reserveVault,
    XLM_TESTNET_CONTRACT_ID: env.contracts.xlmToken,
    CFTUSD_TESTNET_CONTRACT_ID: env.contracts.payoutToken,
  })
    .filter(([, value]) => !value)
    .map(([name]) => name);

  if (missing.length) {
    throw new Error(`Missing contract diagnostics config: ${missing.join(', ')}`);
  }
}

async function simulate({ server, source, contractId, method, args = [] }) {
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
  return result.result?.retval ? normalize(scValToNative(result.result.retval)) : null;
}

async function check(label, run) {
  try {
    const value = await run();
    return { label, ok: true, value };
  } catch (error) {
    return {
      label,
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function classify(results) {
  const quote = results.find((item) => item.label === 'engine.quote_position');
  const reservePool = results.find((item) => item.label === 'reserve.get_pool');
  const create = results.find((item) => item.label === 'engine.create_position preflight');

  if (!quote?.ok && quote?.error?.includes('MissingValue')) {
    return 'The configured protection engine does not expose the V2 quote_position ABI.';
  }

  if (!reservePool?.ok && reservePool?.error?.includes('MissingValue')) {
    return 'The configured reserve vault does not expose the V2 reserve read ABI.';
  }

  if (!create?.ok) {
    return 'The configured contracts reject new protection positions before wallet signing.';
  }

  return 'The configured protection contracts passed the basic V2 preflight.';
}

async function main() {
  dotenv.config({ path: path.resolve(__dirname, '..', '.env') });
  dotenv.config({ path: path.resolve(__dirname, '..', '..', 'logic-pages', '.env') });
  ({ env } = await import('../config/env.js'));

  requiredConfig();

  const server = new rpc.Server(env.contracts.rpcUrl, {
    allowHttp: env.contracts.rpcUrl.startsWith('http://'),
  });
  const source = await server.getAccount(env.contracts.statusSourceAccount);
  const protectedAsset = Address.fromString(env.contracts.xlmToken).toScVal();
  const payoutAsset = Address.fromString(env.contracts.payoutToken).toScVal();
  const amount = nativeToScVal(amountToStroops(process.env.PROTECTION_DIAG_AMOUNT || '12'), {
    type: 'i128',
  });
  const duration = nativeToScVal(604800n, { type: 'u64' });

  const results = await Promise.all([
    check('engine.get_config', () => simulate({
      server,
      source,
      contractId: env.contracts.protectionEngine,
      method: 'get_config',
    })),
    check('engine.quote_position', () => simulate({
      server,
      source,
      contractId: env.contracts.protectionEngine,
      method: 'quote_position',
      args: [protectedAsset, payoutAsset, amount, duration],
    })),
    check('engine.create_position preflight', () => simulate({
      server,
      source,
      contractId: env.contracts.protectionEngine,
      method: 'create_position',
      args: [
        Address.fromString(env.contracts.statusSourceAccount).toScVal(),
        protectedAsset,
        payoutAsset,
        amount,
        duration,
        xdr.ScVal.scvVoid(),
      ],
    })),
    check('reserve.get_pool', () => simulate({
      server,
      source,
      contractId: env.contracts.reserveVault,
      method: 'get_pool',
      args: [payoutAsset],
    })),
    check('reserve.get_projected_utilization_bps', () => simulate({
      server,
      source,
      contractId: env.contracts.reserveVault,
      method: 'get_projected_utilization_bps',
      args: [payoutAsset, amount],
    })),
    check('reserve.get_projected_concentration_bps', () => simulate({
      server,
      source,
      contractId: env.contracts.reserveVault,
      method: 'get_projected_concentration_bps',
      args: [protectedAsset, payoutAsset, amount],
    })),
  ]);

  const ok = results.every((item) => item.ok);
  console.log(JSON.stringify({
    ok,
    network: env.contracts.network,
    rpcUrl: env.contracts.rpcUrl,
    sourceAccount: env.contracts.statusSourceAccount,
    contracts: {
      protectionEngine: env.contracts.protectionEngine,
      reserveVault: env.contracts.reserveVault,
      oracleAdapter: env.contracts.oracleAdapter,
      protectedBalanceVault: env.contracts.protectedBalanceVault,
    },
    assets: {
      protectedAsset: env.contracts.xlmToken,
      payoutAsset: env.contracts.payoutToken,
    },
    results,
    conclusion: classify(results),
  }, null, 2));

  if (!ok) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(JSON.stringify({
    ok: false,
    message: error instanceof Error ? error.message : String(error),
  }, null, 2));
  process.exitCode = 1;
});
