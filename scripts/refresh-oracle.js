import { pathToFileURL } from 'node:url';
import { env } from '../config/env.js';
import { publishFreshMainnetQuorumOracleObservation, publishFreshTestnetOracleObservation } from '../services/oracle-publisher.js';

export function stringifyResult(value) {
  return JSON.stringify(value, (_key, entry) => (
    typeof entry === 'bigint' ? entry.toString() : entry
  ), 2);
}

export async function refreshOracle() {
  const result = env.contracts.network === 'mainnet'
    ? await publishFreshMainnetQuorumOracleObservation()
    : await publishFreshTestnetOracleObservation();
  console.log(stringifyResult(result));
  return result;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  refreshOracle().catch((error) => {
    console.error(stringifyResult({
      ok: false,
      message: error instanceof Error ? error.message : String(error),
    }));
    process.exitCode = 1;
  });
}
