import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';
import { env } from '../config/env.js';
import { getUsdPriceForAsset } from '../services/prices.js';

const execFileAsync = promisify(execFile);
const PRICE_SCALE = 100_000_000;

function optional(name, fallback = '') {
  return String(process.env[name] || fallback).trim();
}

function requiredContract(name, value) {
  const clean = String(value || '').trim();
  if (!clean) {
    throw new Error(`${name} is required.`);
  }
  return clean;
}

async function runStellar(args) {
  try {
    const { stdout, stderr } = await execFileAsync('stellar', args, {
      windowsHide: true,
      maxBuffer: 1024 * 1024 * 4,
    });
    return `${stdout || ''}${stderr || ''}`.trim();
  } catch (error) {
    const output = `${error.stdout || ''}${error.stderr || ''}`.trim();
    throw new Error(output || error.message || 'stellar CLI command failed.');
  }
}

async function getIdentityAddress(identity) {
  return runStellar(['keys', 'address', identity]);
}

async function submitFallbackObservation({
  oracleAdapter,
  network,
  sourceIdentity,
  publisherAddress,
  assetContractId,
  scaledPrice,
  timestamp,
}) {
  return runStellar([
    'contract',
    'invoke',
    '--id',
    oracleAdapter,
    '--source',
    sourceIdentity,
    '--network',
    network,
    '--',
    'submit_fallback',
    '--publisher',
    publisherAddress,
    '--asset',
    assetContractId,
    '--price',
    scaledPrice,
    '--timestamp',
    timestamp,
  ]);
}

export async function refreshOracle() {
  const oracleAdapter = requiredContract('ORACLE_ADAPTER_CONTRACT_ID', env.contracts.oracleAdapter);
  const assetLabel = optional('ORACLE_REFRESH_ASSET', 'XLM Stellar');
  const assetContractId = requiredContract(
    'ORACLE_REFRESH_ASSET_CONTRACT_ID',
    optional('ORACLE_REFRESH_ASSET_CONTRACT_ID', env.contracts.xlmToken),
  );
  const network = optional('ORACLE_REFRESH_NETWORK', env.contracts.network || 'testnet');
  const publisher1Identity = optional('ORACLE_FALLBACK_PUBLISHER1_IDENTITY', 'admin1');
  const publisher2Identity = optional('ORACLE_FALLBACK_PUBLISHER2_IDENTITY', 'admin2');
  const publisher1Address = optional(
    'ORACLE_FALLBACK_PUBLISHER1_ADDRESS',
    await getIdentityAddress(publisher1Identity),
  );
  const publisher2Address = optional(
    'ORACLE_FALLBACK_PUBLISHER2_ADDRESS',
    await getIdentityAddress(publisher2Identity),
  );

  const price = await getUsdPriceForAsset(assetLabel);
  const scaledPrice = String(Math.round(Number(price.price) * PRICE_SCALE));
  const timestamp = optional(
    'ORACLE_REFRESH_TIMESTAMP',
    String(Math.floor(Date.now() / 1000)),
  );

  if (!Number.isFinite(Number(scaledPrice)) || BigInt(scaledPrice) <= 0n) {
    throw new Error(`Invalid scaled oracle price for ${assetLabel}.`);
  }

  const firstSubmission = await submitFallbackObservation({
    oracleAdapter,
    network,
    sourceIdentity: publisher1Identity,
    publisherAddress: publisher1Address,
    assetContractId,
    scaledPrice,
    timestamp,
  });
  const secondSubmission = await submitFallbackObservation({
    oracleAdapter,
    network,
    sourceIdentity: publisher2Identity,
    publisherAddress: publisher2Address,
    assetContractId,
    scaledPrice,
    timestamp,
  });

  const result = {
    ok: true,
    mode: 'fallback-quorum',
    network,
    oracleAdapter,
    asset: assetLabel,
    assetContractId,
    priceUsd: price.price,
    scaledPrice,
    provider: price.provider,
    lastUpdatedAt: price.lastUpdatedAt,
    timestamp,
    publishers: [
      { identity: publisher1Identity, address: publisher1Address },
      { identity: publisher2Identity, address: publisher2Address },
    ],
    submissions: [firstSubmission, secondSubmission],
  };
  console.log(JSON.stringify(result, null, 2));
  return result;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  refreshOracle().catch((error) => {
    console.error(JSON.stringify({
      ok: false,
      message: error instanceof Error ? error.message : String(error),
    }, null, 2));
    process.exitCode = 1;
  });
}
