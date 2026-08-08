import test from 'node:test';
import assert from 'node:assert/strict';

process.env.NODE_ENV = 'test';

const { assertExpectedMainnetPublishers } = await import('../services/oracle-publisher.js');
const { stringifyResult } = await import('../scripts/refresh-oracle.js');

const expected = [
  'GCHYTMJJN3Y6QX6YEICHOJVKMPY27OM2PXYOZ3I5LQSNMLJKNHWWCIBC',
  'GDCHN6PCMEYNO6BE3IJUSIFJIBDHTZKQHNTYAA45BGTBYQFMJR2X56GP',
  'GC54PCUSQDIWAFOLPPGCTCNO7KIVYGTUR7TNZT6IQCMSFAOAAF5IXS5C',
];

test('accepts the three configured Mainnet publishers in role order', () => {
  assert.doesNotThrow(() => assertExpectedMainnetPublishers(expected, expected));
});

test('rejects a secret whose public address belongs to the wrong publisher role', () => {
  assert.throws(
    () => assertExpectedMainnetPublishers([expected[1], expected[0], expected[2]], expected),
    /ORACLE_PUBLISHER_1_SECRET does not match/,
  );
});

test('rejects duplicate publisher addresses', () => {
  assert.throws(
    () => assertExpectedMainnetPublishers([expected[0], expected[0], expected[2]], expected),
    /must be distinct/,
  );
});

test('serializes Soroban bigint results for worker logs', () => {
  assert.equal(stringifyResult({ price: 17833456n }), '{\n  "price": "17833456"\n}');
});
