import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { allocateAtomicSettlement } from './settlement.js';

interface Fixture {
  principalAtomic: string;
  bondAtomic: string;
  vectors: Array<{
    name: string;
    requesterBps: number;
    disputant: 'requester' | 'worker';
    requesterPrincipalAtomic: string;
    workerPrincipalAtomic: string;
    bondRefundAtomic: string;
    bondToCounterpartyAtomic: string;
    bondToRemovalAtomic: string;
  }>;
}

test('customer adapter economics match the Rust contract vectors exactly', () => {
  const fixture = JSON.parse(readFileSync(new URL(
    '../../../../contracts/near/SETTLEMENT_ECONOMICS_VECTORS.json',
    import.meta.url,
  ), 'utf8')) as Fixture;
  for (const vector of fixture.vectors) {
    assert.deepEqual(
      allocateAtomicSettlement({
        principalAtomic: fixture.principalAtomic,
        bondAtomic: fixture.bondAtomic,
        requesterBps: vector.requesterBps,
        disputant: vector.disputant,
      }),
      {
        requesterPrincipalAtomic: vector.requesterPrincipalAtomic,
        workerPrincipalAtomic: vector.workerPrincipalAtomic,
        bondRefundAtomic: vector.bondRefundAtomic,
        bondToCounterpartyAtomic: vector.bondToCounterpartyAtomic,
        bondToRemovalAtomic: vector.bondToRemovalAtomic,
      },
      vector.name,
    );
  }
});

test('customer adapter preserves full uint128 allocations and rejects larger values', () => {
  const maximum = ((1n << 128n) - 1n).toString();
  const allocation = allocateAtomicSettlement({
    principalAtomic: maximum,
    bondAtomic: maximum,
    requesterBps: 5_000,
    disputant: 'requester',
  });
  assert.equal(
    BigInt(allocation.requesterPrincipalAtomic) + BigInt(allocation.workerPrincipalAtomic),
    BigInt(maximum),
  );
  assert.equal(
    BigInt(allocation.bondRefundAtomic)
      + BigInt(allocation.bondToCounterpartyAtomic)
      + BigInt(allocation.bondToRemovalAtomic),
    BigInt(maximum),
  );
  assert.throws(
    () => allocateAtomicSettlement({
      principalAtomic: (1n << 128n).toString(),
      bondAtomic: '0',
      requesterBps: 5_000,
      disputant: 'requester',
    }),
    /exceeds the uint128 settlement limit/,
  );
});
