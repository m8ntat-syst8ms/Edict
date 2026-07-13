/**
 * The seven-line claim, verified: examples/quickstart.ts is counted (non-comment,
 * non-blank source lines <= 7) AND executed end-to-end against the compiled
 * SDK — create client → protect → deliver → dispute → verdict → settle.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

function countCodeLines(source: string): number {
  const noBlockComments = source.replace(/\/\*[\s\S]*?\*\//g, '');
  return noBlockComments
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('//')).length;
}

test('quickstart integrates Edict in <= 7 lines of code and runs end-to-end', async () => {
  const source = await readFile(new URL('../../examples/quickstart.ts', import.meta.url), 'utf8');
  const lines = countCodeLines(source);
  assert.ok(lines <= 7, `examples/quickstart.ts has ${lines} non-comment lines; the <=7-line claim broke`);

  const logged: unknown[][] = [];
  const original = console.log;
  console.log = (...args: unknown[]) => {
    logged.push(args);
  };
  try {
    await import('../examples/quickstart.js'); // executes the demo at import
  } finally {
    console.log = original;
  }
  assert.equal(logged.length, 1, 'quickstart should print exactly one verdict + settlement');
  assert.deepEqual(logged[0]![0], { kind: 'requester_wins' });
  const settlement = logged[0]![1] as { requesterPayoutUsd: number; bondRefundUsd: number };
  assert.equal(settlement.requesterPayoutUsd, 500);
  assert.equal(settlement.bondRefundUsd, 25);
});
