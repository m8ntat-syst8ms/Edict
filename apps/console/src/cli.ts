#!/usr/bin/env node
/**
 * `edict-console` — start the policy console on http://127.0.0.1:4870
 * (override with --port/-p, PORT; --data-dir; --docket-dir).
 */

import type { AddressInfo } from 'node:net';
import { startConsole, type StartConsoleOptions } from './server.js';

function parseArgs(argv: string[]): StartConsoleOptions {
  const opts: StartConsoleOptions = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === '--port' || arg === '-p') {
      const port = Number(argv[++i]);
      if (!Number.isInteger(port) || port < 0 || port > 65_535) {
        console.error(`invalid --port ${argv[i]}`);
        process.exit(1);
      }
      opts.port = port;
    } else if (arg === '--data-dir') {
      opts.dataDir = argv[++i];
    } else if (arg === '--docket-dir') {
      opts.docketDir = argv[++i];
    } else if (arg === '--help' || arg === '-h') {
      console.log('usage: edict-console [--port 4870] [--data-dir ~/.edict-console] [--docket-dir <apps/shadow-docket>]');
      process.exit(0);
    } else {
      console.error(`unknown argument ${arg}`);
      process.exit(1);
    }
  }
  if (opts.port === undefined && process.env.PORT !== undefined) {
    const port = Number(process.env.PORT);
    if (Number.isInteger(port) && port >= 0 && port <= 65_535) opts.port = port;
  }
  return opts;
}

const server = await startConsole(parseArgs(process.argv.slice(2)));
const { port } = server.address() as AddressInfo;
console.log(`edict-console listening on http://127.0.0.1:${port}`);
process.on('SIGINT', () => {
  server.close(() => process.exit(0));
});
