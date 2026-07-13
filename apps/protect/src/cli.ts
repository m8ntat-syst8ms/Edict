#!/usr/bin/env node
/**
 * `edict-protect` — start the Edict customer app on http://127.0.0.1:4880
 * (override with --port/-p, PORT; --data-dir; --dev-console-url). Pass
 * --runtime-url to switch from the local sandbox to the read-only production
 * Activity / Needs attention workspace.
 */

import type { AddressInfo } from 'node:net';
import { startProtectApp, type StartProtectAppOptions } from './server.js';

function parseArgs(argv: string[]): StartProtectAppOptions {
  const opts: StartProtectAppOptions = {};
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
    } else if (arg === '--dev-console-url') {
      opts.devConsoleUrl = argv[++i];
    } else if (arg === '--runtime-url') {
      opts.runtimeBaseUrl = argv[++i];
    } else if (arg === '--runtime-token') {
      opts.runtimeApiToken = argv[++i];
    } else if (arg === '--help' || arg === '-h') {
      console.log('usage: edict-protect [--port 4880] [--data-dir ~/.edict-protect] [--runtime-url http://127.0.0.1:4890] [--runtime-token TOKEN]');
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
  opts.runtimeBaseUrl ??= process.env.EDICT_RUNTIME_URL;
  opts.runtimeApiToken ??= process.env.EDICT_RUNTIME_API_TOKEN;
  return opts;
}

const server = await startProtectApp(parseArgs(process.argv.slice(2)));
const { port } = server.address() as AddressInfo;
console.log(`edict-protect listening on http://127.0.0.1:${port}`);
process.on('SIGINT', () => {
  server.close(() => process.exit(0));
});
