/**
 * edict-node entrypoint. Boot order:
 *   1. load env config (mode is explicit — 'dstack' or 'dev'; no guessing)
 *   2. resolve the signing identity (dstack GetKey in dstack mode; persisted
 *      local key in dev mode) — the ADDRESS is logged, the key never is
 *   3. serve
 */
import { loadConfig } from './config.js';
import { DstackClient } from './dstack.js';
import { resolveIdentity } from './identity.js';
import { createNodeServer, depsFromConfig } from './server.js';

async function main(): Promise<void> {
  const config = loadConfig(process.env);
  const dstack = config.mode === 'dstack' ? new DstackClient(config.dstackSocket) : undefined;
  const identity = await resolveIdentity(config, dstack);

  console.log(`[edict-node] mode=${config.mode}${config.mode === 'dev' ? ' (MOCK ATTESTATION — not a TEE)' : ''}`);
  console.log(`[edict-node] signing address: ${identity.address} (scheme ecdsa_secp256k1_eth)`);
  console.log(`[edict-node] local model server: ${config.localModelUrl}`);
  if (config.modelIdPin !== undefined) console.log(`[edict-node] pinned model id: ${config.modelIdPin}`);

  if (dstack !== undefined) {
    try {
      const info = await dstack.info();
      console.log(
        `[edict-node] dstack app_id=${String(info.app_id ?? '?')} instance_id=${String(info.instance_id ?? '?')} compose_hash=${String(info.compose_hash ?? '?')}`,
      );
    } catch (err) {
      console.warn(`[edict-node] dstack Info unavailable: ${(err as Error).message}`);
    }
  }

  const server = createNodeServer(depsFromConfig(config, identity, dstack));
  server.listen(config.port, config.host, () => {
    console.log(`[edict-node] listening on http://${config.host}:${config.port}`);
  });

  const shutdown = (signal: string): void => {
    console.log(`[edict-node] ${signal} — shutting down`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err) => {
  console.error(`[edict-node] fatal: ${(err as Error).message}`);
  process.exit(1);
});
