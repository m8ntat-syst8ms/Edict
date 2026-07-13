/**
 * @edict/protect-app — public surface: `startProtectApp` plus the store
 * building blocks for embedding.
 */

export { startProtectApp, type StartProtectAppOptions } from './server.js';
export {
  PolicyStore,
  TransactionStore,
  humanReviewCopy,
  presetCards,
  type CreateTxInput,
  type PolicySaveResult,
  type StoreOutcome,
  type StoredPolicy,
  type TxEvent,
} from './store.js';
