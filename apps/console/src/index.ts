/**
 * @edict/console — public surface: `startConsole` plus the building blocks
 * (profile store, draft linting, docket reader, sandbox runner) for embedding.
 */

export { startConsole, type StartConsoleOptions } from './server.js';
export { ProfileStore, type ProfileListEntry, type SaveResult, type StoredProfile } from './profiles.js';
export { completeDraft, lintDraft, type LintDraftResult, type MandateDraft } from './lintDraft.js';
export {
  getCase,
  listCases,
  loadTemplate,
  REGENERATE_HINT,
  type CaseDetail,
  type CaseListing,
  type CaseSummary,
  type CaseTemplate,
} from './docket.js';
export { runSandbox, type SandboxRunOutcome, type SandboxRunRequest } from './sandboxRun.js';
