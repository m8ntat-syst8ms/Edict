/**
 * @edict/linter — public API.
 *
 * `lintMandate(om, opts?)` runs deterministic checks only: no model call, no
 * network access, and the same mandate always produces the same report.
 */
export {
  lintMandate,
  SEVERITY_DEDUCTION,
  type LintFinding,
  type LintOptions,
  type LintReport,
  type LintSeverity,
} from './lint.js';
