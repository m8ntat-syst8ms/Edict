# @edict/linter

Deterministic pre-funding analysis for Edict `OrderMandate` objects.

The linter has no model or network dependency: the same mandate produces the
same report. Malformed input is returned as structured findings rather than
throwing.

## API

```ts
import { lintMandate } from '@edict/linter';

const report = lintMandate(orderMandate, { screen: true });
```

`report` contains:

```ts
interface LintReport {
  score: number;
  machineCoverage: { checked: number; total: number; pct: number };
  findings: Array<{
    severity: 'error' | 'warn' | 'info';
    code: string;
    criterionId?: string;
    message: string;
    suggestion?: string;
  }>;
}
```

Set `screen: false` only for trusted template workflows that intentionally
skip the prompt-injection pass.

## Checks

- machine-check coverage;
- vague or subjective terms;
- missing locale, units, deadline, or acceptance-window parameters;
- malformed and duplicate acceptance criteria;
- Decision Space structure and reachability;
- split outcomes without milestone pricing;
- scalar-unit and value inconsistencies; and
- prompt-injection patterns in mandate-originated text.

Errors deduct 15 points, warnings 5, and informational findings 1. A clean
mandate scores 100. Integrations should configure their own funding gate using
the score and `blockOnError` policy committed in the Protection Profile.

## CLI

```sh
edict-lint <mandate.json> [--json] [--no-screen]
```

The CLI prints the canonical mandate hash, score, machine coverage, and
findings. Exit codes are:

- `0`: no error-severity finding;
- `1`: one or more error-severity findings;
- `2`: invalid CLI use or unreadable input.

## Development

```sh
npm run build -w @edict/linter
npm test -w @edict/linter
```
