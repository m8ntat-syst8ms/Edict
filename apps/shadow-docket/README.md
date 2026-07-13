# @edict/shadow-docket

Reproducible harness for exercising the Edict arbiter pipeline.

The committed docket contains five synthetic or adapted examples spanning
bilateral delivery disputes, categorical public-resolution challenges, and
bounded-scalar claims. They demonstrate the case format, evidence commitments,
decision spaces, replay tooling, and report output.

These fixtures are intentionally public and their expected outcomes are known.
They are **illustrative regression examples, not a production qualification
suite**. Production jury, provider, prompt, verifier, and signer releases must
be evaluated against a separate private holdout and adversarial corpus.

## Public Replay

The harness reports:

- agreement with each illustrative expected outcome;
- ruling stability when party order is swapped;
- escalation and finality behavior;
- Decision Space compliance; and
- roster eligibility under operator-diversity rules.

```sh
npm run build -w @edict/shadow-docket

# Offline deterministic replay
node apps/shadow-docket/dist/run.js run

# Validate fixtures and the example seat roster
node apps/shadow-docket/dist/run.js validate

# Recompute evidence commitments after editing an example
node apps/shadow-docket/dist/run.js rehash
```

Generated reports are written to `apps/shadow-docket/reports/` and are
gitignored.

## Private Qualification

The CLI accepts external case, seat, and output paths so the same public
harness can evaluate a private corpus without copying it into this repository:

```sh
node apps/shadow-docket/dist/run.js run \
  --providers env \
  --cases /private/edict-qualification/holdout/cases \
  --seats /private/edict-qualification/config/production-seats.json \
  --out /private/edict-qualification/results/current \
  --strict
```

Provider-backed results qualify only the exact model, provider, signer policy,
prompts, verifier policy, and configuration used in that run. They do not
establish production suitability for a different release.

## Case Layout

```text
cases/<slug>/
  case.json
  groundtruth.json
  evidence/
    ...
```

`case.json` references evidence with relative `evidence/<filename>` URIs and
SHA-256 commitments. The loader rejects traversal, symlink escape, missing
files, duplicate case identifiers, malformed schemas, and commitment
mismatches.

`groundtruth.json` contains an expected in-space outcome used by the replay
report. It is never provided to the arbiter.

## Public Fixture Changes

Public examples are allowlisted in `PUBLIC_FIXTURES.json`. Adding one requires
updating that manifest and confirming that it contains no holdout,
qualification, or adversarial material. Once disclosed, a fixture can never be
used as a private holdout.

```sh
npm run check:public-boundary
npm test -w @edict/shadow-docket
```
