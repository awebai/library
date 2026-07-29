# AATK increment 2B: current-incumbent HTTP capability transcripts

Increment 2B is an isolated, unattested capability slice. It does not run production, publish
a lifecycle receipt, or authorize planning or release.

## Frozen four-cell slice

The checked-in driver is exactly `library_prod_gate.run_current_incumbent`. The driver keeps its
real incumbent service/deploy/commit/shape validation, both runtime loops, the actual
`OriginConnectTunnel`, `raw_materialize`, `run_checked`, proxy-environment construction, exact
HTTP assertion, recovery-payload validation, and mandatory origin-before-public order.

Exactly four current-incumbent rows are `instrumented-capability`, in this exact passing order:

1. `materialize.origin.claude-code.http-200`;
2. `materialize.origin.pi.http-200`;
3. `materialize.public.claude-code.http-200`;
4. `materialize.public.pi.http-200`.

The other 18 current-incumbent rows remain deferred. In particular, tunnel execution does not
promote route assertions, payload contracts, profile pins, or public-continuation fatality.
Existing cross-domain `identical` mappings do not copy this current-domain capability state to
candidate coverage.

## Honest fixture boundary

The process fixture replaces only the released-aw subprocess leaf. For origin calls it opens a
real loopback connection to the actual proxy, sends the canonical CONNECT authority, and reaches
a local upstream through the actual tunnel. Controlled startup DNS keeps public and origin
addresses disjoint. No capability test replaces `OriginConnectTunnel`, `raw_materialize`,
`run_checked`, `origin_proxy_environment`, `validate_recovery_payload`, or tunnel counters.

Each HTTP child binds the digest and length of the exact bounded status bytes asserted by
`raw_materialize`. A nonzero process is a subject failure, never an HTTP-status negative.
Dedicated HTTP negatives exit normally, traverse every prerequisite component, and supply the
non-200 status at the real assertion.

## Closed transcript contract

`library.aatk-current-incumbent-capability-transcript.v1` accepts only the current-incumbent
domain and `library_prod_gate.run_current_incumbent` driver. It has one four-cell positive recipe
and four exact dedicated-negative recipes. Every negative has exactly its prior passing siblings,
one intended terminal sibling, no later child, and a stable predicate-local top code. Subject and
structural failures are separate nonclaiming variants.

Output is source-clean-bound, outside the repository, private, bounded, and atomic no-replace.
Invalid metadata after run creation produces one setup terminal. Secondary finalization errors
are contained so they do not replace the original subject error.

## Explicit nonclaims

This direct driver slice does not execute Make, parser or `main()` mode selection, or
`verify_released_aw`; the fixture process is not the reviewed released-aw artifact. It does not
prove current-production execution, live incumbent identity, producer authenticity, parent-run
completeness, durable ledger publication, safety selection, same-path lifecycle controls, or any
candidate/postdeploy/rollback result. Lifecycle validation explicitly rejects
`current-incumbent-capability-fixture`.

All nine global deferred obligations continue to block preplan and release-close.
