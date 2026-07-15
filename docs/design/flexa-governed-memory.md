# Flexa governed-memory rollout boundary

The current Hermes seam is intentionally fail-closed and is not deployable on
its own.

A managed profile must carry the exact signed `memory` policy with native
`MEMORY.md` and `USER.md` disabled, `write_approval: true`, and a scoped
external provider. Existing managed bundles without that block are rejected;
there is no compatibility fallback to Hermes' flat local memory files.

Hermes' ordinary write-approval queue is not reused here. It stores pending
plaintext under the writable profile home and relies on interactive approval
commands that are outside the governed RPC allowlist. Until a verified,
tenant/employee/principal-scoped approval token or handler is available:

- completed turns record only an exact `no_write` decision bound to the turn
  and session IDs; no user or assistant text is staged or persisted and the
  provider is not called;
- model-facing memory-provider tools are hidden and defensively rejected;
- native memory writes and pending-write replay remain disabled; and
- an absent, mismatched, or tampered `no_write` decision prevents buffered output from
  being released.

Read-only provider context remains available through initialization, system
prompt context, and scoped prefetch. Failures in those reads, or in provider
compression lifecycle hooks, propagate and fail the governed turn.

Deployment requires one coordinated release containing the Engine-managed
config/roster changes, a reviewed `flexa-memory` provider implementing governed
scope version 1, an authenticated transport principal, and the external write
approval boundary. The Hermes seam must not be pinned before all four exist.
