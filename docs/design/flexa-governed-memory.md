# Flexa governed-memory boundary

Hermes includes one reviewed, read-only `flexa-memory` adapter for governed
scope version 1. It owns no business storage and has no native-memory fallback.
Activation still requires a coordinated Engine bundle with the signed trust
material and recall route described below; an `unconfigured` trust descriptor
keeps the adapter unavailable and fails closed.

## Signed managed policy

The managed `config.yaml` must contain this exact memory object:

```yaml
memory:
  mode: governed_external
  memory_enabled: false
  user_profile_enabled: false
  write_approval: true
  provider: flexa-memory
  principal_assertion:
    algorithm: ed25519
    key_id: <signed key id>
    public_key_sha256: <sha256 of principal-assertion-public-key.pem>
```

Both descriptor values may be `unconfigured` while a bundle is staged, but
runtime recall is then unavailable. The public key filename is fixed as
`principal-assertion-public-key.pem`; its digest is pinned by the signed
managed config. The recall URL is not configurable in Hermes and is derived
only from the signed profile's `enforcement_api` plus `/v1/memory/recall`.

Existing bundles without the exact block are rejected. Hermes never falls
back to `MEMORY.md`, `USER.md`, pending native writes, or a user-selected
memory provider.

## Principal assertion

Each external gateway event must carry a fresh `flexa_principal_assertion` in
event metadata. Hermes removes it before plugins, session lookup, cache lookup,
or model construction. The signed JSON object has these exact fields:

```text
schema_version, issuer, audience, tenant_id, employee_id, profile_id,
release_id, bundle_signing_payload_sha256, principal_namespace, principal_id,
transport_subject_sha256, issued_at, expires_at, nonce, signature
```

`signature` is exactly `{algorithm, key_id, value}` with Ed25519 and standard
padded RFC 4648 base64. The signature covers canonical JSON of every other
field. Hermes binds tenant, employee, profile, release, bundle digest, and
namespace to the verified signed profile. It also requires:

- `transport_subject_sha256 = sha256(namespace + NUL + authenticated subject)`;
- a canonical principal matching `^[a-z][a-z0-9-]{1,62}$`;
- a lifetime no longer than five minutes, with at most 30 seconds of clock
  skew; and
- a valid nonce that has not already been consumed in this process.

Only an opaque process-local binding proceeds past verification. The assertion
and canonical principal are not placed in logs or model context. Governed
session keys contain a one-way tenant/employee/namespace/principal fingerprint,
and cached-agent signatures include the canonical principal, so even normally
shared group threads cannot reuse history or a provider across principals.

## Read-only capability contract

The accepted capability set permits only synchronous recall, same-principal
assertion rebinding, and a process-local active-turn recall binding. It
explicitly disables provider system-prompt blocks, background prefetch, turn
sync, model-facing tools, lifecycle hooks, native write mirroring, and
delegation hooks. Normal turn completion therefore skips provider writes.
Explicit tool/write attempts still fail before dispatch.

Hermes' ordinary approval queue is not reused: it stores plaintext under the
writable profile home and depends on interactive approval commands outside the
governed RPC allowlist. Completed turns retain the existing exact `no_write`
decision bound to turn and session IDs. A missing or tampered decision prevents
buffered output release.

## Recall wire contract

Before recall, Hermes sends the query through the live
`memory.retrieval` boundary. It then obtains a content-free, process-local
binding for the same READY turn and passes that binding to the adapter. The
binding is opaque, non-repr, and never persisted or exposed to the model.
Hermes sends one JSON POST with exactly these seven members:

```json
{
  "query": "boundary-sanitized current user query",
  "task_id": null,
  "session_id": null,
  "limit": 12,
  "principal_assertion": {"...": "the verified signed assertion"},
  "turn": {
    "tenant_id": "signed tenant",
    "employee_id": "signed employee",
    "principal_id": "canonical principal",
    "session_id": "active Hermes session",
    "turn_id": "active Hermes turn"
  },
  "turn_context_token": "opaque active-turn token"
}
```

Protocol version 1 does not delegate runtime task or session scope ownership
to the durable memory service, so both top-level selectors are always null.
The turn object is derived only from the verified profile, principal binding,
and live enforcement registry; it is not caller supplied. The same five turn
identity strings, including `principal_id`, accompany every Hermes boundary
request. Engine independently verifies the assertion, turn identity, and
turn-context token before deriving the authorized access context. Recalled
content passes through `memory.retrieval` again before prompt injection.

The response is exactly `{"hits": [...]}`. Each hit has exactly:

```json
{
  "memory_id": "opaque id",
  "scope": "user_private",
  "version": 1,
  "content": "approved context",
  "partition": {
    "kind": "user_employee",
    "employee_id": "oren-cto",
    "principal_id": "canonical-principal",
    "task_id": null,
    "session_id": null
  },
  "provenance": {
    "evidence_hash": "64 lowercase hex characters",
    "citation": "immutable source citation"
  },
  "score": 0.91
}
```

Scope and partition kind must follow this mapping:

| Scope | Allowed partition kind |
| --- | --- |
| `organization_shared` | `organization` |
| `employee_private`, `employee_episodic`, `policy` | `employee` |
| `user_private` | `user_global` or `user_employee` |

All five partition members are present. Organization has no dimensions;
employee has only `employee_id`; user-global has only `principal_id`;
user-employee has both. `task_id` and `session_id` are always null. Hermes
rejects `working_task` and `session` hits entirely in protocol version 1.
Every non-null employee or principal dimension must exactly match Hermes'
verified request scope.

Hermes rejects extra or missing members, duplicate JSON keys, invalid
provenance, oversized responses, non-finite scores, scope/partition mismatch,
or any cross-partition hit. Provider/network/validation failures propagate and
fail the governed turn; they never activate native memory.

Protocol bounds are 8,192 UTF-8 bytes for the sanitized query, 128 characters
for `memory_id`, 256 characters for the immutable citation, and 32,768
characters and UTF-8 bytes for both an individual hit's content and the total
rendered recall context. Engine's signed `max_tokens` limit remains the
authoritative, normally more conservative response budget.

## Coordinated release requirement

Production activation requires one release containing the Engine-managed
config and fixed public key asset, signed profile/roster bindings, Engine
assertion issuance and independent recall verification, and the reviewed
Hermes adapter. Governed external writes remain outside this version and need
a separate scope-bound approval design before any write capability is enabled.
