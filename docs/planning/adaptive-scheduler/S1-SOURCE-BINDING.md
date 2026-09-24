# Canonical runtime and fixture inventory binding

Contract, 2026-09-24. S1's original daily modules execute from the canonical
runtime, while reviewed experiment fixtures may execute from the implementation
worktree. Hashing the canonical tests tree cannot identify those other bytes.
This closes that build-observation gap without making source data authority.

## Closed binding and bundle compatibility

Keep `BuildIdentity(runtime_sha256, producer_sha256)` and the existing relative
path/content hashing algorithm. Bundle v1 stays unchanged. A bundle v2 has the
same fields plus exactly `source_binding`, whose closed schema is:

```
schema_version: 1
kind: canonical_runtime_fixture_inventory
runtime_root: absolute canonical daily source path
producer_root: absolute reviewed fixture repository path
source_digest: original daily SourceManifest digest
```

The bundle's already-required external SHA pin covers this descriptor. No CLI
producer hash, environment flag, arbitrary per-file allowlist or callback may
replace live observations. Both roots must be safe existing directories with
no reparse/symlink component; runtime_root must also equal the current production
module root and `daily_locations()`' canonical source. Retain root identities.
Aliases, replacement roots and malformed fields are rejected.

`SourceBoundBuildSource` reads the actual canonical SourceManifest and requires
the original digest. It independently hashes the complete existing bounded
runtime inventory (`sentinel/**/*.py`, command adapter) and producer inventories
(`tests/windows`, `tests/benchmarks`, `tests/fixtures`). Relative labels are
resolved against each inventory's own root. All existing entry/file/byte/depth
bounds and stable-file checks remain. Source/root/inventory changes invalidate
the original reader; it does not adopt a new generation or build silently.

`NativeEvidenceAuthority` must choose this concrete reader itself after parsing
and hash-checking bundle v2. It must reject an injected build callback for v2.
It never imports test code. Before evaluating any gate, actual two-root digests
must match the bundle. Missing/failed gates retain exactly the existing outcome;
v2 adds no enrollment, launch, capacity, control or promotion permission.

## Producer execution is a separate obligation

The S1 console bootstrap must pin a finite reviewed module closure, execute the
checked bytes (no stale pyc fallback), and preserve those exact module identities.
The current `tests`, `tests/windows` and `tests/fixtures` directories have no
initializers: bootstrap creates restricted namespace packages and refuses an
unexpected initializer until the reviewed closure explicitly changes. It does
not invent initializers or add a general worktree import path.

The producer uses the same concrete reader and original descriptor for run and
bundle v2. Before capture/admission and before publication it must attest the
actual executed canonical runtime and original fixture modules against that
binding. A matching on-disk inventory alone is not execution provenance.

The first source slice implements only the bounded reader and strict consumer.
It does not unlock the old runner or admission placeholder. Producer/bootstrap
integration must be complete before any actual S1 v2 artifact can be published.

## Verification

Exercise distinct roots with real isolated source files; verify actual runtime
and producer mutations/additions/removals, source digest/root changes, traversal,
redirects, malformed fields, closed bundle schemas and callback rejection.
Explicitly synthetic gate records test the consumer only; they prove no native
gate. Keep v1 behavior covered. Do not copy tests into the daily installer,
rewrite a production module's `_ROOT`, or modify runtime configuration.
