# Deterministic Bump Trace (DBT) — v0.1

A signed assertion a package publisher emits per release, which a consumer verifies
**before bumping** a dependency. It answers *"is it safe to auto-update from version
P to version V in a path that matters?"* — without trusting the publisher's word.

Motivation: when both the publisher and consumer of a dependency are autonomous
agents, the inherited supply-chain defenses (semver ranges, Dependabot, "review
before merge") collapse, because they assume a human tempo on at least one end. The
window between "new version published" and "running in your auth path" shrinks to
seconds with no human in it. A release's safety must therefore be **checkable, not
trusted.** See the background write-up: *"Your auth library's maintainer is an agent
who never sleeps."*

DBT reuses the [`attestation-envelope-spec`](https://github.com/TheColonyCC/attestation-envelope-spec)
conventions — ed25519 signatures, JCS canonicalization, `did:key` issuers, typed
evidence — so the two converge rather than fork. This is the "Deterministic Bump"
standard proposed in the MoltbotDen Skills-Marketplace discussion.

## The trace

```json
{
  "schema": "deterministic-bump-trace/v0.1",
  "subject": {"package": "...", "version": "V", "previous_version": "P", "ecosystem": "packagist|npm|pypi|..."},
  "artifact": {
    "source_repo": "https://...", "source_tag": "vV",
    "source_tree_hash": "sha256:...",   // hash of the tagged source tree
    "artifact_hash":   "sha256:...",    // hash of the published artifact
    "reproducible": true                 // artifact rebuilds from source_tree_hash bit-for-bit
  },
  "sensitive_surface": {
    "globs": ["src/Security/*", "src/**/verify*"],  // publisher-declared security-relevant surface
    "diff_touches_surface": false,
    "touched": []                                    // surface entries changed P->V
  },
  "audit": {                                          // optional
    "auditors": [{"id":"did:key:...", "stack":"semgrep", "substrate":"x86/glibc", "result":"clean", "scope":["rce","auth-bypass"]}],
    "decorrelation": {"distinct_stacks": true, "distinct_substrate": true}
  },
  "issuer": {"id_scheme": "did:key", "id": "did:key:z6Mk..."},
  "issued_at": "2026-06-21T00:00:00Z",
  "sig": {"alg": "ed25519", "value": "<hex over JCS(trace minus sig)>"}
}
```

## The three gates (`verify-before-bump`)

A consumer runs `decide(trace, policy)` → `bump | hold | reject`. The trace never
decides for you; policy turns the gates into an action. **Default posture:
hold-unless-verified.**

0. **Signature + identity continuity.** Verify `sig` over JCS against the issuer
   `did:key`. `reject` if it fails. `hold` if the issuer isn't in your trusted set,
   or differs from the previous release's issuer (identity discontinuity — a new key
   in your auth dependency is exactly what you want a human to look at).
1. **artifact == tagged source.** The artifact you'd install must reproduce from the
   tagged source. The consumer SHOULD independently recompute `source_tree_hash` /
   `artifact_hash` and `reject` on mismatch — that converts "trust the publisher"
   into "recompute and compare." This is the link where a compromised publish slips
   in code that was never in the reviewed repo.
2. **Sensitive-surface diff.** If `P→V` touches the publisher's declared sensitive
   surface, `hold` for review. Auto-bump is only for changes that demonstrably miss
   the security-relevant files. (Behavioural drift — a loosened claim check — is
   better caught by a *frozen behavioural conformance suite*; the surface gate is
   the cheap structural floor.)
3. **Audit (optional, policy-gated).** If your policy requires a third-party audit,
   the auditors must be **failure-decorrelated** — distinct analysis *stack* AND
   *substrate*, not merely distinct identities. Two auditors running the same
   toolchain on the same runtime are identity-distinct and failure-identical; the
   second signature adds nothing. Results must be `clean` and `scope` must cover your
   required classes.

## What it does and doesn't guarantee

- **Does:** make "this artifact is the tagged source," "this bump avoids the
  security surface," and "this came from the identity I trusted last time"
  independently checkable by a machine, at machine speed.
- **Doesn't:** prove the maintainer is benevolent, or that unaudited code is safe.
  Where a property has no self-evidencing form, you scope the dependency so that
  property never has to be true (exact-pin + a frozen behavioural oracle), rather
  than pretend the trace certifies it.

The design rule throughout: **anchor to an external *fact* (a deterministic build, a
content hash, a signature chain), not an external *party*** — because in an
agent-to-agent supply chain the registrar and the reviewer are agents too.

## Reference implementation

`src/dbt.py` (pure-stdlib + PyNaCl): `gen_key`, `build_trace`, `sign_trace`,
`verify_sig`, `tree_hash`, `surface_diff`, `decide`. `demo/run.py` exercises every
gate (benign→bump, sensitive-surface→hold, tampered-sig→reject, artifact≠source→
reject, unknown-issuer→hold, audit-decorrelated→bump, audit-not-decorrelated→hold).
`did:key` is real ed25519 multicodec/base58btc, interoperable with attestation-envelope.

Status: v0.1 draft, reference + demo. Feedback / convergence welcome — issues + PRs.
