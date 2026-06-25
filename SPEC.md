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
    "auditors": [                                     // each declares operator+stack+substrate AND the evidence it re-derived its verdict from
      {"id":"did:key:zAud1", "operator":"did:key:zOrgA", "stack":"semgrep", "substrate":"x86/glibc",  "result":"clean", "scope":["rce","auth-bypass"], "evidence":[{"ref":"reproduced-build-A", "origin":"sha256:9f2b…"}]},
      {"id":"did:key:zAud2", "operator":"did:key:zOrgB", "stack":"codeql",  "substrate":"arm64/musl", "result":"clean", "scope":["rce","auth-bypass"], "evidence":[{"ref":"reproduced-build-B", "origin":"sha256:1c7d…"}]}
    ]
    // Independence is COMPUTED, never declared, two ways: (a) axis-decorrelation from
    // the operator/stack/substrate manifests, and (b) evidence-disjointness — auditors
    // whose `evidence` shares an upstream `origin` are one witness. Any "decorrelation":
    // {...} flag is advisory only.
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
   the auditors must be **failure-decorrelated** — distinct **operator** AND analysis
   *stack* AND *substrate*, not merely distinct identities. Two auditors running the
   same toolchain on the same runtime are identity-distinct and failure-identical; two
   run by the same *operator* share a hand even with different stacks. The grade is
   **computed from the auditors' declared manifests, never from a self-asserted flag**:
   `decide()` returns `decorrelation_grade` = the axes on which the set is provably
   pairwise-distinct, and an axis any auditor leaves **undeclared counts as correlated**
   (default pessimism). Fewer than two auditors decorrelate nothing. Policy picks the
   required axes (default: operator + stack + substrate); the *weakest link* governs.
   Results must be `clean` and `scope` must cover your required classes.

   *Compatibility:* `operator` is an **additive** optional field — v0.1 traces stay valid. The change is verifier policy, not wire format: an audit that omits `operator` simply grades without that axis and is held under the default (operator-inclusive) policy. Set `required_decorrelation_axes` to relax.

   **3b. Evidence-disjointness (the stronger, checkable model).** Axis-decorrelation
   grades a property of the *agent* — operator/stack/substrate are declared and not
   cheaply verifiable, and they over-discount: two auditors on identical weights can
   be genuinely independent on a claim that turns on inputs neither set memorized.
   So each auditor SHOULD also cite the external `evidence` its verdict was re-derived
   from — `[{ref, origin}]`, where `origin` is the *upstream* source. `decide()` then
   counts **effective-independent witnesses** by causally-disjoint origin (union-find):
   two auditors whose evidence shares any origin are **one** witness regardless of
   declared substrate (two articles off one wire report don't double-count); two
   anchored to independently-obtained evidence earn their separate count even on
   identical weights. Set `min_independent_witnesses=N` to require N disjoint
   witnesses; `decide()` returns `evidence_independence = {witnesses, anchored,
   unanchored, uncounted}`.

   **3c. Origin distinctness + consumption, recomputed not asserted (v0.3).** 3b
   still trusts the declared `origin`: an auditor can name a disjoint upstream it
   never consumed and union-find hands you a witness — the "declare your substrate"
   forgery wearing "cite your evidence" vocabulary. v0.3 closes it by pushing the
   same recompute discipline one level down, with two consumer-side checks (like
   `recomputed`, these are the verifier's, not the trace's word):
   - **`require_content_addressed`** — `origin` must be a content-address
     (`algo:hex`), a falsifiable commitment to specific bytes anyone can fetch and
     hash. Then "distinct origins" means "distinct bytes someone can confirm," not
     distinct labels; a mintable label is dropped.
   - **`verified_consumption`** — the set of `(auditor_id, origin)` pairs a
     challenger has confirmed: the artifact resolves *and* the verdict depends on it
     (re-derive the vote from the bytes, or perturb them and watch it move). Only
     verified pairs count; a cited-but-unverified origin is dropped.
   An auditor whose cited evidence all fails policy earns **nothing** (it can't even
   buy the shared slot the v0.2 sentinel gave it — so padding one real auditor with a
   fake no longer reaches a quorum); it falls to the axis floor. `witnesses` counts
   only distinct *substantiated* origin clusters; `uncounted` surfaces the dropped.

   This relocates the independence question from a place no one can check (which
   weights ran) to one anyone can (what the vote was forced to consume) — you don't
   need to prove which weights ran if the vote had to pass through something the
   weights couldn't fake. The two models **compose**: count by disjoint-evidence
   where auditors cite it (`min_independent_witnesses` + `verified_consumption`), and
   lean on the axis floor (`required_decorrelation_axes`) for the residual that cites
   none — pure-judgment claims, or "is this artifact-under-review correct," which have
   no exogenous input to anchor to.

   *Compatibility:* `evidence` is additive and optional, and the wire format is
   unchanged from v0.2 (origin SHOULD now be a content-address; v0.2 traces stay
   valid). v0.3 is verifier policy: with `min_independent_witnesses`,
   `require_content_addressed`, and `verified_consumption` all unset, grading is
   exactly v0.2/v0.1.

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
