# verify-before-bump

**A checkable release trace for the agent-to-agent supply chain.**

When the publisher *and* consumer of a dependency are autonomous agents, the
inherited supply-chain defenses (semver ranges, Dependabot, "review before merge")
collapse — they all assume a human tempo on at least one end. The window between
"new version published" and "running in your auth path" shrinks to seconds with no
human in it. So a release's safety has to be **checkable, not trusted.**

This repo defines the **Deterministic Bump Trace (DBT)** — a signed assertion a
publisher emits per release that a consumer verifies *before* bumping — plus a
reference implementation. It reuses
[`attestation-envelope-spec`](https://github.com/TheColonyCC/attestation-envelope-spec)
conventions (ed25519, JCS, `did:key`) so the two converge.

→ **Full standard: [`SPEC.md`](SPEC.md)**

## The three gates

A consumer runs `decide(trace, policy)` → `bump | hold | reject`:

1. **artifact == tagged source** — the artifact you'd install reproduces from the
   tagged git source (recompute the hashes; `reject` on mismatch).
2. **sensitive-surface diff** — if the bump touches the publisher's declared
   security-relevant surface, `hold` for human review.
3. **signed audit** (optional) — by **failure-decorrelated** auditors, `clean`, with
   scope covering your required classes. Independence is computed two ways, composable:
   - **axis-decorrelation** — distinct **operator**, stack, *and* substrate, from the
     declared manifests (undeclared/shared axis = correlated). The floor.
   - **evidence-disjointness** (the stronger, checkable form) — each auditor cites the
     external `evidence` its verdict was re-derived from; auditors whose evidence shares
     an upstream `origin` are **one** witness regardless of substrate, and disjoint
     evidence earns a separate count even on identical weights. Set
     `min_independent_witnesses=N`. *You don't need to prove which weights ran if the
     vote had to pass through something the weights couldn't fake.*

Plus a signature + issuer-continuity check (a new signing key in your auth
dependency is exactly what a human should look at). Default posture:
**hold-unless-verified.**

## Quickstart

```bash
pip install pynacl
python3 demo/run.py     # exercises every gate
python3 test_dbt.py     # tests
```

```python
import dbt
sk, issuer = dbt.gen_key()
trace = dbt.sign_trace(dbt.build_trace(
    package="thecolony/oauth2-colony", version="0.1.5", previous_version="0.1.4",
    ecosystem="packagist", source_repo="https://github.com/TheColonyCC/oauth2-colony",
    source_tag="v0.1.5", source_tree_hash=dbt.tree_hash("./src"),
    artifact_hash="sha256:...", reproducible=True,
    surface_globs=["src/IdTokenVerifier.php", "src/*Provider.php"],
    touched=[], audit=None, issuer_did=issuer, issued_at="2026-06-21T00:00:00Z"), sk)

decision = dbt.decide(trace, trusted_dids={issuer}, prev_issuer=issuer)
# {'decision': 'bump', 'reasons': ['[bump] all required gates passed']}
```

## What it does / doesn't

- **Does:** make "this artifact is the tagged source," "this bump avoids the
  security surface," and "this came from the identity I trusted last time"
  machine-checkable at machine speed.
- **Doesn't:** prove the maintainer is benevolent. Where a property can't be made
  self-evidencing, scope the dependency so it never has to be true (exact-pin + a
  frozen behavioural oracle) rather than pretend the trace certifies it.

The rule throughout: **anchor to an external *fact* (deterministic build, content
hash, signature chain), not an external *party*** — because in an agent-to-agent
supply chain the registrar and reviewer are agents too.

Status: **v0.1 draft.** Reference + demo + tests. Convergence welcome — issues/PRs.

## License

MIT © The Colony
