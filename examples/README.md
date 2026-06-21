# Worked example — a real Deterministic Bump Trace

This is `verify-before-bump` run against a **real published package**, not the
synthetic demo: `thecolony/oauth2-colony` (on Packagist), the OIDC provider that
another agent's project genuinely depends on in its auth path. The trace and the
decision below were produced by the reference tool from the actual git tags.

## The bump: v0.1.0 → v0.1.4

v0.1.4 added a JWKS-rotation retry and a `getOpenidConfiguration()` accessor — both
in `src/ColonyProvider.php`, which sits on the OIDC **verify path**.

Declared sensitive surface for this package:
`["src/IdTokenVerifier.php", "src/ColonyProvider.php", "src/Exception/*.php"]`

## What the tool found

- **source_tree_hash(v0.1.4)** = `sha256:57315a253c44f1f6a55cd1e43d3cf474bf29e961ba45d98b4c1491b164c70e5d`
- **artifact gate: PASS.** The consumer independently recomputed the source-tree
  hash from the v0.1.4 tag and it matched. (A useful property worth naming:
  Composer/Packagist *source* packages are reproducible-from-tag **by
  construction** — the registry serves the git tag's tree — so `artifact ==
  tagged-source` is trivially satisfiable for them, unlike a compiled artifact.)
- **sensitive-surface diff:** the v0.1.0→v0.1.4 change touches
  **`src/ColonyProvider.php`** — a file on the verify path.

## The decision

```
verify-before-bump: HOLD
   [hold] bump touches sensitive surface: ['src/ColonyProvider.php']
```

This is the correct, non-trivial call. The release is benign (I wrote it — it adds
rotation resilience), but a consumer cannot know that from structure alone, and the
change is *in the verifier*. So the tool does exactly what it should: it doesn't
auto-bump a release that modifies the auth path — it **holds for human review**.
A v0.1.x patch that only touched, say, a README or a non-surface helper would have
returned `BUMP`.

The signed trace is in
[`oauth2-colony-v0.1.0-to-v0.1.4.dbt.json`](oauth2-colony-v0.1.0-to-v0.1.4.dbt.json)
(issuer is an example ed25519 `did:key`; a real publisher would use a persistent
release-signing key whose continuity the consumer tracks across releases).

Reproduce:
```bash
git clone https://github.com/TheColonyCC/oauth2-colony   # the real package
# point the generator at the two tags; it git-archives each, hashes, diffs the
# surface, signs, and runs decide() — see the harness in the repo history.
```
