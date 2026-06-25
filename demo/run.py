"""Demo: verify-before-bump over a sample package with a benign and a malicious bump.

Builds a tiny package in three versions, a publisher key, signed Deterministic Bump
Traces, then runs the consumer's decide() across scenarios:
  benign bump        -> bump
  sensitive-surface  -> hold
  tampered signature -> reject
  artifact != source -> reject (consumer recompute disagrees with the trace)
  unknown issuer     -> hold
  audit required, decorrelated+clean -> bump ; not decorrelated -> hold
  disjoint evidence (identical substrate) -> bump ; shared evidence origin -> hold
  v0.3: content-addressed origins, consumption unverified -> hold ; verified -> bump
"""
import sys, os, tempfile, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import dbt

SURFACE = ["src/Security/*.py", "src/**/verify*", "src/auth/*"]

def write(root, files):
    for rel, content in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(content)

def make_versions(base):
    v1 = os.path.join(base, "v1"); v2b = os.path.join(base, "v2_benign"); v2m = os.path.join(base, "v2_malicious")
    common = {
        "src/Security/verify.py": "def verify(token):\n    return check_sig(token) and check_aud(token) and check_exp(token)\n",
        "src/util/format.py": "def fmt(x):\n    return str(x)\n",
        "README.md": "# sample\nv1\n",
    }
    write(v1, common)
    # benign: only touches a non-sensitive file
    b = dict(common); b["src/util/format.py"] = "def fmt(x):\n    return repr(x)  # nicer\n"; b["README.md"]="# sample\nv2\n"
    write(v2b, b)
    # malicious: silently weakens the auth verifier (a file in the sensitive surface)
    m = dict(common); m["src/Security/verify.py"] = "def verify(token):\n    return check_sig(token)  # dropped aud+exp checks\n"
    write(v2m, m)
    return v1, v2b, v2m

def trace_for(pkg, ver, prev, old_dir, new_dir, issuer_did, sk, *, reproducible=True,
              artifact_hash=None, audit=None):
    touched = dbt.surface_diff(old_dir, new_dir, SURFACE)
    t = dbt.build_trace(
        package=pkg, version=ver, previous_version=prev, ecosystem="demo",
        source_repo="https://example/repo", source_tag="v"+ver,
        source_tree_hash=dbt.tree_hash(new_dir),
        artifact_hash=artifact_hash or dbt.tree_hash(new_dir),  # demo: artifact==source tree
        reproducible=reproducible, surface_globs=SURFACE, touched=touched,
        audit=audit, issuer_did=issuer_did, issued_at="2026-06-21T00:00:00Z")
    return dbt.sign_trace(t, sk)

def show(name, res):
    print(f"  {name:34} -> {res['decision'].upper()}")
    for r in res["reasons"]:
        print(f"        {r}")

def main():
    base = tempfile.mkdtemp(prefix="dbt-demo-")
    try:
        v1, v2b, v2m = make_versions(base)
        sk, issuer = dbt.gen_key()
        trusted = {issuer}
        print("issuer:", issuer[:40], "...\n")

        # 1. benign bump
        t = trace_for("demo/pkg", "2", "1", v1, v2b, issuer, sk)
        show("benign bump", dbt.decide(t, trusted_dids=trusted, prev_issuer=issuer))

        # 2. malicious bump (touches sensitive surface — honest trace still HOLDS it)
        t = trace_for("demo/pkg", "2", "1", v1, v2m, issuer, sk)
        show("sensitive-surface bump", dbt.decide(t, trusted_dids=trusted, prev_issuer=issuer))

        # 3. tampered signature
        t = trace_for("demo/pkg", "2", "1", v1, v2b, issuer, sk)
        t["subject"]["version"] = "2.0.1-evil"   # mutate after signing
        show("tampered signature", dbt.decide(t, trusted_dids=trusted, prev_issuer=issuer))

        # 4. artifact != tagged source (consumer recomputes a different artifact hash)
        t = trace_for("demo/pkg", "2", "1", v1, v2b, issuer, sk)
        show("artifact != source (recompute)", dbt.decide(
            t, trusted_dids=trusted, prev_issuer=issuer,
            recomputed={"artifact_hash": "sha256:deadbeef"}))

        # 5. unknown issuer
        sk2, issuer2 = dbt.gen_key()
        t = trace_for("demo/pkg", "2", "1", v1, v2b, issuer2, sk2)
        show("unknown issuer", dbt.decide(t, trusted_dids=trusted, prev_issuer=issuer))

        # 6. audit required: decorrelated + clean -> bump
        good_audit = {"auditors": [
            {"id":"did:key:zA","operator":"did:key:zOrgA","stack":"semgrep","substrate":"x86/glibc","result":"clean","scope":["rce","auth-bypass"]},
            {"id":"did:key:zB","operator":"did:key:zOrgB","stack":"codeql","substrate":"arm/musl","result":"clean","scope":["rce","auth-bypass"]}]}
        t = trace_for("demo/pkg", "2", "1", v1, v2b, issuer, sk, audit=good_audit)
        show("audit: decorrelated+clean", dbt.decide(
            t, trusted_dids=trusted, prev_issuer=issuer, require_audit=True,
            required_scopes=["rce","auth-bypass"]))

        # 7. audit required: distinct stack+substrate but SAME operator -> HOLD
        #    (the operator axis catches what a stack/substrate-only check misses)
        weak_audit = {"auditors": [
            {"id":"did:key:zA","operator":"did:key:zOrgA","stack":"semgrep","substrate":"x86/glibc","result":"clean","scope":["rce"]},
            {"id":"did:key:zB","operator":"did:key:zOrgA","stack":"codeql","substrate":"arm/musl","result":"clean","scope":["rce"]}]}
        t = trace_for("demo/pkg", "2", "1", v1, v2b, issuer, sk, audit=weak_audit)
        show("audit: same operator (correlated)", dbt.decide(
            t, trusted_dids=trusted, prev_issuer=issuer, require_audit=True,
            required_scopes=["rce"]))

        # 8. evidence-disjointness: two auditors on IDENTICAL substrate but anchored to
        #    disjoint upstream evidence are two witnesses -> bump (axes relaxed to isolate)
        disjoint_evidence = {"auditors": [
            {"id":"did:key:zA","operator":"o","stack":"s","substrate":"x","result":"clean","scope":["rce"],"evidence":[{"ref":"sha256:aa","origin":"reproduced-build-A"}]},
            {"id":"did:key:zB","operator":"o","stack":"s","substrate":"x","result":"clean","scope":["rce"],"evidence":[{"ref":"sha256:bb","origin":"independent-fuzz-run-B"}]}]}
        t = trace_for("demo/pkg", "2", "1", v1, v2b, issuer, sk, audit=disjoint_evidence)
        show("audit: disjoint evidence, identical substrate (2 witnesses)", dbt.decide(
            t, trusted_dids=trusted, prev_issuer=issuer, require_audit=True,
            required_scopes=["rce"], required_decorrelation_axes=(), min_independent_witnesses=2))

        # 9. shared evidence origin: distinct operator/stack/substrate, but both votes
        #    re-derived from ONE upstream -> one witness -> HOLD (two articles, one wire report)
        shared_origin = {"auditors": [
            {"id":"did:key:zA","operator":"oA","stack":"sA","substrate":"xA","result":"clean","scope":["rce"],"evidence":[{"ref":"sha256:aa","origin":"one-wire-report"}]},
            {"id":"did:key:zB","operator":"oB","stack":"sB","substrate":"xB","result":"clean","scope":["rce"],"evidence":[{"ref":"sha256:cc","origin":"one-wire-report"}]}]}
        t = trace_for("demo/pkg", "2", "1", v1, v2b, issuer, sk, audit=shared_origin)
        show("audit: shared evidence origin (1 witness)", dbt.decide(
            t, trusted_dids=trusted, prev_issuer=issuer, require_audit=True,
            required_scopes=["rce"], required_decorrelation_axes=(), min_independent_witnesses=2))

        # 10. v0.3 forgery: distinct content-addressed origins, but consumption UNVERIFIED ->
        #     0 substantiated witnesses -> HOLD (naming an upstream you didn't consume earns nothing)
        H1 = "sha256:" + "a"*64; H2 = "sha256:" + "b"*64
        ca_audit = {"auditors": [
            {"id":"did:key:zA","operator":"oA","stack":"sA","substrate":"xA","result":"clean","scope":["rce"],"evidence":[{"ref":"build-A","origin":H1}]},
            {"id":"did:key:zB","operator":"oB","stack":"sB","substrate":"xB","result":"clean","scope":["rce"],"evidence":[{"ref":"build-B","origin":H2}]}]}
        t = trace_for("demo/pkg", "2", "1", v1, v2b, issuer, sk, audit=ca_audit)
        show("audit: content-addressed origins, consumption UNVERIFIED (0 witnesses)", dbt.decide(
            t, trusted_dids=trusted, prev_issuer=issuer, require_audit=True,
            required_scopes=["rce"], required_decorrelation_axes=(), min_independent_witnesses=2,
            verified_consumption=set()))

        # 11. same trace, a challenger verified each (auditor, origin) consumption -> 2 -> BUMP
        show("audit: same, consumption VERIFIED by challenger (2 witnesses)", dbt.decide(
            t, trusted_dids=trusted, prev_issuer=issuer, require_audit=True,
            required_scopes=["rce"], required_decorrelation_axes=(), min_independent_witnesses=2,
            verified_consumption={("did:key:zA", H1), ("did:key:zB", H2)}))
    finally:
        shutil.rmtree(base, ignore_errors=True)

if __name__ == "__main__":
    main()
