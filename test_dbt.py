import sys, os, tempfile, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
import dbt

def test_did_roundtrip():
    sk, did = dbt.gen_key()
    assert did.startswith("did:key:z6Mk")
    assert dbt.pub_from_did(did) == bytes(sk.verify_key)

def test_sign_verify_and_tamper():
    sk, did = dbt.gen_key()
    t = dbt.build_trace("p","2","1","demo","r","v2","sha256:a","sha256:a",True,["x/*"],[],None,did,"t")
    t = dbt.sign_trace(t, sk)
    assert dbt.verify_sig(t)
    t["subject"]["version"] = "evil"
    assert not dbt.verify_sig(t)

def test_surface_diff():
    base = tempfile.mkdtemp()
    try:
        for d,vf in [("v1","ok"),("v2","BAD")]:
            os.makedirs(os.path.join(base,d,"src/Security"))
            open(os.path.join(base,d,"src/Security/verify.py"),"w").write(vf)
            open(os.path.join(base,d,"src/util.py"),"w").write("same")
        touched = dbt.surface_diff(os.path.join(base,"v1"),os.path.join(base,"v2"),["src/Security/*"])
        assert touched == ["src/Security/verify.py"]
        assert dbt.surface_diff(os.path.join(base,"v1"),os.path.join(base,"v2"),["src/util.py"]) == []
    finally:
        shutil.rmtree(base, ignore_errors=True)

def test_decide_gates():
    sk, did = dbt.gen_key()
    base={"package":"p","version":"2","previous_version":"1","ecosystem":"d","source_repo":"r","source_tag":"v2","source_tree_hash":"sha256:a","artifact_hash":"sha256:a","reproducible":True,"surface_globs":["x/*"],"issuer_did":did,"issued_at":"t"}
    ok = dbt.sign_trace(dbt.build_trace(**base, touched=[], audit=None), sk)
    assert dbt.decide(ok, trusted_dids={did}, prev_issuer=did)["decision"]=="bump"
    touch = dbt.sign_trace(dbt.build_trace(**base, touched=["x/verify"], audit=None), sk)
    assert dbt.decide(touch, trusted_dids={did}, prev_issuer=did)["decision"]=="hold"
    assert dbt.decide(ok, trusted_dids=set(), prev_issuer=did)["decision"]=="hold"  # unknown issuer
    assert dbt.decide(ok, trusted_dids={did}, prev_issuer=did, recomputed={"artifact_hash":"sha256:zzz"})["decision"]=="reject"

def test_audit_decorrelation():
    sk, did = dbt.gen_key()
    base={"package":"p","version":"2","previous_version":"1","ecosystem":"d","source_repo":"r","source_tag":"v2","source_tree_hash":"sha256:a","artifact_hash":"sha256:a","reproducible":True,"surface_globs":["x/*"],"issuer_did":did,"issued_at":"t"}
    def mk(audit): return dbt.sign_trace(dbt.build_trace(**base, touched=[], audit=audit), sk)
    A={"id":"did:key:zA","operator":"did:key:zOpA","stack":"semgrep","substrate":"x86/glibc","result":"clean","scope":["rce"]}
    B={"id":"did:key:zB","operator":"did:key:zOpB","stack":"codeql","substrate":"arm64/musl","result":"clean","scope":["rce"]}
    # helper for the unit-level grade function
    assert dbt.decorrelation_axes([A,B])==["operator","stack","substrate"]
    assert dbt.decorrelation_axes([A])==[]                                   # <2 -> nothing
    assert "operator" not in dbt.decorrelation_axes([A, dict(B, operator="did:key:zOpA")])  # same operator
    Bno=dict(B); Bno.pop("operator")
    assert "operator" not in dbt.decorrelation_axes([A, Bno])                # undeclared == correlated
    # fully decorrelated -> bump, grade carries all three axes
    r=dbt.decide(mk({"auditors":[A,B]}), trusted_dids={did}, prev_issuer=did, require_audit=True, required_scopes=["rce"])
    assert r["decision"]=="bump", r
    assert set(r["decorrelation_grade"])=={"operator","stack","substrate"}
    # same operator (distinct stack+substrate) -> hold; operator absent from grade
    so=mk({"auditors":[A, dict(B, operator="did:key:zOpA")]})
    r=dbt.decide(so, trusted_dids={did}, prev_issuer=did, require_audit=True)
    assert r["decision"]=="hold" and "operator" not in r["decorrelation_grade"]
    # self-asserted decorrelation it doesn't actually have -> still hold, with a note
    lying=mk({"auditors":[A, dict(B, operator="did:key:zOpA", stack="semgrep", substrate="x86/glibc")], "decorrelation":{"distinct_stacks":True,"distinct_substrate":True}})
    r=dbt.decide(lying, trusted_dids={did}, prev_issuer=did, require_audit=True)
    assert r["decision"]=="hold"
    assert any("computed grade governs" in x for x in r["reasons"])
    # single auditor -> hold
    assert dbt.decide(mk({"auditors":[A]}), trusted_dids={did}, prev_issuer=did, require_audit=True)["decision"]=="hold"
    # policy relaxed to stack+substrate -> same-operator audit passes
    r=dbt.decide(so, trusted_dids={did}, prev_issuer=did, require_audit=True, required_decorrelation_axes=("stack","substrate"))
    assert r["decision"]=="bump", r
    # not require_audit -> audit ignored, bump, no grade key
    r=dbt.decide(mk({"auditors":[A,B]}), trusted_dids={did}, prev_issuer=did)
    assert r["decision"]=="bump" and "decorrelation_grade" not in r

if __name__=="__main__":
    import traceback
    n=0
    for name,fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print("ok",name); n+=1
    print(f"{n} tests passed")
