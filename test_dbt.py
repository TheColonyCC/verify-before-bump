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

if __name__=="__main__":
    import traceback
    n=0
    for name,fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print("ok",name); n+=1
    print(f"{n} tests passed")
