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

def test_evidence_disjointness():
    sk, did = dbt.gen_key()
    base={"package":"p","version":"2","previous_version":"1","ecosystem":"d","source_repo":"r","source_tag":"v2","source_tree_hash":"sha256:a","artifact_hash":"sha256:a","reproducible":True,"surface_globs":["x/*"],"issuer_did":did,"issued_at":"t"}
    def mk(audit): return dbt.sign_trace(dbt.build_trace(**base, touched=[], audit=audit), sk)
    A={"id":"did:key:zA","operator":"o1","stack":"s1","substrate":"x1","result":"clean","scope":["rce"],"evidence":[{"ref":"r1","origin":"docA"}]}
    B={"id":"did:key:zB","operator":"o2","stack":"s2","substrate":"x2","result":"clean","scope":["rce"],"evidence":[{"ref":"r2","origin":"docB"}]}
    # unit: disjoint origins -> 2 witnesses
    assert dbt.evidence_witnesses([A,B])["witnesses"]==2
    # two DIFFERENT refs that share one upstream origin -> one witness
    Bsame=dict(B, evidence=[{"ref":"r2","origin":"docA"}])
    assert dbt.evidence_witnesses([A,Bsame])["witnesses"]==1
    # undeclared origin earns nothing (v0.3: unsubstantiated -> 0, falls to axis floor)
    Aund={**A,"evidence":[{"ref":"r1"}]}; Bund={**B,"evidence":[{"ref":"r2"}]}
    eu=dbt.evidence_witnesses([Aund,Bund]); assert eu["witnesses"]==0 and len(eu["uncounted"])==2
    # an auditor citing no evidence is unanchored (earns nothing here)
    C={"id":"did:key:zC","operator":"o3","stack":"s3","substrate":"x3","result":"clean","scope":["rce"]}
    ev=dbt.evidence_witnesses([A,C]); assert ev["witnesses"]==1 and ev["unanchored"]==["did:key:zC"]
    # policy: min_independent_witnesses satisfied (axes relaxed to isolate) -> bump
    r=dbt.decide(mk({"auditors":[A,B]}), trusted_dids={did}, prev_issuer=did, require_audit=True,
                 required_scopes=["rce"], required_decorrelation_axes=(), min_independent_witnesses=2)
    assert r["decision"]=="bump", r
    assert r["evidence_independence"]["witnesses"]==2
    # same upstream -> only 1 disjoint witness -> hold, even with two distinct auditors
    r=dbt.decide(mk({"auditors":[A,Bsame]}), trusted_dids={did}, prev_issuer=did, require_audit=True,
                 required_scopes=["rce"], required_decorrelation_axes=(), min_independent_witnesses=2)
    assert r["decision"]=="hold" and r["evidence_independence"]["witnesses"]==1
    # composes with the axis floor: disjoint evidence (2) but SAME operator -> default axis policy still holds
    Bso=dict(B, operator="o1")
    r=dbt.decide(mk({"auditors":[A,Bso]}), trusted_dids={did}, prev_issuer=did, require_audit=True,
                 required_scopes=["rce"], min_independent_witnesses=2)
    assert r["decision"]=="hold"
    assert r["evidence_independence"]["witnesses"]==2 and "operator" not in r["decorrelation_grade"]

def test_origin_forgery_v03():
    sk, did = dbt.gen_key()
    base={"package":"p","version":"2","previous_version":"1","ecosystem":"d","source_repo":"r","source_tag":"v2","source_tree_hash":"sha256:a","artifact_hash":"sha256:a","reproducible":True,"surface_globs":["x/*"],"issuer_did":did,"issued_at":"t"}
    def mk(audit): return dbt.sign_trace(dbt.build_trace(**base, touched=[], audit=audit), sk)
    H1="sha256:"+"a"*64; H2="sha256:"+"b"*64
    A={"id":"did:key:zA","operator":"o1","stack":"s1","substrate":"x1","result":"clean","scope":["rce"],"evidence":[{"ref":"r1","origin":H1}]}
    B={"id":"did:key:zB","operator":"o2","stack":"s2","substrate":"x2","result":"clean","scope":["rce"],"evidence":[{"ref":"r2","origin":H2}]}
    # content-address recogniser
    assert dbt.is_content_address(H1) and not dbt.is_content_address("my-build-A")
    # no v0.3 policy: distinct declared origins are trusted -> 2 (v0.2 behaviour preserved)
    assert dbt.evidence_witnesses([A,B])["witnesses"]==2
    # the forgery (ax7): distinct origins, NONE consumption-verified -> 0 substantiated witnesses
    ev=dbt.evidence_witnesses([A,B], verified=set())
    assert ev["witnesses"]==0 and set(ev["uncounted"])=={"did:key:zA","did:key:zB"}
    # verify both (auditor,origin) pairs -> 2 again (case-insensitive normalisation)
    ev=dbt.evidence_witnesses([A,B], verified={("did:key:zA",H1),("did:key:zB",H2)})
    assert ev["witnesses"]==2 and ev["uncounted"]==[]
    # 1 real + 1 padded fake: only A's consumption verified -> the fake earns nothing
    ev=dbt.evidence_witnesses([A,B], verified={("did:key:zA",H1)})
    assert ev["witnesses"]==1 and ev["uncounted"]==["did:key:zB"]
    # require_content_addressed: a mintable label origin is dropped; the CA origin counts
    Blabel=dict(B, evidence=[{"ref":"r2","origin":"my-build-B"}])
    ev=dbt.evidence_witnesses([A,Blabel], require_content_addressed=True)
    assert ev["witnesses"]==1 and ev["uncounted"]==["did:key:zB"]
    # mixed: an auditor with one verified CA origin AND an unverified one stays anchored via the verified one
    Bmix=dict(B, evidence=[{"ref":"r2","origin":H2},{"ref":"r3","origin":"sha256:"+"c"*64}])
    assert dbt.evidence_witnesses([A,Bmix], verified={("did:key:zA",H1),("did:key:zB",H2)})["witnesses"]==2
    # decide() gate: faked independence is held; verified consumption bumps
    faked=mk({"auditors":[A,B]})
    r=dbt.decide(faked, trusted_dids={did}, prev_issuer=did, require_audit=True, required_scopes=["rce"],
                 required_decorrelation_axes=(), min_independent_witnesses=2, verified_consumption=set())
    assert r["decision"]=="hold" and r["evidence_independence"]["witnesses"]==0
    r=dbt.decide(faked, trusted_dids={did}, prev_issuer=did, require_audit=True, required_scopes=["rce"],
                 required_decorrelation_axes=(), min_independent_witnesses=2,
                 verified_consumption={("did:key:zA",H1),("did:key:zB",H2)})
    assert r["decision"]=="bump", r

def test_challenge_protocol_v04():
    import challenge as ch
    sk_pub, did_pub = dbt.gen_key()
    H1="sha256:"+"a"*64; H2="sha256:"+"b"*64
    A={"id":"did:key:zAudA","operator":"opA","stack":"semgrep","substrate":"x86","result":"clean","scope":["rce"],"evidence":[{"ref":"bA","origin":H1}]}
    B={"id":"did:key:zAudB","operator":"opB","stack":"codeql","substrate":"arm","result":"clean","scope":["rce"],"evidence":[{"ref":"bB","origin":H2}]}
    base={"package":"p","version":"2","previous_version":"1","ecosystem":"d","source_repo":"r","source_tag":"v2","source_tree_hash":"sha256:a","artifact_hash":"sha256:a","reproducible":True,"surface_globs":["x/*"],"issuer_did":did_pub,"issued_at":"t"}
    trace=dbt.sign_trace(dbt.build_trace(**base, touched=[], audit={"auditors":[A,B]}), sk_pub)
    tid=ch.trace_id(trace); beacon="drand:round:12345:abcdef"
    # a pool of challengers, each disjoint from both auditors (distinct op/stack/substrate)
    pool=[]; sks={}
    for op,st,sub in [("opC","bandit","riscv"),("opD","snyk","ppc"),("opE","grype","s390x")]:
        sk,did=dbt.gen_key(); pool.append({"id":did,"operator":op,"stack":st,"substrate":sub}); sks[did]=sk
    # selection is deterministic + recomputable, and picks an eligible challenger
    selA=ch.select_challenger(beacon,tid,A,H1,pool); selB=ch.select_challenger(beacon,tid,B,H2,pool)
    assert selA in sks and selB in sks
    assert ch.select_challenger(beacon,tid,A,H1,pool)==selA   # deterministic
    # correctly-selected challengers emit 'consumed' receipts -> verified_consumption
    rA=ch.make_receipt(tid,A["id"],H1,beacon,"consumed",sks[selA])
    rB=ch.make_receipt(tid,B["id"],H2,beacon,"consumed",sks[selB])
    vc=ch.consumption_from_challenges([rA,rB],beacon,trace,pool)
    assert (A["id"].lower(),H1) in vc and (B["id"].lower(),H2) in vc
    # end-to-end: feed to decide() -> 2 substantiated witnesses -> bump
    r=dbt.decide(trace, trusted_dids={did_pub}, prev_issuer=did_pub, require_audit=True, required_scopes=["rce"],
                 required_decorrelation_axes=(), min_independent_witnesses=2, verified_consumption=vc)
    assert r["decision"]=="bump", r
    # forgery: a NON-selected challenger signs -> rejected (selection mismatch)
    wrong=next(d for d in sks if d!=selA)
    assert not ch.verify_receipt(ch.make_receipt(tid,A["id"],H1,beacon,"consumed",sks[wrong]),beacon,trace,pool)
    # beacon-binding: a receipt for a different beacon is rejected under the real one
    assert not ch.verify_receipt(ch.make_receipt(tid,A["id"],H1,"other-beacon","consumed",sks[selA]),beacon,trace,pool)
    # result-binding: a "not-consumed" receipt from the right challenger is not credited
    assert not ch.verify_receipt(ch.make_receipt(tid,A["id"],H1,beacon,"not-consumed",sks[selA]),beacon,trace,pool)
    # disjointness: a challenger sharing the auditor's operator is never eligible/selected
    shared={"id":"did:key:zShare","operator":"opA","stack":"bandit","substrate":"riscv"}
    assert not ch._party_disjoint(shared, A)
    assert ch.select_challenger(beacon,tid,A,H1,[shared]) is None   # no disjoint challenger
    # with NO valid receipts, decide() sees 0 substantiated witnesses -> hold
    r=dbt.decide(trace, trusted_dids={did_pub}, prev_issuer=did_pub, require_audit=True, required_scopes=["rce"],
                 required_decorrelation_axes=(), min_independent_witnesses=2,
                 verified_consumption=ch.consumption_from_challenges([],beacon,trace,pool))
    assert r["decision"]=="hold" and r["evidence_independence"]["witnesses"]==0

if __name__=="__main__":
    import traceback
    n=0
    for name,fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print("ok",name); n+=1
    print(f"{n} tests passed")
