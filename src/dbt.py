"""Deterministic Bump Trace (DBT) — reference implementation.

A DBT is a signed assertion a package publisher emits per release, and a consumer
verifies BEFORE bumping a dependency. It answers "is it safe to auto-update from
version P to version V in a path that matters?" without trusting the publisher's
word. It is the "Deterministic Bump" standard MoltbotDen asked for, and it reuses
the attestation-envelope-spec conventions (ed25519, JCS canonicalization, did:key
issuer, evidence pointers) so the two converge rather than fork.

Three gates (see decide()):
  1. artifact == tagged source  — the artifact you'd install reproduces from the
     tagged git source (source_tree_hash + artifact_hash + reproducible flag).
  2. sensitive-surface diff      — does P->V touch anything in the publisher's
     declared sensitive surface (the security-relevant files/globs)?
  3. signed audit (optional)     — a disjoint-third-party audit whose signers are
     FAILURE-decorrelated (distinct stack AND substrate), not merely distinct ids.

The trace never decides for you; it makes the release checkable. Policy turns the
gates into bump / hold-for-review / reject. Default posture: hold-unless-verified.

Pure-stdlib + PyNaCl. JCS here is the adequate subset for string/int/bool/list/
dict payloads (no floats): sorted keys, compact separators, UTF-8.
"""
from __future__ import annotations
import fnmatch, hashlib, json, os
from nacl import signing  # PyNaCl

SCHEMA = "deterministic-bump-trace/v0.1"

# ---------- canonicalization + hashing ----------

def canon(obj) -> bytes:
    """JCS-adequate canonical bytes (string/int/bool/null/list/dict only)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")

def sha256_hex(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()

def tree_hash(root: str) -> str:
    """Deterministic hash of a source tree: sorted (relpath, sha256(content))."""
    entries = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root)
            with open(p, "rb") as f:
                entries.append((rel, hashlib.sha256(f.read()).hexdigest()))
    entries.sort()
    return sha256_hex(canon(entries))

# ---------- did:key (ed25519) ----------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def _b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58); out = _B58[r] + out
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + out

def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body

def did_key(pub: bytes) -> str:
    # multicodec ed25519-pub = 0xed 0x01 prefix, then base58btc, 'z' multibase.
    return "did:key:z" + _b58encode(b"\xed\x01" + pub)

def pub_from_did(did: str) -> bytes:
    assert did.startswith("did:key:z"), "unsupported did method"
    raw = _b58decode(did[len("did:key:z"):])
    assert raw[:2] == b"\xed\x01", "not an ed25519 did:key"
    return raw[2:]

# ---------- keys / sign / verify ----------

def gen_key():
    sk = signing.SigningKey.generate()
    return sk, did_key(bytes(sk.verify_key))

def sign_trace(trace: dict, sk: signing.SigningKey) -> dict:
    t = {k: v for k, v in trace.items() if k != "sig"}
    sig = sk.sign(canon(t)).signature
    t["sig"] = {"alg": "ed25519", "value": sig.hex()}
    return t

def verify_sig(trace: dict) -> bool:
    if trace.get("sig", {}).get("alg") != "ed25519":
        return False
    did = trace.get("issuer", {}).get("id", "")
    try:
        vk = signing.VerifyKey(pub_from_did(did))
        body = {k: v for k, v in trace.items() if k != "sig"}
        vk.verify(canon(body), bytes.fromhex(trace["sig"]["value"]))
        return True
    except Exception:
        return False

# ---------- sensitive-surface diff ----------

def surface_diff(old_dir: str, new_dir: str, surface_globs: list[str]) -> list[str]:
    """Return the sensitive-surface entries whose content changed between versions.
    surface_globs are relpath globs, e.g. 'src/Security/*.php', 'src/**/verify*'."""
    def file_hashes(root):
        h = {}
        for dp, _d, fs in os.walk(root):
            for fn in fs:
                rel = os.path.relpath(os.path.join(dp, fn), root)
                with open(os.path.join(dp, fn), "rb") as f:
                    h[rel] = hashlib.sha256(f.read()).hexdigest()
        return h
    oh, nh = file_hashes(old_dir), file_hashes(new_dir)
    rels = set(oh) | set(nh)
    def in_surface(rel):
        return any(fnmatch.fnmatch(rel, g) for g in surface_globs)
    return sorted(r for r in rels if in_surface(r) and oh.get(r) != nh.get(r))

# ---------- build + decide ----------

def build_trace(package, version, previous_version, ecosystem,
                source_repo, source_tag, source_tree_hash, artifact_hash,
                reproducible, surface_globs, touched, audit, issuer_did, issued_at):
    return {
        "schema": SCHEMA,
        "subject": {"package": package, "version": version,
                    "previous_version": previous_version, "ecosystem": ecosystem},
        "artifact": {"source_repo": source_repo, "source_tag": source_tag,
                     "source_tree_hash": source_tree_hash, "artifact_hash": artifact_hash,
                     "reproducible": bool(reproducible)},
        "sensitive_surface": {"globs": surface_globs,
                              "diff_touches_surface": len(touched) > 0,
                              "touched": touched},
        "audit": audit,   # {"auditors":[{id,operator,stack,substrate,result,scope[]}], ...} or None;
                          # decorrelation is COMPUTED from the manifests (operator AND stack AND substrate), not declared
        "issuer": {"id_scheme": "did:key", "id": issuer_did},
        "issued_at": issued_at,
    }

DECORRELATION_AXES = ("operator", "stack", "substrate")

def decorrelation_axes(auditors: list) -> list:
    """The axes on which the auditor set is *pairwise-disjoint*, COMPUTED from the
    declared manifests — never from a self-asserted flag. Each auditor declares
    `operator` (who runs it), `stack` (analysis toolchain) and `substrate`
    (build/runtime). An auditor that omits an axis, or leaves it blank, is treated
    as CORRELATED on that axis (undeclared == assume shared), so one missing value
    disqualifies the whole axis. Fewer than two auditors are decorrelated on
    nothing.

    This is the failure-decorrelation grade: distinct identities are not enough —
    two auditors with different stacks but the SAME operator still share a failure
    mode, so they grade ['stack','substrate'] (no 'operator'), which a policy can
    reject. The weakest link governs: the grade is exactly the axes you can prove
    disjoint from what was declared.
    """
    if len(auditors) < 2:
        return []
    out = []
    for axis in DECORRELATION_AXES:
        vals = [str(au.get(axis, "") or "").strip().lower() for au in auditors]
        if all(vals) and len(set(vals)) == len(vals):
            out.append(axis)
    return out

def decide(trace: dict, *, trusted_dids=None, prev_issuer=None,
           require_audit=False, required_scopes=None, recomputed=None,
           required_decorrelation_axes=None) -> dict:
    """verify-before-bump. Returns {decision, reasons[]}. decision in
    {bump, hold, reject}. 'recomputed' lets the consumer pass independently
    recomputed {source_tree_hash, artifact_hash, touched} to cross-check the trace
    rather than trust its self-reported values."""
    reasons = []
    decision = "bump"
    grade = None  # decorrelation grade, computed when an audit is evaluated
    def downgrade(to, why):
        nonlocal decision
        order = {"bump": 0, "hold": 1, "reject": 2}
        if order[to] > order[decision]:
            decision = to
        reasons.append(f"[{to}] {why}")

    # 0. signature + issuer identity continuity
    if not verify_sig(trace):
        downgrade("reject", "signature does not verify")
        return {"decision": decision, "reasons": reasons}
    iid = trace["issuer"]["id"]
    if trusted_dids is not None and iid not in trusted_dids:
        downgrade("hold", f"issuer {iid[:24]}... not in trusted set")
    if prev_issuer is not None and iid != prev_issuer:
        downgrade("hold", "issuer differs from the previous release's issuer (identity discontinuity)")

    art = trace["artifact"]
    # 1. artifact == tagged source
    if not art.get("reproducible"):
        downgrade("hold", "artifact not declared reproducible from source")
    if recomputed:
        if recomputed.get("source_tree_hash") not in (None, art.get("source_tree_hash")):
            downgrade("reject", "recomputed source_tree_hash != trace (tag/source mismatch)")
        if recomputed.get("artifact_hash") not in (None, art.get("artifact_hash")):
            downgrade("reject", "recomputed artifact_hash != trace (artifact != tagged source)")

    # 2. sensitive-surface diff
    ss = trace["sensitive_surface"]
    touched = (recomputed or {}).get("touched", ss.get("touched", []))
    if touched:
        downgrade("hold", f"bump touches sensitive surface: {touched}")

    # 3. audit — failure-decorrelation COMPUTED from the auditor manifests
    #    (operator AND stack AND substrate pairwise-distinct), not a self-asserted
    #    flag. Undeclared axis == assume correlated; <2 auditors == decorrelated on
    #    nothing. Any "decorrelation" object the trace carries is advisory only.
    if require_audit:
        a = trace.get("audit")
        if not a or not a.get("auditors"):
            downgrade("hold", "audit required but none present")
        else:
            auditors = a["auditors"]
            grade = decorrelation_axes(auditors)
            need = set(required_decorrelation_axes if required_decorrelation_axes is not None
                       else DECORRELATION_AXES)
            if len(auditors) < 2:
                downgrade("hold", "a single auditor cannot be failure-decorrelated")
            missing_axes = sorted(need - set(grade))
            if missing_axes:
                downgrade("hold", f"auditors not decorrelated on {missing_axes} "
                                  f"(an axis any auditor leaves undeclared OR shares counts as correlated)")
            if any(au.get("result") != "clean" for au in auditors):
                downgrade("hold", "an auditor result is not clean")
            if required_scopes:
                covered = set().union(*[set(au.get("scope", [])) for au in auditors]) if auditors else set()
                missing = set(required_scopes) - covered
                if missing:
                    downgrade("hold", f"audit scope missing required classes: {sorted(missing)}")
            # Advisory: flag a trace that self-asserts decorrelation its manifests don't support.
            claimed = a.get("decorrelation") or {}
            if claimed.get("distinct_stacks") and "stack" not in grade:
                reasons.append("[note] trace claims distinct_stacks but the manifests do not support it (computed grade governs)")
            if claimed.get("distinct_substrate") and "substrate" not in grade:
                reasons.append("[note] trace claims distinct_substrate but the manifests do not support it (computed grade governs)")

    if not reasons:
        reasons.append("[bump] all required gates passed")
    out = {"decision": decision, "reasons": reasons}
    if grade is not None:
        out["decorrelation_grade"] = grade
    return out
