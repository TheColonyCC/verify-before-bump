"""Challenge protocol (v0.4) — make the v0.3 consumption check LIVE, INDEPENDENT, VERIFIABLE.

v0.3 made consumption *checkable*: ``decide(verified_consumption=…)`` credits an
``(auditor, origin)`` pair only if a challenger confirmed the verdict depends on the
content-addressed artifact (re-fetch it, perturb it, watch the vote move). But it
left the residual the Colony thread kept hitting — "verified by *whom*?":

  1. WHO challenges?              an auditor that picks its own challenger, or a
                                 publisher that does, gets a rubber stamp.
  2. selected HOW?               if you can predict which challenger checks you, you
                                 corrupt that one. Selection must be unpredictable.
  3. INDEPENDENT of the auditor? a challenger that shares the auditor's failure modes
                                 (or its evidence) just re-runs the same mistake.

This module closes all three with signed challenge receipts whose selection anyone
can recompute:

  - A registered POOL of challengers, each with an operator/stack/substrate manifest.
  - ``select_challenger(beacon, …)`` picks, from the subset failure-DISJOINT from the
    auditor, one challenger by hashing a public BEACON (e.g. a drand round) fixed
    AFTER the verdicts commit. Unpredictable-before, recomputable-after — the same
    commit-then-sample move, applied to *who checks whom*.
  - The selected challenger re-fetches the content-addressed origin ITSELF (not the
    auditor's bytes) and emits a signed receipt ``{result: consumed|…}``.
  - ``consumption_from_challenges()`` returns the ``verified_consumption`` set for
    ``decide()`` — only pairs whose receipt verifies, was emitted by the correctly
    *selected* challenger, by one *disjoint* from the auditor, with result ``consumed``.

The gate is now only as live as the pool + the beacon, both of which are public:
v0.4 makes "verified by whom" itself checkable, rather than trusting a hand-supplied set.

Reuses the dbt conventions (ed25519, JCS canonicalization, did:key). Pure-stdlib + PyNaCl.
"""
from __future__ import annotations
import hashlib
from nacl import signing  # PyNaCl

import dbt

# ---------- generic signed objects (field-agnostic; signer did passed explicitly) ----------

def sign_obj(obj: dict, sk: signing.SigningKey) -> dict:
    o = {k: v for k, v in obj.items() if k != "sig"}
    o["sig"] = {"alg": "ed25519", "value": sk.sign(dbt.canon(o)).signature.hex()}
    return o

def verify_obj(obj: dict, signer_did: str) -> bool:
    if obj.get("sig", {}).get("alg") != "ed25519":
        return False
    try:
        vk = signing.VerifyKey(dbt.pub_from_did(signer_did))
        body = {k: v for k, v in obj.items() if k != "sig"}
        vk.verify(dbt.canon(body), bytes.fromhex(obj["sig"]["value"]))
        return True
    except Exception:
        return False

# ---------- trace id + disjointness ----------

def trace_id(trace: dict) -> str:
    """A stable id binding a receipt to the exact signed trace it challenges."""
    return dbt.sha256_hex(dbt.canon(trace))

def _party_disjoint(a: dict, b: dict) -> bool:
    """Two parties are failure-disjoint iff they declare DISTINCT operator AND stack
    AND substrate (all present) and aren't the same id. A challenger that shares any
    axis with the auditor shares a failure mode and is not an independent check —
    same pessimism as the axis grade, applied pairwise to challenger-vs-auditor."""
    if str(a.get("id", "")) == str(b.get("id", "")):
        return False
    for axis in dbt.DECORRELATION_AXES:
        av = str(a.get(axis, "") or "").strip().lower()
        bv = str(b.get(axis, "") or "").strip().lower()
        if not av or not bv or av == bv:
            return False
    return True

# ---------- unpredictable, recomputable selection ----------

def select_challenger(beacon, tid: str, auditor: dict, origin, pool: list):
    """Deterministically-but-unpredictably pick the challenger for one (auditor, origin).

    Selection is over only the challengers failure-disjoint from this auditor, indexed
    by a hash of the public `beacon` (fixed AFTER the verdicts commit) plus the trace,
    auditor and origin. The auditor can't pre-arrange its checker — it can't predict
    the beacon — and anyone can recompute the assignment afterward. Returns the
    challenger's did, or None if no disjoint challenger exists (a fact a policy can act on).
    """
    eligible = sorted((c for c in pool if _party_disjoint(c, auditor)),
                      key=lambda c: str(c.get("id", "")))
    if not eligible:
        return None
    h = int(hashlib.sha256(dbt.canon([str(beacon), str(tid),
                                      str(auditor.get("id", "")), str(origin)])).hexdigest(), 16)
    return eligible[h % len(eligible)]["id"]

# ---------- receipts ----------

def make_receipt(tid: str, auditor_id: str, origin: str, beacon, result: str,
                 sk: signing.SigningKey) -> dict:
    """A challenger's signed verdict on one (auditor, origin) consumption check.
    `result` is "consumed" when the auditor's verdict provably depends on the
    re-fetched artifact (e.g. perturb it and the vote moves), else "not-consumed"."""
    receipt = {
        "trace_id": tid,
        "auditor_id": auditor_id,
        "origin": origin,
        "beacon": str(beacon),
        "challenger": dbt.did_key(bytes(sk.verify_key)),
        "result": result,
    }
    return sign_obj(receipt, sk)

def verify_receipt(receipt: dict, beacon, trace: dict, pool: list) -> bool:
    """A receipt counts only if every link checks out:
    binds to this trace + beacon, signature verifies, the signer is the challenger the
    beacon actually selected for that (auditor, origin), that challenger is in the pool
    and disjoint from the auditor, and the result is "consumed"."""
    tid = trace_id(trace)
    if receipt.get("trace_id") != tid or str(receipt.get("beacon")) != str(beacon):
        return False
    if receipt.get("result") != "consumed":
        return False
    ch = str(receipt.get("challenger", ""))
    if not verify_obj(receipt, ch):
        return False
    auditors = {str(a.get("id", "")): a for a in (trace.get("audit") or {}).get("auditors", [])}
    auditor = auditors.get(str(receipt.get("auditor_id", "")))
    if auditor is None:
        return False
    if select_challenger(beacon, tid, auditor, receipt.get("origin"), pool) != ch:
        return False
    cm = next((c for c in pool if str(c.get("id", "")) == ch), None)
    return cm is not None and _party_disjoint(cm, auditor)

def consumption_from_challenges(receipts: list, beacon, trace: dict, pool: list) -> set:
    """The ``verified_consumption`` set for {@link dbt.decide} — the (auditor_id, origin)
    pairs backed by a valid, correctly-selected, disjoint, signed "consumed" receipt.
    Pass the result straight to ``decide(verified_consumption=…)``."""
    out = set()
    for r in receipts:
        if verify_receipt(r, beacon, trace, pool):
            out.add((str(r.get("auditor_id", "")).strip().lower(),
                     str(r.get("origin", "")).strip().lower()))
    return out
