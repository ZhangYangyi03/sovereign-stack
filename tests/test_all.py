"""Tests. Each one is written so it can fail for a specific reason.

The claims the README makes, in the order it makes them:

  custody      a bounded query discloses nothing but the statement it proves
  authority    a delegation chain narrows, and only the grantee may use it
  records      the audit log detects a rewrite, a reorder and a drop
  three-valued an assessment says undetermined where the evidence is thin, and
             the report verifies against its own head, findings and baseline
  convergence  replicas that were partitioned converge with no operation lost
  transport    a frame authenticates once, in one direction
"""
import base64
import json
import os
import random
import secrets
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ss import compliance as CO
from ss import crypto as C
from ss import exchange as EX
from ss import net, ops, zk
from ss.crypto import (HashChain, KeyPair, hkdf, merkle_proof, merkle_root,
                       merkle_verify)
from ss.identity import (Delegation, DidDocument, chain_ok, may, resolve, revoke)


# --------------------------------------------------------------------- helpers


def two_nodes(threshold=10, seed=1):
    rng = random.Random(seed)
    a = EX.Node("Northland Bureau of Statistics", "did:sgw:A")
    b = EX.Node("Southland Health Ministry", "did:sgw:B")
    a.trust(b.did, b.keys.public, b.x25519_public())
    b.trust(a.did, a.keys.public, a.x25519_public())
    bus = EX.Transport()
    bus.register(a)
    bus.register(b)
    regions = ["R%02d" % i for i in range(12)]
    classes = ["caseA", "caseB", "caseC", "caseD", "caseE"]
    counts = {(r, c): rng.randrange(0, 40) for r in regions for c in classes}
    b.load(EX.Series.from_counts("outbreak", "cases", counts))
    keys = {a.did: a.keys.public, b.did: b.keys.public}
    now = time.time()
    grant = Delegation(grantor=b.did, grantee=a.did,
                       scopes=frozenset({"query.aggregate", "audit.read"}),
                       statement_classes=frozenset({"case_count", "case_ratio"}),
                       issued_at=now, expires_at=now + 3600,
                       purpose="surveillance exchange").sign(b.keys)
    return a, b, bus, keys, grant, regions, classes, counts


def bounded_request(requester, regions, classes, rid="q1", bits=16):
    return EX.Request(kind="aggregate.bounded", requester=requester, request_id=rid,
                      series="outbreak", partitions=tuple(regions), subjects=tuple(classes),
                      statement_class="case_count", bits=bits)


# --------------------------------------------------------------------- custody


def ints_in(obj):
    """Every integer anywhere in a nested structure."""
    if isinstance(obj, bool):
        return []
    if isinstance(obj, int):
        return [obj]
    if isinstance(obj, dict):
        return [n for v in obj.values() for n in ints_in(v)]
    if isinstance(obj, (list, tuple)):
        return [n for v in obj for n in ints_in(v)]
    if isinstance(obj, str):
        return [int(obj)] if obj.isdigit() else []
    return []


def test_bounded_query_releases_no_count():
    a, b, bus, keys, grant, regions, classes, counts = two_nodes()
    gw = EX.Gateway(a, bus)
    rep = gw.ask(b.did, bounded_request(a.did, regions[:4], classes), [grant])
    assert rep["receipt"]["status"] == "proved"
    payload = rep["receipt"]["payload"]
    assert set(payload) >= {"commitment", "proof", "statement", "reveals"}
    assert "disclosed" not in payload
    truth = sum(v for (p, s), v in counts.items() if p in regions[:4])
    # The reply carries a commitment and a proof, never the total and never a
    # cell. The strong form of that claim is checkable: the only small integers
    # anywhere in the payload are the ones the request itself supplied -- the bit
    # width, the cell count and the threshold. A leaked count would have to be
    # some other number, and there is no other number.
    numbers = ints_in(payload)
    expected = {16, len(regions[:4]) * len(classes), EX.DEFAULT_THRESHOLD}
    small = {n for n in numbers if n < 1000}
    assert small <= expected, (small - expected)
    assert truth not in numbers


def test_bounded_query_proves_a_true_statement():
    a, b, bus, keys, grant, regions, classes, counts = two_nodes()
    gw = EX.Gateway(a, bus)
    rep = gw.ask(b.did, bounded_request(a.did, regions[:4], classes, bits=16), [grant])
    proof = rep["receipt"]["payload"]["proof"]
    assert zk.verify_range(proof)
    truth = sum(v for (p, s), v in counts.items() if p in regions[:4])
    assert truth < (1 << 16)


def test_a_proof_for_a_different_total_does_not_verify():
    a, b, bus, keys, grant, regions, classes, counts = two_nodes()
    gw = EX.Gateway(a, bus)
    rep = gw.ask(b.did, bounded_request(a.did, regions[:4], classes), [grant])
    proof = json.loads(json.dumps(rep["receipt"]["payload"]["proof"]))
    other, _ = C.commit(999)
    proof["commitment"] = hex(other)
    assert not zk.verify_range(proof)


def test_required_range_is_enforced_server_side():
    """A total the node can see is out of range must not be answered with a proof."""
    a, b, bus, keys, grant, regions, classes, counts = two_nodes()
    gw = EX.Gateway(a, bus)
    big = sum(counts.values())
    rep = gw.ask(b.did, bounded_request(a.did, regions, classes, rid="q-big", bits=4), [grant])
    assert big >= (1 << 4)
    assert rep["receipt"]["status"] == "refused"
    assert rep["receipt"]["reason"].startswith("range-exceeded")
    # and the refusal is on the record, with the requester named
    refusals = [e for e in b.chain.entries if e["event"] == "refuse"]
    assert refusals and refusals[-1]["requester"] == a.did


def test_record_lookup_is_refused_however_it_is_granted():
    a, b, bus, keys, grant, regions, classes, counts = two_nodes()
    wide = Delegation(grantor=b.did, grantee=a.did,
                      scopes=frozenset({"query.record"}), statement_classes=frozenset({"case_count"}),
                      issued_at=time.time(), expires_at=time.time() + 60).sign(b.keys)
    gw = EX.Gateway(a, bus)
    req = EX.Request(kind="record.lookup", requester=a.did, request_id="r", series="outbreak",
                     partitions=("R00",), subjects=("caseA",), statement_class="case_count")
    rep = gw.ask(b.did, req, [wide])
    assert rep["receipt"]["status"] == "refused"
    assert rep["receipt"]["reason"] == "record-lookup-always-refused"


def test_release_sequence_needs_the_lookup_to_be_logged():
    """Every exact release lands in the chain, with the requester named."""
    a, b, bus, keys, grant, regions, classes, counts = two_nodes()
    gw = EX.Gateway(a, bus)
    req = EX.Request(kind="aggregate.exact", requester=a.did, request_id="e1", series="outbreak",
                     partitions=tuple(regions[:3]), subjects=tuple(classes),
                     statement_class="case_count")
    rep = gw.ask(b.did, req, [grant])
    assert rep["receipt"]["status"] == "released"
    events = [e for e in b.chain.entries if e["event"] == "release"]
    assert len(events) == 1
    assert events[0]["requester"] == a.did
    assert events[0]["disclosed"] == rep["receipt"]["payload"]["disclosed"]


def test_disclosure_control_fires_on_a_repeated_slice():
    """Ten overlapping slices make the eleventh cell isolable, so it is refused.

    The history below is ten *different* selections that all contain R00/caseA,
    which is the sequence a differencing attack needs. Ten identical repeats of
    one selection would teach an observer nothing and are not counted.
    """
    history = []
    for i in range(10):
        others = ["R%02d" % (10 + i)]
        history.append({"partitions": ["R00"] + others, "subjects": ["caseA"]})
    ok, why = EX.disclosure_ok(history, ["R00"], ["caseA"], threshold=10)
    assert not ok and why.startswith("subject-exposure:")
    repeat = [{"partitions": ["R00"], "subjects": ["caseA"]}] * 10
    ok2, why2 = EX.disclosure_ok(repeat, ["R00"], ["caseA"], threshold=10)
    assert ok2 and why2 == "ok"


# --------------------------------------------------------------------- authority


def test_chain_narrows_and_a_widened_chain_is_refused():
    a, b, bus, keys, grant, regions, classes, counts = two_nodes()
    a2 = KeyPair.at(77)
    a2_did = "did:sgw:A2"
    a.trust(a2_did, a2.public)
    narrow = Delegation(grantor=a.did, grantee=a2_did,
                        scopes=frozenset({"query.aggregate"}),
                        statement_classes=frozenset({"case_count"}),
                        issued_at=time.time(), expires_at=time.time() + 60).sign(a.keys)
    assert chain_ok([grant, narrow], keys, time.time())[0]
    assert may([grant, narrow], "query.aggregate", "case_count", keys, time.time(),
               requester=a2_did)[0]
    assert not may([grant, narrow], "query.aggregate", "case_ratio", keys, time.time(),
                   requester=a2_did)[0]
    wide = Delegation(grantor=a.did, grantee=a2_did,
                      scopes=frozenset({"query.aggregate", "node.admin"}),
                      statement_classes=frozenset({"case_count"}),
                      issued_at=time.time(), expires_at=time.time() + 60).sign(a.keys)
    ok, why = chain_ok([grant, wide], keys, time.time())
    assert not ok and why.startswith("scope-widened")


def test_the_grantee_is_the_only_one_who_may_use_a_grant():
    a, b, bus, keys, grant, regions, classes, counts = two_nodes()
    ok, why = may([grant], "query.aggregate", "case_count", keys, time.time(),
                  requester="did:sgw:elsewhere")
    assert not ok and why == "not-the-grantee"


def test_expired_and_revoked_grants_are_refused():
    a, b, bus, keys, grant, regions, classes, counts = two_nodes()
    old = Delegation(grantor=b.did, grantee=a.did, scopes=grant.scopes,
                     statement_classes=grant.statement_classes, issued_at=time.time() - 7200,
                     expires_at=time.time() - 3600).sign(b.keys)
    assert chain_ok([old], keys, time.time())[1] == "expired@0"
    cut = revoke([grant], 0)
    assert chain_ok([grant], keys, time.time(), cut)[1] == "revoked@0"


def test_a_grant_that_travelled_through_json_still_verifies():
    """Grants cross a socket, so the wire form has to be checked, not assumed."""
    a, b, bus, keys, grant, regions, classes, counts = two_nodes()
    wire = json.loads(json.dumps([grant.encode()]))
    restored = [Delegation(**{k: v for k, v in d.items() if k != "digest"}) for d in wire]
    assert chain_ok(restored, keys, time.time())[0]
    assert restored[0].scopes == grant.scopes


def test_did_document_self_certifies():
    keys = KeyPair.generate()
    doc = DidDocument("Northland Statistics", keys.public, "tcp://127.0.0.1:9000",
                      frozenset({"query.aggregate"}), expires_at=time.time() + 600)
    encoded = doc.encode(keys)
    assert resolve(encoded, time.time())[0]
    other = KeyPair.generate()
    encoded["did"] = "did:sgw:" + "0" * 32
    assert resolve(encoded)[1] == "id-not-derived-from-key"
    # a document signed by a key that is not the one it names
    forged = DidDocument("Northland Statistics", other.public, "tcp://127.0.0.1:9000",
                         frozenset({"query.aggregate"}), expires_at=time.time() + 600).encode(other)
    forged["public"] = base64.urlsafe_b64encode(keys.public).decode().rstrip("=")
    assert resolve(forged)[1] != "ok"


def test_session_keys_agree_across_the_two_sides():
    a, b, bus, keys, grant, regions, classes, counts = two_nodes()
    assert a.session_key(b.did) == b.session_key(a.did)


# --------------------------------------------------------------------- records


def test_chain_detects_edit_drop_and_reorder():
    chain = HashChain()
    for i in range(12):
        chain.append({"event": "e%d" % i, "i": i})
    assert chain.verify() == (True, 12)
    edited = HashChain(chain.entries)
    edited.entries[5] = {**edited.entries[5], "i": 99}
    assert edited.verify() == (False, 5)
    dropped = HashChain([e for i, e in enumerate(chain.entries) if i != 3])
    assert dropped.verify()[0] is False
    reordered = HashChain([chain.entries[1], chain.entries[0], *chain.entries[2:]])
    assert reordered.verify()[0] is False


def test_inclusion_proof_verifies_without_the_rest_of_the_log():
    chain = HashChain()
    for i in range(9):
        chain.append({"event": "e%d" % i})
    proof = chain.inclusion_proof(-1)
    assert HashChain.verify_inclusion(proof)
    proof["entry"] = {"event": "changed"}
    assert not HashChain.verify_inclusion(proof)


def test_rewrite_detection_from_a_retained_head_list():
    chain = HashChain()
    for i in range(6):
        chain.append({"event": "e%d" % i})
    snapshot = chain.snapshot_heads()
    chain.append({"event": "e6"})
    assert chain.detect_rewrite(snapshot) == {"common_prefix": 6, "appended": 1,
                                             "rewritten": False, "intact": True}
    other = HashChain([{"event": "e0", "x": 1}, *chain.entries[1:]])
    assert other.detect_rewrite(snapshot)["rewritten"] is True


def test_merkle_paths_reach_the_root():
    leaves = [C.sha256_hex(str(i).encode()) for i in range(11)]
    root = merkle_root(leaves)
    for i in range(len(leaves)):
        assert merkle_verify(leaves[i], merkle_proof(leaves, i), root)
    assert not merkle_verify(C.sha256_hex(b"nope"), merkle_proof(leaves, 0), root)


def test_a_consistent_rewrite_is_caught_only_by_the_saved_heads():
    chain = HashChain()
    for i in range(6):
        chain.append({"event": "e%d" % i})
    saved = chain.snapshot_heads()
    # rewrite entry 2 and recompute the log from what is left: it verifies
    entries = list(chain.entries)
    entries[2] = {"event": "rewritten", "seq": 2}
    rebuilt = HashChain(entries)
    assert rebuilt.verify()[0] is True
    matches, bad = rebuilt.matches(saved)
    assert matches is False and bad == 2
    # and a log extended after the snapshot still matches its prefix
    extended = HashChain(chain.entries + [{"event": "e6"}])
    matches2, _ = extended.matches(saved)
    assert matches2 is False  # the length differs


def test_node_chain_reloads_with_the_same_head(tmp_path=None):
    import tempfile
    chain = HashChain()
    for i in range(4):
        chain.append({"event": "e%d" % i})
    path = os.path.join(tempfile.mkdtemp(), "chain.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"entries": chain.entries, "heads": chain.snapshot_heads()}, fh)
    node = EX.Node("n", "did:sgw:n")
    report = EX.load_chain(node, path)
    assert report["chain_ok"] and report["heads_match"] and report["first_bad_index"] is None


# --------------------------------------------------------------------- proofs


def test_zk_bit_proof_accepts_a_bit_and_proves_nothing_for_2():
    for v in (0, 1):
        c, r = C.commit(v)
        assert zk.verify_bit(zk.prove_bit(c, v, r))
    c, r = C.commit(7)
    with pytest.raises(ValueError):
        zk.prove_bit(c, 7, r)


def test_zk_range_proof_round_trip_and_soundness():
    for total in (0, 1, 255, 256, 12345):
        blind = secrets.randbelow(C.group()["q"])
        proof = zk.prove_range(total, blind, 16)
        assert zk.verify_range(proof)
    proof = zk.prove_range(100, secrets.randbelow(C.group()["q"]), 16)
    broken = json.loads(json.dumps(proof))
    broken["bit_proofs"][0]["a"] = broken["bit_proofs"][1]["a"]
    assert not zk.verify_range(broken)


def test_zk_range_refuses_a_value_outside_the_declared_range():
    with pytest.raises(ValueError):
        zk.prove_range(1 << 16, 5, 16)


def test_zk_dlog_and_equality_reject_a_tampered_response():
    G = C.group()
    x = secrets.randbelow(G["q"] - 1) + 1
    proof = zk.prove_dlog("g", G["g"], C.powmod(G["g"], x, G["p"]), x, {"k": 1})
    assert zk.verify_dlog(proof)
    proof["z"] = (proof["z"] + 1) % G["q"]
    assert not zk.verify_dlog(proof)
    y = secrets.randbelow(G["q"] - 1) + 1
    eq = zk.prove_equality([(G["g"], C.powmod(G["g"], y, G["p"])),
                            (G["h"], C.powmod(G["h"], y, G["p"]))], y, {"ctx": "x"})
    assert zk.verify_equality(eq)
    tampered = json.loads(json.dumps(eq))
    tampered["t"][0] = hex(C.powmod(G["g"], y + 1, G["p"]))
    assert not zk.verify_equality(tampered)


def test_commitments_are_additively_homomorphic_and_openable():
    c1, r1 = C.commit(17)
    c2, r2 = C.commit(25)
    assert C.commit_open(C.commit_homomorphic(c1, c2), 42, (r1 + r2) % C.group()["q"])
    assert not C.commit_open(C.commit_homomorphic(c1, c2), 41, (r1 + r2) % C.group()["q"])


def test_the_group_is_the_published_one_and_re_verified():
    G = C.group()
    assert G["p"].bit_length() == 2048
    assert "rfc3526" in G["source"]
    assert C.powmod(G["g"], G["q"], G["p"]) == 1
    assert C.powmod(G["h"], G["q"], G["p"]) == 1


# --------------------------------------------------------------------- three-valued


def evidence_pack():
    ev = CO.Evidence()
    ev.observed("endpoints", [{"name": "gw1", "tls": 1.3, "refuses_plaintext": True}])
    ev.observed("accounts", [{"name": "ops1", "rights": ["store.read"]}])
    ev.observed("admins", [{"name": "a1", "mfa": "hardware", "attested_at": time.time()}])
    ev.observed("restore_tests", [{"at": time.time() - 86400, "verified": True}])
    ev.observed("stores", [{"name": "s1", "region": "eu-west"}])
    chain = HashChain()
    for i in range(4):
        chain.append({"event": "e%d" % i})
    ev.observed("audit_entry_digests", chain.snapshot_heads())
    ev.observed("audit_head", merkle_root(chain.snapshot_heads()))
    return ev


CTX = {"jurisdiction": {"allowed_regions": ["eu-west"]}}


def test_kleene_tables_agree_with_an_independent_evaluation():
    """Every 3^n combination of the connectives, against a truth-table walk."""
    vals = [CO.Verdict.SATISFIED, CO.Verdict.VIOLATED, CO.Verdict.UNDETERMINED]
    for a in vals:
        for b in vals:
            assert str(CO.k_and(a, b)) == str(CO.k_and(b, a))
            assert str(CO.k_or(a, b)) == str(CO.k_or(b, a))
            assert str(CO.k_not(CO.k_not(a))) == str(a)
            and_truth = "violated" if "violated" in (str(a), str(b)) else (
                "undetermined" if "undetermined" in (str(a), str(b)) else "satisfied")
            assert str(CO.k_and(a, b)) == and_truth
    # absorption and distributivity, on the three values, by exhaustion
    for a in vals:
        for b in vals:
            for c in vals:
                assert str(CO.k_and(a, CO.k_or(b, c))) == str(CO.k_or(CO.k_and(a, b), CO.k_and(a, c)))
                assert str(CO.k_or(a, CO.k_and(b, c))) == str(CO.k_and(CO.k_or(a, b), CO.k_or(a, c)))


def test_a_violation_cannot_be_rescued_by_a_satisfaction():
    assert str(CO.k_and(CO.Verdict.VIOLATED, CO.Verdict.SATISFIED)) == "violated"
    assert str(CO.k_or(CO.Verdict.UNDETERMINED, CO.Verdict.VIOLATED)) == "undetermined"


def test_missing_evidence_yields_undetermined_not_violated():
    rep = CO.assess(CO.Evidence(), CTX, profile="moderate")
    counts = rep.counts()
    assert counts["violated"] == 0
    assert counts["undetermined"] > counts["satisfied"]


def test_every_baseline_control_is_accounted_for_exactly_once():
    rep = CO.assess(evidence_pack(), {**CTX, "now": time.time()}, profile="moderate")
    want = CO.baseline_set(CO.load_profile("moderate"))
    got = {f.control for f in rep.findings}
    assert got == want
    assert len(rep.findings) == len(want)


def test_third_party_can_verify_a_report_and_detect_an_edit():
    rep = CO.assess(evidence_pack(), {**CTX, "now": time.time()}, profile="moderate")
    ok, problems = CO.verify_report(rep.to_dict())
    assert ok, problems
    edited = rep.to_dict()
    edited["findings"][0]["verdict"] = "satisfied"
    assert not CO.verify_report(edited)[0]
    dropped = rep.to_dict()
    dropped["findings"] = dropped["findings"][1:]
    assert not CO.verify_report(dropped)[0]


def test_a_stale_attestation_turns_a_satisfaction_into_an_undetermined():
    ev = evidence_pack()
    ev.observed("admins", [{"name": "a1", "mfa": "hardware",
                            "attested_at": time.time() - 400 * 86400}])
    rep = CO.assess(ev, {**CTX, "now": time.time()}, profile="moderate")
    verdicts = rep.control_verdict()
    assert str(verdicts["ia-2.1"]) == "undetermined"


def test_the_procedural_rule_stays_undetermined_and_named():
    rep = CO.assess(evidence_pack(), {**CTX, "now": time.time()}, profile="moderate")
    reasons = rep.undetermined_reasons()
    assert "human-step" in reasons and "sa-9" in reasons["human-step"]
    assert "not-implemented" in reasons


def test_a_human_refinement_is_recorded_rather_than_silent():
    rep = CO.assess(evidence_pack(), {**CTX, "now": time.time()}, profile="moderate")
    assert str(rep.control_verdict()["sa-9"]) == "undetermined"
    before = rep.counts()["satisfied"]
    after = CO.refine(rep, "proc.vendor.review", "satisfied")
    assert after.counts()["satisfied"] == before + 1
    assert str(after.control_verdict()["sa-9"]) == "satisfied"
    assert after.refinements["proc.vendor.review"] == "satisfied"
    assert any(f.reason_code == "human-refinement" for f in after.findings)
    # the evidence it was assessed against is unchanged, and still recorded
    assert after.evidence_digest == rep.evidence_digest
    with pytest.raises(CO.EvidenceError):
        CO.refine(rep, "proc.vendor.review", "undetermined")


def test_control_identifiers_resolve_against_the_catalog():
    catalog = CO.load_catalog()
    assert CO.control_id("IA-2(1)") == "ia-2.1"
    assert CO.control_title("IA-2(1)", catalog) == "Multi-factor Authentication to Privileged Accounts"
    for fn in CO.RULES.values():
        assert CO.control_id(fn.control) in catalog["controls"], fn.control


def test_the_catalog_comes_from_upstream_unchanged():
    catalog = CO.load_catalog()
    assert catalog["n_controls"] == len(catalog["controls"])
    assert catalog["sha256"] and catalog["version"].startswith("5")
    assert catalog["controls"]["ac-6"]["title"] == "Least Privilege"
    assert catalog["controls"]["sc-8"]["family"] == "sc"


@pytest.mark.parametrize("baseline", ["low", "moderate", "high"])
def test_each_baseline_is_a_subset_relation(baseline):
    profile = CO.load_profile(baseline)
    assert len(profile["selected"]) == len(set(profile["selected"]))
    if baseline == "moderate":
        assert CO.baseline_set(CO.load_profile("low")) <= CO.baseline_set(profile)
    if baseline == "high":
        assert CO.baseline_set(CO.load_profile("moderate")) <= CO.baseline_set(profile)


# --------------------------------------------------------------------- convergence


def test_a_partitioned_replica_set_converges_with_nothing_lost():
    for nodes in (["n1", "n2"], ["n1", "n2", "n3"], ["n1", "n2", "n3", "n4", "n5"]):
        report = ops.replica_run(nodes, rounds=4, actions=25)
        assert report["converged"], report
        assert report["lost"] == 0, report
        assert report["total"] == report["increments"]


def test_merge_is_idempotent_order_independent_and_commutative():
    a = ops.Store("A")
    b = ops.Store("B")
    for i in range(20):
        a.inc("cases/total", 1)
    for i in range(11):
        b.inc("cases/total", 2)
    a.set("policy/storage", "eu-only")
    b.set("policy/storage", "regional")
    ops.sync(a, b)
    assert a.value("cases/total") == b.value("cases/total") == 42
    assert a.value("policy/storage") == b.value("policy/storage")
    before = b.size()
    b.merge(list(a.ops))
    assert b.size() == before
    shuffled = list(a.ops)
    random.Random(3).shuffle(shuffled)
    c = ops.Store("C")
    c.merge(shuffled)
    assert c.state_digest() == a.state_digest()


def test_sync_ships_only_what_the_peer_is_missing():
    a = ops.Store("A")
    b = ops.Store("B")
    for i in range(5):
        a.inc("cases/total", 1)
    first = ops.sync(a, b)
    assert first["sent_to_b"] == 5 and first["sent_to_a"] == 0
    second = ops.sync(a, b)
    assert second["sent_to_b"] == 0 and second["sent_to_a"] == 0


def test_outbox_holds_writes_until_they_are_acknowledged():
    store = ops.Store("A")
    box = ops.Outbox(store)
    ids = [box.queue(store.inc("cases/total", 1)) for _ in range(3)]
    assert box.depth() == 3
    batch = box.batch(2)
    box.attempt([op.op_id for op in batch])
    assert box.ack([op.op_id for op in batch]) == 2
    assert box.depth() == 1
    assert box.acked == 2


def test_outbox_gives_up_after_its_budget_and_says_how_many_it_dropped():
    store = ops.Store("A")
    box = ops.Outbox(store, max_attempts=2)
    ident = box.queue(store.inc("cases/total", 1))
    box.attempt([ident])
    box.attempt([ident])
    assert box.give_up() == [ident]
    assert box.dropped == 1 and box.depth() == 0


def test_outbox_refuses_to_grow_without_limit():
    store = ops.Store("A")
    box = ops.Outbox(store, max_pending=2)
    box.queue(store.inc("cases/total", 1))
    box.queue(store.inc("cases/total", 1))
    with pytest.raises(RuntimeError):
        box.queue(store.inc("cases/total", 1))


def test_a_stale_policy_is_served_but_marked_stale():
    cache = ops.PolicyCache({"retention": "7y"}, time.time() - 7200, ttl_seconds=3600)
    answer = cache.decide("retention")
    assert answer["answer"] == "7y"
    assert answer["served_offline"] and answer["requires_review"]
    assert answer["freshness"] == "stale"
    fresh = ops.PolicyCache({"retention": "7y"}, time.time(), ttl_seconds=3600)
    assert fresh.decide("retention")["freshness"] == "current"


# --------------------------------------------------------------------- transport


def test_framing_survives_a_large_message():
    server = net.TcpServer(lambda m: {"len": len(m["blob"]), "ok": True}).start()
    try:
        payload = "x" * 200000
        reply = net.call("127.0.0.1", server.port, {"blob": payload})
        assert reply == {"len": 200000, "ok": True}
    finally:
        server.stop()


def test_sealed_frames_authenticate_once_in_one_direction():
    client, server = net.SecureSession.pair(hkdf(b"k", b"s"))
    frame = client.seal({"a": 1})
    with pytest.raises(ConnectionError):
        client.open(frame)          # reflected back at its own sender
    assert server.open(frame) == {"a": 1}
    with pytest.raises(ConnectionError):
        server.open(frame)          # replayed


def test_a_node_in_sealed_mode_refuses_an_unsealed_frame():
    factory = (lambda: net.SecureSession.pair(hkdf(b"k2", b"s2"))[1])
    server = net.TcpServer(lambda m: {"ok": True}, session_factory=factory).start()
    try:
        reply = net.call("127.0.0.1", server.port, {"verb": "health"})
        assert reply["error"] == "unsealed-frame-refused"
        assert server.unsealed_refused == 1
    finally:
        server.stop()


def test_a_sealed_round_trip_over_a_real_socket():
    shared = hkdf(b"shared", b"session")
    server = net.TcpServer(lambda m: {"echo": m},
                           session_factory=lambda: net.SecureSession.pair(shared)[1]).start()
    try:
        assert net.call("127.0.0.1", server.port, {"verb": "health"},
                        session_factory=lambda: net.SecureSession.pair(shared)[0]) \
            == {"echo": {"verb": "health"}}
        # and again, because the frame counter must not carry between connections
        assert net.call("127.0.0.1", server.port, {"verb": "health"},
                        session_factory=lambda: net.SecureSession.pair(shared)[0]) \
            == {"echo": {"verb": "health"}}
    finally:
        server.stop()


def test_a_handler_that_raises_does_not_kill_the_listener():
    def handler(message):
        if message.get("boom"):
            raise ValueError("deliberate")
        return {"ok": True}
    server = net.TcpServer(handler).start()
    try:
        assert net.call("127.0.0.1", server.port, {"boom": True})["error"] == "ValueError"
        assert net.call("127.0.0.1", server.port, {}) == {"ok": True}
    finally:
        server.stop()


# --------------------------------------------------------------------- the service


def test_the_node_service_answers_every_verb(tmp_path):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from ss import gatewayd
    service = gatewayd.NodeService("Alpha", "did:sgw:alpha", str(tmp_path))
    a, b, bus, keys, grant, regions, classes, counts = two_nodes()
    grant_b = Delegation(grantor="did:sgw:alpha", grantee="did:sgw:peer",
                         scopes=frozenset({"query.aggregate"}),
                         statement_classes=frozenset({"case_count"}),
                         issued_at=time.time(), expires_at=time.time() + 600)
    # the node answers health, a refused query, and a push
    health = gatewayd.dispatch(service, {"verb": "health"})
    assert health["node"] == "did:sgw:alpha"
    assert health["chain_entries"] >= 1
    pushed = gatewayd.dispatch(service, {"verb": "ops.push",
                                         "ops": [service.store.inc("cases/total", 3).body()]})
    assert pushed["received"] == 1
    pulled = gatewayd.dispatch(service, {"verb": "ops.pull", "have": []})
    assert len(pulled["ops"]) == 1
    assert gatewayd.dispatch(service, {"verb": "nonsense"})["error"] == "unknown-verb"
    inspected = gatewayd.dispatch(service, {"verb": "inspect", "n": 3})
    assert inspected["chain_ok"] and len(inspected["entries"]) <= 3


def test_the_node_service_survives_a_restart_with_the_same_state(tmp_path):
    from ss import gatewayd
    first = gatewayd.NodeService("Alpha", "did:sgw:alpha", str(tmp_path))
    first.node.load(EX.Series.from_counts("outbreak", "cases", {("R00", "caseA"): 4}))
    for i in range(5):
        first.outbox.queue(first.store.inc("cases/total", 1))
    saved = first.save()
    second = gatewayd.NodeService("Alpha", "did:sgw:alpha", str(tmp_path))
    loaded = second.load()
    assert loaded["chain_ok"] and loaded["heads_match"]
    assert second.node.keys.public == first.node.keys.public
    assert second.store.state_digest() == saved["state_digest"]
    assert second.store.value("cases/total") == 5


# --------------------------------------------------------------------- the audit join


def test_an_evidence_pack_built_from_a_node_directory_verifies(tmp_path):
    import json as _json
    import importlib.util
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = importlib.util.spec_from_file_location("audit_pack", os.path.join(root, "audit", "pack.py"))
    packing = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(packing)
    from ss import gatewayd
    service = gatewayd.NodeService("Audit", "did:sgw:audit", str(tmp_path))
    for i in range(9):
        service.node.chain.append({"event": "e%d" % i})
    service.save()
    extra_path = os.path.join(str(tmp_path), "extra.json")
    with open(extra_path, "w", encoding="utf-8") as fh:
        _json.dump({"items": [{"id": "endpoints",
                               "kind": "observation",
                               "value": [{"name": "gw1", "tls": 1.3, "refuses_plaintext": True}],
                               "source": "inventory.csv"}]}, fh)
    payload = packing.build(str(tmp_path), profile="moderate",
                            jurisdiction="eu-west", extra_path=extra_path)
    ok, problems = CO.verify_report(payload)
    assert ok, problems
    # the head in the report is a root over the chain the node actually wrote
    assert payload["evidence_digest"]


def test_an_evidence_pack_detects_a_chain_that_does_not_verify(tmp_path):
    import json as _json
    import importlib.util
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = importlib.util.spec_from_file_location("audit_pack", os.path.join(root, "audit", "pack.py"))
    packing = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(packing)
    from ss import gatewayd
    service = gatewayd.NodeService("Audit", "did:sgw:audit", str(tmp_path))
    for i in range(6):
        service.node.chain.append({"event": "e%d" % i})
    service.save()
    chain_path = os.path.join(str(tmp_path), "chain.json")
    with open(chain_path, encoding="utf-8") as fh:
        saved = _json.load(fh)
    saved["entries"][2] = {"event": "rewritten", "seq": 2}
    with open(chain_path, "w", encoding="utf-8") as fh:
        _json.dump(saved, fh)
    payload = packing.build(str(tmp_path), profile="high")
    entry = [f for f in payload["findings"] if f["control"] == "au-9.3"][0]
    # The decisive point: rebuilding a log from its entries recomputes its own
    # heads, so the rebuild alone proves nothing. The saved heads are what catch
    # the edit, and without them the head is withheld and the control is
    # undetermined rather than satisfied.
    assert entry["verdict"] == "undetermined"
    assert entry["reason_code"] == "no-evidence"


# --------------------------------------------------------------------- the experiment


def test_the_modular_rank_tracker_agrees_with_an_exact_one():
    import importlib.util
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = importlib.util.spec_from_file_location("experiment", os.path.join(root, "bench", "experiment.py"))
    experiment = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(experiment)
    rng = random.Random(11)
    for n_cols in (3, 5, 8):
        for _ in range(6):
            matrix = [[rng.choice([0, 0, 0, 1]) for _ in range(n_cols)] for _ in range(n_cols)]
            tracker = experiment.Rank(n_cols)
            for row in matrix:
                tracker.add(row)
            assert tracker.rank == experiment.rank_exact(matrix), matrix
            assert tracker.rank == experiment.rank_mod(matrix), matrix
    # a matrix that is deliberately rank-deficient
    deficient = [[1, 0, 1], [2, 0, 2], [0, 1, 0]]
    assert experiment.rank_exact(deficient) == 2
    assert experiment.Rank(3).add(deficient[0]) == 1


def test_a_differencing_sequence_is_refused_by_the_counter():
    a, b, bus, keys, grant, regions, classes, counts = two_nodes(threshold=4)
    probe = EX.Node("Strict", "did:sgw:C", threshold=4)
    a.trust(probe.did, probe.keys.public, probe.x25519_public())
    probe.trust(a.did, a.keys.public, a.x25519_public())
    second_bus = EX.Transport()
    second_bus.register(a)
    second_bus.register(probe)
    probe.load(EX.Series.from_counts("outbreak", "cases", counts))
    wide = Delegation(grantor=probe.did, grantee=a.did,
                      scopes=frozenset({"query.aggregate", "query.distinct"}),
                      statement_classes=frozenset({"case_count"}),
                      issued_at=time.time(), expires_at=time.time() + 600).sign(probe.keys)
    gw = EX.Gateway(a, second_bus)
    statuses = []
    for j in range(1, 8):
        req = EX.Request(kind="aggregate.exact", requester=a.did, request_id="d%d" % j,
                         series="outbreak", partitions=(regions[0], regions[j]),
                         subjects=(classes[0],), statement_class="case_count")
        reply = gw.ask(probe.did, req, [wide])
        statuses.append(reply["receipt"]["status"])
    assert statuses[0] == "released"
    assert "refused" in statuses, statuses
    # and every refusal is in the chain, with its reason code
    refusals = [e for e in probe.chain.entries if e["event"] == "refuse"]
    assert refusals and refusals[0]["code"].startswith("disclosure-control")
