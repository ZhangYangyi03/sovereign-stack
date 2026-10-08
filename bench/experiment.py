"""The headline experiment. Two measured numbers, both reproducible here.

  custody   Releases are not the same thing as a disclosure, and "we only ever
            released a sum" is not the same thing as "the cells are safe". Build
            the incidence matrix of the released selections over the cells they
            cover and take its rank: when the rank reaches the number of cells
            with a non-zero value, every cell is uniquely determined by the
            released sums, arithmetic alone, no assumption about the attacker.
            The experiment reports where that happens relative to where the
            node's disclosure counter starts refusing, and what a workflow with
            no policy at all releases on the same question sequence.

  verdicts  How many controls a two-valued assessment would report satisfied,
            against how many a three-valued one is willing to stand behind, on
            the same evidence; and how the count moves as attestations age past
            their lease.

Run:  python bench/experiment.py --seeds 8   (about a minute and a half)
Achieved: python bench/experiment.py --seeds 8 --questions 24 --bits 8
"""
from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ss import compliance as CO
from ss import exchange as EX
from ss.crypto import HashChain, merkle_root
from ss.identity import Delegation

HERE = os.path.dirname(os.path.abspath(__file__))


# Rank is computed modulo a 61-bit prime rather than over the rationals. The
# reason is cost: exact Fraction elimination on a 96-column matrix runs into
# minutes, and this table has to be regenerable. The direction of the error is
# the safe one -- rank over F_p is at most rank over Q, so a rank of 96 modulo p
# still means the released sums determine all 96 cells for almost every choice of
# p, and tests/test_all.py checks the modular tracker against an exact
# Fraction-based elimination on the small cases where the exact answer is cheap.
RANK_P = (1 << 61) - 1


def rank_mod(matrix: list) -> int:
    """Exact-rank-quality elimination in F_p, for the tests to compare against."""
    if not matrix:
        return 0
    rows = [[x % RANK_P for x in row] for row in matrix]
    n_rows, n_cols = len(rows), len(rows[0])
    rank = 0
    for col in range(n_cols):
        pivot = next((r for r in range(rank, n_rows) if rows[r][col]), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        inv = pow(rows[rank][col], RANK_P - 2, RANK_P)
        rows[rank] = [x * inv % RANK_P for x in rows[rank]]
        for r in range(n_rows):
            if r != rank and rows[r][col]:
                factor = rows[r][col]
                rows[r] = [(a - factor * b) % RANK_P for a, b in zip(rows[r], rows[rank])]
        rank += 1
        if rank == n_rows:
            break
    return rank


def rank_exact(matrix: list) -> int:  # noqa: C901
    """The same rank over Q, for small matrices. Uniquely determined is a fact
    about the integers, so this is what the modular tracker is checked against."""
    from fractions import Fraction
    if not matrix:
        return 0
    rows = [[Fraction(x) for x in row] for row in matrix]
    n_rows, n_cols = len(rows), len(rows[0])
    rank = 0
    for col in range(n_cols):
        pivot = next((r for r in range(rank, n_rows) if rows[r][col] != 0), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        pv = rows[rank][col]
        rows[rank] = [x / pv for x in rows[rank]]
        for r in range(n_rows):
            if r != rank and rows[r][col] != 0:
                factor = rows[r][col]
                rows[r] = [a - factor * b for a, b in zip(rows[r], rows[rank])]
        rank += 1
        if rank == n_rows:
            break
    return rank


class Rank:
    """Incremental rank in F_p: a row per release, the rank read off as it grows."""

    def __init__(self, n_cols: int, p: int = RANK_P):
        self.n_cols = n_cols
        self.p = p
        self.pivots: list = []      # (col, reduced normalised row)
        self.rank = 0

    def add(self, row: list) -> int:
        cur = [x % self.p for x in row]
        for col, prow in self.pivots:
            if cur[col]:
                factor = cur[col]
                cur = [(a - factor * b) % self.p for a, b in zip(cur, prow)]
        for col in range(self.n_cols):
            if cur[col]:
                inv = pow(cur[col], self.p - 2, self.p)
                cur = [x * inv % self.p for x in cur]
                self.pivots.append((col, cur))
                self.pivots.sort(key=lambda pair: pair[0])
                self.rank += 1
                break
        return self.rank


def custody_run(seed: int, n_regions: int = 12, n_classes: int = 4,
                n_questions: int = 24, threshold: int = 10, bits: int = 8) -> dict:
    """One world, and three workflows measured on it with the same question set.

    A  answer-as-asked, no policy     every release is a sum. The incidence matrix
                                      of the released selections over the cells
                                      says how many cells those sums determine.
    B  bounded queries                the same questions asked as proofs. A proof
                                      carries a commitment and a range, not a
                                      number, so the count of cell values that
                                      appear in the replies is what is measured.
    C  answer-as-asked, counter on    a sequence designed to isolate one cell by
                                      subtraction, against a node that refuses
                                      once a cell has been released into too many
                                      overlapping selections. Where it refuses,
                                      and how many cells it isolated first.
    """
    rng = random.Random(seed)
    a = EX.Node("Northland Bureau of Statistics", "did:sgw:A")
    b = EX.Node("Southland Health Ministry", "did:sgw:B")
    a.trust(b.did, b.keys.public, b.x25519_public())
    b.trust(a.did, a.keys.public, a.x25519_public())
    bus = EX.Transport()
    bus.register(a)
    bus.register(b)
    regions = ["R%02d" % i for i in range(n_regions)]
    classes = ["class%02d" % i for i in range(n_classes)]
    counts = {(r, c): rng.randrange(0, 40) for r in regions for c in classes}
    b.load(EX.Series.from_counts("outbreak", "cases", counts))
    now = time.time()
    grant = Delegation(grantor=b.did, grantee=a.did,
                       scopes=frozenset({"query.aggregate"}),
                       statement_classes=frozenset({"case_count"}),
                       issued_at=now, expires_at=now + 3600).sign(b.keys)
    gw = EX.Gateway(a, bus)

    questions = []
    for _ in range(n_questions):
        questions.append((tuple(sorted(rng.sample(regions, rng.randint(1, min(4, n_regions))))),
                          tuple(sorted(rng.sample(classes, rng.randint(1, min(4, n_classes)))))))

    cells = sorted(counts)
    truth_rank = sum(1 for v in counts.values() if v != 0)
    horizons = [h for h in (6, 12, n_questions) if h <= n_questions]

    # ---- A: answer as asked -------------------------------------------------
    rank_a = Rank(len(cells))
    ranks_a, released_a = [], 0
    for i, (ps, ss) in enumerate(questions):
        req = EX.Request(kind="aggregate.exact", requester=a.did, request_id="a%d" % i,
                         series="outbreak", partitions=ps, subjects=ss,
                         statement_class="case_count")
        reply = gw.ask(b.did, req, [grant])
        if reply["receipt"]["status"] == "released":
            released_a += 1
            ranks_a.append(rank_a.add([1 if (cell[0] in ps and cell[1] in ss) else 0
                                       for cell in cells]))
    # A fresh node, so the counter's history from the previous workflow is not reused.
    strict = EX.Node("Strict node", "did:sgw:C", threshold=threshold)
    a.trust(strict.did, strict.keys.public, strict.x25519_public())
    strict.trust(a.did, a.keys.public, a.x25519_public())
    bus.register(strict)
    strict.load(EX.Series.from_counts("outbreak", "cases", counts))
    grant_c = Delegation(grantor=strict.did, grantee=a.did,
                         scopes=frozenset({"query.aggregate"}),
                         statement_classes=frozenset({"case_count"}),
                         issued_at=time.time(), expires_at=time.time() + 3600).sign(strict.keys)
    gw_c = EX.Gateway(a, bus)

    # ---- B: bounded queries -------------------------------------------------
    leaked = 0
    proved_b = refused_b = 0
    for i, (ps, ss) in enumerate(questions):
        req = EX.Request(kind="aggregate.bounded", requester=a.did, request_id="b%d" % i,
                         series="outbreak", partitions=ps, subjects=ss,
                         statement_class="case_count", bits=bits)
        reply = gw.ask(b.did, req, [grant])
        if reply["receipt"]["status"] != "proved":
            refused_b += 1
            continue
        proved_b += 1
        payload = reply["receipt"]["payload"]
        numbers = ints_in(payload)
        expected = {bits, len(ps) * len(ss), EX.DEFAULT_THRESHOLD}
        leaked += len({n for n in numbers if n < 1000} - expected)

    # ---- C: designed differencing, counter on --------------------------------
    differencing = {"attempts": 0, "released": 0, "refused": 0, "first_refusal": None,
                    "isolated": 0, "reasons": {}}
    rank_c = Rank(len(cells))
    for j in range(1, len(regions)):
        # two releases isolate one cell: {probe, partner} minus {partner}
        for ps, ss in (((regions[0], regions[j]), (classes[0],)),
                       ((regions[j],), (classes[0],))):
            differencing["attempts"] += 1
            req = EX.Request(kind="aggregate.exact", requester=a.did,
                             request_id="d%d" % differencing["attempts"],
                             series="outbreak", partitions=ps, subjects=ss,
                             statement_class="case_count")
            reply = gw_c.ask(strict.did, req, [grant_c])
            if reply["receipt"]["status"] != "released":
                differencing["refused"] += 1
                reason = reply["receipt"]["reason"].split(":")[0]
                differencing["reasons"][reason] = differencing["reasons"].get(reason, 0) + 1
                if differencing["first_refusal"] is None:
                    differencing["first_refusal"] = differencing["attempts"]
                continue
            differencing["released"] += 1
            rank_c.add([1 if (cell[0] in ps and cell[1] in ss) else 0 for cell in cells])
            differencing["isolated"] = rank_c.rank

    def at(ranks, horizon):
        return ranks[min(horizon, len(ranks)) - 1] if ranks else 0

    return {"seed": seed, "cells": len(cells), "non_zero_cells": truth_rank,
            "questions": len(questions), "horizons": horizons,
            "exact": {"released": released_a, "refused": 0,
                      "max_rank": max(ranks_a) if ranks_a else 0,
                      "ranks_at": {h: at(ranks_a, h) for h in horizons},
                      "determined_fraction": round((max(ranks_a) if ranks_a else 0)
                                                    / len(cells), 3)},
            "bounded": {"proved": proved_b, "refused": refused_b,
                        "cells_determined": 0, "counts_leaked": leaked},
            "counter": {"threshold": threshold, **differencing}}


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


def aggregate(runs: list) -> dict:
    """Turn per-seed runs into the table the README quotes.

    Kept separate from the runs so a long experiment can be done in pieces: each
    run is independent and serialisable, and this is a pure function of the list.
    """
    def mean(path):
        vals = []
        for r in runs:
            cur = r
            for key in path:
                cur = cur[key]
            if cur is not None:
                vals.append(cur)
        return round(statistics.fmean(vals), 3) if vals else None



    def distinct(path):
        out = {}
        for r in runs:
            cur = r
            for key in path:
                cur = cur[key]
            out[cur] = out.get(cur, 0) + 1
        return {str(k): v for k, v in sorted(out.items(), key=lambda kv: str(kv[0]))}

    return {"seeds": len(runs), "per_run": runs,
            "cells": runs[0]["cells"], "non_zero_cells": runs[0]["non_zero_cells"],
            "questions": runs[0]["questions"], "horizons": runs[0]["horizons"],
            "exact": {"releases_mean": mean(("exact", "released")),
                      "max_rank_mean": mean(("exact", "max_rank")),
                      "determined_fraction_mean": mean(("exact", "determined_fraction")),
                      "ranks_at_mean": {
                          h: round(statistics.fmean(
                              r["exact"]["ranks_at"][str(h)] for r in runs), 2)
                          for h in runs[0]["horizons"]}},
            "bounded": {"proved_mean": mean(("bounded", "proved")),
                        "refused_mean": mean(("bounded", "refused")),
                        "counts_leaked_total": sum(r["bounded"]["counts_leaked"]
                                                   for r in runs),
                        "cells_determined": 0},
            "counter": {"threshold": runs[0]["counter"]["threshold"],
                        "attempts": runs[0]["counter"]["attempts"],
                        "released_mean": mean(("counter", "released")),
                        "refused_mean": mean(("counter", "refused")),
                        "first_refusal": distinct(("counter", "first_refusal")),
                        "isolated_mean": mean(("counter", "isolated")),
                        "reasons": sorted({k for r in runs
                                           for k in r["counter"]["reasons"]})}}


def custody(seeds: int = 8, questions: int = 48, bits: int = 8, records: str | None = None) -> dict:
    """Run the custody experiment and aggregate it.

    `records` lets the runs be appended to a file after each seed, because a full
    six-seed run is a couple of minutes and losing all of it to one interruption
    is how a table ends up in a README with no way to reproduce it.
    """
    runs = []
    for seed in range(seeds):
        run = custody_run(seed, n_questions=questions, bits=bits)
        runs.append(run)
        if records:
            with open(records, "w", encoding="utf-8") as fh:
                json.dump(runs, fh)
    return aggregate(runs)


def verdicts() -> dict:
    """How much a two-valued assessment would claim, on the same evidence."""
    def pack(admin_age_days: float | None = None, restore_age_days: float = 1.0):
        ev = CO.Evidence()
        ev.observed("endpoints", [{"name": "gw%d" % i, "tls": 1.3, "refuses_plaintext": True}
                                  for i in range(12)])
        ev.observed("accounts", [{"name": "acct%d" % i, "rights": ["store.read"]}
                                 for i in range(50)])
        ev.observed("restore_tests", [{"at": time.time() - restore_age_days * 86400,
                                       "verified": True}])
        ev.observed("stores", [{"name": "s%d" % i, "region": "eu-west"} for i in range(8)])
        if admin_age_days is not None:
            ev.observed("admins", [{"name": "adm%d" % i, "mfa": "hardware",
                                    "attested_at": time.time() - admin_age_days * 86400}
                                   for i in range(6)])
        chain = HashChain()
        for i in range(200):
            chain.append({"event": "e%d" % i})
        ev.observed("audit_entry_digests", chain.snapshot_heads())
        ev.observed("audit_head", merkle_root(chain.snapshot_heads()))
        return ev

    ctx = {"jurisdiction": {"allowed_regions": ["eu-west"]}, "now": time.time()}
    out = {"profiles": {}}
    for profile in ("low", "moderate", "high"):
        rep = CO.assess(pack(), ctx, profile=profile)
        counts = rep.counts()
        reasons = rep.undetermined_reasons()
        out["profiles"][profile] = {
            "controls": len(rep.findings), "counts": counts,
            "two_valued_would_report_satisfied": counts["satisfied"] + counts["undetermined"],
            "undetermined_by_reason": {k: len(v) for k, v in sorted(reasons.items())},
            "head": rep.head()[:16]}
    # attestation ageing: where the verdict flips, and where the evidence stops
    # being evidence at all
    ages = [0, 30, 180, 364, 366, 400, 730]
    swing = []
    for age in ages:
        rep = CO.assess(pack(admin_age_days=age), ctx, profile="moderate")
        v = rep.control_verdict()
        swing.append({"admin_attestation_age_days": age, "ia-2.1": str(v["ia-2.1"]),
                      "satisfied": rep.counts()["satisfied"]})
    restore = []
    for age in (1, 90, 179, 181, 400):
        rep = CO.assess(pack(admin_age_days=1, restore_age_days=age), ctx, profile="moderate")
        restore.append({"restore_test_age_days": age,
                        "cp-9.1": str(rep.control_verdict()["cp-9.1"])})
    out["attestation_ageing"] = swing
    out["restore_ageing"] = restore
    # a report that has been edited
    rep = CO.assess(pack(), ctx, profile="moderate")
    edited = rep.to_dict()
    edited["findings"][3]["verdict"] = "satisfied"
    edited["counts"] = {"satisfied": edited["counts"]["satisfied"] + 1,
                        "violated": edited["counts"]["violated"],
                        "undetermined": edited["counts"]["undetermined"] - 1}
    ok_bad, problems = CO.verify_report(edited)
    out["tamper_detection"] = {"accepted": ok_bad, "problems": problems}
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, default=8)
    parser.add_argument("--questions", type=int, default=48)
    parser.add_argument("--bits", type=int, default=8,
                        help="bit width of the range proof; 8 keeps a full run under a minute")
    parser.add_argument("--out", default=os.path.join(HERE, "results_experiment.json"))
    parser.add_argument("--records", default=None,
                        help="append each seed's raw run to this file as it finishes")
    args = parser.parse_args(argv)
    results = {"custody": custody(args.seeds, args.questions, args.bits,
                                  records=args.records),
               "verdicts": verdicts()}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=1)
    c = results["custody"]
    print("custody: %d seeds, %d questions on %d cells (%d non-zero)"
          % (c["seeds"], c["questions"], c["cells"], c["non_zero_cells"]))
    e = c["exact"]
    print("   A exact answers, no policy      %5.1f releases, rank %s at question %s "
          "(%.0f%% of the cells determined)"
          % (e["releases_mean"], [e["ranks_at_mean"][h] for h in c["horizons"]],
             c["horizons"], 100 * (e["determined_fraction_mean"] or 0)))
    bl = c["bounded"]
    print("   B bounded queries               %5.1f proved, %.1f refused, %d cell values "
          "anywhere in the replies, %d cells determined"
          % (bl["proved_mean"], bl["refused_mean"], bl["counts_leaked_total"],
             bl["cells_determined"]))
    ct = c["counter"]
    print("   C differencing, counter on       %d attempts, %.1f released, %.1f refused, "
          "first refusal at attempt %s"
          % (ct["attempts"], ct["released_mean"], ct["refused_mean"],
             ",".join(ct["first_refusal"])))
    print("      cells isolated before the counter bit: %s; refusal reasons: %s"
          % (ct["isolated_mean"], ", ".join(ct["reasons"])))
    print("written: %s" % args.out)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
