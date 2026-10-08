"""Build an evidence pack from the running node, assess it, and sign the report.

This is the join between the two halves of the project: the audit chain that the
exchange writes to is exactly the evidence the compliance assessment consumes, so
a report can say "the audit head in this evidence commits to the entries this
node produced" without a second data path.

    python audit/pack.py --data node-data --profile moderate --out report.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ss import compliance as CO
from ss.crypto import HashChain, KeyPair, merkle_root


def evidence_from_node_dir(data_dir: str, extra: dict | None = None) -> CO.Evidence:
    """Read a node's own files. Nothing here is taken on trust: the chain is
    rebuilt from its entries and checked before its head is used as evidence."""
    ev = CO.Evidence()
    chain_path = os.path.join(data_dir, "chain.json")
    if os.path.exists(chain_path):
        with open(chain_path, encoding="utf-8") as fh:
            saved = json.load(fh)
        rebuilt = HashChain(saved["entries"])
        ok, idx = rebuilt.verify()
        matches, bad = rebuilt.matches(saved.get("heads", []))
        intact = ok and matches
        if intact:
            ev.observed("audit_entry_digests", rebuilt.snapshot_heads(),
                        "chain.json (recomputed)")
            ev.observed("audit_head", merkle_root(rebuilt.snapshot_heads()),
                        "chain.json (recomputed)")
        else:
            # An edited log is not evidence of anything, so its head is withheld
            # rather than passed on: the assessment then reports the control as
            # undetermined, which is the correct answer to "was the log intact".
            ev.observed("chain_rebuild", {"ok": ok, "heads_match": matches,
                                          "entries": len(rebuilt),
                                          "first_divergent_index": idx if not ok else bad},
                        "chain.json")
        ev.observed("chain_intact", {"ok": intact, "entries": len(rebuilt)}, "chain.json")
    for item in (extra or {}).get("items", []):
        ev.add(CO.EvidenceItem(**item))
    return ev


def build(data_dir: str, profile: str = "moderate", out: str | None = None,
          jurisdiction: str | None = None, sign_with: str | None = None,
          extra_path: str | None = None) -> dict:
    extra = None
    if extra_path and os.path.exists(extra_path):
        with open(extra_path, encoding="utf-8") as fh:
            extra = json.load(fh)
    evidence = evidence_from_node_dir(data_dir, extra)
    ctx = {"now": time.time()}
    if jurisdiction:
        ctx["jurisdiction"] = {"allowed_regions": jurisdiction.split(",")}
    report = CO.assess(evidence, ctx, profile=profile)
    if sign_with and os.path.exists(sign_with):
        with open(sign_with, encoding="utf-8") as fh:
            seed = bytes.fromhex(json.load(fh)["seed"])
        report.sign(KeyPair.from_seed(seed))
    payload = report.to_dict()
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=1)
    return payload


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sgw-audit")
    parser.add_argument("--data", required=True, help="a node's data directory")
    parser.add_argument("--profile", default="moderate",
                        choices=["low", "moderate", "high"])
    parser.add_argument("--jurisdiction", default=None,
                        help="comma-separated regions this assessment is against")
    parser.add_argument("--extra", default=None, help="JSON file of further evidence")
    parser.add_argument("--sign-with", default=None, help="identity.json to sign the report")
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)
    payload = build(args.data, args.profile, args.out, args.jurisdiction,
                    args.sign_with, args.extra)
    ok, problems = CO.verify_report(payload)
    print("report: %s, %d findings, head %s" % (payload["profile"],
                                                len(payload["findings"]),
                                                payload["head"][:16]))
    print("counts: %s" % payload["counts"])
    print("verified against the baseline: %s%s"
          % (ok, "" if ok else " (%s)" % "; ".join(problems)))
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
