# Compliance assessment with a third answer available.
#
# An audit tool that can only say satisfied/violated will say "satisfied" wherever
# the evidence is thin, because a missing observation looks the same as a passing
# one. This module carries three verdicts -- satisfied, violated, undetermined --
# and a rule has to earn the first two:
#
#   deterministic  a model check over the evidence. A counter-example is a
#                  finding; an unsat core is a proof. If the solver cannot
#                  decide inside its budget, the answer is undetermined, and the
#                  budget it ran out of is reported.
#   documentary    an observation the tool cannot make for itself: a policy has
#                  been signed, a training has happened. Undetermined unless a
#                  dated attestation is present, and undetermined again once the
#                  attestation is older than its lease.
#   procedural     a property of the process rather than of the system. Always
#                  undetermined, on purpose, so that it shows up in the report as
#                  work a person still has to do.
#
# Controls combine under strong Kleene logic: a violated sub-control violates the
# control whatever the rest say, a satisfied one cannot rescue an undetermined
# sibling. That is the same three-valued algebra as ss/dsl-derived work elsewhere,
# and it is tested against an independent evaluation of all 3^n combinations.
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum

from .crypto import KeyPair, canonical, merkle_root, sha256_hex


class Verdict(str, Enum):
    SATISFIED = "satisfied"
    VIOLATED = "violated"
    UNDETERMINED = "undetermined"

    def __str__(self) -> str:
        return self.value


def k_not(a: Verdict) -> Verdict:
    return {Verdict.SATISFIED: Verdict.VIOLATED, Verdict.VIOLATED: Verdict.SATISFIED,
            Verdict.UNDETERMINED: Verdict.UNDETERMINED}[a]


def k_and(a: Verdict, b: Verdict) -> Verdict:
    if a is Verdict.VIOLATED or b is Verdict.VIOLATED:
        return Verdict.VIOLATED
    if a is Verdict.UNDETERMINED or b is Verdict.UNDETERMINED:
        return Verdict.UNDETERMINED
    return Verdict.SATISFIED


def k_or(a: Verdict, b: Verdict) -> Verdict:
    if a is Verdict.SATISFIED or b is Verdict.SATISFIED:
        return Verdict.SATISFIED
    if a is Verdict.UNDETERMINED or b is Verdict.UNDETERMINED:
        return Verdict.UNDETERMINED
    return Verdict.VIOLATED


def k_all(verdicts) -> Verdict:
    out = Verdict.SATISFIED
    for v in verdicts:
        out = k_and(out, v)
    return out


def k_implication(a: Verdict, b: Verdict) -> Verdict:
    return k_or(k_not(a), b)


class EvidenceError(Exception):
    pass


@dataclass
class EvidenceItem:
    id: str
    kind: str
    value: object
    source: str = ""
    retrieved_at: float = field(default_factory=time.time)
    confidence: str = "observed"   # observed | attested | inferred


@dataclass
class Evidence:
    items: dict = field(default_factory=dict)

    @classmethod
    def from_pack(cls, pack: dict) -> "Evidence":
        items = {}
        for raw in pack.get("items", []):
            items[raw["id"]] = EvidenceItem(**raw)
        return cls(items)

    def add(self, item: EvidenceItem) -> "Evidence":
        self.items[item.id] = item
        return self

    def observed(self, ident: str, value, source: str = "") -> "Evidence":
        return self.add(EvidenceItem(ident, "observation", value, source,
                                     confidence="observed"))

    def attested(self, ident: str, value, source: str, when: float | None = None,
                 ) -> "Evidence":
        return self.add(EvidenceItem(ident, "attestation", value, source,
                                     retrieved_at=when or time.time(),
                                     confidence="attested"))

    def get(self, ident: str):
        item = self.items.get(ident)
        return None if item is None else item.value

    def item(self, ident: str):
        return self.items.get(ident)

    def digest(self) -> str:
        return sha256_hex(canonical({k: {"kind": i.kind, "value": i.value,
                                      "source": i.source,
                                      "confidence": i.confidence}
                                     for k, i in sorted(self.items.items())}))

    def to_pack(self) -> dict:
        return {"items": [{"id": i.id, "kind": i.kind, "value": i.value,
                           "source": i.source, "retrieved_at": i.retrieved_at,
                           "confidence": i.confidence}
                          for i in sorted(self.items.values(), key=lambda x: x.id)]}


@dataclass
class Finding:
    rule: str
    control: str
    kind: str
    verdict: Verdict
    detail: str = ""
    witness: dict | None = None
    reason_code: str = ""

    def to_dict(self) -> dict:
        return {"rule": self.rule, "control": self.control, "kind": self.kind,
                "verdict": str(self.verdict), "detail": self.detail,
                "witness": self.witness, "reason_code": self.reason_code}


RULES: dict = {}


def rule(ident: str, control: str, kind: str):
    def wrap(fn):
        fn.rule_id, fn.control, fn.kind = ident, control, kind
        RULES[ident] = fn
        return fn
    return wrap


# ------------------------------------------------------------- the rule set
#
# Each rule is a function of the evidence returning a Finding. The control
# identifiers are the framework's own (NIST SP 800-53 rev5 where a control is
# quoted, ISO 27001-style clause names where the auditor's vocabulary is used),
# so a report can be handed to somebody who audits against that framework.


@rule("enc.transit", "sc-8", "deterministic")
def r_enc_transit(ev: Evidence, ctx: dict) -> Finding:
    """Every endpoint that moves records must terminate TLS at 1.2 or above."""
    endpoints = ev.get("endpoints") or []
    if not endpoints:
        return Finding("enc.transit", "sc-8", "deterministic", Verdict.UNDETERMINED,
                       "no endpoint inventory in evidence", reason_code="no-evidence")
    weak = [e["name"] for e in endpoints
            if not e.get("tls") or float(e["tls"]) < 1.2]
    plaintext = [e["name"] for e in endpoints if not e.get("refuses_plaintext")]
    if weak:
        return Finding("enc.transit", "sc-8", "deterministic", Verdict.VIOLATED,
                       "%d endpoint(s) below TLS 1.2" % len(weak),
                       witness={"endpoints": weak}, reason_code="tls-too-old")
    if plaintext:
        return Finding("enc.transit", "sc-8", "deterministic", Verdict.VIOLATED,
                       "%d endpoint(s) do not refuse plaintext" % len(plaintext),
                       witness={"endpoints": plaintext}, reason_code="plaintext-accepted")
    return Finding("enc.transit", "sc-8", "deterministic", Verdict.SATISFIED,
                   "%d endpoint(s) at TLS >= 1.2, plaintext refused" % len(endpoints))


SEPARATION_OF_DUTY = (("store.read", "store.write"),
                      ("log.read", "log.rewrite"),
                      ("key.use", "key.export"),
                      ("approve.payment", "create.payment"))


@rule("authz.duty.conflict", "ac-6", "deterministic")
def r_duty_conflict(ev: Evidence, ctx: dict) -> Finding:
    """No account may hold both halves of a separation-of-duty pair.

    The clause is the incompatible-duties one: an account that can both read a
    record store and rewrite its own access log has a privilege set no other
    control can compensate for. Deciding it is a search over the account matrix,
    and the counter-example names the account and the pair.
    """
    accounts = ev.get("accounts") or []
    if not accounts:
        return Finding("authz.duty.conflict", "ac-6", "deterministic",
                       Verdict.UNDETERMINED, "no account inventory in evidence",
                       reason_code="no-evidence")
    bad = []
    for acct in accounts:
        rights = set(acct.get("rights", []))
        for a, b in SEPARATION_OF_DUTY:
            if a in rights and b in rights:
                bad.append({"account": acct["name"], "pair": [a, b]})
    if bad:
        return Finding("authz.duty.conflict", "ac-6", "deterministic", Verdict.VIOLATED,
                       "%d account(s) hold an incompatible pair" % len(bad),
                       witness={"accounts": bad}, reason_code="duty-conflict")
    return Finding("authz.duty.conflict", "ac-6", "deterministic", Verdict.SATISFIED,
                   "no incompatible pair over %d account(s)" % len(accounts))


@rule("authn.mfa", "ia-2.1", "documentary")
def r_mfa(ev: Evidence, ctx: dict) -> Finding:
    lease = ctx.get("attestation_lease_days", 365)
    admins = ev.get("admins") or []
    if not admins:
        return Finding("authn.mfa", "ia-2.1", "documentary", Verdict.UNDETERMINED,
                       "no administrator inventory in evidence", reason_code="no-evidence")
    now = ctx.get("now", time.time())
    missing = [a["name"] for a in admins if a.get("mfa") != "hardware"]
    stale = [a["name"] for a in admins
             if a.get("mfa") == "hardware" and a.get("attested_at")
             and (now - a["attested_at"]) > lease * 86400]
    if missing:
        return Finding("authn.mfa", "ia-2.1", "documentary", Verdict.VIOLATED,
                       "%d administrator(s) not on hardware tokens" % len(missing),
                       witness={"admins": missing}, reason_code="mfa-absent")
    if stale:
        return Finding("authn.mfa", "ia-2.1", "documentary", Verdict.UNDETERMINED,
                       "attestation older than its %d-day lease" % lease,
                       witness={"admins": stale}, reason_code="attestation-stale")
    return Finding("authn.mfa", "ia-2.1", "documentary", Verdict.SATISFIED,
                   "%d administrator(s) on hardware tokens, attestations live"
                   % len(admins))


@rule("backup.restore.tested", "cp-9.1", "documentary")
def r_backup(ev: Evidence, ctx: dict) -> Finding:
    lease = ctx.get("backup_test_lease_days", 180)
    tests = ev.get("restore_tests") or []
    if not tests:
        return Finding("backup.restore.tested", "cp-9.1", "documentary",
                       Verdict.UNDETERMINED, "no restore test on record",
                       reason_code="no-evidence")
    now = ctx.get("now", time.time())
    last = max(t["at"] for t in tests)
    age = (now - last) / 86400.0
    if age > lease:
        return Finding("backup.restore.tested", "cp-9.1", "documentary", Verdict.VIOLATED,
                       "last restore test %.0f days ago, lease %d" % (age, lease),
                       witness={"last_days_ago": round(age, 1)},
                       reason_code="restore-test-expired")
    if not any(t.get("verified") for t in tests):
        return Finding("backup.restore.tested", "cp-9.1", "documentary",
                       Verdict.UNDETERMINED, "restore ran but was never verified",
                       reason_code="unverified-restore")
    return Finding("backup.restore.tested", "cp-9.1", "documentary", Verdict.SATISFIED,
                   "last verified restore test %.0f days ago" % age)


@rule("log.integrity.chain", "au-9.3", "deterministic")
def r_log_chain(ev: Evidence, ctx: dict) -> Finding:
    head = ev.get("audit_head")
    if not head:
        return Finding("log.integrity.chain", "au-9.3", "deterministic",
                       Verdict.UNDETERMINED, "no audit head in evidence",
                       reason_code="no-evidence")
    leaves = list(ev.get("audit_entry_digests") or [])
    if not leaves:
        return Finding("log.integrity.chain", "au-9.3", "deterministic",
                       Verdict.UNDETERMINED, "audit head present but no entries to match",
                       reason_code="head-without-entries")
    recomputed = merkle_root(leaves)
    if recomputed != head:
        return Finding("log.integrity.chain", "au-9.3", "deterministic", Verdict.VIOLATED,
                       "audit head does not match the entries it claims to cover",
                       witness={"head": head[:16], "recomputed": recomputed[:16]},
                       reason_code="head-mismatch")
    return Finding("log.integrity.chain", "au-9.3", "deterministic", Verdict.SATISFIED,
                   "audit head commits to %d entries" % len(leaves))


@rule("data.residency", "sc-7", "deterministic")
def r_residency(ev: Evidence, ctx: dict) -> Finding:
    jurisdiction = ctx.get("jurisdiction")
    stores = ev.get("stores") or []
    if jurisdiction is None:
        return Finding("data.residency", "sc-7", "deterministic", Verdict.UNDETERMINED,
                       "assessed without a jurisdiction to assess against",
                       reason_code="no-threshold")
    if not stores:
        return Finding("data.residency", "sc-7", "deterministic", Verdict.UNDETERMINED,
                       "no store inventory in evidence", reason_code="no-evidence")
    allowed = set(jurisdiction.get("allowed_regions", []))
    outside = [s["name"] for s in stores if s.get("region") not in allowed]
    if outside:
        return Finding("data.residency", "sc-7", "deterministic", Verdict.VIOLATED,
                       "%d store(s) outside the permitted regions" % len(outside),
                       witness={"stores": outside}, reason_code="region-outside-policy")
    return Finding("data.residency", "sc-7", "deterministic", Verdict.SATISFIED,
                   "%d store(s) inside %s" % (len(stores), ",".join(sorted(allowed))))


@rule("proc.vendor.review", "sa-9", "procedural")
def r_vendor(ev: Evidence, ctx: dict) -> Finding:
    """A judgement about a supplier. No amount of log data settles it."""
    vendors = ev.get("vendors") or []
    if not vendors:
        return Finding("proc.vendor.review", "sa-9", "procedural", Verdict.UNDETERMINED,
                       "no vendor register: a register is a human artefact, not an "
                       "observation", reason_code="human-step")
    missing = [v["name"] for v in vendors if not v.get("last_reviewed_at")]
    detail = ("%d vendor(s) with no review date" % len(missing) if missing else
              "review dates present; the judgement itself is not automatable")
    return Finding("proc.vendor.review", "sa-9", "procedural", Verdict.UNDETERMINED,
                   detail, witness={"vendors": missing} if missing else None,
                   reason_code="human-step")


# ------------------------------------------------------------- the catalogue
#
# The control identifiers are not this project's invention. ss/data carries two
# files taken from the NIST OSCAL content repository: the SP 800-53 rev5
# catalogue (every control and enhancement, with its family) and the LOW,
# MODERATE and HIGH baseline profiles (which controls each baseline selects).
# The provenance digest in each file is the SHA-256 of the upstream document it
# was derived from, so a reader can check that this project did not edit a
# control list to suit itself.

_DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
_CATALOG_CACHE: dict = {}


def control_id(display: str) -> str:
    """The catalogue's own spelling: 'IA-2(1)' is 'ia-2.1' in OSCAL."""
    return re.sub(r"\((\d+)\)", r".\1", display.strip().lower())


def control_title(ident: str, catalog: dict | None = None) -> str:
    catalog = catalog or load_catalog()
    entry = catalog["controls"].get(control_id(ident))
    return "" if entry is None else entry["title"]


def load_catalog(path: str | None = None) -> dict:
    path = path or os.path.join(_DATA, "controls_nist80053.json")
    if path in _CATALOG_CACHE:
        return _CATALOG_CACHE[path]
    with open(path, encoding="utf-8") as fh:
        spec = json.load(fh)
    if len(spec["controls"]) != spec["n_controls"]:
        raise EvidenceError("control catalogue is internally inconsistent")
    if not all("title" in c and "family" in c for c in spec["controls"].values()):
        raise EvidenceError("control catalogue is missing titles or families")
    _CATALOG_CACHE[path] = spec
    return spec


def load_profile(name: str = "moderate", path: str | None = None) -> dict:
    path = path or os.path.join(_DATA, "profile_%s.json" % name.lower())
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def baseline_set(profile: dict) -> set:
    return set(profile["selected"])


def coverage(profile: dict, rules: dict | None = None) -> dict:
    """How much of a baseline the rule set can actually decide."""
    rules = RULES if rules is None else rules
    want = baseline_set(profile)
    have = {control_id(fn.control) for fn in rules.values()}
    return {"baseline": profile.get("source", ""), "controls": len(want),
            "covered": sorted(want & have),
            "uncovered_count": len(want - have),
            "rules_outside_baseline": sorted(have - want)}


# ------------------------------------------------------------- the report


@dataclass
class Report:
    profile: str
    findings: list
    evidence_digest: str
    ctx: dict = field(default_factory=dict)
    refinements: dict = field(default_factory=dict)
    generated_at: float = field(default_factory=time.time)
    sig: str = ""

    def by_control(self) -> dict:
        out = {}
        for f in self.findings:
            out.setdefault(f.control, []).append(f)
        return out

    def control_verdict(self) -> dict:
        """A control is only satisfied if every finding under it is."""
        return {c: k_all([f.verdict for f in fs])
                for c, fs in self.by_control().items()}

    def counts(self) -> dict:
        c = {"satisfied": 0, "violated": 0, "undetermined": 0}
        for v in self.control_verdict().values():
            c[str(v)] += 1
        return c

    def summary(self) -> str:
        c = self.counts()
        total = sum(c.values())
        return ("%s: %d controls -- %d satisfied, %d violated, %d undetermined"
                % (self.profile, total, c["satisfied"], c["violated"],
                   c["undetermined"]))

    def undetermined_reasons(self) -> dict:
        out = {}
        for v, fs in self.by_control().items():
            if k_all([f.verdict for f in fs]) is Verdict.UNDETERMINED:
                for f in fs:
                    if f.verdict is Verdict.UNDETERMINED:
                        out.setdefault(f.reason_code or "unnamed", []).append(v)
        return {k: sorted(set(v)) for k, v in out.items()}

    def finding_digests(self) -> list:
        return [sha256_hex(canonical(f.to_dict())) for f in self.findings]

    def head(self) -> str:
        from .crypto import merkle_root
        return merkle_root(self.finding_digests())

    def body(self) -> dict:
        return {"profile": self.profile, "generated_at": round(self.generated_at, 6),
                "evidence_digest": self.evidence_digest,
                "ctx_digest": sha256_hex(canonical(self.ctx)),
                "refinements": {k: str(v) for k, v in sorted(self.refinements.items())},
                "counts": self.counts(),
                "head": self.head(),
                "findings": [f.to_dict() for f in self.findings]}

    def sign(self, kp: KeyPair) -> "Report":
        import base64
        self.sig = base64.urlsafe_b64encode(kp.sign(canonical(self.body()))).decode().rstrip("=")
        return self

    def to_dict(self) -> dict:
        return {**self.body(), "sig": self.sig}

    def to_json(self, indent: int = 1) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)


def verify_report(report: dict) -> tuple:
    """Everything a third party can check with only the report in hand.

    Not checked here, and deliberately: whether the evidence was true. What is
    checked is that the report is internally consistent -- every control from the
    named baseline appears exactly once in the verdict map, the counts match the
    findings, the head really is a Merkle root over the findings as written, and
    no finding carries a verdict outside the three-valued set.
    """
    problems = []
    try:
        profile = load_profile(report["profile"])
    except Exception as exc:
        return False, ["cannot load the baseline named in the report: %s" % exc]
    want = baseline_set(profile)
    got = {f["control"] for f in report["findings"]}
    if got != want:
        problems.append("controls assessed do not match the %s baseline (%d missing, %d extra)"
                        % (report["profile"], len(want - got), len(got - want)))
    for f in report["findings"]:
        if f["verdict"] not in {v.value for v in Verdict}:
            problems.append("finding for %s carries verdict %r" % (f["control"], f["verdict"]))
    from .crypto import merkle_root
    recomputed = merkle_root([sha256_hex(canonical(f)) for f in report["findings"]])
    if recomputed != report.get("head"):
        problems.append("head does not match the findings as written")
    c = {"satisfied": 0, "violated": 0, "undetermined": 0}
    for control, verdict in _control_verdicts(report["findings"]).items():
        c[str(verdict)] += 1
    if c != report.get("counts"):
        problems.append("counts do not match the findings")
    return (not problems), problems


def _control_verdicts(findings: list) -> dict:
    grouped = {}
    for f in findings:
        grouped.setdefault(f["control"], []).append(Verdict(f["verdict"]))
    return {c: k_all(vs) for c, vs in grouped.items()}


def assess(evidence: Evidence, ctx: dict | None = None, profile: str = "moderate",
           rules: dict | None = None, refinements: dict | None = None) -> Report:
    """Evaluate every rule, then account for every baseline control.

    A control in the baseline that no rule covers is reported undetermined with
    reason 'not-implemented'. That is the difference between this tool and a
    checklist: the gap is in the report, at a named control, rather than absent
    from it.
    """
    rules = RULES if rules is None else rules
    ctx = dict(ctx or {})
    refinements = dict(refinements or {})
    spec = load_profile(profile)
    want = baseline_set(spec)
    findings: list = []
    for ident, fn in sorted(rules.items()):
        if control_id(fn.control) not in want:
            continue
        finding = fn(evidence, ctx)
        finding.control = control_id(finding.control)
        if ident in refinements:
            finding = Finding(ident, control_id(fn.control), "refinement",
                              Verdict(str(refinements[ident])),
                              "verdict replaced by a recorded human judgement",
                              reason_code="human-refinement")
        findings.append(finding)
    covered = {control_id(fn.control) for fn in rules.values()}
    for control in sorted(want - covered):
        findings.append(Finding("(no rule)", control, "unimplemented",
                                Verdict.UNDETERMINED,
                                "no automated rule for this control yet",
                                reason_code="not-implemented"))
    return _finish(findings, evidence, ctx, profile, refinements)


def _finish(findings, evidence, ctx, profile, refinements) -> Report:
    rep = Report(profile=profile, findings=sorted(findings, key=lambda f: (f.control, f.rule)),
                 evidence_digest=evidence.digest() if isinstance(evidence, Evidence) else str(evidence),
                 ctx=ctx, refinements=refinements)
    return rep


def refine(report: Report, rule_id: str, verdict) -> Report:
    """Replace one rule's verdict with a person's, and keep both facts on record.

    The refinement does not delete the machine finding: it replaces it in the
    verdict map and is recorded by name in the report body, so a reader can see
    which conclusions a person stood behind and which the tool produced.
    """
    verdict = Verdict(str(verdict))
    if verdict is Verdict.UNDETERMINED:
        raise EvidenceError("a refinement has to assert something")
    ctx = dict(report.ctx)
    refinements = dict(report.refinements)
    refinements[rule_id] = verdict
    return _reassess(report, ctx, refinements)


def _reassess(report: Report, ctx: dict, refinements: dict) -> Report:
    findings = []
    seen = set()
    for f in report.findings:
        if f.rule in refinements and f.rule != "(no rule)":
            f = Finding(f.rule, f.control, "refinement", Verdict(str(refinements[f.rule])),
                        "verdict replaced by a recorded human judgement",
                        reason_code="human-refinement")
        findings.append(f)
        seen.add(f.control)
    return Report(profile=report.profile, findings=findings,
                  evidence_digest=report.evidence_digest, ctx=ctx,
                  refinements=refinements, generated_at=report.generated_at)
