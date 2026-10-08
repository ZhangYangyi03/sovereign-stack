# sovereign-stack

Data exchange without custody, compliance assessment with a third answer
available, and replication that survives a partition. One Python package, no
service to run besides the one you start, and every number in this file
regenerable from this repository alone.

    pip install -e ".[test,fast]"
    python -m pytest tests -q                       # 56 tests
    python bench/bench.py                           # timing table
    python bench/experiment.py --seeds 8            # the two measured claims
    python -m ss.gatewayd --data node-a --name Alpha --did did:sgw:alpha --secret s --once

## What is measured, and what is asserted

    claim                                     how it is established
    a bounded query discloses no count        every integer in the reply is one the
                                              request supplied; test walks the payload
    a grant cannot be widened                 chain walk refuses scope-widened@i;
                                              leaf grantee must be the requester
    a drop, edit or reorder is detected       verify() over a rebuilt chain, plus the
                                              saved heads, which is the check that
                                              catches a *consistent* rewrite
    the assessment admits it does not know    counts of satisfied / violated /
                                              undetermined against three real baselines
    a two-sided partition loses nothing       8 replicas, 6 partition rounds, lost=0
    a sealed frame authenticates once         reflection and replay both refused
    the report verifies against itself        Merkle head over findings, counts
                                              recomputed, baseline membership checked

## The two measured claims

**1. Custody.** A node holding a register will answer a question about a sum of
its cells, and the answer is a commitment plus a range proof: no cell value and no
total appears in the reply. What the reply does not do is stop the requester from
learning the cells anyway. Release enough overlapping sums and the cells are
determined by arithmetic alone -- no assumption about the attacker's method. The
experiment builds the incidence matrix of the released selections and takes its
rank.

Over 8 seeds, 24 questions, 48 cells:

    workflow                             releases   cells determined   refusals
    A  exact answers, no policy            24.0        24 of 48            0
    B  bounded queries (commit + proof)    22.1        0 of 48             1.9
    C  differencing sequence, counter on   20.0       12 isolated         2

Workflow A is what a data-sharing arrangement without a policy looks like: after
24 ordinary-looking questions, half the register is determined by the sums that
were released. Workflow B answers the same questions and no cell is determined at
all, because nothing in the reply is a number. Workflow C is the attack B does not
stop: releases of {probe, partner} and {partner} isolate the probe cell by
subtraction, and the disclosure counter refuses at attempt 19 in 8 of 8 seeds --
having already isolated 12 cells, which is the honest size of the defence.

**2. Verdicts.** An audit tool that can only say satisfied or violated has to
guess where the evidence is thin. Against the NIST SP 800-53 rev5 baselines, with
real evidence packs:

    baseline   controls   satisfied   violated   undetermined   two-valued would claim
    low          149         1          0          148              149 satisfied
    moderate     287         4          0          283              287 satisfied
    high         370         5          0          365              370 satisfied

The rule set decides a handful of controls and says so; the rest are undetermined
with a reason code, and the reasons are separated: `not-implemented` (no rule
written yet), `no-evidence`, `attestation-stale`, `human-step` (a judgement no log
can settle). A two-valued report on the same evidence would have called all of
them satisfied.

The ageing behaviour is a step function, not a slope. An administrator attestation
is satisfied at 364 days old and undetermined at 366, against a 365-day lease. A
restore test is satisfied at 179 days and violated at 181, against a 180-day
lease: past its lease the evidence does not become weaker, it stops being evidence.

## The control catalogue is not this project's invention

`ss/data/` carries the NIST OSCAL content for SP 800-53 rev5: the full catalogue
(1196 controls and enhancements, with families) and the LOW, MODERATE and HIGH
baseline profiles. Each file records the SHA-256 of the upstream document it was
derived from. Tests assert that the control identifiers used by the rules resolve
against the catalogue, that the baselines nest (low ⊆ moderate ⊆ high), and that
the catalogue is internally consistent. A rule names its control by the catalogue's
own spelling -- `ia-2.1`, not `IA-2(1)` -- because a report that cannot be joined
to the framework it claims is a report nobody can audit against.

## The parts

    ss/crypto.py       Ed25519, HKDF, AES-GCM, HMAC hash chain, Merkle tree, and
                       one published Schnorr group (RFC 3526) with a Pedersen base
                       derived so that nobody knows its discrete log
    ss/zk.py           four proofs: knowledge of an opening, an OR proof on a bit,
                       a bit-decomposed range proof, Chaum-Pedersen equality
    ss/identity.py     self-certifying DIDs, signed scope delegation, and the
                       narrowing rule that decides whether a chain resolves
    ss/exchange.py     the three query classes, the disclosure counter, receipts
    ss/net.py          length-prefixed canonical JSON, sealed frames, a listener
    ss/gatewayd.py     the node: five verbs, files on disk, a CLI
    ss/gatewayctl.py   the client for those verbs
    ss/compliance.py   strong Kleene logic, seven rules, the baselines, reports
    ss/ops.py          a max-register counter, an LWW register, an outbox, sync
    audit/pack.py      build an evidence pack from a node's own files and sign it
    ops/deploy.py      deployment plan and acceptance checks

A full run of one node, two clients, a bounded query, a refusal, an offline write
and a sync, over real sockets:

    python -m ss.gatewayd --data node-b --name Health --did did:sgw:health --port 8787 --secret s
    python -m ss.gatewayctl --port 8787 --secret s --peer-did did:sgw:health health
    python -m ss.gatewayctl --port 8787 --secret s --peer-did did:sgw:health sync --store cli.json

## Benchmarks

Measured on this machine. Regenerate with `python bench/bench.py`; each section
can be run alone (`python bench/bench.py ops`) and merges into the same file.

<!-- bench:start -->
| what | number |
| --- | --- |
| host | AMD64, Windows-11-10.0.26200, 16 cores, python 3.13.13, modexp via gmpy2 |
| group verify (primality, generator order) | 1231.7 ms |
| Pedersen commitment (2048-bit group) | 5.0 ms |
| Ed25519 sign | 26.2 ms |
| Ed25519 verify | 19.5 ms |
| SHA-256 over 1 MiB | 1.2 ms |
| range proof, 8 bits: prove / verify | 190 ms / 192 ms, 39384 bytes |
| range proof, 16 bits: prove / verify | 398 ms / 357 ms, 76407 bytes |
| range proof, 24 bits: prove / verify | 520 ms / 553 ms, 113420 bytes |
| Schnorr dlog proof: prove / verify | 7 ms / 4 ms, 1743 bytes |
| exchange round trip, 20 cells, 8-bit range | 442 ms, proof 39388 bytes |
| exchange round trip, 60 cells, 8-bit range | 613 ms, proof 39379 bytes |
| exchange round trip, 120 cells, 8-bit range | 943 ms, proof 39378 bytes |
| exchange round trip, 60 cells, 24-bit range | 1297 ms, proof 113422 bytes |
| third-party verify of a report (287 controls) | 11.7 ms |
| 4 replicas, 6 partition rounds | 18 ms, 480 ops, lost 0, converged True |
| 12 replicas, 6 partition rounds | 82 ms, 480 ops, lost 0, converged True |
| 40 replicas, 6 partition rounds | 1073 ms, 480 ops, lost 0, converged True |
| one frame over loopback, 1 KiB | 14.32 ms |
| one frame over loopback, 64 KiB | 14.96 ms |
| one frame over loopback, 1024 KiB | 24.79 ms |
| one sealed frame over loopback | 12.85 ms |
<!-- bench:end -->

## What this does not do

Stated in full in docs/THREAT_MODEL.md, and the three that matter most:

* A node that holds data can answer a bounded query with a proof of a false
  statement. Nothing here binds a commitment to the values the node claims to
  hold. The defence is that any grantee can be given the openings and check, which
  makes cheating detectable after the fact rather than impossible before it.
* The disclosure counter bounds repeated overlap. It does not make the register
  safe, and the experiment is included precisely because it shows the size of that
  gap rather than asserting it is closed.
* There is no rate limit per peer and no admission control. The framing caps a
  frame and the outbox caps its depth; a hostile peer can still open connections.

## License

Apache-2.0.
