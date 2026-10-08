# Threat model

What this project defends, against whom, and what it explicitly does not.

## In scope

**An honest-but-curious participant.** It follows the protocol and keeps every
message. It must not learn a cell value from a bounded query: the reply is a
commitment and a proof, and tests/test_all.py checks that no integer in the reply
is a count other than the ones the request itself supplied.

**A participant that asks a designed sequence.** Releasing sums is not the same as
releasing cells; a sequence of overlapping sums determines the cells by
subtraction. The disclosure counter counts the releases that overlap a cell, and
the differencing experiment in bench/experiment.py drives exactly that sequence
against a node with the counter on and reports where it stops.

**A participant that forges or reuses a grant.** Grants are signed Ed25519 over a
canonical body. The chain is walked root-first and every hop must narrow; the
requester must be the grantee of the leaf. Revoking a link invalidates everything
below it.

**A participant that edits the audit log.** Entries are HMAC-chained, each entry
carries its own sequence number, and the head is a Merkle root over the entries.
An edit, a drop and a reorder are each detected, and the report verification step
recomputes both the head and the control counts.

**An attacker on the wire.** Frames are AES-GCM sealed with a key bound to the
peer's DID, one key per direction, with the frame counter in the associated data.
Reflection and replay are both refused.

**An attacker that edits a compliance report.** The report carries a Merkle head
over its findings and its counts; `verify_report` recomputes both and refuses a
report whose controls do not match the baseline it names.

## Out of scope, stated rather than implied

**A malicious node.** A node that holds data can answer a bounded query with a
proof of a false statement, because nothing here proves that a commitment was
built from the values the node claims to hold to. The defence is that a
commitment can be opened to any auditor who is granted that right, which makes
cheating detectable after the fact and not impossible before it. Closing this
needs a proof that the committed value equals a committed database state, which
is a substantially larger system.

**Traffic analysis.** The size of a reply is a function of the number of bits in
the range proof and the number of cells, so an observer learns roughly how much
data a query touched.

**A compromised endpoint.** An attacker with the store file and the identity file
has the node.

**Denial of service.** The framing caps a frame at 16 MiB and the outbox caps its
pending count, but there is no rate limit per peer and no admission control.

**Post-quantum.** Ed25519, X25519, AES-GCM and a 2048-bit discrete-log group are
all broken by a large enough quantum computer. Nothing here is hybrid.
