# The wire protocol

One message in, one message out, over a connection that is sealed or not. There
are five verbs and no state on the client side beyond the store file it may hold.

    verb        request fields                          reply
    health      (none)                                  node, ops, chain head, counters
    exchange    request, chain                          receipt, attestation
    ops.push    ops[]                                   received, applied, acked[]
    ops.pull    have[], limit                           ops[], remaining
    inspect     n                                       entries[], chain_ok, head

## Framing

A frame is a 4-byte big-endian length followed by canonical JSON (sorted keys,
fixed separators, floats at 12 decimal places). Frames over 16 MiB are refused
before the body is read, so a bad length cannot be used to make a node allocate.

## Sealing

When a node is started with `--secret`, every frame on the wire is

    {"n": <counter>, "blob": "<hex of AES-GCM(nonce || ciphertext)>"}

with the key derived as

    hkdf(secret, "ss-v1/session|" + <the DID of the node being called>)

Two keys are derived per session, one per direction. Three consequences, each of
which is a test:

* a frame sent by a client cannot be reflected back and accepted, because it will
  not decrypt under the other direction's key;
* a frame cannot be replayed within a direction, because the counter is in the
  associated data and a counter that does not advance is refused;
* a client that does not know the DID of the node it is calling cannot open the
  reply, which is why `--peer-did` exists on the client and is not optional in
  practice.

An unsealed frame reaching a sealed node is refused with
`unsealed-frame-refused`, and the refusal is counted, so a misconfigured client
is visible in `health` rather than silently ignored.

## The exchange verb

The request names a query class, and the class decides what the answer may
contain.

    aggregate.bounded   the node proves a statement about a sum of cells it holds.
                        The reply carries a commitment and a range proof. No cell
                        value and no total appears anywhere in it.
    aggregate.exact     the node releases the number. A release is a disclosure,
                        so it is written into the audit chain with the requester's
                        DID, and it is subject to the disclosure counter.
    record.lookup       refused, always, whatever the delegation chain says. The
                        scope query.record exists in the vocabulary so that the
                        refusal is visibly a policy and not a missing feature.

The reply is a receipt signed by the node, plus an inclusion proof for the entry
the node just appended to its own chain. A client can verify the receipt with the
node's public key and the inclusion proof without holding the rest of the log.

## The delegation chain

A request carries a chain of grants, root first. A grant names a grantor, a
grantee, a set of scopes, a set of statement classes, an issue time and an expiry.
The chain resolves only if

* every grantor's key is known to the node;
* every grant's signature verifies over its canonical body;
* no grant has expired or been revoked;
* every grant's scopes and statement classes are subsets of its parent's;
* the requester is the grantee of the last grant.

The last condition is the one that matters most in practice: without it, anybody
holding a copy of a grant could use it.
