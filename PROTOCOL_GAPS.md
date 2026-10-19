> Historical baseline record (2026-10-05 or earlier). These results describe
> the earlier implementation. Current source validation is documented in
> [docs/validation/README.md](docs/validation/README.md).

# RoUpSPA protocol gaps and deployment boundaries

The journal manuscript is the protocol reference. This repository does
not alter its manuscript or proof. The sections below distinguish prescribed
behavior, evidence from the preserved implementation, and proposals which
would require a new protocol argument. Passing reproduction tests establish
that a gap exists; they do not establish security of the exposed behavior.

Sources: `network-references/journal/sections/2_Design.tex` (quorum-based
synchronization), `3_Model.tex` (provider restart rule, channels and completion),
`4_Protocol.tex` (phase order and recovery), and the revised synchronization
argument in `5_Security.tex`. These manuscript sources are external to the
repository; their archive filenames and digests are recorded in
`SOURCE_ARCHIVES.txt`.

## 1. An endpoint cannot infer that it missed a completed write

The manuscript requires providers outside a completed acknowledgement set to
remain stale. It also requires Authentication to be read-only and to use only
`t_sp` valid active identification and account responses. The baseline
`RoUpSpaSystem::deliver_account_store` and `deliver_password_update_store`
assign active/stale status directly to *every* provider in the same address
space, including unreachable providers. There is no protocol message conveying
this assignment to an endpoint that never received the write.

A provider can locally justify staleness after its own restart, a detected
outage, a known missing family, or an observed counter discrepancy. It cannot
learn about a suppressed application message while it remains live solely by
examining its unchanged local record. Socket traffic and local durability do
not provide that missing knowledge.

Concrete reproduction with valid `(n_sp,t_sp,q_sp)=(7,2,5)`:

1. Setup and Registration complete at all seven providers.
2. Password Update reaches providers 1â€“5 and their terminal Store is processed.
3. Providers 6â€“7 receive neither message and have no local outage indication.
   Their actual local state remains active with the old counter-zero root.
4. Only providers 6â€“7 answer a later Authentication. The old password recovers
   the old root, and Authentication succeeds because Password Update changes
   neither account ciphertext nor the login-server verifier. The new password
   fails authenticated decryption against those same old roots.

The regression
`undetected_missed_password_write_allows_old_password_threshold_authentication`
preserves the missed endpoints' own pre-operation state to model actual
process isolation, instead of applying the centralized status mutation. The
companion Secret Update regression demonstrates that old account records can
be selected, but the honest login server rejects their obsolete verifier after
its Store. These are different consequences and must not be conflated.

The write/synchronization intersection condition does not imply intersection
of a write quorum and a threshold-only Authentication set. In this example the
two missed providers constitute a complete TOPRF threshold. Restart recovery
alone does not fix live, undetected misses. The network adapter retains the
specified Authentication threshold and does not mutate unreachable endpoints.
Fault experiments must report this result if their schedule exposes it.

**Proposed change, not implemented or proved:** introduce authenticated
freshness evidence or an epoch/lease mechanism which prevents an endpoint from
advertising active records after an unseen completed update. An alternative
is a larger freshness read set with a proved intersection property. Either
changes the protocol or its availability/timing assumptions; merely increasing
the read threshold silently is not a justified implementation fix.

## 2. A signature on a direct account write does not prove completion

Registration and Secret Update directly install a signed account record at a
provider before its acknowledgement. Logical completion additionally requires
`q_sp` matching durable acknowledgements and processing the matching
login-server Store. The signed provider tuple contains the user identifier,
shared routing identifier, ciphertext, and counter. It does not contain a
login-server completion certificate or a quorum certificate.

The preserved synchronization code checks the signature and chooses the
unique highest counter. Its `OperationInFlight` check reads the centralized
client operation map. That map is unavailable to an independent recovering
provider. Even `q_sp` valid signed responses may contain one larger directly
installed account record from an unfinished operation.

The regression
`independent_synchronization_can_install_direct_write_before_login_server_store`
performs one signed Secret Update provider write, obtains only one of the
required five acknowledgements, and leaves the old login-server verifier
current. The writing client correctly blocks its own synchronization call. A
separate recovery context holding the same endpoint records but no client
operation cache collects at least five signed responses and installs that
uncommitted counter-one record. The login server still has the old verifier and
a pending update. No signature forgery, TOPRF share copying, or ciphertext
tampering is needed.

The manuscript's revised proof relies on serialization: no Authentication,
later write, or Synchronization for a family starts while its write is
unresolved. Persisting one client's unfinished log preserves that client's
serialization. It supplies no distributed exclusion or completion evidence
to other clients or to provider-initiated synchronization after a crash.

The network adapter must refuse account activation when it cannot establish
this prerequisite. It must not relabel a signed direct write as completed or
claim fault-tolerant account repair solely from those signatures. Such a
refusal is an explicit unresolved protocol boundary, not successful repair.
The preserved centralized synchronization API remains available for its
original serialized model and benchmarks.

**Proposed change, not implemented or proved:** bind the account-record digest,
family, counter, and session to authenticated evidence that both the write
quorum and matching login-server Store completed. Define how recovering
providers obtain and validate that evidence, and how a terminal decision
survives client loss. A login-server certificate or a distributed commit
certificate would add messages/state and require revisiting the proof and
completion accounting. Reading a benchmark controller's memory is not a
protocol certificate.

## 3. Recovery requires `q_sp` responses from other providers

The manuscript instructs a recovering provider to contact all *other*
providers and obtain `q_sp` valid responses. The range and strict intersection
condition permit `q_sp=n_sp`. A restarted provider then has at most
`n_sp-1` other responders, even when all services are running. The regression
`full_write_quorum_does_not_allow_recovery_from_other_providers` records this
with `(3,2,3)`.

The implementation must not count the stale recovering provider as an
additional peer or relax the response boundary without declaring a protocol
change. Configurations with `q_sp=n_sp` remain valid for initial writes but
cannot perform the specified recovery. This is a recovery limitation, not a
reason to silently reject otherwise valid manuscript coordinates.

**Proposed change, not implemented or proved:** specify whether recovery may
count local durable evidence, or separately require `q_sp<=n_sp-1` for recovery
experiments and explain the resulting availability domain.

## 4. All providers restarting creates an evidence/active-state question

The prescribed restart rule marks known families stale before active reads.
The original synchronization API obtains evidence using the same response
methods that reject stale replicas. If every provider restarts, no active
provider can answer that API, regardless of intact disks. The manuscript does
not explicitly define a separate response type that permits durable stale
records as recovery evidence.

Separating authenticated *recovery evidence* from *active Authentication
responses* may permit recovery without authorizing stale threshold reads. It
still requires a proof that the evidence refers to completed, serialized
state. A provider's locally committed identification record establishes its
own terminal processing; an account record's signature does not establish
login-server Store. The adapter's evidence policy and all-restart outcome must
be reported explicitly. This distinction must not turn stale records into
ordinary active Authentication responses.

## 5. Terminal delivery outside the synchronous assumption

Formal terminal Store/Discard remains one-way. The manuscript assumes a known
message-delay bound Delta and that the accepting honest login server or
tentative-write providers remain live through terminal processing. The client
retransmits identical terminal bytes during the bounded interval and waits
Delta before returning; a socket write succeeding is not proof of handler
processing.

A loss/drop or crash schedule outside this assumption can leave the client
unable to distinguish processed Store from missing Store. Experiments must
record the wait and endpoint durable processing independently, classify the
actual outcome honestly, and preserve the exact unfinished session for retry.
They must not add a formal application acknowledgement merely to hide this
boundary. A controller's endpoint logs are measurement evidence rather than
additional protocol messages.

## 6. Channel and concrete cryptography assumptions

The manuscript assumes confidential, integrity-protected, server-authenticated
channels and a TOPRF with the stated security properties. The preserved
benchmark uses Shamir shares over Ristretto, BLAKE3,
XChaCha20-Poly1305, and Ed25519. It does not implement contribution proofs.
The in-memory code can compare a provider's share against central secret
commitments; an actual client cannot inspect remote share state in this way.
Authenticated decryption detects an incorrect combined key but does not prove
each contribution correct or establish all abstract TOPRF assumptions.

Transport framing, durable journals, and process isolation do not themselves
establish the channel or TOPRF proof assumptions. README and results must name
the actual transport security policy and any unimplemented authentication.

## Verification record

Command executed on 2026-10-05:

```text
cargo test -p upspa_quorum_bench --test roupspa_protocol_gaps -- --nocapture
```

Result: four regression tests passed, zero failed. The reproductions above are
local protocol evidence; real transport/namespace measurements and restart
results are recorded separately under `results/`.
