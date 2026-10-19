> Historical baseline record (2026-10-05 or earlier). These results describe
> the earlier implementation. Current source validation is documented in
> [docs/validation/README.md](docs/validation/README.md).

# Communicating comparison baselines

`src/network/baselines.rs` uses the modern functions in `crates/pastau` and
`crates/augsso`. It never calls their centralized fixture benchmarks. Provisioning
is a trusted setup step outside operation timing: each service file contains only
its own global scalar shares. The client holds the account identifier, password,
and public verification material. Registration generates account shares at the
client, as the existing algorithms specify, and transmits each share only to its
intended provider. Services execute the library store/response/update functions.

Each provider, each token verifier, and each client invocation can be a separate
process. `bench_network service` binds the configured address. The client connects
only to the configured provider and verifier addresses. Setup and connection policy
are the same as the RoUpSPA network adapter in the new harness. Every request opens
a fresh TCP connection, includes connect time in end-to-end time, and enables
TCP_NODELAY. This is an explicit experiment policy; it does not reproduce the
manuscript's persistent-connection policy. The old local and modeled benchmarks
remain available for their existing purposes and labels.

| Scheme and operation | Communicating stages | Completion point |
|---|---|---|
| PASTA-U Registration | One registration submission to every provider | All submissions have been written to sockets |
| PASTA-U Authentication | Token requests to the configured first `t_sp` providers, then token delivery to the verifier | Verifier returns successful verification |
| PASTA-U Password Update | Old-password TOPRF, new-password TOPRF, update-body token generation, update submission to every provider | All final update submissions have been written to sockets |
| AugSSO Registration | One registration submission to every provider | All submissions have been written to sockets |
| AugSSO Authentication | Blinded password/challenge responses from the first `t_sp` providers, encrypted challenge responses, token delivery to verifier | Verifier returns successful verification |
| AugSSO Password Update | Old/new blinded-password requests to every provider, then encrypted challenges containing the new recovery public key | All providers return their durable final response and client checks the phi partials |

Registration has zero provider responses in both existing implementations. PASTA-U
final update submission is also one-way in the new adapter. No RoUpSPA Store,
Discard, quorum rule, or Delta wait is added to either baseline. Consequently a
`completed` one-way operation establishes submission at the client boundary;
it does not establish remote durable processing under loss or crashes. Endpoint
logs and subsequent authentication independently establish processing. Integration
tests wait for actual durable records before checking post-update authentication.

The crate cryptography is preserved: PASTA-U uses Ristretto TOPRF shares, BLS12-381
token signatures, and XChaCha20-Poly1305 authenticated encryption. AugSSO uses
BLS12-381 blinded password evaluation, pairing checks, token and phi shares,
password-derived X25519 recovery keys, and XChaCha20-Poly1305 ciphertexts.
The crates' existing hash-to-group constructions are used unchanged; these are
benchmark implementations, not a claim of compatibility with a standardized
hash-to-curve ciphersuite. The schemes have different cryptographic work and
different numbers of communicating stages.

JSON envelopes carry the real scalar, group, ciphertext, and token bytes. Socket
measurements include these envelopes and four-byte frame prefixes. Endpoint
handlers log actual processing independently of client measurements. The shared
`quorum_ns` field records provider-stage waiting time for baselines; it does not
give the baselines RoUpSPA quorum semantics. `client_ns` is local elapsed processing
and persistence time with blocking provider-stage and verifier waits removed,
not a hardware CPU-cycle counter. `end_to_end_ns` spans the operation through
its stated return boundary. For one-way messages, provider handler times are
available only in endpoint logs, since there is no response carrying them.

Every durable provider transition, random challenge session, and exact response
cache is flushed before any response is sent. Restart loads only that provider's
files. Identical session/stage bytes replay the cached response; conflicting reuse
is rejected. The client writes an unfinished marker before operating. An interrupted
baseline client reports that session as unresolved and refuses to silently start
another operation from potentially inconsistent state. Automatic continuation of
an interrupted baseline client is not implemented: its persisted marker identifies
the session, but does not retain all client ephemeral scalar state. Use a fresh
provisioned experiment state after auditing such a failure. This limitation does
not affect the RoUpSPA recovery implementation.

The benchmark adapter currently stores one account per service-state directory.
Registration samples must use fresh state or deliberately overwrite that account
with another complete registration, as the current store APIs permit. Repeated
password updates use the client's persisted current password.

The preserved `bench_modern_tcp` binary additionally accepts:

```text
bench_modern_tcp --server --n 3 --t 2 --id 1 --listen 10.200.1.2:19001
bench_modern_tcp --n 3 --t 2 --providers 10.200.1.2:19001,10.200.2.2:19002,10.200.3.2:19003 --warmup 1 --samples 2 --out modern.txt
```

Its older behavior still launches local processes when `--providers` is absent.
Externally owned services are not sent shutdown by the client. This preserved
binary uses its existing deterministic benchmark fixtures and persistent connection
policy, and retains the `modern exp2 token_generation_tcp` and
`modern exp2 password_update_tcp` labels. Use `bench_network` for the common
three-scheme comparison policy and durable state.

Validation commands:

```text
cargo test -p augsso_bench --test password_update_api
cargo test -p upspa-unified-benchmark --test network_baselines -- --nocapture
```

The process tests exercise registration, authentication, real password update,
authentication with the new password, provider and verifier restart, exact replay
after restart, conflicting request rejection, wrong-password rejection, and the
preserved external-address TCP binary. Their captured output is in
`results/baseline-network-process-tests.log` and `results/augsso-update-api-test.log`.
