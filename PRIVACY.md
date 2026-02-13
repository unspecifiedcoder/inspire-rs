# Privacy Properties of InsPIRe

This document describes the privacy guarantees, known limitations, and threat model
of the InsPIRe PIR library.

## Overview

InsPIRe implements a single-server Private Information Retrieval (PIR) protocol
based on ring-LWE encryption. The goal is to allow a client to retrieve an entry
from a server-hosted database without the server learning which entry was
requested.

**This library contains no telemetry, analytics, tracking, or outbound network
calls from library code.** The only network communication occurs in the
client/server binaries (`inspire-client`, `inspire-server`) over user-configured
HTTP endpoints.

## Privacy Guarantees

### Query Privacy (Computational)

The server cannot determine which database index the client is querying,
assuming the hardness of ring-LWE with the chosen parameters (128-bit security
level). The query is an RGSW encryption of an inverse monomial — without the
secret key, the server gains no information about the target index.

### Constant-Size Communication

Query and response sizes are constant regardless of the queried index:

- **Query size**: ~230 KB (seeded) / ~458 KB (full JSON)
- **Response size**: ~32 KB (InspiRING packed) / ~544 KB (no packing)

This prevents traffic-analysis attacks that could otherwise infer the queried
index from message sizes.

### No Client-Specific Server State

The server does not store per-client state. The CRS and encoded database are
generic and shared across all clients. This supports client anonymity at the
network layer (e.g., when combined with Tor or a VPN).

## Known Limitations

### 1. Shard ID Sent in Cleartext

The `shard_id` field in `ClientQuery` is sent unencrypted. This reveals which
database shard contains the target entry, reducing the anonymity set from the
full database to a single shard (~33M entries for Ethereum state with default
parameters).

**Impact**: For a 72-shard deployment, an observer learns a 1/72 partition of
where the target entry resides.

**Mitigation**: This is an inherent design trade-off for performance. The shard
size is large enough that the anonymity set remains substantial. Future work
could explore oblivious shard selection at the cost of additional computation.

### 2. Server Response Includes Processing Time

The `processing_time_ms` field in server responses exposes wall-clock query
processing time. In theory, processing time could vary based on memory access
patterns (e.g., cache behavior for specific shard/index combinations).

**Impact**: Low in practice — the dominant cost is polynomial multiplication,
which is data-independent. Memory-mapped mode (`--mmap`) may show more variance
due to page faults.

**Mitigation**: Deployments concerned about timing side-channels can strip this
field via a reverse proxy, or add artificial jitter.

### 3. No TLS Built In

The server binds a plain TCP listener with no TLS support. All communication
(queries, responses, CRS) travels unencrypted unless a TLS-terminating reverse
proxy is placed in front.

**Impact**: Without TLS, a network observer can read queries and responses. While
the PIR ciphertexts protect the queried index, the returned entry value is
also encrypted (RLWE) and cannot be decrypted without the client's secret key.

**Mitigation**: Deploy behind a TLS-terminating reverse proxy (nginx, Caddy, etc.)
for any non-local deployment.

### 4. Secret Key Stored as Plaintext JSON

The `setup` binary writes `secret_key.json` as a plain JSON file with default
filesystem permissions. No encryption-at-rest or restrictive file modes are
applied.

**Impact**: Any process or user with read access to the output directory can
recover the RLWE secret key and decrypt past responses.

**Mitigation**: Operators should restrict file permissions on `secret_key.json`
(e.g., `chmod 600`) and store it on encrypted storage.

### 5. Client Logs Query Indices to stdout

The client binary prints the queried index, shard ID, and result to stdout.
This is local-only but relevant in shared-machine or logging-forwarding
scenarios.

**Impact**: Anyone with access to the client's terminal output or log files
learns which indices were queried.

**Mitigation**: Redirect stdout in automated deployments. The library API
(`inspire::pir`) does not perform any logging — only the CLI binaries do.

## Threat Model

### In Scope

- **Honest-but-curious server**: The server follows the protocol but attempts to
  learn which entry the client queries. InsPIRe provides computational query
  privacy against this adversary.
- **Network eavesdropper** (with TLS): Observes encrypted traffic. Constant-size
  messages prevent traffic analysis.
- **Network eavesdropper** (without TLS): Can read ciphertexts but cannot
  determine the queried index without the secret key. The response value is
  also encrypted and cannot be read without that secret key.

### Out of Scope

- **Malicious server**: A server that deviates from the protocol (e.g., returns
  crafted responses to fingerprint clients) is not covered.
- **Side-channel attacks**: Physical or microarchitectural side channels on the
  server hardware are not addressed.
- **Client compromise**: If the client machine is compromised, the attacker has
  access to the secret key and all query/response data.

## Data Handling Summary

| Data | Where | Encrypted | Notes |
|------|-------|-----------|-------|
| Query index | Client → Server | Yes (RGSW) | Computationally hidden |
| Shard ID | Client → Server | No | Reveals shard partition |
| Response entry | Server → Client | Yes (RLWE) | Decrypted client-side |
| Processing time | Server → Client | No | Potential timing side-channel |
| Secret key | Client filesystem | No | Plaintext JSON |
| CRS | Server → Client | No | Public parameters, no secret data |
