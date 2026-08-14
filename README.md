# CredBind C++ verifier

This repository will contain the independently designed, offline C++17
`credbind-ssh-authorized-keys` verifier for CredBind SSH v1.

The repository pins the immutable `v1.0.0-rc.1` language-neutral conformance
input. The implementation order and acceptance requirements are owned by the
[C++ rewrite plan](https://github.com/credbind/planning/blob/main/rewrite/languages/cpp.md).

## Build baseline

The repository Makefile is the canonical interface. The host C++17 command is
built under `dist/<system>-<architecture>/` with strict warnings, optimization,
PIE, stack protection, fortification, platform relocation hardening, stripped
symbols, remapped source paths, atomic publication and controlled version
metadata:

```sh
make build
make test-unit
make dependencies-check
make verify-binary
```

At this checkpoint the command implements only deterministic
`version`/`--version` output. Every other invocation fails nonzero and writes no
stdout. `verify-binary` checks the native binary type and PIE status, rejects
checkout-path leakage and compares two controlled builds byte for byte.

The aggregate `make test` and `make check` targets intentionally fail until
all deterministic layers they promise are implemented. Required unfinished
targets never skip or report success.

## Strict parser checkpoint

The internal C++17 parser layer uses pinned `nlohmann/json` v3.12.0 through its
SAX interface and pinned `tl::expected` v1.3.1 for value-or-error results. The
committed headers and licenses are verified byte-for-byte by
`make dependencies-check`; exact sources, commits, hashes, licenses and linkage
are recorded in `third_party/dependencies.json`.

The current schema-specific handler covers the closed CredBind core envelope.
It rejects duplicate and unknown members, wrong types, invalid UTF-8, trailing
data, invalid numeric syntax and configured byte, depth, member, value and key
bounds. The independent Base64url decoder rejects padding, whitespace,
non-alphabet characters, impossible lengths and non-zero unused pad bits.

Compact-JWS parsing preserves the exact three non-empty canonical Base64url
segments. The bounded OpenSSH reader covers the admitted P-256 and Ed25519
certificate layouts, exact SSH lengths, user/finite validity, one principal,
the double-wrapped carrier tuple, the closed sorted permission-extension set,
prohibited critical options, matching CA/signature families, truncation and
trailing data.

## Cryptographic checkpoint

The independent cryptographic layer verifies the pinned standard RS256 issuer
signature and the exact eight-round `gq-rs256-v1` proof profile. GQ parsing is
bounded and rejects non-canonical integers, altered transcript inputs, reordered
commitments, substituted responses, ineligible RSA keys, truncation and trailing
data. The implementation uses OpenSSL EVP for RS256 and OpenSSL BIGNUM for GQ;
tests verify dynamic system `libcrypto` 3 linkage and reject `libssl` linkage.

This layer is exercised directly against the immutable corpus. It is not yet
wired through complete issuer policy or the production command, and it does not
claim the maximum-size carrier, complete verifier or conformance gates.

## Offline issuer-key checkpoint

The C++ verifier's typed key-source boundary admits only an absolute
`static-jwks-file` path and rejects `oidc-discovery` without network activity.
It opens one bounded descriptor with no symlink following, requires a regular
file owned by the configured owner or root, and rejects group/other write
permission. The schema-specific SAX parser accepts only complete public RS256
signing JWKs and rejects duplicate JSON members or key IDs, private or unknown
members, unsupported key roles, malformed canonical Base64url and trailing
data. Unknown `kid` resolution fails closed.

This checkpoint validates the offline file/key trust boundary independently.
The issuer policy schema, complete token verifier, `config check`, and
production command integration remain unfinished.

## Issuer evidence-policy checkpoint

The typed issuer verifier now receives one already-selected trusted policy,
loads no trust from token content, resolves the exact `kid` from the offline
JWKS snapshot, and dispatches only the explicitly admitted standard or GQ
profile. Its bounded SAX boundary rejects duplicate issuer JSON members and
token-supplied key references or critical parameters. Complete evidence success
enforces exact issuer, audience/authorized-party policy, all three binding
profiles, typed required-claim predicates, reconstructibility policy, `iat`,
optional `nbf`, `exp`, clock skew and optional maximum credential age.

The result contains only admitted claims, the authenticated issuer/key ID,
binding, earliest credential-validity boundary and independently computed exact
evidence-result digest. This is still an internal direct issuer-evidence layer:
the CIC/caller signature, complete server configuration, account policy, SSH
carrier authorization and production command remain unfinished.

## Conformance input

`make fixtures` fetches and verifies the exact locked artifact and manifest.
An offline reproduction may set `CREDBIND_FIXTURE_SOURCE` to an existing asset;
its SHA-256 must still match.

All unfinished protocol-conformance, integration, syslog, deadline, sanitizer
Make targets, fuzz and real-OpenSSH targets fail explicitly. In particular,
`make test-conformance` cannot report success until the independent verifier
actually passes the shared corpus. This baseline makes no conformance,
security, packaging or platform-support claim.

The project is licensed under Apache License 2.0. Contributions must include a
Developer Certificate of Origin sign-off.
