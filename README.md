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
non-alphabet characters, impossible lengths and non-zero unused pad bits. This
checkpoint does not claim complete token, certificate, JWS or verifier
conformance.

## Conformance input

`make fixtures` fetches and verifies the exact locked artifact and manifest.
An offline reproduction may set `CREDBIND_FIXTURE_SOURCE` to an existing asset;
its SHA-256 must still match.

All unfinished protocol, fixture, integration, syslog, deadline, sanitizer,
fuzz and OpenSSH targets fail explicitly. In particular,
`make test-conformance` cannot report success until the independent verifier
actually passes the shared corpus. This baseline makes no conformance,
security, packaging or platform-support claim.

The project is licensed under Apache License 2.0. Contributions must include a
Developer Certificate of Origin sign-off.
