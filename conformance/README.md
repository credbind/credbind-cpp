# Conformance baseline

`fixtures.lock.json` pins the exact immutable CredBind SSH v1 conformance
release consumed by this repository. Updating it is a coordinated change with
the specification, planning record and Go implementation.

`make fixtures` installs and verifies the pinned artifact. `make test-fixtures`
is offline and exercises the implemented JSON, compact-JWS and OpenSSH
certificate parser subset against all published base vectors and both carrier
certificates. It also exercises the independent standard RS256 and
`gq-rs256-v1` cryptographic primitives against pinned positive vectors and
negative signature, framing, canonical-integer, transcript-substitution,
round-order and RSA-key cases.

The same target loads the pinned issuer JWKS through the production offline
file boundary and covers symlink, non-regular-file, group-write,
duplicate-key-ID, private-member, duplicate-member, invalid-UTF-8,
unsupported-role/algorithm/key, unknown-key-ID and trailing-data denials.

This does not claim full corpus conformance: complete issuer policy and the
production command are not connected yet, and `make test-conformance` continues
to fail closed until every applicable case has a complete harness.
