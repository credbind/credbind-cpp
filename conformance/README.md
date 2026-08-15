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

Issuer-evidence integration covers the five published base vectors across both
evidence profiles and all three bindings, exact evidence-result digests and
credential-validity boundaries. Negative cases cover policy pairing,
reconstructibility, issuer/audience/authorized-party/binding/required-claim/time
failures, protected-header trust restrictions, duplicate claims, standard
signature substitution and GQ transcript substitution.

Direct-core integration additionally validates exact CIC schemas, public-only
P-256 and Ed25519 caller JWKs, commitments, evidence-result binding and caller
signatures for all five base vectors. Both published carrier certificates pass
certificate-signature, certified-key, time, principal and same-rule account
authorization. Direct negatives cover malformed or substituted CIC fields,
private or invalid caller keys, caller and carrier signatures, key-type
agreement, credential-derived identity bounds, principal policy, account
issuer and typed predicates, permission subsets, and the prohibition on
combining account rules.

For the early cross-language subgate,
`tests/fixtures/external_carrier_test.py TEST_BINARY DESCRIPTOR.json` accepts one
bounded externally generated carrier and explicit test policy, invokes the same
internal verifier through its framed test ingress, and prints only a verified
status. The descriptor is a conformance-only interchange file, not a shipping
configuration format.

The current adapter checkpoint adds strict production configuration parsing,
offline `config check`, injection-safe SSH rendering, silent verification
denials and normalized bounded syslog events. The authenticated command/syslog
test reuses the pinned P-256 carrier through the production command path and
proves exact output, trusted audit context and bearer redaction. The same path
uses one configured monotonic deadline capped at ten seconds and a signal-safe
cancellation flag. Deterministic boundary tests cover cumulative expiry,
cancellation, deadline-before-cancellation precedence, exact configuration
bounds and zero authorization output on interruption.

The reconciled R005 initializer is implemented and fixture-tested for exact
deny-all bytes, useful-policy validation and atomic private publication, so
`test-cli` is now implemented. This does not claim full corpus conformance:
individual synchronous calls are not preempted mid-call, and real OpenSSH
timing remains unfinished. `test-openssh`, sanitizer/fuzz and
`make test-conformance` continue to fail closed; offline `test-integration`,
`test-syslog` and `test-deadline` are implemented.
