# CredBind C++ verifier

This repository will contain the independently designed, offline C++17
`credbind-ssh-authorized-keys` verifier for CredBind SSH v1.

The repository pins the immutable `v1.0.0-rc.2` language-neutral conformance
input. The implementation order and acceptance requirements are owned by the
[C++ rewrite plan](https://github.com/credbind/planning/blob/main/rewrite/languages/cpp.md).

## Build baseline

The repository Makefile is the canonical interface. The host C++17 command is
built under `dist/<system>-<architecture>/` with strict warnings, optimization,
PIE, hidden symbol visibility, stack protection, fortification, platform
relocation hardening, stripped symbols, remapped source paths, atomic
publication and controlled version metadata:

```sh
make build
make test-unit
make dependencies-check
make verify-binary
```

The command now also contains the bounded configuration, CLI and local-syslog
adapters described below. `verify-binary` checks the native binary type and PIE
status, rejects checkout-path leakage and compares two controlled builds byte
for byte.

The aggregate `make test` and `make check` targets cover the implemented
deterministic offline layers. Required external or separately instrumented
gates remain explicit targets and never skip or report success.

`make test-readme` verifies every documented shell command against the maintained
Make surface. `make test-openssh` is a joint production-command gate: Go creates
a fresh near-limit GQ carrier directly in an isolated test agent, C++ verifies
it from a static public JWKS file, and an isolated host `sshd` consumes the
rendered `AuthorizedKeysCommand` fragment for allow, PTY and deny checks. OpenSSH
requires that command to be root-owned and not group/world writable. A local
checkout binary therefore fails closed; provide an explicitly installed test
copy with `OPENSSH_TEST_BINARY=/absolute/path` rather than using a wrapper.

`make test-live` extends that same joint harness only for the four accepted
Google/Auth0 workload cells. It consumes an owner-provided protected Go
initialization request and existing ADC/native-store credentials, requires the
exact Auth0 Action source when applicable, generates a fresh standard or GQ
carrier in Go, verifies it through both direct implementations and isolated
OpenSSH using the root-owned C++ command, and writes one new sanitized evidence
file. Go first reverifies the registration through its compiled production
bootstrap and exact installed signed release. The raw credential, carrier and
public-key staging files remain in a
private temporary directory and are removed on every exit. The harness has no
provider-management path and cannot create or change an application, tenant,
service account, role, API, callback, Action or secret. Interactive native and
confidential-web live cells remain outside this workload harness and fail
closed until their owner-provided registrations and hosting prerequisites are
available.

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

This layer is exercised directly against the immutable corpus and is wired
through the issuer policy, direct carrier verifier and production command. The
early maximum-size carrier subgate is complete; full corpus conformance and
real-OpenSSH acceptance remain separate gates.

## Offline issuer-key checkpoint

The C++ verifier's typed key-source boundary admits only an absolute
`static-jwks-file` path and rejects `oidc-discovery` without network activity.
It opens one bounded descriptor with no symlink following, requires a regular
file owned by the configured owner or root, and rejects group/other write
permission. The schema-specific SAX parser accepts only complete public RS256
signing JWKs and rejects duplicate JSON members or key IDs, private or unknown
members, unsupported key roles, malformed canonical Base64url and trailing
data. Unknown `kid` resolution fails closed.

The same offline file/key boundary is consumed by issuer policy,
`config check`, initialization and the production verification command.

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
evidence-result digest. That layer remains independently testable and is now
consumed by the internal direct verifier described below.

## Direct verifier checkpoint

The internal direct verifier now connects the strict envelope, CIC, offline
issuer policy and OpenSSH certificate layers. It validates the exact
nine-member CIC and public-only ES256 or Ed25519 JWK, computes the exact CIC
commitment, independently binds the issuer result digest, and verifies the
caller signature over the preserved JWS signing input.

The carrier boundary verifies the offered key type, P-256 or Ed25519
certificate signature and ephemeral CA, canonical certified-key equality,
credential-derived certificate validity, the derived principal, and
default-deny account rules. One matching rule must own the exact issuer, every
typed claim predicate, and the complete permission-extension subset; rules
never combine. The returned carrier data is authenticated and the internal
command adapter formats its one exact authorized-keys line.

Pinned fixtures pass all five direct core vectors, including GQ, and the two
published standard-evidence P-256 and Ed25519 carriers. The test binary also
provides a bounded `--direct-carrier-file` frame ingress for the early joint
Go-generated maximum-size GQ carrier subgate. This is explicitly a conformance
harness, not a production command or configuration format.

## Configuration, command and syslog adapter checkpoint

The production parser now validates the complete typed server configuration,
including resource and duration bounds, static JWKS, closed algorithms/profile
pairings, same-issuer policies with unique policy IDs, account rules and the
local syslog facility. `config check` is offline and uses that parser;
`sshd-config render` validates its paths and user token before emitting the
minimal deterministic fragment.

The verification adapter implements the exact silent, zero-exit denial
contract and emits one bounded R011 local-syslog event. Tests cover exact field
order and severity, unsafe-username hashing, authenticated identifiers,
identity references, overflow, redaction, logging failure and checked stdout.
Production `verify` applies one configured monotonic budget, capped at ten
seconds, from command entry through the final pre-output boundary. SIGINT and
SIGTERM set a signal-safe cancellation flag. Every verification stage checks
the same absolute budget, with deadline preceding simultaneous cancellation,
and denial remains zero-exit with empty stdout and one audit event. Deterministic
tests cover authenticated production output, cumulative expiry, cancellation,
their simultaneous precedence, the exact ten-second configuration boundary,
and cancellation of offline configuration checking. Individual synchronous
file, OpenSSL and output calls are bounded by admitted input sizes but are not
preempted mid-call; real process/OpenSSH timing evidence remains a later gate.

`config init` implements the reconciled non-interactive R005 grammar. It emits
the exact canonical deny-all profile or combines a strict two-member policy
input with explicit operational overrides. `--output` uses same-directory
atomic 0600 publication, rejects unsafe targets and never overwrites without
`--force`; forced replacement is limited to regular files. The initializer
reuses the production typed parser, including offline static-JWKS validation.
`test-cli` covers exact bytes, useful policy, bounds, publication and safe
failures.

The command root and every implemented subcommand support both `-h` and
`--help`. Help exits successfully, writes only its stable usage text to stdout,
and is handled before configuration access, verification, clock use or audit
emission. Go and C++ emit byte-identical help for their shared
`credbind-ssh-authorized-keys` surface.

## Sanitizer and fuzz gates

`make test-sanitize` builds separate ASan/UBSan parser and production-adapter
test binaries, runs the unit and authenticated command paths, and replays the
pinned parser/carrier/JWKS corpus. Linux retains AddressSanitizer leak
detection. Darwin explicitly uses `ASAN_OPTIONS=detect_leaks=0` because that
platform's AddressSanitizer does not provide LeakSanitizer; this does not make
a Linux leak-check claim.

Three Clang/libFuzzer harnesses cover the strict core JSON boundary, bounded
OpenSSH certificate parser and CredBind token/Base64url/JWS parsing boundary.
The smoke gate copies the small reviewed seed corpora into `.cache` before
mutation, so test execution never rewrites committed inputs or adds generated
corpus objects to the repository:

```sh
make test-sanitize
make test-fuzz-smoke
make fuzz TARGET=json DURATION=60
make fuzz TARGET=certificate DURATION=60
make fuzz TARGET=token DURATION=60
```

`FUZZ_CXX` may select another compatible Clang. The targets fail with a clear
prerequisite error if its libFuzzer runtime is unavailable. Sanitizer and fuzz
binaries remain ignored development artifacts under `.cache`.

## Conformance input

`make fixtures` fetches and verifies the exact locked artifact and manifest.
An offline reproduction may set `CREDBIND_FIXTURE_SOURCE` to an existing asset;
its SHA-256 must still match.

The local real-OpenSSH target remains a release-environment gate until it runs
with the required root-owned verifier copy. Even a passing local target would
be one host slice, not the required RHEL side-by-side suite/extension/disclosure/
deadline matrix. This baseline makes no release, security, packaging or
platform-support claim.

The project is licensed under Apache License 2.0. Contributions must include a
Developer Certificate of Origin sign-off.
