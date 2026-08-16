<!-- SPDX-License-Identifier: Apache-2.0 -->

# C++ verifier operator walkthrough

Status: pre-release walkthrough. The offline verifier command is implemented,
but no server platform is supported until the shared RHEL/OpenSSH matrix is
complete. This guide does not turn a checkout build into an installable
production release.

The C++ artifact is an offline `AuthorizedKeysCommand` verifier. It does not
create SSH certificates, run a client login, perform OIDC discovery or manage
provider resources. Certificates are created by the Go client after its
owner-controlled registry and provider prerequisites are installed.

## 1. Build and run offline checks

From a clean checkout:

```text
make build
make check
./dist/$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)/credbind-ssh-authorized-keys --help
```

Use the repository's canonical `make` targets rather than guessing compiler or
linker flags. `make check` covers the deterministic offline implementation; it
does not install the binary, alter `sshd`, fetch provider data or create trust.

## 2. Verify release material before installation

Use only a published, signed release whose archive checksum, artifact
signature, provenance, SBOM and license inventory have been reviewed. Current
`make release-package` output is deterministic but deliberately unsigned.

The Go and C++ verifier binaries have the same basename and must remain at
distinct absolute paths:

```text
/usr/libexec/credbind/go/credbind-ssh-authorized-keys
/usr/libexec/credbind/cpp/credbind-ssh-authorized-keys
```

Install the selected verifier as root-owned and not group- or world-writable.
Never make the daemon's choice depend on `PATH` order.

## 3. Bootstrap deny-all

Create and validate a complete explicit deny-all configuration:

```text
credbind-ssh-authorized-keys config init --deny-all \
  --output /absolute/staging/path/verifier.json
credbind-ssh-authorized-keys config check \
  --config /absolute/staging/path/verifier.json
```

The deterministic profile materializes the shared defaults, including `30s`
clock skew and a `5s` total verification deadline. It trusts no issuer and
authorizes no account.

## 4. Create useful offline policy

Prepare one protected absolute regular non-symlink JSON file with exactly two
top-level members: non-empty `trusted_issuers` and non-empty `accounts`. C++
accepts only `static-jwks-file`; it does not accept `oidc-discovery` and never
performs network I/O.

```text
credbind-ssh-authorized-keys config init \
  --policy-input /absolute/protected/policy-input.json \
  --output /absolute/staging/path/verifier.json
credbind-ssh-authorized-keys config check \
  --config /absolute/staging/path/verifier.json
```

The static JWKS snapshot must contain only the reviewed public issuer keys and
meet the ownership and mode checks. Client provider data does not create server
trust. Use `--force` only for an intentional replacement of a reviewed regular
output file.

## 5. Render and stage OpenSSH configuration

```text
credbind-ssh-authorized-keys sshd-config render \
  --config /absolute/final/path/verifier.json \
  --verifier /usr/libexec/credbind/cpp/credbind-ssh-authorized-keys \
  --command-user <dedicated-unprivileged-user>
```

The renderer prints only the minimal two-line fragment and changes no host
state. Review it, then use the server's configuration-management procedure to:

1. verify ownership and permissions for the binary, configuration, cache
   directory if present, and every static-JWKS file;
2. install the fragment without removing the prior recovery path;
3. run the host's `sshd -t` and inspect `sshd -T` for the intended daemon
   configuration;
4. reload through the host's established service process; and
5. keep an authenticated recovery session open while testing allow and deny.

The exact privileged commands are platform-owned and are not guessed by this
repository.

## 6. Local real-OpenSSH gate

OpenSSH refuses an `AuthorizedKeysCommand` that is writable by an unprivileged
checkout owner. On a disposable test host, the project owner may install the
exact built test verifier at a separate root-owned path and run:

```text
OPENSSH_TEST_BINARY=/absolute/root-owned/test/verifier make test-openssh
```

The target creates a fresh near-limit GQ certificate in Go, inserts it into an
isolated agent, renders the C++ production command, runs `sshd -t`/`sshd -T`
and exercises allow, PTY and denial behavior. It does not create or modify a
Google/Auth0 resource. A local pass is still not the required RHEL
side-by-side matrix.

## 7. Manual certificate smoke review

The production certificate must first be created with the Go client's
`credbind-ssh login --profile <profile>` after the owner-controlled provider
checkpoint. With the selected client agent and server staging in place, verify:

- the expected account succeeds through this exact absolute C++ verifier path;
- wrong account, issuer, key, principal, validity and extension cases deny with
  exit status zero and empty authorized-keys stdout;
- `sshd` observes the intended PTY and forwarding extensions;
- one bounded local-syslog audit event is emitted for each attempt; and
- audit/log material contains no token, evidence, carrier, offered key or raw
  unsafe user value.

Do not copy a certificate carrier into logs or tickets. Standard evidence can
be reconstructible and bearer-sensitive until its issuer credential expires.

## 8. Rollback

Rollback selects the prior absolute `AuthorizedKeysCommand` path and prior
reviewed daemon configuration, validates it with `sshd -t`/`sshd -T`, and
reloads through the host's normal process. It does not delete the new verifier,
policy or evidence until the owner-selected rollback window ends. See the
shared [migration and cutover plan](https://github.com/credbind/planning/blob/main/rewrite/migration-cutover.md).
