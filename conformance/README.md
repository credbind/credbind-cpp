# Conformance baseline

`fixtures.lock.json` pins the exact immutable CredBind SSH v1 conformance
release consumed by this repository. Updating it is a coordinated change with
the specification, planning record and Go implementation.

`make fixtures` installs and verifies the pinned artifact. `make test-fixtures`
is offline and exercises the implemented JSON, compact-JWS, and OpenSSH
certificate parser subset against all published base vectors and both carrier
certificates. It does not claim full corpus conformance: `make
test-conformance` continues to fail closed until every applicable case has a
complete harness.
