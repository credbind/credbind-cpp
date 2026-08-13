# Conformance baseline

`fixtures.lock.json` pins the exact immutable CredBind SSH v1 conformance
release consumed by this repository. Updating it is a coordinated change with
the specification, planning record and Go implementation.

This repository-bootstrap lock is not a conformance result. The build-baseline
checkpoint must add offline `make fixtures` and `make test-conformance` targets
before implementation evidence can be recorded.
