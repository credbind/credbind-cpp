#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Create deterministic checksums, SPDX, licenses and provenance for C++."""

from __future__ import annotations

import argparse
import datetime
import gzip
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
PROJECT = "credbind-cpp"
STABLE_VERSION = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")
TARGET = re.compile(r"(?:darwin|linux)-(?:arm64|amd64)\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def fail(message: str) -> None:
    raise RuntimeError(message)


def run(arguments: list[str]) -> str:
    result = subprocess.run(
        arguments, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, text=True,
    )
    if result.returncode != 0:
        fail(f"command failed: {' '.join(arguments)}: {result.stderr.strip()}")
    return result.stdout.strip()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def load_json(path: pathlib.Path) -> Any:
    data = path.read_bytes()
    if len(data) > 1 << 20:
        fail(f"oversized JSON input: {path}")
    try:
        return json.loads(data, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid JSON input {path}: {error}")


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)


def write_file(path: pathlib.Path, data: bytes, mode: int = 0o644) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)


def validate_inputs(arguments: argparse.Namespace) -> tuple[pathlib.Path, pathlib.Path, bool, int]:
    if not REVISION.fullmatch(arguments.revision):
        fail("revision must be exactly 40 lowercase hexadecimal characters")
    if not TARGET.fullmatch(arguments.target):
        fail("target must be one supported normalized system-architecture pair")
    try:
        source_epoch = int(arguments.source_date_epoch)
    except ValueError:
        fail("source date epoch must be a positive integer")
    if source_epoch <= 0:
        fail("source date epoch must be a positive integer")
    if run(["git", "rev-parse", "HEAD"]) != arguments.revision:
        fail("release revision does not match HEAD")
    if run(["git", "show", "-s", "--format=%ct", "HEAD"]) != str(source_epoch):
        fail("source date epoch does not match the release revision")
    dirty = bool(run(["git", "status", "--porcelain", "--untracked-files=normal"]))
    stable = bool(STABLE_VERSION.fullmatch(arguments.version))
    if arguments.archive and (not stable or dirty):
        fail("release archive requires a stable version and clean source tree")
    if not stable and arguments.version != "v0.0.0-dev":
        fail("version must be a stable vMAJOR.MINOR.PATCH or v0.0.0-dev")
    dist_root = ROOT / "dist"
    distribution = ROOT / arguments.dist
    if distribution != dist_root / arguments.target or not safe_release_directory(dist_root) \
            or not safe_release_directory(distribution):
        fail("distribution must be the exact existing dist/TARGET directory")
    binary = distribution / "credbind-ssh-authorized-keys"
    status = binary.lstat()
    if not stat.S_ISREG(status.st_mode) or binary.is_symlink() or status.st_mode & 0o111 == 0:
        fail("release binary is not a regular executable")
    return distribution, binary, dirty, source_epoch


def safe_release_directory(path: pathlib.Path) -> bool:
    try:
        status = path.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(status.st_mode) and not path.is_symlink() \
        and status.st_uid == os.geteuid() and status.st_mode & 0o022 == 0


def reviewed_dependencies(metadata: Any, pkg_config: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not isinstance(metadata, dict) or set(metadata) != {"dependencies", "system_dependencies", "policy"}:
        fail("invalid C++ dependency inventory envelope")
    dependencies = metadata["dependencies"]
    systems = metadata["system_dependencies"]
    if not isinstance(dependencies, list) or len(dependencies) != 2 or not isinstance(systems, list) or len(systems) != 1:
        fail("unexpected C++ dependency inventory size")
    names: set[str] = set()
    for item in dependencies:
        required = {"name", "version", "license", "license_file", "license_sha256", "header", "header_sha256", "repository", "source", "commit", "commit_signature_verified", "release_published", "linkage"}
        if not isinstance(item, dict) or set(item) != required or item["name"] in names:
            fail("invalid or duplicate vendored dependency metadata")
        names.add(item["name"])
        for path_field, digest_field in (("header", "header_sha256"), ("license_file", "license_sha256")):
            source = ROOT / item[path_field]
            if not source.is_file() or source.is_symlink() or not SHA256.fullmatch(item[digest_field]) \
                    or digest(source.read_bytes()) != item[digest_field]:
                fail(f"vendored dependency digest mismatch: {item['name']}")
    system = systems[0]
    required_system = {"name", "minimum_version", "api_baseline", "license", "linkage", "pkg_config", "prohibited_linkage"}
    if not isinstance(system, dict) or set(system) != required_system or system["pkg_config"] != "libcrypto":
        fail("invalid system dependency metadata")
    version = run([pkg_config, "--modversion", "libcrypto"])
    try:
        numeric = tuple(int(value) for value in version.split("."))
    except ValueError:
        fail("libcrypto reported a non-numeric version")
    if numeric < (3, 0, 0):
        fail("libcrypto is below the reviewed 3.0 API floor")
    resolved = dict(system)
    resolved["version"] = version
    return sorted(dependencies, key=lambda item: item["name"]), resolved


def copy_licenses(stage: pathlib.Path, dependencies: list[dict[str, Any]], system: dict[str, Any]) -> list[dict[str, Any]]:
    directory = stage / "LICENSES"
    directory.mkdir(mode=0o755)
    project_data = (ROOT / "LICENSE").read_bytes()
    if digest(project_data) != "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4":
        fail("project license digest mismatch")
    project_file = f"LICENSE.{PROJECT}"
    write_file(directory / project_file, project_data)
    entries = [{"name": PROJECT, "version": "PROJECT", "license": "Apache-2.0", "license_sha256": digest(project_data), "shipped_file": f"LICENSES/{project_file}", "distribution": "project"}]
    for item in dependencies:
        data = (ROOT / item["license_file"]).read_bytes()
        output = f"LICENSE.{safe_name(item['name'])}"
        write_file(directory / output, data)
        entries.append({"name": item["name"], "version": item["version"], "license": item["license"], "license_sha256": item["license_sha256"], "shipped_file": f"LICENSES/{output}", "distribution": item["linkage"]})
    entries.append({"name": system["name"], "version": system["version"], "license": system["license"], "license_sha256": None, "distribution": system["linkage"], "shipped_file": None})
    return entries


def fixture_materials() -> list[dict[str, Any]]:
    lock = load_json(ROOT / "conformance" / "fixtures.lock.json")
    if not isinstance(lock, dict) or set(lock) != {
        "format_version", "release", "specification_revision", "artifact", "manifest",
    } or lock["format_version"] != 1 or not REVISION.fullmatch(str(lock["specification_revision"])):
        fail("invalid fixture lock envelope")
    artifact = lock["artifact"]
    manifest = lock["manifest"]
    if not isinstance(artifact, dict) or set(artifact) != {"name", "url", "sha256"} \
            or not isinstance(manifest, dict) or set(manifest) != {"path", "sha256"} \
            or not isinstance(artifact["url"], str) or not SHA256.fullmatch(str(artifact["sha256"])) \
            or not isinstance(manifest["path"], str) or not SHA256.fullmatch(str(manifest["sha256"])):
        fail("invalid fixture lock material")
    return [
        {
            "uri": f"git+https://github.com/credbind/spec@{lock['specification_revision']}",
            "digest": {"gitCommit": lock["specification_revision"]},
        },
        {"uri": artifact["url"], "digest": {"sha256": artifact["sha256"]}},
        {
            "uri": f"{artifact['url']}#{manifest['path']}",
            "digest": {"sha256": manifest["sha256"]},
        },
    ]


def spdx(version: str, revision: str, target: str, created: str, dependencies: list[dict[str, Any]], system: dict[str, Any], binary_sha: str) -> dict[str, Any]:
    root_id = "SPDXRef-Package-credbind-cpp"
    packages = [{"SPDXID": root_id, "name": PROJECT, "versionInfo": version, "downloadLocation": f"https://github.com/credbind/credbind-cpp/commit/{revision}", "filesAnalyzed": False, "licenseConcluded": "Apache-2.0", "licenseDeclared": "Apache-2.0", "supplier": "Organization: CredBind", "copyrightText": "NOASSERTION"}]
    relationships = []
    for index, item in enumerate(dependencies + [system], 1):
        identifier = f"SPDXRef-Package-dependency-{index}"
        package = {"SPDXID": identifier, "name": item["name"], "versionInfo": item["version"], "downloadLocation": item.get("source", "NOASSERTION"), "filesAnalyzed": False, "licenseConcluded": item["license"], "licenseDeclared": item["license"], "copyrightText": "NOASSERTION"}
        packages.append(package)
        relationships.append({"spdxElementId": root_id, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": identifier})
    binary_id = "SPDXRef-File-credbind-ssh-authorized-keys"
    relationships.append({"spdxElementId": root_id, "relationshipType": "CONTAINS", "relatedSpdxElement": binary_id})
    return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": f"{PROJECT}-{version}-{target}", "documentNamespace": f"https://credbind.dev/spdx/{PROJECT}/{version}/{revision}/{target}", "creationInfo": {"created": created, "creators": ["Organization: CredBind", "Tool: credbind-cpp-release-v1"]}, "packages": packages, "files": [{"SPDXID": binary_id, "fileName": "credbind-ssh-authorized-keys", "checksums": [{"algorithm": "SHA256", "checksumValue": binary_sha}], "licenseConcluded": "NOASSERTION", "licenseInfoInFiles": ["NOASSERTION"], "copyrightText": "NOASSERTION"}], "relationships": relationships}


def provenance(arguments: argparse.Namespace, source_epoch: int, dirty: bool, dependencies: list[dict[str, Any]], system: dict[str, Any], subjects: list[dict[str, str]]) -> dict[str, Any]:
    materials = [{"uri": f"git+https://github.com/credbind/credbind-cpp@{arguments.revision}", "digest": {"gitCommit": arguments.revision}}]
    materials.extend({"uri": item["source"], "digest": {"sha256": item["header_sha256"]}} for item in dependencies)
    materials.append({"uri": f"pkg:generic/openssl@{system['version']}?component=libcrypto"})
    materials.extend(fixture_materials())
    compiler = run([arguments.cxx, "--version"]).splitlines()[0]
    return {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": item["name"], "digest": {"sha256": item["sha256"]}} for item in subjects], "predicateType": "https://slsa.dev/provenance/v1", "predicate": {"buildDefinition": {"buildType": "https://credbind.dev/build/cpp-release-v1", "externalParameters": {"version": arguments.version, "revision": arguments.revision, "target": arguments.target, "sourceDateEpoch": source_epoch}, "internalParameters": {"compiler": compiler, "libcryptoVersion": system["version"], "sourceDirty": dirty}, "resolvedDependencies": materials}, "runDetails": {"builder": {"id": f"https://github.com/credbind/credbind-cpp/blob/{arguments.revision}/Makefile#release-metadata"}}}}


def add_tar_file(bundle: tarfile.TarFile, source: pathlib.Path, name: pathlib.Path, mode: int, source_epoch: int) -> None:
    data = source.read_bytes()
    info = tarfile.TarInfo(name.as_posix())
    info.size = len(data)
    info.mode = mode
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = source_epoch
    bundle.addfile(info, io.BytesIO(data))


def archive(distribution: pathlib.Path, stage: pathlib.Path, binary: pathlib.Path, version: str, target: str, source_epoch: int) -> pathlib.Path:
    release_root = distribution.parent / "release"
    release_root.mkdir(mode=0o755, exist_ok=True)
    if not safe_release_directory(release_root):
        fail("release output directory has an unsafe owner, mode or type")
    output = release_root / f"{PROJECT}-{version}-{target}.tar.gz"
    descriptor, temporary_name = tempfile.mkstemp(prefix=".archive-", dir=release_root)
    temporary = pathlib.Path(temporary_name)
    prefix = f"{PROJECT}-{version}-{target}"
    try:
        with os.fdopen(descriptor, "wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=source_epoch) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as bundle:
                    add_tar_file(bundle, binary, pathlib.Path(prefix) / binary.name, 0o755, source_epoch)
                    for source in sorted(stage.rglob("*")):
                        if source.is_file():
                            add_tar_file(bundle, source, pathlib.Path(prefix) / source.relative_to(stage), 0o644, source_epoch)
            raw.flush()
            os.fsync(raw.fileno())
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()
    atomic_replace(output.with_suffix(output.suffix + ".sha256"), f"{digest(output.read_bytes())}  {output.name}\n".encode("ascii"))
    return output


def atomic_replace(path: pathlib.Path, data: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def replace_directory(source: pathlib.Path, destination: pathlib.Path) -> None:
    if destination.exists() or destination.is_symlink():
        if not safe_release_directory(destination):
            fail("existing release metadata directory has an unsafe owner, mode or type")
        shutil.rmtree(destination)
    os.replace(source, destination)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cxx", default="c++")
    parser.add_argument("--pkg-config", default="pkg-config")
    parser.add_argument("--dist", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--source-date-epoch", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--archive", action="store_true")
    arguments = parser.parse_args()
    distribution, binary, dirty, source_epoch = validate_inputs(arguments)
    dependencies, system = reviewed_dependencies(load_json(ROOT / "third_party" / "dependencies.json"), arguments.pkg_config)
    binary_sha = digest(binary.read_bytes())
    created = datetime.datetime.fromtimestamp(source_epoch, datetime.UTC).isoformat().replace("+00:00", "Z")
    temporary: pathlib.Path | None = pathlib.Path(tempfile.mkdtemp(prefix=".release-metadata-", dir=distribution))
    try:
        licenses = copy_licenses(temporary, dependencies, system)
        write_file(temporary / "licenses.json", canonical({"version": 1, "entries": licenses}))
        write_file(temporary / "sbom.spdx.json", canonical(spdx(arguments.version, arguments.revision, arguments.target, created, dependencies, system, binary_sha)))
        subjects = [{"name": binary.name, "sha256": binary_sha}, {"name": "licenses.json", "sha256": digest((temporary / "licenses.json").read_bytes())}, {"name": "sbom.spdx.json", "sha256": digest((temporary / "sbom.spdx.json").read_bytes())}]
        write_file(temporary / "provenance.json", canonical(provenance(arguments, source_epoch, dirty, dependencies, system, subjects)))
        checksummed = subjects + [
            {"name": "provenance.json", "sha256": digest((temporary / "provenance.json").read_bytes())},
        ] + [{"name": path.relative_to(temporary).as_posix(), "sha256": digest(path.read_bytes())} for path in sorted((temporary / "LICENSES").iterdir())]
        write_file(temporary / "SHA256SUMS", "".join(f"{item['sha256']}  {item['name']}\n" for item in sorted(checksummed, key=lambda value: value["name"])).encode("ascii"))
        destination = distribution / "release-metadata"
        replace_directory(temporary, destination)
        temporary = None
        if arguments.archive:
            print(archive(distribution, destination, binary, arguments.version, arguments.target, source_epoch).relative_to(ROOT))
        else:
            print(destination.relative_to(ROOT))
    finally:
        if temporary is not None and temporary.exists():
            shutil.rmtree(temporary)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        raise SystemExit(str(error)) from None
