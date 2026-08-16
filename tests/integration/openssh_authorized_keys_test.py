#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise a fresh maximum-size GQ carrier through the production command and sshd."""

from __future__ import annotations

import base64
import json
import os
import pathlib
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import time


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def executable(name: str) -> str:
    path = shutil.which(name)
    require(path is not None, f"required executable is unavailable: {name}")
    return str(pathlib.Path(path).resolve())


def run(
    command: list[str],
    *,
    cwd: pathlib.Path | None = None,
    environment: dict[str, str] | None = None,
    timeout: float = 30,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )


def write_private(path: pathlib.Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        written = os.write(descriptor, data)
        require(written == len(data), "short private test-file write")
    finally:
        os.close(descriptor)


def reserve_port() -> int:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])
    finally:
        listener.close()


def wait_for_socket(path: pathlib.Path, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        require(process.poll() is None, "isolated ssh-agent exited before creating its socket")
        if path.exists():
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                connection.settimeout(0.1)
                connection.connect(str(path))
                return
            except OSError:
                pass
            finally:
                connection.close()
        time.sleep(0.02)
    raise RuntimeError("isolated ssh-agent did not create its socket")


def wait_for_tcp(port: int, process: subprocess.Popen[bytes], log: pathlib.Path) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"isolated sshd exited early: {log.read_text(errors='replace')}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.02)
    raise RuntimeError(f"isolated sshd did not listen: {log.read_text(errors='replace')}")


def stop(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def verifier_config(descriptor: dict[str, object], jwks: pathlib.Path) -> bytes:
    issuer = str(descriptor["issuer"])
    user = str(descriptor["requested_user"])
    account = descriptor["account_rule"]
    require(isinstance(account, dict), "generated account rule has the wrong type")
    value = {
        "version": 1,
        "clock_skew": "30s",
        "total_verification_deadline": "10s",
        "resource_limits": {
            "max_token_bytes": 32768,
            "max_evidence_bytes": 16384,
            "max_ssh_certificate_bytes": 49152,
            "max_offered_key_chars": 65536,
            "max_authorized_keys_output_chars": 4096,
        },
        "trusted_issuers": [{
            "policy_id": "joint-gq-live",
            "issuer": issuer,
            "key_source": {"type": "static-jwks-file", "path": str(jwks)},
            "audiences": [str(descriptor["audience"])],
            "issuer_algorithms": ["RS256"],
            "caller_algorithms": list(descriptor["caller_algorithms"]),
            "evidence_profiles": list(descriptor["evidence_profiles"]),
            "binding_profiles": list(descriptor["binding_profiles"]),
            "acquisition_profiles": ["oidc-native-auth-code-v1"],
            "require_non_reconstructible_evidence": True,
            "certificate_principal_claim": str(descriptor["principal_claim"]),
        }],
        "accounts": {user: {"allow": [{
            "issuer": issuer,
            "all": [{
                "claim": str(account["claim"]),
                "type": "string",
                "op": "equals",
                "value": str(account["value"]),
            }],
            "allowed_certificate_extensions": list(
                account["allowed_certificate_extensions"]
            ),
        }]}},
        "logging": {"facility": "authpriv"},
    }
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def main() -> int:
    require(len(sys.argv) == 3, "usage: openssh_authorized_keys_test.py BINARY GO_ROOT")
    require(sys.platform.startswith(("darwin", "linux")), "real OpenSSH gate requires Darwin or Linux")
    binary = pathlib.Path(sys.argv[1]).resolve()
    go_root = pathlib.Path(sys.argv[2]).resolve()
    require(binary.is_file(), "C++ verifier binary is unavailable")
    binary_status = binary.stat()
    require(
        binary_status.st_uid == 0 and binary_status.st_mode & 0o022 == 0,
        "OpenSSH requires a root-owned, non-group/world-writable command; "
        "install the built verifier temporarily and set OPENSSH_TEST_BINARY",
    )
    require((go_root / "go.mod").is_file(), "Go carrier generator repository is unavailable")
    ssh = executable("ssh")
    sshd = executable("sshd")
    ssh_agent = executable("ssh-agent")
    ssh_keygen = executable("ssh-keygen")
    go = executable("go")
    current_user = pwd.getpwuid(os.geteuid()).pw_name
    require(current_user != "", "current account has no OpenSSH username")

    root = pathlib.Path(tempfile.mkdtemp(prefix="credbind-cpp-ssh-", dir="/tmp"))
    agent: subprocess.Popen[bytes] | None = None
    server: subprocess.Popen[bytes] | None = None
    server_log_handle = None
    try:
        agent_socket = root / "agent.sock"
        agent = subprocess.Popen(
            [ssh_agent, "-D", "-a", str(agent_socket)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wait_for_socket(agent_socket, agent)

        artifact = root / "carrier"
        artifact.mkdir(mode=0o700)
        environment = dict(os.environ)
        environment.update({
            "CREDBIND_JOINT_GQ_OUTPUT": str(artifact),
            "CREDBIND_JOINT_GQ_USER": current_user,
            "CREDBIND_JOINT_GQ_AGENT": "1",
            "GOEXPERIMENT": "jsonv2",
            "SSH_AUTH_SOCK": str(agent_socket),
        })
        generated = run(
            [go, "test", "-count=1", "-run", "^TestMaximumSizeGQCarrier$", "./ssh/internal/verifier"],
            cwd=go_root,
            environment=environment,
            timeout=90,
        )
        require(
            generated.returncode == 0,
            f"fresh Go GQ carrier generation failed: {generated.stderr.decode(errors='replace')}",
        )
        descriptor_path = artifact / "carrier.json"
        descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
        jwks = artifact / "issuer-jwks.json"
        require(jwks.is_file(), "fresh generator did not publish its public JWKS")

        config_path = root / "verifier.json"
        allow_config = verifier_config(descriptor, jwks)
        write_private(config_path, allow_config)
        checked = run([str(binary), "config", "check", "--config", str(config_path)])
        require(
            (checked.returncode, checked.stdout, checked.stderr)
            == (0, b"configuration valid\n", b""),
            "fresh verifier configuration was rejected",
        )
        offered_key = str(descriptor["certificate_blob_base64"])
        key_type = str(descriptor["key_type_argument"])
        direct = run([
            str(binary), "verify", "--config", str(config_path), "--user", current_user,
            "--key", offered_key, "--key-type", key_type,
        ], timeout=15)
        expected = descriptor["expected"]
        require(isinstance(expected, dict), "generated expected result has the wrong type")
        expected_line = (
            f'cert-authority,principals="{expected["principal"]}" '
            f'{expected["ca_key_type"]} {expected["ca_public_key_base64"]}\n'
        ).encode()
        require(
            (direct.returncode, direct.stdout, direct.stderr) == (0, expected_line, b""),
            "production C++ verifier rejected the fresh maximum-size GQ carrier",
        )

        rendered = run([
            str(binary), "sshd-config", "render", "--config", str(config_path),
            "--verifier", str(binary), "--command-user", current_user,
        ])
        require(rendered.returncode == 0 and rendered.stderr == b"", "sshd fragment render failed")
        expected_fragment = (
            f"AuthorizedKeysCommand {binary} verify --config {config_path} "
            f"--user %u --key %k --key-type %t\n"
            f"AuthorizedKeysCommandUser {current_user}\n"
        ).encode()
        require(rendered.stdout == expected_fragment, "rendered sshd fragment was not exact")

        host_key = root / "host-ed25519"
        host_key_result = run([ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)])
        require(host_key_result.returncode == 0, "temporary sshd host-key generation failed")
        port = reserve_port()
        sshd_config = root / "sshd_config"
        sshd_bytes = (
            f"Port {port}\n"
            "ListenAddress 127.0.0.1\n"
            f"HostKey {host_key}\n"
            f"PidFile {root / 'sshd.pid'}\n"
            "AuthorizedKeysFile none\n"
        ).encode() + rendered.stdout + (
            "AuthenticationMethods publickey\n"
            "PubkeyAuthentication yes\n"
            "PasswordAuthentication no\n"
            "KbdInteractiveAuthentication no\n"
            "UsePAM no\n"
            "PermitRootLogin no\n"
            "StrictModes no\n"
            f"AllowUsers {current_user}\n"
            "PermitTTY yes\n"
            "AllowTcpForwarding yes\n"
            "X11Forwarding no\n"
            "LogLevel VERBOSE\n"
        ).encode()
        write_private(sshd_config, sshd_bytes)
        syntax = run([sshd, "-t", "-f", str(sshd_config)])
        require(syntax.returncode == 0, f"sshd -t rejected rendered fragment: {syntax.stderr.decode(errors='replace')}")
        effective = run([sshd, "-T", "-f", str(sshd_config)])
        normalized_effective = effective.stdout.lower()
        require(
            effective.returncode == 0
            and b"authorizedkeyscommand " + str(binary).lower().encode() in normalized_effective
            and b"authenticationmethods publickey" in normalized_effective,
            "sshd -T did not retain the production command boundary: "
            + effective.stderr.decode(errors="replace")
            + effective.stdout.decode(errors="replace"),
        )

        server_log = root / "sshd.log"
        server_log_handle = server_log.open("wb")
        server = subprocess.Popen(
            [sshd, "-D", "-e", "-f", str(sshd_config)],
            stdin=subprocess.DEVNULL,
            stdout=server_log_handle,
            stderr=server_log_handle,
        )
        wait_for_tcp(port, server, server_log)
        client_base = [
            ssh, "-F", "/dev/null", "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ControlMaster=no", "-o", f"IdentityAgent={agent_socket}",
            "-o", "IdentityFile=none", "-p", str(port), "-l", current_user,
            "127.0.0.1",
        ]
        client_environment = dict(os.environ)
        client_environment["SSH_AUTH_SOCK"] = str(agent_socket)
        allowed = run(client_base + ["true"], environment=client_environment, timeout=20)
        server_log_handle.flush()
        require(
            allowed.returncode == 0,
            "real OpenSSH rejected the production C++ AuthorizedKeysCommand result\n"
            + allowed.stderr.decode(errors="replace")
            + server_log.read_text(errors="replace"),
        )
        pty = run(client_base[:1] + ["-tt"] + client_base[1:] + ["test -t 0"], environment=client_environment, timeout=20)
        require(pty.returncode == 0, "admitted permit-pty extension was not effective")

        denied_value = json.loads(allow_config)
        denied_value["accounts"] = {}
        replacement = root / "deny.json"
        write_private(replacement, (json.dumps(denied_value, indent=2, sort_keys=True) + "\n").encode())
        os.replace(replacement, config_path)
        denied = run(client_base + ["true"], environment=client_environment, timeout=20)
        require(denied.returncode != 0, "real OpenSSH unexpectedly admitted deny-all policy")

        server_log_handle.flush()
        server_bytes = server_log.read_bytes()
        disclosed = allowed.stdout + allowed.stderr + denied.stdout + denied.stderr + server_bytes
        require(offered_key.encode() not in disclosed, "OpenSSH diagnostics disclosed the offered carrier")
        certificate_blob = base64.b64decode(offered_key, validate=True)
        require(certificate_blob not in disclosed, "OpenSSH diagnostics disclosed raw certificate bytes")
        print("real OpenSSH accepted fresh maximum-size GQ via production C++ verifier; denial remained closed")
        return 0
    finally:
        stop(server)
        if server_log_handle is not None:
            server_log_handle.close()
        stop(agent)
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
