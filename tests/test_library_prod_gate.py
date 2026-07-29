from __future__ import annotations

import copy
import hashlib
import json
import shutil
import socket
import socketserver
import stat
import subprocess
import tempfile
import threading
from argparse import Namespace
from pathlib import Path

import pytest

from scripts import aatk
from scripts import library_prod_gate as gate

EXPECTED_VERSION = "0.1.8"
EXPECTED_DIGEST = f"sha256:{'a' * 64}"


def payload(runtime: str, *, managed: list[str] | None = None) -> dict:
    paths = [".aw/profile/ref.json", "AGENTS.md", "CLAUDE.md"]
    ref = {
        "profile_ref": "developer",
        "profile_version": EXPECTED_VERSION,
        "profile_digest": EXPECTED_DIGEST,
        "runtime_kind": runtime,
        "managed_set": paths if managed is None else managed,
        "source_blueprint_ref": "aweb.team",
        "source_blueprint_version": "0.1.12",
    }
    return {
        "home_files": [
            {"path": paths[0], "content_utf8": json.dumps(ref)},
            {"path": paths[1], "content_utf8": "# Developer\n"},
            {"path": paths[2], "kind": "symlink", "target": "AGENTS.md"},
        ]
    }


def legacy_payload(runtime: str) -> dict:
    value = payload(runtime)
    ref_entry = value["home_files"][0]
    ref = json.loads(ref_entry["content_utf8"])
    ref.pop("runtime_kind")
    ref.pop("managed_set")
    ref_entry["content_utf8"] = json.dumps(ref)
    return value


def current_incumbent_args(tmp_path: Path, **overrides) -> Namespace:
    values = {
        "source_home": tmp_path,
        "public_url": "https://library.example",
        "origin_url": "https://library-origin.example",
        "expected_profile_version": EXPECTED_VERSION,
        "expected_profile_digest": EXPECTED_DIGEST,
        "incumbent_service_id": "srv-d8qm4jvavr4c73dhrmgg",
        "incumbent_deploy_id": "dep-d9koecdbedkc73b582vg",
        "incumbent_commit": "3376af7ee4a571488441794047018af94b06057f",
    }
    values.update(overrides)
    return Namespace(**values)


def test_candidate_requires_positional_managed_set() -> None:
    summary = gate.validate_candidate_payload(
        payload("claude-code"),
        "claude-code",
        expected_version=EXPECTED_VERSION,
        expected_digest=EXPECTED_DIGEST,
    )
    assert summary["managed_set_count"] == 3
    same_set_wrong_order = ["AGENTS.md", "CLAUDE.md", ".aw/profile/ref.json"]
    with pytest.raises(gate.GateError, match="index 0"):
        gate.validate_candidate_payload(
            payload("claude-code", managed=same_set_wrong_order),
            "claude-code",
            expected_version=EXPECTED_VERSION,
            expected_digest=EXPECTED_DIGEST,
        )


@pytest.mark.parametrize(
    "unsafe",
    [
        ".",
        "foo//bar",
        "foo/",
        "foo/./bar",
        "scheme://host",
        "../escape",
        "nul\x00path",
        "line\npath",
    ],
)
def test_managed_paths_must_be_canonical_and_safe(unsafe: str) -> None:
    with pytest.raises(gate.GateError, match="noncanonical or unsafe"):
        gate.validate_relative_paths([unsafe])


def test_candidate_rejects_unapproved_profile_pin() -> None:
    with pytest.raises(gate.GateError, match="profile_digest"):
        gate.validate_candidate_payload(
            payload("pi"),
            "pi",
            expected_version=EXPECTED_VERSION,
            expected_digest=f"sha256:{'b' * 64}",
        )


def test_candidate_rejects_duplicates() -> None:
    with pytest.raises(gate.GateError, match="duplicate"):
        gate.validate_candidate_payload(
            payload("pi", managed=[".aw/profile/ref.json", "AGENTS.md", "AGENTS.md"]),
            "pi",
            expected_version=EXPECTED_VERSION,
            expected_digest=EXPECTED_DIGEST,
        )


def test_recovery_requires_known_old_fingerprint() -> None:
    old = legacy_payload("pi")
    summary = gate.validate_recovery_payload(
        old,
        "pi",
        expected_version=EXPECTED_VERSION,
        expected_digest=EXPECTED_DIGEST,
    )
    assert summary["gate"] == "raw-recovery"
    with pytest.raises(gate.GateError, match="not the known"):
        gate.validate_recovery_payload(
            payload("pi"),
            "pi",
            expected_version=EXPECTED_VERSION,
            expected_digest=EXPECTED_DIGEST,
        )
    present_but_empty = payload("pi")
    empty_ref_entry = present_but_empty["home_files"][0]
    empty_ref = json.loads(empty_ref_entry["content_utf8"])
    empty_ref["runtime_kind"] = ""
    empty_ref["managed_set"] = []
    empty_ref_entry["content_utf8"] = json.dumps(empty_ref)
    with pytest.raises(gate.GateError, match="not the known"):
        gate.validate_recovery_payload(
            present_but_empty,
            "pi",
            expected_version=EXPECTED_VERSION,
            expected_digest=EXPECTED_DIGEST,
        )


def test_recovery_rejects_unrelated_nonzero_exit(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    with pytest.raises(gate.GateError, match="expected schema rejection"):
        gate.require_recovery_rejection(Path("/usr/bin/false"), home, "pi", tmp_path)


def test_recovery_accepts_only_exact_schema_rejection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class Completed:
        returncode = 1

    def expected_failure(command, cwd, stdout, stderr, check):
        stderr.write(
            b'Error: library materialize response runtime_kind "pi" does not match ref.json ""\n'
        )
        return Completed()

    monkeypatch.setattr(gate.subprocess, "run", expected_failure)
    home = tmp_path / "home"
    home.mkdir()
    result = gate.require_recovery_rejection(Path("/released/aw"), home, "pi", tmp_path)
    assert result["exit"] == 1


def test_materialized_ref_is_strict(tmp_path: Path) -> None:
    path = tmp_path / ".aw" / "profile" / "ref.json"
    path.parent.mkdir(parents=True)
    (tmp_path / "AGENTS.md").write_text("# Developer\n")
    path.write_text(
        json.dumps(
            {
                "profile_ref": "developer",
                "profile_version": EXPECTED_VERSION,
                "profile_digest": EXPECTED_DIGEST,
                "runtime_kind": "pi",
                "managed_set": ["AGENTS.md", ".aw/profile/ref.json"],
            }
        )
    )
    assert (
        gate.validate_materialized_ref(
            path,
            "pi",
            expected_version=EXPECTED_VERSION,
            expected_digest=EXPECTED_DIGEST,
        )["runtime_kind"]
        == "pi"
    )
    with pytest.raises(gate.GateError, match="mismatch"):
        gate.validate_materialized_ref(
            path,
            "claude-code",
            expected_version=EXPECTED_VERSION,
            expected_digest=EXPECTED_DIGEST,
        )


def test_materialized_ref_rejects_broken_or_escaping_symlinks(tmp_path: Path) -> None:
    home = tmp_path / "home"
    ref_path = home / ".aw" / "profile" / "ref.json"
    ref_path.parent.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.write_text("outside")
    link = home / "managed-link"
    link.symlink_to(outside)
    ref_path.write_text(
        json.dumps(
            {
                "profile_ref": "developer",
                "profile_version": EXPECTED_VERSION,
                "profile_digest": EXPECTED_DIGEST,
                "runtime_kind": "pi",
                "managed_set": ["managed-link", ".aw/profile/ref.json"],
            }
        )
    )
    with pytest.raises(gate.GateError, match="resolves outside") as escaped:
        gate.validate_materialized_ref(
            ref_path,
            "pi",
            expected_version=EXPECTED_VERSION,
            expected_digest=EXPECTED_DIGEST,
        )
    assert str(link) in str(escaped.value)
    assert str(outside) in str(escaped.value)
    link.unlink()
    link.symlink_to(home / "missing")
    with pytest.raises(gate.GateError, match="broken"):
        gate.validate_materialized_ref(
            ref_path,
            "pi",
            expected_version=EXPECTED_VERSION,
            expected_digest=EXPECTED_DIGEST,
        )


def test_released_aw_version_is_exact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = tmp_path / "aw"
    binary.write_bytes(b"reviewed aw fixture")

    class Completed:
        stdout = "aw 1.34.1\n"

    monkeypatch.setattr(gate, "REQUIRED_AW_PATH", binary)
    monkeypatch.setattr(gate, "REQUIRED_AW_SHA256", hashlib.sha256(binary.read_bytes()).hexdigest())
    monkeypatch.setattr(gate.subprocess, "run", lambda *args, **kwargs: Completed())
    with pytest.raises(gate.GateError, match="metadata"):
        gate.verify_released_aw(binary)


def test_spoofed_same_version_aw_fails_artifact_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = tmp_path / "aw"
    fake.write_text(f"#!/bin/sh\nprintf '{gate.REQUIRED_AW_VERSION_OUTPUT}'\n")
    fake.chmod(0o755)
    monkeypatch.setattr(gate, "REQUIRED_AW_PATH", fake)
    with pytest.raises(gate.GateError, match="SHA-256"):
        gate.verify_released_aw(fake)


def test_wrong_interpreter_or_entrypoint_artifact_is_refused(tmp_path: Path) -> None:
    fake = tmp_path / "fake"
    fake.write_text("#!/bin/sh\necho fake\n")
    fake.chmod(0o755)
    for expected_path, expected_digest, label in (
        (gate.REQUIRED_NODE_PATH, gate.REQUIRED_NODE_SHA256, "Node interpreter"),
        (gate.REQUIRED_PI_PATH, gate.REQUIRED_PI_SHA256, "Pi entry script"),
    ):
        with pytest.raises(gate.GateError, match="path must be exactly"):
            gate.verify_file_artifact(
                fake,
                expected_path=expected_path,
                expected_sha256=expected_digest,
                label=label,
            )
        with pytest.raises(gate.GateError, match="SHA-256"):
            gate.verify_file_artifact(
                fake,
                expected_path=fake,
                expected_sha256=expected_digest,
                label=label,
            )


def test_harness_artifact_overrides_are_not_exposed() -> None:
    with pytest.raises(SystemExit):
        gate.parser().parse_args(["candidate", "--pi-bin", "/tmp/fake-pi"])


def test_fake_pi_printing_expected_lines_is_refused(tmp_path: Path) -> None:
    fake_pi = tmp_path / "pi"
    fake_pi.write_text(
        "#!/bin/sh\n"
        "echo '# Developer'\n"
        "echo '> Profile developer v0.1.8 · blueprint aweb.team v0.1.12'\n"
    )
    fake_pi.chmod(0o755)
    with pytest.raises(gate.GateError, match="path must be exactly"):
        gate.verify_file_artifact(
            fake_pi,
            expected_path=gate.REQUIRED_PI_PATH,
            expected_sha256=gate.REQUIRED_PI_SHA256,
            label="Pi entry script",
        )


def test_claude_artifact_shape_is_native_macho(tmp_path: Path) -> None:
    native = tmp_path / "native-claude"
    native.write_bytes(gate.REQUIRED_CLAUDE_MAGIC + b"fixture")
    gate.verify_native_claude(native)

    script = tmp_path / "claude"
    script.write_text("#!/bin/sh\n")
    with pytest.raises(gate.GateError, match="native Mach-O"):
        gate.verify_native_claude(script)


def test_pi_harness_bypasses_fake_path_node(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    (fake_bin / "node").write_text("#!/bin/sh\necho FAKE_NODE_INTERCEPTED_PI\n")
    (fake_bin / "node").chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}:{gate.HARNESS_PATH}")
    monkeypatch.setenv("UNREVIEWED_INTERCEPT", "must-not-pass")
    home = tmp_path / "home"
    ref_path = home / ".aw" / "profile" / "ref.json"
    ref_path.parent.mkdir(parents=True)
    ref_path.write_text(
        json.dumps(
            {
                "profile_ref": "developer",
                "profile_version": EXPECTED_VERSION,
                "profile_digest": EXPECTED_DIGEST,
                "runtime_kind": "pi",
                "managed_set": [".aw/profile/ref.json"],
                "source_blueprint_ref": "aweb.team",
                "source_blueprint_version": "0.1.12",
            }
        )
    )
    captured = {}

    def fake_run_checked(command, *, cwd, stdout, stderr, label, env=None):
        captured["command"] = command
        captured["path"] = env["PATH"]
        captured["environment"] = env
        stdout.write_text("# Developer\n> Profile developer v0.1.8 · blueprint aweb.team v0.1.12\n")

    monkeypatch.setattr(gate, "run_checked", fake_run_checked)
    gate.run_harness(
        home,
        "pi",
        tmp_path,
        gate.REQUIRED_CLAUDE_PATH,
        gate.REQUIRED_PI_PATH,
        gate.REQUIRED_NODE_PATH,
    )
    assert captured["command"][:2] == [
        str(gate.REQUIRED_NODE_PATH),
        str(gate.REQUIRED_PI_PATH),
    ]
    assert captured["path"] == gate.HARNESS_PATH
    assert str(fake_bin) not in captured["path"]
    assert "UNREVIEWED_INTERCEPT" not in captured["environment"]
    assert set(captured["environment"]) <= {*gate.HARNESS_ENV_KEYS, "PATH"}


def test_node_options_preload_cannot_intercept_pi(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    marker = tmp_path / "node-options-intercepted"
    preload = tmp_path / "intercept.cjs"
    preload.write_text(
        "require('fs').writeFileSync(" + json.dumps(str(marker)) + ", 'intercepted');\n"
    )
    monkeypatch.setenv("NODE_OPTIONS", f"--require={preload}")
    monkeypatch.setenv("NODE_PATH", str(tmp_path / "fake-modules"))
    node = shutil.which("node")
    assert node is not None, "Node is required to exercise the controlled harness environment"
    pi_fixture = tmp_path / "pi.mjs"
    pi_fixture.write_text('console.log("0.82.1");\n')
    completed = gate.subprocess.run(
        [node, str(pi_fixture)],
        check=True,
        text=True,
        capture_output=True,
        env=gate.controlled_harness_environment(),
    )
    assert completed.stdout.strip() == "0.82.1"
    assert not marker.exists()
    assert "NODE_OPTIONS" not in gate.controlled_harness_environment()
    assert "NODE_PATH" not in gate.controlled_harness_environment()


def test_functional_gate_urls_match_the_pinned_production_topology() -> None:
    config = json.loads(
        (Path(__file__).resolve().parents[1] / "ops" / "render-production.json").read_text()
    )
    assert gate.REQUIRED_ORIGIN_URL == config["origin_url"]
    assert gate.REQUIRED_PUBLIC_URL == config["public_url"]


def test_origin_connect_tunnel_routes_only_the_canonical_authority() -> None:
    class EchoHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            data = self.request.recv(1024)
            self.request.sendall(data)

    upstream = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    try:
        with gate.OriginConnectTunnel(
            canonical_url="https://127.0.0.2",
            origin_url=f"https://127.0.0.1:{upstream.server_address[1]}",
        ) as tunnel:
            with socket.create_connection(tunnel.address, timeout=2) as client:
                client.sendall(
                    b"CONNECT 127.0.0.2:443 HTTP/1.1\r\n"
                    b"Host: 127.0.0.2:443\r\n\r\n"
                )
                response = client.recv(4096)
                assert response.startswith(b"HTTP/1.1 200 Connection Established\r\n")
                client.sendall(b"origin probe")
                assert client.recv(1024) == b"origin probe"
            assert tunnel.connection_attempts == 1
            assert tunnel.successful_connections == 1
            assert tunnel.peer_ip == "127.0.0.1"
            assert tunnel.peer_ip == tunnel.selected_origin_ip

            with socket.create_connection(tunnel.address, timeout=2) as client:
                client.sendall(
                    b"CONNECT attacker.example:443 HTTP/1.1\r\n"
                    b"Host: attacker.example:443\r\n\r\n"
                )
                assert client.recv(4096).startswith(b"HTTP/1.1 403 Forbidden\r\n")
            assert tunnel.connection_attempts == 2
            assert tunnel.successful_connections == 1
    finally:
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=2)


def test_origin_connect_tunnel_uses_only_startup_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EchoHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            data = self.request.recv(1024)
            self.request.sendall(data)

    upstream = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    original_getaddrinfo = socket.getaddrinfo
    resolutions = {"public.invalid": 0, "origin.invalid": 0}
    startup_complete = False

    def controlled_resolution(host, port, family=0, type=0, proto=0, flags=0):
        if host in resolutions:
            assert not startup_complete, f"post-start DNS lookup for {host}"
            resolutions[host] += 1
            target = "127.0.0.2" if host == "public.invalid" else "127.0.0.1"
            return original_getaddrinfo(target, port, family, type, proto, flags)
        return original_getaddrinfo(host, port, family, type, proto, flags)

    monkeypatch.setattr(gate.socket, "getaddrinfo", controlled_resolution)
    try:
        with gate.OriginConnectTunnel(
            canonical_url="https://public.invalid",
            origin_url=f"https://origin.invalid:{upstream.server_address[1]}",
        ) as tunnel:
            startup_complete = True
            with socket.create_connection(tunnel.address, timeout=2) as client:
                client.sendall(
                    b"CONNECT public.invalid:443 HTTP/1.1\r\n"
                    b"Host: public.invalid:443\r\n\r\n"
                )
                assert client.recv(4096).startswith(
                    b"HTTP/1.1 200 Connection Established\r\n"
                )
                client.sendall(b"pinned DNS")
                assert client.recv(1024) == b"pinned DNS"
            assert tunnel.peer_ip == "127.0.0.1"
            assert resolutions == {"public.invalid": 1, "origin.invalid": 1}
    finally:
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=2)


def test_origin_connect_tunnel_refuses_dns_overlap_and_resolution_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(gate.GateError, match="DNS addresses overlap"):
        gate.OriginConnectTunnel(
            canonical_url="https://127.0.0.1",
            origin_url="https://127.0.0.1",
        )

    original_getaddrinfo = socket.getaddrinfo

    def failed_origin_resolution(host, port, family=0, type=0, proto=0, flags=0):
        if host == "missing.invalid":
            raise socket.gaierror("not found")
        return original_getaddrinfo(host, port, family, type, proto, flags)

    monkeypatch.setattr(gate.socket, "getaddrinfo", failed_origin_resolution)
    with pytest.raises(gate.GateError, match="failed to resolve generated origin URL"):
        gate.OriginConnectTunnel(
            canonical_url="https://127.0.0.2",
            origin_url="https://missing.invalid",
        )


def test_origin_raw_materialize_keeps_canonical_url_and_requires_tunnel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class TraversedTunnel:
        proxy_url = "http://127.0.0.1:43210"
        selected_origin_ip = "192.0.2.10"

        def __init__(self) -> None:
            self.connection_attempts = 0
            self.successful_connections = 0
            self.peer_ip = ""

    seen: dict[str, object] = {}

    def successful_aw(command, *, cwd, stdout, stderr, label, env=None):
        seen["command"] = command
        seen["environment"] = env
        tunnel.connection_attempts = 1
        tunnel.successful_connections = 1
        tunnel.peer_ip = tunnel.selected_origin_ip
        stdout.write_text(json.dumps(payload("pi")))
        stderr.write_text("HTTP 200\n")

    monkeypatch.setattr(gate, "run_checked", successful_aw)
    monkeypatch.setenv("HTTP_PROXY", "http://untrusted.example")
    monkeypatch.setenv("https_proxy", "http://untrusted.example")
    monkeypatch.setenv("ALL_PROXY", "socks5://untrusted.example")
    monkeypatch.setenv("no_proxy", "library.example")
    tunnel = TraversedTunnel()
    result = gate.raw_materialize(
        Path("/released/aw"),
        tmp_path,
        "https://library.example",
        "pi",
        tmp_path,
        origin_tunnel=tunnel,
    )
    assert result == payload("pi")
    assert seen["command"][4] == "https://library.example/v1/materialize"
    environment = seen["environment"]
    assert environment["HTTPS_PROXY"] == tunnel.proxy_url
    assert environment["NO_PROXY"] == ""
    assert "HTTP_PROXY" not in environment
    assert "https_proxy" not in environment
    assert "ALL_PROXY" not in environment
    assert "no_proxy" not in environment

    class BypassedTunnel:
        proxy_url = tunnel.proxy_url
        selected_origin_ip = tunnel.selected_origin_ip
        connection_attempts = 0
        successful_connections = 0
        peer_ip = ""

    def bypassed_aw(command, *, cwd, stdout, stderr, label, env=None):
        stdout.write_text(json.dumps(payload("pi")))
        stderr.write_text("HTTP 200\n")

    monkeypatch.setattr(gate, "run_checked", bypassed_aw)
    with pytest.raises(gate.GateError, match="exactly one pinned origin socket"):
        gate.raw_materialize(
            Path("/released/aw"),
            tmp_path,
            "https://library.example",
            "pi",
            tmp_path,
            origin_tunnel=BypassedTunnel(),
        )


def test_raw_materialize_requires_exact_http_200(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def redirected_aw(command, *, cwd, stdout, stderr, label, env=None):
        stdout.write_text(json.dumps(payload("pi")))
        stderr.write_text("HTTP 302\n")

    monkeypatch.setattr(gate, "run_checked", redirected_aw)
    with pytest.raises(gate.GateError, match="did not return exact HTTP 200"):
        gate.raw_materialize(
            Path("/released/aw"), tmp_path, "https://library.example", "pi", tmp_path
        )


def test_candidate_runs_origin_functional_probes_before_public_edge(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[str, str, bool]] = []

    class FakeTunnel:
        peer_ip = "192.0.2.10"

        def __init__(self, *, canonical_url: str, origin_url: str) -> None:
            assert canonical_url == "https://library.example"
            assert origin_url == "https://library-origin.example"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_raw(aw_bin, source_home, public_url, runtime, root, *, origin_tunnel=None):
        calls.append((runtime, public_url, origin_tunnel is not None))
        return payload(runtime)

    monkeypatch.setattr(gate, "OriginConnectTunnel", FakeTunnel)
    monkeypatch.setattr(gate, "raw_materialize", fake_raw)
    monkeypatch.setattr(gate, "clone_auth_home", lambda source, destination: None)
    monkeypatch.setattr(
        gate,
        "strict_materialize",
        lambda *args, **kwargs: {"gate": "released-strict-client"},
    )
    monkeypatch.setattr(gate, "run_harness", lambda *args, **kwargs: {"gate": "real-harness"})
    args = Namespace(
        source_home=tmp_path,
        public_url="https://library.example",
        origin_url="https://library-origin.example",
        expected_profile_version=EXPECTED_VERSION,
        expected_profile_digest=EXPECTED_DIGEST,
    )
    summaries = gate.run_candidate(args, tmp_path)
    assert calls == [
        ("claude-code", "https://library.example", True),
        ("pi", "https://library.example", True),
        ("claude-code", "https://library.example", False),
        ("pi", "https://library.example", False),
    ]
    assert [item["gate"] for item in summaries[:4]] == [
        "raw-candidate-origin",
        "raw-candidate-origin",
        "raw-candidate-public",
        "raw-candidate-public",
    ]
    assert [item.get("transport_peer_ip") for item in summaries[:2]] == [
        "192.0.2.10",
        "192.0.2.10",
    ]


def test_candidate_cannot_pass_when_canonical_public_probe_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[str, bool]] = []

    class FakeTunnel:
        peer_ip = "192.0.2.10"

        def __init__(self, *, canonical_url: str, origin_url: str) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def public_failure(aw_bin, source_home, public_url, runtime, root, *, origin_tunnel=None):
        is_origin = origin_tunnel is not None
        calls.append((runtime, is_origin))
        if not is_origin:
            raise gate.GateError("canonical public edge failed")
        return payload(runtime)

    monkeypatch.setattr(gate, "OriginConnectTunnel", FakeTunnel)
    monkeypatch.setattr(gate, "raw_materialize", public_failure)
    monkeypatch.setattr(gate, "clone_auth_home", lambda source, destination: None)
    monkeypatch.setattr(
        gate,
        "strict_materialize",
        lambda *args, **kwargs: {"gate": "released-strict-client"},
    )
    monkeypatch.setattr(gate, "run_harness", lambda *args, **kwargs: {"gate": "real-harness"})
    args = Namespace(
        source_home=tmp_path,
        public_url="https://library.example",
        origin_url="https://library-origin.example",
        expected_profile_version=EXPECTED_VERSION,
        expected_profile_digest=EXPECTED_DIGEST,
    )
    with pytest.raises(gate.GateError, match="canonical public edge failed"):
        gate.run_candidate(args, tmp_path)
    assert calls == [
        ("claude-code", True),
        ("pi", True),
        ("claude-code", False),
    ]


def test_current_incumbent_source_inventory_and_paths_are_exact() -> None:
    expected = {
        "materialize.origin.claude-code.http-200",
        "materialize.origin.pi.http-200",
        "materialize.origin.response-contract.claude-code",
        "materialize.origin.response-contract.pi",
        "materialize.public-continuation.claude-code.fatal",
        "materialize.public-continuation.pi.fatal",
        "materialize.public.claude-code.http-200",
        "materialize.public.pi.http-200",
        "materialize.response-contract.claude-code",
        "materialize.response-contract.pi",
        "materialize.profile-pin.claude-code",
        "materialize.profile-pin.pi",
        "origin-route.claude-code.dns-public-disjoint",
        "origin-route.pi.dns-public-disjoint",
        "origin-route.claude-code.ambient-proxy-isolated",
        "origin-route.pi.ambient-proxy-isolated",
        "origin-route.claude-code.no-post-start-dns",
        "origin-route.pi.no-post-start-dns",
        "origin-route.claude-code.kernel-peer-selected",
        "origin-route.pi.kernel-peer-selected",
        "origin-route.claude-code.canonical-authority",
        "origin-route.pi.canonical-authority",
    }
    assert set(gate.current_incumbent_predicate_inventory()) == expected
    postdeploy = set(gate.postdeploy_predicate_inventory())
    assert not any(item.startswith("origin-route.") for item in postdeploy)
    assert not any(item.startswith("materialize.origin.") for item in postdeploy)
    assert {
        "materialize.public.claude-code.http-200",
        "materialize.public.pi.http-200",
    } <= postdeploy
    paths = gate.current_incumbent_predicate_paths()
    assert set(paths) == expected
    for predicate_id, path in paths.items():
        assert path[0] == "make.prod-gate-current-incumbent"
        assert path[1] == "library-prod-gate.current-incumbent"
        assert path[-1] == predicate_id
        assert len(path) == len(set(path))
        runtime = "claude-code" if "claude-code" in predicate_id else "pi"
        assert any(runtime in component for component in path[2:])


def test_current_incumbent_identity_has_no_drifting_parser_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in ("INCUMBENT_SERVICE_ID", "INCUMBENT_DEPLOY_ID", "INCUMBENT_COMMIT"):
        monkeypatch.delenv(key, raising=False)
    args = gate.parser().parse_args(["current-incumbent"])
    assert args.incumbent_service_id == ""
    assert args.incumbent_deploy_id == ""
    assert args.incumbent_commit == ""


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("incumbent_service_id", "srv-other"),
        ("incumbent_deploy_id", "dep-other"),
        ("incumbent_commit", "a" * 40),
        ("incumbent_service_id", ""),
        ("incumbent_deploy_id", ""),
        ("incumbent_commit", ""),
    ],
)
def test_current_incumbent_identity_mismatch_fails_before_functional_calls(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    calls: list[str] = []

    def must_not_materialize(*args, **kwargs):
        calls.append("materialize")
        raise AssertionError("functional call ran before identity validation")

    monkeypatch.setattr(gate, "raw_materialize", must_not_materialize)
    args = current_incumbent_args(tmp_path, **{field: value})
    with pytest.raises(gate.GateError, match=field.replace("_", "-")):
        gate.run_current_incumbent(args, tmp_path)
    assert calls == []


def _current_capability_transcript(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    mutation_predicate: str = "",
    process_failure_index: int = -1,
) -> tuple[dict, list[tuple[str, str]], int]:
    source = {
        "verifier_source_sha": "a" * 40,
        "verifier_script_sha256": "b" * 64,
        "verifier_script_path": "scripts/library_prod_gate.py",
    }
    monkeypatch.setattr(gate, "_current_capability_source_identity", lambda: source)

    class Upstream(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            self.request.recv(1024)

    class FixtureServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    upstream = FixtureServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    original_getaddrinfo = socket.getaddrinfo

    def fixture_dns(host, port, family=0, type=0, proto=0, flags=0):
        targets = {"public.invalid": "127.0.0.2", "origin.invalid": "127.0.0.1"}
        target = targets.get(host, host)
        return original_getaddrinfo(target, port, family, type, proto, flags)

    monkeypatch.setattr(gate.socket, "getaddrinfo", fixture_dns)
    calls: list[tuple[str, str]] = []
    traversals = 0
    capability_root = Path(
        tempfile.mkdtemp(prefix="library-current-capability-tests-")
    ).resolve(strict=True)
    capability_root.chmod(0o700)
    capability_path = capability_root / "current-capability"
    subject_root = capability_root / "subjects"
    subject_root.mkdir(mode=0o700)
    args = current_incumbent_args(
        tmp_path,
        public_url="https://public.invalid",
        origin_url=f"https://origin.invalid:{upstream.server_address[1]}",
        current_capability_dir=str(capability_path),
        current_capability_correlation_id="current.slice.fixture",
        current_capability_mutation_id=(
            f"{mutation_predicate}.dedicated-negative" if mutation_predicate else ""
        ),
    )

    def fixture_process(command, *, cwd, stdout, stderr, check, env=None, **kwargs):
        nonlocal traversals
        request_path = Path(command[command.index("--body-file") + 1])
        runtime = json.loads(request_path.read_text())["runtime_kind"]
        surface = "origin" if env is not None and "HTTPS_PROXY" in env else "public"
        call_index = len(calls)
        calls.append((surface, runtime))
        if call_index == process_failure_index:
            stderr.write(b"fixture process failed")
            return subprocess.CompletedProcess(command, 9)
        if surface == "origin":
            proxy = gate.urlsplit(env["HTTPS_PROXY"])
            with socket.create_connection((proxy.hostname, proxy.port), timeout=2) as client:
                client.sendall(
                    b"CONNECT public.invalid:443 HTTP/1.1\r\n"
                    b"Host: public.invalid:443\r\n\r\n"
                )
                response = b""
                while b"\r\n\r\n" not in response:
                    response += client.recv(4096)
                assert response.startswith(b"HTTP/1.1 200 Connection Established\r\n")
                client.sendall(b"fixture traversal")
            traversals += 1
        predicate = f"materialize.{surface}.{runtime}.http-200"
        stdout.write(json.dumps(legacy_payload(runtime)).encode())
        stderr.write(b"HTTP 403\n" if predicate == mutation_predicate else b"HTTP 200\n")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(gate.subprocess, "run", fixture_process)
    try:
        if mutation_predicate or process_failure_index >= 0:
            with pytest.raises(gate.GateError):
                gate.run_current_incumbent(args, subject_root)
        else:
            gate.run_current_incumbent(args, subject_root)
    finally:
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=2)
    artifact_paths = sorted(capability_path.glob("*.json"))
    assert stat.S_IMODE(capability_path.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(item.stat().st_mode) == 0o600 for item in artifact_paths)
    artifacts = [json.loads(item.read_text()) for item in artifact_paths]
    events = [
        item
        for item in artifacts
        if item.get("probe_kind") == "aatk-current-incumbent-capability-transcript"
    ]
    assert len(events) == 1
    transcript = events[0]["transcript"]
    assert aatk.validate_current_incumbent_capability_transcript(transcript) is transcript
    for child in transcript["children"]:
        captured = (subject_root / child["status_subject_name"]).read_bytes()
        assert len(captured) == child["status_subject_size"]
        assert hashlib.sha256(captured).hexdigest() == child["status_subject_sha256"]
    shutil.rmtree(capability_root)
    return transcript, calls, traversals


def test_current_capability_source_identity_rejects_dirty_script(tmp_path: Path) -> None:
    repo = tmp_path / "source-identity"
    script = repo / "scripts" / "library_prod_gate.py"
    script.parent.mkdir(parents=True)
    script.write_text("print('clean')\n")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
    identity = gate._current_capability_source_identity(repo_root=repo, script_path=script)
    assert identity["verifier_script_path"] == "scripts/library_prod_gate.py"
    assert identity["verifier_script_sha256"] == hashlib.sha256(script.read_bytes()).hexdigest()
    script.write_text("print('dirty')\n")
    with pytest.raises(gate.GateError, match="tracked changes"):
        gate._current_capability_source_identity(repo_root=repo, script_path=script)


def test_current_capability_invalid_metadata_emits_one_setup_terminal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        gate,
        "_current_capability_source_identity",
        lambda: {
            "verifier_source_sha": "a" * 40,
            "verifier_script_sha256": "b" * 64,
            "verifier_script_path": "scripts/library_prod_gate.py",
        },
    )
    root = Path(tempfile.mkdtemp(prefix="library-current-setup-tests-")).resolve(strict=True)
    root.chmod(0o700)
    output = root / "invalid"
    args = current_incumbent_args(
        tmp_path,
        current_capability_dir=str(output),
        current_capability_correlation_id="invalid correlation",
        current_capability_mutation_id="",
    )
    with pytest.raises(gate.GateError, match="correlation ID"):
        gate.run_current_incumbent(args, tmp_path)
    artifacts = [json.loads(item.read_text()) for item in sorted(output.glob("*.json"))]
    terminals = [
        item
        for item in artifacts
        if item.get("probe_kind") == "aatk-current-incumbent-capability-setup-outcome"
    ]
    assert len(terminals) == 1
    assert terminals[0] is artifacts[-1]
    assert terminals[0]["outcome"] == "failed"
    shutil.rmtree(root)


def test_current_capability_rejects_secret_bearing_url_without_recording_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        gate,
        "_current_capability_source_identity",
        lambda: {
            "verifier_source_sha": "a" * 40,
            "verifier_script_sha256": "b" * 64,
            "verifier_script_path": "scripts/library_prod_gate.py",
        },
    )
    root = Path(tempfile.mkdtemp(prefix="library-current-secret-tests-")).resolve(strict=True)
    root.chmod(0o700)
    output = root / "invalid"
    args = current_incumbent_args(
        tmp_path,
        public_url="https://operator:secret@public.invalid",
        current_capability_dir=str(output),
        current_capability_correlation_id="current.slice.fixture",
        current_capability_mutation_id="",
    )
    with pytest.raises(gate.GateError, match="without path, query, or credentials"):
        gate.run_current_incumbent(args, tmp_path)
    encoded = b"".join(item.read_bytes() for item in sorted(output.glob("*.json")))
    assert b"operator" not in encoded
    assert b"secret" not in encoded
    shutil.rmtree(root)


def test_current_capability_secondary_finish_failure_preserves_subject_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        gate,
        "_current_capability_source_identity",
        lambda: {
            "verifier_source_sha": "a" * 40,
            "verifier_script_sha256": "b" * 64,
            "verifier_script_path": "scripts/library_prod_gate.py",
        },
    )
    root = Path(tempfile.mkdtemp(prefix="library-current-finish-tests-")).resolve(strict=True)
    root.chmod(0o700)
    calls = 0

    def fail_finish(self, *, outcome: str, error_code: str = "") -> None:
        nonlocal calls
        calls += 1
        raise gate.GateError("forced secondary finish failure")

    monkeypatch.setattr(gate.CurrentIncumbentCapabilityRecorder, "finish", fail_finish)
    args = current_incumbent_args(
        tmp_path,
        incumbent_commit="0" * 40,
        current_capability_dir=str(root / "finish"),
        current_capability_correlation_id="current.slice.fixture",
        current_capability_mutation_id="",
    )
    with pytest.raises(gate.GateError, match="incumbent-commit must be exactly") as caught:
        gate.run_current_incumbent(args, tmp_path)
    assert calls == 1
    assert caught.value.__notes__ == [
        "current capability finalization failed: GateError"
    ]
    shutil.rmtree(root)


def test_current_capability_preexisting_output_is_not_replaced(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        gate,
        "_current_capability_source_identity",
        lambda: {
            "verifier_source_sha": "a" * 40,
            "verifier_script_sha256": "b" * 64,
            "verifier_script_path": "scripts/library_prod_gate.py",
        },
    )
    root = Path(tempfile.mkdtemp(prefix="library-current-noreplace-tests-")).resolve(strict=True)
    root.chmod(0o700)
    output = root / "existing"
    output.mkdir(mode=0o700)
    marker = output / "retained"
    marker.write_text("original")
    marker.chmod(0o600)
    args = current_incumbent_args(
        tmp_path,
        current_capability_dir=str(output),
        current_capability_correlation_id="current.slice.fixture",
        current_capability_mutation_id="",
    )
    with pytest.raises(RuntimeError, match="must not already exist"):
        gate.run_current_incumbent(args, tmp_path)
    assert marker.read_text() == "original"
    assert list(output.iterdir()) == [marker]
    shutil.rmtree(root)


def test_current_capability_passes_four_http_cells_through_real_tunnel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    transcript, calls, traversals = _current_capability_transcript(monkeypatch, tmp_path)
    assert calls == [
        ("origin", "claude-code"),
        ("origin", "pi"),
        ("public", "claude-code"),
        ("public", "pi"),
    ]
    assert traversals == 2
    assert [child["predicate_id"] for child in transcript["children"]] == list(
        gate.CURRENT_INCUMBENT_CAPABILITY_ORDER
    )
    assert {child["terminal"]["outcome"] for child in transcript["children"]} == {
        "passed"
    }
    assert transcript["terminal"] == {"outcome": "passed", "error_code": "", "count": 1}


@pytest.mark.parametrize(
    "predicate_id", gate.CURRENT_INCUMBENT_CAPABILITY_ORDER
)
def test_current_capability_http_negatives_have_exact_terminal_recipe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, predicate_id: str
) -> None:
    transcript, calls, traversals = _current_capability_transcript(
        monkeypatch, tmp_path, mutation_predicate=predicate_id
    )
    target_index = gate.CURRENT_INCUMBENT_CAPABILITY_ORDER.index(predicate_id)
    assert len(calls) == target_index + 1
    assert [child["terminal"]["outcome"] for child in transcript["children"]] == [
        *(["passed"] * target_index),
        "expected-failure",
    ]
    assert transcript["children"][-1]["status_subject_sha256"] == hashlib.sha256(
        b"HTTP 403\n"
    ).hexdigest()
    assert transcript["terminal"]["error_code"] == (
        f"{predicate_id}.dedicated-negative-observed"
    )
    assert traversals == min(target_index + 1, 2)


def test_current_capability_transcript_schema_is_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    transcript, _, _ = _current_capability_transcript(monkeypatch, tmp_path)
    incomplete = copy.deepcopy(transcript)
    incomplete["mutation_id"] = "materialize.public.pi.http-200.dedicated-negative"
    incomplete["terminal"] = {
        "outcome": "failed",
        "error_code": "current-capability-incomplete",
        "count": 1,
    }
    assert (
        aatk.validate_current_incumbent_capability_transcript(incomplete) is incomplete
    )

    mutations: list[tuple[dict, str]] = []

    changed = copy.deepcopy(transcript)
    changed["driver"] = "library_prod_gate.main"
    mutations.append((changed, "current-capability-transcript"))

    changed = copy.deepcopy(transcript)
    changed["domain"] = "candidate-postdeploy"
    mutations.append((changed, "current-capability-transcript"))

    changed = copy.deepcopy(transcript)
    changed["substitutions"][0]["boundary_id"] = "raw-materialize.mock"
    mutations.append((changed, "current-capability-substitutions"))

    changed = copy.deepcopy(transcript)
    changed["children"].pop()
    mutations.append((changed, "current-capability-positive-recipe"))

    changed = copy.deepcopy(transcript)
    changed["children"][0], changed["children"][1] = (
        changed["children"][1],
        changed["children"][0],
    )
    mutations.append((changed, "current-capability-child-order"))

    changed = copy.deepcopy(transcript)
    changed["children"][0]["status_subject_sha256"] = "not-a-digest"
    mutations.append((changed, "current-capability-child"))

    changed = copy.deepcopy(transcript)
    changed["candidate_mapping"] = "identical"
    mutations.append((changed, "current-capability-transcript"))

    for changed, expected_code in mutations:
        with pytest.raises(aatk.AATKError) as caught:
            aatk.validate_current_incumbent_capability_transcript(changed)
        assert caught.value.code == expected_code


def test_current_capability_negative_rejects_later_child_and_unstable_top_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    passing, _, _ = _current_capability_transcript(monkeypatch, tmp_path)
    negative, _, _ = _current_capability_transcript(
        monkeypatch,
        tmp_path,
        mutation_predicate="materialize.origin.pi.http-200",
    )
    changed = copy.deepcopy(negative)
    changed["children"].append(copy.deepcopy(passing["children"][2]))
    with pytest.raises(aatk.AATKError) as caught:
        aatk.validate_current_incumbent_capability_transcript(changed)
    assert caught.value.code in {
        "current-capability-path",
        "current-capability-negative-recipe",
    }

    changed = copy.deepcopy(negative)
    changed["children"][-1]["status_subject_sha256"] = hashlib.sha256(
        b"HTTP 404\n"
    ).hexdigest()
    with pytest.raises(aatk.AATKError) as caught:
        aatk.validate_current_incumbent_capability_transcript(changed)
    assert caught.value.code == "current-capability-status-subject"

    changed = copy.deepcopy(negative)
    changed["terminal"]["error_code"] = "GateError"
    with pytest.raises(aatk.AATKError) as caught:
        aatk.validate_current_incumbent_capability_transcript(changed)
    assert caught.value.code == "current-capability-negative-recipe"


def test_current_capability_process_failure_is_not_an_http_negative(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    transcript, calls, traversals = _current_capability_transcript(
        monkeypatch,
        tmp_path,
        mutation_predicate="materialize.public.pi.http-200",
        process_failure_index=3,
    )
    assert len(calls) == 4
    assert [child["terminal"]["outcome"] for child in transcript["children"]] == [
        "passed",
        "passed",
        "passed",
    ]
    assert transcript["terminal"]["error_code"] == "current-capability-subject-failure"
    assert traversals == 2


def test_current_incumbent_runs_pinned_origin_then_mandatory_public_for_both_runtimes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[str, bool]] = []

    class FakeTunnel:
        peer_ip = "192.0.2.10"

        def __init__(self, *, canonical_url: str, origin_url: str) -> None:
            assert canonical_url == "https://library.example"
            assert origin_url == "https://library-origin.example"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_raw(aw_bin, source_home, public_url, runtime, root, *, origin_tunnel=None):
        calls.append((runtime, origin_tunnel is not None))
        return legacy_payload(runtime)

    monkeypatch.setattr(gate, "OriginConnectTunnel", FakeTunnel)
    monkeypatch.setattr(gate, "raw_materialize", fake_raw)
    summaries = gate.run_current_incumbent(current_incumbent_args(tmp_path), tmp_path)
    assert calls == [
        ("claude-code", True),
        ("pi", True),
        ("claude-code", False),
        ("pi", False),
    ]
    assert [summary["gate"] for summary in summaries] == [
        "current-incumbent-identity",
        "raw-current-incumbent-origin",
        "raw-current-incumbent-origin",
        "raw-current-incumbent-public",
        "raw-current-incumbent-public",
        "current-incumbent-predicate-inventory",
    ]
    assert {summary["output_class"] for summary in summaries} == {
        "current-incumbent-debug"
    }
    assert summaries[0] == {
        "gate": "current-incumbent-identity",
        "output_class": "current-incumbent-debug",
        "service_id": "srv-d8qm4jvavr4c73dhrmgg",
        "deploy_id": "dep-d9koecdbedkc73b582vg",
        "commit": "3376af7ee4a571488441794047018af94b06057f",
        "shape": "library-materialize.pre-aasb.no-runtime-managed",
    }
    assert summaries[1]["predicate_ids"] == [
        "materialize.origin.claude-code.http-200",
        "materialize.origin.response-contract.claude-code",
        "origin-route.claude-code.ambient-proxy-isolated",
        "origin-route.claude-code.canonical-authority",
        "origin-route.claude-code.dns-public-disjoint",
        "origin-route.claude-code.kernel-peer-selected",
        "origin-route.claude-code.no-post-start-dns",
    ]
    assert summaries[3]["predicate_ids"] == [
        "materialize.profile-pin.claude-code",
        "materialize.public-continuation.claude-code.fatal",
        "materialize.public.claude-code.http-200",
        "materialize.response-contract.claude-code",
    ]
    assert summaries[-1]["predicate_paths"] == gate.current_incumbent_predicate_paths()
    emitted = {
        predicate_id
        for summary in summaries[1:-1]
        for predicate_id in summary["predicate_ids"]
    }
    assert emitted == set(gate.current_incumbent_predicate_inventory())


@pytest.mark.parametrize(
    ("failing_runtime", "expected_calls"),
    [
        (
            "claude-code",
            [
                ("claude-code", True),
                ("pi", True),
                ("claude-code", False),
            ],
        ),
        (
            "pi",
            [
                ("claude-code", True),
                ("pi", True),
                ("claude-code", False),
                ("pi", False),
            ],
        ),
    ],
)
def test_current_incumbent_public_failure_is_fatal_per_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failing_runtime: str,
    expected_calls: list[tuple[str, bool]],
) -> None:
    calls: list[tuple[str, bool]] = []

    class FakeTunnel:
        peer_ip = "192.0.2.10"

        def __init__(self, *, canonical_url: str, origin_url: str) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def injected_public_failure(
        aw_bin, source_home, public_url, runtime, root, *, origin_tunnel=None
    ):
        is_origin = origin_tunnel is not None
        calls.append((runtime, is_origin))
        if not is_origin and runtime == failing_runtime:
            raise gate.GateError(f"canonical public {runtime} failed")
        return legacy_payload(runtime)

    monkeypatch.setattr(gate, "OriginConnectTunnel", FakeTunnel)
    monkeypatch.setattr(gate, "raw_materialize", injected_public_failure)
    with pytest.raises(gate.GateError, match=f"canonical public {failing_runtime} failed"):
        gate.run_current_incumbent(current_incumbent_args(tmp_path), tmp_path)
    assert calls == expected_calls


def test_current_incumbent_rejects_candidate_semantics_on_origin_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class FakeTunnel:
        peer_ip = "192.0.2.10"

        def __init__(self, *, canonical_url: str, origin_url: str) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(gate, "OriginConnectTunnel", FakeTunnel)
    monkeypatch.setattr(gate, "raw_materialize", lambda *args, **kwargs: payload("claude-code"))
    with pytest.raises(gate.GateError, match="not the known pre-fix behavior"):
        gate.run_current_incumbent(current_incumbent_args(tmp_path), tmp_path)


def test_current_incumbent_make_target_does_not_shell_interpolate_identity() -> None:
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [
            "make",
            "-n",
            "prod-gate-current-incumbent",
            "INCUMBENT_SERVICE_ID='; echo INJECTED; #'",
            "INCUMBENT_DEPLOY_ID=dep-x",
            f"INCUMBENT_COMMIT={'a' * 40}",
        ],
        cwd=root,
        check=True,
        text=True,
        capture_output=True,
    )
    assert "INJECTED" not in completed.stdout
    recipe_lines = [
        line for line in completed.stdout.splitlines() if not line.startswith("make[")
    ]
    assert recipe_lines == ["uv run python scripts/library_prod_gate.py current-incumbent"]


def test_clone_auth_home_removes_profile_and_delivery_state(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    (source / ".aw" / "profile").mkdir(parents=True)
    (source / ".aw" / "profile" / "ref.json").write_text("{}")
    (source / ".aw" / "signing.key").write_text("secret")
    (source / ".aw" / "interaction-log.jsonl").write_text("private")
    destination.mkdir()
    gate.clone_auth_home(source, destination)
    assert (destination / ".aw" / "signing.key").read_text() == "secret"
    assert not (destination / ".aw" / "profile").exists()
    assert not (destination / ".aw" / "interaction-log.jsonl").exists()
