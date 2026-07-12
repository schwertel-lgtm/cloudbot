"""Only process with Docker socket access; exposes a narrow Unix-socket API."""

from __future__ import annotations

import base64
import io
import json
import os
from pathlib import Path
import socketserver
import tarfile
from typing import Any

try:
    import docker
    from docker.errors import APIError, NotFound
except ModuleNotFoundError:  # Controller/test environments intentionally lack Docker SDK.
    docker = None
    class APIError(Exception):
        pass
    class NotFound(APIError):
        pass

from docker_broker_client import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, DockerBrokerError
from exec_security import ALLOWED_CONTAINERS, validate_exec_command


SOCKET_PATH = Path(os.environ.get("DOCKER_BROKER_SOCKET", "/run/docker-broker/broker.sock"))
ALLOWED_TARGETS = ALLOWED_CONTAINERS
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TEXT_BYTES = 256 * 1024
OPERATIONS = {
    "list_containers": frozenset(), "start": frozenset({"name"}),
    "stop": frozenset({"name"}), "restart": frozenset({"name"}),
    "logs": frozenset({"name"}), "exec_kali": frozenset({"command", "timeout"}),
    "vpn_status": frozenset(),
    "download_file": frozenset({"name", "path"}), "list_files": frozenset({"path"}),
}


def _target(value: Any) -> str:
    if not isinstance(value, str) or value == "cloudbot-claude" or value not in ALLOWED_TARGETS:
        raise DockerBrokerError("CONTAINER_NOT_ALLOWED")
    return value


def _path(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value or len(value) > 4096:
        raise DockerBrokerError("INVALID_REQUEST")
    return value


def _validate_request(value: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != {"operation", "params"}:
        raise DockerBrokerError("INVALID_REQUEST")
    operation, params = value["operation"], value["params"]
    if operation not in OPERATIONS or not isinstance(params, dict) or set(params) != OPERATIONS[operation]:
        raise DockerBrokerError("INVALID_REQUEST")
    if "name" in params:
        _target(params["name"])
    if "path" in params:
        _path(params["path"])
    if operation == "exec_kali":
        command, timeout = params["command"], params["timeout"]
        valid, _ = validate_exec_command(command) if isinstance(command, str) else (False, "")
        if not valid:
            raise DockerBrokerError("COMMAND_BLOCKED")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 1800:
            raise DockerBrokerError("INVALID_REQUEST")
    return operation, params


def _exec(container: Any, argv: list[str]) -> dict[str, Any]:
    result = container.exec_run(argv, demux=True)
    if isinstance(result.exit_code, bool) or not isinstance(result.exit_code, int):
        raise DockerBrokerError("DOCKER_ERROR")
    output = result.output if isinstance(result.output, tuple) else (result.output, b"")
    stdout_raw, stderr_raw = output
    stdout_raw = stdout_raw or b""
    stderr_raw = stderr_raw or b""
    if not isinstance(stdout_raw, bytes) or not isinstance(stderr_raw, bytes):
        raise DockerBrokerError("DOCKER_ERROR")
    if len(stdout_raw) + len(stderr_raw) > MAX_TEXT_BYTES:
        stdout_raw, stderr_raw = stdout_raw[:MAX_TEXT_BYTES], b"\n[Ausgabe gekuerzt]"
    return {"exit_code": result.exit_code,
            "stdout": stdout_raw.decode("utf-8", errors="replace"),
            "stderr": stderr_raw.decode("utf-8", errors="replace")}


def _dispatch(client: Any, operation: str, params: dict[str, Any]) -> Any:
    if operation == "list_containers":
        statuses = []
        for name in sorted(ALLOWED_TARGETS):
            try:
                item = client.containers.get(name)
                statuses.append({"name": name, "status": str(item.status)})
            except NotFound:
                continue
        return statuses
    if operation in {"start", "stop", "restart", "logs", "download_file"}:
        container = client.containers.get(_target(params["name"]))
        if operation in {"start", "stop", "restart"}:
            getattr(container, operation)()
            return None
        if operation == "logs":
            return (container.logs(tail=30) or b"").decode("utf-8", errors="replace")[:MAX_TEXT_BYTES]
        path = _path(params["path"])
        try:
            archive, _ = container.get_archive(path)
        except NotFound:
            # Docker get_archive kann tmpfs-Dateien nicht auf jeder Engine
            # liefern. Fester argv-Aufruf ohne Shell/Interpolation, mit hart
            # begrenzter Ausgabe; ausschließlich auf bereits geprüftem Ziel.
            result = container.exec_run(
                ["timeout", "--signal=KILL", "5s", "head", "-c",
                 str(MAX_FILE_BYTES + 1), "--", path], demux=True
            )
            output = result.output if isinstance(result.output, tuple) else (result.output, b"")
            data = output[0] or b""
            if result.exit_code in {124, 137}:
                raise DockerBrokerError("FILE_READ_TIMEOUT")
            if result.exit_code != 0:
                raise DockerBrokerError("FILE_NOT_FOUND")
            if len(data) > MAX_FILE_BYTES:
                raise DockerBrokerError("FILE_TOO_LARGE")
            return {"data": base64.b64encode(data).decode("ascii")}
        chunks, archive_size = [], 0
        for chunk in archive:
            archive_size += len(chunk)
            if archive_size > MAX_FILE_BYTES * 2:
                raise DockerBrokerError("FILE_TOO_LARGE")
            chunks.append(chunk)
        archive_data = b"".join(chunks)
        with tarfile.open(fileobj=io.BytesIO(archive_data)) as tar:
            members = tar.getmembers()
            if len(members) != 1 or not members[0].isfile() or members[0].size > MAX_FILE_BYTES:
                raise DockerBrokerError("FILE_TOO_LARGE")
            extracted = tar.extractfile(members[0])
            if extracted is None:
                raise DockerBrokerError("FILE_NOT_FOUND")
            with extracted:
                data = extracted.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            raise DockerBrokerError("FILE_TOO_LARGE")
        return {"data": base64.b64encode(data).decode("ascii")}
    if operation == "exec_kali":
        container = client.containers.get("kali")
        timeout = params["timeout"]
        result = _exec(container, ["timeout", "--signal=KILL", f"{timeout}s", "bash", "-c", params["command"]])
        if result["exit_code"] in {124, 137}:
            raise DockerBrokerError("EXEC_TIMEOUT")
        return result
    if operation == "vpn_status":
        return _exec(client.containers.get("nordvpn"), ["nordvpn", "status"])
    if operation == "list_files":
        result = _exec(client.containers.get("kali"), ["find", _path(params["path"]), "-maxdepth", "2", "-type", "f", "-printf", "%s %p\n"])
        return result["stdout"]
    raise DockerBrokerError("INVALID_REQUEST")


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        try:
            raw = self.rfile.readline(MAX_REQUEST_BYTES + 1)
            if len(raw) > MAX_REQUEST_BYTES or not raw.endswith(b"\n"):
                raise DockerBrokerError("INVALID_REQUEST")
            operation, params = _validate_request(json.loads(raw))
            result = _dispatch(self.server.docker_client, operation, params)
            response = {"ok": True, "result": result, "error": None}
        except DockerBrokerError as exc:
            response = {"ok": False, "result": None, "error": exc.code}
        except NotFound:
            response = {"ok": False, "result": None, "error": "CONTAINER_NOT_FOUND"}
        except (APIError, OSError):
            response = {"ok": False, "result": None, "error": "DOCKER_ERROR"}
        except (UnicodeDecodeError, ValueError, TypeError, KeyError, json.JSONDecodeError, tarfile.TarError):
            response = {"ok": False, "result": None, "error": "INVALID_REQUEST"}
        encoded = json.dumps(response, separators=(",", ":")).encode() + b"\n"
        if len(encoded) > MAX_RESPONSE_BYTES:
            encoded = b'{"ok":false,"result":null,"error":"RESPONSE_TOO_LARGE"}\n'
        self.wfile.write(encoded)


if hasattr(socketserver, "ThreadingUnixStreamServer"):
    class _Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True
        allow_reuse_address = True
        def __init__(self, path: str, handler: Any, docker_client: Any):
            self.docker_client = docker_client
            super().__init__(path, handler)
else:  # pragma: no cover - Unix sockets run only in the Linux broker image.
    _Server = None


def _prepare_socket_path(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise RuntimeError("Broker-Socketpfad darf kein Symlink sein")
    path.unlink(missing_ok=True)


def main() -> None:
    if docker is None or _Server is None:
        raise RuntimeError("Docker SDK fehlt im Broker-Image")
    _prepare_socket_path(SOCKET_PATH)
    client = docker.from_env(timeout=1900)
    client.ping()
    with _Server(str(SOCKET_PATH), _Handler, client) as server:
        os.chmod(SOCKET_PATH, 0o600)
        server.serve_forever()


if __name__ == "__main__":
    main()
