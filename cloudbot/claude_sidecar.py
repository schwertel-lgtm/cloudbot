"""Unix-Socket-Sidecar, der als einziger Prozess Claude Code ausfuehrt."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socketserver
import subprocess
import threading
from typing import Any

from claude_code_client import ClaudeCodeClient, ClaudeCodeError, MAX_IPC_BYTES


SOCKET_PATH = Path(os.environ.get("CLAUDE_IPC_SOCKET", "/run/claude-ipc/claude.sock"))
ALLOWED_MODELS = frozenset({
    "claude-haiku-4-5",
    "claude-sonnet-5",
    "claude-sonnet-4-6",
    "claude-sonnet-4-5",
    "claude-opus-4-8",
    "claude-opus-4-7",
    "claude-opus-4-6",
    "claude-opus-4-5",
})
MAX_CLI_OUTPUT_BYTES = 1024 * 1024
CLAUDE_CLI = "/usr/local/bin/claude"
_QUERY_SLOTS = threading.BoundedSemaphore(2)
TOOL_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "text": {"type": "string"},
        "done": {"type": "boolean"},
        "tool_calls": {
            "type": "array",
            "maxItems": 4,
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "enum": ["exec_kali", "container_status"]},
                    "command": {"type": "string"},
                },
                "required": ["name", "command"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["text", "done", "tool_calls"],
    "additionalProperties": False,
}


def _child_environment() -> dict[str, str]:
    """Konstruiert eine kleine Allowlist statt die Sidecar-Umgebung zu erben."""
    defaults = {
        "HOME": "/root",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "DISABLE_AUTOUPDATER": "1",
    }
    return {key: os.environ.get(key, value) for key, value in defaults.items()}


def _run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_child_environment(),
            cwd="/app",
        )
    except OSError as exc:
        raise ClaudeCodeError("CLAUDE_UNAVAILABLE") from exc

    captured: list[bytes] = [b"", b""]

    def drain(index: int, stream: Any) -> None:
        chunks, kept = [], 0
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            if kept < MAX_CLI_OUTPUT_BYTES:
                part = chunk[:MAX_CLI_OUTPUT_BYTES - kept]
                chunks.append(part)
                kept += len(part)
        captured[index] = b"".join(chunks)

    readers = [
        threading.Thread(target=drain, args=(0, process.stdout), daemon=True),
        threading.Thread(target=drain, args=(1, process.stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise ClaudeCodeError("CLAUDE_TIMEOUT") from exc
    finally:
        for reader in readers:
            reader.join(timeout=5)
    return subprocess.CompletedProcess(
        command, returncode,
        captured[0].decode("utf-8", errors="replace"),
        captured[1].decode("utf-8", errors="replace"),
    )


def _max_authenticated() -> bool:
    completed = _run([CLAUDE_CLI, "auth", "status", "--json"], 30)
    if completed.returncode != 0:
        return False
    try:
        status = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return False
    if not isinstance(status, dict):
        return False
    account_type = status.get("subscriptionType", status.get("accountType"))
    return (
        status.get("loggedIn") is True
        and status.get("authMethod") == "claude.ai"
        and account_type == "max"
    )


def _validate_request(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict) or "action" not in request:
        raise ClaudeCodeError("INVALID_REQUEST")
    if request["action"] == "auth_status":
        if set(request) != {"action"}:
            raise ClaudeCodeError("INVALID_REQUEST")
        return request
    if request["action"] != "query" or set(request) != {
        "action", "system_prompt", "prompt", "timeout", "model"
    }:
        raise ClaudeCodeError("INVALID_REQUEST")
    if not isinstance(request["system_prompt"], str) or not isinstance(request["prompt"], str):
        raise ClaudeCodeError("INVALID_REQUEST")
    if not request["system_prompt"] or not request["prompt"]:
        raise ClaudeCodeError("INVALID_REQUEST")
    timeout = request["timeout"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 30 <= timeout <= 600:
        raise ClaudeCodeError("INVALID_REQUEST")
    if not isinstance(request["model"], str) or request["model"] not in ALLOWED_MODELS:
        raise ClaudeCodeError("INVALID_REQUEST")
    return request


def _query_unlimited(request: dict[str, Any]) -> dict[str, Any]:
    if not _max_authenticated():
        raise ClaudeCodeError("MAX_AUTH_REQUIRED")
    command = [
        CLAUDE_CLI, "-p", "--output-format", "json",
        "--json-schema", json.dumps(TOOL_RESPONSE_SCHEMA, separators=(",", ":")),
        "--tools", "", "--model", request["model"], "--no-session-persistence",
        "--system-prompt", request["system_prompt"], request["prompt"],
    ]
    completed = _run(command, request["timeout"])
    if completed.returncode != 0:
        raise ClaudeCodeError("CLAUDE_NONZERO_EXIT")
    try:
        envelope = json.loads(completed.stdout)
        if not isinstance(envelope, dict) or envelope.get("is_error") is True:
            raise ClaudeCodeError("CLAUDE_RESPONSE_ERROR")
        payload = envelope.get("structured_output")
        if payload is None:
            payload = json.loads(envelope["result"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ClaudeCodeError("CLAUDE_MALFORMED_OUTPUT") from exc
    parsed = ClaudeCodeClient._parse_payload(payload)
    return {
        "text": parsed.text,
        "done": parsed.done,
        "tool_calls": [call.__dict__ for call in parsed.tool_calls],
    }


def _query(request: dict[str, Any]) -> dict[str, Any]:
    if not _QUERY_SLOTS.acquire(blocking=False):
        raise ClaudeCodeError("SIDECAR_BUSY")
    try:
        return _query_unlimited(request)
    finally:
        _QUERY_SLOTS.release()


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        try:
            raw = self.rfile.readline(MAX_IPC_BYTES + 1)
            if not raw.endswith(b"\n") or len(raw) > MAX_IPC_BYTES:
                raise ClaudeCodeError("INVALID_REQUEST")
            request = _validate_request(json.loads(raw))
            if request["action"] == "auth_status":
                result = {"authenticated": _max_authenticated()}
            else:
                result = _query(request)
            response = {"ok": True, "result": result, "error": None}
        except ClaudeCodeError as exc:
            response = {"ok": False, "result": None, "error": exc.code}
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
            response = {"ok": False, "result": None, "error": "INVALID_REQUEST"}
        try:
            self.wfile.write(json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n")
        except (BrokenPipeError, ConnectionResetError):
            # Lokale Healthchecks duerfen nach dem Request schliessen, ohne die
            # spaetere Antwort noch zu lesen. Das ist kein Sidecar-Fehler.
            return


if hasattr(socketserver, "ThreadingUnixStreamServer"):
    class _Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True
        allow_reuse_address = True
else:  # pragma: no cover - Unix-Sockets werden nur im Linux-Container betrieben.
    _Server = None


def _prepare_socket_path(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise RuntimeError("Claude-Socketpfad darf kein Symlink sein")
    path.unlink(missing_ok=True)


def main() -> None:
    if _Server is None:
        raise RuntimeError("Unix Domain Sockets werden auf dieser Plattform nicht unterstützt")
    _prepare_socket_path(SOCKET_PATH)
    with _Server(str(SOCKET_PATH), _Handler) as server:
        os.chmod(SOCKET_PATH, 0o600)
        server.serve_forever()


if __name__ == "__main__":
    main()
