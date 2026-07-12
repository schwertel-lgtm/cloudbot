"""Minimaler IPC-Client zum isolierten Claude-Max-Sidecar."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import socket
from typing import Any


DEFAULT_SOCKET_PATH = "/run/claude-ipc/claude.sock"
MAX_IPC_BYTES = 1_000_000
SIDECAR_ERROR_CODES = {
    "CLAUDE_MALFORMED_OUTPUT",
    "CLAUDE_NONZERO_EXIT",
    "CLAUDE_RESPONSE_ERROR",
    "CLAUDE_TIMEOUT",
    "CLAUDE_UNAVAILABLE",
    "INVALID_MODEL_PAYLOAD",
    "INVALID_REQUEST",
    "MAX_AUTH_REQUIRED",
    "SIDECAR_BUSY",
}


class ClaudeCodeError(RuntimeError):
    """Stabil klassifizierter, fuer Logs und UI geeigneter Sidecar-Fehler."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ToolCall:
    name: str
    command: str


@dataclass(frozen=True)
class ClaudeCodeResult:
    text: str
    done: bool
    tool_calls: tuple[ToolCall, ...]


class ClaudeCodeClient:
    def __init__(self, model: str = "sonnet", socket_path: str = DEFAULT_SOCKET_PATH) -> None:
        self.model = model
        self.socket_path = socket_path

    def _request(self, payload: dict[str, Any], timeout: int) -> dict[str, Any]:
        wire = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(wire) > MAX_IPC_BYTES:
            raise ClaudeCodeError("REQUEST_TOO_LARGE")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(max(1, timeout))
                connection.connect(self.socket_path)
                connection.sendall(wire)
                chunks: list[bytes] = []
                size = 0
                while True:
                    chunk = connection.recv(min(65536, MAX_IPC_BYTES + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > MAX_IPC_BYTES:
                        raise ClaudeCodeError("RESPONSE_TOO_LARGE")
                    if b"\n" in chunk:
                        break
        except socket.timeout as exc:
            raise ClaudeCodeError("SIDECAR_TIMEOUT") from exc
        except OSError as exc:
            raise ClaudeCodeError("SIDECAR_UNAVAILABLE") from exc

        raw = b"".join(chunks)
        if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
            raise ClaudeCodeError("INVALID_SIDECAR_RESPONSE")
        try:
            response = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ClaudeCodeError("INVALID_SIDECAR_RESPONSE") from exc
        if not isinstance(response, dict) or set(response) != {"ok", "result", "error"}:
            raise ClaudeCodeError("INVALID_SIDECAR_RESPONSE")
        if response["ok"] is False:
            code = response["error"]
            if code not in SIDECAR_ERROR_CODES:
                code = "SIDECAR_ERROR"
            raise ClaudeCodeError(code)
        if response["ok"] is not True or response["error"] is not None:
            raise ClaudeCodeError("INVALID_SIDECAR_RESPONSE")
        if not isinstance(response["result"], dict):
            raise ClaudeCodeError("INVALID_SIDECAR_RESPONSE")
        return response["result"]

    def authentication_status(self) -> bool:
        result = self._request({"action": "auth_status"}, 35)
        if set(result) != {"authenticated"} or not isinstance(result["authenticated"], bool):
            raise ClaudeCodeError("INVALID_SIDECAR_RESPONSE")
        return result["authenticated"]

    def is_authenticated(self) -> bool:
        try:
            return self.authentication_status()
        except ClaudeCodeError:
            return False

    def query(self, system_prompt: str, prompt: str, timeout: int) -> ClaudeCodeResult:
        result = self._request(
            {
                "action": "query",
                "system_prompt": system_prompt,
                "prompt": prompt,
                "timeout": timeout,
                "model": self.model,
            },
            timeout + 5,
        )
        return self._parse_payload(result)

    @staticmethod
    def _parse_payload(payload: Any) -> ClaudeCodeResult:
        if not isinstance(payload, dict) or set(payload) != {"text", "done", "tool_calls"}:
            raise ClaudeCodeError("INVALID_MODEL_PAYLOAD")
        text = payload["text"]
        done = payload["done"]
        raw_calls = payload["tool_calls"]
        if not isinstance(text, str) or not isinstance(done, bool) or not isinstance(raw_calls, list):
            raise ClaudeCodeError("INVALID_MODEL_PAYLOAD")
        if len(raw_calls) > 4 or (done and raw_calls):
            raise ClaudeCodeError("INVALID_MODEL_PAYLOAD")

        calls: list[ToolCall] = []
        for raw_call in raw_calls:
            if not isinstance(raw_call, dict) or set(raw_call) != {"name", "command"}:
                raise ClaudeCodeError("INVALID_MODEL_PAYLOAD")
            name = raw_call["name"]
            command = raw_call["command"]
            if name not in {"exec_kali", "container_status"} or not isinstance(command, str):
                raise ClaudeCodeError("INVALID_MODEL_PAYLOAD")
            if (name == "exec_kali" and not command.strip()) or (name == "container_status" and command != ""):
                raise ClaudeCodeError("INVALID_MODEL_PAYLOAD")
            calls.append(ToolCall(name=name, command=command))
        return ClaudeCodeResult(text=text, done=done, tool_calls=tuple(calls))
