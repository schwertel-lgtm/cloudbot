"""Strict, size-bounded client for the isolated Docker broker."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import os
import socket
from typing import Any


MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 12 * 1024 * 1024
SOCKET_PATH = os.environ.get("DOCKER_BROKER_SOCKET", "/run/docker-broker/broker.sock")
KNOWN_ERRORS = {
    "BROKER_UNAVAILABLE", "BROKER_TIMEOUT", "INVALID_REQUEST", "INVALID_RESPONSE",
    "REQUEST_TOO_LARGE", "RESPONSE_TOO_LARGE", "CONTAINER_NOT_FOUND",
    "CONTAINER_NOT_ALLOWED", "EXEC_NOT_ALLOWED", "COMMAND_BLOCKED", "DOCKER_ERROR",
    "EXEC_TIMEOUT", "FILE_NOT_FOUND", "FILE_TOO_LARGE", "FILE_READ_TIMEOUT",
}


class DockerBrokerError(RuntimeError):
    def __init__(self, code: str):
        self.code = code if code in KNOWN_ERRORS else "DOCKER_ERROR"
        super().__init__(self.code)


@dataclass(frozen=True)
class ContainerStatus:
    name: str
    status: str


@dataclass(frozen=True)
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str


class DockerBrokerClient:
    def __init__(self, socket_path: str = SOCKET_PATH):
        self.socket_path = socket_path

    def _request(self, operation: str, **params: Any) -> Any:
        raw = json.dumps({"operation": operation, "params": params}, separators=(",", ":")).encode() + b"\n"
        if len(raw) > MAX_REQUEST_BYTES:
            raise DockerBrokerError("REQUEST_TOO_LARGE")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(1900)
                connection.connect(self.socket_path)
                connection.sendall(raw)
                chunks, size = [], 0
                while True:
                    chunk = connection.recv(min(65536, MAX_RESPONSE_BYTES + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise DockerBrokerError("RESPONSE_TOO_LARGE")
                    if chunk.endswith(b"\n"):
                        break
        except DockerBrokerError:
            raise
        except socket.timeout as exc:
            raise DockerBrokerError("BROKER_TIMEOUT") from exc
        except OSError as exc:
            raise DockerBrokerError("BROKER_UNAVAILABLE") from exc
        try:
            response = json.loads(b"".join(chunks))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DockerBrokerError("INVALID_RESPONSE") from exc
        if not isinstance(response, dict) or set(response) != {"ok", "result", "error"}:
            raise DockerBrokerError("INVALID_RESPONSE")
        if response["ok"] is not True:
            if response["result"] is not None or not isinstance(response["error"], str):
                raise DockerBrokerError("INVALID_RESPONSE")
            raise DockerBrokerError(response["error"])
        if response["error"] is not None:
            raise DockerBrokerError("INVALID_RESPONSE")
        return response["result"]

    def list_containers(self) -> tuple[ContainerStatus, ...]:
        result = self._request("list_containers")
        if not isinstance(result, list):
            raise DockerBrokerError("INVALID_RESPONSE")
        try:
            if any(not isinstance(item, dict) or set(item) != {"name", "status"}
                   or not isinstance(item["name"], str) or not isinstance(item["status"], str)
                   for item in result):
                raise DockerBrokerError("INVALID_RESPONSE")
            return tuple(ContainerStatus(item["name"], item["status"]) for item in result)
        except (KeyError, TypeError) as exc:
            raise DockerBrokerError("INVALID_RESPONSE") from exc

    def start(self, name: str) -> None: self._request("start", name=name)
    def stop(self, name: str) -> None: self._request("stop", name=name)
    def restart(self, name: str) -> None: self._request("restart", name=name)
    def logs(self, name: str) -> str: return self._string("logs", name=name)
    def vpn_status(self) -> ExecResult: return self._exec_result("vpn_status")
    def exec_kali(self, command: str, timeout: int) -> ExecResult:
        return self._exec_result("exec_kali", command=command, timeout=timeout)
    def list_files(self, path: str) -> str: return self._string("list_files", path=path)

    def download_file(self, name: str, path: str) -> bytes:
        result = self._request("download_file", name=name, path=path)
        if not isinstance(result, dict) or set(result) != {"data"} or not isinstance(result["data"], str):
            raise DockerBrokerError("INVALID_RESPONSE")
        try:
            return base64.b64decode(result["data"], validate=True)
        except ValueError as exc:
            raise DockerBrokerError("INVALID_RESPONSE") from exc

    def _string(self, operation: str, **params: Any) -> str:
        result = self._request(operation, **params)
        if not isinstance(result, str):
            raise DockerBrokerError("INVALID_RESPONSE")
        return result

    def _exec_result(self, operation: str, **params: Any) -> ExecResult:
        result = self._request(operation, **params)
        if (not isinstance(result, dict) or set(result) != {"exit_code", "stdout", "stderr"}
                or isinstance(result["exit_code"], bool) or not isinstance(result["exit_code"], int)
                or not isinstance(result["stdout"], str) or not isinstance(result["stderr"], str)):
            raise DockerBrokerError("INVALID_RESPONSE")
        return ExecResult(**result)
