import io
import os
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("TELEGRAM_CHAT_ID", "7459992119")

import docker_broker
from docker_broker_client import DockerBrokerClient, DockerBrokerError


class BrokerContractTest(unittest.TestCase):
    def test_accepts_exact_contract_for_every_operation(self):
        valid = {
            "list_containers": {}, "start": {"name": "kali"},
            "stop": {"name": "nordvpn"}, "restart": {"name": "cloudbot"},
            "logs": {"name": "kali"},
            "exec_kali": {"command": "id", "timeout": 10},
            "vpn_status": {}, "download_file": {"name": "kali", "path": "/root/data/a"},
            "list_files": {"path": "/root/data"},
        }
        for operation, params in valid.items():
            self.assertEqual(
                (operation, params),
                docker_broker._validate_request({"operation": operation, "params": params}),
            )

    def test_rejects_claude_and_unknown_targets(self):
        for name in ("cloudbot-claude", "unknown", "cloudbot-docker-broker"):
            with self.assertRaisesRegex(DockerBrokerError, "CONTAINER_NOT_ALLOWED"):
                docker_broker._validate_request({
                    "operation": "logs", "params": {"name": name},
                })

    def test_rejects_generic_or_non_kali_exec(self):
        for request in (
            {"operation": "exec", "params": {"name": "kali", "command": "id"}},
            {"operation": "exec_kali", "params": {"name": "nordvpn", "command": "id", "timeout": 1}},
        ):
            with self.assertRaisesRegex(DockerBrokerError, "INVALID_REQUEST"):
                docker_broker._validate_request(request)

    def test_broker_revalidates_kali_command(self):
        with self.assertRaisesRegex(DockerBrokerError, "COMMAND_BLOCKED"):
            docker_broker._validate_request({
                "operation": "exec_kali", "params": {"command": "docker ps", "timeout": 10},
            })

    def test_kali_exec_has_hard_process_timeout(self):
        client = MagicMock()
        result = MagicMock(exit_code=0, output=(b"ok", None))
        client.containers.get.return_value.exec_run.return_value = result
        response = docker_broker._dispatch(client, "exec_kali", {"command": "id", "timeout": 9})
        argv = client.containers.get.return_value.exec_run.call_args.args[0]
        self.assertEqual(["timeout", "--signal=KILL", "9s", "bash", "-c", "id"], argv)
        self.assertEqual("", response["stderr"])
        self.assertEqual(0, response["exit_code"])

    def test_specialized_operations_use_fixed_argv(self):
        client = MagicMock()
        container = client.containers.get.return_value
        container.exec_run.return_value = MagicMock(exit_code=0, output=(b"Status: Connected", b""))
        result = docker_broker._dispatch(client, "vpn_status", {})
        client.containers.get.assert_called_with("nordvpn")
        container.exec_run.assert_called_once_with(["nordvpn", "status"], demux=True)
        self.assertEqual("Status: Connected", result)

    def test_download_tmpfs_fallback_uses_fixed_bounded_argv(self):
        client = MagicMock()
        container = client.containers.get.return_value
        container.get_archive.side_effect = docker_broker.NotFound("missing")
        container.exec_run.return_value = MagicMock(exit_code=0, output=(b"content", None))
        result = docker_broker._dispatch(
            client, "download_file", {"name": "kali", "path": "/tmp/report.txt"}
        )
        container.exec_run.assert_called_once_with(
            ["timeout", "--signal=KILL", "5s", "head", "-c",
             str(docker_broker.MAX_FILE_BYTES + 1), "--", "/tmp/report.txt"],
            demux=True,
        )
        self.assertEqual("Y29udGVudA==", result["data"])

    def test_download_tmpfs_timeout_has_stable_code(self):
        client = MagicMock()
        container = client.containers.get.return_value
        container.get_archive.side_effect = docker_broker.NotFound("missing")
        container.exec_run.return_value = MagicMock(exit_code=124, output=(b"", b""))
        with self.assertRaisesRegex(DockerBrokerError, "FILE_READ_TIMEOUT"):
            docker_broker._dispatch(
                client, "download_file", {"name": "kali", "path": "/tmp/fifo"}
            )

    def test_socket_symlink_is_rejected_before_unlink(self):
        path = MagicMock()
        path.is_symlink.return_value = True
        with self.assertRaisesRegex(RuntimeError, "Symlink"):
            docker_broker._prepare_socket_path(path)
        path.unlink.assert_not_called()

    def test_all_contract_operations_are_known(self):
        self.assertEqual({
            "list_containers", "start", "stop", "restart", "logs", "exec_kali",
            "vpn_status", "download_file", "list_files",
        }, set(docker_broker.OPERATIONS))


class BrokerClientFailureTest(unittest.TestCase):
    def test_oversized_request_is_rejected_before_connect(self):
        with self.assertRaisesRegex(DockerBrokerError, "REQUEST_TOO_LARGE"):
            DockerBrokerClient().exec_kali("x" * 70000, 1)

    @patch("docker_broker_client.socket.AF_UNIX", 1, create=True)
    @patch("docker_broker_client.socket.socket")
    def test_malformed_response_is_stable_error(self, socket_mock):
        connection = socket_mock.return_value.__enter__.return_value
        connection.recv.side_effect = [b"not-json\n"]
        with self.assertRaisesRegex(DockerBrokerError, "INVALID_RESPONSE"):
            DockerBrokerClient().list_containers()

    @patch("docker_broker_client.socket.AF_UNIX", 1, create=True)
    @patch("docker_broker_client.socket.socket")
    def test_unknown_broker_error_is_not_exposed(self, socket_mock):
        connection = socket_mock.return_value.__enter__.return_value
        connection.recv.side_effect = [b'{"ok":false,"result":null,"error":"SECRET"}\n']
        with self.assertRaisesRegex(DockerBrokerError, "DOCKER_ERROR"):
            DockerBrokerClient().logs("kali")


if __name__ == "__main__":
    unittest.main()
