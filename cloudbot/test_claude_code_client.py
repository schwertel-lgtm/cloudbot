import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("TELEGRAM_CHAT_ID", "7459992119")
os.environ.setdefault("TELEGRAM_BOT_TOKEN", "1:" + "x" * 40)

import ai_agent
import bot
import claude_sidecar
import claude_code_client
from claude_code_client import ClaudeCodeClient, ClaudeCodeError


VALID_PAYLOAD = {"text": "Fertig", "done": True, "tool_calls": []}


class PayloadValidationTest(unittest.TestCase):
    def test_cross_layer_model_allowlists_are_invariant(self):
        canonical = set(claude_code_client.ALLOWED_MODELS)
        self.assertEqual(canonical, set(claude_sidecar.ALLOWED_MODELS))
        self.assertEqual(canonical | {"auto"}, set(ai_agent.MODEL_SELECTIONS))
        self.assertEqual(canonical | {"auto"}, set(bot.AI_MODEL_SELECTIONS))
        self.assertTrue(set(bot.AI_V1_MODEL_ALIASES.values()) <= canonical | {"auto"})

    def test_client_and_sidecar_canonical_model_allowlists_match(self):
        self.assertEqual(
            set(claude_sidecar.ALLOWED_MODELS),
            set(claude_code_client.ALLOWED_MODELS),
        )

    def test_accepts_valid_payload(self):
        result = ClaudeCodeClient._parse_payload(VALID_PAYLOAD)
        self.assertEqual("Fertig", result.text)
        self.assertTrue(result.done)

    def test_query_sends_per_request_model_without_mutable_client_state(self):
        client = ClaudeCodeClient()
        with patch.object(client, "_request", return_value=VALID_PAYLOAD) as request:
            client.query("system", "prompt", 30, "claude-haiku-4-5")
            client.query("system", "prompt", 30, "claude-opus-4-7")
        self.assertEqual("claude-haiku-4-5", request.call_args_list[0].args[0]["model"])
        self.assertEqual("claude-opus-4-7", request.call_args_list[1].args[0]["model"])
        self.assertFalse(hasattr(client, "model"))

    def test_query_rejects_auto_and_unknown_model_before_ipc(self):
        client = ClaudeCodeClient()
        with patch.object(client, "_request") as request:
            for model in ("auto", "sonnet", "claude-sonnet-4-0", "opus --help", ["opus"]):
                with self.subTest(model=model), self.assertRaises(ClaudeCodeError):
                    client.query("system", "prompt", 30, model)
        request.assert_not_called()

    def test_rejects_top_level_additional_field(self):
        with self.assertRaisesRegex(ClaudeCodeError, "INVALID_MODEL_PAYLOAD"):
            ClaudeCodeClient._parse_payload({**VALID_PAYLOAD, "extra": True})

    def test_rejects_more_than_four_calls(self):
        call = {"name": "container_status", "command": ""}
        with self.assertRaises(ClaudeCodeError):
            ClaudeCodeClient._parse_payload({"text": "", "done": False, "tool_calls": [call] * 5})

    def test_rejects_tool_additional_field(self):
        with self.assertRaises(ClaudeCodeError):
            ClaudeCodeClient._parse_payload({
                "text": "", "done": False,
                "tool_calls": [{"name": "exec_kali", "command": "id", "extra": 1}],
            })

    def test_rejects_unknown_tool(self):
        with self.assertRaises(ClaudeCodeError):
            ClaudeCodeClient._parse_payload({
                "text": "", "done": False,
                "tool_calls": [{"name": "Bash", "command": "id"}],
            })

    def test_container_status_must_not_have_command(self):
        with self.assertRaises(ClaudeCodeError):
            ClaudeCodeClient._parse_payload({
                "text": "", "done": False,
                "tool_calls": [{"name": "container_status", "command": "id"}],
            })

    def test_done_must_not_have_calls(self):
        with self.assertRaises(ClaudeCodeError):
            ClaudeCodeClient._parse_payload({
                "text": "Fertig", "done": True,
                "tool_calls": [{"name": "container_status", "command": ""}],
            })


class SidecarTest(unittest.TestCase):
    def test_sidecar_model_allowlist_is_exact(self):
        self.assertEqual({
            "claude-haiku-4-5",
            "claude-sonnet-5", "claude-sonnet-4-6", "claude-sonnet-4-5",
            "claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6", "claude-opus-4-5",
        }, set(claude_sidecar.ALLOWED_MODELS))
        base = {
            "action": "query", "system_prompt": "s", "prompt": "p", "timeout": 30,
        }
        for model in ("auto", "sonnet", "claude-opus-4-4", "Opus", ["opus"]):
            with self.subTest(model=model), self.assertRaises(ClaudeCodeError):
                claude_sidecar._validate_request({**base, "model": model})

    def test_child_environment_is_strict_allowlist(self):
        credentials = {
            "ANTHROPIC_API_KEY": "secret",
            "ANTHROPIC_AUTH_TOKEN": "secret",
            "ANTHROPIC_BASE_URL": "https://routing.invalid",
            "CLAUDE_CODE_USE_BEDROCK": "1",
            "AWS_ACCESS_KEY_ID": "secret",
            "AWS_SECRET_ACCESS_KEY": "secret",
            "GOOGLE_APPLICATION_CREDENTIALS": "secret",
            "AZURE_API_KEY": "secret",
        }
        with patch.dict(os.environ, credentials, clear=False):
            child_env = claude_sidecar._child_environment()
        self.assertEqual(
            {"HOME", "PATH", "LANG", "LC_ALL", "DISABLE_AUTOUPDATER"},
            set(child_env),
        )
        self.assertTrue(set(credentials).isdisjoint(child_env))

    @patch("claude_sidecar._run")
    def test_authentication_requires_max_claude_ai_login(self, run_mock):
        for status in (
            {"loggedIn": True, "authMethod": "apiKey", "subscriptionType": "max"},
            {"loggedIn": True, "authMethod": "claude.ai", "subscriptionType": "pro"},
            {"loggedIn": False, "authMethod": "claude.ai", "subscriptionType": "max"},
        ):
            run_mock.return_value = subprocess.CompletedProcess([], 0, json.dumps(status), "")
            self.assertFalse(claude_sidecar._max_authenticated())
        run_mock.return_value = subprocess.CompletedProcess([], 0, json.dumps({
            "loggedIn": True, "authMethod": "claude.ai", "subscriptionType": "max",
        }), "")
        self.assertTrue(claude_sidecar._max_authenticated())

    def test_request_contract_rejects_extra_fields_and_bad_timeout(self):
        with self.assertRaises(ClaudeCodeError):
            claude_sidecar._validate_request({"action": "auth_status", "extra": 1})
        with self.assertRaises(ClaudeCodeError):
            claude_sidecar._validate_request({
                "action": "query", "system_prompt": "s", "prompt": "p",
                "timeout": 1, "model": "claude-sonnet-5",
            })

    @patch("claude_code_client.socket.AF_UNIX", 1, create=True)
    @patch("claude_code_client.socket.socket")
    def test_client_replaces_unknown_sidecar_error(self, socket_mock):
        connection = socket_mock.return_value.__enter__.return_value
        connection.recv.side_effect = [
            b'{"ok":false,"result":null,"error":"SECRET_FROM_STDERR"}\n'
        ]
        with self.assertRaisesRegex(ClaudeCodeError, "^SIDECAR_ERROR$"):
            ClaudeCodeClient()._request({"action": "auth_status"}, 30)

    @patch("claude_sidecar.subprocess.Popen")
    def test_subprocess_timeout_has_stable_code(self, popen_mock):
        process = popen_mock.return_value
        process.stdout.read.return_value = b""
        process.stderr.read.return_value = b""
        process.wait.side_effect = [subprocess.TimeoutExpired("claude", 30), 0]
        with self.assertRaisesRegex(ClaudeCodeError, "CLAUDE_TIMEOUT"):
            claude_sidecar._run(["claude"], 30)

    @patch("claude_sidecar._max_authenticated", return_value=True)
    @patch("claude_sidecar._run")
    def test_query_uses_noninteractive_security_flags(self, run_mock, _auth_mock):
        run_mock.return_value = subprocess.CompletedProcess([], 0, json.dumps({
            "structured_output": VALID_PAYLOAD,
        }), "")
        claude_sidecar._query({
            "model": "claude-sonnet-5", "system_prompt": "s", "prompt": "p", "timeout": 30,
        })
        command = run_mock.call_args.args[0]
        self.assertEqual("/usr/local/bin/claude", command[0])
        self.assertIn("-p", command)
        self.assertEqual("", command[command.index("--tools") + 1])
        self.assertIn("--no-session-persistence", command)
        self.assertIn("--json-schema", command)
        self.assertEqual("claude-sonnet-5", command[command.index("--model") + 1])

    def test_query_capacity_exhaustion_is_stable_busy_error(self):
        with patch.object(claude_sidecar._QUERY_SLOTS, "acquire", return_value=False), \
             patch.object(claude_sidecar._QUERY_SLOTS, "release") as release:
            with self.assertRaisesRegex(ClaudeCodeError, "SIDECAR_BUSY"):
                claude_sidecar._query({})
        release.assert_not_called()

    def test_socket_symlink_is_rejected_before_unlink(self):
        path = MagicMock()
        path.is_symlink.return_value = True
        with self.assertRaisesRegex(RuntimeError, "Symlink"):
            claude_sidecar._prepare_socket_path(path)
        path.unlink.assert_not_called()

    @patch("claude_sidecar._max_authenticated", return_value=True)
    @patch("claude_sidecar._run")
    def test_query_rejects_nonzero_without_leaking_stderr(self, run_mock, _auth_mock):
        run_mock.return_value = subprocess.CompletedProcess([], 2, "", "sensitive-token")
        with self.assertRaisesRegex(ClaudeCodeError, "^CLAUDE_NONZERO_EXIT$") as raised:
            claude_sidecar._query({
                "model": "claude-sonnet-5", "system_prompt": "s", "prompt": "p", "timeout": 30,
            })
        self.assertNotIn("sensitive", str(raised.exception))

    @patch("claude_sidecar._max_authenticated", return_value=True)
    @patch("claude_sidecar._run")
    def test_query_rejects_malformed_output(self, run_mock, _auth_mock):
        run_mock.return_value = subprocess.CompletedProcess([], 0, "not-json", "")
        with self.assertRaisesRegex(ClaudeCodeError, "CLAUDE_MALFORMED_OUTPUT"):
            claude_sidecar._query({
                "model": "claude-sonnet-5", "system_prompt": "s", "prompt": "p", "timeout": 30,
            })

    @unittest.skipIf(claude_sidecar._Server is None, "Unix Domain Sockets sind hier nicht verfügbar")
    def test_real_unix_socket_round_trip(self):
        with tempfile.TemporaryDirectory() as temporary:
            socket_path = str(Path(temporary) / "claude.sock")
            server = claude_sidecar._Server(socket_path, claude_sidecar._Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with patch("claude_sidecar._max_authenticated", return_value=True):
                    self.assertTrue(ClaudeCodeClient(socket_path=socket_path).is_authenticated())
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
