import os
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

os.environ.setdefault("TELEGRAM_CHAT_ID", "7459992119")
os.environ.setdefault("TELEGRAM_BOT_TOKEN", "1:" + "x" * 40)

import bot
from docker_broker_client import DockerBrokerError, ExecResult


class BrokerHandlerTest(unittest.IsolatedAsyncioTestCase):
    async def test_vpn_handler_offloads_fixed_broker_operation(self):
        message = SimpleNamespace(reply_text=AsyncMock())
        update = SimpleNamespace(
            effective_chat=SimpleNamespace(id=7459992119),
            effective_user=SimpleNamespace(username="ralph"),
            message=message,
        )
        with patch("bot.is_authorized", return_value=True), \
             patch("bot.check_rate_limit", return_value=(True, "")), \
             patch.object(bot.docker_broker, "vpn_status", return_value=ExecResult(
                 exit_code=0, stdout="Status: Connected", stderr=""
             )) as vpn, patch("bot.log_action"):
            await bot.cmd_vpn(update, SimpleNamespace(args=[]))
        vpn.assert_called_once_with()
        message.reply_text.assert_awaited_once_with("VPN Status:\n\nStatus: Connected")

    def test_broker_error_messages_are_stable_and_differentiated(self):
        self.assertEqual(
            "Datei nicht gefunden.", bot._broker_error_text(DockerBrokerError("FILE_NOT_FOUND"))
        )
        self.assertEqual(
            "Datei ist zu groß (maximal 8 MB).",
            bot._broker_error_text(DockerBrokerError("FILE_TOO_LARGE")),
        )
        self.assertEqual(
            "Docker-Dienst ist derzeit nicht erreichbar.",
            bot._broker_error_text(DockerBrokerError("DOCKER_ERROR")),
        )

    async def test_files_handler_ignores_malformed_size_lines(self):
        message = SimpleNamespace(reply_text=AsyncMock())
        update = SimpleNamespace(
            effective_chat=SimpleNamespace(id=7459992119),
            effective_user=SimpleNamespace(username="ralph"),
            message=message,
        )
        with patch("bot.is_authorized", return_value=True), \
             patch("bot.check_rate_limit", return_value=(True, "")), \
             patch.object(bot.docker_broker, "list_files",
                          return_value="not-a-size /bad\n42 /root/data/good.txt\n"), \
             patch("bot.log_action"):
            await bot.cmd_files(update, SimpleNamespace(args=[]))
        sent = message.reply_text.await_args.args[0]
        self.assertIn("42 B -- /root/data/good.txt", sent)
        self.assertNotIn("/bad", sent)


if __name__ == "__main__":
    unittest.main()
