import os
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

os.environ.setdefault("TELEGRAM_CHAT_ID", "7459992119")
os.environ.setdefault("TELEGRAM_BOT_TOKEN", "1:" + "x" * 40)

import bot
from docker_broker_client import DockerBrokerError, ExecResult


class BrokerHandlerTest(unittest.IsolatedAsyncioTestCase):
    def test_webapp_url_gets_contract_cache_buster_without_losing_url_parts(self):
        versioned = bot._versioned_webapp_url(
            "https://dashboard.example/app?theme=dark&cloudbot_contract=old#panel"
        )
        self.assertEqual(
            "https://dashboard.example/app?theme=dark&cloudbot_contract=ai-request-v2#panel",
            versioned,
        )
        self.assertEqual("", bot._versioned_webapp_url(""))

    def test_ai_request_contract_accepts_exact_versioned_payload(self):
        request = bot._parse_ai_request(json.dumps({
            "type": "ai_request", "version": 2,
            "message": "SEO-Analyse", "model": "claude-sonnet-4-6",
        }))
        self.assertEqual("SEO-Analyse", request.message)
        self.assertEqual("claude-sonnet-4-6", request.model)

    def test_v2_contract_accepts_every_canonical_model_and_auto(self):
        for model in bot.AI_MODEL_SELECTIONS:
            with self.subTest(model=model):
                request = bot._parse_ai_request(json.dumps({
                    "type": "ai_request", "version": 2,
                    "message": "Auftrag", "model": model,
                }))
                self.assertEqual(model, request.model)

    def test_cached_v1_aliases_are_normalized_for_bot_first_rollout(self):
        aliases = {
            "auto": "auto",
            "haiku": "claude-haiku-4-5",
            "sonnet": "claude-sonnet-5",
            "opus": "claude-opus-4-8",
        }
        for old, canonical in aliases.items():
            with self.subTest(old=old):
                request = bot._parse_ai_request(json.dumps({
                    "type": "ai_request", "version": 1,
                    "message": "Auftrag", "model": old,
                }))
                self.assertEqual(canonical, request.model)

    def test_ai_request_contract_rejects_bad_shapes_types_and_models(self):
        valid = {
            "type": "ai_request", "version": 2,
            "message": "Auftrag", "model": "claude-sonnet-5",
        }
        invalid = [
            [],
            {**valid, "extra": True},
            {key: value for key, value in valid.items() if key != "model"},
            {**valid, "type": "command"},
            {**valid, "version": True},
            {**valid, "version": 3},
            {**valid, "message": "  "},
            {**valid, "message": 3},
            {**valid, "model": "opus"},
            {**valid, "model": "claude-sonnet-4-0"},
            {**valid, "model": "claude-unknown-9"},
            {**valid, "model": "auto --dangerously-skip-permissions"},
        ]
        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                bot._parse_ai_request(json.dumps(payload))
        with self.assertRaises(ValueError):
            bot._parse_ai_request("Profil: schnell")

    def test_ai_request_contract_enforces_utf8_byte_limit(self):
        payload = json.dumps({
            "type": "ai_request", "version": 2,
            "message": "ä" * 4096, "model": "auto",
        }, ensure_ascii=False)
        with self.assertRaises(ValueError):
            bot._parse_ai_request(payload)

    async def test_webapp_ai_request_passes_structured_model_separately(self):
        payload = json.dumps({
            "type": "ai_request", "version": 2,
            "message": "SEO-Analyse example.de", "model": "claude-opus-4-7",
        })
        message = SimpleNamespace(
            web_app_data=SimpleNamespace(data=payload), reply_text=AsyncMock(),
        )
        update = SimpleNamespace(
            update_id=77,
            effective_chat=SimpleNamespace(id=7459992119),
            effective_user=SimpleNamespace(username="ralph"),
            effective_message=message,
        )
        with patch("bot.is_authorized", return_value=True), \
             patch("bot.check_rate_limit", return_value=(True, "")), \
             patch("bot._already_processed", return_value=False), \
             patch("bot.process_message", new=AsyncMock(return_value="Bericht")) as process, \
             patch("bot._send_seo_pdf", new=AsyncMock()) as pdf, \
             patch("bot.log_action") as audit:
            await bot.handle_webapp_data(update, SimpleNamespace(args=[]))
        process.assert_awaited_once_with(
            "SEO-Analyse example.de", 7459992119, "claude-opus-4-7"
        )
        pdf.assert_awaited_once()
        self.assertTrue(all("example.de" not in str(call) for call in audit.call_args_list))

    async def test_invalid_webapp_ai_request_never_reaches_model(self):
        message = SimpleNamespace(
            web_app_data=SimpleNamespace(data='{"type":"ai_request"}'),
            reply_text=AsyncMock(),
        )
        update = SimpleNamespace(
            update_id=78,
            effective_chat=SimpleNamespace(id=7459992119),
            effective_user=SimpleNamespace(username="ralph"),
            effective_message=message,
        )
        with patch("bot.is_authorized", return_value=True), \
             patch("bot.check_rate_limit", return_value=(True, "")), \
             patch("bot._already_processed", return_value=False), \
             patch("bot.process_message", new=AsyncMock()) as process, \
             patch("bot.log_action"):
            await bot.handle_webapp_data(update, SimpleNamespace(args=[]))
        process.assert_not_awaited()
        message.reply_text.assert_awaited_once_with("Ungültige Dashboard-Anfrage.")

    async def test_plain_telegram_text_always_uses_auto_model_selection(self):
        message = SimpleNamespace(text="Bitte schnell prüfen", reply_text=AsyncMock())
        update = SimpleNamespace(
            update_id=79,
            effective_chat=SimpleNamespace(id=7459992119),
            effective_user=SimpleNamespace(username="ralph"),
            message=message,
        )
        with patch("bot.is_authorized", return_value=True), \
             patch("bot.check_rate_limit", return_value=(True, "")), \
             patch("bot._already_processed", return_value=False), \
             patch("bot.process_message", new=AsyncMock(return_value="Fertig")) as process:
            await bot.handle_message(update, SimpleNamespace(args=[]))
        process.assert_awaited_once_with("Bitte schnell prüfen", 7459992119, "auto")

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
