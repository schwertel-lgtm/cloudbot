from pathlib import Path
import re
import unittest


HTML = (Path(__file__).parents[1] / "webapp" / "index.html").read_text(encoding="utf-8")
COMPOSE = (Path(__file__).parents[1] / "docker-compose.yml").read_text(encoding="utf-8")


class WebAppContractTest(unittest.TestCase):
    def test_local_preview_initialization_is_guarded_and_visible(self):
        self.assertIn(
            "const tg = window.Telegram && window.Telegram.WebApp ? window.Telegram.WebApp : null;",
            HTML,
        )
        self.assertIn("typeof tg.ready === 'function'", HTML)
        self.assertIn("typeof tg.expand === 'function'", HTML)
        self.assertIn("typeof tg.sendData === 'function'", HTML)
        initialization = HTML[HTML.index("const tg = "):HTML.index("let scanProfile")]
        self.assertIn("if (isTelegramMiniApp)", initialization)
        self.assertIn("tg.ready();", initialization)
        self.assertIn("tg.expand();", initialization)
        self.assertIn("document.getElementById('preview-notice').hidden = false", initialization)
        self.assertIn(
            '<div class="preview-notice" id="preview-notice" hidden>'
            'Lokale Vorschau – Senden deaktiviert</div>',
            HTML,
        )

    def test_send_functions_fail_closed_in_preview_without_fake_success(self):
        send_body = HTML[HTML.index("function send(command)"):HTML.index("function sendAi(message)")]
        send_ai_body = HTML[HTML.index("function sendAi(message)"):HTML.index("function execCustom()")]
        for body, send_call in ((send_body, "tg.sendData(command)"), (send_ai_body, "tg.sendData(payload)")):
            guard = body.index("if (!isTelegramMiniApp)")
            preview = body.index("Lokale Vorschau – Senden deaktiviert")
            transport = body.index(send_call)
            success = body.index("showToast('Gesendet!')")
            self.assertLess(guard, preview)
            self.assertLess(preview, transport)
            self.assertLess(transport, success)
            self.assertIn("return false", body[guard:transport])
            self.assertIn("return true", body[transport:])
        self.assertNotIn("sendData: function", HTML)

    def test_obsolete_global_model_override_is_not_deployed(self):
        self.assertNotIn("CLAUDE_CODE_MODEL", COMPOSE)

    def test_model_selector_is_between_system_and_logs_with_auto_default(self):
        system_end = HTML.index("</div>", HTML.index("<h2>System</h2>"))
        selector = HTML.index('<h2>KI-Modell</h2>')
        logs = HTML.index("<h2>Logs</h2>")
        self.assertLess(system_end, selector)
        self.assertLess(selector, logs)
        model_area = HTML[selector:logs]
        radios = re.findall(
            r'<input type="radio" name="ai-model" value="([^"]+)"([^>]*)>',
            model_area,
        )
        self.assertEqual(9, len(radios))
        checked = [value for value, attributes in radios if "checked" in attributes.split()]
        self.assertEqual(["auto"], checked)
        self.assertNotIn("onclick=", model_area)

    def test_native_details_expose_each_family_without_javascript(self):
        model_area = HTML[HTML.index('<h2>KI-Modell</h2>'):HTML.index("<h2>Logs</h2>")]
        self.assertEqual(3, model_area.count('<details class="model-family">'))
        for family in ("Haiku", "Sonnet", "Opus"):
            self.assertIn(f"<summary>{family}</summary>", model_area)
        self.assertNotIn(" hidden", model_area)
        self.assertIn(".model-option input:checked + span", HTML)
        self.assertNotIn(":has(", HTML)

    def test_native_radio_values_are_exact_canonical_versions(self):
        expected = {
            "auto": "Auto",
            "claude-haiku-4-5": "4.5",
            "claude-sonnet-5": "5",
            "claude-sonnet-4-6": "4.6",
            "claude-sonnet-4-5": "4.5",
            "claude-opus-4-8": "4.8",
            "claude-opus-4-7": "4.7",
            "claude-opus-4-6": "4.6",
            "claude-opus-4-5": "4.5",
        }
        values = set(re.findall(r'name="ai-model" value="([^"]+)"', HTML))
        self.assertEqual(set(expected), values)
        for model, label in expected.items():
            self.assertRegex(
                HTML,
                rf'value="{re.escape(model)}"[^>]*>\s*<span>{re.escape(label)}</span>',
            )
        self.assertNotIn("selectModelFamily", HTML)
        self.assertNotIn("selectModelVersion", HTML)
        self.assertNotIn("selectedModel", HTML)

    def test_ai_transport_has_exact_versioned_fields_and_utf8_limit(self):
        send_ai = re.search(
            r"function sendAi\(message\) \{(?P<body>.*?)\n\}", HTML, re.DOTALL
        )
        self.assertIsNotNone(send_ai)
        body = send_ai.group("body")
        for field in ("type: 'ai_request'", "version: 2", "message: message", "model: checkedModel.value"):
            self.assertIn(field, body)
        self.assertIn("new TextEncoder().encode(payload).length > 4096", body)
        self.assertIn("tg.sendData(payload)", body)

    def test_send_ai_reads_checked_radio_and_revalidates_exact_allowlist(self):
        allowlist_match = re.search(
            r"const allowedModelIds = new Set\(\[(?P<values>.*?)\]\);",
            HTML,
            re.DOTALL,
        )
        self.assertIsNotNone(allowlist_match)
        allowed = set(re.findall(r"'([^']+)'", allowlist_match.group("values")))
        radio_values = set(re.findall(r'name="ai-model" value="([^"]+)"', HTML))
        self.assertEqual(radio_values, allowed)

        body = HTML[HTML.index("function sendAi(message)"):HTML.index("function execCustom()")]
        query = "document.querySelector('input[name=\"ai-model\"]:checked')"
        self.assertIn(query, body)
        validation = "if (!checkedModel || !allowedModelIds.has(checkedModel.value))"
        self.assertIn(validation, body)
        self.assertLess(body.index(validation), body.index("JSON.stringify"))
        self.assertLess(body.index(validation), body.index("tg.sendData(payload)"))
        blocked = body[body.index(validation):body.index("JSON.stringify")]
        self.assertIn("Senden blockiert", blocked)
        self.assertIn("return false", blocked)

    def test_all_ai_senders_use_json_and_slash_commands_stay_plaintext(self):
        self.assertEqual(5, len(re.findall(r"\bsendAi\(", HTML)) - 1)
        for command in ("/status", "/vpn", "/ip", "/audit", "/logs kali", "/restart kali"):
            self.assertIn(f"send('{command}')", HTML)
        self.assertIn("send('/exec kali ' + cmd.trim())", HTML)


if __name__ == "__main__":
    unittest.main()
