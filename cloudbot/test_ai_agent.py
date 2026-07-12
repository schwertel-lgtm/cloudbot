import os
import unittest
from unittest.mock import patch

os.environ.setdefault("TELEGRAM_CHAT_ID", "7459992119")

import ai_agent
from claude_code_client import ClaudeCodeResult, ToolCall


class ProcessMessageTest(unittest.IsolatedAsyncioTestCase):
    def test_agent_model_allowlist_is_exact_and_has_no_aliases(self):
        self.assertEqual({
            "auto", "claude-haiku-4-5",
            "claude-sonnet-5", "claude-sonnet-4-6", "claude-sonnet-4-5",
            "claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6", "claude-opus-4-5",
        }, set(ai_agent.MODEL_SELECTIONS))

    def test_auto_model_policy_covers_all_profiles(self):
        cases = {
            "Bitte schnell prüfen": "claude-haiku-4-5",
            "Normale Recherche": "claude-sonnet-5",
            "SEO-Schnellanalyse für example.de": "claude-sonnet-5",
            "Hallo Cloudbot": "claude-sonnet-5",
            "Bitte intensiv und vollständig prüfen": "claude-opus-4-8",
        }
        for message, expected in cases.items():
            with self.subTest(message=message):
                self.assertEqual(expected, ai_agent._resolve_model(message, "auto"))

    def test_manual_model_overrides_profile_without_changing_limits(self):
        self.assertEqual(
            "claude-opus-4-6",
            ai_agent._resolve_model("schnell", "claude-opus-4-6"),
        )
        self.assertEqual(ai_agent.SCAN_PROFILES["schnell"], ai_agent._detect_profile("schnell"))

    def test_invalid_model_selection_is_rejected(self):
        with self.assertRaises(ValueError):
            ai_agent._resolve_model("Hallo", "sonnet")

    async def test_done_with_empty_text_is_stable_failure_and_failed_audit(self):
        empty_done = ClaudeCodeResult(text="", done=True, tool_calls=())
        with patch.object(ai_agent.client_ai, "authentication_status", return_value=True), \
             patch.object(ai_agent.client_ai, "query", return_value=empty_done), \
             patch("ai_agent.log_action") as audit:
            result = await ai_agent.process_message("Hallo", 1)
        self.assertEqual("Die KI hat keinen vollständigen Endbericht geliefert. Bitte versuche es erneut.", result)
        self.assertFalse(audit.call_args.args[-1])
        self.assertEqual("KI_ENDBERICHT_UNVOLLSTAENDIG", audit.call_args.args[-2])

    async def test_tool_loop_requests_and_returns_final_report(self):
        tool_round = ClaudeCodeResult(
            text="", done=False,
            tool_calls=(ToolCall(name="container_status", command=""),),
        )
        final = ClaudeCodeResult(text="Alles in Ordnung.", done=True, tool_calls=())
        with patch.object(ai_agent.client_ai, "authentication_status", return_value=True), \
             patch.object(ai_agent.client_ai, "query", side_effect=[tool_round, final]) as query, \
             patch("ai_agent._get_container_status", return_value="[+] kali -- running"), \
             patch("ai_agent.log_action") as audit:
            result = await ai_agent.process_message("Status?", 1)
        self.assertEqual("Alles in Ordnung.", result)
        self.assertEqual(2, query.call_count)
        self.assertTrue(audit.call_args.args[-1])

    async def test_tool_execution_is_offloaded_from_event_loop(self):
        tool_round = ClaudeCodeResult(
            text="", done=False,
            tool_calls=(ToolCall(name="container_status", command=""),),
        )
        final = ClaudeCodeResult(text="Fertig.", done=True, tool_calls=())
        calls = []

        async def recording_to_thread(function, *args):
            calls.append(function)
            return function(*args)

        with patch.object(ai_agent.client_ai, "authentication_status", return_value=True), \
             patch.object(ai_agent.client_ai, "query", side_effect=[tool_round, final]), \
             patch("ai_agent._get_container_status", return_value="[+] kali -- running"), \
             patch("ai_agent.asyncio.to_thread", side_effect=recording_to_thread), \
             patch("ai_agent.log_action"):
            self.assertEqual("Fertig.", await ai_agent.process_message("Status?", 1))
        self.assertIn(ai_agent._handle_tool_call, calls)

    async def test_resolved_model_is_passed_to_every_query(self):
        final = ClaudeCodeResult(text="Fertig.", done=True, tool_calls=())
        with patch.object(ai_agent.client_ai, "authentication_status", return_value=True), \
             patch.object(ai_agent.client_ai, "query", return_value=final) as query, \
             patch("ai_agent.log_action"):
            self.assertEqual(
                "Fertig.",
                await ai_agent.process_message("Bitte schnell prüfen", 1, "auto"),
            )
        self.assertEqual("claude-haiku-4-5", query.call_args.args[3])

    async def test_manual_model_is_not_written_into_prompt(self):
        final = ClaudeCodeResult(text="Fertig.", done=True, tool_calls=())
        with patch.object(ai_agent.client_ai, "authentication_status", return_value=True), \
             patch.object(ai_agent.client_ai, "query", return_value=final) as query, \
             patch("ai_agent.log_action"):
            await ai_agent.process_message("Normaler Auftrag", 1, "claude-opus-4-7")
        system_prompt, prompt, _timeout, model = query.call_args.args
        self.assertEqual("claude-opus-4-7", model)
        self.assertNotIn("claude-opus-4-7", system_prompt.lower())
        self.assertNotIn("claude-opus-4-7", prompt.lower())

    async def test_resolved_model_reaches_forced_completion_round(self):
        incomplete = ClaudeCodeResult(text="Zwischenstand", done=False, tool_calls=())
        final = ClaudeCodeResult(text="Endbericht", done=True, tool_calls=())
        with patch.object(ai_agent.client_ai, "authentication_status", return_value=True), \
             patch.object(ai_agent.client_ai, "query", side_effect=[incomplete, final]) as query, \
             patch("ai_agent.log_action"):
            result = await ai_agent.process_message("Intensiver Auftrag", 1, "claude-opus-4-8")
        self.assertEqual("Zwischenstand\nEndbericht", result)
        self.assertEqual(2, query.call_count)
        self.assertEqual(
            ["claude-opus-4-8", "claude-opus-4-8"],
            [call.args[3] for call in query.call_args_list],
        )

    async def test_resolved_model_reaches_timeout_summary(self):
        tool_round = ClaudeCodeResult(
            text="", done=False,
            tool_calls=(ToolCall(name="container_status", command=""),),
        )
        summary = ClaudeCodeResult(text="Kurze Zusammenfassung", done=True, tool_calls=())
        with patch.object(ai_agent.client_ai, "authentication_status", return_value=True), \
             patch.object(ai_agent.client_ai, "query", side_effect=[tool_round, summary]) as query, \
             patch("ai_agent._get_container_status", return_value="[+] kali -- running"), \
             patch("ai_agent.time.time", side_effect=[0, 0, 301, 301]), \
             patch("ai_agent.log_action"):
            result = await ai_agent.process_message("Bitte schnell prüfen", 1, "auto")
        self.assertIn("Kurze Zusammenfassung", result)
        self.assertIn("Timeout nach 301s", result)
        self.assertEqual(2, query.call_count)
        self.assertEqual(
            ["claude-haiku-4-5", "claude-haiku-4-5"],
            [call.args[3] for call in query.call_args_list],
        )


if __name__ == "__main__":
    unittest.main()
