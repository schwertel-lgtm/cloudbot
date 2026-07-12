import os
import unittest
from unittest.mock import patch

os.environ.setdefault("TELEGRAM_CHAT_ID", "7459992119")

import ai_agent
from claude_code_client import ClaudeCodeResult, ToolCall


class ProcessMessageTest(unittest.IsolatedAsyncioTestCase):
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


if __name__ == "__main__":
    unittest.main()
