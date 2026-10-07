"""Provider opt-in: preserve cache history below pressure, retain overflow safety."""
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from agent.turn_preflight import compress_after_tool_results


@pytest.mark.parametrize('billed,strict,expect_prune', [
    (120000, True, False), (300000, True, True),
    (300001, True, True), (120000, False, True),
])
def test_prune_respects_native_cache_prefix_until_compression_pressure(billed, strict, expect_prune):
    class NativeClient:
        HERMES_PRESERVE_CACHED_HISTORY = strict

    class Compressor:
        threshold_tokens = 300000
        last_prompt_tokens = billed
        awaiting_real_usage_after_compression = False
        context_length = 1000000
        def should_compress(self, _):
            return False
        def should_compress_info(self, _):
            return False, None
        def should_defer_preflight_to_real_usage(self):
            return True
        def get_active_compression_failure_cooldown(self):
            return None
        def prune_tool_results_only(self, messages, current_tokens=None):
            prunes.append(current_tokens)
            return [*messages[:-1], {**messages[-1], 'content': '[pruned]'}], 1

    prunes = []
    history = [{'role': 'user', 'content': 'continue'},
               {'role': 'tool', 'tool_call_id': 't', 'content': 'Already cached tool output'}]
    a = SimpleNamespace(client=NativeClient(), context_compressor=Compressor(),
                        compression_enabled=True, session_id='fixture')
    with patch('agent.turn_preflight._reset_read_dedup_caches'):
        verdict = compress_after_tool_results(
            a, messages=history, system_message='system', user_message='continue',
            active_system_prompt='system', conversation_history=[],
            compression_attempts=0, max_compression_attempts=3,
            effective_task_id=None, final_response='', turn_exit_reason=None)
    assert bool(prunes) is expect_prune
    if not expect_prune:
        assert verdict.messages is history
        assert verdict.messages[-1]['content'] == 'Already cached tool output'
