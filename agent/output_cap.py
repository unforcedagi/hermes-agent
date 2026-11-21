"""The output cap a main-loop request carries: ``agent.max_tokens``, else ``model.max_tokens``.

``model.max_tokens`` in config.yaml is the configured default model's output cap. It matters
most on a custom OpenAI-compatible endpoint, where Hermes otherwise sends no cap and a reasoning
model on vLLM can think until the server's own limit, the whole remaining context window (T-488).
There is no automatic default: a guessed number can exceed what a local server accepts (a 400),
so with no setting the server's default still applies.

Like ``model.context_length``, the value describes the configured default route. It is read once
at construction (``agent_init._resolve_config_max_tokens``) and applies only while the agent runs
on that route, checked with the same scoping as ``model.context_length`` once per runtime: a
``--model`` launch, ``/model`` switch, fallback or delegated child on another model or endpoint
never inherits it, and switching onto (or restoring) the configured model brings it back. An explicit ``max_tokens`` passed to ``AIAgent`` (internal
bounded tasks) always wins.
"""

import inspect
from contextlib import suppress
import logging
from typing import Any, Optional, Tuple

from hermes_cli.route_identity import normalize_route_base_url

logger = logging.getLogger(__name__)


def output_cap_route(agent: Any) -> Tuple[str, str, str]:
    """The runtime identity the scope decision is memoized on: (model, provider, route URL)."""
    return (
        str(getattr(agent, "model", "") or ""),
        str(getattr(agent, "provider", "") or "").strip().lower(),
        normalize_route_base_url(getattr(agent, "base_url", "") or ""),
    )


def effective_max_tokens(agent: Any) -> Optional[int]:
    """The cap for the next request on ``agent``'s CURRENT runtime, or None (server default)."""
    explicit = getattr(agent, "max_tokens", None)
    if explicit is not None:
        return explicit
    cap = getattr(agent, "_config_max_tokens", None)
    if not cap:
        return None
    route = output_cap_route(agent)
    memo = getattr(agent, "_config_max_tokens_memo", None)
    if memo is None or memo[0] != route:  # decided once per runtime, not per request
        try:
            from agent.agent_init import config_max_tokens_applies  # lazy: agent_init imports this module
            applies = config_max_tokens_applies(agent)
        except Exception:
            logger.warning("Could not scope model.max_tokens to %s on %s; sending no output cap",
                           route[0], route[1], exc_info=True)  # never the URL: a query string can hold a key
            applies = False
        memo = agent._config_max_tokens_memo = (route, applies)
    return cap if memo[1] else None


def output_reservation(agent: Any) -> int:
    """The output the compressor reserves out of the window on the CURRENT runtime: the request's cap,
    or the native-Gemini adapter default when unset (generateContent still sends maxOutputTokens=65,535
    and the threshold is pct x (window - max_tokens), so reserving 0 let the provider 400 before
    compaction fired). 0 = no reservation (never None: ``update_model`` reads None as "keep the old
    one"). Re-derived on every runtime change (switch, fallback, primary restore) so an uncapped
    route clears a capped route's reservation and it tracks the cap actually sent."""
    cap = effective_max_tokens(agent)
    if cap is not None:
        return cap
    with suppress(Exception):
        from agent.gemini_native_adapter import GEMINI_DEFAULT_MAX_OUTPUT_TOKENS, is_native_gemini_base_url
        gemini_provider = str(getattr(agent, "provider", "") or "").strip().lower() in {
            "gemini", "google", "google-gemini", "google-ai-studio",
        }
        if gemini_provider or is_native_gemini_base_url(getattr(agent, "base_url", "")):
            return GEMINI_DEFAULT_MAX_OUTPUT_TOKENS
    return 0


def reservation_kwargs(engine: Any, agent: Any) -> dict:
    """``{"max_tokens": output_reservation(agent)}`` for an engine whose ``update_model`` takes it
    (the built-in compressor), else ``{}``: a plugin ``ContextEngine`` keeping the base signature
    has no ``max_tokens`` parameter and would raise TypeError on every switch or fallback."""
    try:
        params = inspect.signature(engine.update_model).parameters.values()
    except (TypeError, ValueError, AttributeError):
        return {}
    if any(p.name == "max_tokens" or p.kind is inspect.Parameter.VAR_KEYWORD for p in params):
        return {"max_tokens": output_reservation(agent)}
    return {}
