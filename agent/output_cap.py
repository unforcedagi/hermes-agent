"""The output cap a main-loop request carries: ``agent.max_tokens``, else ``model.max_tokens``.

``model.max_tokens`` in config.yaml is the configured default model's output cap. It matters
most on a custom OpenAI-compatible endpoint, where Hermes otherwise sends no cap and a reasoning
model on vLLM can think until the server's own limit, the whole remaining context window (T-488).
There is no automatic default: a guessed number can exceed what a local server accepts (a 400),
so with no setting the server's default still applies.

Like ``model.context_length``, the value describes the configured default route. It is read once
at construction (``agent_init._resolve_config_max_tokens``) together with the route it belongs
to, and applies only while the agent runs on that route: a ``--model`` launch, ``/model`` switch,
fallback or delegated child on another model or endpoint never inherits it, and restoring the
primary runtime brings it back. An explicit ``max_tokens`` passed to ``AIAgent`` (internal
bounded tasks) always wins.
"""

from typing import Any, Optional, Tuple

from hermes_cli.route_identity import normalize_route_base_url


def output_cap_route(agent: Any) -> Tuple[str, str, str]:
    """The (model, provider, route URL) a configured cap belongs to."""
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
    if cap and getattr(agent, "_config_max_tokens_route", None) == output_cap_route(agent):
        return cap
    return None
