"""``model.max_tokens`` reaches the wire for the configured model on a custom endpoint (T-488).

Without it Hermes sends no output cap to a custom OpenAI-compatible server, so a reasoning
model on vLLM thinks until the server's own limit (the whole remaining context window).
The cap is the configured default model's setting: a runtime on another model or route
never inherits it, and with no setting the server's default still applies.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import yaml

from run_agent import AIAgent


@pytest.fixture
def local_server():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            if not self.path.split("?", 1)[0].endswith("/chat/completions"):  # endpoint probes (e.g. Ollama /api/show)
                self.send_response(404)
                self.end_headers()
                return
            requests.append(body)
            message = {"role": "assistant", "content": "ok"}
            if body.get("stream"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                chunk = {"id": "c", "object": "chat.completion.chunk", "created": 1, "model": body["model"],
                         "choices": [{"index": 0, "delta": message, "finish_reason": "stop"}]}
                self.wfile.write(f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n".encode())
                return
            payload = json.dumps({"id": "c", "object": "chat.completion", "created": 1, "model": body["model"],
                                  "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
                                  "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _home(tmp_path, monkeypatch, base_url, **model_extra):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    model = {"provider": "custom", "default": "local-model", "base_url": base_url, **model_extra}
    (tmp_path / "config.yaml").write_text(yaml.safe_dump({"model": model}))


def _chat(base_url, model="local-model"):
    agent = AIAgent(api_key="local-test", base_url=base_url, provider="custom", model=model,
                    platform="cli", quiet_mode=True, skip_memory=True, skip_context_files=True,
                    enabled_toolsets=[], save_trajectories=False)
    agent.chat("hi")
    return agent


def test_configured_cap_reaches_the_custom_endpoint(tmp_path, monkeypatch, local_server):
    base_url, requests = local_server
    _home(tmp_path, monkeypatch, base_url, max_tokens=7777)

    _chat(base_url)
    assert requests and requests[-1].get("max_tokens") == 7777, requests[-1]

    # Another model on the same endpoint is not the configured default: no inherited cap,
    # whether it is started on that model or switched to it live (/model).
    requests.clear()
    other = _chat(base_url, model="other-model")
    assert requests and "max_tokens" not in requests[-1], requests[-1]
    # Switching onto the configured model brings the cap AND the compressor's output reservation.
    other.switch_model("local-model", "custom", api_key="local-test", base_url=base_url)
    assert other.context_compressor.max_tokens == 7777
    other.chat("now capped")
    assert requests[-1].get("max_tokens") == 7777, requests[-1]
    other.switch_model("other-model", "custom", api_key="local-test", base_url=base_url)
    assert other.context_compressor.max_tokens is None  # switching away clears the reservation

    agent = _chat(base_url)
    requests.clear()
    agent.switch_model("other-model", "custom", api_key="local-test", base_url=base_url)
    agent.chat("hi again")
    assert requests and "max_tokens" not in requests[-1], requests[-1]
    agent.switch_model("local-model", "custom", api_key="local-test", base_url=base_url)
    agent.chat("back")
    assert requests[-1].get("max_tokens") == 7777, requests[-1]


def test_no_setting_leaves_the_server_default(tmp_path, monkeypatch, local_server):
    base_url, requests = local_server
    _home(tmp_path, monkeypatch, base_url)

    _chat(base_url)
    assert requests and "max_tokens" not in requests[-1], requests[-1]


def test_configured_route_with_a_query_string_keeps_its_cap(tmp_path, monkeypatch, local_server):
    """Init moves a base URL's query string into the client's default query; the configured route
    (which keeps it) must still match, or the cap is silently dropped on Azure-style URLs."""
    base_url, requests = local_server
    routed = f"{base_url}?api-version=2026-01-01"
    _home(tmp_path, monkeypatch, routed, max_tokens=4321)

    _chat(routed)
    assert requests and requests[-1].get("max_tokens") == 4321, requests[-1]


def test_switch_with_a_base_signature_plugin_engine_does_not_break(tmp_path, monkeypatch, local_server):
    """A plugin ContextEngine keeping the base ``update_model`` signature (no ``max_tokens``) must
    still survive a /model switch: the reservation is passed only to engines that take it."""
    from agent.context_engine import ContextEngine

    class PlainEngine(ContextEngine):
        name = "plain"
        threshold_tokens = 0
        context_length = 0

        def update_from_response(self, usage):
            pass

        def should_compress(self, prompt_tokens=None):
            return False

        def compress(self, messages, current_tokens=None, **kwargs):
            return messages

    base_url, requests = local_server
    _home(tmp_path, monkeypatch, base_url, max_tokens=7777)
    agent = _chat(base_url)
    agent.context_compressor = PlainEngine()
    agent.switch_model("other-model", "custom", api_key="local-test", base_url=base_url)
    assert agent.model == "other-model"
