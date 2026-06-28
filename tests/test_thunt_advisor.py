import json
import sys
import types
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

import thunt_advisor


@pytest.fixture
def prompt_file(tmp_path):
    path = tmp_path / "prompt.md"
    path.write_text(
        "ctx={{ADDITIONAL_PRE_CONTEXT}} title={{ARTICLE_TITLE}} "
        "url={{ARTICLE_URL}} lang={{LANG}} body={{CONTENT}}",
        encoding="utf-8",
    )
    return str(path)


def _install_fake_bedrock(monkeypatch, captured, blocks):
    class FakeBody:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return json.dumps(self._payload).encode("utf-8")

    class FakeClient:
        def invoke_model(self, **kwargs):
            captured.update(kwargs)
            captured["body"] = json.loads(kwargs["body"])
            return {"body": FakeBody({"content": blocks})}

    def fake_client(service, **kwargs):
        captured["client_args"] = {"service": service, **kwargs}
        return FakeClient()

    fake = types.ModuleType("boto3")
    fake.client = fake_client
    monkeypatch.setitem(sys.modules, "boto3", fake)


def _install_fake_openai(monkeypatch, captured, content):
    class FakeCompletions:
        def create(self, **kwargs):
            captured.update(kwargs)
            message = types.SimpleNamespace(content=content)
            choice = types.SimpleNamespace(message=message)
            return types.SimpleNamespace(choices=[choice])

    class FakeClient:
        def __init__(self, **kwargs):
            captured["client_kwargs"] = kwargs
            self.chat = types.SimpleNamespace(completions=FakeCompletions())

    fake = types.ModuleType("openai")
    fake.OpenAI = FakeClient
    monkeypatch.setitem(sys.modules, "openai", fake)


def test_bedrock_path_concatenates_text_blocks(monkeypatch, prompt_file):
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.claude-opus-4-8")
    captured = {}
    blocks = [
        {"type": "text", "text": "Hello "},
        {"type": "thinking", "text": "ignored"},
        {"type": "text", "text": "World"},
    ]
    _install_fake_bedrock(monkeypatch, captured, blocks)

    result = thunt_advisor.analyze_threat_article(
        content="malware",
        title="T",
        url="http://x",
        prompt_path=prompt_file,
        additional_pre_context="pre",
    )

    assert result == "Hello World"
    assert captured["modelId"] == "anthropic.claude-opus-4-8"
    assert captured["body"]["max_tokens"] == 16000
    assert captured["body"]["anthropic_version"] == "bedrock-2023-05-31"
    assert captured["body"]["system"] == thunt_advisor.SYSTEM_PROMPT
    assert captured["body"]["messages"][0]["role"] == "user"
    assert "body=malware" in captured["body"]["messages"][0]["content"]
    assert "ctx=pre" in captured["body"]["messages"][0]["content"]


def test_bedrock_uses_default_model_when_env_absent(monkeypatch, prompt_file):
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.delenv("BEDROCK_MODEL_ID", raising=False)
    captured = {}
    _install_fake_bedrock(monkeypatch, captured, [{"type": "text", "text": "ok"}])

    thunt_advisor.analyze_threat_article(content="c", prompt_path=prompt_file)

    assert captured["modelId"] == thunt_advisor.DEFAULT_BEDROCK_MODEL


def test_openai_path_returns_message_content(monkeypatch, prompt_file):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "dummy")
    captured = {}
    _install_fake_openai(monkeypatch, captured, "openai-result")

    result = thunt_advisor.analyze_threat_article(content="c", prompt_path=prompt_file)

    assert result == "openai-result"
    assert captured["model"] == thunt_advisor.DEFAULT_OPENAI_MODEL
    assert captured["messages"][0]["role"] == "system"
    assert captured["messages"][1]["role"] == "user"


def test_explicit_model_overrides_default(monkeypatch, prompt_file):
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    captured = {}
    _install_fake_bedrock(monkeypatch, captured, [{"type": "text", "text": "ok"}])

    thunt_advisor.analyze_threat_article(
        content="c", model="anthropic.claude-sonnet-4-6", prompt_path=prompt_file
    )

    assert captured["modelId"] == "anthropic.claude-sonnet-4-6"


def test_missing_prompt_file_returns_empty(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    result = thunt_advisor.analyze_threat_article(
        content="c", prompt_path="/nonexistent/prompt.md"
    )
    assert result == ""


def test_provider_exception_returns_empty(monkeypatch, prompt_file):
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")

    fake = types.ModuleType("boto3")

    def boom(*args, **kwargs):
        raise RuntimeError("no creds")

    fake.client = boom
    monkeypatch.setitem(sys.modules, "boto3", fake)

    result = thunt_advisor.analyze_threat_article(content="c", prompt_path=prompt_file)
    assert result == ""
