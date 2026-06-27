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


class _Block:
    def __init__(self, text, type="text"):
        self.text = text
        self.type = type


def _install_fake_bedrock(monkeypatch, captured, blocks):
    class FakeMessages:
        def create(self, **kwargs):
            captured.update(kwargs)
            return types.SimpleNamespace(content=blocks)

    class FakeClient:
        def __init__(self, **kwargs):
            captured["client_kwargs"] = kwargs
            self.messages = FakeMessages()

    fake = types.ModuleType("anthropic")
    fake.AnthropicBedrockMantle = FakeClient
    monkeypatch.setitem(sys.modules, "anthropic", fake)


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
    blocks = [_Block("Hello "), _Block("ignored", type="thinking"), _Block("World")]
    _install_fake_bedrock(monkeypatch, captured, blocks)

    result = thunt_advisor.analyze_threat_article(
        content="malware",
        title="T",
        url="http://x",
        prompt_path=prompt_file,
        additional_pre_context="pre",
    )

    assert result == "Hello World"
    assert captured["model"] == "anthropic.claude-opus-4-8"
    assert captured["max_tokens"] == 16000
    assert captured["system"] == thunt_advisor.SYSTEM_PROMPT
    assert captured["messages"][0]["role"] == "user"
    assert "body=malware" in captured["messages"][0]["content"]
    assert "ctx=pre" in captured["messages"][0]["content"]


def test_bedrock_uses_default_model_when_env_absent(monkeypatch, prompt_file):
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.delenv("BEDROCK_MODEL_ID", raising=False)
    captured = {}
    _install_fake_bedrock(monkeypatch, captured, [_Block("ok")])

    thunt_advisor.analyze_threat_article(content="c", prompt_path=prompt_file)

    assert captured["model"] == thunt_advisor.DEFAULT_BEDROCK_MODEL


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
    _install_fake_bedrock(monkeypatch, captured, [_Block("ok")])

    thunt_advisor.analyze_threat_article(
        content="c", model="anthropic.claude-sonnet-4-6", prompt_path=prompt_file
    )

    assert captured["model"] == "anthropic.claude-sonnet-4-6"


def test_missing_prompt_file_returns_empty(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    result = thunt_advisor.analyze_threat_article(
        content="c", prompt_path="/nonexistent/prompt.md"
    )
    assert result == ""


def test_provider_exception_returns_empty(monkeypatch, prompt_file):
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")

    fake = types.ModuleType("anthropic")

    class Boom:
        def __init__(self, **kwargs):
            raise RuntimeError("no creds")

    fake.AnthropicBedrockMantle = Boom
    monkeypatch.setitem(sys.modules, "anthropic", fake)

    result = thunt_advisor.analyze_threat_article(content="c", prompt_path=prompt_file)
    assert result == ""
