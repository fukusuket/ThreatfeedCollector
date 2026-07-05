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


def _install_fake_bedrock_openai(monkeypatch, captured, content):
    class FakeBody:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return json.dumps(self._payload).encode("utf-8")

    class FakeClient:
        def invoke_model(self, **kwargs):
            captured.update(kwargs)
            captured["body"] = json.loads(kwargs["body"])
            return {
                "body": FakeBody(
                    {"choices": [{"message": {"role": "assistant", "content": content}}]}
                )
            }

    def fake_client(service, **kwargs):
        captured["client_args"] = {"service": service, **kwargs}
        return FakeClient()

    fake = types.ModuleType("boto3")
    fake.client = fake_client
    monkeypatch.setitem(sys.modules, "boto3", fake)


def test_bedrock_gpt_oss_model_uses_chat_completions_schema(monkeypatch, prompt_file):
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.setenv("BEDROCK_MODEL_ID", "us.openai.gpt-oss-120b-1:0")
    captured = {}
    _install_fake_bedrock_openai(monkeypatch, captured, "openai-on-bedrock")

    result = thunt_advisor.analyze_threat_article(
        content="malware",
        title="T",
        url="http://x",
        prompt_path=prompt_file,
        additional_pre_context="pre",
    )

    assert result == "openai-on-bedrock"
    assert captured["modelId"] == "us.openai.gpt-oss-120b-1:0"
    assert captured["body"]["max_completion_tokens"] == 16000
    assert captured["body"]["messages"][0]["role"] == "system"
    assert captured["body"]["messages"][0]["content"] == thunt_advisor.SYSTEM_PROMPT
    assert captured["body"]["messages"][1]["role"] == "user"
    assert "body=malware" in captured["body"]["messages"][1]["content"]
    assert "ctx=pre" in captured["body"]["messages"][1]["content"]
    assert "title=T" in captured["body"]["messages"][1]["content"]
    assert "url=http://x" in captured["body"]["messages"][1]["content"]


def _install_fake_bedrock_mantle(monkeypatch, captured, text):
    class FakeResponses:
        def create(self, **kwargs):
            captured.update(kwargs)
            return types.SimpleNamespace(output_text=text)

    class FakeClient:
        def __init__(self, **kwargs):
            captured["client_kwargs"] = kwargs
            self.responses = FakeResponses()

    fake = types.ModuleType("openai")
    fake.OpenAI = FakeClient
    monkeypatch.setitem(sys.modules, "openai", fake)


def test_bedrock_gpt55_uses_mantle_responses_api(monkeypatch, prompt_file):
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.setenv("BEDROCK_MODEL_ID", "openai.gpt-5.5")
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "bedrock-key")
    monkeypatch.setenv("AWS_REGION", "us-east-2")
    captured = {}
    _install_fake_bedrock_mantle(monkeypatch, captured, "gpt55-on-bedrock")

    result = thunt_advisor.analyze_threat_article(
        content="malware", prompt_path=prompt_file
    )

    assert result == "gpt55-on-bedrock"
    assert captured["model"] == "openai.gpt-5.5"
    assert captured["instructions"] == thunt_advisor.SYSTEM_PROMPT
    assert "body=malware" in captured["input"]
    assert captured["client_kwargs"]["api_key"] == "bedrock-key"
    assert (
        captured["client_kwargs"]["base_url"]
        == "https://bedrock-mantle.us-east-2.api.aws/openai/v1"
    )


def test_bedrock_gpt55_without_api_key_returns_empty(monkeypatch, prompt_file):
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.setenv("BEDROCK_MODEL_ID", "openai.gpt-5.5")
    monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)

    result = thunt_advisor.analyze_threat_article(content="c", prompt_path=prompt_file)
    assert result == ""


def test_bedrock_uses_default_model_when_env_absent(monkeypatch, prompt_file):
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.delenv("BEDROCK_MODEL_ID", raising=False)
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "bedrock-key")
    captured = {}
    _install_fake_bedrock_mantle(monkeypatch, captured, "ok")

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
    _install_fake_bedrock_openai(monkeypatch, captured, "ok")

    thunt_advisor.analyze_threat_article(
        content="c", model="us.openai.gpt-oss-20b-1:0", prompt_path=prompt_file
    )

    assert captured["modelId"] == "us.openai.gpt-oss-20b-1:0"


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
