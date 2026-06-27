from pathlib import Path
import os
from dotenv import load_dotenv

env_path = Path(__file__).resolve().parent / ".env"
if not env_path.exists():
    env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(env_path)

SYSTEM_PROMPT = "You are a senior threat intelligence analyst."
DEFAULT_OPENAI_MODEL = "gpt-5.5"
DEFAULT_BEDROCK_MODEL = "anthropic.claude-opus-4-8"


def _provider() -> str:
    return os.getenv("LLM_PROVIDER", "openai").strip().lower()


def _resolve_model(model: str, provider: str) -> str:
    if model:
        return model
    if provider == "bedrock":
        return os.getenv("BEDROCK_MODEL_ID", DEFAULT_BEDROCK_MODEL)
    return os.getenv("OPENAI_MODEL", DEFAULT_OPENAI_MODEL)


def _get_api_key(service: str = "openai") -> str:
    if service == "openai":
        env_key = os.getenv("OPENAI_API_KEY")
        if env_key:
            return env_key

        raise RuntimeError(
            "OpenAI API key not found. "
            "Set OPENAI_API_KEY environment variable or pass api_key explicitly."
        )
    return ""


def _call_openai(prompt: str, system: str, model: str) -> str:
    from openai import OpenAI
    import httpx

    http_client = httpx.Client(verify=False)
    try:
        client = OpenAI(api_key=_get_api_key("openai"), http_client=http_client)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        )
        return response.choices[0].message.content
    finally:
        try:
            http_client.close()
        except Exception:
            pass


def _call_bedrock(prompt: str, system: str, model: str) -> str:
    from anthropic import AnthropicBedrockMantle

    client = AnthropicBedrockMantle(aws_region=os.getenv("AWS_REGION", "us-east-1"))
    response = client.messages.create(
        model=model,
        max_tokens=16000,
        system=system,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in response.content if block.type == "text")


def analyze_threat_article(
    content: str,
    title: str = "",
    url: str = "",
    model: str = "",
    lang: str = "Japanese",
    prompt_path: str = str(Path(__file__).resolve().parent / "config" / "prompt-hunt.md"),
    additional_pre_context: str = "",
) -> str:
    try:
        prompt_template = Path(prompt_path).read_text(encoding="utf-8")
        prompt_template = prompt_template.replace(
            "{{ADDITIONAL_PRE_CONTEXT}}", additional_pre_context
        )
        prompt_template = prompt_template.replace("{{ARTICLE_TITLE}}", title)
        prompt_template = prompt_template.replace("{{ARTICLE_URL}}", url)
        prompt_template = prompt_template.replace("{{LANG}}", lang)
        prompt = prompt_template.replace("{{CONTENT}}", content)
    except Exception:
        return ""

    provider = _provider()
    resolved_model = _resolve_model(model, provider)
    try:
        if provider == "bedrock":
            return _call_bedrock(prompt, SYSTEM_PROMPT, resolved_model)
        return _call_openai(prompt, SYSTEM_PROMPT, resolved_model)
    except Exception:
        return ""
