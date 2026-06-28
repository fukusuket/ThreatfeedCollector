from pathlib import Path
import logging
import os
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

env_path = Path(__file__).resolve().parent / ".env"
if not env_path.exists():
    env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(env_path)

SYSTEM_PROMPT = "You are a senior threat intelligence analyst."
DEFAULT_OPENAI_MODEL = "gpt-5.5"
# Newer Claude models on Bedrock require a cross-region inference profile ID
# (region-prefixed, e.g. "apac.", "us.", "eu."); on-demand model IDs like
# "anthropic.claude-opus-4-8" raise ValidationException.
DEFAULT_BEDROCK_MODEL = "apac.anthropic.claude-opus-4-8"


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
    import json

    import boto3

    region = os.getenv("AWS_REGION", "us-east-1")
    logger.info(f"Calling Bedrock model '{model}' in region '{region}'")
    client = boto3.client("bedrock-runtime", region_name=region)
    body = json.dumps(
        {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 16000,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
    )
    logger.debug(f"Bedrock request body size: {len(body)} bytes")
    try:
        response = client.invoke_model(modelId=model, body=body)
    except Exception as e:
        logger.error(f"Bedrock invoke_model failed for model '{model}': {e}")
        raise
    payload = json.loads(response["body"].read())
    logger.debug(f"Bedrock response payload keys: {list(payload.keys())}")
    result = "".join(
        block["text"]
        for block in payload.get("content", [])
        if block.get("type") == "text"
    )
    logger.info(f"Bedrock returned {len(result)} characters")
    if not result:
        logger.warning(f"Bedrock returned empty text. Full payload: {payload}")
    return result


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
    except Exception as e:
        logger.error(f"Failed to build prompt from {prompt_path}: {e}")
        return ""

    provider = _provider()
    resolved_model = _resolve_model(model, provider)
    logger.info(f"Analyzing article with provider '{provider}', model '{resolved_model}'")
    try:
        if provider == "bedrock":
            return _call_bedrock(prompt, SYSTEM_PROMPT, resolved_model)
        return _call_openai(prompt, SYSTEM_PROMPT, resolved_model)
    except Exception as e:
        logger.exception(f"LLM call failed (provider='{provider}', model='{resolved_model}'): {e}")
        return ""
