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
# GPT-5.x models on Bedrock are served only through the bedrock-mantle
# endpoint's Responses API (InvokeModel/Converse raise ValidationException)
# and are available only in us-east-1 / us-east-2.
# Newer Claude models on Bedrock require a cross-region inference profile ID
# (region-prefixed, e.g. "apac.", "us.", "eu."); on-demand model IDs like
# "anthropic.claude-opus-4-8" raise ValidationException.
DEFAULT_BEDROCK_MODEL = "openai.gpt-5.5"


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


def _is_bedrock_openai_model(model: str) -> bool:
    # OpenAI models on Bedrock use "openai." in the model/inference-profile ID
    # (e.g. "openai.gpt-5.5", "us.openai.gpt-oss-120b-1:0").
    return "openai." in model.lower()


def _uses_bedrock_mantle(model: str) -> bool:
    # GPT-5.x models on Bedrock support only the Responses API on the
    # bedrock-mantle endpoint; gpt-oss models still go through InvokeModel.
    return _is_bedrock_openai_model(model) and "gpt-oss" not in model.lower()


def _call_bedrock_mantle(prompt: str, system: str, model: str) -> str:
    from openai import OpenAI
    import httpx

    api_key = os.getenv("AWS_BEARER_TOKEN_BEDROCK")
    if not api_key:
        raise RuntimeError(
            "AWS_BEARER_TOKEN_BEDROCK not found. GPT models on Bedrock use the "
            "bedrock-mantle endpoint, which authenticates with a Bedrock API key."
        )
    region = os.getenv("AWS_REGION", "us-east-1")
    logger.info(
        f"Calling Bedrock model '{model}' in region '{region}' "
        f"(bedrock-mantle Responses API)"
    )
    http_client = httpx.Client(verify=False)
    try:
        client = OpenAI(
            api_key=api_key,
            base_url=f"https://bedrock-mantle.{region}.api.aws/openai/v1",
            http_client=http_client,
        )
        response = client.responses.create(
            model=model,
            instructions=system,
            input=prompt,
        )
        result = response.output_text or ""
        logger.info(f"Bedrock returned {len(result)} characters")
        return result
    finally:
        try:
            http_client.close()
        except Exception:
            pass


def _bedrock_openai_body(prompt: str, system: str) -> str:
    # OpenAI models on Bedrock expect the OpenAI Chat Completions schema,
    # not Anthropic's ("anthropic_version"/"system"/content blocks).
    import json

    return json.dumps(
        {
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "max_completion_tokens": 16000,
        }
    )


def _bedrock_anthropic_body(prompt: str, system: str) -> str:
    import json

    return json.dumps(
        {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 16000,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
    )


def _parse_bedrock_openai_payload(payload: dict) -> str:
    # OpenAI Chat Completions response shape.
    choices = payload.get("choices", [])
    if not choices:
        return ""
    return choices[0].get("message", {}).get("content") or ""


def _parse_bedrock_anthropic_payload(payload: dict) -> str:
    return "".join(
        block["text"]
        for block in payload.get("content", [])
        if block.get("type") == "text"
    )


def _call_bedrock(prompt: str, system: str, model: str) -> str:
    if _uses_bedrock_mantle(model):
        return _call_bedrock_mantle(prompt, system, model)

    import json

    import boto3

    region = os.getenv("AWS_REGION", "us-east-1")
    is_openai = _is_bedrock_openai_model(model)
    logger.info(
        f"Calling Bedrock model '{model}' in region '{region}' "
        f"(schema={'openai' if is_openai else 'anthropic'})"
    )
    client = boto3.client("bedrock-runtime", region_name=region)
    body = (
        _bedrock_openai_body(prompt, system)
        if is_openai
        else _bedrock_anthropic_body(prompt, system)
    )
    logger.debug(f"Bedrock request body size: {len(body)} bytes")
    try:
        response = client.invoke_model(modelId=model, body=body)
    except Exception as e:
        logger.error(f"Bedrock invoke_model failed for model '{model}': {e}")
        raise
    payload = json.loads(response["body"].read())
    logger.debug(f"Bedrock response payload keys: {list(payload.keys())}")
    result = (
        _parse_bedrock_openai_payload(payload)
        if is_openai
        else _parse_bedrock_anthropic_payload(payload)
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
