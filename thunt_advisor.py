from pathlib import Path
from openai import OpenAI
import httpx
import os
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv(Path(__file__).resolve().parent / ".env")


def _get_api_key() -> str:
    env_key = os.getenv("OPENAI_API_KEY")
    if env_key:
        return env_key

    raise RuntimeError(
        "OpenAI API key not found. "
        "Set OPENAI_API_KEY environment variable or pass api_key explicitly."
    )


def analyze_threat_article(
    article_text: str,
    model: str = "gpt-5.2",
    prompt_path: str = "/shared/threatfeed-collector/prompt.md",
    article_url: str = "",
    additional_pre_context: str = "",
) -> str:
    try:
        resolved_api_key = _get_api_key()
        http_client = httpx.Client(verify=False)
        client = OpenAI(
            api_key=resolved_api_key,
            http_client=http_client
        )
        prompt_template = Path(prompt_path).read_text(encoding="utf-8")
        prompt_template = prompt_template.replace("{{ARTICLE_URL}}", article_url)
        prompt_template = prompt_template.replace("{{ADDITIONAL_PRE_CONTEXT}}", additional_pre_context)
        prompt = prompt_template.replace("{{ARTICLE_BODY}}", article_text)

        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a senior threat intelligence analyst."},
                {"role": "user", "content": prompt}
            ],
        )
        return response.choices[0].message.content
    except Exception:
        return ""
    finally:
        if "http_client" in locals():
            try:
                http_client.close()
            except Exception:
                pass
