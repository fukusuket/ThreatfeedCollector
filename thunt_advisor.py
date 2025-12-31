from pathlib import Path
from openai import OpenAI
import httpx
import os
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")


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


def analyze_threat_article(
    content: str,
    title: str = "",
    url: str = "",
    model: str = "gpt-5.2",
    prompt_path: str = "/shared/threatfeed-collector/prompt-hunt.md",
    additional_pre_context: str = "",
) -> str:
    try:
        prompt_template = Path(prompt_path).read_text(encoding="utf-8")
        prompt_template = prompt_template.replace(
            "{{ADDITIONAL_PRE_CONTEXT}}", additional_pre_context
        )
        prompt_template = prompt_template.replace("{{ARTICLE_TITLE}}", title)
        prompt_template = prompt_template.replace("{{ARTICLE_URL}}", url)
        prompt = prompt_template.replace("{{CONTENT}}", content)
    except Exception:
        return ""

    http_client = None
    try:
        resolved_api_key = _get_api_key()
        http_client = httpx.Client(verify=False)
        client = OpenAI(api_key=resolved_api_key, http_client=http_client)

        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior threat intelligence analyst.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0,
        )
        return response.choices[0].message.content
    except Exception:
        return ""
    finally:
        if http_client:
            try:
                http_client.close()
            except Exception:
                pass
