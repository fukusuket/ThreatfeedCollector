from pathlib import Path
from openai import OpenAI
from google import genai
from google.genai import types
import httpx
import os
from dotenv import load_dotenv

# Load environment variables from .env if present
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
    elif service == "google":
        env_key = os.getenv("GOOGLE_API_KEY")
        if env_key:
            return env_key

        raise RuntimeError(
            "Google API key not found. "
            "Set GOOGLE_API_KEY environment variable."
        )
    return ""


def analyze_threat_article(
    article_text: str,
    article_url: str = "",
    model: str = "gpt-5.2",
    prompt_path: str = "/shared/threatfeed-collector/prompt.md",
    additional_pre_context: str = "",
) -> str:
    try:
        prompt_template = Path(prompt_path).read_text(encoding="utf-8")
        prompt_template = prompt_template.replace("{{ARTICLE_URL}}", article_url)
        prompt_template = prompt_template.replace("{{ADDITIONAL_PRE_CONTEXT}}", additional_pre_context)
        prompt = prompt_template.replace("{{ARTICLE_BODY}}", article_text)
    except Exception:
        return ""

    if "gemini" in model.lower():
        try:
            api_key = _get_api_key("google")
            client = genai.Client(api_key=api_key)
            response = client.models.generate_content(
                model=model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction="You are a senior threat intelligence analyst.",
                    temperature=0,
                )
            )
            return response.text
        except Exception:
            return ""

    http_client = None
    try:
        resolved_api_key = _get_api_key()
        http_client = httpx.Client(verify=False)
        client = OpenAI(
            api_key=resolved_api_key,
            http_client=http_client
        )

        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a senior threat intelligence analyst."},
                {"role": "user", "content": prompt}
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
