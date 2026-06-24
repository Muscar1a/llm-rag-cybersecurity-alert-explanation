from langchain_openai import ChatOpenAI
from .settings import settings

PROVIDERS = {
    "vllm": {
        "label": "vLLM (Local)",
        "base_url": settings.vllm_base_url,
        "model": "Qwen/Qwen2.5-14B-Instruct",
        "models": ["Qwen/Qwen2.5-14B-Instruct"],
        "requires_api_key": False,
    },
    "openai": {
        "label": "OpenAI",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "models": ["gpt-4o-mini", "gpt-4o", "gpt-4.1-mini", "gpt-4.1-nano"],
        "requires_api_key": True,
    },
    "deepseek": {
        "label": "DeepSeek",
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
        "models": ["deepseek-chat", "deepseek-reasoner"],
        "requires_api_key": True,
    },
    "gemini": {
        "label": "Google Gemini",
        "base_url": None,
        "model": "gemini-2.0-flash",
        "models": ["gemini-2.0-flash", "gemini-2.5-flash", "gemini-2.5-pro"],
        "requires_api_key": True,
    },
    "glm": {
        "label": "GLM (Zhipu)",
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "model": "glm-4-flash",
        "models": ["glm-4-flash", "glm-4-plus"],
        "requires_api_key": True,
    },
    "kimi": {
        "label": "Kimi (Moonshot)",
        "base_url": "https://api.moonshot.cn/v1",
        "model": "moonshot-v1-8k",
        "models": ["moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k"],
        "requires_api_key": True,
    },
    "grok": {
        "label": "Grok (xAI)",
        "base_url": "https://api.x.ai/v1",
        "model": "grok-3-mini",
        "models": ["grok-3-mini", "grok-3"],
        "requires_api_key": True,
    },
}


def build_llm(
    provider: str = "vllm",
    api_key: str | None = None,
    model: str | None = None,
    temperature: float = 0.1,
    max_tokens: int = 4096,
):
    cfg = PROVIDERS.get(provider)
    if cfg is None:
        raise ValueError(f"Unknown provider: {provider}. Supported: {list(PROVIDERS)}")

    model_name = model or cfg["model"]

    if api_key is None and cfg["requires_api_key"]:
        api_key = getattr(settings, f"{provider}_api_key", None)

    if provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(
            model=model_name,
            google_api_key=api_key,
            temperature=temperature,
            max_output_tokens=max_tokens,
        )

    kwargs = {
        "model": model_name,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if provider == "vllm":
        kwargs["base_url"] = cfg["base_url"]
        kwargs["api_key"] = "EMPTY"
    else:
        kwargs["base_url"] = cfg["base_url"]
        kwargs["api_key"] = api_key

    return ChatOpenAI(**kwargs)
