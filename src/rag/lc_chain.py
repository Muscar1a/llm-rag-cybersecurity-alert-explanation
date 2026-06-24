import os
import yaml
from langchain_classic.chains.combine_documents import create_stuff_documents_chain
from langchain_classic.chains import create_retrieval_chain
from .llm_factory import build_llm
from .lc_vectorstore import build_retriever
from .lc_prompt import DOCUMENT_PROMPT, DOCUMENT_SEPARATOR, get_qa_prompt
from .settings import settings


def build_analyze_chain(
    k: int = 5,
    template_name: str = "basic",
    provider: str = "vllm",
    api_key: str | None = None,
    model: str | None = None,
):
    temperature = 0.1
    max_tokens = settings.vllm_max_tokens
    try:
        if os.path.exists("params.yaml"):
            with open("params.yaml", "r", encoding="utf-8") as f:
                p = yaml.safe_load(f)
            llm_p = p.get("llm", {})
            temperature = llm_p.get("temperature", temperature)
            if provider == "vllm" and not model and not settings.vllm_model:
                model = llm_p.get("model", None)
    except Exception:
        pass

    if provider == "vllm" and not model:
        model = settings.vllm_model or None

    llm = build_llm(
        provider=provider,
        api_key=api_key,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
    )

    qa_chain = create_stuff_documents_chain(
        llm,
        get_qa_prompt(template_name),
        document_prompt=DOCUMENT_PROMPT,
        document_separator=DOCUMENT_SEPARATOR,
    )

    return create_retrieval_chain(build_retriever(k=k), qa_chain)

