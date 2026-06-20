import os
import yaml
from langchain_classic.chains.combine_documents import create_stuff_documents_chain
from langchain_classic.chains import create_retrieval_chain
from langchain_ollama import ChatOllama
from .lc_vectorstore import build_retriever
from .lc_prompt import DOCUMENT_PROMPT, DOCUMENT_SEPARATOR, get_qa_prompt
from .settings import settings


def build_analyze_chain(
    k: int = 5,
    template_name: str = "basic",
):
    model = settings.ollama_model or "deepseek-r1:14b"
    temperature = 0.1
    num_ctx = settings.ollama_num_ctx
    try:
        if os.path.exists("params.yaml"):
            with open("params.yaml", "r", encoding="utf-8") as f:
                p = yaml.safe_load(f)
            llm_p = p.get("llm", {})
            if not settings.ollama_model:
                model = llm_p.get("model", model)
            temperature = llm_p.get("temperature", temperature)
            num_ctx = llm_p.get("num_ctx", num_ctx)
    except Exception:
        pass

    llm = ChatOllama(
        model=model,
        base_url=settings.ollama_host,
        temperature=temperature,
        num_ctx=num_ctx,
    )

    qa_chain = create_stuff_documents_chain(
        llm,
        get_qa_prompt(template_name),
        document_prompt=DOCUMENT_PROMPT,
        document_separator=DOCUMENT_SEPARATOR,
    )

    return create_retrieval_chain(build_retriever(k=k), qa_chain)
