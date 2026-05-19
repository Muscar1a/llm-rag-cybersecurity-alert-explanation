from langchain_classic.chains.combine_documents import (
    create_stuff_documents_chain,
)
from langchain_classic.chains import create_retrieval_chain, create_history_aware_retriever
from langchain_core.chat_history import InMemoryChatMessageHistory
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_ollama import ChatOllama
from .lc_vectorstore import build_retriever
from .lc_prompt import DOCUMENT_PROMPT, DOCUMENT_SEPARATOR, contextualize_prompt, get_qa_prompt
from .settings import settings

_session_store: dict[str, InMemoryChatMessageHistory] = {}

def get_session_history(session_id: str) -> InMemoryChatMessageHistory:
    if session_id not in _session_store:
        _session_store[session_id] = InMemoryChatMessageHistory()
    return _session_store[session_id]


def clear_session(session_id: str) -> None:
    _session_store.pop(session_id, None)
    

def build_chat_chain(
    source: str | None = None, 
    k: int = 5,
    template_name: str = "basic",
) -> RunnableWithMessageHistory:
    llm = ChatOllama(
        model=settings.ollama_model or "mistral:7b-instruct-q4_K_M",
        base_url=settings.ollama_host,
        temperature=0.1,
    )
    
    history_aware_retriever = create_history_aware_retriever(
        llm,
        build_retriever(source=source, k=k),
        contextualize_prompt
    )
    
    qa_chain = create_stuff_documents_chain(
        llm, 
        get_qa_prompt(template_name),
        document_prompt=DOCUMENT_PROMPT,
        document_separator=DOCUMENT_SEPARATOR
    )

    return RunnableWithMessageHistory(
        create_retrieval_chain(history_aware_retriever, qa_chain),
        get_session_history,
        input_messages_key="input",
        history_messages_key="chat_history",
        output_messages_key="answer",
    )
