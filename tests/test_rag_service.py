"""
Tests for src/rag/lc_service.py and the /chat API endpoints.

Unit tests mock the LLM chain so no Ollama/Qdrant is required.
Integration tests use FastAPI TestClient with the same mocks.
"""

import json
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from langchain_core.documents import Document


# ── helpers ────────────────────────────────────────────────────────────────────

def _chain_result(answer: str, docs: list | None = None):
    """Build the dict that build_chat_chain().invoke() returns."""
    return {
        "answer": answer,
        "context": docs or [],
    }


def _good_answer(severity: str = "High") -> str:
    return json.dumps({
        "threat_description": "Port scan detected",
        "severity": severity,
        "rationale": "Nmap UA found",
        "mitigation_steps": ["Block IP", "Investigate"],
    })


# ── _extract_json ──────────────────────────────────────────────────────────────

class TestExtractJson:
    def setup_method(self):
        from src.rag.lc_service import _extract_json
        self.fn = _extract_json

    def test_plain_json(self):
        raw = '{"a": 1}'
        assert self.fn(raw) == '{"a": 1}'

    def test_answer_tags(self):
        raw = '<answer>\n{"a": 1}\n</answer>'
        assert self.fn(raw) == '{"a": 1}'

    def test_code_block(self):
        raw = '```json\n{"a": 1}\n```'
        assert self.fn(raw) == '{"a": 1}'

    def test_embedded_in_text(self):
        raw = 'Here is the result: {"a": 1} done.'
        assert self.fn(raw) == '{"a": 1}'

    def test_raises_when_no_json(self):
        with pytest.raises(ValueError, match="No JSON found"):
            self.fn("no json here at all")


# ── _normalize ─────────────────────────────────────────────────────────────────

class TestNormalize:
    def setup_method(self):
        from src.rag.lc_service import _normalize
        self.fn = _normalize

    def test_full_valid_input(self):
        data = {
            "threat_description": "desc",
            "severity": "High",
            "rationale": "reason",
            "mitigation_steps": ["step1", "step2"],
        }
        result = self.fn(data)
        assert result["severity"] == "High"
        assert result["mitigation_steps"] == ["step1", "step2"]

    def test_missing_keys_use_defaults(self):
        result = self.fn({})
        assert result["threat_description"] == ""
        assert result["severity"] == "Unknown"
        assert result["rationale"] == ""
        assert result["mitigation_steps"] == []

    def test_steps_as_string_becomes_list(self):
        result = self.fn({"mitigation_steps": "single step"})
        assert result["mitigation_steps"] == ["single step"]

    def test_steps_coerced_to_str(self):
        result = self.fn({"mitigation_steps": [1, 2, 3]})
        assert result["mitigation_steps"] == ["1", "2", "3"]


# ── _parse_output ──────────────────────────────────────────────────────────────

class TestParseOutput:
    def setup_method(self):
        from src.rag.lc_service import _parse_output
        self.fn = _parse_output

    def test_valid_json_string(self):
        raw = _good_answer("Medium")
        result = self.fn(raw)
        assert result["severity"] == "Medium"
        assert result["threat_description"] == "Port scan detected"

    def test_fallback_on_invalid_input(self):
        result = self.fn("not json at all")
        assert result["severity"] == "Unknown"
        assert "Could not parse" in result["rationale"]
        assert result["threat_description"] == "not json at all"

    def test_code_block_json(self):
        raw = f"```json\n{_good_answer('Low')}\n```"
        result = self.fn(raw)
        assert result["severity"] == "Low"


# ── ChatService (unit, chain mocked) ──────────────────────────────────────────

class TestChatService:
    def _make_doc(self, chunk_id: str) -> Document:
        return Document(page_content="ctx", metadata={"chunk_id": chunk_id})

    @patch("src.rag.lc_service.build_chat_chain")
    def test_chat_returns_parsed_result(self, mock_build):
        chain = MagicMock()
        chain.invoke.return_value = _chain_result(
            _good_answer("High"),
            [self._make_doc("chunk-1"), self._make_doc("chunk-2")],
        )
        mock_build.return_value = chain

        from src.rag.lc_service import ChatService
        svc = ChatService()
        result = svc.chat(session_id="s1", message="test alert")

        assert result["severity"] == "High"
        assert result["session_id"] == "s1"
        assert result["retrieved_context_ids"] == ["chunk-1", "chunk-2"]

    @patch("src.rag.lc_service.build_chat_chain")
    def test_chat_passes_source_and_k(self, mock_build):
        chain = MagicMock()
        chain.invoke.return_value = _chain_result(_good_answer())
        mock_build.return_value = chain

        from src.rag.lc_service import ChatService
        ChatService().chat(session_id="s1", message="msg", source="mitre", k=3, template_name="cot")

        mock_build.assert_called_once_with(source="mitre", k=3, template_name="cot")

    @patch("src.rag.lc_service.build_chat_chain")
    def test_chat_handles_malformed_llm_output(self, mock_build):
        chain = MagicMock()
        chain.invoke.return_value = _chain_result("totally not json")
        mock_build.return_value = chain

        from src.rag.lc_service import ChatService
        result = ChatService().chat(session_id="s1", message="msg")
        assert result["severity"] == "Unknown"

    def test_get_history_empty(self):
        from src.rag.lc_service import ChatService, clear_session
        session_id = "hist-test-empty"
        clear_session(session_id)
        assert ChatService().get_history(session_id) == []

    @patch("src.rag.lc_service.build_chat_chain")
    def test_get_history_after_chat(self, mock_build):
        chain = MagicMock()
        chain.invoke.return_value = _chain_result(_good_answer())
        mock_build.return_value = chain

        from src.rag.lc_service import ChatService, clear_session, get_session_history
        from langchain_core.messages import HumanMessage, AIMessage

        session_id = "hist-test-populated"
        clear_session(session_id)

        history = get_session_history(session_id)
        history.add_message(HumanMessage(content="hello"))
        history.add_message(AIMessage(content="world"))

        msgs = ChatService().get_history(session_id)
        assert msgs == [
            {"role": "human", "content": "hello"},
            {"role": "ai", "content": "world"},
        ]

    def test_clear_removes_session(self):
        from src.rag.lc_service import ChatService
        from src.rag.lc_chain import get_session_history, _session_store
        session_id = "clear-test"
        get_session_history(session_id)
        assert session_id in _session_store

        ChatService().clear(session_id)
        assert session_id not in _session_store


# ── FastAPI endpoint integration ──────────────────────────────────────────────

@pytest.fixture()
def client():
    """TestClient with ChatService.chat mocked to avoid real LLM/Qdrant calls."""
    with patch("src.api.main.chat_svc") as mock_svc:
        mock_svc.chat.return_value = {
            "threat_description": "Scan",
            "severity": "Medium",
            "rationale": "evidence",
            "mitigation_steps": ["step"],
            "session_id": "test-session",
            "retrieved_context_ids": ["c1"],
        }
        mock_svc.get_history.return_value = [
            {"role": "human", "content": "hello"},
            {"role": "ai", "content": "world"},
        ]
        from src.api.main import app
        yield TestClient(app)


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_chat_endpoint_success(client):
    resp = client.post("/chat", json={"message": "nmap scan detected", "session_id": "test-session"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["severity"] == "Medium"
    assert body["session_id"] == "test-session"
    assert "mitigation_steps" in body


def test_chat_endpoint_with_source_and_template(client):
    resp = client.post("/chat", json={
        "message": "brute force login",
        "session_id": "s2",
        "source": "mitre",
        "k": 3,
        "template_name": "cot",
    })
    assert resp.status_code == 200


def test_chat_endpoint_invalid_message(client):
    resp = client.post("/chat", json={"message": ""})
    assert resp.status_code == 422


def test_chat_endpoint_invalid_template(client):
    resp = client.post("/chat", json={"message": "alert", "template_name": "unknown"})
    assert resp.status_code == 422


def test_chat_endpoint_invalid_source(client):
    resp = client.post("/chat", json={"message": "alert", "source": "invalid_source"})
    assert resp.status_code == 422


def test_chat_endpoint_k_out_of_range(client):
    resp = client.post("/chat", json={"message": "alert", "k": 0})
    assert resp.status_code == 422
    resp = client.post("/chat", json={"message": "alert", "k": 21})
    assert resp.status_code == 422


def test_history_endpoint(client):
    resp = client.get("/chat/test-session/history")
    assert resp.status_code == 200
    body = resp.json()
    assert body["session_id"] == "test-session"
    assert body["messages"][0]["role"] == "human"
    assert body["messages"][1]["role"] == "ai"


def test_clear_chat_endpoint(client):
    resp = client.delete("/chat/test-session")
    assert resp.status_code == 200
    assert resp.json() == {"cleared": "test-session"}
