# RAG Pipeline — LangChain Migration

## Tổng quan

Hệ thống RAG được migrate từ pipeline thủ công (SentenceTransformer + QdrantClient + OllamaLLM) sang LangChain. Mục tiêu: bổ sung khả năng **chatbot multi-turn** cho phép analyst hỏi follow-up về cùng một IDS alert, trong khi vẫn giữ nguyên endpoint `/analyze` một chiều.

---

## Các thay đổi theo file

### `src/rag/embeddings.py` — Thay thế hoàn toàn

**Trước:** Class `QueryEmbedder` dùng `SentenceTransformer` trực tiếp, không có caching — model load lại mỗi lần khởi tạo.

**Sau:** Hàm `get_embeddings()` trả về `HuggingFaceEmbeddings` (LangChain), bọc bằng `@lru_cache(maxsize=1)` — model chỉ load một lần duy nhất trong suốt vòng đời process.

```
QueryEmbedder (SentenceTransformer)  →  get_embeddings() (HuggingFaceEmbeddings + lru_cache)
```

Tự động chọn `cuda` nếu có GPU, fallback về `cpu`.

---

### `src/rag/lc_vectorstore.py` — Tạo mới

Thay thế `retriever.py`. Wrap `QdrantVectorStore` của LangChain thay vì dùng `QdrantClient` trực tiếp.

| Hàm | Mô tả |
|---|---|
| `get_vectorstore()` | Khởi tạo `QdrantVectorStore` kết nối Qdrant qua `build_client()` |
| `build_retriever(source, k)` | Trả về `VectorStoreRetriever` với filter theo `source` nếu được chỉ định |

Filter nguồn dữ liệu (`cve`, `mitre`, `sigma`) dùng `qdrant_client.models.Filter` truyền vào `search_kwargs`.

---

### `src/rag/lc_prompt.py` — Tạo mới

Thay thế `prompt_builder.py`. Dùng `ChatPromptTemplate` thay vì f-string thủ công.

**Các thành phần:**

| Thành phần | Mục đích |
|---|---|
| `DOCUMENT_PROMPT` | Format mỗi retrieved document: `source={source} doc_id={doc_id}\n{text}` |
| `DOCUMENT_SEPARATOR` | Ký tự phân cách giữa các document (`\n\n`) |
| `contextualize_prompt` | Rewrite follow-up question thành standalone question dựa trên chat history |
| `basic_prompt` | Prompt phân tích thẳng, yêu cầu output JSON trực tiếp |
| `cot_prompt` | Chain-of-Thought: LLM lý luận từng bước trước khi output JSON trong `<answer>` tags |
| `few_shot_prompt` | Kèm ví dụ mẫu (Nmap scan alert) để hướng dẫn format output |
| `get_qa_prompt(template_name)` | Selector trả về prompt theo tên (`basic` / `cot` / `few_shot`) |

Tất cả QA prompt đều có `MessagesPlaceholder("chat_history")` để hỗ trợ multi-turn.

Cấu trúc output JSON thống nhất với `llm_ollama.py`:
```json
{
  "threat_description": "...",
  "severity": "Low | Medium | High | Unknown",
  "rationale": "...",
  "mitigation_steps": ["...", "..."]
}
```

---

### `src/rag/lc_chain.py` — Tạo mới

Xây dựng LangChain RAG chain hoàn chỉnh với conversation memory.

**Luồng xây dựng chain:**

```
build_retriever(source, k)
        │
        ▼
create_history_aware_retriever(llm, retriever, contextualize_prompt)
        │  rewrite query dựa trên chat_history
        ▼
create_stuff_documents_chain(llm, qa_prompt, document_prompt, document_separator)
        │  nhét context vào prompt → gọi LLM
        ▼
create_retrieval_chain(history_aware_retriever, qa_chain)
        │
        ▼
RunnableWithMessageHistory(chain, get_session_history, ...)
        │  quản lý memory per session_id
        ▼
  chain sẵn sàng invoke
```

**Memory management:**

- `_session_store`: dict lưu `InMemoryChatMessageHistory` theo `session_id`
- `get_session_history(session_id)`: tạo history mới nếu chưa tồn tại
- `clear_session(session_id)`: xóa history của một session

> **Giới hạn:** Memory lưu in-process, mất khi restart server.

---

### `src/rag/lc_service.py` — Tạo mới

Tầng service cho chatbot. Xử lý JSON parsing từ LLM output với logic fallback giống `OllamaLLM` cũ.

**JSON extraction (theo thứ tự ưu tiên):**
1. Text bắt đầu `{` kết thúc `}` → parse trực tiếp
2. Có `<answer>{...}</answer>` → dùng regex extract
3. Có code fence ` ```json{...}``` ` → extract từ fence
4. Regex tìm `{...}` đầu tiên trong text
5. Fallback: trả về raw text với `severity: Unknown`

**`ChatService` methods:**

| Method | Mô tả |
|---|---|
| `chat(session_id, message, source, k, template_name)` | Invoke chain, parse output, trả về dict chuẩn |
| `get_history(session_id)` | Trả về list `{role, content}` của session |
| `clear(session_id)` | Xóa history của session |

Output của `chat()` là superset của output `RagService.analyze()`:
```python
{
    "threat_description": str,
    "severity": str,
    "rationale": str,
    "mitigation_steps": list[str],
    "session_id": str,           # thêm mới
    "retrieved_context_ids": list[str],
}
```

---

### `src/rag/service.py` — Viết lại

`RagService` được đơn giản hóa thành thin wrapper gọi `ChatService` với session tạm:

```python
class RagService:
    def analyze(self, alert_text, k, source) -> dict:
        session_id = str(uuid.uuid4())   # session dùng một lần
        result = _chat.chat(session_id, alert_text, source, k)
        _chat.clear(session_id)          # dọn dẹp ngay sau khi xong
        return result
```

Giữ nguyên interface → `api/main.py` endpoint `/analyze` không cần sửa.

---

### `src/api/main.py` — Thêm 3 endpoint mới

| Method | Endpoint | Mô tả |
|---|---|---|
| `POST` | `/chat` | Gửi message, nhận phân tích có history |
| `GET` | `/chat/{session_id}/history` | Xem lịch sử hội thoại của session |
| `DELETE` | `/chat/{session_id}` | Xóa session |

`/analyze` giữ nguyên, không thay đổi.

---

## Sơ đồ dependency sau migration

```
api/main.py
    ├── RagService (service.py)
    │       └── ChatService (lc_service.py)
    │               └── build_chat_chain (lc_chain.py)
    │                       ├── build_retriever (lc_vectorstore.py)
    │                       │       ├── get_vectorstore → QdrantVectorStore
    │                       │       │       ├── build_client (qdrant_store.py)
    │                       │       │       └── get_embeddings (embeddings.py)
    │                       │       └── Filter (qdrant_client)
    │                       ├── get_qa_prompt (lc_prompt.py)
    │                       └── ChatOllama (langchain_ollama)
    │
    └── ChatService (lc_service.py)   ← dùng trực tiếp cho /chat
```

---

## Files đã xóa

| File | Thay bằng |
|---|---|
| `retriever.py` | `lc_vectorstore.py` |
| `llm_ollama.py` | `ChatOllama` trong `lc_chain.py` |
| `prompt_builder.py` | `lc_prompt.py` |

---

## Dependencies mới

```
langchain
langchain-core
langchain-community
langchain-huggingface
langchain-qdrant
langchain-ollama
```

---

## Các vấn đề cần sửa

| File | Dòng | Vấn đề |
|---|---|---|
| `lc_chain.py` | 1–4 | Import từ `langchain_classic` — package không tồn tại. Đổi thành `langchain` |
| `lc_prompt.py` | 17 | `_OUTPUT_SCHEMA` có `.add()` thừa ở cuối dòng đầu — syntax error |
| `lc_prompt.py` | 20 | Typo: `"Semeantic"` → `"Semantic"`, `"waht"` → `"what"` |
| `lc_prompt.py` | 80 | Tag đóng sai: `<answer>` → `</answer>` |
| `schemas.py` | — | Thiếu `ChatRequest`, `ChatResponse`, `ChatMessage`, `ChatHistoryResponse` — `api/main.py` đang import nhưng chưa có |
