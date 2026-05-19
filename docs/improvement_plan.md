# RAG System Improvement Plan

Dựa trên phân tích output tại `tests/rag_output_results.json` và review code pipeline.

---

## Tổng quan vấn đề

| Layer | File | Vấn đề |
|-------|------|---------|
| Retrieval | `src/rag/lc_vectorstore.py:27` | `search_type="similarity"` không có diversity → 5 CVE pulled về gần giống nhau |
| Prompt | `src/rag/lc_prompt.py:37-56` | Không có baseline rules → model không biết "HTTPS 10:1 là bình thường" |
| Prompt | `src/rag/lc_prompt.py:44` | Không có constraint kiểm tra flag trước khi kết luận attack type → hallucination |
| Alert text | `src/data_process/alert_builder.py:129-138` | `Init Bwd Win = -1` không được flag ra alert text |
| LLM | `src/rag/lc_chain.py:29` | `qwen2.5:3b` nhỏ → hallucination cao |

---

## 1. Prompt Engineering

**File:** `src/rag/lc_prompt.py`
**Effort:** Thấp | **Impact:** Cao

### Vấn đề
- Model kết luận "SYN flood" khi `SYN Flag Cnt = 0` (Alert 5) vì không có grounding constraint.
- HTTPS flows với server:client ratio cao bị rate Medium thay vì Low/Info.

### Việc cần làm

**a. Thêm Baseline Rules vào system prompt**

```python
_BASELINE_RULES = """\
Baseline knowledge (do NOT escalate these alone):
- Port 443/HTTPS: server-to-client byte ratio up to 20:1 is NORMAL for content delivery. Do not rate as Medium solely based on ratio.
- Short flows (<1ms, <10 packets, 0 bytes): likely TCP handshake fragments or keepalives. Rate as Low unless other indicators present.
- Ephemeral ports (>49152): dynamic client-side ports. Never recommend blocking them.
"""
```

**b. Thêm Grounding Constraint**

```python
_GROUNDING_RULES = """\
Before naming any specific attack, verify:
- SYN flood → SYN Flag Cnt must be > 0 and ACK Flag Cnt near 0
- DoS/DDoS → requires abnormally high packet rate or duration
- Port scan → requires many destination ports (not visible in single-flow alert)
If the required conditions are NOT present in the alert, do NOT name that attack.
"""
```

**c. Tích hợp vào `_BASIC_SYSTEM` và `_COT_SYSTEM`**

Chèn `_BASELINE_RULES` và `_GROUNDING_RULES` vào trước phần `Rules:` hiện tại.

---

## 2. Retrieval Diversity

**File:** `src/rag/lc_vectorstore.py`
**Effort:** Thấp (1 dòng) | **Impact:** Cao

### Vấn đề
Hiện tại `search_type="similarity"` → kéo về 5 document gần nhau nhất trong vector space → thường là cùng 1 CVE chia nhiều chunk.

Ví dụ: `CVE-2021-47099_c3`, `CVE-2021-47139_c4`, `CVE-2024-26781_c2` xuất hiện lặp lại ở alert 1, 3, 5.

### Việc cần làm

**a. Đổi sang MMR (Maximal Marginal Relevance)**

```python
# Trước
return get_vectorstore().as_retriever(
    search_type="similarity",
    search_kwargs=search_kwargs,
)

# Sau
search_kwargs["fetch_k"] = k * 4   # fetch rộng hơn để MMR chọn
search_kwargs["lambda_mult"] = 0.6  # 0=max diversity, 1=max relevance
return get_vectorstore().as_retriever(
    search_type="mmr",
    search_kwargs=search_kwargs,
)
```

LangChain hỗ trợ MMR sẵn với `QdrantVectorStore`, không cần thêm dependency.

**b. (Tùy chọn) Source balancing**

Nếu muốn đảm bảo mỗi lần retrieve có đủ cả CVE + MITRE + Sigma, cần custom retriever chạy 3 sub-query với `source` filter rồi merge. Phức tạp hơn, làm sau khi MMR đã cải thiện.

---

## 3. Sigma Chunk Enrichment (re-ingest)

**File:** `src/data_process/chunk_data.py`
**Effort:** Thấp (1 dòng) + re-ingest | **Impact:** Cao

### Vấn đề

`chunk_data.py` dòng 30 chỉ dùng 4 fields cho sigma:

```python
"text_cols": ["title", "description", "level", "tags"]
```

`sigma_cleaned.parquet` đã có sẵn `logsource` và `falsepositives` (parse từ YAML gốc) nhưng bị bỏ qua khi chunk. Kết quả: embedding của mỗi sigma chunk quá ngắn và generic — `sigma_2514_c0` ("Suspicious Use of /dev/tcp") xuất hiện trong 30/36 output vì vector của nó gần với mọi network flow query.

Quan trọng nhất là `logsource` — nó phân biệt rule áp dụng cho `network`, `windows`, `linux`, hay `cloud`. `sigma_2514_c0` có `logsource: {product: linux, category: process_creation}`, tức là **không liên quan đến network flow**, nhưng vì không có logsource trong embedding nên nó vẫn được retrieve.

### Việc cần làm

**a. Thêm fields vào `text_cols` của sigma**

```python
# Trước
{
    "name":       "sigma",
    "text_cols":  ["title", "description", "level", "tags"],
    ...
}

# Sau
{
    "name":       "sigma",
    "text_cols":  ["title", "description", "level", "tags", "logsource", "falsepositives"],
    ...
}
```

**b. Re-run pipeline**

```bash
python -m src.data_process.chunk_data
python -m src.data_process.embed_chunks --source sigma --recreate
```

---

## 4. Score Threshold ở Retriever (safety net)

**File:** `src/rag/lc_vectorstore.py`
**Effort:** Thấp | **Impact:** Trung bình

### Vấn đề

`BalancedRetriever` lấy đúng 1 sigma chunk mỗi query mà không kiểm tra similarity score. Ngay cả khi chunk gần nhất chỉ có cosine similarity thấp (không thực sự liên quan), nó vẫn được trả về.

### Việc cần làm

Thêm `score_threshold` vào `search_kwargs` của từng source trong `BalancedRetriever`:

```python
results = self.vectorstore.max_marginal_relevance_search(
    query,
    k=k,
    fetch_k=k * self.fetch_k_mult,
    lambda_mult=self.lambda_mult,
    score_threshold=0.45,          # thêm dòng này
    filter=Filter(must=[...]),
)
```

Nếu không có sigma chunk nào vượt threshold → trả về 0 sigma chunk thay vì chunk không liên quan.

**Lưu ý:** Nên làm **sau** Option 1 (Sigma Enrichment). Option 1 fix gốc rễ; Option 4 là safety net phòng trường hợp vẫn có chunk generic lọt qua.

---

## 5. Alert Builder Enhancement

**File:** `src/data_process/alert_builder.py`
**Effort:** Thấp | **Impact:** Trung bình

### Vấn đề
- `Init Bwd Win Byts = -1` (server không respond) bị bỏ qua hoàn toàn vì điều kiện `if init_bwd_win > 0` (dòng 137).
- Không có computed context giúp model hiểu "điều kiện cho attack X có thỏa mãn không".

### Việc cần làm

**a. Fix `Init Bwd Win = -1`**

```python
# Trước (dòng 137)
if init_bwd_win > 0:
    win_parts.append(f"server init window {init_bwd_win} B")

# Sau
if init_bwd_win == -1:
    win_parts.append("server init window: none (server did not respond)")
elif init_bwd_win > 0:
    win_parts.append(f"server init window {init_bwd_win} B")
```

**b. Thêm computed anomaly hints**

Thêm một block cuối `build_alert_text()` để ghi rõ điều kiện:

```python
# Computed hints để giúp LLM reasoning
hints = []
syn_cnt = get_int(row, "SYN Flag Cnt")
ack_cnt = get_int(row, "ACK Flag Cnt")
bwd_bytes = get_float(row, "TotLen Bwd Pkts")
fwd_bytes = get_float(row, "TotLen Fwd Pkts")

if syn_cnt == 0:
    hints.append("SYN flood: NOT possible (SYN count = 0)")
if fwd_bytes == 0 and bwd_bytes == 0:
    hints.append("Zero-byte flow: no data transferred")

if hints:
    parts.append(f"Analysis hints: {'; '.join(hints)}.")
```

---

## 6. LLM Upgrade

**File:** `src/rag/lc_chain.py`
**Effort:** Cao (phụ thuộc phần cứng) | **Impact:** Cao nếu đủ GPU

### Vấn đề
`qwen2.5:3b` là model nhỏ → reasoning yếu → hallucination cao với alert phức tạp.

### Việc cần làm

Đổi model trong `build_chat_chain()`:

```python
# Trước
model=settings.ollama_model or "mistral:7b-instruct-q4_K_M"

# Sau (chọn theo VRAM)
# 8GB VRAM  → "qwen2.5:7b-instruct"
# 16GB VRAM → "qwen2.5:14b-instruct"
# Hoặc đổi sang "mistral:7b-instruct" nếu muốn thử
```

Nên làm **sau** khi 3 bước trên đã hoàn tất, để phân biệt được improvement đến từ prompt/retrieval hay model.

---

## Thứ tự thực hiện

```
1. Prompt Engineering       ← làm trước, free, impact ngay lập tức
2. Retrieval Diversity      ← 1 dòng thay đổi, loại bỏ duplicate CVEs
3. Sigma Chunk Enrichment   ← fix gốc rễ sigma_2514_c0 over-retrieval, cần re-ingest
4. Score Threshold          ← safety net sau khi sigma enriched, không cần re-ingest
5. Alert Builder            ← thêm context cụ thể hơn cho LLM
6. LLM Upgrade              ← làm sau cùng, cần đánh giá phần cứng
```

---

## Cách đánh giá sau khi cải thiện

Chạy lại `tests/run_rag_on_network_alerts.py` và so sánh:

| Metric | Hiện tại | Mục tiêu |
|--------|----------|-----------|
| Alert 5 — SYN flood khi SYN=0 | Hallucinate | Không xảy ra |
| HTTPS benign flows — severity | Medium | Low/Info |
| Retrieved CVE diversity | 3 CVE lặp lại | ≥3 source khác nhau |
| Ephemeral port mitigation | "Block port 49684" | Không xuất hiện |
