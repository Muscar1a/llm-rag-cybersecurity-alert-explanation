## Rag Architecture 
```
  User message (turn N)
          │
          ▼
  [History-Aware Retriever]
    ├── chat history (turn 1..N-1)
    └── LLM rewrite query thành standalone question
          │
          ▼ reformulated query
  [QdrantVectorStore.as_retriever(filter=source)]
          │
          ▼ top-K chunks
  [ChatPromptTemplate]
    ├── system: "You are a cybersecurity analyst..."
    ├── chat_history: MessagesPlaceholder
    ├── context: {chunks}
    └── human: {input}
          │
          ▼
  [ChatOllama]
          │
          ▼
  Response → lưu vào ChatMessageHistoryhax
```

## Baseline Component (`src/monitoring/baseline.py`)

Cung cấp statistical grounding cho LLM — thay vì LLM đoán "giá trị này có bất thường không?", baseline annotation trả lời câu đó bằng số liệu thực từ CICIDS-2018 Benign traffic.

### Grouping strategy

```
(Protocol, Dst Port)  →  đủ >= 30 samples? dùng
                      →  không đủ? fallback lên (Protocol)
                      →  vẫn không đủ? annotate() trả None
```

### Robust statistics (Rousseeuw & Hubert, 2018)

Dùng **Median + MAD** thay vì Mean + Std vì network traffic có heavy-tailed distribution — mean và std bị kéo lệch bởi burst hợp lệ.

```
MAD = median( |xi - median(x)| )

modified z-score = 0.6745 × (x - median) / MAD
```

Hệ số `0.6745` để MAD consistent với std khi distribution là normal.

Kết hợp với **p95, p99** làm empirical threshold (percentile không bị ảnh hưởng bởi outlier):

```
|z| <= 2.5  và  value < p95  →  None        (bình thường, không ghi vào alert)
value > p99                  →  ">p99, z=X" (cực kỳ bất thường)
value > p95                  →  ">p95, z=X" (đáng chú ý)
z < -2.5                     →  "unusually low, z=X"
```

### Cách tính baseline (`build_baseline.py`)

Để tránh load toàn bộ 9 file CSV vào RAM cùng lúc (~30GB), script xử lý từng file độc lập rồi gộp kết quả:

```
File 1 → filter Benign → tính stats → partial_baseline_1 → giải phóng RAM
File 2 → filter Benign → tính stats → partial_baseline_2 → giải phóng RAM
...
File 9 → filter Benign → tính stats → partial_baseline_9 → giải phóng RAM
                                              ↓
                                  merge (weighted average theo n)
                                              ↓
                                   baselines/cicids2018.json
```

Weighted average vì mỗi file có số Benign rows khác nhau — file nhiều sample hơn đóng góp nhiều hơn vào baseline cuối.

**Lưu ý:** weighted average của percentile (p95, p99) là xấp xỉ, không phải giá trị chính xác của combined dataset. Chấp nhận được cho mục đích annotation.

### Features được giữ lại / loại bỏ

**Loại bỏ khỏi baseline (không tính stats):**

| Lý do | Columns |
|---|---|
| Grouping key | `Dst Port`, `Protocol` |
| Flow identifier | `Src Port`, `Src IP`, `Dst IP`, `Flow ID` |
| Label | `Label` |
| Timestamp | `Timestamp` |
| Luôn bằng 0 với Benign (`p99 == 0`) | flag bytes, backward metrics của one-directional flow, v.v. |
| Chứa `inf` do `Flow Duration = 0` | `Flow Byts/s`, `Flow Pkts/s` của một số port — lọc bằng `np.isfinite()` trước khi tính |

**Giữ lại:**
- Toàn bộ numeric columns còn lại sau khi loại trừ trên
- Chỉ giữ entry nếu có `>= 30 Benign samples` và `p99 > 0`

### Tích hợp vào alert_builder

`build_alert_text(row, baseline=None)` — khi `baseline` được truyền vào, annotation được thêm vào phần `Analysis hints` của alert text. Khi `baseline=None` (default), hàm hoạt động như cũ.

---

## Evaluation Architecture (`tests/evaluate_ragas.py`)

Đánh giá chất lượng RAG pipeline trên `data/raw/cse-cic-ids2018/combined_shorten.csv` (chỉ gồm attack records, đã loại Benign).

### Vai trò các model

| Model | Vai trò | Lý do |
|---|---|---|
| `qwen2.5:3b` (Ollama local) | RAG output generation | System under test |
| Gemini Pro (`gemini-pro-latest`) | Ground truth generation | SOTA model sinh reference answer |
| GPT-4.1 (OpenAI) | RAGAs judge | Khác family với Gemini → tránh intra-family bias |

**Tại sao tách ground truth gen và judge:**
- Nếu Gemini Pro sinh GT và Gemini Flash judge → Flash chấm cao những gì giống style của Pro (same-family bias)
- Dùng GPT-4.1 làm judge → cross-family, đánh giá dựa trên nội dung thực chất

### Luồng dữ liệu

```
combined_shorten.csv
        │
        ▼
build_alert_text(row, baseline)
        │ alert_text
        ├─────────────────────────────────────────┐
        ▼                                         ▼
RagService.analyze()                   Gemini Pro
(qwen2.5:3b via Ollama)                generate_ground_truth(alert_text)
        │                                         │
        │ actual_output                            │ reference
        │ retrieved_contexts                       │
        └──────────────────┬──────────────────────┘
                           ▼
        ┌──────────────────────────────────────────┐
        │           evaluate_ragas.py              │
        │                                          │
        │  Layer 1 — RAGAs (GPT-4.1 as judge)     │
        │    answer_correctness  ← cần reference   │
        │    faithfulness        ← không cần GT    │
        │    answer_relevancy    ← không cần GT    │
        │                                          │
        │  Layer 2 — Rule-based (no LLM judge)    │
        │    severity_verdict                      │
        │    attack_type_hit                       │
        │    hallucination_flag                    │
        │    context_source_diversity              │
        │    sigma_2514_hit                        │
        └──────────────────────────────────────────┘
                           │
                           ▼
              evaluation_report.csv
              evaluation_results.json
```

### Layer 1 — RAGAs metrics

Input cho RAGAs mỗi record:
```
user_input         = alert_text
response           = threat_description + "\n" + rationale
retrieved_contexts = [page_content của mỗi chunk retrieved]
reference          = ground truth do Gemini Pro sinh ra
```

| Metric | Cần GT? | Đo gì |
|---|---|---|
| `answer_correctness` | Có | Output của local LLM có đúng với reference (Gemini Pro) không? |
| `faithfulness` | Không | Output có hallucinate so với retrieved context không? |
| `answer_relevancy` | Không | Output có trả lời đúng câu hỏi (alert) không? |

### Ground truth generation

Gemini Pro nhận `alert_text` và sinh ra một reference answer theo cùng schema với local LLM:

```
threat_description, severity, rationale, mitigation_steps
```

Reference này không phải "đáp án tuyệt đối" mà là **upper-bound anchor** — đánh giá local LLM lệch bao nhiêu so với một SOTA model khi cùng nhìn vào cùng alert.

### Layer 2 — Rule-based metrics

**`severity_verdict`** — 3 giá trị dựa trên ordering `Low < Medium < High`:

| Verdict | Ý nghĩa | Rủi ro |
|---|---|---|
| `correct` | Output nằm đúng expected minimum | — |
| `underestimated` | Output thấp hơn expected minimum | **Nguy hiểm** — analyst có thể bỏ qua |
| `overestimated` | Output cao hơn expected minimum | Chấp nhận được — thà bắt nhầm hơn bỏ sót |

Expected minimum severity per attack type:

| Expected minimum | Labels |
|---|---|
| `High` | DDOS attack-HOIC, DoS attacks-GoldenEye, DoS attacks-Hulk, SQL Injection, Infilteration |
| `Medium` | DoS attacks-Slowloris, DoS attacks-SlowHTTPTest, FTP-BruteForce, SSH-Bruteforce, Brute Force -Web, Brute Force -XSS, Bot |

**`attack_type_hit`** — `threat_description + rationale` có chứa keyword đúng của label không (case-insensitive).

**`hallucination_flag`** — mâu thuẫn giữa alert text và output:

| Điều kiện trong alert_text | Output vi phạm nếu chứa |
|---|---|
| `"SYN flood: NOT possible"` | `"syn flood"` |
| `"Zero-byte flow"` | `"exfiltrat"` |
| `"server did not respond"` | `"established connection"` |

**`context_source_diversity`** — từ `retrieved_context_ids`, check có ≥1 CVE + ≥1 MITRE + ≥1 Sigma không.

**`sigma_2514_hit`** — boolean, theo dõi tỷ lệ `sigma_2514_c0` xuất hiện trước/sau khi fix sigma enrichment.

### Output schema

`evaluation_report.csv` — mỗi record = 1 row:
```
label, severity_output, severity_verdict, attack_type_hit, hallucination_flag,
sigma_2514_hit, context_diversity, answer_correctness, faithfulness, answer_relevancy
```

`evaluation_results.json` — full detail per record:
```json
{
  "label": "...",
  "raw_packet": { ... },
  "input": "alert_text",
  "reference": "ground truth từ Gemini Pro",
  "output": { "threat_description", "severity", "rationale", "mitigation_steps",
              "retrieved_context_ids", "retrieved_contexts_text" },
  "evaluation": { "severity_verdict", "attack_type_hit", "hallucination_flag",
                  "sigma_2514_hit", "context_diversity",
                  "answer_correctness", "faithfulness", "answer_relevancy" }
}
```