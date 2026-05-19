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

## Evaluation Architecture (`tests/evaluate_rag.py`)

Đánh giá chất lượng RAG pipeline trên `data/raw/cse-cic-ids2018/combined_shorten.csv` (chỉ gồm attack records, đã loại Benign).

### Luồng dữ liệu

```
combined_shorten.csv
        │
        ▼
build_alert_text(row, baseline)
        │ alert_text
        ▼
RagService.analyze()
        │ {answer, context_ids, context_texts}  ← context_texts cần thêm vào lc_service.py
        ▼
┌─────────────────────────────────────────┐
│            evaluate_rag.py              │
│                                         │
│  Layer 1 — RAGAs (Gemini 1.5 Flash)    │
│    faithfulness, answer_relevancy       │
│                                         │
│  Layer 2 — Rule-based (no LLM judge)   │
│    severity_correct                     │
│    attack_type_hit                      │
│    hallucination_flag                   │
│    context_source_diversity             │
│    sigma_2514_hit                       │
└─────────────────────────────────────────┘
        │
        ▼
tests/evaluation_report.csv
```

### Layer 1 — RAGAs metrics

Dùng **Gemini Flash** làm judge LLM (free tier đủ cho 36 records).

| Metric | Cần ground truth? | Đo gì |
|---|---|---|
| `faithfulness` | Không | Answer có được support bởi retrieved context không, hay LLM tự bịa? |
| `answer_relevancy` | Không | Answer có trả lời đúng câu hỏi (alert) không? |

Input cho RAGAs mỗi record:
```
user_input         = alert_text
response           = threat_description + "\n" + rationale
retrieved_contexts = [page_content của mỗi chunk retrieved]
```

### Layer 2 — Rule-based metrics

**`severity_verdict`** — thay vì binary đúng/sai, dùng 3 giá trị dựa trên ordering `Low < Medium < High`:

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

Aggregate thành 2 con số báo cáo: **underestimation rate** (quan trọng nhất) và **overestimation rate**.

**`attack_type_hit`** — kiểm tra `threat_description + rationale` có chứa keyword đúng của label không (case-insensitive). Ví dụ: `SQL Injection` → keywords `["sql", "injection", "database"]`.

**`hallucination_flag`** — phát hiện mâu thuẫn giữa alert text và output:

| Điều kiện trong alert_text | Output vi phạm nếu chứa |
|---|---|
| `"SYN flood: NOT possible"` | `"syn flood"` |
| `"Zero-byte flow"` | `"exfiltrat"` |
| `"server did not respond"` | `"established connection"` |

**`context_source_diversity`** — từ `retrieved_context_ids`, check có đủ ≥1 CVE + ≥1 MITRE + ≥1 Sigma không.

**`sigma_2514_hit`** — boolean, theo dõi tỷ lệ `sigma_2514_c0` xuất hiện trước/sau khi fix sigma enrichment.

### Output schema (`evaluation_report.csv`)

Mỗi record = 1 row:

```
label, severity_output, severity_verdict, attack_type_hit, hallucination_flag,
sigma_2514_hit, context_diversity, faithfulness, answer_relevancy
```

Cuối file: aggregate summary per label + overall averages, bao gồm underestimation rate và overestimation rate.