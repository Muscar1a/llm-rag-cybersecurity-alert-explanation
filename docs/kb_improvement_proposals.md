# Knowledge Base Improvement — Analysis & Proposals

## Current KB state

| Source | File | Chunks |
|---|---|---|
| MITRE ATT&CK | `data/processed/MITRE/chunks.parquet` | Techniques + sub-techniques (incl. `detection` field) |
| Sigma (network) | `data/processed/sigma/chunks.parquet` | Network-category rules only |
| ET rules | `data/processed/emerging_threats/chunks.parquet` | Filtered by keyword list |
| ~~Behavioral rules~~ | ~~removed~~ | All Botnet/C2 — mismatched with UWF, deleted |

Pipeline: `clean_data.py` → `chunk_data.py` → `embed_chunks.py` → Qdrant `cyber_chunks`

---

## What the code reveals

### zeek_alert_builder.py
`build_alert_text()` already encodes into the alert string:
- conn_state code + short description + behavioral meaning (from `CONN_STATE_INFO`)
- Byte ratio with direction label (server-dominant / client-dominant)
- TCP history decoded to packet sequence
- Detected services (translated from Zeek service names)
- Behavioral hints (S0 → scan, OTH+ACK → ACK scan, RSTO+data → C2/exfil, SMB+auth → lateral movement, port 4848 → GlassFish brute-force hint, etc.)

**Implication:** Adding a Zeek conn_state knowledge document to the KB is redundant — the alert text already contains that information.

**Critical constraint:** Only `alert_text` is passed to the RAG service at inference time. No label, no metadata.

### chunk_data.py
MITRE chunks use `text_cols = ["name", "description", "tactics", "detection"]` — the `detection` field IS included. This is not the bottleneck.

### Root cause of low faithfulness (5.8% basic, 0.942 hallucination)
**Vocabulary mismatch** between query and KB:
- Alert text uses Zeek/TCP vocabulary: *"REJ", "S0", "SYN → RST", "zero bytes", "server-dominant byte ratio"*
- MITRE entries use abstract ATT&CK vocabulary: *"adversaries may execute active reconnaissance", "gather information during targeting"*

The embedding model (`bge-base-en-v1.5`) must bridge "SYN+RST+zero_bytes" → "active scanning" semantically. When it fails, retrieved chunks are irrelevant → LLM ignores context → hallucinates.

COT template achieves 0.75 faithfulness with the same KB, confirming the problem is partly prompt-side (LLM not forced to use context) — already fixed. The remaining gap is retrieval-side.

---

## Benchmark results (hiện tại)

> **Lưu ý:** COT checkpoint chỉ có 1 sample từ tập CIC-IDS2018 cũ (label "Bot"), không phải UWF. Basic và few_shot là UWF-ZeekData24.

### basic — 12 samples (UWF, đã hoàn thành)

| Metric | Value |
|---|---|
| faithfulness | **0.058** |
| hallucination_rate | **0.942** |
| context_precision | 0.289 |
| context_recall | **0.050** |
| answer_relevancy | 0.736 |
| severity_correct | 1 / 12 |
| p50 latency | 4.9 s |

Per-tactic:

| Tactic | n | faithfulness | ctx_precision | ctx_recall | severity_correct |
|---|---|---|---|---|---|
| Credential_Access | 8 | 0.000 | 0.250 | 0.000 | 0/8 |
| Defense_Evasion | 1 | 0.000 | 0.639 | 0.600 | 0/1 |
| Exfiltration | 1 | 0.556 | 0.500 | 0.000 | 0/1 |
| Initial_Access | 1 | 0.000 | 0.000 | 0.000 | 0/1 |
| Reconnaissance | 1 | 0.143 | 0.333 | 0.000 | 1/1 |

### cot — 1 sample (CIC-IDS2018 "Bot", không đại diện)

| faithfulness | ctx_precision | ctx_recall | severity_correct |
|---|---|---|---|
| 0.750 | 1.000 | 0.600 | 1/1 |

### few_shot — 30 samples (UWF, phase=eval — chạy dở)

| Tactic | n | faithfulness | ctx_precision | ctx_recall | severity_correct |
|---|---|---|---|---|---|
| Credential_Access | 26 | 0.000 | 0.000 | 0.000 | 0/26 |
| Defense_Evasion | 1 | 0.167 | 0.639 | 0.400 | 0/1 |
| Exfiltration | 1 | 0.286 | 0.500 | 0.000 | 0/1 |
| Initial_Access | 1 | 0.167 | 0.000 | 0.000 | 0/1 |
| Reconnaissance | 1 | 0.000 | 0.333 | 0.250 | 1/1 |

### Key observations

1. **Credential_Access chiếm đa số** (26/30 few_shot, 8/12 basic) và có faithfulness=0, ctx_recall=0 → kéo toàn bộ average xuống.
2. **context_recall cực thấp (0.05 overall)** → retrieved chunks không chứa thông tin cần thiết cho reference answer. Đây là retrieval failure, không phải generation failure.
3. **context_precision=0 cho Credential_Access trong few_shot** → không có chunk nào trong top-k là relevant với T1110/port 4848.
4. **Severity underestimated: 11/12 (basic)** → LLM không có đủ context để đánh giá mức độ nguy hiểm chính xác.
5. **answer_relevancy cao (0.736)** → LLM trả lời đúng format, đúng chủ đề, nhưng bịa nội dung thay vì dùng retrieved context.

---

## Re-framing từ code review

Đọc lại code retrieval làm thay đổi cách đặt vấn đề ở §"Root cause" phía trên. Bốn phát hiện chi phối toàn bộ phần Proposals:

1. **`build_alert_text()` đã dịch sẵn sang từ vựng ngữ nghĩa.** Alert text không phải Zeek codes thô — nó đã chứa tiếng Anh tự nhiên cùng tầng với MITRE: *"high-value target for credential brute-forcing"* (port 4848), *"command-and-control check-in... or exfiltration"*, *"consistent with port scanning"*, *"typical of lateral movement"*. → **Khoảng cách từ vựng hẹp hơn tài liệu khẳng định.** Nếu Credential_Access vẫn có ctx_recall=0 dù query đã ghi rõ "credential brute-forcing", nguyên nhân chính khả năng là **cơ chế retrieval lọc mất chunk đúng**, không phải embedding yếu.

2. **`score_threshold = 0.60` cứng tại MMR** (`lc_vectorstore.py:80-86`) — nghi phạm số 1. Với bge-base, cosine giữa alert và passage MITRE trừu tượng thường rơi 0.4–0.6. Sàn 0.60 có thể âm thầm vứt chunk đúng → candidate set rỗng/teo → ctx_recall ≈ 0. Comment ghi *"original was 0.82"*: đã hạ nhưng có thể chưa đủ.

3. **Reranker cross-encoder ĐÃ tồn tại** (`ms-marco-MiniLM-L-6-v2`). Hệ quả: rerank **không cứu được** chunk đã bị threshold lọc ở bước trước → phải sửa recall TRƯỚC, rerank mới có nghĩa.

4. **`max_per_source = 2` + MMR `lambda_mult=0.5`** ép đa dạng nguồn (sigma/et_rules) vào top-k ngay cả khi các chunk đúng nhất đều là MITRE → có thể đẩy chunk MITRE đúng ra khỏi top-k.

**Kết luận lại:** Phải đo và sửa cơ chế retrieval (free, zero-overfit) TRƯỚC khi đụng tới data/model — vì các con số 0.000 đồng loạt của Credential_Access trông giống lỗi cơ chế (threshold/cap lọc sạch) hơn lỗi ngữ nghĩa.

---

## Lan can chống overfit (áp cho mọi đề xuất bên dưới)

Tập eval cực nhỏ (12 basic / 30 few_shot) và **~85% là Credential_Access / T1110 / port-4848**. Mọi thay đổi nhắm nâng **con số tổng** đều có nguy cơ overfit vào đúng một technique — chính cái bẫy đã khiến behavioral rules bị xóa. Quy tắc:

1. Đánh giá theo **recall per-tactic**, không theo aggregate.
2. Ưu tiên thay đổi **technique-agnostic** (N0–N2, N4) hơn văn bản technique-specific (Hướng 2).
3. Giữ một held-out slice / thêm vài alert non-UWF làm sanity check.
4. Tinh chỉnh tham số dựa trên **recall@k diagnostic (N0)**, KHÔNG dựa trên faithfulness của 12 mẫu — nếu không, chính bước tuning lại thành overfit.

---

## Proposals

> Đánh số lại `N0–N4` để phản ánh thứ tự thực thi. Ba "Hướng" cũ (1/2/3) được giữ lại bên dưới với đánh giá overfit đã hiệu chỉnh.

### N0 — Retrieval diagnostic (làm TRƯỚC mọi thứ)

Trước khi sửa bất cứ gì, đo recall@k để biết đề xuất nào mới đáng làm. Với mỗi alert eval, **TẮT threshold** và kiểm tra: chunk technique đúng có nằm trong candidates ở k=5/20/50/100 không?

Tách bạch 3 khả năng:
- *Không có trong KB* → cần N3 (bổ sung nội dung).
- *Có nhưng bị threshold/cap lọc* → cần N1 (sửa cơ chế).
- *Có nhưng rank thấp* → cần N2 (hybrid) hoặc rerank.

**Changes required:** script đo recall@k trên tập eval, gold chunk = MITRE technique khớp `label_technique`.

**Overfit: 0** — chỉ là đo lường, không thay đổi hệ thống. Đây là bước tài liệu gốc bỏ qua (fix mù).

---

### N1 — Recalibrate `score_threshold` + tinh chỉnh MMR / source-cap

Khả năng thắng lớn nhất, gần như free. Bỏ sàn `0.60` cứng (đặt theo phân phối điểm thực đo của model), tăng `lambda_mult` (ưu tiên relevance hơn diversity), nới `max_per_source`.

**Changes required:** `params.yaml` (`retrieval.score_threshold`, `lambda_mult`) + `lc_vectorstore.py` (`max_per_source`).

**Overfit: 0 — nhưng có điều kiện:** việc tuning phải dựa trên **recall@k của N0 + held-out slice**, KHÔNG dựa trên faithfulness 12/30 mẫu. Nếu tune trực tiếp lên số cuối của tập nhỏ → biến thành overfit.

---

### N2 — Hybrid retrieval (sparse BM25 + dense, fusion bằng RRF)

Alert text chứa các "mỏ neo" từ vựng chính xác mà embedding dày đặc làm nhòe: *"GlassFish", "4848", "RST", "SMB", "brute-forcing"*. Sparse bắt khớp chính xác token, dense lo ngữ nghĩa, RRF hợp nhất hai bảng xếp hạng.

**Changes required:** thêm sparse index (Qdrant hỗ trợ sparse vectors / BM25) + bước RRF trong `lc_vectorstore.py`.

**Overfit: 0** — kiến trúc retrieval chuẩn, áp cho mọi query. **Mạnh hơn và rẻ hơn HyDE** (không thêm LLM call). Thay thế tốt cho Hướng 3.

---

### N3 — Dùng ATT&CK tags của Sigma làm cầu nối *cấu trúc* (bản thay thế an toàn cho Hướng 2)

Sigma rule đã có sẵn cả `attack.tXXXX` tags LẪN detection logic bằng từ vựng network (xác nhận trong `ingest_sigma.py:59,85` — tags được giữ trong payload). Thay vì **tự tay viết** "network indicators" cho MITRE (Hướng 2, rủi ro rò rỉ test), hãy enrich mỗi MITRE technique bằng điều kiện detection từ các Sigma rule **được cộng đồng gán tag chính thức** cho technique đó.

Đạt đúng mục tiêu Hướng 2 (bắc cầu từ vựng) nhưng văn bản đến từ **nguồn ngoài, không phải người đã thấy eval set** → overfit thấp hơn hẳn. Nếu N0 cho thấy coverage technique (vd T1110) trong category `network` quá mỏng → nạp thêm category Sigma khác.

**Changes required:** map MITRE technique ↔ Sigma rule qua `attack.*` tags, ghép detection text vào MITRE chunk; re-run pipeline.

**Overfit: Thấp** — nội dung do cộng đồng Sigma viết, không phải hand-craft theo UWF.

---

### N4 — Multi-query trên observables có sẵn (bản thay thế an toàn cho HyDE)

`build_alert_text` đã sinh sẵn các câu "behavioral hints" rời rạc. Phát từng hint làm sub-query rồi fuse bằng RRF — **không LLM call mới, không bịa label**.

**Overfit: 0** — ít khuếch đại sai hơn HyDE (HyDE có thể bịa sai technique → retrieve sai một cách tự tin).

---

## Ba "Hướng" gốc — đánh giá overfit đã hiệu chỉnh

### Hướng 1 — Embedding model upgrade (`bge-base` → `gte-base-en-v1.5` / `e5-base-v2`)

**Vẫn nên làm, nhưng là bổ trợ song song, không phải fix chính.** Cảnh báo: mỗi model có phân phối điểm khác nhau → đổi model mà giữ `score_threshold=0.60` cứng sẽ lại lọc sai. **Phải recalibrate threshold (N1) cho model mới.** Tác động vẫn bất định vì gte/e5 không được huấn luyện nặng trên Zeek logs.

**Overfit: 0.**

### Hướng 2 — Augment MITRE với network-observable vocabulary (viết tay)

**Đánh giá lại: overfit MEDIUM, không phải "Low" như bản gốc.** Ví dụ T1110 trong tài liệu (*"repeated SF connections, consistent orig_bytes, server-dominant byte ratio"*) gần như chép đúng chữ ký GlassFish brute-force của UWF. Người viết "mô tả tổng quát" mà đã biết tập test sẽ rò rỉ phân phối test vào KB; lập luận "áp cho mọi technique" rất yếu khi từ vựng được chọn phản chiếu chính các alert eval. **→ N3 thay thế hướng này với cùng mục tiêu nhưng nguồn ngoài.** Chỉ dùng Hướng 2 nếu N3 không phủ đủ.

### Hướng 3 — HyDE retrieval

Không overfit về kiến trúc, nhưng (a) thêm LLM call có thể bịa sai technique → retrieve sai tự tin, nguy hiểm khi LLM nền yếu; (b) dư thừa vì alert_text đã dịch nhẹ rồi. **→ N4 (multi-query) đạt mục tiêu tương tự, an toàn hơn, không tốn LLM call.** Để cuối, chỉ dùng khi N1+N2 không đủ.

---

## Comparison (đã cập nhật)

| # | Proposal | Overfit risk | Effort | Expected impact |
|---|---|---|---|---|
| N0 | Retrieval diagnostic (recall@k) | None | Script đo | Tiền đề — quyết định việc còn lại |
| N1 | Recalibrate threshold / MMR / cap | None* | Config | **High — khả năng vớt phần lớn recall, free** |
| N2 | Hybrid (sparse + dense, RRF) | None | Pipeline retrieval | High — bắt khớp lexical, rẻ hơn HyDE |
| N3 | Sigma ATT&CK-tag bridge | Low | Enrich + re-pipeline | High — bắc cầu từ vựng, nguồn ngoài |
| N4 | Multi-query trên observables | None | `lc_chain.py` | Medium — an toàn hơn HyDE |
| H1 | Embedding upgrade | None | Re-index | Medium — cần N1 kèm theo |
| H2 | MITRE augmentation (viết tay) | **Medium** | Knowledge writing | High nhưng rủi ro overfit → ưu tiên N3 |
| H3 | HyDE | None | `lc_chain.py` + LLM call | High nhưng tốn latency/cost → ưu tiên N4 |

\* N1 zero-overfit *chỉ khi* tuning dựa trên recall@k diagnostic, không dựa trên faithfulness của tập eval nhỏ.

## Kết quả N0 (đã thực thi + kiểm chứng 2 lần) — xem `n0_diagnostic_walkthrough.md`

> [!WARNING]
> `measure_recall_k.py` dùng `similarity_search` **toàn cục** (gộp mọi source) → cho `0.000`. Đó **không phải** thứ production chạy (`BalancedRetriever` query per-source). Số liệu đúng đo theo per-source:

- **Per-source MITRE Recall@5 = 0.210** (không phải 0.000). `Credential_Access (T1110) = 100%@5`; `Exfiltration (T1048)` lọt ở @50; **`T1078/T1190/T1595` ngoài top-50** → bge collapse thật cho 4/5 (T1499.001 DoS là #1 cho cả 5).
- **Chạy đúng `BalancedRetriever` (production) = 0/5.** Kể cả T1110 (chunk đúng rank 2, score 0.618 qua threshold) bị **MMR-diversity + `max_per_source=2` + reranker** vứt khỏi top-5.
- **N1 (tune threshold/MMR/cap) đã thử thực tế → vẫn 0/5.** Reranker cross-encoder tự nó dìm MITRE dưới et_rules. N1 vô dụng — đúng kết quả nhưng **lý do là reranker/cross-source, không phải threshold**.
- **Bug dữ liệu:** MITRE trùng 2x (1118 `mitre` + 1118 `mitre_attck` nested). Production chỉ đọc bản `mitre` → trùng chỉ bẩn phép đo toàn cục, **không trực tiếp hại production**.

**Điều chỉnh do N0 — HAI vấn đề độc lập:**
- **VĐ1 Credential_Access (~85% eval):** chunk retrieve ĐƯỢC nhưng kiến trúc pipeline vứt → fix bằng **sửa kiến trúc retriever** (đảm bảo slot MITRE theo dense, bỏ qua MMR/reranker cho slot đó), KHÔNG phải tune tham số.
- **VĐ2 (T1078/T1190/T1595):** chunk ngoài top-50 MITRE-only → **embedding hỏng thật** → cần hybrid/đổi embedding.
- N3/H2 vẫn KHÔNG đẩy lên: H2 overfit MEDIUM; N3 chỉ 60 sigma points.

---

## N5 — Signature profiles (Suricata alert → KB bridge)

### Bối cảnh

Kiến trúc đã chuyển từ Zeek-only sang **Suricata + Zeek telemetry**. Alert text giờ bắt đầu bằng `"Suricata alert: {signature} (severity {sev}, {category})."` — nhưng retriever không có cơ chế khai thác thông tin này. Signature name chứa intent keywords ("SCAN", "Exploitation", "Probe") mà port/conn_state không có → **cầu nối tự nhiên giữa wire observables và MITRE tactics**.

### Mục tiêu

Thêm `signature_profiles.jsonl` làm KB source thứ 5, lookup bằng regex (deterministic, như port/conn_state). Mỗi entry mô tả signature detect gì, hành vi nào trigger, và **associated MITRE tactics** — giải quyết trực tiếp VĐ2 (tactic retrieval gap) bằng structured bridge thay vì semantic search.

### Overfit risk: LOW

- Signature descriptions dựa trên ET Open ruleset conventions, không hand-craft theo eval set
- Tactic associations là kiến thức an ninh mạng chuẩn (SCAN → Reconnaissance, SMB Exploitation → Defense_Evasion/Credential_Access)
- Deterministic lookup (regex) — không tune threshold hay scoring

### Plan

#### Step 1 — Tạo `data/kb/signature_profile/signature_profiles.jsonl`

23 entries (1 per unique signature) + 1 fallback template. Format:

```jsonl
{
  "id": "sig_scan_possible_smb_probe",
  "document": "Suricata rule 'ET SCAN Possible SMB Connection Probe' fires when a TCP SYN is sent to port 445/SMB but no SYN-ACK is received (conn_state S0). This pattern is consistent with port scanning or host discovery targeting the SMB service. Associated MITRE tactics: Reconnaissance (T1595 — Active Scanning), Discovery. Common false positives: firewall blocking legitimate SMB, transient network issues. Severity guidance: medium — investigate if source IP repeats across multiple targets.",
  "metadata": {
    "source": "kb_v2",
    "kb_type": "signature_profile",
    "signature": "ET SCAN Possible SMB Connection Probe",
    "category": "Attempted Information Leak",
    "associated_tactics": ["reconnaissance", "discovery"]
  }
}
```

Nội dung mỗi entry gồm 5 phần:
1. **Trigger condition** — hành vi mạng nào kích rule
2. **Security meaning** — pattern này có ý nghĩa gì trong threat landscape
3. **Associated MITRE tactics** — danh sách tactics liên quan (structured bridge)
4. **Common false positives** — khi nào alert là noise
5. **Severity guidance** — mức độ ưu tiên xử lý

#### Step 2 — Cập nhật retriever (`lc_vectorstore.py`)

Thêm regex + exact fetch:

```python
_SIG_RE = re.compile(r'Suricata alert: (.+?) \(severity')
```

Trong `KBRetriever._get_relevant_documents()`, thêm signature lookup trước semantic search:

```python
sig_m = _SIG_RE.search(query)
if sig_m:
    sig_name = sig_m.group(1)
    for d in self._exact_fetch("signature_profile", [
        FieldCondition(key="signature", match=MatchValue(value=sig_name))
    ]):
        add(d)
```

#### Step 3 — Upload lên Qdrant

Dùng pipeline hiện có (`embed_chunks.py` hoặc script upload riêng) để index signature_profiles vào collection `cyber_chunks` với `metadata.source = "kb_v2"`.

#### Step 4 — Cập nhật ground truth prompt

Thêm SIGNATURE_KB vào `prompt_ground_truth.md` Part 1 (KB lookups):
- Extract signature name từ `alert_text`
- Lookup trong `signature_profiles.jsonl`
- Thêm vào reference (sentence 3 giờ cite từ KB thay vì tự suy)

### Tác động kỳ vọng

| Metric | Trước | Kỳ vọng |
|---|---|---|
| Tactic retrieval | Semantic search thường miss (VĐ2) | Signature profile chứa associated_tactics → reranker có thêm tín hiệu |
| Context recall | Thiếu IDS context | +1 relevant chunk per alert (signature description) |
| Faithfulness | LLM thiếu grounding cho IDS analysis | Signature KB cung cấp grounding text |

### Không giải quyết

- Không thay thế semantic tactic search — bổ sung thêm tín hiệu
- Không fix embedding quality (VĐ2 nhóm T1078/T1190) — cần H1 kèm theo
- Fallback signature ("ET POLICY Unusual...") sẽ có entry chung, không specific

---

## Thứ tự thực thi đề xuất (cập nhật sau kiểm chứng lần 2)

```
1. [XONG] Sửa BalancedRetriever: dense per-source + round-robin, reranker chỉ
   sắp xếp → recall@5 0.000→0.210, Credential_Access 0→100% (vá VĐ1)
2. [BÁC BỎ] N2 Hybrid BM25+RRF → net-negative (0.210→0.154, Cred 1.0→0.73).
3. [BÁC BỎ] N4 focused-query → @5 KHÔNG đổi (0.210).
4. [TIẾP THEO] N5 Signature profiles — thêm KB source thứ 5: Suricata signature
   → regex lookup, mỗi entry chứa associated_tactics (structured tactic bridge)
   → kỳ vọng: +1 relevant chunk/alert, cải thiện context_recall & tactic grounding
5. H1 Embedding upgrade (gte/e5) — lever zero-overfit cho VĐ2
6. Sửa measure_recall_k.py → đo per-source; Dedup MITRE = vệ sinh, ưu tiên thấp
7. Chỉ khi trên vẫn thiếu → N3; TUYỆT ĐỐI tránh H2 viết tay; H3 (HyDE) để cuối
— Lưu ý: VĐ2 bị giới hạn bởi TÍN HIỆU trong alert_text; N5 bổ sung tín hiệu
   structured (tactic association) thay vì ép semantic search
```
