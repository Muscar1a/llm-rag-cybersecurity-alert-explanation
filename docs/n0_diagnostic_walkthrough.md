# Báo cáo Thực thi N0 (Retrieval Diagnostic: Recall@K)

Tôi đã hoàn tất việc chạy script chẩn đoán `measure_recall_k.py` trên tập `ground_truth.json` (143 samples). Thay vì dùng `BalancedRetriever` có tích hợp sẵn MMR và `score_threshold`, tôi đã thực hiện **truy vấn trực tiếp `similarity_search(k=100)`** xuống thẳng Qdrant để xem năng lực thô (raw capability) của mô hình embedding.

## Kết quả Đo lường

Kết quả cho thấy một hiện tượng cực kỳ đáng báo động (nhưng cũng rất thú vị để giải quyết):

```
========================================
OVERALL RECALL@K (Raw Similarity)
========================================
Recall@5  : 0.000 (0/143)
Recall@10 : 0.000 (0/143)
Recall@20 : 0.000 (0/143)
Recall@50 : 0.000 (0/143)
Recall@100: 0.000 (0/143)
```

**Tất cả các mốc Recall đều là 0.000**. Không có bất kỳ chunk nào chứa đúng mã Technique (ví dụ: `T1110`) lọt vào top 100 kết quả trả về của Qdrant.

## Phân tích nguyên nhân (Root Cause Analysis)

Để tìm hiểu tại sao kết quả lại tệ đến mức này, tôi đã chạy thêm một script để in ra `source` của 100 chunks được trả về bởi Qdrant cho mẫu `T1110`. Kết quả:

- `set([d.metadata.get('source')])` → `{'et_rules'}`.
- Không có bất kỳ chunk `mitre_attck` nào trong top 100. Toàn bộ 100 chunks đều thuộc về nguồn `et_rules`.

### Hiện tượng "Domain Domination" (Source Starvation)

1. **Sự tương đồng về từ vựng mạng (Network Vocabulary Match):** Đầu vào của chúng kế (`alert_text`) chứa rất nhiều thuật ngữ mạng như "TCP", "port", "RST", "brute-force". Các chunk từ `et_rules` hoặc `sigma` (chứa các rules/signatures mạng) có độ tương đồng cosine (cosine similarity) với `alert_text` cao hơn rất nhiều so với các đoạn văn bản mô tả trừu tượng của MITRE ATT&CK.
2. **Cơ chế hoạt động của `fetch_k` trong `BalancedRetriever`:** Mặc dù hệ thống có tham số `max_per_source = 2` (nghĩa là chỉ cho phép tối đa 2 chunks từ mỗi nguồn), nhưng thuật toán MMR của LangChain yêu cầu chúng ta phải lấy lên một tập `candidate_k` (thường là 20 hoặc 50) từ VectorDB trước, sau đó mới áp dụng logic đa dạng hóa nguồn. Vì **toàn bộ top 50/100 candidates từ Qdrant đều là `et_rules`**, hệ thống chỉ lấy được 2 chunks `et_rules` và **hết candidates**. Nó không thể lấy chunk `mitre_attck` vì Qdrant không hề đưa chunk MITRE nào vào pool candidates ban đầu!
3. **Threshold 0.60 không phải là thủ phạm duy nhất:** Dù chúng ta có tắt threshold `min_score = 0.60`, thì chunk MITRE vẫn không thể lọt vào Top-K vì nó đã bị văng ra khỏi top 100 ngay từ đầu do điểm similarity quá thấp.

> [!CAUTION]
> Đề xuất **N1 (Recalibrate threshold / MMR / cap)** trong `kb_improvement_proposals.md` sẽ **KHÔNG THỂ** giải quyết được vấn đề `context_recall` thấp cho MITRE một cách đơn độc. Vì dù có tinh chỉnh MMR hay nới rộng cap cỡ nào, nguồn cung cấp (Qdrant) đã không chứa MITRE trong top candidates rồi.

## Kiểm chứng bổ sung (follow-up verification)

Trước khi chấp nhận kết luận "Domain Domination" và đổi lộ trình, đã chạy thêm 3 phép kiểm chứng để loại trừ bug đo lường. Kết quả vừa xác nhận, vừa **sửa** một phần báo cáo gốc.

### Loại trừ bug đo lường (xác nhận Recall=0 là thật)

- **Bug khớp ID — LOẠI BỎ.** `label_technique` trong ground_truth đều là parent ID sạch (`T1110, T1078, T1190, T1595, T1048`). Cả 5 đều tồn tại trong collection dưới dạng parent + sub (vd `T1110, T1110.001..004`). Script khớp bằng `doc_id.startswith(...)` nên hợp lệ.
- **Bug thiếu dữ liệu — LOẠI BỎ.** Đếm điểm trong Qdrant: `et_rules=4967, mitre=1118, sigma=60`. MITRE có đầy đủ trong collection.

### Phát hiện 1 — Bug bất nhất tên source (cần sửa ngay)

MITRE points mang **top-level `payload.source='mitre'`** nhưng **nested `metadata.source='mitre_attck'`**. Vì `BalancedRetriever` đọc `doc.metadata.get('source')` → ra `mitre_attck`, còn `build_retriever(source='mitre')` lại lọc `metadata.source='mitre'` → **trả về rỗng cho MITRE một cách âm thầm**. Mọi per-source filter cho MITRE đang hỏng. (Nghi do `ingest_attck.py` vs `embed_chunks.py` gắn tag khác nhau — cần xác minh.)

### Phát hiện 2 — Per-source retrieval CHỈ cứu 1/5 (sửa hotfix #3 của báo cáo)

Lọc riêng `source=mitre_attck` (loại hoàn toàn cạnh tranh từ et_rules), đo rank của technique đúng trong top-20 MITRE-only:

| Technique | Rank đúng (MITRE-only top-20) | #1 MITRE hit |
|---|---|---|
| T1110 (Brute Force) | **1** ✓ | T1499.001 |
| T1078 (Valid Accounts) | không có trong top-20 | T1499.001 |
| T1048 (Exfiltration) | không có | T1499.001 |
| T1190 (Exploit Public-Facing) | không có | T1499.001 |
| T1595 (Active Scanning) | không có | T1499.001 |

→ "Domain Domination" là thật nhưng **không phải toàn bộ câu chuyện**. Phát query riêng từng source (hotfix #3) chỉ cứu được T1110; 4 technique còn lại không lọt nổi top-20 ngay cả khi chỉ thi đấu nội bộ MITRE.

### Phát hiện 3 — bge-base sụp đổ ngữ nghĩa ở mức technique

Bằng chứng đắt nhất: **`T1499.001` (DoS OS-Exhaustion Flood) là hit MITRE #1 cho CẢ 5 loại tấn công khác nhau.** Embedding gộp mọi alert mạng vào chung một cụm "network flood" generic, không phân biệt scan/brute-force/exfil/exploit. Đây là vấn đề **chất lượng ngữ nghĩa của retrieval**, không phải vấn đề thiếu nội dung KB.

## Kiểm chứng lần 2 — đo đúng tầng production (sửa kết luận lần 1)

> [!WARNING]
> Phần "Kiểm chứng bổ sung" phía trên đo bằng `vs.similarity_search` **toàn cục** (gộp mọi source). Đó **KHÔNG phải** thứ production chạy. `BalancedRetriever` query **per-source riêng biệt** rồi mới gộp. Đo lại đúng tầng production lật ngược vài kết luận.

### Số liệu đúng (per-source MITRE, lọc `source=mitre`, 143 mẫu)

| Tactic | @5 | @20 | @50 |
|---|---|---|---|
| Credential_Access (T1110) | **1.00** | 1.00 | 1.00 |
| Exfiltration (T1048) | 0 | 0 | **1.00** |
| Defense_Evasion (T1078) | 0 | 0 | 0 |
| Initial_Access (T1190) | 0 | 0 | 0 |
| Reconnaissance (T1595) | 0 | 0 | 0 |

→ Overall Recall@5 = **0.210** (không phải 0.000). Con số `0.000` ở phần đầu là **artifact đo toàn cục**, không phản ánh năng lực retrieval thật.

### Điểm số thật vs threshold (top-5 MITRE-only)

| Tech | #1 hit (sai) | Chunk đúng | Điểm | Threshold 0.60 |
|---|---|---|---|---|
| T1110 | T1499.001 (0.664) | rank 2, **0.618** | ✅ QUA |
| T1048/T1078/T1190/T1595 | T1499.001 | ngoài top-10 | — |

Điểm dồn cục 0.60–0.67; T1499.001 (DoS) là #1 cho cả 5 — bge collapse là thật cho 4/5 technique.

### Chạy ĐÚNG `BalancedRetriever` (production) → 0/5

Cả 5 technique đều **không** có chunk đúng trong production top-5. Kể cả T1110 (chunk đúng rank 2, qua threshold): production trả `T1499.001 + T1049` cho 2 slot MITRE rồi 3 et_rules.

Chuỗi giết chunk đúng của T1110:
1. T1110.004 retrieve được (rank 2, 0.618, qua threshold).
2. **MMR `lambda_mult=0.5`** hạ bậc (nó "giống" T1499.001 đứng trên → MMR chọn T1049 cho đa dạng).
3. **`max_per_source=2`** chặn còn 2 slot MITRE → vứt T1110.004.
4. **Reranker** không thấy nó.

### N1 (tune threshold/MMR/cap) — ĐÃ THỬ, KHÔNG ĂN

Thử `lambda_mult=1.0, max_per_source=8, threshold=0.30` → vẫn **0/5**. Nới cap cho nhiều MITRE vào pool hơn nhưng **cross-encoder reranker tự nó dìm MITRE xuống dưới et_rules**. Vậy doc gốc kết luận "N1 vô dụng" là **đúng kết quả nhưng sai lý do**: thủ phạm là reranker + cạnh tranh cross-source, không phải threshold lọc mất.

### Bug dữ liệu: MITRE trùng 2x (vệ sinh, không hại production)

`total=7263`; top-level `source`: et_rules=4967, **mitre=2236**, sigma=60; nested `metadata.source`: et_rules=4967, **mitre_attck=1118, mitre=1118**, sigma=60. MITRE bị ingest 2 lần (846 technique x2), một bản nested tag `mitre_attck` mồ côi mà `delete_source('mitre')` không dọn. Production lọc nested `metadata.source='mitre'` → chỉ đọc bản sạch → **trùng chỉ bẩn phép đo toàn cục, không trực tiếp hại production.**

## Đề xuất điều chỉnh lộ trình (sau kiểm chứng lần 2)

> [!IMPORTANT]
> Hai vấn đề ĐỘC LẬP, hai tầng khác nhau — đừng gộp:
> - **VĐ1 Credential_Access (T1110, ~85% eval):** chunk retrieve ĐƯỢC (MITRE-only @5=100%) nhưng **kiến trúc pipeline vứt nó** (MMR-diversity + cap=2 + reranker thiên vị et_rules). Fix = sửa kiến trúc, KHÔNG phải tune tham số.
> - **VĐ2 (T1078/T1190/T1595):** chunk ngoài top-50 ngay cả MITRE-only → **embedding hỏng thật**, không mẹo cấu hình nào cứu.

```
1. Sửa BalancedRetriever: đảm bảo top-k MITRE theo dense vào thẳng context,
   bỏ qua MMR-diversity + reranker cho slot per-source đảm bảo
   (zero-overfit, technique-agnostic) → vớt VĐ1 (85% eval)
2. N2 Hybrid (BM25 sparse + dense, RRF)   (zero-overfit) → cho VĐ2:
      "scanning"/"valid accounts"/"exploit"/"exfiltration" nằm thẳng trong alert_text
3. H1 Embedding upgrade (gte/e5)          (zero-overfit) nếu hybrid chưa đủ
4. Sửa measure_recall_k.py → đo per-source (khớp production), bỏ phép đo toàn cục gây hiểu lầm
5. Dedup MITRE (xoá bản nested 'mitre_attck') = vệ sinh, ưu tiên thấp
— TUYỆT ĐỐI tránh H2 viết tay; N3 chỉ khi 1–3 vẫn thiếu (60 sigma points quá mỏng)
```

## Đã thực thi bước 1 — sửa `BalancedRetriever` (kết quả)

Thay cơ chế per-source: **dense similarity** (bỏ MMR-diversity) → **round-robin merge** (đảm bảo mỗi source có slot) → reranker chỉ **sắp xếp** tập đã merge (không loại source nào vì `len ≤ k`). `min_score`/`lambda_mult`/`fetch_k_mult` trở thành inert.

Production Recall@5 (full `BalancedRetriever`, 143 mẫu):

| Tactic | Trước | Sau |
|---|---|---|
| **Overall** | 0.000 | **0.210** (30/143) |
| Credential_Access | 0.000 | **1.000** (30/30) |
| Defense_Evasion | 0.000 | 0.000 |
| Exfiltration | 0.000 | 0.000 |
| Initial_Access | 0.000 | 0.000 |
| Reconnaissance | 0.000 | 0.000 |

→ VĐ1 (Credential_Access — 26/30 mẫu benchmark few_shot) **đã vá trọn**. 4 tactic còn lại đúng dự đoán VĐ2 (embedding hỏng) → chuyển sang bước 2 (hybrid BM25).

## Đã thử bước 2 — Hybrid BM25+RRF (BÁC BỎ, net-negative)

> [!CAUTION]
> Giả định trong proposal ("tên technique nằm thẳng trong alert_text") **SAI** cho VĐ2. Từ vựng MITRE KHÔNG xuất hiện literal trong alert: T1595 alert ghi *"port closed/firewall acl drop"* (không có "scanning"); T1048 *"reset by originator, abrupt teardown"* (không có "exfiltration"); T1078 *"host discovery"* (không có "valid accounts").

Đo BM25 thô (per-source MITRE, k=50): **chunk đúng KHÔNG nằm top-50 cho cả 5** technique; `T1499.001` là BM25 #1 cho cả 5 — collapse y hệt dense. Nguyên nhân: alert bị **token mạng generic** ("tcp"/"connection" lặp 3x/"port"/"state") nhấn chìm → BM25 dồn về T1499.

Full recall@5 với hybrid bật:

| | Dense-only (bước 1) | Hybrid |
|---|---|---|
| Overall | **0.210** | 0.154 |
| Credential_Access | **1.000** | 0.733 |
| 4 tactic kia | 0 | 0 |

→ BM25 chỉ thêm nhiễu, đẩy T1110 đúng ra khỏi top-5 (30→22), không cứu tactic nào. **Đã revert** (`lc_vectorstore.py` về dense-only, xoá `lc_bm25.py`, bỏ `rank_bm25`). VĐ2 cần lever khác: **H1 đổi embedding** hoặc **N4 focused-query** (cắt nhiễu generic), KHÔNG phải hybrid.

## Đã thử N4 — focused-query (KHÔNG implement, không vượt @5)

Probe FREE: trích phần 2 (behavioral meaning) + phần 7 (behavioral hints) của `build_alert_text` làm query, vứt token số liệu generic. Dense MITRE-only recall:

| Query | @5 (production) | @20 | @50 |
|---|---|---|---|
| Full alert | 0.210 | 0.210 | 0.371 |
| Focused (part 2+7) | **0.210** | 0.280 | 0.399 |

Nhích ở @20/@50 (Exfiltration, Reconnaissance) nhưng **@5 KHÔNG đổi** → không vượt điểm vận hành. Không đáng sửa kiến trúc chain cho 0 lợi ích @5.

> [!IMPORTANT]
> **Trần tín hiệu dữ liệu.** `focus()` để lộ: behavioral-hint thường KHÔNG khớp nhãn technique. T1190 (Exploit Public-Facing) alert port 80 SF chỉ là *"normal bidirectional flow"* — **không có tín hiệu exploit nào**. T1048 hint nói *"scan or evasion"* (không phải exfiltration); T1078 (Valid Accounts) hint nói *"port scanning"*. → Với vài tactic, alert_text tầng network-flow **không mang tín hiệu phân biệt technique**. Không lever retrieval/embedding nào tạo ra tín hiệu không tồn tại; ép = rò rỉ nhãn = **overfit**. Đây là giới hạn của dữ liệu, không phải của hệ thống.

Lever zero-overfit còn lại: **H1 (gte/e5)** — có thể kéo tín hiệu yếu-nhưng-có (Exfil @50) lên @5, nhưng gần như KHÔNG cứu được nhóm thiếu tín hiệu (T1190).
