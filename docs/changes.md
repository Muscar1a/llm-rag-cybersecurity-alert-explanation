# Changelog — RAG Pipeline Improvements

---

## suppressor.py (`src/rag/suppressor.py`)

### BL-002 — Fix false negative cho HTTP-based attacks

**Vấn đề:** BL-002 suppress nhầm các attack flow (DoS-Hulk, DDOS-HOIC, Brute Force-Web, Brute Force-XSS, SQL Injection) vì chỉ check port/pkts/duration/ratio mà không check RST flag và packet rate.

**Root cause:**
- HOIC flows có `RST Flag Cnt = 1` nhưng BL-002 không kiểm tra → bị suppress
- Hulk/Brute/XSS/SQL có `Flow Pkts/s` từ 3,000 đến 90,000 nhưng BL-002 không kiểm tra → bị suppress

**Thay đổi:** Thêm `rst == 0` và `pkt_rate < 500` vào điều kiện BL-002.

```python
# Trước
if (dst_port == 80 and tot_pkts <= 20 and dur_ms < 300 and ratio <= 10):
    return True

# Sau
pkt_rate = _get(row, "Flow Pkts/s")
if (dst_port == 80 and tot_pkts <= 20 and dur_ms < 300
        and ratio <= 10 and rst == 0 and pkt_rate < 500):
    return True
```

---

## alert_builder.py (`src/data_process/alert_builder.py`)

### Xóa comment code cũ thừa

Xóa 2 dòng comment còn sót lại sau khi fix `init_bwd_win == -1`:

```python
# Xóa:
# if init_bwd_win > 0:
#     win_parts.append(f"server init window {init_bwd_win} B")
```

---

## lc_vectorstore.py (`src/rag/lc_vectorstore.py`)

### BalancedRetriever — Source balancing để fix context toàn CVE

**Vấn đề:** Collection có 295,914 CVE (nvd) vs 1,118 MITRE ATT&CK vs 2,888 Sigma. MMR đơn thuần vẫn luôn trả về CVE vì chênh lệch volume quá lớn — retrieved context 100% CVE, không có MITRE/Sigma để LLM identify attack pattern.

**Thay đổi:** Thêm `BalancedRetriever` chạy 3 sub-query song song với filter per-source, merge và deduplicate kết quả.

Phân bổ mặc định với `k=5`: `nvd=2, mitre_attck=2, sigma=1` — ưu tiên MITRE và Sigma để bù cho việc chúng bị CVE lấn át.

`build_retriever` không có `source` filter giờ trả về `BalancedRetriever`. Khi có `source` filter (single-source mode) vẫn giữ nguyên behavior cũ với MMR.

**Lưu ý:** Filter key dùng `metadata.source` (nested path trong Qdrant payload), không phải `source` như code cũ — đã verify hoạt động qua Qdrant client trực tiếp.

---

## lc_prompt.py (`src/rag/lc_prompt.py`)

### Thêm baseline rules và grounding constraints

**Vấn đề:**
- Model kết luận "SYN flood" khi `SYN Flag Cnt = 0` (hallucination)
- HTTPS flows với byte ratio cao bị rate Medium thay vì Low

**Thay đổi:** Thêm 2 block vào trước phần `Rules:` trong `_BASIC_SYSTEM`, `_COT_SYSTEM`, và `FEW_SHOT_SYSTEM`:

- `_BASELINE_RULES`: grounding về HTTPS ratio bình thường, short flows, ephemeral ports
- `_GROUNDING_RULES`: constraint bắt buộc verify điều kiện trước khi đặt tên attack (SYN flood, DoS, port scan)

**Lưu ý:** Không hardcode dataset-specific knowledge (CICIDS-2018) vào prompt — chỉ dùng general networking knowledge áp dụng được trong production.

---

## lc_vectorstore.py — MMR thay similarity

**Thay đổi trước đó:** Đổi `search_type` từ `"similarity"` sang `"mmr"`, thêm `fetch_k = k * 4` và `lambda_mult = 0.6`.

---

## alert_builder.py — Fix Init Bwd Win = -1 và thêm analysis hints

**Thay đổi trước đó:**

Fix `Init Bwd Win Byts = -1` (server không respond) bị bỏ qua:
```python
if init_bwd_win == -1:
    win_parts.append("server init window: none (server did not respond)")
elif init_bwd_win > 0:
    win_parts.append(f"server init window {init_bwd_win} B")
```

Thêm analysis hints cuối `build_alert_text()` để grounding LLM reasoning:
```python
hints = []
if get_int(row, "SYN Flag Cnt") == 0:
    hints.append("SYN flood: NOT possible (SYN count = 0)")
if fwd_bytes == 0 and bwd_bytes == 0:
    hints.append("Zero-byte flow: no data transferred")
if hints:
    parts.append(f"Analysis hints: {'; '.join(hints)}.")
```

---

## suppressor.py — BL-006 ICMP

**Thay đổi trước đó:** Implement BL-006 với các field có sẵn trong CICIDS-2018 (thay thế `icmp_type` và `dst != broadcast` không computable):

```python
if proto == ICMP:
    fwd_pkts_raw = int(_get(row, "Tot Fwd Pkts"))
    bwd_pkts_raw = int(_get(row, "Tot Bwd Pkts"))
    avg_pkt_size = payload / tot_pkts if tot_pkts > 0 else 0
    pkt_rate = _get(row, "Flow Pkts/s")
    if (pkt_rate < 5 and avg_pkt_size <= 64
            and fwd_pkts_raw <= 10 and bwd_pkts_raw <= 10):
        return True
```

---

## tests/run_rag_on_network_alerts.py

**Thay đổi trước đó:** Đổi từ "5 records đầu tiên" sang "3 records per label":

- Dùng `defaultdict(int)` track `label_counts` per label
- Skip nếu label đã đủ `MAX_PER_LABEL = 3`
- Thêm field `"label"` vào mỗi result trong JSON output
- In per-label breakdown ở cuối
- Fix typo `[SUPPPRESSED]` → `[SUPPRESSED]`

---

## baseline_suppression_rules.md (`docs/baseline_suppression_rules.md`)

**Thay đổi:** Sửa header count cho đúng với nội dung thực tế:

```
# Trước
32 rules · 8 categories · 12 Suppress · 20 Alert

# Sau
34 rules · 8 categories · 6 Suppress · 28 Alert
```
