# Knowledge Base Improvement Plan

## Bối cảnh

Hệ thống RAG dùng để giải thích các network attack alert từ dataset CIC-IDS2018.  
Input là mô tả thống kê TCP/UDP flow (packet count, byte ratio, IAT, TCP flags, window size...).  
Output là phân tích mối đe dọa (threat description, severity, rationale, mitigation steps).

**Vấn đề cốt lõi:** KB hiện tại chứa 99% CVE descriptions — mô tả lỗ hổng phần mềm, không phải hành vi traffic mạng. Embedding cosine similarity giữa flow query và CVE text chỉ đạt ~0.5–0.6, không bao giờ vượt ngưỡng 0.82 → `retrieved_context_ids: []` trong toàn bộ evaluation.

---

## Kiểm tra thực tế (từ `tests/inspect_kb.py`)

```
Collection: cyber_chunks
Points    : 299,215
Vector    : 768-dim COSINE (BAAI/bge-base-en-v1.5)

Source breakdown (sample 2000):
  nvd          1,973  (98.7%)
  sigma           19  (0.95%)
  mitre_attck      8  (0.40%)

Retrieval test — query: "botnet C2 beaconing TCP port 8080 custom stack PSH RST"
  min_score=0.82 → 0 results
  min_score=0.0  → 5 results, tất cả đều là CVE không liên quan
```

---

## Đánh giá nguồn dữ liệu hiện có

### Sigma (`data/raw/sigma/`)

| Thư mục | Số file | Đánh giá |
|---------|---------|-----------|
| `windows/` | 2,396 | ❌ Không liên quan — endpoint rules (registry, process, PowerShell) |
| `linux/` | 209 | ❌ Không liên quan |
| `cloud/` | 230 | ❌ Không liên quan |
| `network/` | **53** | ✅ Giữ lại — Zeek, DNS, firewall, cleartext protocol detection |

Các rule trong `network/` bao gồm: Cobalt Strike certificate, DNS tunneling, BPFdoor TCP redirect, cleartext protocols (port 8080, 21, 80...), Zeek HTTP/SMB detection.

### MITRE ATT&CK (`data/raw/MITRE/enterprise-attack/enterprise-attack.json`)

858 attack-patterns tổng cộng. 23 techniques liên quan đến network traffic:

| ID | Tên | Liên quan |
|----|-----|-----------|
| T1498 / T1498.001 / T1498.002 | Network Denial of Service | ✅ HULK, GoldenEye, HOIC |
| T1499 / T1499.001 / T1499.002 | Endpoint Denial of Service | ✅ Slowloris, SlowHTTPTest |
| T1071 / T1071.001 / T1071.004 | Application Layer Protocol (C2) | ✅ Bot C2, Infiltration |
| T1095 | Non-Application Layer Protocol | ✅ Bot C2 non-standard port |
| T1571 | Non-Standard Port | ✅ Bot TCP 8080, Infiltration high ports |
| T1572 | Protocol Tunneling | ✅ DNS tunneling, Infiltration |
| T1046 | Network Service Discovery | ✅ Port scan adjacent |
| T1110 / .001 / .002 / .003 / .004 | Brute Force | ✅ Web BF, FTP-BF, SSH-BF |
| T1190 | Exploit Public-Facing Application | ✅ SQL Injection |
| T1048 | Exfiltration Over Alternative Protocol | ✅ Infiltration |
| T1041 | Exfiltration Over C2 Channel | ✅ Infiltration HTTPS C2 |
| T1008 | Fallback Channels | ✅ Bot redundant C2 |
| T1205 | Traffic Signaling | ✅ URG flag abuse, covert signaling |

### NVD CVE (`data/processed/CVE/`)

~295,000 entries. Hầu hết là mô tả lỗ hổng phần mềm (XSS, buffer overflow, privilege escalation...) không có giá trị cho network flow analysis.

---

## Vấn đề trong pipeline ingestion hiện tại

### 1. MITRE — thiếu field `detection` trong `chunk_data.py`

```python
# src/data_process/chunk_data.py L25 — MITRE hiện tại (THIẾU)
"text_cols": ["name", "description", "tactics"]

# Nên thêm
"text_cols": ["name", "description", "tactics", "detection"]
```

Field `detection` đã được parse bởi `parse_attck.py` (L31) và tồn tại trong `mitre_cleaned.parquet`, nhưng `chunk_data.py` bỏ qua nó. Field này chứa hướng dẫn phát hiện behavior — phần quan trọng nhất để match với network flow query.

### 2. Sigma — 98% là nhiễu

2835/2888 sigma rules là Windows/Cloud/Linux endpoint rules. Chúng chiếm dung lượng và làm giảm chất lượng retrieval do dilution effect trong vector space.

### 3. `min_score = 0.82` quá cao

```python
# src/rag/lc_vectorstore.py L54
min_score: float = 0.82

# src/rag/lc_vectorstore.py L109 — hardcoded lần nữa trong build_retriever()
"score_threshold": 0.82
```

Threshold này được set cho CVE-to-CVE similarity. Với cross-domain queries (flow stats → attack descriptions), score tự nhiên thấp hơn dù nội dung liên quan.

### 4. Thiếu network behavior signatures — nguồn quan trọng nhất

Không có bất kỳ chunk nào mô tả **hành vi traffic** của từng loại tấn công. Đây chính xác là thứ embedding model cần để match với input query.

**Lý do không dùng attack profiles tự viết:** Viết profiles dựa trên thống kê từ CIC-IDS2018 sẽ gây overfitting — KB sẽ match chính xác trên eval data nhưng fail trên real traffic. Ví dụ: `DoS-SlowHTTPTest` trong dataset nhắm port 21 (FTP) với 0 bytes payload — đây là artifact của CICFlowMeter, không phải hành vi thực của công cụ.

**Giải pháp:** Dùng **Emerging Threats Suricata/Snort rules** — được viết bởi security researchers từ threat intelligence thực tế, không phụ thuộc vào bất kỳ dataset cụ thể nào.

---

## Kế hoạch cải thiện

### Bước 0 — Đo baseline (30–60 phút)

Chạy evaluation TRƯỚC khi thay đổi bất kỳ gì, để có số liệu so sánh.

```bash
python tests/evaluate_ragas.py --reset
copy tests\evaluation_comparison.json tests\evaluation_comparison_baseline.json
```

---

### Bước 1 — Hạ `min_score` (5 phút)

**File:** `src/rag/lc_vectorstore.py`

```diff
 # L54 — BalancedRetriever field
-    min_score: float = 0.82
+    min_score: float = 0.60

 # L109 — build_retriever() hardcoded value
-            "score_threshold": 0.82,
+            "score_threshold": 0.60,
```

**Lưu ý:** 0.60 là giá trị tạm. Sau khi rebuild KB (bước 3), nên chạy score sweep trên ground_truth để chọn threshold tối ưu:
1. Set `min_score = 0.0` tạm thời
2. Log score distribution cho tất cả queries
3. Chọn threshold ở elbow point hoặc P10

**Verify:**
```bash
python tests/inspect_kb.py --query "botnet C2 beaconing port 8080" --score 0.60
# Expected: > 0 results
```

---

### Bước 2 — Fix MITRE `detection` field (15 phút + re-embed)

**File:** `src/data_process/chunk_data.py`

```diff
 # L25
-        "text_cols":  ["name", "description", "tactics"],
+        "text_cols":  ["name", "description", "tactics", "detection"],
```

Không cần sửa upstream — `parse_attck.py` đã parse `x_mitre_detection` và `clean_data.py` đã lưu cột `detection` vào `mitre_cleaned.parquet`.

**Verify:**
```bash
python src/data_process/chunk_data.py
python -c "import pandas as pd; df=pd.read_parquet('data/processed/MITRE/chunks.parquet'); print(df.iloc[0]['text'][:500])"
# Expected: text chứa "Detection:" content
```

---

### Bước 3 — Emerging Threats Suricata rules (~2 giờ)

Nguồn: `https://rules.emergingthreats.net/open/suricata/rules/` (miễn phí, BSD license)

**Tại sao ET rules không bị overfit:**
- Được viết từ threat intelligence thực tế và tool documentation, không từ dataset cụ thể
- Mỗi rule có `msg` (tên tấn công), protocol, ports, payload signature, classtype, reference URL
- Generalizable sang real traffic

**Rule files cần dùng:**

| File | Số rules | Attack types liên quan |
|------|----------|------------------------|
| `emerging-dos.rules` | 59 | HOIC, LOIC, Slowloris, GoldenEye, HTTP flood |
| `emerging-sql.rules` | 191 | SQL injection (error-based, time-based, UNION) |
| `emerging-scan.rules` | 285 | Port scan, brute force scanning |
| `emerging-web_specific_apps.rules` | 5,917 | XSS, web brute force — **cần filter** |
| `emerging-policy.rules` | 838 | Cleartext protocol, non-standard port — **cần filter** |

**Phần A — Download rules**

```bash
mkdir data/raw/emerging_threats
BASE=https://rules.emergingthreats.net/open/suricata/rules

curl -o data/raw/emerging_threats/emerging-dos.rules              $BASE/emerging-dos.rules
curl -o data/raw/emerging_threats/emerging-sql.rules              $BASE/emerging-sql.rules
curl -o data/raw/emerging_threats/emerging-scan.rules             $BASE/emerging-scan.rules
curl -o data/raw/emerging_threats/emerging-web_specific_apps.rules $BASE/emerging-web_specific_apps.rules
curl -o data/raw/emerging_threats/emerging-policy.rules           $BASE/emerging-policy.rules
```

**Phần B — Parser script: `src/data_process/parse_et_rules.py`**

Parser extract từ Snort/Suricata rule format:

```
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET DOS..."; classtype:attempted-dos; content:"..."; reference:url,...; sid:2014153; metadata:signature_severity Major;)
```

CURL data 
```
curl.exe -L --create-dirs -o "data/raw/emerging_threats/emerging-dos.rules" https://rules.emergingthreats.net/open/suricata/rules/emerging-dos.rules

curl.exe -L --create-dirs -o "data/raw/emerging_threats/emerging-sql.rules" https://rules.emergingthreats.net/open/suricata/rules/emerging-sql.rules

curl.exe -L --create-dirs -o "data/raw/emerging_threats/emerging-scan.rules" https://rules.emergingthreats.net/open/suricata/rules/emerging-scan.rules

curl.exe -L --create-dirs -o "data/raw/emerging_threats/emerging-web_specific_apps.rules" https://rules.emergingthreats.net/open/suricata/rules/emerging-web_specific_apps.rules

curl.exe -L --create-dirs -o "data/raw/emerging_threats/emerging-policy.rules" https://rules.emergingthreats.net/open/suricata/rules/emerging-policy.rules
```

Fields cần extract: `msg`, `classtype`, `protocol`, `dst_port`, danh sách `content` patterns, `reference`, `signature_severity` từ metadata.

Output mỗi rule thành human-readable text để embed, ví dụ:
```
Rule: ET DOS High Orbit Ion Cannon (HOIC) Attack Inbound
Protocol: TCP → HTTP ports
Detection: HTTP header double-spaced User-Agent; HTTP/1.0 with malformed headers
Threshold: 225 requests per 60 seconds from same source
Classtype: attempted-dos
Severity: Major
Reference: blog.spiderlabs.com/2012/01/hoic-ddos-analysis-and-detection.html
```

**Keyword filter cho `web_specific_apps` và `policy`** (để tránh nhập 6,000+ rules không liên quan):
```python
KEEP_KEYWORDS = [
    "brute", "xss", "cross-site", "sql", "injection",
    "botnet", "c2", "beacon", "c&c",
    "ssh", "ftp", "telnet", "rdp",
    "dos", "flood", "slowloris", "slow http",
    "scan", "sweep", "cleartext", "non-standard port",
    "infiltrat", "exfiltrat", "tunnel",
]
```

**Phần C — Thêm vào pipeline**

`src/data_process/chunk_data.py` — thêm entry vào `SOURCES`:
```python
{
    "name":      "et_rules",
    "input":     "data/processed/emerging_threats/et_rules_cleaned.parquet",
    "output":    "data/processed/emerging_threats/chunks.parquet",
    "id_col":    "sid",
    "text_cols": ["rule_text"],   # pre-rendered human-readable text từ parser
},
```

`src/data_process/embed_chunks.py` — thêm vào `SOURCES` dict:
```python
"et_rules": Path("data/processed/emerging_threats/chunks.parquet"),
```

Thêm metadata enrichment vào `_build_points()`:
```python
elif source == "et_rules":
    payload.update({
        "classtype": meta.get("classtype", ""),
        "severity":  meta.get("severity", ""),
        "sid":       meta.get("sid", ""),
    })
```

**Verify:**
```bash
python src/data_process/parse_et_rules.py
python src/data_process/chunk_data.py
python src/data_process/embed_chunks.py --source et_rules

python tests/inspect_kb.py --query "HOIC DDoS HTTP flood port 80" --score 0.60
# Expected: et_rules chunks trong kết quả với msg chứa HOIC
```

---

### Bước 4 — Filter Sigma, chỉ giữ `network/` (30 phút)

**File:** `src/data_process/clean_data.py`

```diff
 # L18
-SIGMA_CATEGORIES = ["network", "windows", "linux", "cloud"]
+SIGMA_CATEGORIES = ["network"]
```

Thay đổi 1 dòng duy nhất. Kết quả: 53 rules thay vì 2888, giảm nhiễu 98%.

**Verify:**
```bash
python src/data_process/clean_data.py
python -c "import pandas as pd; df=pd.read_parquet('data/processed/sigma/sigma_cleaned.parquet'); print(f'{len(df)} rules')"
# Expected: ~53 rules
```

---

### Bước 5 — Bỏ hoàn toàn CVE (Option B) (5 phút)

Xoá entry `cve` khỏi `SOURCES` trong `chunk_data.py` và `embed_chunks.py`.  
Bởi vì CVE chỉ mô tả cách thức tấn công/lỗ hổng phần mềm, không mô tả hướng đi lưu lượng, nên chúng ta loại bỏ hoàn toàn để tránh nhiễu và cải thiện hiệu năng.

**Verify:**
Kiểm tra biến `SOURCES` trong `src/data_process/chunk_data.py` và `src/data_process/embed_chunks.py` không còn chứa `cve`.

---

### Rebuild KB & Đo after

```bash
# Full rebuild
python src/data_process/chunk_data.py
python src/data_process/embed_chunks.py --recreate

# Verify KB composition
python tests/inspect_kb.py

# Đo after
python tests/evaluate_ragas.py --reset
```

**Metrics cần so sánh với baseline:**

| Metric | Baseline (expected) | After (target) |
|--------|-------------------|----------------|
| `avg_context_recall` | ~0 (no retrieval) | > 0.5 |
| `avg_context_precision` | ~0 | > 0.4 |
| `avg_answer_correctness` | low | higher |
| `attack_semantic_hit` | ? | > 70% |
| `context_diversity` | `none` | `et_rules+mitre` hoặc tương tự |

Dùng `--recreate` để truncate & rebuild toàn bộ Qdrant collection. Đây là approach đúng vì số chunks giảm từ 299K → ~5K — incremental delete phức tạp hơn recreate.

---

## KB mục tiêu sau khi cải thiện

```
cyber_chunks (Qdrant)
├── et_rules           ~300–500 chunks  (Emerging Threats — HOIC/LOIC/SQLi/BruteForce/C2 sigs)
├── sigma              ~53 chunks       (Zeek, DNS, firewall, cleartext protocol)
└── mitre              ~23 chunks       (T1071, T1095, T1110, T1190, T1498, T1499... + detection field)
```

Tổng: **~400–600 chunks** thay vì 299,215 hiện tại.  
Nhỏ hơn 50x nhưng semantic relevance cao hơn nhiều lần. Không có overfitting risk vì không dùng data từ CIC-IDS2018.

---

## Thứ tự ưu tiên thực hiện

| Thứ tự | Bước | Thời gian | Tác động | Dependency |
|--------|------|-----------|----------|------------|
| 0 | **Đo baseline** (`evaluate_ragas.py`) | 30–60 phút | Có số liệu so sánh | Không |
| 1 | Hạ `min_score` 0.82 → 0.60 | 5 phút | Ngay lập tức cho phép retrieve | Không |
| 2 | Fix MITRE `detection` field | 15 phút + re-embed | MITRE chunks chính xác hơn | Không |
| 3 | **Emerging Threats rules** + pipeline | ~2 giờ | **Cao nhất** — network behavior signatures, không overfit | Không |
| 4 | Filter Sigma chỉ `network/` | 30 phút | Giảm nhiễu 98% | Không |
| 5 | Bỏ hoàn toàn CVE | 5 phút | Dọn dẹp KB, cải thiện precision tối đa | Không |
| — | `embed_chunks.py --recreate` | 15–30 phút | Rebuild KB | Sau 2–5 |
| 6 | **Đo after** (`evaluate_ragas.py`) | 30–60 phút | Xác nhận cải thiện | Sau rebuild |

> **Quyết định thiết kế:** Attack profiles tự viết từ CIC-IDS2018 stats đã bị loại bỏ vì rủi ro overfitting trên eval data. Emerging Threats rules thay thế hoàn toàn vì được viết từ threat intelligence độc lập với dataset.
