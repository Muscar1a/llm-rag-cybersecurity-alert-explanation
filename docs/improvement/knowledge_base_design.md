# Knowledge Base Design — RAG Cybersecurity Alert Explanation

> File này mô tả thiết kế knowledge base (KB) cho hệ thống RAG giải thích cảnh báo
> an ninh mạng. Phần đầu là tổng quan project để bất kỳ ai (hoặc model nào) đọc file
> này lần đầu đều nắm được bối cảnh; phần sau là đặc tả KB chi tiết.

---

## 0. Tổng quan project (context cho người/model đọc lần đầu)

**Tên project:** LLM-based Retrieval-Augmented Cybersecurity Alert Explanation System.

**Mục tiêu:** Xây một hệ thống RAG để **giải thích từng cảnh báo an ninh mạng đơn lẻ**
(single-alert explanation). KHÔNG phải correlate nhiều alert thành một incident, KHÔNG
phải tái dựng attack campaign. Input là một cảnh báo về một network flow; output là một
giải thích kỹ thuật (threat description, mức độ nghiêm trọng + lý do, gợi ý xử lý).

**RAG là ràng buộc cứng của đề tài** — không được bỏ. Vì vậy bài toán không phải "có nên
dùng RAG không" mà là "làm cho RAG thực sự có giá trị".

**Pipeline tổng thể:**

```
Zeek conn.log row
      │  (zeek_alert_builder.py — rule-based, fact-only)
      ▼
Alert text THUẦN FACT  ──────────►  Retriever  ──────►  KB (interpretation knowledge)
      │                                                        │
      └──────────────────►  LLM  ◄──────── retrieved context ──┘
                             │
                             ▼
                    Explanation (grounded vào retrieved context)
                             │
                             ▼
                         RAGAS evaluation
```

**Dữ liệu nguồn chính:** UWF-ZeekData24 — dataset Zeek conn.log của Đại học West Florida,
label theo MITRE ATT&CK (tactic + technique). Có sẵn ở định dạng parquet và CSV.

**Alert generation (đã hoàn thiện):** Rule-based, file `zeek_alert_builder.py`. Quan trọng:
alert text được thiết kế **chỉ chứa fact quan sát được** (port number trần, conn_state,
byte/packet counts, byte ratio, duration, TCP history sequence, detected services). Đã chủ
động **bóc bỏ mọi diễn giải** — không có "brute-force", "high-value target", "exfiltration",
"scanning", "lateral movement", và không gán tên service vào port (chỉ ghi `port 4848`,
không ghi "GlassFish admin"). Lý do: nếu alert đã chứa kết luận thì LLM chỉ paraphrase và
RAG trở nên thừa. Diễn giải là việc của KB + LLM. Các label (label_tactic, label_technique,
label_binary, label_cve) được giữ trong **metadata**, KHÔNG nằm trong alert text, để dùng
làm ground truth mà không leak đáp án vào input.

**Dữ liệu test (đã chốt):** Trộn một slice nhỏ stratified của UWF-ZeekData24 với dataset
IoT-23 (Stratosphere Lab) — chi tiết ở file `test_dataset_design.md`.

**Bối cảnh chẩn đoán (lý do KB được thiết kế như dưới đây):** Các lần chạy RAGAS đầu tiên
cho faithfulness, context_precision, context_recall đều **thấp**. Nguyên nhân gốc gồm ba
phần: (1) ground truth ban đầu do Claude sinh từ prior knowledge chứ không từ retrieved
context, nên claims không grounded vào context; (2) alert text cũ chứa sẵn diễn giải khiến
RAG không có gì để đóng góp; (3) KB ban đầu (MITRE/ET/Sigma ở dạng thô) chứa toàn thứ LLM
đã biết sẵn VÀ lệch domain so với network-flow alert (MITRE mô tả endpoint Windows, ET là
detection signature, không phải tri thức giải thích hành vi network). File này giải quyết
phần (3).

**Nguyên tắc thiết kế KB (cốt lõi):** KB chỉ nên chứa tri thức nằm đúng giữa hai lằn ranh:
- KHÔNG phải thứ LLM đã biết sẵn (nếu không, retrieve = thêm noise, RAG thừa).
- KHÔNG phải đáp án cụ thể của test set (nếu không, hệ thống overfit thành nearest-neighbor
  classifier đội lốt RAG, và metric trở nên ảo).
KB phải chứa **tri thức diễn giải khái niệm**: cái gì là gì, hành vi này nghĩa là gì, ở mức
tổng quát — đủ để LLM tự reason ghép lại, không phải tra sẵn câu trả lời.

---

## 1. KB gồm những gì — bốn nhóm tri thức

KB phải gánh đúng những phần diễn giải đã bị bóc khỏi alert. Vì alert mô tả flow theo các
chiều {port, conn_state, traffic pattern, service, sequence}, KB được tổ chức thành bốn
nhóm tương ứng. Mỗi nhóm là một loại "concept entry" độc lập, được index chung vào một
vector store nhưng phân biệt bằng trường `kb_type` trong metadata.

### Nhóm 1 — Port / Service Profiles (`kb_type: port_profile`)

Quan trọng nhất, vì alert giờ chỉ ghi số port trần. Mỗi entry mô tả một port/dịch vụ.

Trường nội dung (đi vào phần `document` để embed):
- `service_name`: tên dịch vụ chạy trên port (vd "GlassFish Java EE admin console").
- `role`: vai trò trong hệ thống (admin/management interface, file sharing, database,
  web app, authentication, remote access...).
- `attack_surface`: bề mặt tấn công điển hình của dịch vụ này.
- `detection_hints`: **CHỈ** dấu hiệu hành vi ĐẶC THÙ DỊCH VỤ (vd DNS → high-entropy subdomain,
  TXT abuse, AXFR; SMB → truy cập C$/ADMIN$, SMBv1 negotiation; HTTPS → JA3/JA3S mismatch,
  SNI bất thường, beaconing). Hành vi CHUNG (brute-force bursts, horizontal scan, beaconing
  chung, reset-after-data...) KHÔNG để ở đây — chuyển sang Nhóm 3 (traffic_pattern), viết một
  lần, tránh lặp ở nhiều port. Phép thử: "hint này có còn đúng nếu đổi sang dịch vụ khác?"
  Còn đúng → Nhóm 3; chỉ đúng với dịch vụ này → ở đây.
- `representative_cves`: 3 CVE tiêu biểu (định danh + severity + tóm tắt tác động ngắn), chọn
  tự động theo CVSS (ưu tiên match product slug rồi tới keyword), review/gạch tay sau. KHÔNG
  liệt kê dài (review của ChatGPT/Gemini: list CVE dài gây nhiễu, ít giá trị cho explain).
- `normal_baseline`: traffic bình thường trông như thế nào (ai truy cập, từ đâu, tần suất,
  khối lượng) so với dấu hiệu bất thường.

> Lưu ý: `attack_examples` (tên các attack kinh điển) đã được CÂN NHẮC rồi BỎ — gộp ý niệm
> đó vào `detection_hints` (đặc thù dịch vụ) và Nhóm 3 (hành vi chung).

Trường metadata (để retriever filter/match chính xác):
- `kb_type` = `port_profile`.
- `port` (int) — khớp trực tiếp với `dest_port` trong metadata của alert.
- `protocol` (tcp/udp).
- `service_name` (str) — tiện hiển thị/tra cứu.
- `cve_ids` (str) — danh sách cve_id nối bằng dấu phẩy (ChromaDB metadata chỉ nhận scalar,
  nên list bị flatten thành string). Nội dung CVE chi tiết nằm trong `document`, không ở đây.

**Nguồn dữ liệu (theo từng trường):**

Không có một dataset nào trả về sẵn cả 7 trường. Chia làm ba mức:

1. *Tự động — từ IANA.* File CSV chính thức `service-names-port-numbers.csv` (~14.000 dòng,
   cột: Service Name, Port Number, Transport Protocol, Description) cho trực tiếp:
   - `port` ← Port Number
   - `protocol` ← Transport Protocol
   - `service_name` ← Service Name + Description (lưu ý: mô tả IANA rất ngắn, không có
     security context — chỉ ở mức tên gọi).

2. *Bán tự động — từ NVD, cho trường `representative_cves`.* NVD KHÔNG index theo port mà theo
   **sản phẩm (CPE)**. Cần ba thứ:
   - **Bảng map port → product_slugs + keywords** (TỰ LẬP, đã làm — xem `port_product_map_draft.md`).
     Đây là mắt xích bắt buộc và tốn công nhất. Lưu ý: nhiều CVE quan trọng KHÔNG gắn đúng
     product slug (vd CVE-2014-8361 Realtek lại gắn `dlink/*`), nên phải kết hợp keyword search
     trên `description`.
   - **Nguồn CVE: file CVE đã crawl** (`2010.json`..`2025.json`, mỗi record có cve_id,
     description, cvss_score, cvss_severity, products). Lưu ý file chia theo NĂM CÔNG BỐ, không
     theo mã CVE → phải quét tất cả file.
   - **Lọc & xếp hạng**: match (product slug) HOẶC (keyword trong description), khử trùng, xếp
     theo CVSS giảm dần, lấy top 3. Ưu tiên pool slug (chính xác) rồi mới tới pool keyword.
     Các port chỉ-dùng-keyword (111, 135) nhiễu hơn → cần gạch tay khi review.

3. *Không có trong dataset nào — phần giá trị nhất.* Ba trường `role`, `attack_surface`,
   `normal_baseline` không tồn tại ở dạng cấu trúc trong IANA/NVD/MITRE. Đây là tri thức tổng
   hợp của analyst, tạo ra bằng: (a) LLM enrichment offline một lần (cho model nhận
   service_name + description + danh sách CVE rồi sinh ba trường này, có review), hoặc (b)
   viết tay cho các port quan trọng. Chính ba trường này là thứ LLM-runtime không có sẵn ở
   dạng chuẩn hóa/kiểm chứng được, nên là phần tạo ra giá trị thực của RAG (xem mục 4 về vai
   trò "trí nhớ đã kiểm duyệt").

**Phạm vi (ĐÃ CHỐT):** 16 port — 20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
445, 992, 4848. Các port loại 2 (threat-intel: 81, 9527, 52869, 62336) và port mơ hồ (50, 2407)
đã BỎ ở vòng này (không tra CVE tự động được; nếu cần sau này thì viết tay từ threat-intel).
Artifact đã build: `port_profiles.jsonl` (ChromaDB-ready) + `port_profiles_review.md` (bản review).

### Nhóm 2 — Connection-State Semantics (`kb_type: conn_state`)

Chính là tri thức đã bị bóc khỏi bảng `CONN_STATE_INFO` của builder. Mỗi entry giải thích
một conn_state của Zeek.

Trường nội dung:
- `state_code`: mã (SF, S0, REJ, RSTO, SH, OTH...).
- `wire_meaning`: chuyện gì xảy ra trên dây (packet nào thấy/không thấy) — phần fact.
- `behavioral_interpretation`: nghĩa về mặt hành vi an ninh (vd S0 = SYN không đáp → có thể
  scan/host discovery/firewall drop). Đây là phần diễn giải mà LLM hay nói không nhất quán.

Metadata:
- `state_code` — khớp với `conn_state` trong metadata alert.

**Nguồn:** Zeek documentation chính thức (conn.log conn_state field) cho `wire_meaning`;
diễn giải security cho `behavioral_interpretation`. Tập nhỏ (~13 trạng thái) nhưng giá trị
rất cao vì conn_state là tín hiệu phân loại mạnh trong Zeek data.

### Nhóm 3 — Traffic-Pattern Semantics (`kb_type: traffic_pattern`)

Diễn giải các đặc trưng định lượng của flow.

Trường nội dung:
- `pattern_name`: tên mẫu (vd "high server-to-client byte ratio", "repeated short
  connections to same port", "asymmetric client-dominant upload", "history với nhiều
  retransmission").
- `observable_signature`: mô tả định lượng (vd byte ratio > 5, duration < 1s lặp lại).
- `interpretation`: các khả năng hành vi (viết ở dạng "có thể là A, B, hoặc C" — KHÔNG kết
  luận tuyệt đối, để tránh overfit).

Metadata:
- `applies_to`: các chiều liên quan (byte_ratio / duration / packet_asymmetry / history).

**Nguồn:** tổng hợp từ threat-hunting literature và Zeek-based detection writeups, enrich
bằng LLM. **Lưu ý chống leakage:** viết ở mức tổng quát, KHÔNG tinh chỉnh để khớp với flow cụ
thể nào trong test set.

### Nhóm 4 — Attack-Technique References (`kb_type: technique`)

Tận dụng ba nguồn parquet đã có (MITRE ATT&CK, Emerging Threats, Sigma) NHƯNG tái cấu trúc,
KHÔNG dùng thô. Mỗi technique được viết lại dưới góc nhìn **network-observable**.

Trường nội dung:
- `technique_id` + `technique_name`: vd T1110 Brute Force, T1190 Exploit Public-Facing App.
- `network_observable`: technique này trông như thế nào TRONG Zeek conn.log — port nào,
  conn_state nào, byte/duration pattern nào. Đây là lớp dịch quan trọng nhất, vì MITRE thô
  mô tả góc endpoint (process, registry, memory) không khớp với network flow.
- `description`: mô tả hành vi attacker ở mức vừa đủ.

Metadata:
- `technique_id`, `tactic` — để map với label và filter.

**Nguồn:** MITRE/ET/Sigma parquet hiện có làm liệu thô, qua một bước enrich bằng LLM để sinh
`network_observable`. ET rules enrich thêm "trigger khi nào, attacker đạt được gì".

---

## 2. Cách key & retrieve

Alert text được embed và dùng làm query semantic. Đồng thời, metadata của alert (đặc biệt
`dest_port`, `conn_state`, `service`) được dùng làm **structured filter / hybrid signal** để
kéo đúng các entry KB tương ứng. Khuyến nghị hybrid retrieval:

- **Dense (semantic):** embed alert text, retrieve top-k concept entry gần nghĩa nhất.
- **Structured boost:** ưu tiên `port_profile` có `port == alert.dest_port`, `conn_state`
  entry có `state_code == alert.conn_state`. Đây là match chính xác, không phụ thuộc embedding.
- **Rerank:** nếu có cross-encoder, rerank để tăng context_precision (giảm chunk thừa).

Mục tiêu: mỗi alert thường nên kéo về một `port_profile`, một `conn_state`, một vài
`traffic_pattern`/`technique` liên quan. Đây là context đủ để LLM viết explanation grounded.

---

## 3. Định dạng lưu trữ

Theo đúng schema parquet hiện có để tương thích pipeline: mỗi chunk gồm
`chunk_id, doc_id, source, text, metadata(JSON)`. Trong đó:
- `source` = `kb_v2` (phân biệt với MITRE/ET/Sigma thô cũ).
- `text` = phần nội dung diễn giải (sẽ được embed).
- `metadata` = JSON chứa `kb_type` + các trường filter (`port`, `state_code`, `technique_id`...).

Một entry = một chunk độc lập, đủ nghĩa khi đứng riêng (tránh lỗi chunk-vỡ-giữa-câu như bản
MITRE thô trước đây).

---

## 4. Quy tắc chống leakage (BẮT BUỘC)

KB phải được xây **độc lập hoàn toàn** với test set, từ kiến thức tổng quát (IANA, NVD, Zeek
docs, MITRE/ET/Sigma), rồi **đóng băng**, rồi mới chạy test. Tuyệt đối KHÔNG nhìn vào các flow
cụ thể trong test rồi viết diễn giải cho khớp chúng — đó là leakage làm mọi metric trở nên ảo.
Đây cũng là cơ chế đảm bảo RAGAS faithfulness/recall đo đúng khả năng **generalize**, không
phải khả năng nhớ.

**Vì sao RAG vẫn có giá trị dù LLM "đã biết" nhiều thứ — vai trò "trí nhớ đã kiểm duyệt":**
Các trường diễn giải (role, attack_surface, normal_baseline) được enrich offline MỘT LẦN, có
prompt cẩn thận và có review/sửa, rồi đóng băng thành KB. Lúc runtime LLM retrieve tri thức đã
chuẩn hóa và kiểm chứng này thay vì sinh tự do mỗi lần (vốn không nhất quán, dễ hallucinate,
không truy vết được). RAG do đó biến tri thức bất định của LLM thành tri thức cố định, truy vết
và đánh giá được — một lý do chính đáng để RAG tồn tại kể cả khi LLM "về lý thuyết đã biết".

---

## 5. Quyết định taxonomy (ĐÃ CHỐT)

**Đánh giá ở tactic-level.** UWF-ZeekData24 label theo MITRE (tactic + technique, technique là
mã T-code), IoT-23 label theo loại hành vi malware của Stratosphere (không có technique-level,
vd `PartOfAHorizontalPortScan`). Hai hệ technique KHÔNG cùng không gian giá trị nên không gộp
trực tiếp được.

Quyết định: `label_tactic` là anchor cho ground truth và chấm điểm (hai dataset hòa hợp tốt).
`label_technique` KHÔNG cần map giữa hai dataset — chỉ giữ làm metadata phụ để tham khảo/phân
tích. Do đó nhóm 4 (technique references) cũng được tổ chức và đánh giá ở mức tactic, không bắt
buộc khớp technique-level chính xác.

---

## 6. Checklist tiến độ

### Pipeline tổng thể
- [x] `zeek_alert_builder.py` — sinh alert fact-only (bóc interpretation, port trần)
- [x] Chốt dataset test: UWF-ZeekData24 (slice) + IoT-23 (đã align schema)
- [x] Chốt taxonomy đánh giá: tactic-level
- [ ] Sinh test set (stratified sample + alert text + ground truth)
- [ ] Pipeline RAG end-to-end (retriever + LLM)
- [ ] Chạy RAGAS, báo cáo metric tách theo dataset

### Knowledge base — Nhóm 1 (port_profile)
- [x] Lập danh sách port (16 port)
- [x] Bảng map port → product_slugs + keywords (`port_product_map_draft.md`)
- [x] Lọc CVE từ corpus (top 3 theo CVSS, ưu tiên slug)
- [x] Soạn role / attack_surface / normal_baseline (đã sửa theo review)
- [x] Soạn detection_hints (đặc thù dịch vụ)
- [x] Sinh `port_profiles.jsonl` + `port_profiles_review.md`
- [x] **Bạn review**: gạch CVE nhiễu (vd CVE-2015-7182 NSS ở 4848), chỉnh detection_hints/baseline
- [x] Đóng băng Nhóm 1

### Knowledge base — Nhóm 2 (conn_state)
- [x] Soạn entry cho 13 conn_state (wire_meaning + behavioral_interpretation, hedge)
- [x] Sinh `conn_state_profiles.jsonl` + `conn_state_review.md`
- [x] **Bạn review**: chỉnh behavioral_interpretation nếu cần
- [x] Đóng băng Nhóm 2

### Knowledge base — Nhóm 3 (traffic_pattern) — chứa HÀNH VI CHUNG
- [x] Soạn 12 pattern (6 single_flow + 6 multi_flow), metadata `scope`
- [x] Đổi tên trung lập (client/server-dominant bulk transfer thay vì exfil/download)
- [x] Multi-flow patterns ghi rõ "cần nhiều flow, single flow = part of"
- [x] Sinh `traffic_pattern_profiles.jsonl` + `traffic_pattern_review.md`
- [x] **Bạn review**: chỉnh interpretation nếu cần
- [x] Đóng băng Nhóm 3

### Knowledge base — Nhóm 4 (tactic) — MITRE ATT&CK framework context
- [x] Đổi tên: technique → tactic (kb_type=tactic, tactic_profiles.jsonl)
- [x] Cover toàn bộ 14 tactic MITRE (không phụ thuộc dataset → không leakage)
- [x] Schema: attacker_objective, network_context, representative_techniques (3-5),
      kill_chain_relationships
- [x] Network context giữ khái quát (không lấn Nhóm 3), đã sửa theo review
- [x] Collection nhấn staging, Impact nhấn disruption/availability
- [x] Sinh `tactic_profiles.jsonl` + `tactic_review.md`
- [x] **Bạn review**: chỉnh network_context / kill_chain nếu cần
- [x] Đóng băng Nhóm 4

### Ingest & retrieval
- [ ] Quyết định: 4 nhóm chung 1 collection hay tách riêng (ảnh hưởng `where` filter)
- [ ] Script ingest ChromaDB
- [ ] Logic dedup chunk (vd 20&21, 110&143 trùng CVE — điểm Gemini nêu)
- [ ] Hybrid retrieval: Nhóm 1 filter port, Nhóm 2 filter state_code, Nhóm 3 semantic top-3,
      Nhóm 4 filter tactic (eval) hoặc semantic top-2 (production)
- [ ] Rerank (cross-encoder)
