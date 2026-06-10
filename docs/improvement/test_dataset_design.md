# Test Dataset Design — RAG Cybersecurity Alert Explanation

> File này mô tả thiết kế bộ dữ liệu đánh giá (test set) cho hệ thống RAG giải thích cảnh
> báo an ninh mạng. Phần đầu là tổng quan project để người/model đọc lần đầu nắm bối cảnh;
> phần sau là đặc tả test set chi tiết.

---

## 0. Tổng quan project (context cho người/model đọc lần đầu)

**Tên project:** LLM-based Retrieval-Augmented Cybersecurity Alert Explanation System.

**Mục tiêu:** Hệ thống RAG **giải thích từng cảnh báo an ninh mạng đơn lẻ** (single-alert
explanation). Input: một cảnh báo về một network flow. Output: giải thích kỹ thuật gồm
threat description, severity + rationale, mitigation. RAG là **ràng buộc cứng** của đề tài.

**Pipeline:** Zeek conn.log row → `zeek_alert_builder.py` (rule-based, fact-only) → alert
text thuần fact → Retriever → KB (interpretation knowledge) → LLM → explanation → RAGAS.

**Dữ liệu nguồn chính:** UWF-ZeekData24 (Zeek conn.log, label MITRE ATT&CK tactic+technique,
parquet/CSV).

**Alert generation (đã hoàn thiện):** `zeek_alert_builder.py` sinh alert **chỉ chứa fact**
(port number trần, conn_state, byte/packet counts, byte ratio, duration, TCP history, detected
services). Đã bóc bỏ mọi diễn giải và bỏ tên service khỏi port. Label giữ trong **metadata**
(label_tactic, label_technique, label_binary, label_cve), không nằm trong alert text — để làm
ground truth mà không leak đáp án.

**Knowledge base:** xem file `knowledge_base_design.md`. Tóm tắt: KB chứa tri thức diễn giải
khái niệm (port profiles, conn-state semantics, traffic patterns, technique references viết
lại theo góc network-observable), xây độc lập với test set để tránh leakage.

**Bối cảnh chẩn đoán:** RAGAS (faithfulness, context_precision, context_recall) ban đầu đều
thấp do (1) ground truth sinh từ prior knowledge không từ retrieved context, (2) alert cũ chứa
sẵn diễn giải, (3) KB thô lệch domain. Đã/đang khắc phục cả ba.

**Lý do cần test set trộn:** Chỉ test trên UWF dễ khiến hệ thống "thuộc" một dataset. Trộn
thêm IoT-23 (môi trường + loại attack khác hẳn) để chứng minh **generalize** và làm RAGAS
metric đáng tin hơn nhờ phân phối rộng hơn.

---

## 1. Hai thành phần của test set

### Thành phần A — UWF-ZeekData24 (chính)

Slice nhỏ, **stratified theo label_tactic**. Lý do stratified: UWF rất imbalanced (phần lớn
là Reconnaissance/Discovery); sample ngẫu nhiên sẽ chỉ ra một hai loại attack. Lấy cân theo
từng label để test phủ nhiều tactic.

- Định dạng: Zeek conn.log (parquet). Schema khớp trực tiếp với `zeek_alert_builder.py`.
- Cỡ gợi ý: vài nghìn flow, cân bằng giữa các tactic có mặt (kể cả benign nếu có).
- Trường label dùng làm anchor cho ground truth: `label_tactic` (và `label_technique` nếu
  giữ technique-level).

### Thành phần B — IoT-23 (đa dạng hóa) — ĐÃ CHỐT

Dataset malware/benign IoT traffic của Stratosphere Laboratory.

- **Định dạng khớp hoàn hảo:** IoT-23 cung cấp file `conn.log.labeled` — chính là Zeek
  conn.log thu được bằng cách chạy Zeek analyzer trên pcap gốc. Cùng schema conn.log với UWF
  → builder chạy được gần như không cần sửa, vì có sẵn `conn_state`, `history`, `orig_bytes`,
  `resp_bytes`, `duration`, `service`...
- **Bản tải:** dùng bản nhẹ (chỉ README + conn.log, ~8.7GB) để khỏi tải toàn bộ pcap 20GB.
  Nguồn: Stratosphere IPS datasets (datasets-iot23).
- **Đa dạng:** attack type (C&C, DDoS, horizontal port scan, Okiru, Mirai...) và môi trường
  (IoT) khác hẳn UWF (enterprise) → đúng mục tiêu generalization.
- Cỡ gợi ý: slice tương đương thành phần A, cũng stratified theo nhãn hành vi.

**Lưu ý kỹ thuật khi nạp IoT-23:**
- Tên cột conn.log của IoT-23 có thể khác đôi chút so với schema UWF mà builder mong đợi
  (vd `id.resp_p` vs `dest_port_zeek`, `orig_bytes`, `resp_bytes`...). Cần một bước **rename
  cột** để map về đúng tên builder dùng (`dest_port_zeek`, `src_ip_zeek`, `conn_state`,
  `history`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts`, `duration`, `service`).
- Cột label của IoT-23 (`label` / `detailed-label`) đưa vào metadata, KHÔNG vào alert text.

---

## 2. Hòa hợp nhãn (label harmonization)

Hai dataset label theo hai hệ khác nhau:
- UWF-ZeekData24: MITRE ATT&CK (tactic + technique).
- IoT-23: loại hành vi malware (benign, C&C, DDoS, PartOfAHorizontalPortScan, Okiru...).

Cần một bảng map đưa cả hai về **một taxonomy chung** khi đánh giá. Khuyến nghị quy về
**tactic-level** (Reconnaissance, Discovery, Command-and-Control, Exfiltration, Impact,
Initial Access, benign...). Ví dụ map:
- IoT-23 `PartOfAHorizontalPortScan` → Reconnaissance/Discovery.
- IoT-23 `C&C` → Command-and-Control.
- IoT-23 `DDoS` → Impact.
- UWF giữ nguyên tactic của MITRE.

> Đây là quyết định còn mở (tactic-level vs technique-level) — xem mục 5 file
> `knowledge_base_design.md`. IoT-23 không có technique-level nên nếu chọn technique sẽ phải
> xử lý riêng phần IoT-23. Mặc định khuyến nghị: tactic-level.

---

## 3. Quy trình sinh test set (end-to-end)

1. **Sample** stratified từ UWF (theo label_tactic) và từ IoT-23 (theo detailed-label).
2. **Rename cột** IoT-23 về schema builder.
3. **Sinh alert text** bằng `zeek_alert_builder.py` cho cả hai → cột `text` + `metadata`.
4. **Sinh ground truth** cho mỗi alert — xem mục 4.
5. **Đóng gói** thành EvaluationDataset cho RAGAS — xem mục 5.

---

## 4. Ground truth — cách làm ĐÚNG (tránh lỗi ban đầu)

Lỗi ban đầu: Claude sinh ground truth từ alert_text + raw_packet bằng **prior knowledge**,
không liên quan retrieved context → claims không grounded → faithfulness thấp một cách giả tạo.

Cách đúng cho test set này: ground truth phải **neo vào label thật** của dataset (đã có sẵn,
không phải bịa) VÀ vào tri thức trong KB, KHÔNG sinh tự do từ prior knowledge.

Quy trình đề xuất:
- Với mỗi alert, lấy `label_tactic` (ground-truth thật từ dataset) làm khung.
- Sinh `reference` explanation bằng cách cho model viết giải thích **chỉ dựa trên** (a) alert
  text fact-only, (b) label thật, (c) các KB entry liên quan. Cấm dùng kiến thức ngoài.
- Như vậy `reference` vừa đúng (neo label thật), vừa nằm trong không gian tri thức của KB
  (nên context_recall/faithfulness đo đúng khả năng retrieve+ground của hệ thống).

Trường ground truth (giữ schema JSON cũ của project): `threat_description`, `severity`,
`rationale`, `mitigation_step`. Riêng `severity` nên có quy tắc map từ tactic/label để nhất
quán giữa hai dataset, thay vì để model tự cho điểm.

---

## 5. Đóng gói cho RAGAS

Mỗi sample map sang các trường RAGAS như sau:
- `user_input` = alert text (fact-only) — câu hỏi/đầu vào cần giải thích.
- `retrieved_contexts` = list các KB chunk mà retriever kéo về cho alert đó.
- `response` = explanation do hệ thống RAG sinh ra (cái đang được đánh giá).
- `reference` = ground truth explanation (mục 4), neo vào label thật.

Metric và ý nghĩa trong bối cảnh này:
- **Faithfulness**: response có bám vào retrieved KB context không (không hallucinate). Giờ
  đo được đúng, vì alert không còn chứa sẵn kết luận và KB chứa tri thức thật để bám.
- **Context Precision**: KB chunk kéo về có thực sự cần cho explanation không (đo chất lượng
  retriever + rerank).
- **Context Recall**: KB context có cover được thông tin trong reference không (đo retriever
  có bỏ sót tri thức cần thiết không).
- Cân nhắc thêm **Response Relevancy** và **Factual Correctness** (so với reference).

---

## 6. Quy tắc tách bạch (BẮT BUỘC)

- Test set và KB **độc lập**: KB xây từ kiến thức tổng quát rồi đóng băng TRƯỚC khi sinh test.
- Label nằm trong **metadata**, không trong alert text → không leak đáp án vào input.
- Stratified sampling cả hai dataset để metric không bị chi phối bởi class đa số.
- Báo cáo metric **tách theo từng dataset** (UWF riêng, IoT-23 riêng) NGOÀI con số tổng, để
  thấy rõ khả năng generalize sang domain mới (IoT-23) so với domain gốc (UWF).

---

## 7. Quyết định còn mở

- **Độ chi tiết taxonomy** (tactic vs technique) — chốt cùng với KB. Mặc định: tactic-level.
- **Cỡ slice cụ thể** mỗi dataset và mỗi class — phụ thuộc ngân sách token cho việc sinh
  ground truth và chạy RAGAS (mỗi sample tốn nhiều LLM call).
- **Quy tắc map severity** từ label sang {Low, Medium, High, Critical} — cần định nghĩa cố
  định để ground truth nhất quán giữa hai dataset.
