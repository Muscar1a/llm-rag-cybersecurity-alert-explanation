# Prompt v3

> Cơ sở: benchmark `benchmark_basic_v3.json`, 135 samples, template `basic`.
> Số liệu tổng thể: Faithfulness = 0.429 · Context Recall = 0.658 · Answer Relevancy = 0.509 · Hallucination Rate = 0.571

---

## Vấn đề 1 — Negative citation constraint không hiệu quả với small LLM

**Mô tả:** Prompt hiện tại dùng dạng cấm: *"do NOT introduce CVEs, technique IDs, or rule names from training-data memory"*. Với model 7B, negative constraint yêu cầu model nhận ra ý định vi phạm *trước khi* generate token — điều này thường không xảy ra khi gặp trigger mạnh (tên service quen như GlassFish, port đặc trưng như 4848).

**Bằng chứng:**
- Faithfulness tổng thể = **0.429**, hallucination rate = **0.571** — hơn nửa số claim trong output không trace được về retrieved context.
- Credential_Access tệ nhất: faithfulness = **0.247**. Các alert port 4848/GlassFish kích hoạt LLM liên tưởng đến CVE cụ thể và technique ID từ training data dù prompt đã cấm rõ ràng.

---

## Vấn đề 2 — Severity không có anchor định lượng

**Mô tả:** Prompt chỉ liệt kê bốn nhãn `Low | Medium | High | Unknown` mà không định nghĩa boundary dựa trên observable. LLM tự suy severity từ prior knowledge (e.g. "GlassFish = critical service → High") thay vì từ retrieved context — đây là dạng hallucination về severity, không phải về fact.

**Bằng chứng:**
- Answer Relevancy tổng thể = **0.509**.
- Defense_Evasion đặc biệt thấp: answer relevancy = **0.346**.
- Phân tích mẫu: cùng conn_state REJ + zero bytes nhưng output assign severity không nhất quán tùy port.

---

## Vấn đề 3 — CoT scratchpad không có grounding constraint

**Mô tả:** Template `cot` yêu cầu model reason trong `<scratchpad>` trước khi output JSON. Tuy nhiên scratchpad không có ràng buộc "only reference text from Retrieved Knowledge" — model tự do reason từ memory trong scratchpad, sau đó JSON output chỉ là paraphrase của chain đó thay vì của retrieved context.

**Bằng chứng:** Cần ablation `basic` vs `cot` để xác nhận định lượng. Về mặt cơ chế: khi model "nghĩ" trong scratchpad về GlassFish hay một port quen thuộc, nó dễ pull prior knowledge vào chain of thought, chain này sau đó drive toàn bộ output — bypass citation rules trong system prompt.

---

## Vấn đề 4 — Tactic ambiguity khi context chứa nhiều tactic candidate gần nhau

**Mô tả:** Semantic search k=2 cho tactic retrieval kéo về cả Exfiltration lẫn C2/Command_and_Control vì hai tactic có network signature tương tự trong KB (large outbound transfer, uncommon ports, encrypted channels). Prompt không có cơ chế hướng dẫn LLM prioritize hoặc disambiguate khi context chứa nhiều tactic candidate — dẫn đến output blend cả hai hoặc chọn sai.

**Bằng chứng:**
- Answer Relevancy của Exfiltration = **0.439** — output hay nghiêng về C2/Command_and_Control.
- Đây là hệ quả trực tiếp của semantic search k=2 khi Exfiltration và C2 gần nhau trong embedding space, kết hợp với prompt không disambiguate.

---

## Vấn đề 5 — Grounding rules đặt quá xa điểm generate

**Mô tả:** Toàn bộ grounding rules và citation contract nằm ở đầu system prompt (~600 tokens trước retrieved context và human message). Với attention mechanism của Qwen 7B, instruction ở đầu system prompt bị "loãng" khi model generate — hiện tượng *lost in the middle*. Khi gặp trigger mạnh ở cuối context, model override instruction đã đọc từ đầu.

**Bằng chứng:**
- Hallucination rate cao nhất ở tactic có trigger mạnh: Credential_Access = **0.753** (= 1 − 0.247).
- So với tactic "trung tính" hơn: Defense_Evasion = **0.370**, Reconnaissance = **0.433**.
- Pattern nhất quán: hallucination rate tỉ lệ thuận với mức độ "quen thuộc" của service trong training data.

---

## Tổng hợp

| # | Vấn đề | Metric bị ảnh hưởng | Tactic tệ nhất |
|---|--------|---------------------|----------------|
| 1 | Negative citation constraint | Faithfulness = 0.429 | Credential_Access (0.247) |
| 2 | Severity không có anchor | Answer Relevancy = 0.509 | Defense_Evasion (0.346) |
| 3 | CoT scratchpad không constrained | Faithfulness (cần ablation) | — |
| 4 | Tactic ambiguity trong context | Answer Relevancy Exfiltration = 0.439 | Exfiltration |
| 5 | Grounding rules xa điểm generate | Hallucination rate Credential_Access = 0.753 | Credential_Access |