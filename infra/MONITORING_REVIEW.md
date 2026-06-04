# Đánh giá Monitoring Setup

> Review các thay đổi: `Makefile`, `docker-compose.yml`, `infra/prometheus.yml`,
> `infra/grafana/**`, `src/api/main.py`, `src/api/middleware.py`, `src/rag/lc_service.py`

**Tổng quan:** Hướng đi tốt và gọn — tách HTTP / retrieval / LLM latency là đúng bài,
dashboard 4 panel hợp lý. Việc `/analyze` đi qua `ChatService.chat` nên retrieval/LLM
metrics được ghi đúng cho cả `/analyze` lẫn `/chat`. Tuy nhiên có vài lỗi khiến monitoring
**không chạy được ngay** khi bật lên.

---

## 🔴 Lỗi chặn (phải sửa, nếu không monitoring không hoạt động)

### 1. Grafana chưa có datasource Prometheus → dashboard lỗi "Datasource not found"

`infra/grafana/dashboards/rag.json` đang ở **định dạng export** (có `"__inputs"` +
`${DS_PROMETHEUS}`). Format này chỉ dùng cho import thủ công qua UI — Grafana sẽ hỏi chọn
datasource. Khi **provisioning bằng file**, Grafana KHÔNG hỏi, và biến `${DS_PROMETHEUS}`
không được thay thế.

Ngoài ra trong `infra/grafana/provisioning/` chỉ có `dashboards.yml`, **không có
`datasources.yml`** → Prometheus chưa được đăng ký làm datasource.

**Cách sửa:**
- Thêm `infra/grafana/provisioning/datasources/datasources.yml` trỏ tới
  `http://prometheus:9090` với `uid` cố định.
- Trong `rag.json`: bỏ `"__inputs"`, thay mọi `"uid": "${DS_PROMETHEUS}"` bằng uid cố định đó.

### 2. Mount volume Grafana sai cấu trúc thư mục

```yaml
# docker-compose.yml (hiện tại)
- ./infra/grafana/provisioning:/etc/grafana/provisioning
- ./infra/grafana/dashboards:/etc/grafana/provisioning/dashboards
```

`dashboards.yml` (provider) đang nằm ở `provisioning/` gốc, còn thư mục JSON lại được mount
đè vào `provisioning/dashboards/`. Cách này dễ vỡ.

**Cách sửa:** Gộp tất cả dưới `infra/grafana/provisioning/{dashboards,datasources}/`, mount
**một** dòng `./infra/grafana/provisioning:/etc/grafana/provisioning`, rồi để `path:` trong
provider trỏ tới nơi chứa file JSON.

---

## 🟠 Lỗi logic (chạy được nhưng số liệu sai / rò rỉ)

### 3. Cardinality nổ vì `session_id` trong path — `src/api/middleware.py:37`

```python
endpoint = request.url.path
```

Với `/chat/{session_id}/history` và `DELETE /chat/{session_id}`, mỗi UUID tạo một label
`endpoint` mới → Prometheus đẻ vô hạn time series (anti-pattern kinh điển). Phải dùng **route
template** thay vì path thật:

```python
route = request.scope.get("route")
endpoint = getattr(route, "path", request.url.path)  # -> "/chat/{session_id}/history"
```

### 4. Lỗi 5xx do exception không được đếm — `src/api/middleware.py:39-46`

`call_next` ném exception khi endpoint lỗi → các dòng `observe/inc` bị bỏ qua, panel
"Error Rate" sẽ không thấy lỗi nặng nhất. Bọc `try/finally` và đếm status 500 ở nhánh
`except`.

---

## 🟡 Góp ý nhỏ (tùy chọn, không gấp)

- **`retrieval_duration = t_total - llm_duration`** (`src/rag/lc_service.py:106`): đây là
  "thời gian ngoài LLM" chứ không thuần retrieval (gồm cả parse, build prompt, callback
  overhead). Với đồ án thì chấp nhận được, nhưng nên đổi tên / ghi chú để khỏi hiểu nhầm.
  Lưu ý history-aware retriever có **2 lần gọi LLM** (condense + answer) — code đã cộng đúng
  cả 2 nên phần này ổn.
- **Prometheus không có volume** → restart là mất data. Đồ án có thể bỏ qua, demo lại từ đầu.
- `infra/prometheus.yml` không khai báo `metrics_path` — OK vì mặc định `/metrics` khớp với
  mount của app.
- Dashboard panel #3 chỉ lọc `endpoint="/analyze"`; nếu demo chủ yếu qua `/chat` thì panel
  sẽ trống.

---

## Ưu tiên sửa

| # | Mức độ | File | Tóm tắt |
|---|--------|------|---------|
| 1 | 🔴 | `infra/grafana/provisioning/`, `rag.json` | Thêm datasource Prometheus + bỏ `__inputs` |
| 2 | 🔴 | `docker-compose.yml`, `dashboards.yml` | Sửa cấu trúc mount provisioning |
| 3 | 🟠 | `src/api/middleware.py` | Dùng route template thay path thật |
| 4 | 🟠 | `src/api/middleware.py` | Đếm lỗi 5xx bằng try/finally |

Sửa 4 mục trên là đủ để `make monitoring` chạy đúng ngay.
