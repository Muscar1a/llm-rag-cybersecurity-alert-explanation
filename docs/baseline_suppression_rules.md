# Baseline Suppression Rules — Network Traffic
> **Mục tiêu:** Lọc Benign trước khi đưa vào RAG alert pipeline, giảm false positive  
> **Tổng:** 34 rules · 8 categories · 6 Suppress · 28 Alert  
> **Nguồn tham chiếu:** CICIDS-2018 dataset analysis

---

## Quy ước

| Action | Ý nghĩa |
|--------|---------|
| `SUPPRESS` | Bỏ qua hoàn toàn, không đưa vào alert pipeline |
| `LOW` | Log lại để audit, không escalate |
| `MEDIUM` | Tạo alert, analyst cần xem xét |
| `HIGH` | Escalate ngay lập tức |

---

## 1. Baseline — Benign Suppression

> Áp dụng **trước tiên**. Nếu flow khớp bất kỳ rule nào trong section này → SUPPRESS, không xử lý tiếp.

### BL-001 · Normal HTTPS Handshake
- **Action:** `SUPPRESS`
- **Mô tả:** Port 443, packet count thấp, duration ngắn, server-dominant byte ratio trong ngưỡng bình thường, không có RST/URG flag
- **Condition:**
  ```
  dst_port = 443
  AND tot_pkts <= 30
  AND duration < 500ms
  AND byte_ratio <= 15
  AND rst_flag = 0
  AND urg_flag = 0
  ```
- **Rationale:** Giải quyết trực tiếp lỗi false positive trong RAG pipeline — HTTPS session server-dominant là bình thường khi client tải nội dung lớn.

---

### BL-002 · Normal HTTP Handshake
- **Action:** `SUPPRESS`
- **Mô tả:** Port 80, packet count thấp, byte ratio trong ngưỡng bình thường
- **Condition:**
  ```
  dst_port = 80
  AND tot_pkts <= 20
  AND duration < 300ms
  AND byte_ratio <= 10
  ```

---

### BL-003 · TCP 3-Way Handshake Bình Thường
- **Action:** `SUPPRESS`
- **Mô tả:** Handshake hoàn chỉnh SYN→SYN-ACK→ACK, không có data transfer, duration cực ngắn
- **Condition:**
  ```
  syn_cnt = 1
  AND ack_cnt = 1
  AND fin_cnt = 0
  AND rst_cnt = 0
  AND total_bytes < 100
  AND duration < 5ms
  ```
- **Rationale:** Tránh flag nhầm các connection setup hợp lệ.

---

### BL-004 · DNS Query Bình Thường
- **Action:** `SUPPRESS`
- **Mô tả:** UDP port 53, payload nhỏ, ít packet, duration ngắn
- **Condition:**
  ```
  protocol = UDP
  AND dst_port = 53
  AND payload < 512
  AND tot_pkts <= 2
  AND duration < 200ms
  ```

---

### BL-005 · NTP Sync Bình Thường
- **Action:** `SUPPRESS`
- **Mô tả:** UDP port 123, 1–2 packets, payload đúng chuẩn NTP
- **Condition:**
  ```
  protocol = UDP
  AND dst_port = 123
  AND tot_pkts <= 2
  AND payload <= 76
  ```

---

### BL-006 · ICMP Echo Request/Reply Bình Thường
- **Action:** SUPPRESS
- **Condition:**
```
  Protocol = 1                          -- ICMP
  AND Flow Pkts/s < 5
  AND (TotLen Fwd Pkts + TotLen Bwd Pkts) / (Tot Fwd Pkts + Tot Bwd Pkts) <= 64
                                        -- avg packet size ≈ payload nhỏ
  AND Tot Fwd Pkts <= 10                -- short flow, không phải flood
  AND Tot Bwd Pkts <= 10
```
---

## 2. DoS / DDoS

### DOS-001 · SYN Flood
- **Action:** `HIGH`
- **Mô tả:** SYN liên tục không có ACK follow-up, rate cực cao — dấu hiệu cổ điển của SYN flood
- **Condition:**
  ```
  syn_cnt > 0
  AND ack_cnt = 0
  AND fin_cnt = 0
  AND flow_pkts_per_s > 1000
  AND duration < 10s
  ```
- **Lưu ý:** Cross-check syn_cnt > 0 trước khi kết luận — lỗi phổ biến của model là gán "SYN flood" khi syn_cnt = 0.

---

### DOS-002 · UDP Flood
- **Action:** `HIGH`
- **Mô tả:** UDP volume cực lớn, nhiều destination port, payload ngẫu nhiên
- **Condition:**
  ```
  protocol = UDP
  AND flow_byts_per_s > 5,000,000
  AND dst_port_entropy > 0.8
  ```

---

### DOS-003 · ICMP Flood (Smurf / Ping Flood)
- **Action:** `HIGH`
- **Mô tả:** ICMP rate vượt ngưỡng hoặc gửi tới broadcast address
- **Condition:**
  ```
  protocol = ICMP
  AND (pkt_rate > 100 pkt/s OR dst = broadcast)
  ```

---

### DOS-004 · HTTP Slowloris
- **Action:** `MEDIUM`
- **Mô tả:** Nhiều connection song song, IAT rất lớn, payload mỗi packet rất nhỏ — giữ socket mở cạn kiệt server
- **Condition:**
  ```
  dst_port IN (80, 443)
  AND fwd_iat_mean > 30,000ms
  AND fwd_pkt_len_mean < 50
  AND active_conn > 50
  ```

---

### DOS-005 · DNS Amplification
- **Action:** `HIGH`
- **Mô tả:** Response/request ratio cực lớn trên UDP 53 — attacker lợi dụng DNS server làm amplifier
- **Condition:**
  ```
  protocol = UDP
  AND dst_port = 53
  AND byte_ratio > 10
  AND tot_bwd_bytes > 10,000
  ```

---

### DOS-006 · ACK Flood
- **Action:** `MEDIUM`
- **Mô tả:** ACK-only packet rate cao, không có SYN trước đó trong session
- **Condition:**
  ```
  ack_cnt > 0
  AND syn_cnt = 0
  AND fin_cnt = 0
  AND flow_pkts_per_s > 500
  ```

---

## 3. Port Scan

### SCAN-001 · TCP SYN Scan (Stealth)
- **Action:** `MEDIUM`
- **Mô tả:** Nhiều dst port khác nhau từ 1 src, SYN không có ACK follow-up, duration cực ngắn mỗi flow
- **Condition:**
  ```
  distinct_dst_ports > 20
  AND syn_cnt > 0
  AND ack_cnt = 0
  AND duration_per_flow < 2ms
  ```

---

### SCAN-002 · Full TCP Connect Scan
- **Action:** `MEDIUM`
- **Mô tả:** 3-way handshake tới nhiều port, ngay sau đó FIN/RST, không có data transfer thực sự
- **Condition:**
  ```
  distinct_dst_ports > 20
  AND syn_cnt > 0
  AND fin_cnt > 0
  AND fwd_act_data_pkts = 0
  ```

---

### SCAN-003 · UDP Port Scan
- **Action:** `MEDIUM`
- **Mô tả:** UDP tới nhiều port khác nhau, response là ICMP unreachable
- **Condition:**
  ```
  protocol = UDP
  AND distinct_dst_ports > 30
  AND icmp_unreachable_ratio > 0.5
  ```

---

### SCAN-004 · OS Fingerprinting (Xmas / FIN / NULL Scan)
- **Action:** `HIGH`
- **Mô tả:** Combination flag bất thường — Xmas scan (URG+PSH+FIN), NULL scan (không có flag nào)
- **Condition:**
  ```
  (urg_cnt > 0 AND psh_cnt > 0 AND fin_cnt > 0)   -- Xmas scan
  OR
  (syn_cnt = 0 AND ack_cnt = 0 AND fin_cnt = 0
   AND rst_cnt = 0 AND psh_cnt = 0)                 -- NULL scan
  ```

---

### SCAN-005 · Service Version Scan (Banner Grab)
- **Action:** `LOW`
- **Mô tả:** Kết nối SYN→ACK, nhận ít bytes banner từ server, RST ngay — lặp lại trên nhiều port
- **Condition:**
  ```
  syn_cnt = 1
  AND ack_cnt = 1
  AND rst_cnt = 1
  AND tot_bwd_bytes > 0
  AND tot_bwd_bytes < 200
  AND distinct_dst_ports > 5
  ```

---

## 4. Brute Force

### BF-001 · SSH Brute Force
- **Action:** `HIGH`
- **Mô tả:** Port 22, nhiều connection thất bại liên tiếp từ 1 src, RST ratio cao
- **Condition:**
  ```
  dst_port = 22
  AND conn_per_min > 10
  AND avg_duration < 3s
  AND rst_ratio > 0.5
  ```

---

### BF-002 · RDP Brute Force
- **Action:** `HIGH`
- **Mô tả:** Port 3389, tần suất kết nối cao, byte ratio thấp (auth fail không transfer data)
- **Condition:**
  ```
  dst_port = 3389
  AND conn_per_min > 5
  AND avg_byte_ratio < 1.5
  AND avg_duration < 5s
  ```

---

### BF-003 · HTTP Login Brute Force
- **Action:** `MEDIUM`
- **Mô tả:** POST tới cùng URL nhiều lần/phút, response size đồng đều (dấu hiệu auth fail đồng nhất)
- **Condition:**
  ```
  dst_port IN (80, 443)
  AND http_method = POST
  AND req_per_min > 20
  AND bwd_pkt_len_std < 50
  ```

---

### BF-004 · FTP Brute Force
- **Action:** `MEDIUM`
- **Mô tả:** Port 21, nhiều kết nối ngắn liên tiếp, byte thấp mỗi flow
- **Condition:**
  ```
  dst_port = 21
  AND conn_per_min > 10
  AND avg_duration < 2s
  AND avg_bytes_per_flow < 200
  ```

---

## 5. Data Exfiltration

### EX-001 · Large Outbound Upload Bất Thường
- **Action:** `HIGH`
- **Mô tả:** Upload lớn trên port không phải backup/cloud thông thường, ngoài giờ hành chính
- **Condition:**
  ```
  fwd_bytes > 10,000,000
  AND dst_port NOT IN (443, 80, 22, 2049)
  AND time NOT IN (business_hours)
  AND dst = external_ip
  ```

---

### EX-002 · DNS Tunneling
- **Action:** `HIGH`
- **Mô tả:** DNS query với subdomain cực dài, entropy cao, tần suất cao — dấu hiệu covert channel
- **Condition:**
  ```
  dst_port = 53
  AND avg_query_len > 50 chars
  AND query_entropy > 3.5
  AND query_rate > 20 queries/min
  ```

---

### EX-003 · ICMP Tunneling
- **Action:** `HIGH`
- **Mô tả:** ICMP payload vượt quá chuẩn ping (64B), data entropy cao, nhiều packet liên tục
- **Condition:**
  ```
  protocol = ICMP
  AND payload > 64
  AND pkt_rate > 10 pkt/s
  AND icmp_data_entropy > 3.0
  ```

---

### EX-004 · Outbound HTTP Upload Lớn
- **Action:** `MEDIUM`
- **Mô tả:** POST/PUT body lớn tới external IP không thuộc known cloud provider
- **Condition:**
  ```
  http_method IN (POST, PUT)
  AND body_size > 1,000,000
  AND dst NOT IN (known_cloud_ranges)
  ```

---

## 6. C2 / Beaconing

### C2-001 · Periodic Beaconing (Fixed Interval)
- **Action:** `HIGH`
- **Mô tả:** Flow IAT std rất thấp so với mean — kết nối đều đặn như đồng hồ, đặc trưng của C2 beacon
- **Condition:**
  ```
  flow_iat_std < 0.05 * flow_iat_mean
  AND tot_flows > 10
  AND dst = external_ip
  ```
- **Rationale:** Indicator mạnh nhất để phát hiện beaconing với ít false positive. Malware thường beacon theo interval cố định.

---

### C2-002 · Heartbeat Trên Port Không Phổ Biến
- **Action:** `HIGH`
- **Mô tả:** Kết nối ra ngoài đều đặn tới port lạ, payload nhỏ và kích thước cố định
- **Condition:**
  ```
  dst_port NOT IN (80, 443, 53, 22, 25)
  AND pkt_len_std < 10
  AND conn_interval_std < 500ms
  AND dst = external_ip
  ```

---

### C2-003 · Long Duration Low-Volume Connection
- **Action:** `MEDIUM`
- **Mô tả:** Kết nối tồn tại rất lâu nhưng transfer rất ít data — dấu hiệu C2 keep-alive hoặc RAT idle
- **Condition:**
  ```
  duration > 3,600s
  AND total_bytes < 50,000
  AND dst = external_ip
  ```

---

### C2-004 · Domain Generation Algorithm (DGA)
- **Action:** `HIGH`
- **Mô tả:** Kết nối tới nhiều domain có entropy tên cao, NX domain ratio cao, không có lịch sử DNS
- **Condition:**
  ```
  dns_nxdomain_ratio > 0.3
  AND avg_domain_entropy > 3.8
  AND distinct_domains > 50 per hour
  ```

---

## 7. Web Attack

### WEB-001 · SQL Injection Attempt
- **Action:** `HIGH`
- **Mô tả:** HTTP payload chứa pattern SQL đặc trưng, kết hợp response bất thường
- **Condition:**
  ```
  http_payload MATCHES sql_patterns
    (UNION, SELECT, OR 1=1, --, SLEEP(), WAITFOR)
  AND (bwd_bytes > fwd_bytes * 5 OR http_status = 500)
  ```

---

### WEB-002 · Directory / Path Traversal
- **Action:** `HIGH`
- **Mô tả:** URL chứa `../` hoặc encoded variant, request tới file nhạy cảm
- **Condition:**
  ```
  http_uri MATCHES traversal_patterns
    (\.\./, %2e%2e%2f, ..%2f, %252e%252e)
  AND http_status IN (200, 403)
  ```

---

### WEB-003 · Web Scanner Fingerprint (Nikto / OWASP ZAP)
- **Action:** `MEDIUM`
- **Mô tả:** Nhiều request 4xx liên tiếp, User-Agent khớp known scanner, path diversity cao
- **Condition:**
  ```
  http_4xx_ratio > 0.4
  AND req_per_min > 60
  AND (ua MATCHES scanner_ua_list OR path_variety > 100)
  ```

---

## 8. Miscellaneous

### MISC-001 · ECE Flag Bất Thường
- **Action:** `LOW`
- **Mô tả:** ECE flag xuất hiện mà không có congestion context (CWR=0, window không giảm) — anomaly nhưng thường Benign
- **Condition:**
  ```
  ece_cnt > 0
  AND cwe_cnt = 0
  AND window_reduction = false
  ```
- **Rationale:** Xuất hiện phổ biến trong dataset CICIDS-2018 trên các flow Benign. Chỉ log, không escalate.

---

### MISC-002 · Init TCP Window Quá Nhỏ
- **Action:** `LOW`
- **Mô tả:** Client init window < 200B — có thể là custom stack, IoT device, hoặc evasion technique
- **Condition:**
  ```
  init_fwd_win_bytes < 200
  AND init_fwd_win_bytes > 0
  ```
- **Rationale:** Init window = 8192B (Windows XP/2003) và các giá trị phổ biến khác không nên bị flag là "non-standard". Chỉ flag khi < 200B.

---

## Thứ Tự Áp Dụng (Processing Order)

```
Flow đến
    │
    ▼
[1] Kiểm tra Baseline rules (BL-001 → BL-006)
    │   Khớp → SUPPRESS (dừng, không xử lý tiếp)
    │
    ▼
[2] Kiểm tra DoS rules (DOS-001 → DOS-006)
    │   Khớp HIGH → Escalate ngay
    │
    ▼
[3] Kiểm tra Scan rules (SCAN-001 → SCAN-005)
    │
    ▼
[4] Kiểm tra Brute Force rules (BF-001 → BF-004)
    │
    ▼
[5] Kiểm tra Exfiltration rules (EX-001 → EX-004)
    │
    ▼
[6] Kiểm tra C2/Beacon rules (C2-001 → C2-004)
    │
    ▼
[7] Kiểm tra Web Attack rules (WEB-001 → WEB-003)
    │
    ▼`
[8] Kiểm tra Misc rules (MISC-001 → MISC-002)
    │
    ▼
[9] Không khớp rule nào → Đưa vào RAG pipeline
```

---

## Tóm Tắt Theo Category

| Category | Rules | Suppress | Low | Medium | High |
|----------|-------|----------|-----|--------|------|
| Baseline | 6 | 6 | — | — | — |
| DoS/DDoS | 6 | — | — | 2 | 4 |
| Port Scan | 5 | — | 1 | 3 | 1 |
| Brute Force | 4 | — | — | 2 | 2 |
| Data Exfil | 4 | — | — | 1 | 3 |
| C2/Beacon | 4 | — | — | 1 | 3 |
| Web Attack | 3 | — | — | 1 | 2 |
| Misc | 2 | — | 2 | — | — |
| **Total** | **34** | **6** | **3** | **10** | **15** |

---

*Tài liệu này được tạo từ phân tích RAG output trên CICIDS-2018 dataset.*  
*Version 1.0 — Cần review và tune threshold theo môi trường thực tế của tổ chức.*
