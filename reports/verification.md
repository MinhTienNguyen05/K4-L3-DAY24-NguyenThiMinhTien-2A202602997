# Verification — điền trước khi nộp

- OS / Python / Gitleaks version: macOS / Python 3.11.14 / gitleaks 8.30.1
- `python -m pytest tests/ -q`:
- `pre-commit run --all-files`:
- Ledger verify: True
- Các lỗi còn lại: Không



## Chi tiết kết quả kiểm tra từng bước

### CP3a — PII Gate (Precision / Recall)
- Lệnh chạy: `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp`
- Kết quả: `gold=118`, `pred=118`, `tp=118`
- Precision: `1.000` (100%)
- Recall: `1.000` (100%)
- Giới hạn của regex:
  - Phụ thuộc vào các từ khóa (ví dụ "STK", "số tài khoản" cho tài khoản ngân hàng).
  - Không xử lý được các cấu trúc văn bản phi cấu trúc, sai chính tả, hoặc viết tắt phức tạp nếu không có mẫu cố định như mô hình NER chuyên sâu.


### CP3b, CP3c, CP3e — Policy, OBO & Ledger
- `tests/test_policy.py`: PASSED
- `tests/test_obo.py`: PASSED
- `tests/test_injection.py`: 8/8 PASSED (chặn đứng exfiltration trên cả 4 biến thể dưới support_l1 và dpo)
- `tests/test_ledger.py`: 3/3 PASSED (hash chain hợp lệ, phát hiện can thiệp và yêu cầu reason)
- Ledger verify: `verify(Path('reports/ledger.jsonl')) == True`

### CP4 — Supply Chain & Secrets
- Gitleaks scan history: Phát hiện 1 token giả tại commit `1bdd849` (đúng dự kiến).
- Gitleaks scan directory: 0 findings (sạch).
- `requirements.lock`: Đã tạo đầy đủ sha256 hash cho tất cả dependencies.
- `tests/test_supply_chain.py`: PASSED.

### CP5 — Prove & Containment
- `reports/attack-after.log`: 0 byte.
- `reports/ledger.jsonl`: Đã có dòng deny `http_post` với `on_behalf_of=dpo` và `reason` hợp lệ.
- Lệnh kiểm tra ledger verify: `True`.