# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
- `python -m pytest tests/ -q`:
- `pre-commit run --all-files`:
- Ledger verify:
- Các lỗi còn lại:



## Chi tiết kết quả kiểm tra từng bước

### CP3a — PII Gate (Precision / Recall)
- Lệnh chạy: `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp`
- Kết quả: `gold=118`, `pred=118`, `tp=118`
- Precision: `1.000` (100%)
- Recall: `1.000` (100%)
- Giới hạn của regex:
  - Phụ thuộc vào các từ khóa (ví dụ "STK", "số tài khoản" cho tài khoản ngân hàng).
  - Không xử lý được các cấu trúc văn bản phi cấu trúc, sai chính tả, hoặc viết tắt phức tạp nếu không có mẫu cố định như mô hình NER chuyên sâu.


