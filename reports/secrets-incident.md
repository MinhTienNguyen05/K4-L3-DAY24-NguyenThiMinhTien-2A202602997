# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản: Gitleaks v8.30.1
- Commit chứa token giả: 1bdd849
- File, rule và kết quả quét lịch sử: Rule lab24-synthetic-token phát hiện token giả LAB24_FAKE_TOKEN tại commit 1bdd849. Lệnh gitleaks git trả về exit code 1 với 1 finding đúng như dự kiến.
- Kết quả quét file hiện tại: Lệnh gitleaks dir trên thư mục làm việc hiện tại không tìm thấy secret nào (0 finding, exit code 0).
- Nếu đây là credential thật, cần xử lý thế nào: Cần lập tức thu hồi / rotate secret tại hệ thống cấp phát (IdP/IAM/nhà cung cấp dịch vụ), kiểm tra audit log phát hiện lạm dụng và làm sạch lịch sử Git.
- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ: Xoá file ở commit mới chỉ ẩn file khỏi HEAD nhưng secret vẫn tồn tại trong lịch sử Git; pin dependency và hook chỉ ngăn chặn mã độc mới chứ không thể tự động thu hồi một secret đã bị lộ ra ngoài.