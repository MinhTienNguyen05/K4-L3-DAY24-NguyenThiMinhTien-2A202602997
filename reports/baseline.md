# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
- Chưa có identity mỗi run
- Hàm `_naive_loop()` chỉ nhận chuỗi đầu vào (`message`) và mô hình ngôn ngữ (`llm`). Nó không yêu cầu hay khởi tạo`agent_id`, `run_id`, hay danh tính người dùng để xác thực
- Bằng chứng tại: `agent/loop.py` tại dòng 27
2. Ai cho phép `http_post`? Dẫn file/hàm:
- Không có cơ chế ho phép `http_post`
- Lệnh `http_post` được thực thi vì hệ thống coi dữ liệu bên trong ticket (do LLM trích xuất qua `injected.target_url`) như là một câu lệnh hợp lệ để chạy
- Bằng chứng tại: `agent/loop.py` tại dòng 35 - 44
3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
- Hệ thống gom toàn bộ hồ sơ khách hàng nhạy cảm (PII) vào biến collected, rồi đưa gói dữ liệu này vào http_post để gửi ra ngoài. Sau đó, máy chủ bên ngoài (file sink/sink.py) sẽ nhận gói dữ liệu này và in thẳng vào log.
- Bằng chứng gửi đi: `agent/loop.py` dòng 44
- Nơi ghi log: `sink/sink.py` dòng 46
