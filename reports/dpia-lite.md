# DPIA-lite — điền trong checkpoint 5

1. Loại dữ liệu và phân loại:
- Dữ liệu ticket hỗ trợ khách hàng: Phân loại `internal`. Chứa nội dung khiếu nại, phản hồi của người dùng và các ghi chú hỗ trợ trong thư mục `corpus/`.
- Dữ liệu thông tin cá nhân khách hàng (PII): Phân loại `restricted`. Chứa thông tin nhạy cảm của khách hàng trong `data/customers.json`, bao gồm: Họ tên, Số CCCD (12 chữ số), Số điện thoại (bắt đầu bằng 0), Số tài khoản ngân hàng (8-16 chữ số), Địa chỉ email, và danh sách ticket liên quan (`related_tickets`).
2. Mục đích xử lý và principal:
- `support_l1`:
  - Mục đích: `summarize-tickets`, `support-reply`.
  - Quyền hạn: Chỉ được phép gọi `search_docs` để tra cứu và tóm tắt ticket; bị cấm tuyệt đối truy cập hồ sơ khách hàng (`read_customer`) và cấm gọi mạng ra ngoài (`http_post`).
- `dpo`:
  - Mục đích: `summarize-tickets`, `support-reply`, `privacy-audit`.
  - Quyền hạn: Được phép gọi `search_docs` và `read_customer` đối với các khách hàng gắn với ticket hợp lệ trong luồng giải quyết hỗ trợ; bị cấm tuyệt đối gọi mạng ra ngoài (`http_post`) khi xử lý dữ liệu `restricted`.
3. Dữ liệu đi qua những run/tool nào, endpoint nào:
- Run A (Untrusted Data Ingestion):
  - Nhận truy vấn từ người dùng, gọi `tools.search_docs` (chân 1 của trifecta) để đọc các file `.md` trong `corpus/`.
  - Trích xuất danh sách số ticket ID hoàn toàn từ tên file (ví dụ `ticket-901.md` -> `901`).
  - Nội dung text tự do của document bị chặn lại tại Run A; PII Gate (`agent/pii.py`) phát hiện và che giấu (redact) các giá trị nhạy cảm trước khi đưa vào context.
- Run B (Private Store Access):
  - Chỉ nhận danh sách typed `ticket_ids` từ Run A, sau đó tra cứu nguồn tin cậy `data/customers.json` qua trường `related_tickets` để xác định danh tính khách hàng hợp lệ.
  - Đi qua cổng Policy (`agent/policy.py`) trước khi gọi `tools.read_customer` (chân 2 của trifecta).
- Cổng PEP & Egress Endpoint:
  - Khi có chỉ thị injection yêu cầu gọi `tools.http_post` (chân 3 của trifecta) ra endpoint localhost `http://127.0.0.1:10024/reconcile`, PEP áp dụng rule tối thiểu chặn đứng request do dữ liệu thuộc loại `restricted` và `egress_enabled == True`.
- Audit Ledger:
  - Tất cả các yêu cầu gọi tool (kể cả `allow` hay `deny`) đều được ghi vết vào `reports/ledger.jsonl` kèm mã băm tham số (`args_hash`), danh tính ủy quyền (`on_behalf_of`), định danh tác vụ (`agent_id`, `run_id`), thời hạn (`expires_at`) và lý do (`reason`).

4. Bằng chứng deny/allow và giới hạn của mock:
- Bằng chứng kỹ thuật:
  - `reports/attack-before.log`: Chứa request exfiltration thành công mang toàn bộ PII của `KH-000999` ra sink trước khi có biện pháp kiểm soát.
  - `reports/attack-after.log`: Có kích thước chính xác 0 byte, chứng minh không còn bất kỳ request rò rỉ PII nào thoát ra ngoài sau khi triển khai containment.
  - `reports/ledger.jsonl`: Lưu đầy đủ dòng `http_post` với `decision=deny`, `classification=restricted`, `on_behalf_of=dpo` và `reason="DENY: Egress is strictly forbidden on restricted data."`.
  - Lệnh kiểm tra tính toàn vẹn `agent.ledger.verify(Path('reports/ledger.jsonl'))` trả về `True`.
- Giới hạn của hệ thống lab / mock:
  - Xác thực: Tham số `--as` chỉ đọc quyền giả lập từ file cấu hình tĩnh `data/principals.json`, không phải cơ chế xác thực danh tính người dùng thực tế (như SSO, OAuth2/OIDC, mTLS).
  - Mô hình ngôn ngữ: Đánh giá dựa trên `MockLLM` nhận diện pattern cố định; chưa phản ánh toàn diện tính ngẫu nhiên hay các kỹ thuật jailbreak phức tạp trên LLM production.
  - PII Gate: Dựa vào biểu thức chính quy (regex), có thể bỏ sót các mẫu viết tắt bất thường hoặc sinh ra false positive/false negative với dữ liệu phi cấu trúc phức tạp.
  - Audit Ledger: Chuỗi băm SHA-256 cục bộ phát hiện được việc sửa đổi/chèn/xóa dòng ở giữa file, nhưng không tự ngăn chặn được việc cắt bỏ dòng cuối hoặc ghi đè toàn bộ file nếu thiếu mốc tin cậy độc lập bên ngoài (như timestamp authority, remote WORM storage hay immutable cloud logging).
