"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_FILE = Path(__file__).resolve().parent.parent / "data" / "customers.json"


def _hash_args(args: dict) -> str:
    s = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    agent_id = "lab24-agent"
    expires_at = "2099-01-01T00:00:00+00:00"
    ts = datetime.now(timezone.utc).isoformat()

    # ================= RUN A =================
    # Tìm kiếm tài liệu, chỉ cho phép tool search_docs
    run_a_id = "run-a"
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner=f"{agent_id}/{run_a_id}",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=("search_docs",),
        expires_at=expires_at,
    )
    allow_search, reason_search = check(ctx_search)
    ledger.append({
        "ts": ts,
        "agent_id": agent_id,
        "run_id": run_a_id,
        "tool": "search_docs",
        "args_hash": _hash_args({"query": message}),
        "classification": "internal",
        "decision": "allow" if allow_search else "deny",
        "reason": reason_search,
        "on_behalf_of": principal_id,
        "expires_at": expires_at,
    }, ledger_path)

    if not allow_search:
        return "Yêu cầu bị từ chối bởi chính sách."

    docs = tools.search_docs(message)

    # Trích xuất typed ticket_ids từ tên file (vd: ticket-001.md -> 1)
    ticket_ids = []
    for d in docs:
        m = re.search(r"ticket-(\d+)", d["id"])
        if m:
            ticket_ids.append(int(m.group(1)))

    # ================= RUN B =================
    # Phục vụ đọc customer records qua related_tickets (Trifecta Split)
    run_b_id = "run-b"
    customers_data = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))

    # Lấy customer_ids hợp lệ dựa vào ticket_ids từ Run A
    target_customers = []
    for c in customers_data:
        if any(t in c.get("related_tickets", []) for t in ticket_ids):
            target_customers.append(c["customer_id"])

    # Nếu không tìm thấy khách nào gắn với ticket nhưng principal là support_l1
    # Vẫn cần kiểm tra PEP khi có tác vụ đọc customer để đảm bảo ghi nhận deny vào ledger
    candidate_cids = target_customers if target_customers else (["KH-000999"] if principal_id == "support_l1" else [])

    for cid in candidate_cids:
        ctx_customer = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=f"{agent_id}/{run_b_id}",
            delegation_depth=1,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=("search_docs", "read_customer"),
            parent_scopes=("search_docs", "read_customer") if principal_id == "dpo" else ("search_docs",),
            expires_at=expires_at,
        )
        allow_cust, reason_cust = check(ctx_customer)
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_b_id,
            "tool": "read_customer",
            "args_hash": _hash_args({"customer_id": cid}),
            "classification": "restricted",
            "decision": "allow" if allow_cust else "deny",
            "reason": reason_cust,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        }, ledger_path)

        if allow_cust:
            try:
                tools.read_customer(cid)
            except Exception:
                pass

    return llm.summarize(docs)
