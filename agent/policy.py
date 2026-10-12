"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def check(context: PolicyContext) -> tuple[bool, str]:
    # 1. Kiểm tra classification hợp lệ
    valid_classes = {"public", "internal", "restricted"}
    if context.data_classification not in valid_classes:
        return False, f"Invalid data classification: {context.data_classification}"

    # 2. Rule tối thiểu: restricted + egress bị cấm hoàn toàn
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "DENY: Egress is strictly forbidden on restricted data."

    # 3. Kiểm tra expires_at (UTC)
    if context.expires_at:
        try:
            exp_time = datetime.fromisoformat(context.expires_at)
            now = datetime.now(timezone.utc)
            if exp_time < now:
                return False, f"DENY: Token/session expired at {context.expires_at}"
        except Exception:
            return False, "DENY: Invalid expires_at format"

    # Nếu không chỉ định principal_id hoặc requested_tool (chỉ kiểm tra rule cơ bản như test_policy)
    if not context.principal_id and not context.requested_tool:
        return True, "ALLOW: Policy checks passed"

    # 4. Kiểm tra OBO Principal
    if not PRINCIPALS_PATH.exists():
        return False, "DENY: principals.json missing"

    principals_data = json.loads(PRINCIPALS_PATH.read_text(encoding="utf-8"))
    principal = principals_data.get(context.principal_id)
    if not principal:
        return False, f"DENY: Unknown principal identity '{context.principal_id}'"

    # 5. Kiểm tra purpose
    if context.request_purpose and context.request_purpose not in principal.get("purposes", []):
        return False, f"DENY: Purpose '{context.request_purpose}' not allowed for principal '{context.principal_id}'"

    # 6. Kiểm tra requested_tool nằm trong quyền principal và agent
    if context.requested_tool:
        if context.requested_tool not in principal.get("allowed_tools", []):
            return False, f"DENY: Tool '{context.requested_tool}' not allowed for principal '{context.principal_id}'"

        if context.agent_scopes and context.requested_tool not in context.agent_scopes:
            return False, f"DENY: Tool '{context.requested_tool}' exceeds agent_scopes"

        # Kiểm tra delegation_depth
        if context.delegation_depth > 0:
            if context.requested_tool not in context.parent_scopes:
                return False, f"DENY: Tool '{context.requested_tool}' exceeds parent_scopes in delegation"

    return True, f"ALLOW: Authorized tool '{context.requested_tool}' for principal '{context.principal_id}'"