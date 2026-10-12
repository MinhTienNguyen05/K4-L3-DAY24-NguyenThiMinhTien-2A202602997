"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

# Regex patterns tối ưu theo vn_pii_testset.jsonl
PATTERNS = [
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")),
    ("VN_BANK_ACCOUNT", re.compile(r"(?:STK|số tài khoản|tài khoản)\s+(\d{8,16})\b", re.IGNORECASE)),
    ("VN_CCCD", re.compile(r"\b\d{12}\b")),
    ("VN_PHONE", re.compile(r"\b0\d{9,10}\b")),
]


def detect(text: str) -> list[dict]:
    raw_spans = []

    for pii_type, pattern in PATTERNS:
        for match in pattern.finditer(text):
            if pii_type == "VN_BANK_ACCOUNT" and match.groups():
                # Lấy start/end của nhóm capture chữ số tài khoản
                start, end = match.start(1), match.end(1)
            else:
                start, end = match.start(), match.end()
            raw_spans.append({"type": pii_type, "start": start, "end": end})

    # Sắp xếp theo vị trí bắt đầu tăng dần, độ dài giảm dần
    raw_spans.sort(key=lambda x: (x["start"], -(x["end"] - x["start"])))

    # Lọc bỏ các entity bị overlap
    filtered: list[dict] = []
    for span in raw_spans:
        overlap = False
        for chosen in filtered:
            if max(span["start"], chosen["start"]) < min(span["end"], chosen["end"]):
                overlap = True
                break
        if not overlap:
            filtered.append(span)

    # Sắp xếp lại theo start
    filtered.sort(key=lambda x: x["start"])
    return filtered


def redact(text: str) -> str:
    entities = detect(text)
    # Thay thế từ cuối chuỗi lên đầu chuỗi
    for ent in sorted(entities, key=lambda x: x["start"], reverse=True):
        tag = f"[REDACTED_{ent['type']}]"
        text = text[:ent["start"]] + tag + text[ent["end"]:]
    return text