"""Extract a bounded, explicit final verdict from an analyst report."""
import re

_FINAL_VERDICT = re.compile(
    r"^\s*(?:[-*]\s*)?(?:\*\*)?FINAL VERDICT(?:\*\*)?\s*:\s*"
    r"(?:\*\*)?\s*(BENIGN|MALICIOUS)\b",
    re.IGNORECASE | re.MULTILINE,
)


def extract_verdict(report: str) -> str | None:
    """Return benign/malicious only when the report states the exact verdict line."""
    match = _FINAL_VERDICT.search(report or "")
    return match.group(1).lower() if match else None


def normalize_report_classification(report: str, verdict: str | None) -> str:
    """Make the report's human-readable classification agree with its explicit verdict."""
    if verdict not in {"benign", "malicious"}:
        return report
    classification = "False Positive / benign finding" if verdict == "benign" else "True Positive (malicious)"
    return re.sub(
        r"(?im)^(\s*[-*]\s*\*\*Alert Classification:\*\*\s*).*$",
        lambda match: match.group(1) + classification,
        report,
        count=1,
    )
