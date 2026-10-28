"""Versioned, data-driven deterministic detection rules."""
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

@lru_cache
def rule_set() -> dict[str, Any]:
    return json.loads((Path(__file__).with_name("rules.json")).read_text(encoding="utf-8"))

def evaluate_rules(flow: dict[str, Any]) -> list[dict[str, Any]]:
    matches = []
    for rule in rule_set()["rules"]:
        valid = True
        for key, expected in rule["when"].items():
            if key == "exclude_dst_ports": valid &= flow.get("dst_port", 0) not in expected
            elif key.endswith("_lte"): valid &= float(flow.get(key[:-4], 0)) <= expected
            elif key.endswith("_gt"): valid &= float(flow.get(key[:-3], 0)) > expected
            elif key.endswith("_lt"): valid &= float(flow.get(key[:-3], 0)) < expected
        if valid: matches.append({k: rule[k] for k in ("id", "severity", "mitre", "rationale")})
    return matches

def evaluate_heuristics(flow: dict[str, Any]) -> list[str]:
    return [item["id"] for item in evaluate_rules(flow)]
