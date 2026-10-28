import json
from pathlib import Path

from app.module1_aggregator.flow_features import Flow
from app.module1_aggregator.parser import parse_pcap_batches
from app.module2_detector.rules import evaluate_rules, rule_set
from app.schemas import FlowEvent
from app.module3_explainer.verdict import extract_verdict, normalize_report_classification

def test_flow_statistics_are_bounded_and_rates_are_correct():
    flow = Flow("10.0.0.1", "10.0.0.2", 1, 2, 6, 1.0)
    flow.add_packet(100, 1.0); flow.add_packet(200, 2.0)
    result = flow.to_features()
    assert result["total_packets"] == 2 and result["total_bytes"] == 300
    assert result["bytes_per_second"] == 300

def test_versioned_rule_evidence_contains_soc_metadata():
    matches = evaluate_rules({"total_packets": 1, "flow_duration": .01, "dst_port": 22})
    assert matches[0]["id"] == "HEURISTIC_PORT_SCAN_PROBE"
    assert matches[0]["mitre"] == ["T1046"] and rule_set()["version"] == "1.0.0"

def test_flow_schema_rejects_invalid_ports():
    try: FlowEvent(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=99999, dst_port=2, protocol=6, flow_duration=1, total_packets=1, total_bytes=1)
    except Exception: return
    assert False, "invalid port must be rejected"


def test_sample_pcap_yields_schema_compatible_flow_batches():
    sample = Path("app/samples/tfp_capture.pcapng")
    flows = [flow for batch in parse_pcap_batches(str(sample), batch_size=4) for flow in batch]
    assert flows
    for flow in flows:
        FlowEvent(**flow)


def test_analyst_verdict_requires_explicit_final_line():
    assert extract_verdict("FINAL VERDICT: MALICIOUS\n### Attack Overview") == "malicious"
    assert extract_verdict("**FINAL VERDICT: BENIGN**\n### Technical Feature Analysis") == "benign"
    assert extract_verdict("The traffic looks suspicious, perhaps benign.") is None


def test_report_classification_is_normalized_to_final_verdict():
    report = "FINAL VERDICT: BENIGN\n- **Alert Classification:** True Positive (Reconnaissance)"
    normalized = normalize_report_classification(report, extract_verdict(report))
    assert "Alert Classification:** False Positive / benign finding" in normalized
