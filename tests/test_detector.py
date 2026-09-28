from app.detection.source_detector import SourceDetector
from tests.factories import (
    azure_record,
    cloudtrail_event,
    gcp_record,
    paloalto_record,
    vpc_record,
    windows_event,
)


def test_detects_cloudtrail(mappings):
    detector = SourceDetector(mappings)
    result = detector.detect(cloudtrail_event())
    assert result is not None
    assert result.source_name == "aws_cloudtrail"


def test_detects_windows(mappings):
    detector = SourceDetector(mappings)
    assert detector.detect(windows_event()).source_name == "windows_security"


def test_detects_vpc_flowlogs(mappings):
    detector = SourceDetector(mappings)
    assert detector.detect(vpc_record()).source_name == "aws_vpc_flowlogs"


def test_detects_azure(mappings):
    detector = SourceDetector(mappings)
    assert detector.detect(azure_record()).source_name == "azure_activity"


def test_detects_gcp(mappings):
    detector = SourceDetector(mappings)
    assert detector.detect(gcp_record()).source_name == "gcp_audit"


def test_detects_paloalto(mappings):
    detector = SourceDetector(mappings)
    assert detector.detect(paloalto_record()).source_name == "paloalto_firewall"


def test_unknown_source_returns_none(mappings):
    detector = SourceDetector(mappings)
    assert detector.detect({"totally": "unknown", "shape": True}) is None


def test_missing_required_field_is_not_matched(mappings):
    detector = SourceDetector(mappings)
    event = cloudtrail_event()
    del event["eventName"]
    assert detector.detect(event) is None  # eventSource pattern alone is not enough


def test_non_dict_input_returns_none(mappings):
    detector = SourceDetector(mappings)
    assert detector.detect(["not", "a", "dict"]) is None
    assert detector.detect(None) is None


def test_priority_ordering_wins_over_generic_rule():
    configs = {
        "generic": {
            "source_name": "generic",
            "priority": 1,
            "detection": {"required_fields": ["a"]},
            "ocsf": {"class_uid": 1, "class_name": "x", "category_uid": 1, "category_name": "y"},
        },
        "specific": {
            "source_name": "specific",
            "priority": 100,
            "detection": {"required_fields": ["a", "b"]},
            "ocsf": {"class_uid": 1, "class_name": "x", "category_uid": 1, "category_name": "y"},
        },
    }
    detector = SourceDetector(configs)
    assert detector.detect({"a": 1, "b": 2}).source_name == "specific"
    assert detector.detect({"a": 1}).source_name == "generic"


def test_field_pattern_rejects_non_matching_value(mappings):
    detector = SourceDetector(mappings)
    event = cloudtrail_event(eventSource="notaws.example.com")
    assert detector.detect(event) is None
