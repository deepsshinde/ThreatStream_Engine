import copy

import pytest

from app.mapping.mapper import EventMapper
from app.validation.validator import OCSFValidator
from tests.factories import cloudtrail_event


@pytest.fixture
def mapped_event(mappings) -> dict:
    return EventMapper(mappings).map_event(cloudtrail_event(), "aws_cloudtrail")


@pytest.fixture
def validator():
    return OCSFValidator()


def test_valid_event_passes(validator, mapped_event):
    result = validator.validate(mapped_event)
    assert result.valid, result.errors
    assert result.errors == []
    assert result.to_dict() == {"valid": True, "errors": []}


def test_missing_class_uid(validator, mapped_event):
    event = copy.deepcopy(mapped_event)
    del event["class_uid"]
    result = validator.validate(event)
    assert not result.valid
    assert "Missing required field: class_uid" in result.errors


def test_non_object_event(validator):
    assert not validator.validate(["not", "a", "dict"]).valid
    assert not validator.validate(None).valid


def test_class_name_must_match_registry(validator, mapped_event):
    event = copy.deepcopy(mapped_event)
    event["class_name"] = "Authenticatione"  # typo
    result = validator.validate(event)
    assert not result.valid
    assert any("does not match class_uid" in e for e in result.errors)


def test_unknown_class_uid(validator, mapped_event):
    event = copy.deepcopy(mapped_event)
    event["class_uid"] = 9999
    event["type_uid"] = 9999 * 100 + event["activity_id"]
    result = validator.validate(event)
    assert not result.valid
    assert any("Unknown class_uid" in e for e in result.errors)


def test_severity_out_of_range(validator, mapped_event):
    event = copy.deepcopy(mapped_event)
    event["severity_id"] = 9
    result = validator.validate(event)
    assert not result.valid
    assert any("severity_id 9 out of range" in e for e in result.errors)


def test_severity_name_must_match_id(validator, mapped_event):
    event = copy.deepcopy(mapped_event)
    event["severity_id"] = 4
    event["severity"] = "Low"  # mismatch, 4 == High
    result = validator.validate(event)
    assert not result.valid
    assert any("does not match severity_id" in e for e in result.errors)


def test_time_must_be_plausible_epoch_ms(validator, mapped_event):
    event = copy.deepcopy(mapped_event)
    event["time"] = 12345
    result = validator.validate(event)
    assert not result.valid
    assert any("not a plausible epoch-milliseconds" in e for e in result.errors)


def test_type_uid_consistency(validator, mapped_event):
    event = copy.deepcopy(mapped_event)
    event["type_uid"] = 123
    result = validator.validate(event)
    assert not result.valid
    assert any("type_uid 123 !=" in e for e in result.errors)


def test_nested_type_check_actor_user_name(validator, mapped_event):
    event = copy.deepcopy(mapped_event)
    event["actor"]["user"]["name"] = 42
    result = validator.validate(event)
    assert not result.valid
    assert any("actor.user.name" in e for e in result.errors)


def test_nested_type_check_src_endpoint_ip(validator, mapped_event):
    event = copy.deepcopy(mapped_event)
    event["src_endpoint"]["ip"] = 12345
    result = validator.validate(event)
    assert not result.valid
    assert any("src_endpoint.ip" in e for e in result.errors)


def test_missing_metadata(validator, mapped_event):
    event = copy.deepcopy(mapped_event)
    del event["metadata"]
    result = validator.validate(event)
    assert not result.valid
    assert any("metadata" in e for e in result.errors)
