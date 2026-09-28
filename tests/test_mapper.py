from datetime import datetime, timezone

import pytest

from app.mapping.mapper import EventMapper
from tests.factories import (
    azure_record,
    cloudtrail_event,
    gcp_record,
    paloalto_record,
    vpc_record,
    windows_event,
)


@pytest.fixture
def mapper(mappings):
    return EventMapper(mappings)


class TestCloudTrail:
    def test_console_login_success(self, mapper):
        out = mapper.map_event(cloudtrail_event(), "aws_cloudtrail")
        assert out["class_uid"] == 3002
        assert out["class_name"] == "Authentication"
        assert out["category_uid"] == 3
        assert out["activity_id"] == 1
        assert out["activity_name"] == "Logon"
        assert out["type_uid"] == 300201
        assert out["status"] == "Success"
        assert out["status_id"] == 1
        assert out["severity_id"] == 1
        assert out["actor"]["user"]["name"] == "bob"
        assert out["src_endpoint"]["ip"] == "203.0.113.50"
        assert out["metadata"]["product"]["name"] == "CloudTrail"
        assert "uid" not in out["metadata"]  # assigned later by dedup fingerprint
        expected = int(datetime(2026, 9, 24, 9, 6, tzinfo=timezone.utc).timestamp() * 1000)
        assert out["time"] == expected

    def test_console_login_failure(self, mapper):
        out = mapper.map_event(cloudtrail_event(failed=True), "aws_cloudtrail")
        assert out["status"] == "Failure"
        assert out["status_id"] == 2
        assert out["severity_id"] == 2  # on_failure policy
        assert out["severity"] == "Low"
        assert out["status_detail"] == "Failed authentication"

    def test_create_user_is_account_change(self, mapper):
        event = cloudtrail_event(
            event_name="CreateUser",
            eventSource="iam.amazonaws.com",
            requestParameters={"userName": "backup-service"},
        )
        event.pop("responseElements", None)
        out = mapper.map_event(event, "aws_cloudtrail")
        assert out["class_uid"] == 3001
        assert out["class_name"] == "Account Change"
        assert out["activity_id"] == 1
        assert out["activity_name"] == "Create"
        assert out["type_uid"] == 300101

    def test_wildcard_api_read(self, mapper):
        event = cloudtrail_event(event_name="DescribeInstances", eventSource="ec2.amazonaws.com")
        out = mapper.map_event(event, "aws_cloudtrail")
        assert out["class_uid"] == 6003
        assert out["activity_id"] == 2
        assert out["activity_name"] == "Read"

    def test_unknown_api_default_other(self, mapper):
        event = cloudtrail_event(event_name="FrobnicateGizmos", eventSource="gizmo.amazonaws.com")
        out = mapper.map_event(event, "aws_cloudtrail")
        assert out["class_uid"] == 6003
        assert out["activity_id"] == 99
        assert out["activity_name"] == "Other"


class TestWindows:
    def test_failed_logon(self, mapper):
        out = mapper.map_event(windows_event(4625), "windows_security")
        assert out["class_uid"] == 3002
        assert out["activity_name"] == "Logon"
        assert out["status"] == "Failure"
        assert out["status_id"] == 2
        assert out["severity_id"] == 3  # on_failure policy -> Medium
        assert out["status_code"] == "0xC000006A"

    def test_successful_logon(self, mapper):
        out = mapper.map_event(windows_event(4624, status=None), "windows_security")
        assert out["status"] == "Success"
        assert out["status_id"] == 1
        assert out["severity_id"] == 1

    def test_account_created_is_account_change(self, mapper):
        out = mapper.map_event(
            windows_event(4720, status=None, EventData={"TargetUserName": "newhire.temp", "TargetDomainName": "CORP"}),
            "windows_security",
        )
        assert out["class_uid"] == 3001
        assert out["activity_name"] == "Create"
        assert out["actor"]["user"]["name"] == "newhire.temp"


class TestVpcFlowLogs:
    def test_accept(self, mapper):
        out = mapper.map_event(vpc_record("ACCEPT"), "aws_vpc_flowlogs")
        assert out["class_uid"] == 4001
        assert out["activity_id"] == 1
        assert out["activity_name"] == "Traffic"
        assert out["status_id"] == 1
        assert out["time"] == 1790240700 * 1000
        assert out["src_endpoint"] == {"ip": "10.0.2.45", "port": 52344}
        assert out["dst_endpoint"]["port"] == 443
        assert out["traffic"]["bytes"] == 15200

    def test_reject_is_failure_and_refuse(self, mapper):
        out = mapper.map_event(vpc_record("REJECT"), "aws_vpc_flowlogs")
        assert out["status"] == "Failure"
        assert out["status_id"] == 2
        assert out["activity_id"] == 9
        assert out["activity_name"] == "Refuse"
        assert out["severity_id"] == 2


class TestPaloAlto:
    def test_allow_parses_custom_time_format(self, mapper):
        out = mapper.map_event(paloalto_record("allow"), "paloalto_firewall")
        expected = int(datetime(2026, 9, 24, 9, 22, 1, tzinfo=timezone.utc).timestamp() * 1000)
        assert out["time"] == expected
        assert out["status"] == "Success"
        assert out["activity_id"] == 1

    def test_deny(self, mapper):
        out = mapper.map_event(paloalto_record("deny"), "paloalto_firewall")
        assert out["status_id"] == 2
        assert out["activity_id"] == 9
        assert out["severity_id"] == 2


class TestAzure:
    def test_role_assignment_is_account_change(self, mapper):
        out = mapper.map_event(azure_record("MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"), "azure_activity")
        assert out["class_uid"] == 3001
        assert out["activity_name"] == "Create"
        assert out["severity_id"] == 2

    def test_delete_failure(self, mapper):
        out = mapper.map_event(
            azure_record("MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE", resultType="Failure"),
            "azure_activity",
        )
        assert out["class_uid"] == 6003
        assert out["activity_name"] == "Delete"
        assert out["status"] == "Failure"
        assert out["status_id"] == 2


class TestGcp:
    def test_create_service_account(self, mapper):
        out = mapper.map_event(gcp_record(), "gcp_audit")
        assert out["class_uid"] == 3001
        assert out["activity_name"] == "Create"
        assert out["status"] == "Success"
        assert out["actor"]["user"]["name"] == "devops.lead@example-corp.com"

    def test_denied_call(self, mapper):
        import copy

        event = copy.deepcopy(gcp_record("storage.objects.get", severity="ERROR"))
        event["protoPayload"]["status"] = {"code": 7, "message": "PERMISSION_DENIED"}
        out = mapper.map_event(event, "gcp_audit")
        assert out["activity_name"] == "Read"
        assert out["status"] == "Failure"
        assert out["status_id"] == 2
        assert out["status_detail"].startswith("PERMISSION_DENIED")

    def test_unknown_source_mapping_error(self, mapper):
        from app.exceptions import MappingError

        with pytest.raises(MappingError):
            mapper.map_event({}, "no_such_source")
