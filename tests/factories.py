"""Raw-event builders shared by tests."""

from __future__ import annotations

from typing import Any


def cloudtrail_event(event_name: str = "ConsoleLogin", **overrides: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDABOBEXAMPLE123456",
            "accountId": "123456789012",
            "userName": "bob",
        },
        "eventTime": "2026-09-24T09:06:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": event_name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.50",
        "userAgent": "Mozilla/5.0",
        "requestParameters": None,
        "responseElements": {"ConsoleLogin": "Success"},
        "eventID": "ct-test-1",
        "recipientAccountId": "123456789012",
    }
    if event_name == "ConsoleLogin" and overrides.pop("failed", False):
        event["errorCode"] = "Failed authentication"
        event["responseElements"] = {"ConsoleLogin": "Failure"}
    event.update(overrides)
    return event


def windows_event(event_id: int = 4625, status: str | None = "0xC000006A", **overrides: Any) -> dict[str, Any]:
    event_data: dict[str, Any] = {
        "TargetUserName": "asmith",
        "TargetDomainName": "CORP",
        "IpAddress": "10.1.2.34",
        "LogonType": "3",
    }
    if status is not None:
        event_data["Status"] = status
    event: dict[str, Any] = {
        "EventID": event_id,
        "TimeCreated": "2026-09-24T09:11:00Z",
        "Computer": "WIN-DC01.corp.local",
        "Channel": "Security",
        "EventData": event_data,
    }
    event.update(overrides)
    return event


def vpc_record(action: str = "ACCEPT", **overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "version": 2,
        "account-id": "123456789012",
        "interface-id": "eni-0abc123def4567890",
        "srcaddr": "10.0.2.45",
        "dstaddr": "10.0.1.15",
        "srcport": 52344,
        "dstport": 443,
        "protocol": 6,
        "packets": 24,
        "bytes": 15200,
        "start": 1790240700,
        "end": 1790240760,
        "action": action,
        "log-status": "OK",
    }
    record.update(overrides)
    return record


def paloalto_record(action: str = "allow", **overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "serial": "001201000992",
        "type": "TRAFFIC",
        "subtype": "end",
        "time_generated": "2026/09/24 09:22:01",
        "src": "10.8.4.21",
        "dst": "142.250.77.142",
        "rule": "Allow-Outbound-Web",
        "app": "ssl",
        "sport": 52998,
        "dport": 443,
        "proto": "tcp",
        "action": action,
        "bytes": 1823442,
        "pkts": 2204,
    }
    record.update(overrides)
    return record


def azure_record(operation: str = "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE", **overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "operationName": operation,
        "resultType": "Success",
        "resultSignature": "Succeeded.OK",
        "correlationId": "c23e07c1-test",
        "identity": {"authorization": {"evidence": {"principalId": "p-1", "role": "Contributor"}}},
        "time": "2026-09-24T09:15:12Z",
        "caller": "deploy-bot@contoso.com",
        "callerIpAddress": "20.204.15.7",
        "resourceId": "/SUBSCRIPTIONS/9A8B7C6D/RESOURCEGROUPS/RG-PROD-CORE",
    }
    record.update(overrides)
    return record


def gcp_record(method: str = "google.iam.admin.v1.CreateServiceAccount", **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "serviceName": "iam.googleapis.com",
        "methodName": method,
        "authenticationInfo": {"principalEmail": "devops.lead@example-corp.com"},
        "requestMetadata": {"callerIp": "34.105.22.9"},
        "resourceName": "projects/prod-analytics-2811",
    }
    record: dict[str, Any] = {
        "protoPayload": payload,
        "severity": "NOTICE",
        "logName": "projects/prod-analytics-2811/logs/cloudaudit.googleapis.com%2Factivity",
        "timestamp": "2026-09-24T09:19:05Z",
    }
    record.update(overrides)
    return record
