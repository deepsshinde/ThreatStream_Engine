from datetime import datetime, timezone

import pytest

from app.mapping import resolver


class TestGetPath:
    def test_nested_path(self):
        event = {"a": {"b": {"c": 42}}}
        assert resolver.get_path(event, "a.b.c") == 42

    def test_missing_path_returns_none(self):
        assert resolver.get_path({"a": {"b": 1}}, "a.b.c.d") is None

    def test_list_index(self):
        event = {"items": [{"name": "first"}, {"name": "second"}]}
        assert resolver.get_path(event, "items.1.name") == "second"

    def test_path_through_scalar_returns_none(self):
        assert resolver.get_path({"a": 5}, "a.b") is None


class TestTemplates:
    def test_full_placeholder_preserves_type(self):
        event = {"EventData": {"LogonType": "3"}, "packets": 24}
        assert resolver.resolve_template("{packets}", event) == 24
        assert resolver.resolve_template("{EventData.LogonType}", event) == "3"

    def test_missing_full_placeholder_is_none(self):
        assert resolver.resolve_template("{missing.field}", {"a": 1}) is None

    def test_static_value_passthrough(self):
        assert resolver.resolve_template(3002, {"a": 1}) == 3002
        assert resolver.resolve_template("plain text", {"a": 1}) == "plain text"

    def test_mixed_template_interpolation(self):
        event = {"user": {"name": "bob"}, "ip": "10.0.0.1"}
        out = resolver.resolve_template("user {user.name} from {ip}", event)
        assert out == "user bob from 10.0.0.1"

    def test_mixed_template_missing_becomes_empty(self):
        out = resolver.resolve_template("ip=[{ip}]", {"a": 1})
        assert out == "ip=[]"

    def test_fallback_paths(self):
        event = {"EventData": {"TargetUserName": "asmith"}}
        out = resolver.resolve_template("{userIdentity.userName|EventData.TargetUserName}", event)
        assert out == "asmith"


class TestEnum:
    EVENT = {"errorCode": "AccessDenied"}

    def spec(self, values, other="Failure"):
        return {"evaluate": "{errorCode}", "values": values, "other": other}

    def test_exact_value_match(self):
        out = resolver.resolve_enum(self.spec({"AccessDenied": "Failure"}), self.EVENT)
        assert out == "Failure"

    def test_null_key_matches_missing_value(self):
        out = resolver.resolve_enum(self.spec({None: "Success"}), {"a": 1})
        assert out == "Success"

    def test_other_fallback(self):
        out = resolver.resolve_enum(self.spec({"AccessDenied": "Denied"}), {"errorCode": "Throttling"})
        assert out == "Failure"

    def test_int_key_match(self):
        spec = {"evaluate": "{EventID}", "values": {4624: "yes"}, "other": "no"}
        assert resolver.resolve_enum(spec, {"EventID": 4624}) == "yes"
        assert resolver.resolve_enum(spec, {"EventID": 4625}) == "no"


class TestWildcardMap:
    MAP = {"ConsoleLogin": {"uid": 1}, "Create*": {"uid": 9}, "*": {"uid": 99}}

    def test_exact_match_wins(self):
        assert resolver.match_pattern_map("ConsoleLogin", self.MAP) == {"uid": 1}

    def test_wildcard_match(self):
        assert resolver.match_pattern_map("CreateUser", self.MAP) == {"uid": 9}

    def test_catch_all(self):
        assert resolver.match_pattern_map("DeleteEverything", self.MAP) == {"uid": 99}

    def test_int_key_exact(self):
        assert resolver.match_pattern_map(4624, {4624: {"uid": 1}}) == {"uid": 1}

    def test_default_returned(self):
        assert resolver.match_pattern_map("zzz", {"A*": 1}, default={"uid": 0}) == {"uid": 0}


class TestToEpochMs:
    def test_epoch_seconds(self):
        assert resolver.to_epoch_ms(1790240700) == 1790240700 * 1000

    def test_epoch_millis_passthrough(self):
        assert resolver.to_epoch_ms(1790240700000) == 1790240700000

    def test_iso_8601_z(self):
        expected = int(datetime(2026, 9, 24, 9, 6, tzinfo=timezone.utc).timestamp() * 1000)
        assert resolver.to_epoch_ms("2026-09-24T09:06:00Z") == expected

    def test_numeric_string(self):
        assert resolver.to_epoch_ms("1790240700") == 1790240700000

    def test_custom_format(self):
        dt = datetime.strptime("2026/09/24 09:22:01", "%Y/%m/%d %H:%M:%S")
        expected = int(dt.replace(tzinfo=timezone.utc).timestamp() * 1000)
        assert resolver.to_epoch_ms("2026/09/24 09:22:01", format="%Y/%m/%d %H:%M:%S") == expected

    def test_datetime_naive_assumed_utc(self):
        dt = datetime(2026, 9, 24, 9, 0, 0)
        assert resolver.to_epoch_ms(dt) == int(datetime(2026, 9, 24, 9, tzinfo=timezone.utc).timestamp() * 1000)

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            resolver.to_epoch_ms("not-a-time")
        with pytest.raises(ValueError):
            resolver.to_epoch_ms(None)
        with pytest.raises(ValueError):
            resolver.to_epoch_ms(True)
