from app.deduplication.deduplicator import Deduplicator

T0 = 1_790_241_300_000  # epoch ms
MIN = 60_000


def event(time_ms: int = T0, user: str = "bob", ip: str = "203.0.113.50") -> dict:
    return {
        "class_uid": 3002,
        "class_name": "Authentication",
        "activity_id": 1,
        "activity_name": "Logon",
        "time": time_ms,
        "actor": {"user": {"name": user}},
        "src_endpoint": {"ip": ip},
        "metadata": {"product": {"name": "CloudTrail"}},
    }


def test_redelivered_event_is_duplicate():
    """Byte-identical events (at-least-once redelivery) are duplicates."""
    dedup = Deduplicator(window_minutes=60)
    first_dup, fp1 = dedup.is_duplicate(event(T0))
    second_dup, fp2 = dedup.is_duplicate(event(T0))
    assert first_dup is False
    assert second_dup is True
    assert fp1 == fp2


def test_same_signature_is_new_after_window_expires():
    dedup = Deduplicator(window_minutes=60)
    dup, fp = dedup.is_duplicate(event(T0))
    assert dup is False
    # Simulate the fingerprint expiring from memory (white-box, no sleeping)
    dedup._seen[fp] -= 121 * MIN
    assert dedup.is_duplicate(event(T0))[0] is False


def test_events_at_different_times_are_distinct_events_not_duplicates():
    """Two identical logins minutes apart are real events - never deduped."""
    dedup = Deduplicator(window_minutes=60)
    assert dedup.is_duplicate(event(T0))[0] is False
    assert dedup.is_duplicate(event(T0 + 5 * MIN))[0] is False  # different time -> distinct
    assert dedup.is_duplicate(event(T0))[0] is True  # exact redelivery of the first one


def test_different_content_is_not_duplicate():
    dedup = Deduplicator(window_minutes=60)
    assert dedup.is_duplicate(event(T0, user="bob"))[0] is False
    assert dedup.is_duplicate(event(T0, user="alice"))[0] is False


def test_fingerprint_is_deterministic_and_ignores_volatile_metadata():
    e1 = event(T0)
    e2 = event(T0)
    e2["metadata"]["uid"] = "assigned-uid-abc"
    e2["metadata"]["logged_time"] = 9999999999999
    assert Deduplicator.fingerprint(e1) == Deduplicator.fingerprint(e2)
    assert len(Deduplicator.fingerprint(e1)) == 64  # sha256 hex


def test_fingerprint_changes_with_content():
    assert Deduplicator.fingerprint(event(T0, user="bob")) != Deduplicator.fingerprint(
        event(T0, user="alice")
    )


def test_disabled_deduplication_never_duplicates():
    dedup = Deduplicator(window_minutes=60, enabled=False)
    assert dedup.is_duplicate(event(T0))[0] is False
    assert dedup.is_duplicate(event(T0))[0] is False


def test_state_persistence_across_instances(tmp_path):
    state = tmp_path / "dedup_state.json"
    first = Deduplicator(window_minutes=60, state_path=state)
    assert first.is_duplicate(event(T0))[0] is False
    first.close()

    second = Deduplicator(window_minutes=60, state_path=state)
    assert second.is_duplicate(event(T0))[0] is True
    second.close()
