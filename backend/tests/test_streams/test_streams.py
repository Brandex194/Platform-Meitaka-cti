import fakeredis
import pytest

from app.streams.streams import get_cursor, publish, read_batch, save_cursor


@pytest.fixture
def fake_redis():
    return fakeredis.FakeRedis(decode_responses=True)


def test_publish_returns_msg_id(fake_redis):
    msg_id = publish("raw-observations", {"k": "v"}, r=fake_redis)
    assert isinstance(msg_id, str)
    assert "-" in msg_id


def test_read_batch_returns_messages(fake_redis):
    publish("raw-observations", {"k": "v"}, r=fake_redis)
    result = read_batch("raw-observations", "0-0", r=fake_redis)
    assert len(result) == 1
    msg_id, fields = result[0]
    assert fields["k"] == "v"


def test_cursor_round_trip(fake_redis):
    save_cursor("raw-observations", "123-0", r=fake_redis)
    assert get_cursor("raw-observations", r=fake_redis) == "123-0"


def test_get_cursor_default(fake_redis):
    assert get_cursor("no-such-stream", r=fake_redis) == "0-0"


def test_read_batch_empty(fake_redis):
    result = read_batch("raw-observations", "0-0", r=fake_redis)
    assert result == []


def test_cursor_not_advanced_on_empty(fake_redis):
    # read_batch on empty stream returns [] without touching cursor
    save_cursor("raw-observations", "0-0", r=fake_redis)
    result = read_batch("raw-observations", "0-0", r=fake_redis)
    assert result == []
    assert get_cursor("raw-observations", r=fake_redis) == "0-0"


def test_cursor_not_advanced_on_exception(fake_redis):
    """Cursor must not advance if processing raises — caller is responsible for save_cursor."""
    publish("raw-observations", {"k": "v"}, r=fake_redis)
    batch = read_batch("raw-observations", "0-0", r=fake_redis)
    assert len(batch) == 1
    msg_id, _ = batch[0]

    # Simulate: processing fails — save_cursor is never called
    try:
        raise RuntimeError("simulated processing failure")
    except RuntimeError:
        pass  # caller does NOT call save_cursor on failure

    # Cursor must still be at the default "0-0"
    cursor = get_cursor("raw-observations", r=fake_redis)
    assert cursor == "0-0"

    # Verify: if processing succeeds, save_cursor advances the cursor
    save_cursor("raw-observations", msg_id, r=fake_redis)
    assert get_cursor("raw-observations", r=fake_redis) == msg_id


def test_read_batch_exclusive_lower_bound(fake_redis):
    """Reading from last returned ID should return [] (exclusive bound)."""
    publish("raw-observations", {"k": "1"}, r=fake_redis)
    publish("raw-observations", {"k": "2"}, r=fake_redis)

    batch = read_batch("raw-observations", "0-0", r=fake_redis)
    assert len(batch) == 2
    last_id = batch[-1][0]

    # Read from the last ID — should be empty (exclusive)
    second_batch = read_batch("raw-observations", last_id, r=fake_redis)
    assert second_batch == []
