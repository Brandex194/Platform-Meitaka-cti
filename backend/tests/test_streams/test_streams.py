import fakeredis
import pytest

from app.streams.streams import get_cursor, publish, read_batch, save_cursor


@pytest.fixture
def r():
    return fakeredis.FakeRedis(decode_responses=True)


def test_publish_returns_msg_id(r):
    msg_id = publish("raw-observations", {"k": "v"}, r=r)
    assert isinstance(msg_id, str)
    assert "-" in msg_id


def test_read_batch_returns_messages(r):
    publish("raw-observations", {"k": "v"}, r=r)
    result = read_batch("raw-observations", "0-0", r=r)
    assert len(result) == 1
    msg_id, fields = result[0]
    assert fields["k"] == "v"


def test_cursor_round_trip(r):
    save_cursor("raw-observations", "123-0", r=r)
    assert get_cursor("raw-observations", r=r) == "123-0"


def test_get_cursor_default(r):
    assert get_cursor("no-such-stream", r=r) == "0-0"


def test_read_batch_empty(r):
    result = read_batch("raw-observations", "0-0", r=r)
    assert result == []


def test_cursor_not_advanced_on_empty(r):
    # Cursor stays at "0-0" when read_batch returns nothing (empty stream)
    save_cursor("raw-observations", "0-0", r=r)
    result = read_batch("raw-observations", "0-0", r=r)
    assert result == []
    assert get_cursor("raw-observations", r=r) == "0-0"
