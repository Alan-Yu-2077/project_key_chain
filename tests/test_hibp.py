import hashlib
import socket
import urllib.error

import pytest

from keychain import hibp
from keychain.errors import BreachCheckFailed

# SHA-1("password") = 5BAA6 | 1E4C9B93F3F0682250B6CF8331B7EE68FD8
PREFIX = "5BAA6"
SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"


class FakeApi:
    """Stands in for `fetch_range`: records every prefix asked for and answers with `lines`."""

    def __init__(self, *lines):
        self.lines = lines or ("0018A45C4D1DEF81644B54AB7F969B88D65:1",)
        self.prefixes = []

    def __call__(self, prefix):
        self.prefixes.append(prefix)
        return "\r\n".join(self.lines)


@pytest.fixture
def fake_urlopen(monkeypatch):
    """Replaces urllib's urlopen: records each (request, timeout) and answers with `.body`."""

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, limit):
            return fake.body[:limit]

    def fake(request, timeout):
        fake.requests.append((request, timeout))
        return Response()

    fake.requests, fake.body = [], b""
    monkeypatch.setattr("urllib.request.urlopen", fake)
    return fake


# --- What is computed and what is sent ------------------------------------------------------


def test_sha1_is_the_uppercase_hex_digest_of_the_utf8_bytes():
    assert hibp.sha1_hex("password") == PREFIX + SUFFIX
    assert hibp.sha1_hex("pässwörd") == hashlib.sha1("pässwörd".encode()).hexdigest().upper()


def test_only_the_5_character_prefix_is_handed_to_the_network():
    api = FakeApi()
    hibp.breach_counts(["password"], fetch=api)
    assert api.prefixes == [PREFIX]


def test_the_request_carries_the_prefix_and_nothing_else_about_the_password(fake_urlopen):
    password = "correct-horse-battery"
    digest = hibp.sha1_hex(password)
    fake_urlopen.body = f"{digest[5:]}:3\r\n".encode()
    assert hibp.breach_counts([password]) == [3]

    [(request, timeout)] = fake_urlopen.requests
    assert request.full_url == hibp.API_URL + digest[:5]
    assert request.get_method() == "GET" and request.data is None
    assert request.get_header("Add-padding") == "true"  # urllib stores header names capitalized
    assert 0 < timeout <= 30
    everything_sent = request.full_url + repr(request.header_items())
    assert password not in everything_sent
    assert digest[5:] not in everything_sent.upper()


@pytest.mark.parametrize("body", [b"x" * (hibp.MAX_RESPONSE_BYTES + 1), "caf\u00e9:1".encode()])
def test_an_oversized_or_non_text_answer_is_an_error(fake_urlopen, body):
    fake_urlopen.body = body
    with pytest.raises(BreachCheckFailed):
        hibp.fetch_range(PREFIX)


@pytest.mark.parametrize("prefix", ["5BAA61", "5BAA", "5baa6", "5BAAG", PREFIX + SUFFIX])
def test_fetch_range_refuses_to_send_anything_but_a_prefix(prefix, monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", pytest.fail)
    with pytest.raises(ValueError):
        hibp.fetch_range(prefix)


def test_a_password_used_twice_is_asked_about_once():
    api = FakeApi()
    hibp.breach_counts(["password", "something else", "password"], fetch=api)
    assert sorted(api.prefixes) == sorted({PREFIX, hibp.sha1_hex("something else")[:5]})


# --- Reading the answer ---------------------------------------------------------------------


def test_a_breached_password_is_found_with_its_count():
    api = FakeApi("0018A45C4D1DEF81644B54AB7F969B88D65:1", f"{SUFFIX}:52256179")
    assert hibp.breach_counts(["password"], fetch=api) == [52256179]


def test_a_password_missing_from_the_range_is_not_found():
    assert hibp.breach_counts(["password"], fetch=FakeApi()) == [0]


def test_a_padding_entry_is_not_a_match():
    assert hibp.breach_counts(["password"], fetch=FakeApi(f"{SUFFIX}:0")) == [0]


def test_lowercase_hashes_and_surrounding_whitespace_are_accepted():
    assert hibp.breach_counts(["password"], fetch=FakeApi(f"  {SUFFIX.lower()}:7 ")) == [7]


def test_counts_line_up_with_the_passwords_given():
    api = FakeApi(f"{SUFFIX}:9")
    assert hibp.breach_counts(["not it", "password", "not it either"], fetch=api) == [0, 9, 0]


def test_an_empty_answer_is_an_error_not_a_silent_not_found():
    with pytest.raises(BreachCheckFailed):
        hibp.breach_counts(["password"], fetch=lambda prefix: "")


@pytest.mark.parametrize("bad_line", [
    "<html>captive portal</html>",
    f"{SUFFIX}",
    f"{SUFFIX}:",
    f"{SUFFIX}:-1",
    f"{SUFFIX[:-1]}:1",
    f"{SUFFIX}0:1",
])
def test_one_malformed_line_makes_the_whole_answer_an_error(bad_line):
    # Among valid lines, so skipping the bad line would wrongly report "not found".
    body = f"0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{bad_line}\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2"
    with pytest.raises(BreachCheckFailed):
        hibp.breach_counts(["password"], fetch=lambda prefix: body)


# --- Network failures become one clear error ------------------------------------------------


@pytest.mark.parametrize("error", [
    urllib.error.URLError(socket.gaierror(8, "nodename nor servname provided")),
    urllib.error.HTTPError(hibp.API_URL + PREFIX, 503, "Service Unavailable", None, None),
    TimeoutError("timed out"),
    ConnectionResetError("connection reset"),
])
def test_network_failures_are_reported_as_breach_check_failed(error, monkeypatch):
    def urlopen(request, timeout):
        raise error

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    with pytest.raises(BreachCheckFailed):
        hibp.fetch_range(PREFIX)
