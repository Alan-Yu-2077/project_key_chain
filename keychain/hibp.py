"""Breach check with Have I Been Pwned's Pwned Passwords range API, using k-anonymity.

The password and its full hash never leave this machine. Only the first 5 hex characters of the
password's SHA-1 hash are sent:

    GET https://api.pwnedpasswords.com/range/5BAA6

The service answers with every breached hash that starts with those 5 characters: the other 35
characters of each, and how many times it was seen. The password's own 35 characters are then
looked for in that list here, locally. There are 16^5 (about a million) prefixes, and each one is
shared by about two thousand breached passwords and by countless passwords that were never
breached, so the service cannot tell which one was checked, nor whether it was found.

Two details keep the rest of the exchange from giving that away:

- the request asks for padding (`Add-Padding: true`), so the response is filled up with fake
  entries (count 0) and its size does not reveal the prefix to someone watching the encrypted
  traffic;
- each prefix is requested at most once per check, so two entries that share a password do not
  show up as the same request twice.

SHA-1 is broken for collisions, but no protection here relies on it: it is only the key under
which the service files its hashes.
"""

import hashlib
import http.client
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable

from .errors import BreachCheckFailed

API_URL = "https://api.pwnedpasswords.com/range/"
PREFIX_LENGTH = 5
TIMEOUT_SECONDS = 10
USER_AGENT = "project_key_chain (a course-project password manager)"
# A padded response holds about two thousand 40-byte lines; anything far larger is not the API.
MAX_RESPONSE_BYTES = 1024 * 1024

_PREFIX = re.compile(r"[0-9A-F]{5}")
_LINE = re.compile(r"([0-9A-F]{35}):([0-9]+)", re.IGNORECASE)


def sha1_hex(password: str) -> str:
    """The SHA-1 of the password's UTF-8 bytes, as 40 uppercase hex characters (HIBP's form)."""
    return hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()


def breach_counts(passwords: Iterable[str], fetch: Callable[[str], str] | None = None) -> list[int]:
    """How many times each password appears in known breaches, 0 for one that never does.

    `fetch(prefix)` returns the API's answer for a 5-character prefix; it defaults to
    `fetch_range` (a real request) and is replaced by a fake in the tests.
    """
    fetch = fetch or fetch_range
    hashes = [sha1_hex(password) for password in passwords]
    ranges: dict[str, dict[str, int]] = {}
    for prefix in dict.fromkeys(digest[:PREFIX_LENGTH] for digest in hashes):
        ranges[prefix] = parse_range(fetch(prefix))
    return [ranges[digest[:PREFIX_LENGTH]].get(digest[PREFIX_LENGTH:], 0) for digest in hashes]


def fetch_range(prefix: str) -> str:
    """Ask the API for every breached hash starting with `prefix`. Sends nothing else."""
    if not _PREFIX.fullmatch(prefix):  # never let anything longer than a prefix out by mistake
        raise ValueError("only a 5-character uppercase hex prefix may be sent")
    request = urllib.request.Request(
        API_URL + prefix, headers={"Add-Padding": "true", "User-Agent": USER_AGENT}
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise BreachCheckFailed(f"Have I Been Pwned answered HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise BreachCheckFailed(f"could not reach Have I Been Pwned: {exc.reason}") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise BreachCheckFailed(f"could not reach Have I Been Pwned: {exc}") from exc
    if len(body) > MAX_RESPONSE_BYTES:
        raise BreachCheckFailed("Have I Been Pwned sent an unexpectedly large response")
    try:
        return body.decode("ascii")
    except UnicodeDecodeError:
        raise BreachCheckFailed("Have I Been Pwned sent a response that is not text") from None


def parse_range(body: str) -> dict[str, int]:
    """Turn the API's `SUFFIX:COUNT` lines into {suffix: count}.

    Padding entries have a count of 0, so they never count as a match.
    """
    counts = {}
    for line in body.splitlines():
        match = _LINE.fullmatch(line.strip())
        if match is None:
            raise BreachCheckFailed("Have I Been Pwned sent a response in an unexpected format")
        counts[match[1].upper()] = int(match[2])
    if not counts:  # every prefix has entries, and padding adds more: empty means a broken answer
        raise BreachCheckFailed("Have I Been Pwned sent an empty response")
    return counts
