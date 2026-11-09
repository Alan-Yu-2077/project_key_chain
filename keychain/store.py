"""The vault file: its format, and how it is read and written.

On disk the vault is one JSON file (also shown in TEAM_PLAN.md, section 4):

    {
      "cipher": "aes-256-gcm",
      "ciphertext": "<base64: AES-GCM ciphertext followed by the 16-byte tag>",
      "kdf": {
        "alg": "argon2id",
        "memory_cost": 65536,
        "parallelism": 4,
        "salt": "<base64: 16 bytes>",
        "time_cost": 3
      },
      "master_hash": "$argon2id$v=19$m=65536,t=3,p=4$...",
      "nonce": "<base64: 12 bytes>",
      "version": 1
    }

The entries (site, username, password) exist only inside the ciphertext. Everything else, the
"header", is not secret but is authenticated: it is passed to AES-GCM as associated data.

No key is written anywhere. The key is derived from the master password and the KDF salt at
every unlock, and only kept in memory while the vault is open.

Why changing any bit of the file is detected:
  1. The parser only accepts a file that is byte for byte what `Vault.save` would write for the
     values it contains. So a changed file is either rejected outright, or it holds different
     values.
  2. Only four values are free; every other field must equal a constant of this version. All
     four are covered by the GCM tag:
       salt        -> a different key is derived, and the associated data differs
       master_hash -> the password no longer verifies, or the associated data differs
       nonce       -> the tag is checked under a different nonce
       ciphertext  -> the tag no longer matches
"""

import base64
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import crypto
from .errors import VaultAlreadyExists, VaultCorrupted, VaultNotFound, WrongMasterPassword

FORMAT_VERSION = 1
CIPHER = "aes-256-gcm"
KDF_ALGORITHM = "argon2id"


@dataclass(frozen=True)
class Entry:
    """One stored credential. The password is left out of repr() so it is never printed by accident."""

    username: str
    password: str = field(repr=False)


class Vault:
    """An unlocked vault: the entries in memory, plus what is needed to encrypt them again.

    Get one from `create` or `unlock`, change `entries`, then call `save`.
    """

    def __init__(self, path: Path, *, key: bytes, salt: bytes, master_hash: str,
                 entries: dict[str, Entry]) -> None:
        self.path = path
        self.entries = entries
        self._key = key  # derived from the master password; never written to disk
        self._salt = salt
        self._master_hash = master_hash

    def save(self) -> None:
        """Encrypt the entries under a fresh nonce and replace the vault file atomically.

        The key and the salt stay the same for the life of the vault; only the nonce changes,
        and `crypto.encrypt` draws a new random one on every call.
        """
        header = _header(self._master_hash, self._salt)
        nonce, ciphertext = crypto.encrypt(
            self._key, _encode_entries(self.entries), _associated_data(header)
        )
        _write_atomically(self.path, _serialize(_document(header, nonce, ciphertext)))


def create(path: Path, master_password: str) -> Vault:
    """Create an empty vault at `path`, protected by `master_password`."""
    if path.exists():
        raise VaultAlreadyExists(f"a vault already exists at {path}")
    salt = crypto.new_salt()  # for the key; independent of the salt inside master_hash
    vault = Vault(
        path,
        key=crypto.derive_key(master_password, salt),
        salt=salt,
        master_hash=crypto.hash_master_password(master_password),
        entries={},
    )
    vault.save()
    return vault


def unlock(path: Path, master_password: str) -> Vault:
    """Open the vault at `path`.

    Raises VaultNotFound, VaultCorrupted if the file was modified or damaged, and
    WrongMasterPassword if the password does not match the stored hash.
    """
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        raise VaultNotFound(f"there is no vault at {path}") from None
    master_hash, salt, nonce, ciphertext = _parse(data)

    if not crypto.verify_master_password(master_hash, master_password):
        raise WrongMasterPassword("wrong master password")
    key = crypto.derive_key(master_password, salt)
    plaintext = crypto.decrypt(key, nonce, ciphertext, _associated_data(_header(master_hash, salt)))
    return Vault(path, key=key, salt=salt, master_hash=master_hash, entries=_decode_entries(plaintext))


# --- File format ----------------------------------------------------------------------------


def _header(master_hash: str, salt: bytes) -> dict:
    """Every field of the file except the nonce and the ciphertext."""
    params = crypto.PARAMS
    return {
        "cipher": CIPHER,
        "kdf": {
            "alg": KDF_ALGORITHM,
            "memory_cost": params.memory_cost,
            "parallelism": params.parallelism,
            "salt": _b64encode(salt),
            "time_cost": params.time_cost,
        },
        "master_hash": master_hash,
        "version": FORMAT_VERSION,
    }


def _document(header: dict, nonce: bytes, ciphertext: bytes) -> dict:
    return {**header, "nonce": _b64encode(nonce), "ciphertext": _b64encode(ciphertext)}


def _associated_data(header: dict) -> bytes:
    """The header in compact, key-sorted JSON, so the writer and the reader build the same bytes."""
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("ascii")


def _serialize(document: dict) -> bytes:
    """The single byte form a vault file is allowed to have."""
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("ascii")


def _parse(data: bytes) -> tuple[str, bytes, bytes, bytes]:
    """Read (master_hash, salt, nonce, ciphertext) from a vault file, or raise VaultCorrupted.

    Checking the decoded values alone would not be enough: JSON whitespace, escape sequences such
    as \\u0061 for "a", and the unused low bits of a base64 string can all change without changing
    what they decode to. So the file is rebuilt from the four values and must come out identical.
    That one comparison also pins every other field (version, cipher, KDF parameters) to the
    values this version writes.
    """
    try:
        document = json.loads(data.decode("ascii"))
        master_hash = document["master_hash"]
        if not isinstance(master_hash, str) or not master_hash.startswith(_master_hash_prefix()):
            # The hash must use our parameters too: otherwise an edited file could make
            # verification run Argon2 with, say, several gigabytes of memory.
            raise ValueError("master_hash is not an Argon2id hash with this version's parameters")
        salt = _b64decode(document["kdf"]["salt"], crypto.SALT_LENGTH)
        nonce = _b64decode(document["nonce"], crypto.NONCE_LENGTH)
        ciphertext = _b64decode(document["ciphertext"])
    except (ValueError, LookupError, TypeError, RecursionError) as exc:
        # ValueError includes bad ASCII, bad JSON and bad base64.
        raise VaultCorrupted("the vault file is damaged: it is not a well-formed vault") from exc
    if len(ciphertext) < crypto.TAG_LENGTH:
        raise VaultCorrupted("the vault file is damaged: the ciphertext is too short")

    if _serialize(_document(_header(master_hash, salt), nonce, ciphertext)) != data:
        raise VaultCorrupted("the vault file has been modified: it is not exactly what this program writes")
    return master_hash, salt, nonce, ciphertext


def _master_hash_prefix() -> str:
    params = crypto.PARAMS
    return f"$argon2id$v=19$m={params.memory_cost},t={params.time_cost},p={params.parallelism}$"


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64decode(text: object, length: int | None = None) -> bytes:
    if not isinstance(text, str):
        raise ValueError("expected a base64 string")
    raw = base64.b64decode(text, validate=True)
    if length is not None and len(raw) != length:
        raise ValueError(f"expected {length} bytes, got {len(raw)}")
    return raw


# --- Entries (the plaintext) ----------------------------------------------------------------


def _encode_entries(entries: dict[str, Entry]) -> bytes:
    plain = {name: {"password": e.password, "username": e.username} for name, e in entries.items()}
    return json.dumps(plain, sort_keys=True).encode("utf-8")


def _decode_entries(plaintext: bytes) -> dict[str, Entry]:
    # The plaintext passed the GCM check, so this program wrote it. This only guards against bugs.
    try:
        plain = json.loads(plaintext.decode("utf-8"))
        entries = {name: Entry(username=e["username"], password=e["password"]) for name, e in plain.items()}
    except (ValueError, LookupError, TypeError, AttributeError) as exc:
        raise VaultCorrupted("the decrypted entries are malformed") from exc
    if not all(isinstance(e.username, str) and isinstance(e.password, str) for e in entries.values()):
        raise VaultCorrupted("the decrypted entries are malformed")
    return entries


# --- Writing --------------------------------------------------------------------------------


def _write_atomically(path: Path, data: bytes) -> None:
    """Write `data` to `path` so that a crash leaves either the old file or the new one, never half.

    The temporary file is created next to the vault, because os.replace is only atomic within
    one file system, and mkstemp creates it with mode 0600, so only the owner can read the vault.
    """
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
