"""Cryptographic building blocks of the vault.

Nothing here is home-made: every primitive comes from an established library.

* argon2-cffi  -> Argon2id hash of the master password (stored in the vault, used to verify it)
* cryptography -> Argon2id used as a key derivation function, to obtain the vault key
* cryptography -> AES-256-GCM, to encrypt and authenticate the vault

Randomness comes from the operating system's CSPRNG through `secrets`.
"""

import secrets
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from .errors import VaultCorrupted

KEY_LENGTH = 32    # bytes: a 256-bit key, for AES-256
SALT_LENGTH = 16   # bytes: RFC 9106 recommends 128-bit salts
NONCE_LENGTH = 12  # bytes: the 96-bit nonce GCM is designed for (NIST SP 800-38D)
TAG_LENGTH = 16    # bytes: the 128-bit authentication tag AESGCM appends to the ciphertext


@dataclass(frozen=True)
class Argon2Params:
    """Argon2id cost parameters, shared by the stored hash and the key derivation.

    The defaults are RFC 9106's second recommended option (the one for memory-constrained
    environments), which is also argon2-cffi's default: every guess an attacker makes costs
    3 passes over 64 MiB of memory.
    """

    time_cost: int = 3            # number of passes over the memory
    memory_cost: int = 64 * 1024  # in KiB, so 64 MiB
    parallelism: int = 4          # number of lanes


PARAMS = Argon2Params()


# --- Building block 1: master password stored with Argon2 ----------------------------------


def hash_master_password(password: str) -> str:
    """Hash the master password for storage.

    Returns a self-describing string "$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>".
    argon2-cffi draws a fresh random salt for every call, so hashing the same password twice
    gives two different strings.
    """
    return _hasher().hash(password)


def verify_master_password(stored_hash: str, password: str) -> bool:
    """Check `password` against a hash produced by `hash_master_password`.

    Returns False for a wrong password. A stored value that is not a valid Argon2id hash means
    the vault file was modified, so that raises VaultCorrupted instead.
    """
    # An Argon2 hash string is pure ASCII; argon2-cffi would crash on anything else.
    if not stored_hash.isascii() or not stored_hash.startswith("$argon2id$"):
        raise VaultCorrupted("the stored master-password hash is not an Argon2id hash")
    try:
        return _hasher().verify(stored_hash, password)
    except VerifyMismatchError:
        return False
    except (InvalidHashError, VerificationError) as exc:
        raise VaultCorrupted("the stored master-password hash is malformed") from exc


# --- Building block 2: encryption key derived from the master password ---------------------


def new_salt() -> bytes:
    """Return a fresh random salt for the key derivation.

    It is independent of the salt inside the stored hash, so the stored hash and the derived
    key are unrelated values.
    """
    return secrets.token_bytes(SALT_LENGTH)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive the 256-bit vault key from the master password with Argon2id.

    The same password and salt always give the same key, so the key never has to be stored:
    it is recomputed from the master password at every unlock. Only the salt is stored.
    """
    kdf = Argon2id(
        salt=salt,
        length=KEY_LENGTH,
        iterations=PARAMS.time_cost,
        lanes=PARAMS.parallelism,
        memory_cost=PARAMS.memory_cost,
    )
    return kdf.derive(password.encode("utf-8"))


# --- Building block 3: vault encrypted with AES-GCM ----------------------------------------


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes) -> tuple[bytes, bytes]:
    """Encrypt and authenticate `plaintext` with AES-256-GCM.

    Returns (nonce, ciphertext). The ciphertext ends with the 16-byte authentication tag, which
    covers the ciphertext and `associated_data`: data that is not encrypted but must not be
    modified either (the vault header).

    The nonce is drawn here, fresh for every call, so a caller cannot reuse one by mistake.
    Encrypting two messages with the same key and nonce would break GCM: it would reveal the
    XOR of the two plaintexts and let an attacker forge tags.
    """
    nonce = secrets.token_bytes(NONCE_LENGTH)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, associated_data)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
    """Check the authentication tag, then decrypt.

    If the key, the nonce, the ciphertext, the tag or `associated_data` differs in any bit from
    what `encrypt` used, the tag check fails and this raises VaultCorrupted. It never returns
    unauthenticated plaintext.
    """
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise VaultCorrupted("the vault failed its integrity check (AES-GCM tag mismatch)") from exc


def _hasher() -> PasswordHasher:
    return PasswordHasher(
        time_cost=PARAMS.time_cost,
        memory_cost=PARAMS.memory_cost,
        parallelism=PARAMS.parallelism,
        hash_len=KEY_LENGTH,
        salt_len=SALT_LENGTH,
    )
