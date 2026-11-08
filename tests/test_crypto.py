import base64

import pytest

from keychain import crypto
from keychain.errors import VaultCorrupted

PASSWORD = "correct horse battery staple"


# --- Building block 1: master password stored with Argon2 ----------------------------------


def test_hash_is_an_argon2id_string_with_rfc9106_parameters():
    assert crypto.hash_master_password(PASSWORD).startswith("$argon2id$v=19$m=65536,t=3,p=4$")


def test_hash_does_not_contain_the_password():
    assert PASSWORD not in crypto.hash_master_password(PASSWORD)


def test_hash_is_salted():
    assert crypto.hash_master_password(PASSWORD) != crypto.hash_master_password(PASSWORD)


def test_verify_accepts_the_right_password():
    assert crypto.verify_master_password(crypto.hash_master_password(PASSWORD), PASSWORD) is True


def test_verify_rejects_a_wrong_password():
    assert crypto.verify_master_password(crypto.hash_master_password(PASSWORD), PASSWORD + "!") is False


@pytest.mark.parametrize(
    "stored",
    [
        "",
        "plain-text-password",
        "$argon2i$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo",  # Argon2i, not Argon2id
        "$argon2id$garbage",
    ],
)
def test_verify_treats_a_malformed_stored_hash_as_corruption(stored):
    with pytest.raises(VaultCorrupted):
        crypto.verify_master_password(stored, PASSWORD)


# --- Building block 2: encryption key derived from the master password ---------------------


def test_derived_key_is_256_bits():
    assert len(crypto.derive_key(PASSWORD, crypto.new_salt())) == 32


def test_same_password_and_salt_give_the_same_key():
    salt = crypto.new_salt()
    assert crypto.derive_key(PASSWORD, salt) == crypto.derive_key(PASSWORD, salt)


def test_key_depends_on_the_password():
    salt = crypto.new_salt()
    assert crypto.derive_key(PASSWORD, salt) != crypto.derive_key(PASSWORD + "!", salt)


def test_key_depends_on_the_salt():
    assert crypto.derive_key(PASSWORD, crypto.new_salt()) != crypto.derive_key(PASSWORD, crypto.new_salt())


def test_salts_are_random_and_128_bits():
    salts = {crypto.new_salt() for _ in range(1000)}
    assert len(salts) == 1000
    assert all(len(salt) == 16 for salt in salts)


def test_derived_key_is_unrelated_to_the_stored_hash():
    """The stored hash must not reveal the key. The PHC string encodes its hash in unpadded
    base64, so check both encodings of the key."""
    key = crypto.derive_key(PASSWORD, crypto.new_salt())
    stored = crypto.hash_master_password(PASSWORD)
    assert key.hex() not in stored
    assert base64.b64encode(key).decode().rstrip("=") not in stored
