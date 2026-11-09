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
        "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNö",  # not ASCII
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


# --- Building block 3: vault encrypted with AES-GCM ----------------------------------------

KEY = bytes(range(32))
PLAINTEXT = b'{"github": {"password": "s3cret", "username": "alice"}}'
AAD = b'{"version":1}'


def test_encrypt_then_decrypt_gives_back_the_plaintext():
    nonce, ciphertext = crypto.encrypt(KEY, PLAINTEXT, AAD)
    assert crypto.decrypt(KEY, nonce, ciphertext, AAD) == PLAINTEXT


def test_ciphertext_hides_the_plaintext_and_carries_a_16_byte_tag():
    _, ciphertext = crypto.encrypt(KEY, PLAINTEXT, AAD)
    assert len(ciphertext) == len(PLAINTEXT) + 16
    assert b"s3cret" not in ciphertext


def test_every_encryption_uses_a_fresh_96_bit_nonce():
    results = [crypto.encrypt(KEY, PLAINTEXT, AAD) for _ in range(1000)]
    nonces = {nonce for nonce, _ in results}
    assert len(nonces) == 1000
    assert all(len(nonce) == 12 for nonce in nonces)
    assert len({ciphertext for _, ciphertext in results}) == 1000


def test_decrypt_rejects_a_wrong_key():
    nonce, ciphertext = crypto.encrypt(KEY, PLAINTEXT, AAD)
    with pytest.raises(VaultCorrupted):
        crypto.decrypt(bytes(32), nonce, ciphertext, AAD)


def test_decrypt_rejects_a_different_nonce():
    nonce, ciphertext = crypto.encrypt(KEY, PLAINTEXT, AAD)
    with pytest.raises(VaultCorrupted):
        crypto.decrypt(KEY, bytes([nonce[0] ^ 1]) + nonce[1:], ciphertext, AAD)


def test_decrypt_rejects_different_associated_data():
    nonce, ciphertext = crypto.encrypt(KEY, PLAINTEXT, AAD)
    with pytest.raises(VaultCorrupted):
        crypto.decrypt(KEY, nonce, ciphertext, b'{"version":2}')


def test_decrypt_rejects_any_flipped_bit_in_the_ciphertext_or_tag():
    nonce, ciphertext = crypto.encrypt(KEY, PLAINTEXT, AAD)
    for i in range(len(ciphertext)):
        for bit in range(8):
            tampered = bytearray(ciphertext)
            tampered[i] ^= 1 << bit
            with pytest.raises(VaultCorrupted):
                crypto.decrypt(KEY, nonce, bytes(tampered), AAD)
