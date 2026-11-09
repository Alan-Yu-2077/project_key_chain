import base64
import json
import os
import stat

import pytest

from keychain import crypto, store
from keychain.errors import VaultAlreadyExists, VaultCorrupted, VaultNotFound, WrongMasterPassword

PASSWORD = "correct horse battery staple"


@pytest.fixture
def path(tmp_path):
    return tmp_path / "vault.json"


def load(path):
    return json.loads(path.read_text())


def write_canonical(path, document):
    """Write `document` in the same byte form the vault uses, so only the values differ."""
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


# --- Creating, saving, reopening ------------------------------------------------------------


def test_a_new_vault_is_empty_and_reopens_with_the_master_password(path):
    store.create(path, PASSWORD)
    assert store.unlock(path, PASSWORD).entries == {}


def test_saved_entries_survive_reopening(path):
    vault = store.create(path, PASSWORD)
    vault.entries["github"] = store.Entry("alice", "s3cret")
    vault.entries["café.fr"] = store.Entry("bob", "pässwörd 🔑")
    vault.save()
    assert store.unlock(path, PASSWORD).entries == {
        "github": store.Entry("alice", "s3cret"),
        "café.fr": store.Entry("bob", "pässwörd 🔑"),
    }


def test_deleted_entries_stay_deleted(path):
    vault = store.create(path, PASSWORD)
    vault.entries["github"] = store.Entry("alice", "s3cret")
    vault.save()
    vault = store.unlock(path, PASSWORD)
    del vault.entries["github"]
    vault.save()
    assert store.unlock(path, PASSWORD).entries == {}


def test_create_refuses_to_overwrite_an_existing_vault(path):
    store.create(path, PASSWORD)
    before = path.read_bytes()
    with pytest.raises(VaultAlreadyExists):
        store.create(path, "another password")
    assert path.read_bytes() == before


def test_unlock_reports_a_missing_vault(path):
    with pytest.raises(VaultNotFound):
        store.unlock(path, PASSWORD)


def test_unlock_rejects_a_wrong_master_password(path):
    store.create(path, PASSWORD)
    with pytest.raises(WrongMasterPassword):
        store.unlock(path, PASSWORD + "!")


# --- What is on disk ------------------------------------------------------------------------


def test_file_has_the_documented_format(path):
    store.create(path, PASSWORD)
    document = load(path)
    assert document.keys() == {"cipher", "ciphertext", "kdf", "master_hash", "nonce", "version"}
    assert document["version"] == 1
    assert document["cipher"] == "aes-256-gcm"
    assert document["kdf"] == {
        "alg": "argon2id",
        "memory_cost": 65536,
        "parallelism": 4,
        "salt": document["kdf"]["salt"],
        "time_cost": 3,
    }
    assert len(base64.b64decode(document["kdf"]["salt"])) == 16
    assert len(base64.b64decode(document["nonce"])) == 12
    assert document["master_hash"].startswith("$argon2id$v=19$m=65536,t=3,p=4$")


def test_entries_are_not_readable_in_the_file(path):
    vault = store.create(path, PASSWORD)
    vault.entries["github"] = store.Entry("alice", "s3cret")
    vault.save()
    data = path.read_bytes()
    for secret in (b"github", b"alice", b"s3cret", PASSWORD.encode()):
        assert secret not in data


def test_every_save_uses_a_fresh_nonce(path):
    vault = store.create(path, PASSWORD)
    first = load(path)
    vault.save()  # same entries, same key
    second = load(path)
    assert first["nonce"] != second["nonce"]
    assert first["ciphertext"] != second["ciphertext"]
    assert first["kdf"]["salt"] == second["kdf"]["salt"]
    assert first["master_hash"] == second["master_hash"]


def test_vault_file_is_readable_by_its_owner_only(path):
    store.create(path, PASSWORD)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_save_leaves_no_temporary_file(path):
    vault = store.create(path, PASSWORD)
    vault.save()
    assert [p.name for p in path.parent.iterdir()] == ["vault.json"]


def test_a_failed_save_keeps_the_previous_file(path, monkeypatch):
    vault = store.create(path, PASSWORD)
    before = path.read_bytes()

    def fail(*args):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", fail)
    vault.entries["github"] = store.Entry("alice", "s3cret")
    with pytest.raises(OSError):
        vault.save()
    assert path.read_bytes() == before
    assert [p.name for p in path.parent.iterdir()] == ["vault.json"]


def test_repr_never_shows_a_password():
    assert "s3cret" not in repr(store.Entry("alice", "s3cret"))


# --- The parser accepts only what save() writes ---------------------------------------------


def test_reformatted_json_is_rejected(path):
    """Same values, different whitespace: GCM alone would not notice, the parser must."""
    store.create(path, PASSWORD)
    path.write_text(json.dumps(load(path), indent=4, sort_keys=True) + "\n")
    with pytest.raises(VaultCorrupted):
        store.unlock(path, PASSWORD)


def test_an_escaped_character_is_rejected(path):
    """"\\u0061" decodes to "a", so the value is unchanged but the bytes are not."""
    store.create(path, PASSWORD)
    path.write_bytes(path.read_bytes().replace(b'"aes-256-gcm"', b'"\\u0061es-256-gcm"'))
    assert load(path)["cipher"] == "aes-256-gcm"
    with pytest.raises(VaultCorrupted):
        store.unlock(path, PASSWORD)


def test_non_canonical_base64_is_rejected(path):
    """A 16-byte salt is 22 base64 digits plus "==". The last digit carries 4 unused bits, so
    changing them gives a different string that decodes to the same salt."""
    store.create(path, PASSWORD)
    document = load(path)
    salt = document["kdf"]["salt"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    tweaked = salt[:21] + alphabet[alphabet.index(salt[21]) ^ 1] + salt[22:]
    assert base64.b64decode(tweaked) == base64.b64decode(salt)
    document["kdf"]["salt"] = tweaked
    write_canonical(path, document)
    with pytest.raises(VaultCorrupted):
        store.unlock(path, PASSWORD)


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(version=2),
        lambda d: d.update(version=True),
        lambda d: d.update(cipher="aes-128-gcm"),
        lambda d: d.update(extra="field"),
        lambda d: d.pop("nonce"),
        lambda d: d["kdf"].update(memory_cost=4 * 1024 * 1024),  # 4 GiB per guess
        lambda d: d["kdf"].update(time_cost=1),
        lambda d: d.update(master_hash=d["master_hash"].replace("m=65536", "m=4194304")),
        lambda d: d.update(master_hash=d["master_hash"][:-1] + "ö"),  # written as ö
        lambda d: d.update(nonce=base64.b64encode(bytes(16)).decode()),
        lambda d: d.update(ciphertext=""),
    ],
    ids=[
        "other-version", "boolean-version", "other-cipher", "extra-field", "missing-nonce",
        "huge-kdf-memory", "weaker-kdf", "huge-hash-memory", "non-ascii-hash", "long-nonce",
        "empty-ciphertext",
    ],
)
def test_anything_but_this_version_s_exact_format_is_rejected(path, change):
    store.create(path, PASSWORD)
    document = load(path)
    change(document)
    write_canonical(path, document)
    with pytest.raises(VaultCorrupted):
        store.unlock(path, PASSWORD)


# --- The header is authenticated ------------------------------------------------------------


def test_swapping_in_an_attacker_s_master_hash_does_not_open_the_vault(tmp_path):
    """The attacker replaces master_hash with the hash of a password they know. That password
    now passes the hash check, but it derives the wrong key and the header no longer matches the
    associated data, so AES-GCM refuses to decrypt."""
    victim, attacker = tmp_path / "victim.json", tmp_path / "attacker.json"
    store.create(victim, PASSWORD)
    store.create(attacker, "attacker password")
    document = load(victim)
    document["master_hash"] = load(attacker)["master_hash"]
    write_canonical(victim, document)

    with pytest.raises(VaultCorrupted):
        store.unlock(victim, "attacker password")
    with pytest.raises(WrongMasterPassword):
        store.unlock(victim, PASSWORD)


def test_the_key_comes_from_the_password_and_the_kdf_salt(path):
    """Decrypting by hand with a key derived from the file's salt works: nothing else is needed."""
    vault = store.create(path, PASSWORD)
    vault.entries["github"] = store.Entry("alice", "s3cret")
    vault.save()
    document = load(path)
    key = crypto.derive_key(PASSWORD, base64.b64decode(document["kdf"]["salt"]))
    header = {k: v for k, v in document.items() if k not in ("nonce", "ciphertext")}
    aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    plaintext = crypto.decrypt(
        key, base64.b64decode(document["nonce"]), base64.b64decode(document["ciphertext"]), aad
    )
    assert json.loads(plaintext) == {"github": {"password": "s3cret", "username": "alice"}}
