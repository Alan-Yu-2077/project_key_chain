"""The assignment's "done when" checks for the four building blocks.

Blocks 1-3 run against a real vault file; block 4 checks the password generator.
"""

import ast
import base64
import json
import string
from pathlib import Path

import pytest

from keychain import crypto, generator, store
from keychain.errors import VaultCorrupted, WrongMasterPassword

PASSWORD = "correct horse battery staple"


def make_vault(path):
    vault = store.create(path, PASSWORD)
    vault.entries["github"] = store.Entry("alice", "s3cret")
    vault.save()


def test_1_master_password_is_stored_as_argon2id_and_a_wrong_one_is_rejected(tmp_path):
    """Done when: the stored master-password value is an `$argon2id$...` string, and a wrong master
    password is rejected."""
    path = tmp_path / "vault.json"
    make_vault(path)

    assert json.loads(path.read_text())["master_hash"].startswith("$argon2id$")
    assert PASSWORD.encode() not in path.read_bytes()
    with pytest.raises(WrongMasterPassword, match="wrong master password"):
        store.unlock(path, "not the master password")


def test_2_there_is_no_key_file_and_the_master_password_alone_opens_the_vault(tmp_path):
    """Done when: there is no key file. The only secret that unlocks the vault is the master
    password."""
    path = tmp_path / "vault.json"
    make_vault(path)

    assert [p.name for p in tmp_path.iterdir()] == ["vault.json"]
    salt = base64.b64decode(json.loads(path.read_text())["kdf"]["salt"])
    key = crypto.derive_key(PASSWORD, salt)
    data = path.read_bytes()
    assert key.hex().encode() not in data
    assert base64.b64encode(key).rstrip(b"=") not in data
    # A fresh unlock gets nothing but the path and the master password.
    assert store.unlock(path, PASSWORD).entries == {"github": store.Entry("alice", "s3cret")}


def test_3_flipping_any_bit_of_the_vault_file_fails_loudly(tmp_path, monkeypatch):
    """Done when: flipping a single byte of the vault file makes decryption fail loudly, not
    return garbage.

    This flips every bit of every byte, one at a time, and unlocks with the right password. Each
    attempt must raise VaultCorrupted. The one exception is a flip inside the stored master hash:
    a modified hash cannot be told apart from a wrong password, so WrongMasterPassword is also
    accepted there. Either way the vault does not open.

    That is several thousand unlocks, so this test lowers the Argon2 cost parameters to keep it
    fast. They play no part in detecting changes, which comes from the strict parser and the GCM
    tag.
    """
    monkeypatch.setattr(crypto, "PARAMS", crypto.Argon2Params(time_cost=1, memory_cost=8, parallelism=1))
    path = tmp_path / "vault.json"
    make_vault(path)
    original = path.read_bytes()
    assert store.unlock(path, PASSWORD).entries == {"github": store.Entry("alice", "s3cret")}

    master_hash = json.loads(original)["master_hash"].encode()
    hash_start = original.index(master_hash)
    hash_end = hash_start + len(master_hash)

    for i in range(len(original)):
        for bit in range(8):
            tampered = bytearray(original)
            tampered[i] ^= 1 << bit
            path.write_bytes(tampered)
            try:
                store.unlock(path, PASSWORD)
            except VaultCorrupted:
                continue
            except WrongMasterPassword:
                assert hash_start <= i < hash_end, f"byte {i}, bit {bit}: reported as a wrong password"
                continue
            pytest.fail(f"flipping bit {bit} of byte {i} went undetected")


def test_4_generated_passwords_are_long_random_and_use_a_wide_character_set():
    """Done when: passwords are long, random, and use a wide character set, from `secrets` and
    not `random`; the user picks the length."""
    assert len(generator.generate_password()) >= 20
    assert len(generator.generate_password(32)) == 32
    assert len(generator.ALPHABET) == 94

    passwords = {generator.generate_password() for _ in range(1000)}
    assert len(passwords) == 1000
    used = set("".join(passwords))
    for kind in (string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation):
        assert set(kind) <= used

    imports = _imported_modules(Path(generator.__file__))
    assert "secrets" in imports
    root = Path(__file__).resolve().parent.parent
    for source in [root / "vault.py", *sorted((root / "keychain").glob("*.py"))]:
        assert "random" not in _imported_modules(source), f"{source.name} imports random"


def _imported_modules(source):
    """Top-level names of every module `source` imports, found by parsing it, not by grep."""
    names = set()
    for node in ast.walk(ast.parse(source.read_text())):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names
