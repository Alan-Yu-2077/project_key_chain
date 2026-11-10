import json
import os
import stat

import pytest

from keychain import cli, generator

MASTER = "correct horse battery staple"


@pytest.fixture
def run(tmp_path, monkeypatch, capsys):
    """Run `vault.py --vault <tmp>/vault.json <args>`.

    `secrets` answers the hidden getpass prompts in order, `inputs` the visible input() prompts.
    Every prompt must be answered and every answer used, so each test also pins down exactly
    which questions a command asks.
    """
    path = tmp_path / "vault.json"

    def run_(*args, secrets=(), inputs=(), vault=path):
        secrets, inputs = list(secrets), list(inputs)
        monkeypatch.setattr("getpass.getpass", lambda prompt="": secrets.pop(0))
        monkeypatch.setattr("builtins.input", lambda prompt="": inputs.pop(0))
        argv = (["--vault", str(vault)] if vault is not None else []) + list(args)
        code = cli.main(argv)
        assert secrets == [] and inputs == [], "a prompt was not asked"
        out, err = capsys.readouterr()
        return code, out, err

    run_.path = path
    return run_


@pytest.fixture
def vault(run):
    """A vault holding one entry, github / alice / s3cret-pass."""
    assert run("init", secrets=[MASTER, MASTER])[0] == 0
    assert run("add", "github", "--user", "alice", secrets=[MASTER, "s3cret-pass", "s3cret-pass"])[0] == 0
    return run


# --- init -----------------------------------------------------------------------------------


def test_init_creates_a_vault(run):
    code, out, _ = run("init", secrets=[MASTER, MASTER])
    assert code == 0
    assert "Created an empty vault" in out
    assert json.loads(run.path.read_text())["master_hash"].startswith("$argon2id$")


def test_init_refuses_mismatched_passwords(run):
    code, _, err = run("init", secrets=[MASTER, MASTER + "!"])
    assert code == 1
    assert "do not match" in err
    assert not run.path.exists()


def test_init_refuses_a_short_master_password(run):
    code, _, err = run("init", secrets=["tooshort"])
    assert code == 1
    assert "at least 12 characters" in err
    assert not run.path.exists()


def test_init_does_not_overwrite_an_existing_vault(vault):
    before = vault.path.read_bytes()
    code, _, err = vault("init")  # refused before any password is asked
    assert code == 1
    assert "already exists" in err
    assert vault.path.read_bytes() == before


def test_default_vault_lives_in_a_private_directory_in_home(run, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert run("init", secrets=[MASTER, MASTER], vault=None)[0] == 0
    directory = tmp_path / "home" / ".keychain"
    assert (directory / "vault.json").is_file()
    assert stat.S_IMODE(os.stat(directory).st_mode) == 0o700


# --- add / get / list / delete --------------------------------------------------------------


def test_get_shows_the_username_and_password(vault):
    code, out, _ = vault("get", "github", secrets=[MASTER])
    assert code == 0
    assert out == "username: alice\npassword: s3cret-pass\n"


def test_add_asks_for_the_username_when_it_is_not_given(vault):
    vault("add", "gitlab", secrets=[MASTER, "pw-for-gitlab", "pw-for-gitlab"], inputs=["bob"])
    assert vault("get", "gitlab", secrets=[MASTER])[1] == "username: bob\npassword: pw-for-gitlab\n"


def test_add_with_generate_stores_and_shows_a_generated_password(vault):
    code, out, _ = vault("add", "mail", "--user", "carol", "--generate", "--length", "24", secrets=[MASTER])
    assert code == 0
    generated = out.split("Generated password: ")[1].strip()
    assert len(generated) == 24
    assert vault("get", "mail", secrets=[MASTER])[1] == f"username: carol\npassword: {generated}\n"


def test_add_refuses_mismatched_passwords(vault):
    code, _, err = vault("add", "gitlab", "--user", "bob", secrets=[MASTER, "one", "two"])
    assert code == 1
    assert "do not match" in err


def test_add_refuses_an_existing_name(vault):
    code, _, err = vault("add", "github", "--user", "mallory", secrets=[MASTER])
    assert code == 1
    assert "already an entry named 'github'" in err


def test_length_without_generate_is_refused(vault):
    code, _, err = vault("add", "gitlab", "--length", "20")
    assert code == 1
    assert "--length only applies together with --generate" in err


def test_list_shows_names_and_usernames_but_no_password(vault):
    vault("add", "a-long-site-name", "--user", "bob", secrets=[MASTER, "pw-2", "pw-2"])
    code, out, _ = vault("list", secrets=[MASTER])
    assert code == 0
    assert out == "a-long-site-name  bob\ngithub            alice\n"
    assert "s3cret-pass" not in out


def test_list_of_an_empty_vault(run):
    run("init", secrets=[MASTER, MASTER])
    assert run("list", secrets=[MASTER])[1] == "The vault is empty.\n"


def test_delete_asks_for_confirmation(vault):
    code, out, _ = vault("delete", "github", secrets=[MASTER], inputs=["n"])
    assert code == 0
    assert "Nothing deleted" in out
    assert vault("get", "github", secrets=[MASTER])[0] == 0

    vault("delete", "github", secrets=[MASTER], inputs=["y"])
    code, _, err = vault("get", "github", secrets=[MASTER])
    assert code == 1
    assert "no entry named 'github'" in err


def test_delete_with_yes_does_not_ask(vault):
    assert vault("delete", "github", "--yes", secrets=[MASTER])[0] == 0
    assert vault("list", secrets=[MASTER])[1] == "The vault is empty.\n"


# --- gen ------------------------------------------------------------------------------------


def test_gen_prints_a_password_of_the_default_length(run):
    code, out, _ = run("gen")
    assert code == 0
    assert len(out.strip()) == generator.DEFAULT_LENGTH


def test_gen_respects_the_chosen_length(run):
    assert len(run("gen", "--length", "40")[1].strip()) == 40


@pytest.mark.parametrize("length", ["8", "129", "twenty"])
def test_gen_refuses_a_bad_length(run, length):
    with pytest.raises(SystemExit) as exit_:
        run("gen", "--length", length)
    assert exit_.value.code == 2


# --- Errors are clear and never a traceback -------------------------------------------------


def test_a_wrong_master_password_is_rejected_with_a_clear_message(vault):
    code, out, err = vault("get", "github", secrets=["not the master password"])
    assert code == 1
    assert err == "error: wrong master password\n"
    assert "s3cret-pass" not in out


def test_a_missing_vault_points_to_init(run):
    code, _, err = run("list", secrets=[MASTER])
    assert code == 1
    assert "python vault.py init" in err


def test_a_modified_vault_is_reported(vault):
    data = bytearray(vault.path.read_bytes())
    data[-10] ^= 1
    vault.path.write_bytes(data)
    code, _, err = vault("get", "github", secrets=[MASTER])
    assert code == 1
    assert err.startswith("error: the vault")


def test_ctrl_c_at_a_prompt_cancels_cleanly(run, monkeypatch):
    def interrupt(prompt=""):
        raise KeyboardInterrupt

    monkeypatch.setattr("getpass.getpass", interrupt)
    assert cli.main(["--vault", str(run.path), "init"]) == 1
    assert not run.path.exists()


# --- No secret is ever an argument ----------------------------------------------------------


@pytest.mark.parametrize("option", ["--password", "--master-password", "--pass"])
def test_no_command_accepts_a_password_argument(run, option):
    for command in (["init"], ["add", "github"], ["get", "github"]):
        with pytest.raises(SystemExit) as exit_:
            run(*command, option, "hunter2hunter2")
        assert exit_.value.code == 2
