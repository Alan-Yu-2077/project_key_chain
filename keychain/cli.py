"""Command-line interface: `python vault.py <command>`.

Secrets (the master password and the stored passwords) are only ever typed at a getpass prompt,
which does not echo them. They are never taken from command-line arguments, which stay in the
shell history and are visible to every user of the machine through `ps`, nor from environment
variables, which child processes inherit.
"""

import argparse
import getpass
import sys
from pathlib import Path

from . import generator, store
from .errors import EntryAlreadyExists, EntryNotFound, VaultAlreadyExists, VaultError, VaultNotFound

# The vault file can be attacked offline, at Argon2's cost per guess and with no rate limit, so
# the master password needs more than the 8 characters NIST allows for online logins.
MIN_MASTER_PASSWORD_LENGTH = 12


def default_vault_path() -> Path:
    return Path.home() / ".keychain" / "vault.json"


def main(argv: list[str] | None = None) -> int:
    """Run one command. Returns the exit status: 0 on success, 1 on an error, 2 on bad usage."""
    args = _parser().parse_args(argv)
    if args.vault is None:
        args.vault = default_vault_path()
    try:
        args.run(args)
    except VaultNotFound as exc:
        return _fail(f"{exc}; create one with `python vault.py init`")
    except VaultError as exc:
        return _fail(str(exc))
    except OSError as exc:
        return _fail(f"cannot access {exc.filename or 'the vault'}: {exc.strerror or exc}")
    except (KeyboardInterrupt, EOFError):
        print(file=sys.stderr)
        return _fail("cancelled")
    return 0


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


# --- Commands -------------------------------------------------------------------------------


def _init(args: argparse.Namespace) -> None:
    if args.vault.exists():  # checked here too, so nobody types a password for nothing
        raise VaultAlreadyExists(f"a vault already exists at {args.vault}")
    password = getpass.getpass("New master password: ")
    if len(password) < MIN_MASTER_PASSWORD_LENGTH:
        raise VaultError(
            f"the master password must be at least {MIN_MASTER_PASSWORD_LENGTH} characters; "
            "a few random words are long and still easy to remember"
        )
    if getpass.getpass("Repeat the master password: ") != password:
        raise VaultError("the two master passwords do not match")
    args.vault.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    store.create(args.vault, password)
    print(f"Created an empty vault at {args.vault}")


def _add(args: argparse.Namespace) -> None:
    if args.length is not None and not args.generate:
        raise VaultError("--length only applies together with --generate")
    vault = _unlock(args)
    if args.name in vault.entries:
        raise EntryAlreadyExists(f"there is already an entry named {args.name!r}; delete it first")
    username = args.user if args.user is not None else input("Username: ")
    if args.generate:
        password = generator.generate_password(args.length or generator.DEFAULT_LENGTH)
    else:
        password = getpass.getpass(f"Password for {args.name}: ")
        if not password:
            raise VaultError("the password is empty")
        if getpass.getpass("Repeat it: ") != password:
            raise VaultError("the two passwords do not match")
    vault.entries[args.name] = store.Entry(username, password)
    vault.save()
    print(f"Added {args.name}")
    if args.generate:
        print(f"Generated password: {password}")


def _get(args: argparse.Namespace) -> None:
    entry = _entry(_unlock(args), args.name)
    print(f"username: {entry.username}")
    print(f"password: {entry.password}")


def _list(args: argparse.Namespace) -> None:
    entries = _unlock(args).entries
    if not entries:
        print("The vault is empty.")
        return
    width = max(len(name) for name in entries)
    for name in sorted(entries):
        print(f"{name:<{width}}  {entries[name].username}")


def _delete(args: argparse.Namespace) -> None:
    vault = _unlock(args)
    entry = _entry(vault, args.name)
    if not args.yes:
        answer = input(f"Delete {args.name} ({entry.username})? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("Nothing deleted.")
            return
    del vault.entries[args.name]
    vault.save()
    print(f"Deleted {args.name}")


def _gen(args: argparse.Namespace) -> None:
    print(generator.generate_password(args.length))


def _unlock(args: argparse.Namespace) -> store.Vault:
    return store.unlock(args.vault, getpass.getpass("Master password: "))


def _entry(vault: store.Vault, name: str) -> store.Entry:
    try:
        return vault.entries[name]
    except KeyError:
        raise EntryNotFound(f"there is no entry named {name!r}") from None


# --- Argument parsing -----------------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault.py",
        description="A small command-line password manager. Passwords are always typed at a "
                    "hidden prompt, never given as arguments.",
    )
    parser.add_argument("--vault", type=Path, metavar="PATH",
                        help="the vault file (default: ~/.keychain/vault.json)")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    init = commands.add_parser("init", help="create a new vault and set its master password")
    init.set_defaults(run=_init)

    add = commands.add_parser("add", help="add an entry")
    add.add_argument("name", help="what the entry is for, e.g. github")
    add.add_argument("--user", help="the username (asked for if left out)")
    add.add_argument("--generate", action="store_true", help="generate the password instead of typing it")
    add.add_argument("--length", type=_length,
                     help=f"length of the generated password (default {generator.DEFAULT_LENGTH})")
    add.set_defaults(run=_add)

    get = commands.add_parser("get", help="show an entry's username and password")
    get.add_argument("name")
    get.set_defaults(run=_get)

    list_ = commands.add_parser("list", help="list entries and usernames (no passwords)")
    list_.set_defaults(run=_list)

    delete = commands.add_parser("delete", help="delete an entry")
    delete.add_argument("name")
    delete.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    delete.set_defaults(run=_delete)

    gen = commands.add_parser("gen", help="generate a strong password (no vault needed)")
    gen.add_argument("--length", type=_length, default=generator.DEFAULT_LENGTH,
                     help=f"number of characters (default {generator.DEFAULT_LENGTH})")
    gen.set_defaults(run=_gen)
    return parser


def _length(text: str) -> int:
    try:
        length = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number: {text!r}") from None
    if not generator.MIN_LENGTH <= length <= generator.MAX_LENGTH:
        raise argparse.ArgumentTypeError(
            f"must be between {generator.MIN_LENGTH} and {generator.MAX_LENGTH}"
        )
    return length
