"""Errors the vault reports to the user."""


class VaultError(Exception):
    """Base class for every error the vault reports to the user."""


class VaultCorrupted(VaultError):
    """Data read from the vault file was modified or is malformed."""


class WrongMasterPassword(VaultError):
    """The master password does not match the hash stored in the vault."""


class VaultNotFound(VaultError):
    """There is no vault file at the given path."""


class VaultAlreadyExists(VaultError):
    """A vault file already exists at the path where a new one was to be created."""


class EntryNotFound(VaultError):
    """The vault has no entry with the requested name."""


class EntryAlreadyExists(VaultError):
    """The vault already has an entry with that name."""


class BreachCheckFailed(VaultError):
    """The Have I Been Pwned breach check could not be completed."""
