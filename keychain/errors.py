"""Errors the vault reports to the user."""


class VaultError(Exception):
    """Base class for every error the vault reports to the user."""


class VaultCorrupted(VaultError):
    """Data read from the vault file was modified or is malformed."""
