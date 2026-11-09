"""Building block 4: strong password generator.

Every character comes from `secrets`, which reads the operating system's CSPRNG. The `random`
module is a Mersenne Twister: fast and fine for simulations, but predictable. Its whole state
can be rebuilt from 624 consecutive 32-bit outputs, after which every past and future value is
known. A password drawn from it is only as secret as that state.
"""

import math
import secrets
import string

# All 94 printable ASCII characters except space: letters, digits and punctuation.
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = string.punctuation
ALPHABET = LOWERCASE + UPPERCASE + DIGITS + SYMBOLS

DEFAULT_LENGTH = 20  # about 131 bits
MIN_LENGTH = 12      # about 79 bits: out of reach even if a site stores it under a fast hash
MAX_LENGTH = 128     # far above any site's limit; stops a typo like 20000000 from hanging


def generate_password(length: int = DEFAULT_LENGTH) -> str:
    """Return a random password of `length` characters drawn uniformly from ALPHABET.

    Many sites demand at least one lowercase letter, uppercase letter, digit and symbol. Rather
    than inserting the missing kinds (which would make some positions predictable), a password
    lacking one is thrown away and drawn again. The result is uniform over all passwords that
    contain every kind; this costs well under one bit of entropy.
    """
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        raise ValueError(f"length must be between {MIN_LENGTH} and {MAX_LENGTH}")
    while True:
        password = "".join(secrets.choice(ALPHABET) for _ in range(length))
        if all(any(c in kind for c in password) for kind in (LOWERCASE, UPPERCASE, DIGITS, SYMBOLS)):
            return password


def entropy_bits(length: int) -> float:
    """Entropy of a password of `length` characters drawn uniformly from ALPHABET."""
    return length * math.log2(len(ALPHABET))
