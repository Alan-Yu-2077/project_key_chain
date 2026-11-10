import string

import pytest

from keychain import generator

KINDS = (string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation)


def test_alphabet_is_the_94_printable_ascii_characters_without_space():
    assert sorted(generator.ALPHABET) == sorted(chr(c) for c in range(33, 127))


def test_default_length_is_20_characters_and_about_131_bits():
    assert len(generator.generate_password()) == 20
    assert round(generator.entropy_bits(20)) == 131


@pytest.mark.parametrize("length", [generator.MIN_LENGTH, 24, 64, generator.MAX_LENGTH])
def test_the_chosen_length_is_respected(length):
    assert len(generator.generate_password(length)) == length


@pytest.mark.parametrize("length", [0, 8, generator.MIN_LENGTH - 1, generator.MAX_LENGTH + 1])
def test_lengths_outside_the_allowed_range_are_refused(length):
    with pytest.raises(ValueError):
        generator.generate_password(length)


def test_every_password_contains_every_kind_of_character():
    # At the minimum length about 30 % of draws lack a kind and are drawn again.
    for _ in range(500):
        password = generator.generate_password(generator.MIN_LENGTH)
        assert all(any(c in kind for c in password) for kind in KINDS)


def test_characters_are_spread_evenly_over_the_alphabet():
    """40,000 characters: each of the 94 is expected about 425 times. The bounds are loose
    (about 10 standard deviations), so this only catches a broken generator, not bad luck."""
    counts = dict.fromkeys(generator.ALPHABET, 0)
    for _ in range(2000):
        for c in generator.generate_password(20):
            counts[c] += 1
    assert min(counts.values()) > 200
    assert max(counts.values()) < 650
