# project_key_chain

A small command-line password manager, written for EPITA Software Security, Project 2.

It keeps your passwords in one encrypted file. The only thing that opens it is a master password
that you remember: no key is stored anywhere on disk.

Team: Alan, Leah and Theodore.

## Quick start

Needs Python 3.10 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

```text
$ python vault.py init
New master password:
Repeat the master password:
Created an empty vault at /Users/alice/.keychain/vault.json

$ python vault.py add github --user alice
Master password:
Password for github:
Repeat it:
Added github

$ python vault.py add mail --user carol --generate --length 24
Master password:
Added mail
Generated password: 8v}Qe#2LtW_m(Rx0j&Ka9!pZ

$ python vault.py list
Master password:
github  alice
mail    carol

$ python vault.py get github
Master password:
username: alice
password: hunter2-but-longer
```

Nothing typed at the password prompts is shown on screen.

## Commands

| Command | What it does |
|---|---|
| `init` | Create a new vault and set its master password (typed twice, at least 12 characters). |
| `add NAME [--user USER] [--generate [--length N]]` | Add an entry. The password is typed twice, or generated with `--generate`. The username is asked for if `--user` is left out. |
| `get NAME` | Show the entry's username and password. |
| `list` | List the entries and their usernames. Never shows a password. |
| `delete NAME [--yes]` | Delete an entry, after a `[y/N]` confirmation unless `--yes` is given. |
| `gen [--length N]` | Print a strong password. Needs no vault. Default length 20, allowed 12 to 128. |
| `check [NAME ...]` | Check the stored passwords (all of them, or the ones named) against known breaches with Have I Been Pwned. The only command that uses the network. |

- The vault is `~/.keychain/vault.json` by default. `--vault PATH` picks another file and goes
  **before** the command: `python vault.py --vault /tmp/test.json init`.
- The vault's directory is created with mode `0700` and the file with mode `0600`.
- Passwords are only ever typed at a hidden prompt. No command accepts a password as an argument
  or reads one from an environment variable.
- To change an entry, `delete` it and `add` it again.
- Errors are one line, `error: ...`, with exit status 1. A mistyped command exits with status 2.

## How it works

```text
init   : master password (typed twice)
         -> master_hash = Argon2id hash of it        (argon2-cffi; carries its own random salt)
         -> salt = 16 random bytes                   (for the key derivation only)
         -> key  = Argon2id KDF(password, salt)      (cryptography; 32 bytes, never stored)
         -> AES-256-GCM encrypt(key, entries, associated data = header) -> write the file

unlock : read the file -> strict parse (the file must be exactly in canonical form)
         -> check the password against master_hash   (mismatch -> "wrong master password")
         -> key = Argon2id KDF(password, salt)
         -> AES-256-GCM decrypt                      (tag mismatch -> "the vault failed its integrity check")

save   : fresh random 12-byte nonce -> encrypt again -> temporary file, fsync, os.replace
```

The vault file:

```json
{
  "cipher": "aes-256-gcm",
  "ciphertext": "<base64: AES-GCM ciphertext + 16-byte authentication tag>",
  "kdf": {
    "alg": "argon2id",
    "memory_cost": 65536,
    "parallelism": 4,
    "salt": "<base64: 16 bytes>",
    "time_cost": 3
  },
  "master_hash": "$argon2id$v=19$m=65536,t=3,p=4$...",
  "nonce": "<base64: 12 bytes>",
  "version": 1
}
```

- **No key is stored.** The key exists only in memory and is derived again from the master
  password at every unlock.
- **Everything about the entries is encrypted:** names, usernames and passwords are all inside
  `ciphertext`.
- **The header** (`cipher`, `kdf`, `master_hash`, `version`) is not secret but is passed to AES-GCM
  as associated data, so changing any of it makes decryption fail. `nonce` and `ciphertext` are
  covered by the tag itself.
- **The parser only accepts a byte-for-byte canonical file** (sorted keys, fixed indentation,
  canonical base64), so even bytes that would decode to the same values, such as extra
  whitespace or unused base64 bits, are rejected.
- **Saving is atomic:** the new vault is written to a temporary file in the same directory and
  then renamed over the old one, so a crash mid-save leaves the old vault intact.

| Parameter | Value | Where |
|---|---|---|
| Argon2id cost (hash and KDF) | time 3, memory 64 MiB, parallelism 4 (RFC 9106, second recommended option) | `keychain/crypto.py`, `Argon2Params` |
| Salt of the stored hash / hash length | 16 / 32 bytes | `crypto._hasher` |
| Salt of the key derivation | 16 bytes, drawn independently | `crypto.new_salt` |
| Key / nonce / tag | 32 / 12 / 16 bytes | `crypto.py` constants |
| Generated passwords | 94 printable ASCII characters, default length 20 (about 131 bits), 12 to 128 | `keychain/generator.py` |
| Minimum master-password length | 12 characters | `cli.MIN_MASTER_PASSWORD_LENGTH` |

```text
vault.py               entry point
keychain/crypto.py     Argon2id hash, Argon2id key derivation, AES-GCM (building blocks 1-3)
keychain/store.py      vault file format, strict parsing, atomic save
keychain/generator.py  password generator (building block 4)
keychain/hibp.py       breach check (bonus B)
keychain/cli.py        command-line interface
keychain/errors.py     the errors shown to the user
tests/                 129 tests
```

## Libraries

| Library | Used for |
|---|---|
| [`argon2-cffi`](https://argon2-cffi.readthedocs.io/) | Hashing and verifying the master password with Argon2id. |
| [`cryptography`](https://cryptography.io/) | Argon2id as a key derivation function, and AES-256-GCM. |
| `secrets` (standard library) | Every random value: salts, nonces and generated passwords. |
| `urllib`, `hashlib` (standard library) | The Have I Been Pwned request and the SHA-1 it is indexed by. |

We use established libraries and write no cryptography of our own: home-made crypto is exactly
where subtle, invisible mistakes hide (and the assignment forbids it). The two libraries split the
work by what each Argon2 call has to produce:

- **`argon2-cffi`** for the stored hash. Its job is verification, and it produces exactly the
  self-describing `$argon2id$v=19$m=...,t=...,p=...$salt$hash` string that is needed for that: the
  salt and the parameters travel with the hash.
- **`cryptography`** for the key. AES needs raw key bytes, and its Argon2id KDF returns raw bytes.
  The same library also provides AES-GCM.

Same primitive, two different purposes, so each comes from the API made for that purpose.

## Design choices

### 1. Why Argon2 for the master password, and not SHA-256 or AES?

Someone who steals the vault file can test guesses for the master password on their own machine,
offline, with no limit on the number of tries. SHA-256 is designed to be fast, so a master password
stored as a SHA-256 hash could be brute-forced in a time the attacker can easily afford: on our test
machine one SHA-256 takes about 0.25 µs even in plain Python (about 4 million guesses per second on
one core), and a GPU computes billions per second.

Argon2 is slow on purpose, and on top of that it needs memory: every guess uses 64 MiB, spread
over 4 parallel lanes. This raises the hardware cost of brute force. An attacker with limited
hardware cannot run many guesses at the same time, so cannot crack the password quickly. On the
same machine, one Argon2id guess with our parameters takes about 37 ms, about 150,000 times longer
than one SHA-256.

AES would not make sense here. Encrypting the master password needs a key, and that key has to be
somewhere: storing it on disk is ruled out, and deriving it from the master password is circular,
since we would need the master password to decrypt the master password. And we never need the
master password back: we only need to check it, and a one-way hash is enough for that.

The salt (16 random bytes, new for every hash):

1. makes precomputed rainbow tables useless;
2. gives the same password a different hash every time;
3. makes the attacker's comparisons more expensive: each salted hash has to be attacked on its own,
   instead of comparing one computation against many hashes at once.

### 2. Why derive the key from the master password instead of storing a key file?

A random key saved in a file next to the vault would be like leaving the key next to the lock:
whoever gets the files gets everything inside, and the master password is just for show. When the
key is derived, there is nothing on disk that opens the vault: the master password, in the user's
head, is the only way in.

The price: the master password becomes the one and only key. If it is lost, the key is lost with
it, and nothing will ever decrypt the vault again. There is no recovery.

**Two Argon2 runs, two independent salts.** The stored hash is written in clear in the vault file.
If the key derivation reused its salt (with the same parameters and length), the derived key would
be exactly the hash stored in the file, and anyone reading the file would have the key. With
independent salts, the stored hash says nothing about the key.

**The stored hash is not what protects the vault.** It only lets us say "wrong master password"
clearly. An attacker who replaces it with the hash of a password of their own gets past that check,
but the key is still derived from the password typed, so it is the wrong key and AES-GCM refuses
to decrypt.

### 3. Why AES-GCM, and not AES without authentication?

Without authentication, an attacker who can guess where sensitive information sits in the file can
change it on purpose, without ever needing the key: with AES-CTR, for instance, flipping a bit of
the ciphertext flips the same bit of the plaintext. Just destroying data is even easier: flipping a
few bytes anywhere is enough. Either way, decryption would hand back the modified data as if
nothing had happened.

**What GCM adds** is a 16-byte authentication tag, computed over the ciphertext and over the
associated data. Decryption checks the tag first; if any bit of the key, the nonce, the ciphertext,
the tag or the associated data differs, it refuses and returns nothing.

**The header as associated data.** The header (`cipher`, `kdf`, `master_hash`, `version`) is not
secret, but it must not be changed. Passing it as associated data makes GCM check it too. Changing
the salt or the KDF parameters would already give a wrong key, but fields that do not change the
key, such as `master_hash` or `version`, could otherwise be modified without GCM noticing.

**A fresh nonce at every save.** Encrypting two messages with the same key and the same nonce
breaks GCM: it reveals the XOR of the two plaintexts and lets an attacker forge tags. `encrypt`
draws a new random 12-byte nonce itself on every call, so no caller can reuse one by mistake.

**Every bit is covered.** A modified vault never opens: the parser rejects anything that is not
exactly the expected format, a modified `master_hash` no longer matches the password (so it is
reported as a wrong master password), and any other change fails the GCM check. GCM alone is not
quite enough, though: it only authenticates the bytes it is given, and JSON whitespace or unused
base64 bits can change without changing those bytes. So the parser rebuilds the file from the
values it read and requires it to be byte-for-byte identical. The acceptance test flips every
bit of every byte of a vault file, one at a time, and each flip is reported.

### 4. Why `secrets` and not `random` for generating passwords?

`random` is a Mersenne Twister, a pseudo-random generator made for simulations, not for security.
Its output is predictable: after observing enough of it (624 consecutive 32-bit outputs), anyone
can rebuild its whole internal state and compute every value that follows. Its seed is not the
problem (by default it comes from the operating system); its structure is.

`secrets` draws from the operating system's cryptographically secure random source (`os.urandom`),
whose next output cannot be predicted, even from everything it produced before.

Our generator picks every character with `secrets.choice` among the 94 printable ASCII characters,
so a 20-character password has about 131 bits of entropy. When a password lacks one kind of
character (lowercase, uppercase, digit, symbol), the whole password is drawn again instead of
patching the missing kind in: patching would make some passwords more likely than others, while
drawing again keeps every valid password equally likely. It costs only about 0.2 bits of entropy
at length 20.

## Security model

### What it protects against

Someone who steals the vault file gets the vault content encrypted with the key derived from the
master password, plus the fields we write in clear (algorithm names, Argon2 parameters, salt,
master-password hash, nonce). They get neither the master password nor any stored entry: names,
usernames and passwords are all inside the ciphertext. The only way in is to guess the master
password, at Argon2's cost for every guess.

The tool also:

- detects any change to the vault file and refuses to open it, instead of returning altered data;
- never takes a password from the command line (which ends up in the shell history and is visible
  to other users through `ps`) or from an environment variable (inherited by child processes):
  passwords are typed at a prompt that does not echo them;
- keeps the vault private to its owner on a shared machine (directory `0700`, file `0600`).

### What it does not protect against

- **Attacks on the machine itself: keyloggers, malware, memory.** The protection is for the file at
  rest. A keylogger records the master password as it is typed, and malware running as the user
  can read the passwords from memory while the vault is open. A program cannot defend against the
  machine it runs on.
- **A weak master password.** We require at least 12 characters, but length is only a floor:
  `Password1234` is long enough and still weak, and we do not check against a list of common
  passwords. Argon2 makes every guess expensive, but a password that is among the first guesses
  still falls.
- **Someone seeing the information directly.** `get` and `add --generate` print the password,
  because the user needs to see it to use it. Anyone looking at the screen, a screen recording, the
  terminal's scrollback, or output redirected to a file can capture it. The tool keeps passwords
  safe in storage; it cannot help against someone standing behind you.

## Bonus: breach check with Have I Been Pwned

`python vault.py check` asks Have I Been Pwned whether the stored passwords appear in a known
breach, without sending them:

```text
password  --SHA-1-->  5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
                      \___/\_________________________________/
                    sent: only        kept on this machine
                    these 5

GET https://api.pwnedpasswords.com/range/5BAA6
```

The service answers with every breached hash that starts with those 5 characters (the other 35
characters of each, and how many times it was seen, about two thousand lines), and the password's
own 35 characters are looked up in that list locally.

- The request asks for padding (`Add-Padding: true`): the answer is filled up with a random number
  of fake entries with a count of 0.
- Each prefix is requested at most once per check.
- The master password is never checked.
- A malformed answer is reported as an error, never as "not found".

**Why sending these 5 characters is safe.** There are 16^5, about a million, possible prefixes,
and each one is shared by about two thousand breached passwords and by countless passwords that
were never breached. The service only learns which bucket our hash falls into, not which password
it is. It sends back the whole bucket and the comparison happens on our machine, so it does not
even learn whether the password was found.

**What they still reveal.** The prefix is 20 bits of the password's hash. For a generated password
this changes nothing (131 bits of entropy still leave 111). For a weak, human-chosen password it
matters more: someone holding the prefix can cut a dictionary down to about one entry in a million
and guess among what is left.

**Why the master password is never checked.** SHA-1 is fast and unsalted. An attacker who saw the
request and also stole the vault file could compute one cheap SHA-1 per guess and throw away every
guess whose prefix does not match, running the slow Argon2 only on the one guess in a million that
is left. Argon2 would become about a million times less effective.

**Why padding, and why ask only once.** Different prefixes have different numbers of entries, so
even through encrypted traffic the size of the answer could tell an observer which prefix was asked
for; padding hides that. Two entries with the same password have the same prefix, and asking for it
twice would tell the service that a password is reused.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

The assignment's "done when" checks are automated:

| Check | Test |
|---|---|
| The stored master password is an `$argon2id$...` string, and a wrong one is rejected | `tests/test_acceptance.py::test_1` |
| There is no key file; the master password alone opens the vault | `tests/test_acceptance.py::test_2` |
| Flipping any bit of any byte of the vault file fails loudly | `tests/test_acceptance.py::test_3` |
| Generated passwords are long, random, use a wide character set, and come from `secrets` (the imports of every file are parsed to check that nothing imports `random`) | `tests/test_acceptance.py::test_4` |
| Only the 5-character hash prefix leaves the machine | `tests/test_hibp.py` |

The other tests cover the building blocks one by one (`test_crypto.py`, `test_store.py`,
`test_generator.py`) and every command of the interface (`test_cli.py`).
