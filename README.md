# project_key_chain

A small command-line password manager (EPITA Software Security, Project 2), by Alan, Leah and
Theodore. All passwords live in one encrypted file that only the master password opens; no key is
stored anywhere on disk.

## Usage

Needs Python 3.10 or newer.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

```text
$ python vault.py init                               # set the master password (typed twice, 12+ characters)
$ python vault.py add github --user alice            # the password is typed twice at a hidden prompt
$ python vault.py add mail --user carol --generate   # ... or generated (--length N, default 20)
$ python vault.py list                               # names and usernames, never passwords
$ python vault.py get github                         # username and password
$ python vault.py delete github                      # asks for confirmation (--yes skips it)
$ python vault.py gen --length 24                    # a strong password, no vault needed
$ python vault.py check                              # breach check, the only command that goes online
```

- The vault is `~/.keychain/vault.json` (directory `0700`, file `0600`). `--vault PATH` picks
  another file and goes before the command.
- Passwords are only ever typed at a prompt that does not echo them, never passed as arguments or
  environment variables.
- Every error is one line, `error: ...`, never a traceback.

## How it works

```text
init   : master_hash = Argon2id hash of the master password       (argon2-cffi, own random salt)
         key = Argon2id KDF(master password, 16-byte random salt)  (cryptography, never stored)
         vault file = header in clear + AES-256-GCM(key, entries, associated data = header)
unlock : check the password against master_hash -> derive the key again -> decrypt
```

The header holds the cipher name, the Argon2 parameters and salt, `master_hash` and a version.
Entry names, usernames and passwords are all inside the ciphertext.

| Parameter | Value | In the code |
|---|---|---|
| Argon2id (hash and KDF) | time 3, memory 64 MiB, parallelism 4 (RFC 9106) | `crypto.Argon2Params` |
| Salts | 16 bytes each, drawn independently | `crypto._hasher`, `crypto.new_salt` |
| Key / nonce / tag | 32 / 12 / 16 bytes | `crypto.py` |
| Generated passwords | 94 printable ASCII characters, length 20 by default (about 131 bits), 12 to 128 | `generator.py` |
| Master password | at least 12 characters | `cli.py` |

## Libraries

We write no cryptography of our own: home-made crypto is where subtle, invisible mistakes hide.
Argon2 is used for two different purposes, so each use comes from the API made for it:

- **`argon2-cffi`** for the stored master-password hash. Its job is verification, and it produces
  exactly the self-describing `$argon2id$v=19$m=...,t=...,p=...$salt$hash` string needed for that.
- **`cryptography`** for the key: AES needs raw key bytes, which its Argon2id KDF returns. It also
  provides AES-GCM.
- **`secrets`** (standard library) for every random value: salts, nonces, generated passwords.

## Why each choice

### 1. Why Argon2 for the master password, and not SHA-256 or AES?

Someone who steals the vault file can test guesses on their own machine, offline, with no limit on
the number of tries. SHA-256 is designed to be fast, so a SHA-256 hash could be brute-forced in a
time the attacker can easily afford: about 0.25 µs per guess on our test machine in plain Python,
and billions per second on a GPU.

Argon2 is slow on purpose, and it also needs memory: every guess uses 64 MiB. This raises the
hardware cost of brute force: an attacker with limited hardware cannot run many guesses at once,
so cannot crack the password quickly. One Argon2id guess takes about 37 ms on the same machine,
about 150,000 times longer than SHA-256.

AES would not make sense: encrypting the master password needs a key, which has to be somewhere.
Storing it on disk is ruled out, and deriving it from the master password is circular. And we
never need the master password back, only to check it, which a one-way hash does.

The salt (16 random bytes, new for every hash) makes rainbow tables useless, gives the same
password a different hash every time, and forces the attacker to attack each hash on its own.

### 2. Why derive the key instead of storing a key file?

A key file next to the vault is the key left next to the lock: whoever gets the files gets
everything, and the master password is just for show. A derived key leaves nothing on disk that
opens the vault; the master password, in the user's head, is the only way in.

The price: if the master password is lost, the key is lost with it, and the vault can never be
decrypted again.

The KDF salt is independent of the hash's salt; with the same salt, the derived key would be the
very hash stored in clear in the file. And the stored hash only serves to say "wrong master
password": an attacker who swaps in the hash of their own password passes that check, but derives
the wrong key, and AES-GCM refuses to decrypt.

### 3. Why AES-GCM, and not AES without authentication?

Without authentication, an attacker who can guess where sensitive information sits can change it
on purpose, without the key (with AES-CTR, flipping a ciphertext bit flips the same plaintext
bit), or simply destroy data by flipping a few bytes. Decryption would return the modified data as
if nothing had happened.

GCM adds a 16-byte authentication tag over the ciphertext and the associated data (our header).
Decryption checks it first and refuses if a single bit changed, so tampering fails loudly. Two
details matter:

- **A fresh random nonce at every save.** Reusing a nonce with the same key reveals the XOR of the
  two plaintexts and allows forged tags.
- **The file must be byte-for-byte canonical.** GCM only authenticates the bytes it is given, so
  changes that decode to the same values (JSON whitespace, unused base64 bits) are caught by the
  parser instead. The acceptance test flips every bit of the file and each flip is reported.

### 4. Why `secrets` and not `random`?

`random` is a Mersenne Twister, made for simulations: after 624 consecutive 32-bit outputs, anyone
can rebuild its internal state and predict every value that follows. `secrets` draws from the
operating system's cryptographically secure source, whose next output cannot be predicted.

A password missing one kind of character (lowercase, uppercase, digit, symbol) is drawn again
whole rather than patched: patching would make some passwords more likely than others.

## Security model

**Protected:** someone who steals the vault file gets only ciphertext and the fields written in
clear. They get neither the master password nor any entry; the only way in is to guess the master
password, at Argon2's cost per guess. Any change to the file is detected, and passwords never go
through the command line, environment variables or the screen while typed.

**Not protected:**

- **Attacks on the machine itself** (keyloggers, malware, memory). A keylogger records the master
  password as it is typed; malware can read passwords from memory while the vault is open.
- **A weak master password.** Length is only a floor: `Password1234` has 12 characters and is
  still weak, and we do not check against a list of common passwords. Argon2 slows guessing, but a
  password among the first guesses still falls.
- **Someone seeing the information directly.** `get` and `add --generate` print passwords, since
  the user needs to see them. A person behind you, a screen recording or the terminal's scrollback
  can capture them.

## Bonus: breach check with Have I Been Pwned

```text
password  --SHA-1-->  5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
                      \___/\_________________________________/
                     sent      kept on this machine

GET https://api.pwnedpasswords.com/range/5BAA6
```

The service returns every breached hash starting with those 5 characters (about two thousand), and
the remaining 35 characters are matched locally.

- **Why it is safe:** there are about a million prefixes, each shared by about two thousand
  breached passwords and countless others. The service learns which bucket the hash falls in, not which
  password, and not even whether it was found, since the match happens on our machine.
- **What it still reveals:** 20 bits of the hash. Harmless for a generated password (131 bits
  leave 111), but it narrows a dictionary attack on a weak one about a million times.
- **Why the master password is never checked:** SHA-1 is fast and unsalted. An attacker holding the
  vault and the prefix could discard all but one guess in a million with a cheap SHA-1, making
  Argon2 about a million times less effective.
- **Padding** (`Add-Padding: true`) hides which prefix was asked from the size of the answer, and
  each prefix is requested once, so a reused password does not show up as a repeated request.

## Tests

```bash
pip install -r requirements-dev.txt && python -m pytest
```

| Assignment check | Test |
|---|---|
| Stored value is `$argon2id$...`; a wrong master password is rejected | `test_acceptance.py::test_1` |
| No key file; the master password alone opens the vault | `test_acceptance.py::test_2` |
| Flipping any bit of the vault file fails loudly | `test_acceptance.py::test_3` |
| Long, random, wide-alphabet passwords from `secrets`; nothing imports `random` | `test_acceptance.py::test_4` |
| Only the 5-character prefix leaves the machine | `test_hibp.py` |
