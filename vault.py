"""Entry point: python vault.py <command>. Run `python vault.py --help` for the commands."""

import sys

from keychain.cli import main

if __name__ == "__main__":
    sys.exit(main())
