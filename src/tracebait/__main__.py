"""Allow ``python -m tracebait``, so runners can start the honeypot from this interpreter."""

from tracebait.cli import app

app(prog_name="tracebait")
