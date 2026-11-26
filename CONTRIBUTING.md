# Contributing to tracebait

Thank you for helping. tracebait measures whether AI security agents can be steered by
text in log fields, so its results are only useful if they are correct and reproducible.
This guide explains how changes are made.

## Ground rules

- Test only agents you deploy yourself, on infrastructure you control. Do not run
  tracebait, its payloads or its packs against any agent or system you do not own or
  have written permission to test.
- Report vulnerabilities in tracebait privately, as described in [SECURITY.md](SECURITY.md).
  If your work finds an agent that can be steered, tell its maintainers privately and
  wait at least 30 days before naming it.
- Be respectful and constructive in issues and reviews.

## Getting set up

You need Python 3.11 or newer and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/Ojasvi-Poonia/Tracebait.git
cd Tracebait
uv sync
uv run pytest --cov
```

Before you open a pull request, run the same checks as CI:

```bash
uv lock --check
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest --cov
```

If you change dependencies, commit the updated `uv.lock`: CI installs with
`uv sync --locked` and fails on a stale lockfile.

## How changes are made

- **Test first.** Write a failing test, make it pass, then tidy up. Coverage must stay at
  80% or higher; CI fails below that.
- **Property tests for invariants.** Twin structure (exactly one field changes,
  placement, mirrors) is property-tested with Hypothesis; field-limit rules have example
  tests. Before changing twin logic, run
  `HYPOTHESIS_PROFILE=thorough uv run pytest tests/unit/test_twins.py`.
- **Immutable, validated data.** Models are frozen pydantic models that reject unknown
  keys. Validate anything read from files or produced by an agent.
- **Small, focused modules.** Prefer several small files to one large one.
- **Conventional Commits.** Use `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `ci:` or
  `chore:` prefixes, and describe user-visible changes in [CHANGELOG.md](CHANGELOG.md).

## Changing the field registry

`src/tracebait/data/fields.json` sets the limits every payload must fit, so each value
needs evidence.

1. Find primary sources: vendor documentation, RFCs, logger or SIEM source code, and
   real records from public datasets. Blog posts alone are not enough.
2. Record the limit, its unit (code points, UTF-16 units or UTF-8 bytes), the allowed
   characters and which end of the value the attacker controls.
3. Update both `fields.json` and [docs/field-limits.md](docs/field-limits.md). A test
   checks that the table and character classes in the docs match the registry.
4. Write character classes as ASCII escapes, never as literal special characters.

## Payloads

The corpus is `src/tracebait/data/payloads.json`. A test builds a twin from every
payload on every shipped incident that has its field, so a payload that does not fit
fails CI.

- Every payload must be your own original text. Do not copy payloads from papers,
  datasets or other tools, especially material under non-commercial or no-derivatives
  licences.
- Payloads must fit the target field's registry limits; the twin builder rejects those
  that do not.
- Tag each payload with its MITRE ATLAS and OWASP agentic-AI identifiers.
- Do not include real people's personal data or working credentials.

## Incident packs

- Use public datasets whose licences allow redistribution, and keep slices small.
- Add a recipe to `scripts/pack_recipes.py` (file URL at a pinned commit, its SHA-256,
  the events to select and any echoed fields to drop), run
  `uv run python scripts/build_packs.py`, and commit the generated file under
  `src/tracebait/data/packs/`. Never edit a pack by hand.
- Add the source, licence and upstream commit to [NOTICE](NOTICE).
- Remove mirrored copies of target values (for example the rendered `Message` field in
  OTRF records, or response echoes in CloudTrail). The twin builder refuses incidents
  that repeat a target value: inside another field for values of 8 or more characters,
  or as an exact copy for shorter ones.

## Pull requests

- Keep each pull request focused on one change.
- Fill in the pull request template, including how you tested the change.
- Expect review comments; they are about the code, not about you.

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).
