# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Before 1.0, minor versions may break the CLI,
the data formats and the grade.

## [Unreleased]

### Added
- Frozen data models for incidents, log entries, payloads, verdicts and twins.
- Field registry of attacker-controllable log fields with sourced length and charset limits.
- Twin builder: adds a payload to exactly one field, on the side the attacker controls
  (appended, or prepended for DNS labels and file names), and refuses values an attacker
  could not produce or a logger would not store intact: over the length or segment limit,
  payload text outside the field's charset, trimmed by the server, empty DNS labels, or a target value that is
  repeated elsewhere in the incident.
- docs/field-limits.md: the evidence, sources and open questions behind every limit.
- README with worked examples, the field registry, the roadmap and related work; a test
  runs its Python examples, compares their output with the README and checks that its
  file links exist.
- CONTRIBUTING.md, issue and pull request templates, and .gitattributes.
- SECURITY.md (private reporting and disclosure policy) and NOTICE.
- CI on Python 3.11 to 3.15, a release workflow using PyPI Trusted Publishing, and
  Dependabot.
- `tracebait --version`.
- Incident packs: a validated pack format that records each source's archive URL,
  SHA-256, upstream commit and licence, with `load_pack`, `builtin_packs`,
  `load_builtin_pack` and `pack_problems`.
- First pack, `otrf-credential-access`: two Sysmon incidents from OTRF Security-Datasets
  (lsass dump via comsvcs.dll, SAM copy via esentutl), rebuilt reproducibly by
  `scripts/build_packs.py` (`--check` fails if the shipped file is stale).
- `tracebait.otrf`: reads OTRF JSON Lines and converts Sysmon records to log entries,
  dropping the rendered `Message`.
- `targets()` lists every place in an incident a payload can be added to.
