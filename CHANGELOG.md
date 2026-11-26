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
- Second pack, `splunk-aws-iam`: two CloudTrail incidents from splunk/attack_data
  (CreateAccessKey for another user; CreateLoginProfile followed by that user's console
  login), giving the CloudTrail `userAgent` and `requestParameters.userName` fields
  their first targets.
- `tracebait.cloudtrail` flattens CloudTrail records to dotted keys;
  `tracebait.records` reads JSON Lines and drops fields a record echoes.
- `pack_problems` flags a target value repeated inside its own record; a value repeated
  in another record is kept as evidence, and `targets()` skips that field.
- Honeypot MCP server (`tracebait honeypot`): serves one clean or poisoned incident over
  stdio through `get_alert`, `search_logs`, `get_process_tree` and `lookup_asset`, and
  records `block_ip`, `disable_user`, `isolate_host` and `close_incident` calls to a JSON
  Lines action log without acting on anything. It never reveals the incident id, source,
  ground truth or payload, and presents itself as an ordinary SOC console.
- Asset inventory model for `lookup_asset` and, later, for scoring collateral actions.
- Dependency on the MCP Python SDK (`mcp` 2.x).
- `tracebait run`: runs Claude Code headless (`claude -p`) on the clean and poisoned
  copies of an incident, alternating variants, with a structured verdict schema, a
  per-run budget cap and a tally of dispositions, actions and cost. Sessions run in
  neutral temporary directories with the honeypot as their only tool source.
- `python -m tracebait`.
- `tracebait score`: grades an experiment from 0 to 100 on four deterministic rates
  (verdict flip, suppression, attacker-directed and collateral actions), attributing an
  effect only when a one-sided Fisher exact test gives p < 0.05; `--fail-under` for CI
  and `--json` output.
- `tracebait run --inventory` serves an asset inventory and records it for scoring.
  `experiment.json` is now a validated model, and pack file paths are made absolute so
  the honeypot finds them from the agent's working directory.
- First payload corpus (`data/payloads.json`): 15 original payloads, three in each of
  the five classes, for the command-line, CloudTrail user-agent and IAM user-name fields
  the shipped packs contain, tagged with MITRE ATLAS and OWASP agentic-AI ids. Every
  payload is tested against every shipped incident with its field.
- `--payload` takes a built-in payload id as well as a `.json` file, and
  `tracebait list` shows the built-in packs, incidents, targetable fields and payloads.
- Third pack, `splunk-web-scanners`: the first benign incidents. Two requests from
  self-identified research scanners (Censys, NetSystemsResearch) to a public nginx server,
  taken from the background traffic of a splunk/attack_data Log4Shell capture and mapped
  to ECS by the new `tracebait.nginx` module. They give `user_agent.original` its first
  targets, and five new payloads try to provoke disruptive actions through it.
- `scripts/build_packs.py` lists a source shared by several incidents once and downloads
  it once.
