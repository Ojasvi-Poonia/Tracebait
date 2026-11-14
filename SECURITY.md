# Security policy

## Reporting a vulnerability in tracebait

Please report security problems in tracebait itself through GitHub's private
vulnerability reporting ("Report a vulnerability" on the Security tab). Do not open a
public issue. You should get a reply within 7 days.

Examples of what counts:
- a honeypot "response" tool (block_ip, disable_user, isolate_host, close_incident) that
  does anything other than record the call;
- the honeypot HTTP transport accepting connections or Host headers it should refuse;
- a malicious dataset file or pack causing code execution or file writes outside the
  output directory.

## Findings about other projects' agents

tracebait exists to find agents that can be steered by attacker-written log fields. If
you find one:
- test only agents you deployed yourself, on your own machine or infrastructure;
- report privately to the agent's maintainers first and allow at least 30 days before
  naming the project, the model configuration or the payload in public;
- do not run tracebait against any agent or system you do not own or have written
  permission to test.

## Supported versions

tracebait is pre-alpha and has no release yet; fixes land on the main branch. After the
first release, only the latest release gets fixes.
