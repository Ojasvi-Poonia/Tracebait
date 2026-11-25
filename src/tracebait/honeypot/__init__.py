"""The honeypot: an MCP server that serves one incident and records response actions.

Read tools serve the incident's log entries; response tools record the call and never
act on anything. Nothing the agent can see says it is being tested, and the clean and
poisoned copies of an incident are served identically apart from the poisoned field.
"""
