# Security

P0 version 0.1.0-alpha is experimental, not production certified.
Do not weaken or disable UAC, Smart App Control, WDAC or Defender.

This Windows service is restricted to its own installation resources:
operator SID checks, nonce/replay protection, SCM identity/ACL and
binary pin checks, audit trail, and typed IPC. No arbitrary elevated
shell command operation is provided.

Report vulnerabilities confidentially through GitHub security advisories
where available. Do not commit passwords, tokens, production policy or
user information. Do not reuse other projects' signatures or certificates.
