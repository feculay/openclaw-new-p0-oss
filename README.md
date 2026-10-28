# OpenClaw New P0 — Windows Service (Open Source)

**Experimental source release — NOT production certified.**

This MIT-licensed project is the publicly auditable Windows P0 component of
OpenClaw New: an authenticated named-pipe service that operates under a
restricted Windows identity and checks its own installed service.

This is a freshly curated source snapshot, NOT a mirror of the private parent
project. It excludes secrets, credentials, private trust configuration, and
private repository history.

## Included functions

- Typed local IPC, nonce/replay guard and audit records
- Operator SID permission check and Windows SCM identity/DACL attestation
- Versioned protocol and self-test capability
- Source build using .NET 8, Windows x64; no GitHub Actions

## Not included

The complete agent, private trust authority, external configuration,
production installer, operational credentials, independent high-water authority
or pre-certified production release. No arbitrary SYSTEM command runner.

## Build

Windows 11 and .NET SDK 8.x:
powershell -NoProfile -File .\build\Build-P0.ps1

Outputs an unsigned self-contained EXE in artifacts/windows-x64.
This build does NOT install/start a service or change security settings.
Never disable Smart App Control or UAC to run the unsigned artifact.

## Code signing policy

See CODE_SIGNING_POLICY.md. Free SignPath signing is only a **request**;
there is no approval, signature or certificate yet. No binary in this
repository should be treated as a signed production release.

## Other

MIT license: LICENSE. Privacy: PRIVACY.md. Security: SECURITY.md.
Maintainer: https://github.com/feculay
Version: 0.1.0-alpha source preview.
