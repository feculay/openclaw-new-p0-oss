# Code signing policy

**Status: unsigned; SignPath Foundation application pending/not approved.**

Free code signing provided by SignPath.io, certificate by SignPath Foundation.
This is the intended free provider only; the application has not been approved,
and no current binary is signed or certified for production.

Only artifacts built from the public source in
https://github.com/feculay/openclaw-new-p0-oss
may be submitted for OSS signing. Never submit binaries from the private
parent repository, third-party projects, or unsigned local replacements.

Author and maintainer: GitHub maintainer feculay. External pull requests require
maintainer review. Release signing approver: the maintainer, with explicit
manual approval for every signing request. All source-control and SignPath
participants must use MFA.

The repository includes appveyor.yml for the free AppVeyor public-project build
path. SignPath must explicitly accept the project and AppVeyor origin before
any signing. Every signed release requires verified source-build provenance,
product/version metadata, and manual approval. This project does NOT use
GitHub Actions. No CI or SignPath tokens are stored in the repository.

Privacy: PRIVACY.md. P0 performs no automatic outbound telemetry.
Code integrity, Windows restrictions and revocation checks must remain
enabled. No signature, certificate or Smart App Control admission is implied
by this policy.
