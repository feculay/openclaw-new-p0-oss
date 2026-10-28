# Code signing policy

**Not signed. SignPath Foundation application NOT approved.**

Free code signing provided by SignPath.io, certificate by SignPath
Foundation — only if the foundation accepts this open-source project.

Only artifacts built from the public source in
https://github.com/feculay/openclaw-new-p0-oss
may be submitted for OSS signing. Never submit binaries from the private
parent repository, third-party projects, or unsigned local replacements.

Initial author, code reviewer and release signing approver: GitHub
maintainer feculay. External pull requests require maintainer review,
and every signing request requires explicit authorized manual approval.
All source control and SignPath participants must use MFA.

Signed releases require a provider-approved trusted build system, origin
verification and product/version metadata. This project does NOT use
GitHub Actions. Jenkins or Azure DevOps can be considered only after
SignPath supports and approves the actual configured origin.

Privacy: PRIVACY.md. P0 performs no automatic outbound telemetry.
Code integrity, Windows restrictions and revocation checks must remain
enabled. No signature, certificate or Smart App Control admission is
implied by this policy.
