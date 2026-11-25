# Security vulnerability disclosure

This file is the vulnerability disclosure process for this plugin repository (id `ssh-guard`); it is not a security design document.

## Scope

Covers: the implementation of `SSH 加固插件` (id `ssh-guard`), the capability declaration in `info.json`, the `web/` front end and the `make dist` artifacts.

Not covered: kernel and protocol issues — please report those per the [kore SECURITY.md](https://github.com/kore-pl/kore/blob/main/SECURITY.md); please also report known vulnerabilities in upstream third-party dependencies to the upstream project.

## Supported versions

| Version | Status | Notes |
| --- | --- | --- |
| `0.4.0` (current latest) | ✅ Accepted and fixed | Security fixes are provided only for the latest patch version |
| Earlier `0.x` versions | ❌ Unsupported | Please upgrade to the latest version first |

During `0.x`, support is minimal: only the latest patch of a minor line receives fixes; older patch versions are not backported.

## Attack surface of this repository

- **RPC methods**: all `ssh-guard.*` methods (see `README.md`); missing parameter validation can lead to privilege escalation or injection.
- **capabilities**: `info.json.capabilities` is the plugin's complete authorization surface; every extra declaration is another attack path.
- **Separate process and UDS**: the plugin runs as a separate process; its socket is created by the host shell, `chown kore-<id>`, mode `0600`; bypassing socket permissions or connecting to another plugin's socket is a vulnerability.
- **Host write surface**: writes beyond the capabilities actually granted (files / processes / network / database) are vulnerabilities.
- **Front end**: `web/` runs in a separate-origin iframe and communicates with the host shell via postMessage; XSS, message forgery and cross-plugin data reads are all security-boundary issues.

## Reporting

1. **Prefer a GitHub Security Advisory**: this repository's Security page → "Report a vulnerability" (private channel, no public issue).
2. **Fallback email**: `pengtang1024@users.noreply.github.com`, subject `[kore security] ssh-guard`.
3. **Do not open public issues and do not paste PoCs in discussions or PRs.**
4. Include: affected version, reproduction steps or PoC, impact assessment, whether it is public already, and credit preference.

## Timeline and disclosure

- Acknowledge and give a first assessment within **72 hours**; a plan follows for complex issues.
- Coordinate disclosure after a fix, with a default **90-day** window; consult first if the issue is actively exploited.
- Record security fixes in `CHANGELOG.md` after release (without exploitation details) and publish a security advisory as needed.

## Acknowledgements

Credit is given in release notes with the reporter's consent; anonymous by request.
