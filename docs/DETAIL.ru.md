# SSH Hardening Plugin (ssh-guard)

## What it does

kore's SSH hardening plugin: configuration audit + attack statistics + ban view. 0.2.0 upgraded the text-audit skeleton to real log statistics, protection-source detection and root-action declarations; 0.2.2 made ban / unban really execute through the kernel privilege-escalation channel with read-back verification; 0.4.0 made the ban list a real implementation (pagination, source, remaining time and whitelist markers).

## Protocol and compatibility

Protocol `kore.plugin.v1`, `lifecycle=lazy`, `depth_level=basic`, `requires_kore >=0.1.0 <0.2.0`; the only third-party dependency is `github.com/pengtang1024/kore/pkg/pluginapi v0.1.3`.

## Main capabilities

- `status`: read-only configuration audit (5 rules) and protection-source detection (fail2ban status via the root channel); it never opens or rewrites the real `/etc/ssh/sshd_config`.
- `attempts`: parses the last 1 MiB of `/var/log/auth.log` (or journalctl) for attack statistics; usernames are masked as `***` and IP addresses are the only sensitive values shown.
- `bans` / `ban.list`: current banned / suspicious IPs with source, rule, observation time and whitelist-conflict warnings; the `whitelist` family manages a 0600 on-disk whitelist.
- `suggest`: read-only advisory mode (dry_run=true, no host writes), producing suggested sshd_config.d text, risks, apply commands and verification commands.
- `ban.add` / `ban.remove`: really executed via `fail2ban-banip` / `fail2ban-unbanip` root actions; banning is irreversible, requires a one-time confirm token, and whitelisted IPs are refused. The plugin itself never escalates and bundles no fail2ban / iptables / nftables / sshd.

## Install and verification

`make check` is the local gate; `make dist` produces a bit-for-bit reproducible `dist/ssh-guard-0.4.0.tar.gz`. Real privileged e2e still requires a root + systemd environment; unit tests cover argv and read-back via a stub channel.
Report vulnerabilities privately per SECURITY.md; MIT license; contributions: CONTRIBUTING.md.