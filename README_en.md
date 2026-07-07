[Español](README.md) · **English**

# Security-Manager-NG

Successor of [Security-Manager-Go](https://github.com/terracenter/Security-Manager-Go) —
Linux host security manager with **native nftables backend**. SM-Go remains frozen
as a historical reference.

---

## Why a new version

SM-Go used UFW as a host for **raw iptables injections** in
`/etc/ufw/before.rules`, anchored to zone markers. Two structural problems:

1. **Fragile:** rule order depends on markers that must survive between
   `before/after/user.rules` and UFW reloads.
2. **Not portable:** AlmaLinux and Rocky Linux don't include UFW in their base repos and
   conflict with firewalld.

Security-Manager-NG abandons that model. It builds a **declarative, atomic,
100% SM-owned nftables ruleset**, identical across the four target distro families.

---

## Supported distros

| Family | Versions |
|--------|----------|
| Debian | 12 (Bookworm), 13 (Trixie) |
| Ubuntu | 20.04, 22.04, 24.04, 26.04 LTS |
| AlmaLinux / Rocky Linux | 8, 9 |

The kernel in all of them already uses `nf_tables` natively.

---

## Architecture

### Single `inet sm` table

A single declarative ruleset in `/etc/security-manager/sm.nft`, loaded atomically with
`nft -f`. IPv4 and IPv6 unified in a single `inet` table.

### Filtering pipeline — `input` chain

`chain input { type filter hook input priority filter; policy drop; }`

Everything not explicitly accepted falls to `policy drop`.

| # | Stage | Result |
|---|-------|--------|
| 1 | **Conntrack fast-path** — `ct state established,related` | ACCEPT immediate |
| 2 | **Loopback** — `iif lo` | ACCEPT |
| 3 | **Conntrack invalid** — `ct state invalid` | DROP |
| 4 | **Antirecon** — TCP flags XMAS/NULL/FIN+SYN/SYN+RST → rate-limit → log `SM-ANTIRECON` | DROP |
| 5 | **Blacklist** — `@sm_blacklist4/6` | DROP |
| 6 | **Whitelist / SSOT** — `@sm_whitelist4/6` | ACCEPT (total bypass) |
| 7 | **Conditional GeoIP** — `@geoip_<cc>4/6`; disallowed countries → log `SM-GEOIP` | DROP or continue |
| 8 | **Services** — `tcp dport { 22, 80, 443 }`, `icmp/icmpv6 echo-request` | ACCEPT |
| 9 | **Default** — `policy drop` + log `SM-DROP-DEFAULT` | DROP |

> **Critical order:** blacklist (5) before whitelist (6); whitelist (6) before GeoIP (7).

Full pipeline documentation: [`docs/arquitectura-pipeline-nftables.md`](docs/arquitectura-pipeline-nftables.md)

### Native sets (replace ipset)

All with `flags interval` to support CIDR ranges.

| Set | Contents |
|-----|----------|
| `sm_whitelist4` / `sm_whitelist6` | SSOT — trusted infra subnets/VLANs |
| `geoip_<cc>4` / `geoip_<cc>6` | Ranges per allowed country |
| `sm_blacklist4` / `sm_blacklist6` | Manual bans |

Atomic reload: regenerate the set block and apply with `nft -f` (no ipset swap pattern —
nftables is natively atomic).

### Coexistence with fail2ban

fail2ban operates in its own `f2b-table` (nftables banaction). Does not interfere with
`inet sm`; its rules evaluate at their own hook.

### NAT WireGuard

```
chain postrouting {
    type nat hook postrouting priority srcnat;
    oifname $WAN masquerade
}
```

Within the same `inet sm` table.

---

## Legacy assets from Security-Manager-Go

| Component | Description |
|-----------|-------------|
| `internal/safeapply` | Model `backup → preflight → deadman → confirm` with automatic rollback. Only the reload command changes: `ufw reload` → `nft -f`. |
| `sys.DetectDistro()` | Distro family detection for cutover preflight. |

The **safe-apply** model is mandatory for any firewall change in production:
deadman via `systemd-run --on-active` that rolls back (`nft -f` of backup) if Freddy
doesn't confirm within the timeout.

---

## Project structure

```
Security-Manager-NG/
├── main.go                          # Entry point, module registry
├── go.mod / go.sum
├── internal/
│   ├── modules/                     # One subdirectory per module
│   │   ├── firewall/                # nftables engine (sm.nft generation)
│   │   ├── whitelist/               # SSOT management (sm_whitelist4/6)
│   │   ├── geoip/                   # GeoIP set download and loading
│   │   ├── blacklist/               # Manual bans
│   │   ├── hardroot/                # root/sudoers hardening
│   │   ├── ssh/                     # sshd_config hardening
│   │   ├── fail2ban/                # fail2ban monitoring (read-only)
│   │   └── infra/                   # Shared SSOT across modules
│   ├── safeapply/                   # Safe-apply (deadman + rollback)
│   └── sys/                         # DetectDistro, OS helpers
├── deploy/
│   ├── deploy.sh                    # Cross-compile + rsync to remote host
│   └── install.sh                   # Installer on target host
└── docs/
    ├── arquitectura-pipeline-nftables.md
    └── diagramas/
        ├── sm-ng-pipeline-nftables.drawio
        ├── sm-ng-pipeline-nftables.dot
        └── sm-ng-pipeline-nftables.png
```

> The `internal/modules/` structure is still under construction — this is the
> target architecture.

---

## Build and deploy

```bash
# Verify local compilation
go build ./...
```

```bash
# Cross-compile and deploy to remote host (requires Go in PATH)
bash deploy/deploy.sh <IP_or_hostname>
```

The binary is installed to `/usr/local/sbin/security-manager-ng` on the remote host. **Never**
use `go run` in production — always use the compiled binary.

### Validate the ruleset before applying

```bash
sudo nft -c -f /etc/security-manager/sm.nft
```

```bash
# Inspect after applying under safe-apply
sudo nft list table inet sm
sudo nft list set inet sm sm_whitelist4
```

### Installation from GitHub Releases (alternate)

```bash
curl -sL https://github.com/terracenter/security-manager-ng/releases/latest/download/security-manager-ng -o security-manager-ng
sha256sum -c security-manager-ng.sha256   # verify against the checksum published in the Release
sudo install -m 750 -o root -g root security-manager-ng /usr/local/sbin/security-manager-ng
```

---

## Development conventions

- Branch `dev` for all development. **Never** merge to `main` without explicit validation.
- Each module implements the `modules.Module` interface (Order, Name, Menu, Reset).
- `os/exec` for all system commands (`nft`, `ip`, `systemctl`).
- No `panic()` in production paths — return error or print and continue.
- Explicit permissions when writing files: `0600` sensitive data, `0644` config.

---

## Current status

✅ **In active development, functional — not yet published to `main`.**

- **Complete modules** (interactive menu + CLI): `firewall` (declarative nftables ruleset +
  safe-apply), `whitelist` (Tier A/B, syncs CrowdSec and fail2ban), `geoip` (allowlist per
  country via ipdeny.com), `blacklist` (manual IPv4/IPv6 bans), `hardroot` (root/sudoers hardening),
  `ssh` (`sshd_config.d` hardening), `fail2ban` (read-only monitoring).
- **CrowdSec**: integrated as threat detection backend — optional per-distro prerequisite,
  `crowdsec-blacklists` set in nftables ruleset, allowlist sync from whitelist Tier B. Not yet
  exposed as its own menu/CLI module (that's a pending improvement, not implemented).
- **Infrastructure**: dual `SMLogger` screen+log, automatic prerequisite detection/installation per
  distro, detected services wizard, SSH IP Guard (fixed in TASK-F4.5 — works under `sudo` via
  `sys.GetSSHIP()`).
- **safe-apply**: cycle `backup → preflight → deadman (.timer as arbiter) → confirm/rollback`,
  with validated persistence at `/etc/nftables.conf` (handles `chattr +i` from prior runs).
- **Validated in production**: Debian 12, pilot host `PILOT-HOST-REDACTED` (latest formal tag
  `v0.6.0`).
- **Pending:**
  - Expose CrowdSec as its own menu/CLI module (today it's backend only).
  - New release tag — `dev` is 87 commits ahead of `v0.6.0` without a new tag.
  - Merge `dev` → `main` — requires explicit approval from Freddy (workspace Golden Rule);
    today `main` only has the bootstrap commit, no code.

---

## Roadmap

- **CrowdSec own module** (menu + CLI): today `internal/modules/crowdsec/` is internal support
  logic, called from `whitelist.go` (allowlist sync) and `infra.go` (ruleset sets). Does not
  implement the `modules.Module` interface or get registered in `main.go`. Need to implement
  `Order()/Name()/Menu()/Reset()` and move the installation logic currently in
  `internal/sys/prereqs.go` (`CheckAndInstallCrowdSec` and helpers) into its own module.
- **Runtime CLI internationalization**: today all program messages (menu, prompts, help) are
  hardcoded in Spanish. Need to design an i18n system (string map or library) so the binary
  itself supports Spanish (Venezuela) by default and English (US) as secondary — not just
  the documentation.

---

## License

AGPLv3 — see [`LICENSE`](LICENSE). This software is open source; the binary is not sold. The
sustainability model is support and consulting, not software licensing. See also
[`NOTICE`](NOTICE), [`THIRD-PARTY-LICENSES.md`](THIRD-PARTY-LICENSES.md) and
[`SECURITY.md`](SECURITY.md) to report vulnerabilities.
