[Español](README.md) · **English**

# Security-Manager-NG

![License](https://img.shields.io/badge/license-AGPLv3-blue)
![Status](https://img.shields.io/badge/status-pre--release-orange)
![Distros](https://img.shields.io/badge/distros-Debian%20%7C%20Ubuntu%20%7C%20AlmaLinux%20%7C%20Rocky-informational)

Linux host security manager with a **native nftables backend**: a declarative, atomic
firewall applied from a single static binary, identical across Debian, Ubuntu, AlmaLinux
and Rocky Linux. Built for sysadmins running multi-distro fleets who need a reproducible,
auditable ruleset with automatic rollback if something goes wrong (`safe-apply`).

Beyond the firewall it also handles: whitelist/blacklist, per-country GeoIP blocking, SSH
and root/sudoers hardening, fail2ban monitoring, and optional CrowdSec sync — all from the
same binary, via an interactive menu or a CLI for automation.

> ⚠️ **Release candidate — under active validation.** See [Current status](#current-status)
> before using in production.

---

## Quickstart / Usage

Install: see [Installation from GitHub Releases](#installation-from-github-releases-alternate)
below (mandatory GPG signature verification included).

SM-NG has two coexisting usage modes:

```bash
# No arguments → interactive menu (recommended for guided initial setup)
sudo security-manager-ng

# With arguments → non-interactive CLI (recommended for automation/scripts/cron)
sudo security-manager-ng firewall allow --port 8080 --proto tcp --tier global --comment "public API"
sudo security-manager-ng firewall deny  --port 8080 --proto tcp

sudo security-manager-ng whitelist add 203.0.113.5 --tier A --responsable "freddy" --proposito "office"

sudo security-manager-ng geoip add VE CO PE

sudo security-manager-ng blacklist add 198.51.100.7

sudo security-manager-ng firewall estado
sudo security-manager-ng ssh estado

# Full help (embedded in the binary)
security-manager-ng --help
security-manager-ng --version
```

`--tier global` exposes the port to any IP; `--tier geo` restricts it to the countries
enabled in GeoIP. In `whitelist add`, `--tier A` is trusted-but-bannable and `--tier B` is
immune (never gets caught by fail2ban/CrowdSec).

## Demo

```
# illustrative example of the interactive menu, not a real capture yet

$ sudo security-manager-ng

  Security-Manager-NG — v0.7.0
  Firewall: inet sm active · 3 GeoIP countries · 12 IPs in whitelist

  [1] Firewall       [5] Root hardening
  [2] Whitelist      [6] SSH hardening
  [3] GeoIP          [7] fail2ban (monitoring)
  [4] Blacklist       [0] Exit

  Select an option:
```

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

Every Release is GPG-signed. Signature verification is **mandatory and automatic** — the installer
aborts on its own if it fails; it doesn't depend on the user reviewing it by hand.

**Release signing key fingerprint:** `6D33CBB56A4FA1E2966C40225923730155062949`

**One-command install** (downloads, verifies SHA256, and installs):

```bash
curl -fsSL https://raw.githubusercontent.com/terracenter/security-manager/dev/script-dev/install.sh | bash
```

**Important:** run this as a normal user, **never** with `sudo` in front of the command — the
script aborts on its own if it detects it's running as root directly (it requires a normal user +
internal `sudo`). The script will prompt for your `sudo` password right at the moment it copies
the binary to `/usr/local/sbin/security-manager-ng-dev` — that's expected, just answer it.

> ⚠️ **This is the `dev` branch (pre-release).** The script prints a large banner:
> `!!! ATENCION: INSTALADOR DE DESARROLLO (rama: dev) !!!`. If you do NOT see that banner,
> the script is wrong. For production, use the `main` installer with GPG.

<details>
<summary>Manual installation (step-by-step audit, for anyone who prefers to review each verification)</summary>

The public key is available from two sources independent of each other (and of this repo itself, so a
GitHub compromise alone can't forge both at once):
- [keys.openpgp.org](https://keys.openpgp.org/search?q=terracenter@gmail.com)
- [gpg-key.humanbyte.net](https://gpg-key.humanbyte.net)

```bash
# Import the public key (from either source)
gpg --keyserver keys.openpgp.org --recv-keys 6D33CBB56A4FA1E2966C40225923730155062949
# or: curl -fsSL https://gpg-key.humanbyte.net/sm-ng-release-signing.pub.asc | gpg --import

# Confirm the imported fingerprint matches the one above exactly
gpg --fingerprint 6D33CBB56A4FA1E2966C40225923730155062949

# Download the binary, checksum, and signature
# NOTE: while the project has no stable release yet (see Current status below), use the
# explicit tag instead of "latest" — check the most recent one at
# https://github.com/terracenter/Security-Manager-Ng/releases
curl -sL https://github.com/terracenter/security-manager-ng/releases/download/v0.7.0/security-manager-ng -o security-manager-ng
curl -sL https://github.com/terracenter/security-manager-ng/releases/download/v0.7.0/security-manager-ng.sha256 -o security-manager-ng.sha256
curl -sL https://github.com/terracenter/security-manager-ng/releases/download/v0.7.0/security-manager-ng.asc -o security-manager-ng.asc

# Verify the GPG signature (required) and checksum (extra defense)
gpg --verify security-manager-ng.asc security-manager-ng
sha256sum -c security-manager-ng.sha256

sudo install -m 750 -o root -g root security-manager-ng /usr/local/sbin/security-manager-ng
```

</details>

---

## Development conventions

- Branch `dev` for all development. **Never** merge to `main` without explicit validation.
- Each module implements the `modules.Module` interface (Order, Name, Menu, Reset).
- `os/exec` for all system commands (`nft`, `ip`, `systemctl`).
- No `panic()` in production paths — return error or print and continue.
- Explicit permissions when writing files: `0600` sensitive data, `0644` config.

---

## Current status

✅ **In active development, functional — public repo, not yet published to `main`.**

⚠️ **Release candidate — under active validation, please report bugs.** Releases are published marked
as pre-release until validation on a real production host completes (BLOQUE B-SM-B1). Don't use in
production without checking that validation's status first.

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
- **Validated in production**: Debian 12, test pilot host (latest formal tag
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
