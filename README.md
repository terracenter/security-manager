**Español** · [English](README_en.md)

# Security-Manager-NG

Sucesor de [Security-Manager-Go](https://github.com/terracenter/Security-Manager-Go) —
gestor de seguridad de hosts Linux con backend **nftables nativo**. SM-Go queda congelado
como referencia histórica.

---

## Por qué una versión nueva

SM-Go usaba UFW como anfitrión de **inyecciones crudas de iptables** en
`/etc/ufw/before.rules`, ancladas a marcadores de zona. Dos problemas estructurales:

1. **Frágil:** el orden de las reglas depende de marcadores que deben sobrevivir entre
   `before/after/user.rules` y recargas de UFW.
2. **No portable:** AlmaLinux y Rocky Linux no incluyen UFW en sus repos base y pelean con
   firewalld.

Security-Manager-NG abandona ese modelo. Construye un **ruleset nftables declarativo,
atómico y 100% propiedad de SM**, idéntico en las cuatro familias de distros destino.

---

## Distros soportadas

| Familia | Versiones |
|---------|-----------|
| Debian | 12 (Bookworm), 13 (Trixie) |
| Ubuntu | 20.04, 22.04, 24.04, 26.04 LTS |
| AlmaLinux / Rocky Linux | 8, 9 |

El kernel en todas ellas ya usa `nf_tables` nativamente.

---

## Arquitectura

### Tabla única `inet sm`

Un solo ruleset declarativo en `/etc/security-manager/sm.nft`, cargado atómico con
`nft -f`. IPv4 e IPv6 unificados en una sola tabla `inet`.

### Pipeline de filtrado — chain `input`

`chain input { type filter hook input priority filter; policy drop; }`

Todo lo que no se acepta explícitamente cae en `policy drop`.

| # | Etapa | Resultado |
|---|-------|-----------|
| 1 | **Conntrack fast-path** — `ct state established,related` | ACCEPT inmediato |
| 2 | **Loopback** — `iif lo` | ACCEPT |
| 3 | **Conntrack inválido** — `ct state invalid` | DROP |
| 4 | **Antirecon** — TCP flags XMAS/NULL/FIN+SYN/SYN+RST → rate-limit → log `SM-ANTIRECON` | DROP |
| 5 | **Blacklist** — `@sm_blacklist4/6` | DROP |
| 6 | **Whitelist / SSoT** — `@sm_whitelist4/6` | ACCEPT (bypass total) |
| 7 | **GeoIP** condicional — `@geoip_<cc>4/6`; países no permitidos → log `SM-GEOIP` | DROP o continúa |
| 8 | **Servicios** — `tcp dport { 22, 80, 443 }`, `icmp/icmpv6 echo-request` | ACCEPT |
| 9 | **Default** — `policy drop` + log `SM-DROP-DEFAULT` | DROP |

> **Orden crítico:** blacklist (5) antes que whitelist (6); whitelist (6) antes que GeoIP (7).

Documentación completa del pipeline: [`docs/arquitectura-pipeline-nftables.md`](docs/arquitectura-pipeline-nftables.md)

### Sets nativos (reemplazan ipset)

Todos con `flags interval` para soportar rangos CIDR.

| Set | Contenido |
|-----|-----------|
| `sm_whitelist4` / `sm_whitelist6` | SSoT — subredes/VLANs de infra confiable |
| `geoip_<cc>4` / `geoip_<cc>6` | Rangos por país permitido |
| `sm_blacklist4` / `sm_blacklist6` | Bans manuales |

Recarga atómica: se regenera el bloque del set y se aplica con `nft -f` (sin el patrón
swap de ipset — nftables es atómico nativo).

### Coexistencia con fail2ban

fail2ban opera en su propia tabla `f2b-table` (banaction nftables). No interfiere con
`inet sm`; sus reglas se evalúan en su propio hook.

### NAT WireGuard

```
chain postrouting {
    type nat hook postrouting priority srcnat;
    oifname $WAN masquerade
}
```

Dentro de la misma tabla `inet sm`.

---

## Activos heredados de Security-Manager-Go

| Componente | Descripción |
|------------|-------------|
| `internal/safeapply` | Modelo `backup → preflight → deadman → confirm` con rollback automático. Solo cambia el comando de reload: `ufw reload` → `nft -f`. |
| `sys.DetectDistro()` | Detección de familia de distro para preflight de cutover. |

El modelo **safe-apply** es obligatorio para cualquier cambio de firewall en producción:
deadman vía `systemd-run --on-active` que hace rollback (`nft -f` del backup) si Freddy
no confirma dentro del timeout.

---

## Estructura del proyecto

```
Security-Manager-NG/
├── main.go                          # Entry point, registro de módulos
├── go.mod / go.sum
├── internal/
│   ├── modules/                     # Un subdirectorio por módulo
│   │   ├── firewall/                # Engine nftables (generación de sm.nft)
│   │   ├── whitelist/               # Gestión del SSoT (sm_whitelist4/6)
│   │   ├── geoip/                   # Descarga y carga de sets GeoIP
│   │   ├── blacklist/               # Bans manuales
│   │   ├── hardroot/                # Hardening root/sudoers
│   │   ├── ssh/                     # Hardening sshd_config
│   │   ├── fail2ban/                # Monitoreo (no gestión) de fail2ban
│   │   └── infra/                   # SSoT compartido entre módulos
│   ├── safeapply/                   # Safe-apply (deadman + rollback)
│   └── sys/                         # DetectDistro, helpers OS
├── deploy/
│   ├── deploy.sh                    # Cross-compile + rsync al host remoto
│   └── install.sh                   # Instalador en el host destino
└── docs/
    ├── arquitectura-pipeline-nftables.md
    └── diagramas/
        ├── sm-ng-pipeline-nftables.drawio
        ├── sm-ng-pipeline-nftables.dot
        └── sm-ng-pipeline-nftables.png
```

> La estructura `internal/modules/` todavía está en construcción — esta es la arquitectura
> objetivo.

---

## Build y deploy

```bash
# Verificar compilación local
go build ./...
```

```bash
# Cross-compile y deploy al host remoto (requiere Go en PATH)
bash deploy/deploy.sh <IP_o_hostname>
```

El binario se instala en `/usr/local/sbin/security-manager-ng` del host remoto. **Nunca**
usar `go run` en producción — siempre binario compilado.

### Instalación desde GitHub Releases (alterno)

```bash
curl -sL https://github.com/terracenter/security-manager-ng/releases/latest/download/security-manager-ng -o security-manager-ng
sha256sum -c security-manager-ng.sha256   # verificar contra el checksum publicado en el Release
sudo install -m 750 -o root -g root security-manager-ng /usr/local/sbin/security-manager-ng
```

### Validar el ruleset antes de aplicar

```bash
sudo nft -c -f /etc/security-manager/sm.nft
```

```bash
# Inspeccionar tras aplicar bajo safe-apply
sudo nft list table inet sm
sudo nft list set inet sm sm_whitelist4
```

---

## Convenciones de desarrollo

- Branch `dev` para todo el desarrollo. **Nunca** merge a `main` sin validación explícita.
- Cada módulo implementa la interface `modules.Module` (Order, Name, Menu, Reset).
- `os/exec` para todos los comandos del sistema (`nft`, `ip`, `systemctl`).
- Sin `panic()` en paths de producción — retornar error o imprimir y continuar.
- Permisos explícitos al escribir archivos: `0600` datos sensibles, `0644` conf.

---

## Estado actual

✅ **En desarrollo activo, funcional — no publicado en `main` todavía.**

- **Módulos completos** (menú interactivo + CLI): `firewall` (ruleset nftables declarativo +
  safe-apply), `whitelist` (Tier A/B, sincroniza CrowdSec y fail2ban), `geoip` (allowlist por
  país vía ipdeny.com), `blacklist` (bans manuales IPv4/IPv6), `hardroot` (hardening root +
  sudoers), `ssh` (hardening `sshd_config.d`), `fail2ban` (monitoreo de solo lectura).
- **CrowdSec**: integrado como backend de detección de amenazas — prerequisito opcional
  instalado por distro, set `crowdsec-blacklists` en el ruleset nftables, sincronización de
  allowlist desde whitelist Tier B. Aún no expuesto como módulo propio de menú/CLI (esa es una
  mejora pendiente, no implementada).
- **Infraestructura**: `SMLogger` dual pantalla+log, detección e instalación automática de
  prerequisitos por distro, wizard de servicios detectados, SSH IP Guard (corregido en
  TASK-F4.5 — funciona bajo `sudo` vía `sys.GetSSHIP()`).
- **safe-apply**: ciclo `backup → preflight → deadman (.timer como árbitro) → confirm/rollback`,
  con persistencia validada en `/etc/nftables.conf` (maneja `chattr +i` de corridas previas).
- **Validado en producción**: Debian 12, host piloto de pruebas (última tag formal
  `v0.6.0`).
- **Pendiente:**
  - Exponer CrowdSec como módulo propio de menú/CLI (hoy es solo backend).
  - Nueva tag de release — `dev` está 87 commits adelante de `v0.6.0` sin tag nueva.
  - Merge `dev` → `main` — requiere aprobación explícita de Freddy (Regla de Oro del workspace);
    hoy `main` solo tiene el commit de bootstrap, sin código.

---

## Roadmap

- **Módulo CrowdSec propio** (menú + CLI): hoy `internal/modules/crowdsec/` es lógica de soporte
  interna, llamada desde `whitelist.go` (sincronización de allowlist) e `infra.go` (sets de
  ruleset). No implementa la interface `modules.Module` ni está registrado en `main.go`. Falta
  implementar `Order()/Name()/Menu()/Reset()` y mover la lógica de instalación hoy en
  `internal/sys/prereqs.go` (`CheckAndInstallCrowdSec` y helpers) hacia el módulo propio.
- **Internacionalización del CLI en runtime**: hoy todos los mensajes del programa (menú,
  prompts, ayuda) están hardcodeados en español. Falta diseñar un sistema de i18n (mapa de
  strings o librería) para que el binario mismo soporte español (Venezuela) por defecto e
  inglés (US) como secundario — no solo la documentación.

---

## Licencia

AGPLv3 — ver [`LICENSE`](LICENSE). Este software es open source; no se vende el binario. El
modelo de sostenibilidad es soporte y consultoría, no venta de licencias. Ver también
[`NOTICE`](NOTICE), [`THIRD-PARTY-LICENSES.md`](THIRD-PARTY-LICENSES.md) y
[`SECURITY.md`](SECURITY.md) para reportar vulnerabilidades.
