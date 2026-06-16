---
title: "Security-Manager-NG — Arquitectura del pipeline de filtrado (nftables)"
created: 2026-06-10
tags:
  - security-manager
  - nftables
  - firewall
  - arquitectura
---

# 🔥 Pipeline de filtrado — tabla `inet sm`

Este documento fija la **lógica del firewall** de Security-Manager-NG: cómo un paquete
entrante recorre la tabla `inet sm` y se decide su aceptación o descarte. Es la referencia
que guía la implementación del backend nftables.

A diferencia del modelo UFW/`before.rules` (fragmentos inyectados con orden dependiente de
marcadores), aquí el recorrido es **declarativo, atómico y de orden total y explícito**.

---

## 📊 Figura 1.1: Topología lógica del pipeline

![Figura 1.1: Pipeline de filtrado de la tabla inet sm](diagramas/sm-ng-pipeline-nftables.png)

> Fuente editable: `diagramas/sm-ng-pipeline-nftables.drawio` (draw.io) y
> `diagramas/sm-ng-pipeline-nftables.dot` (graphviz, render del PNG).

---

## 📈 Diagrama 1.2: Recorrido del paquete (Mermaid)

```mermaid
graph TD
    PKT["📥 Paquete entrante (WAN / LAN)"]
    CHAIN["chain input<br/>hook input · priority filter · policy DROP"]

    PKT --> CHAIN
    CHAIN --> S1{"1 · ct state<br/>established,related?"}
    S1 -->|sí| ACC1["ACCEPT (fast-path)"]
    S1 -->|no| S2{"2 · iif lo?"}
    S2 -->|sí| ACC2["ACCEPT"]
    S2 -->|no| S3{"3 · ct state invalid?"}
    S3 -->|sí| D3["DROP"]
    S3 -->|no| ANTI{"4 · ANTIRECON<br/>tcp flags XMAS/NULL/<br/>FIN+SYN/SYN+RST?"}

    ANTI -->|match| DANTI["limit rate → log SM-ANTIRECON → DROP"]
    ANTI -->|no match| BL{"5 · BLACKLIST<br/>@sm_blacklist4/6?"}
    BL -->|match| DBL["DROP"]
    BL -->|no match| WL{"6 · WHITELIST / SSoT<br/>@sm_whitelist4/6?"}
    WL -->|match| AWL["ACCEPT (bypass total — infra confiable)"]
    WL -->|no match| GEO{"7 · GEOIP condicional<br/>@geoip_&lt;cc&gt;?"}
    GEO -->|país no permitido| DGEO["log SM-GEOIP → DROP"]
    GEO -->|permitido / sin geoip| SRV{"8 · SERVICIOS<br/>tcp dport 22/80/443 · icmp echo?"}
    SRV -->|match| ASRV["ACCEPT"]
    SRV -->|no match| DEF["9 · POLICY DROP · log SM-DROP-DEFAULT"]

    style CHAIN fill:#1f3864,color:#fff
    style ACC1 fill:#d5e8d4,stroke:#82b366
    style ACC2 fill:#d5e8d4,stroke:#82b366
    style AWL fill:#d5e8d4,stroke:#82b366
    style ASRV fill:#d5e8d4,stroke:#82b366
    style D3 fill:#f8cecc,stroke:#b85450
    style DANTI fill:#f8cecc,stroke:#b85450
    style DBL fill:#f8cecc,stroke:#b85450
    style DGEO fill:#f8cecc,stroke:#b85450
    style DEF fill:#b85450,color:#fff
```

---

## 🔎 Recorrido paso a paso (chain `input`)

`chain input { type filter hook input priority filter; policy drop; }` — todo lo que no se
acepta explícitamente, cae en `policy drop`.

| # | Etapa | Regla nftables (conceptual) | Resultado |
|---|---|---|---|
| 1 | **Conntrack fast-path** | `ct state established,related accept` | ACCEPT inmediato — tráfico ya conocido |
| 2 | **Loopback** | `iif lo accept` | ACCEPT — tráfico local |
| 3 | **Conntrack inválido** | `ct state invalid drop` | DROP — paquetes fuera de estado |
| 4 | **Antirecon** | `tcp flags & (fin\|syn\|rst\|psh\|ack\|urg) == ...` (XMAS/NULL/FIN+SYN/SYN+RST) → `limit rate` → `log prefix "SM-ANTIRECON"` → `drop` | DROP con rate-limit — escaneos |
| 5 | **Blacklist** | `ip saddr @sm_blacklist4 drop` / `ip6 saddr @sm_blacklist6 drop` | DROP — bans manuales |
| 6 | **Whitelist / SSoT** | `ip saddr @sm_whitelist4 accept` / `ip6 saddr @sm_whitelist6 accept` | **ACCEPT (bypass total)** — infra confiable |
| 7 | **GeoIP** (condicional) | `ip saddr @geoip_<cc>4 ...` por país permitido; resto `log prefix "SM-GEOIP"` → `drop` | continúa o DROP |
| 8 | **Servicios permitidos** | `tcp dport { 22, 80, 443 } accept`; `icmp/icmpv6 echo-request limit rate ... accept` | ACCEPT — servicios públicos |
| 9 | **Default** | `policy drop` + `log prefix "SM-DROP-DEFAULT"` | DROP — todo lo demás |

> **Orden crítico:** blacklist (5) **antes** que whitelist (6) — un origen baneado nunca debe
> ganar por estar también en una subred whitelisteada. Whitelist (6) **antes** que GeoIP (7) —
> la infra confiable nunca depende del país de origen.

---

## 🗃️ Sets nativos (reemplazan ipset)

Todos con `flags interval` para soportar rangos/CIDR.

| Set | Tipo | Origen / contenido |
|---|---|---|
| `sm_whitelist4` / `sm_whitelist6` | `ipv4_addr` / `ipv6_addr` | **SSoT** — subredes/VLANs de infra confiable |
| `geoip_<cc>4` / `geoip_<cc>6` | `ipv4_addr` / `ipv6_addr` | rangos por país permitido (descarga GeoIP) |
| `sm_blacklist4` / `sm_blacklist6` | `ipv4_addr` / `ipv6_addr` | bans manuales |

**Recarga atómica:** se regenera el bloque del set y se aplica con `nft -f` (atómico nativo;
no se necesita el patrón swap de ipset).

### Componentes externos a la chain `input`

- **fail2ban** → opera en su **propia tabla `f2b-table`** (banaction nftables). Coexiste con
  `inet sm` sin interferir; sus reglas se evalúan en su propio hook.
- **NAT WireGuard** → `chain postrouting { type nat hook postrouting priority srcnat; oifname $WAN masquerade }`
  dentro de la misma tabla `inet sm`.

---

## ✅ Validación del ruleset

```bash
# Validar sintaxis sin aplicar (siempre antes de cargar)
sudo nft -c -f /etc/security-manager/sm.nft
```

```bash
# Inspeccionar tras aplicar bajo safe-apply (deadman activo)
sudo nft list table inet sm
sudo nft list set inet sm sm_whitelist4
```
