# TASK_LOG — Security-Manager-NG

> Bitácora de ejecución. Append-only: nunca borrar entradas.
> Índice de planificación: `Obsidian/Planes/task-checklist.md` (vault)
> Ficha del proyecto: `Obsidian/Planes/Security-Manager-NG/00-proyecto-sm-ng.md`

---

## Leyenda de estados

| Símbolo | Significado |
|---------|-------------|
| ⏳ | Pendiente / en espera |
| 🔄 | En progreso |
| ✅ | Completo |
| ❌ | Fallido / bloqueado |
| — | No aplica aún |

---

## Fases estándar de una tarea

```
desarrollo → build → deploy → validación → commit → cerrado
```

---

## [TASK-001] Bootstrap del repositorio GitHub

**Inicio:** 2026-06-16
**Agente:** Claude Code (Sonnet 4.6)
**Branch:** `main` (bootstrap inicial) → `dev` (desarrollo futuro)

| Fase       | Estado      | Timestamp   | Notas |
|------------|-------------|-------------|-------|
| desarrollo | ✅ completo | 2026-06-16  | README.md completo, TASK_LOG.md creado, CLAUDE.md heredado de SM-Go |
| commit     | ✅ completo | 2026-06-16  | Commit inicial con docs, diagramas y archivos de configuración del proyecto |
| deploy     | ✅ completo | 2026-06-16  | Push a `main` en `git@github.com:terracenter/Security-Manager-Ng.git` |
| validación | ✅ completo | 2026-06-16  | Branch `dev` creada y publicada para el desarrollo futuro |
| cerrado    | ✅          | 2026-06-16  | Repo público en GitHub con documentación inicial completa |

**Contenido del commit inicial:**

| Archivo | Descripción |
|---------|-------------|
| `README.md` | Documentación completa: arquitectura, pipeline, sets, build, deploy |
| `CLAUDE.md` | Instrucciones del agente heredadas del proyecto |
| `TASK_LOG.md` | Este archivo (primera entrada) |
| `.gitignore` | Exclusiones del repo |
| `docs/arquitectura-pipeline-nftables.md` | Especificación técnica del pipeline nftables |
| `docs/diagramas/sm-ng-pipeline-nftables.drawio` | Diagrama editable draw.io |
| `docs/diagramas/sm-ng-pipeline-nftables.dot` | Fuente graphviz |
| `docs/diagramas/sm-ng-pipeline-nftables.png` | Diagrama renderizado |

**Próxima tarea:** TASK-002 — Estructura base del proyecto Go (`go mod init`, `main.go`, interface `modules.Module`, scaffold de módulos)

---

## [TASK-002] Estructura base Go — módulos e infraestructura interna

**Inicio:** 2026-06-16
**Agente:** Claude Code (Sonnet 4.6)
**Branch:** `dev`

| Fase       | Estado      | Timestamp   | Notas |
|------------|-------------|-------------|-------|
| desarrollo | ✅ completo | 2026-06-16  | 7 stubs de módulos + infra + sys + safeapply |
| verificación | ✅ completo | 2026-06-16 | Haiku verificó C1–C5: go build ✅ go vet ✅ interface ✅ |
| cerrado    | ✅          | 2026-06-16  | Commit a5c0d3c en branch dev |

**Archivos creados:**

| Archivo | Descripción |
|---------|-------------|
| `go.mod` | `module github.com/terracenter/security-manager-ng`, `go 1.24.4` |
| `internal/modules/module.go` | Interface `Module` (Order, Name, Menu, Reset) |
| `internal/modules/firewall/firewall.go` | Stub Order=1 |
| `internal/modules/whitelist/whitelist.go` | Stub Order=2 |
| `internal/modules/geoip/geoip.go` | Stub Order=3 |
| `internal/modules/blacklist/blacklist.go` | Stub Order=4 |
| `internal/modules/hardroot/hardroot.go` | Stub Order=5 |
| `internal/modules/ssh/ssh.go` | Stub Order=6 |
| `internal/modules/fail2ban/fail2ban.go` | Stub Order=7 |
| `internal/modules/infra/infra.go` | Constantes SSoT (ConfDir, RulesetFile, sets, Table) |
| `internal/sys/sys.go` | Port de SM-Go: GetSSHIP, DetectVPNSubnets, DetectDistro, OfferInstall |
| `internal/safeapply/safeapply.go` | Esqueleto Plan struct + Apply() — pendiente TASK-004 |

**Próxima tarea:** TASK-003 — `main.go` con menú interactivo

---

## [TASK-003] main.go — menú interactivo principal

**Inicio:** 2026-06-16
**Agente:** Claude Code (Sonnet 4.6)
**Branch:** `dev`

| Fase       | Estado      | Timestamp   | Notas |
|------------|-------------|-------------|-------|
| desarrollo | ✅ completo | 2026-06-16  | main.go con initModules, printMenu, loop de selección |
| build      | ✅ completo | 2026-06-16  | `go build ./...` OK, `go vet ./...` OK |
| validación | ✅ completo | 2026-06-16  | Haiku verificó C1–C6: build ✅ vet ✅ menú ✅ input-inválido ✅ git-log ✅ |
| commit     | ✅ completo | 2026-06-16  | Commit a5c0d3c (junto a TASK-002) en branch dev |
| deploy     | ✅ completo | 2026-06-16  | Push a origin/dev |

**Lógica de main.go:**
- `initModules()`: instancia los 7 módulos, los ordena por `Order()` con `sort.Slice`
- `printMenu()`: encabezado, usuario activo vía `sys.CurrentUser()`, lista numerada [1–7] + [0] Salir
- Loop principal: lee stdin, despacha a `mods[sel-1].Menu()` o termina con 0

| cerrado    | ✅          | 2026-06-16  | Verificación Haiku C1–C6 all pass |

**Próxima tarea:** TASK-004 — Implementar `safeapply.Apply()` (backup → preflight → deadman → confirm/rollback)

---

## [TASK-004] safeapply.Apply() — ciclo completo backup → deadman → confirm/rollback

**Inicio:** 2026-06-16
**Agente:** Claude Code (Sonnet 4.6) — Implementación; Haiku 4.5 — Verificación
**Branch:** `dev`

| Fase       | Estado      | Timestamp   | Notas |
|------------|-------------|-------------|-------|
| desarrollo | ✅ completo | 2026-06-16  | Implementación Sonnet: backup → preflight → nft -f → systemd-run → askConfirm(goroutine+select) → cancelDeadman/rollback |
| build      | ✅ completo | 2026-06-16  | `go build ./...` OK; `go vet ./...` OK |
| validación | ✅ completo | 2026-06-16  | Haiku verificó C1–C6: todas ✅. Apply() presente, Plan struct correcto, 8 funciones internas, cero panic() |
| commit     | ✅ completo | 2026-06-16  | Commit 8c9c1d3 en branch dev — push a origin/dev |
| cerrado    | ✅          | 2026-06-16  | TASK-004 validado y listo para próximo módulo (TASK-005: firewall module) |

**Próxima tarea:** TASK-005 — Módulo firewall (implementación real con ruleset nftables 9 etapas)

---

## [TASK-005] Módulo firewall — ruleset nftables declarativo completo

**Inicio:** 2026-06-16
**Agente:** Claude Code (Sonnet 4.6)
**Branch:** `dev`

| Fase       | Estado      | Timestamp   | Notas |
|------------|-------------|-------------|-------|
| desarrollo | ✅ completo | 2026-06-16  | generateRuleset(9 etapas), applyBase(nft -c + safeapply), showStatus, resetTable, detectSSHPort |
| build      | ✅ completo | 2026-06-16  | `go build ./...` OK; `go vet ./...` OK |
| validación | ✅ completo | 2026-06-16  | Haiku verificó C1–C7: build ✅ vet ✅ interface ✅ generateRuleset ✅ safeapply ✅ nft -c ✅ commit ✅ |
| commit     | ✅ completo | 2026-06-16  | Commit de64a4f en branch dev — push a origin/dev |
| cerrado    | ✅          | 2026-06-16  | Verificación Haiku C1–C7 all pass — implementación sólida |

**Funciones implementadas:**

| Función | Descripción |
|---------|-------------|
| `generateRuleset(sshPort int)` | Produce sm.nft completo: 4 sets vacíos + 9 etapas del pipeline |
| `applyBase()` | Escribe archivo temporal, valida con `nft -c`, mueve a `sm.nft`, llama `safeapply.Apply()` |
| `showStatus()` | `nft list table inet sm` |
| `resetTable()` | `nft flush table inet sm` con confirmación previa |
| `detectSSHPort()` | Lee `/etc/ssh/sshd_config` para puerto no estándar (default 22) |
| `ensureConfDir()` | Crea `/etc/security-manager/` si no existe |
| `Menu()` | Submenú [1-3/0] con bucle propio |

**Próxima tarea:** TASK-006 — Módulo whitelist (gestión de sm_whitelist4/6 con safeapply)

---

## [TASK-006] Módulo whitelist — gestión de sm_whitelist4/6

**Inicio:** 2026-06-16
**Agente:** Claude Code (Sonnet 4.6)
**Branch:** `dev`

| Fase       | Estado      | Timestamp   | Notas |
|------------|-------------|-------------|-------|
| desarrollo | ✅ completo | 2026-06-16  | addIP, addSelf, listIPs, deleteIP, resolveSet, nftAddElement, nftDeleteElement |
| build      | ✅ completo | 2026-06-16  | `go build ./...` OK; `go vet ./...` OK |
| validación | ✅ completo | 2026-06-16  | Haiku verificó C1–C7: build ✅ vet ✅ interface ✅ resolveSet ✅ GetSSHIP ✅ nft-atómico ✅ commit ✅ |
| commit     | ✅ completo | 2026-06-16  | Commit ae753ee en branch dev — push a origin/dev |
| cerrado    | ✅          | 2026-06-16  | Verificación Haiku C1–C7 all pass — operaciones atómicas sin safeapply |

**Funciones implementadas:**

| Función | Descripción |
|---------|-------------|
| `addIP()` | Solicita IP/CIDR; llama `resolveSet()` para clasificar; `nft add element` atómico |
| `addSelf()` | Usa `sys.GetSSHIP()` + confirmación antes de agregar; detecta IPv4/IPv6 |
| `listIPs()` | `nft list set inet sm sm_whitelist4/6` |
| `deleteIP()` | Solicita IP/CIDR + confirmación; `nft delete element` atómico |
| `resolveSet()` | `net.ParseCIDR`/`net.ParseIP` — clasificación sin inyección posible |
| `nftAddElement()` | Wrapper de `nft add element inet sm <set> { <entry> }` |
| `nftDeleteElement()` | Wrapper de `nft delete element inet sm <set> { <entry> }` |

**Diseño técnico validado:**
- Operaciones sobre sets son atómicas (`nft add/delete element`) — correcto no usar safeapply.
- `resolveSet()` valida con stdlib antes de invocar nft — sin inyección de shell.
- Compile-time interface check con `var _ interface{...} = (*Whitelist)(nil)`.

**Próxima tarea:** TASK-007 — Módulo geoip

---

## [TASK-007] Módulo geoip — bloqueo por país con ipdeny.com

**Inicio:** 2026-06-16
**Agente:** Claude Code (Sonnet 4.6)
**Branch:** `dev`

| Fase       | Estado      | Timestamp   | Notas |
|------------|-------------|-------------|-------|
| desarrollo | ✅ completo | 2026-06-16  | geoip.go completo + refactor infra + fix safeapply backup + persistencia whitelist |
| build      | ✅ completo | 2026-06-16  | `go build ./...` OK; `go vet ./...` OK |
| validación | ✅ completo | 2026-06-16  | Haiku verificó C1–C8: build ✅ vet ✅ geoip-interface ✅ funciones-privadas ✅ infra-centralizado ✅ SkipBackup-fix ✅ persistencia-whitelist ✅ commit ✅ |
| commit     | ✅ completo | 2026-06-16  | Commit f962bb7 en branch dev — push a origin/dev |
| cerrado    | ✅          | 2026-06-16  | Verificación Haiku C1–C8 all pass — geoip + refactor infra + fix safeapply backup |

**Archivos modificados:**

| Archivo | Cambio |
|---------|--------|
| `internal/modules/geoip/geoip.go` | Implementación completa (stub → módulo real) |
| `internal/modules/infra/infra.go` | `GenerateRuleset()`, `DetectSSHPort()`, `LoadGeoIPData()`, `ReadLines()`, constantes geoip/persist |
| `internal/modules/firewall/firewall.go` | Usa `infra.GenerateRuleset()`, backup correcto pre-rename |
| `internal/modules/whitelist/whitelist.go` | Persistencia add/delete en whitelist4.conf/whitelist6.conf |
| `internal/safeapply/safeapply.go` | Campo `SkipBackup bool`; fix bug backup post-rename |

**Funciones geoip implementadas:**

| Función | Descripción |
|---------|-------------|
| `addCountry()` | Agrega CC a blocked_countries.conf (valida ISO 3166-1 alfa-2) |
| `removeCountry()` | Elimina CC del config |
| `listCountries()` | Muestra países con estado de zone files (✓/⚠) |
| `updateRanges()` | Descarga zone files de ipdeny.com (IPv4 + IPv6) via curl |
| `applyGeoIP()` | LoadGeoIPData → GenerateRuleset → nft -c → backup → rename → safeapply |

**Bug corregido (pre-existente desde TASK-005):**
- `safeapply.Apply()` hacía backup DESPUÉS del rename → `sm.nft.bak` = nuevo ruleset → deadman rollbackeaba al mismo estado.
- Fix: `SkipBackup: true` + backup manual ANTES del rename en todos los módulos que aplican ruleset.

**Próxima tarea:** TASK-008 — Módulo blacklist

---

## [TASK-008] Módulo blacklist — bans manuales sm_blacklist4/6

**Inicio:** 2026-06-16
**Agente:** Claude Code (Sonnet 4.6 implementa; Haiku 4.5 verifica)
**Branch:** `dev`

| Fase       | Estado      | Timestamp   | Notas |
|------------|-------------|-------------|-------|
| desarrollo | ✅ completo | 2026-06-16  | blacklist.go completo: addIP, listIPs, deleteIP, flushAll, resolveSet atómico |
| build      | ✅ completo | 2026-06-16  | `go build ./...` OK; `go vet ./...` OK |
| validación | ✅ completo | 2026-06-16  | Haiku verificó C1–C9: build ✅ vet ✅ interface ✅ Order/Name ✅ funciones ✅ infra-constants ✅ flushAll-confirm ✅ git-state ✅ commit ✅ |
| commit     | ✅ completo | 2026-06-16  | Commit f76a1ab en branch dev — push a origin/dev |
| cerrado    | ✅          | 2026-06-16  | Verificación Haiku C1–C9 all pass — patrón idéntico a whitelist |

**Funciones implementadas:**

| Función | Descripción |
|---------|-------------|
| `addIP()` | Solicita IP/CIDR; `resolveSet()` clasifica; `nft add element` atómico + persistencia |
| `listIPs()` | `nft list set inet sm sm_blacklist4/6` |
| `deleteIP()` | IP/CIDR + confirmación; `nft delete element` atómico + remoción del archivo |
| `flushAll()` | Confirmación `[s/N]` → `nft flush set` ambos sets + truncate de archivos conf |
| `resolveSet()` | `net.ParseCIDR`/`net.ParseIP` — clasificación IPv4/IPv6 sin inyección de shell |
| `nftAddElement()` | Wrapper `nft add element inet sm <set> { <entry> }` |
| `nftDeleteElement()` | Wrapper `nft delete element inet sm <set> { <entry> }` |

**Diseño técnico:**
- Operaciones atómicas (`nft add/delete element`) — no requiere safeapply.
- Persistencia simétrica a whitelist: `appendToFile`/`removeFromFile` → `blacklist4/6.conf`.
- `flushAll()` tiene doble protección: confirmación interactiva + truncate solo si nft flush OK.
- Compile-time interface check con `var _ interface{...} = (*Blacklist)(nil)` en línea 233.

**Próxima tarea:** TASK-009 — Módulo hardroot (hardening root SSH + sudoers)

---

## [TASK-RELEASES] GitHub Releases retroactivos v0.4.0–v0.6.0

**Inicio:** 2026-06-16
**Agente:** Claude Code (Sonnet 4.6 planifica; Haiku 4.5 ejecuta)
**Branch:** `main` (tags sobre commits de `dev`)

| Fase       | Estado      | Timestamp   | Notas |
|------------|-------------|-------------|-------|
| planificación | ✅ completo | 2026-06-16 | Sonnet preparó checklist en handoff; tags v0.1.0–v0.6.0 ya existían |
| ejecución  | ✅ completo | 2026-06-16  | Haiku creó 3 releases retroactivos (C1–C3) y verificó los 6 (C4) |
| cerrado    | ✅          | 2026-06-16  | 6 releases en GitHub: v0.1.0–v0.6.0, todos Pre-release |

| Release | Tag commit | URL |
|---------|-----------|-----|
| v0.4.0  | TASK-005 (de64a4f) | https://github.com/terracenter/Security-Manager-Ng/releases/tag/v0.4.0 |
| v0.5.0  | TASK-006 (ae753ee) | https://github.com/terracenter/Security-Manager-Ng/releases/tag/v0.5.0 |
| v0.6.0  | TASK-007 (f962bb7) | https://github.com/terracenter/Security-Manager-Ng/releases/tag/v0.6.0 |

---

## [TASK-009] Módulo hardroot — hardening root SSH + sudoers

**Inicio:** 2026-06-16
**Agente:** Claude Code (Sonnet 4.6 implementa; Haiku 4.5 verifica)
**Branch:** `dev`

| Fase       | Estado      | Timestamp   | Notas |
|------------|-------------|-------------|-------|
| desarrollo | ✅ completo | 2026-06-16  | hardroot.go adaptado de SM-Go: opciones SSH + sudoers + passwd |
| build      | ✅ completo | 2026-06-16  | `go build ./...` OK; `go vet ./...` OK |
| validación | ✅ completo | 2026-06-16  | Haiku verificó C1–C7: build ✅ vet ✅ interface ✅ struct ✅ Menu ✅ funciones ✅ commit ✅ |
| commit     | ✅ completo | 2026-06-16  | Commit 9c30ca2 en branch dev — push a origin/dev |
| cerrado    | ✅          | 2026-06-16  | Verificación Haiku C1–C7 all pass |

**Funciones implementadas:**

| Función | Descripción |
|---------|-------------|
| `showStatus()` | Lee sshd_config, passwd, sudoers.d/sm-ng — estado actual de hardening |
| `hardenSSHRoot()` | Modifica sshd_config: `PermitRootLogin without-password` (SSH-key only) |
| `blockRoot()` | Ejecuta `passwd -l root` para bloquear login interactivo |
| `configureSudoers()` | Crea/actualiza `/etc/sudoers.d/sm-ng` con configuración segura |
| `Menu()` | Submenú [1-4/0] con bucle propio |

**Diseño técnico:**
- Interfaz `Module` implementada: `Order()=5`, `Name()`, `Menu()`, `Reset()=noop`.
- Heredado de SM-Go con adaptaciones mínimas a la nueva interfaz.
- Sudo sin `log_output` (corregido en SM-Go).

**Próxima tarea:** TASK-010 — Módulo ssh (sshd hardening heredado de SM-Go)

---

## [TASK-010] Módulo ssh — hardening sshd_config.d

**Inicio:** 2026-06-16
**Agente:** Claude Code (Sonnet 4.6 planifica; Haiku 4.5 ejecuta)
**Branch:** `dev`

| Fase       | Estado      | Timestamp   | Notas |
|------------|-------------|-------------|-------|
| planificación | ✅ completo | 2026-06-16 | Sonnet diseñó checklist C1–C12 en handoff; identificadas 4 incompatibilidades SM-Go→SM-NG |
| desarrollo | ✅ completo | 2026-06-16  | ssh.go completo (562 líneas): templates + Menu + 9 funciones + helpers bufio.Scanner |
| build      | ✅ completo | 2026-06-16  | `go build ./...` OK; `go vet ./...` OK |
| validación | ✅ completo | 2026-06-16  | Haiku verificó C1–C12: constantes ✅ struct ✅ interface ✅ Menu ✅ showStatus ✅ preflight ✅ applyBase-backup ✅ banners ✅ validate ✅ helpers ✅ build ✅ vet ✅ commit ✅ |
| commit     | ✅ completo | 2026-06-16  | Commit fa93dd3 en branch dev — push a origin/dev |
| cerrado    | ✅          | 2026-06-16  | Verificación Haiku C1–C12 all pass — módulo ssh listo para producción |

**Funciones implementadas:**

| Función | Descripción |
|---------|-------------|
| `showStatus()` | Servicio SSH, archivos config, directivas sshd -T, puerto :22, banners |
| `preflight()` | Verifica SUDO_USER→USER, membresía AllowGroups via id -Gn, ~/.ssh/authorized_keys si PasswordAuth=no |
| `applyBase()` | Backup manual baseConf+.bak, idempotencia, sshd -t, rollback si falla, sshdReload |
| `applyBanners()` | Escribe /etc/issue.net y /etc/issue con contenido legal bilingüe |
| `validate()` | sshd -T filtrado, puerto ss -lnpt, últimas autenticaciones journalctl |
| `readLine()` | Input interactivo con bufio.Scanner (reemplaza ui.ReadLine) |
| `askAuthMethod()` | 3 modos: solo llave / llave-o-contraseña / llave-y-contraseña (MFA) |
| `askPermitTunnel()` | Habilitar/deshabilitar túneles TUN/TAP SSH |
| `askAllowGroups()` | Pide grupos permitidos, valida contra getent group |

**Templating (SM-Go → SM-NG exacto):**
- `baseConfTemplate`: hardening criptográfico post-cuántico (sntrup761x25519, algoritmos modernos, PermitRootLogin no) |
- `issueNetContent`/`issueContent`: banners bilingües (inglés/español) con advertencia legal PCI-DSS/ISO 27001 |

**Diferencias SM-Go → SM-NG (resueltas en TASK-010):**

| Aspecto | SM-Go | SM-NG | Solución |
|---------|-------|-------|----------|
| Input interactivo | `ui.ReadLine()` | ❌ no existe | `bufio.Scanner` en struct SSH |
| safeapply para SSH | `safeapply.Apply()` | ❌ solo nftables | Backup manual + `os.Rename()` + rollback |
| Usuario actual | `sys.CurrentUser()` | ❌ no existe | `os.Getenv("SUDO_USER")` → `"USER"` → `"root"` |
| FreeIPA | `20-sshd-freeipa.conf` | ❌ no incluido | Excluido de TASK-010 (TASK futura si se necesita) |

**Diseño técnico:**
- `Order()=6`, `Name()="SSH — hardening sshd_config"`, `Menu()` loop interactivo con 5 opciones.
- Backup antes de escribir; rollback automático si `sshd -t` falla — red de seguridad contra auto-bloqueo.
- `preflight()` detiene aplicación si usuario activo quedaría bloqueado por AllowGroups.
- Compile-time interface assertion `var _ interface{...} = (*SSH)(nil)` en línea 516.

**Próxima tarea:** TASK-011 — Módulo fail2ban (monitoreo de jails heredado de SM-Go)

---

## [TASK-011] Módulo fail2ban — monitoreo (solo lectura)

**Inicio:** 2026-06-16
**Agente:** Claude Code (Sonnet 4.6 planifica; Haiku 4.5 ejecuta)
**Branch:** `dev`

| Fase       | Estado      | Timestamp   | Notas |
|------------|-------------|-------------|-------|
| planificación | ✅ completo | 2026-06-16 | Sonnet diseñó checklist D1–D10 en handoff; scope: monitoreo solo (no gestión), stdlib only |
| desarrollo | ✅ completo | 2026-06-16  | fail2ban.go completo (~300 líneas): Menu 5 opciones + Status + IPs baneadas + Búsqueda + Geo + helpers |
| build      | ✅ completo | 2026-06-16  | `go build ./...` OK; `go vet ./...` OK |
| validación | ✅ completo | 2026-06-16  | Haiku verificó D1–D10: constantes ✅ struct ✅ interface ✅ Menu ✅ showStatus ✅ listBanned ✅ searchIP ✅ geoInfo ✅ helpers ✅ build ✅ vet ✅ commit ✅ |
| commit     | ✅ completo | 2026-06-16  | Commit 5248cbe en branch dev — push a origin/dev; TASK_LOG.md actualizado |
| cerrado    | ✅          | 2026-06-16  | Validación Haiku D1–D10 all pass — módulo fail2ban listo |

**Funciones implementadas:**

| Función | Descripción |
|---------|-------------|
| `showStatus()` | systemctl is-active/is-enabled, lista jails con "Currently banned" y "Total banned" |
| `listBanned(jail)` | Obtiene IPs baneadas, geo on-demand (ipinfo.io), pagina ≥15 IPs |
| `searchIP(ip)` | Busca IP en todos los jails activos, muestra resultado + geo |
| `geoInfo(ip)` | Consulta ipinfo.io directa — país/ciudad/org/timezone/loc sin caché |
| `readLine()` | Input interactivo con bufio.Scanner (bufio.Scanner en struct) |
| `activeJails()` | Parsea `fail2ban-client status` para extraer lista de jails |
| `parseBannedIPs()` | Extrae IPs de línea "Banned IP list:" |
| `fetchGeo()` | HTTP GET a ipinfo.io, JSON decode, manejo de errores |

**Alcance y diferencias SM-Go → SM-NG (resueltas):**

| Aspecto | SM-Go | SM-NG | Decisión |
|---------|-------|-------|----------|
| Fuente datos | SQLite + fail2ban-client | fail2ban-client solo | Monitoreo no necesita persitencia |
| Caché geo | SQLite 7 días | Sin caché | HTTP on-demand (simple, plan free: 50k/mes) |
| Whitelist DB | ✓ (admin) | ❌ (no existe) | TASK-011 es monitoreo, no admin |
| Ban/unban | ✓ (admin) | ❌ (no existe) | Prohibido en alcance "monitoreo" |
| jail.local config | ✓ (admin) | ❌ (no existe) | No aplica a TASK-011 |
| AbuseIPDB | ✓ (opcional) | ❌ (no existe) | Plan free ipinfo.io suficiente |
| Dependencias externas | `modernc.org/sqlite` | **stdlib only** | go.mod limpio, sin requires |

**Diseño técnico:**
- `Order()=7`, `Name()="Fail2ban — monitoreo"`, `Menu()` loop interactivo con 5 opciones [1-4/0].
- Struct Fail2ban con `*bufio.Scanner` — reemplaza `ui.ReadLine()` de SM-Go.
- `geoInfo()` llama HTTP directo a ipinfo.io — sin token, plan free suficiente (50k/mes manual).
- Compile-time interface assertion `var _ interface{...} = (*Fail2ban)(nil)` al final del archivo.
- Reset() imprime aviso informativo — módulo es de solo lectura.

**Próxima tarea:** TASK-012 — Deploy script e install.sh

---

## [TASK-FIX-B1B2] Corrección bloqueantes B1 (deadman primera instalación) + B2 (ssh cross-distro)

**Inicio:** 2026-06-16
**Agente:** Claude Code (Haiku 4.5) — Ejecución de checklist validado por Opus
**Branch:** `dev`

| Fase       | Estado      | Timestamp   | Notas |
|------------|-------------|-------------|-------|
| planificación | ✅ completo | 2026-06-16 | Sonnet (Senior) diseñó checklist C1–C8; Opus (Arquitecto) validó y señaló 3 correcciones obligatorias |
| validación | ✅ completo | 2026-06-16 | Opus veredicto OBSERVACIONES: (1) B1 usa `flush table` (lockout) → cambiar a `delete table` en C1/C2/C6; (2) B3 detectado en resetTable (C8); (3) B4 registrado como tarea de seguimiento aparte |
| desarrollo | ✅ completo | 2026-06-16  | Haiku ejecutó C1–C8: safeapply (scheduleDeadman/rollback), ssh (detectSSHService), firewall (resetTable) |
| build      | ✅ completo | 2026-06-16  | `go build ./...` OK; `go vet ./...` OK — sin errores |
| commit     | ✅ completo | 2026-06-16  | Commit c55438b en branch dev — fix safeapply/firewall/ssh |
| cerrado    | ✅          | 2026-06-16  | Haiku validación C1–C8 all pass — bloqueantes B1/B2/B3 solucionados; B4 para próximo |

**Correcciones aplicadas:**

| ID | Problema | Ubicación | Solución | Commit |
|----|----------|-----------|----------|--------|
| B1 | deadman/rollback fallan en primera instalación (`.bak` no existe) | `safeapply.go` | Verificar `os.Stat()` — si no existe usar `nft delete table inet sm` (C1/C2) | c55438b |
| B2 | Módulo ssh hardcoded a unit `ssh` — rompe en RHEL-family | `ssh.go` | Agregar `detectSSHService()` que prueba `systemctl cat ssh.service` (C3/C4) | c55438b |
| B3/C8 | resetTable() usa `nft flush table inet sm` — lockout sin deadman | `firewall.go:126` | Cambiar a `nft delete table inet sm` + ajustar textos | c55438b |
| B4 | ruleset empieza con `flush ruleset` — borra `f2b-table` de fail2ban | `infra.go:135` | **NO ejecutar aquí** — registrada como TASK-B4 para decisión de Freddy | — |

**Archivos modificados:**

| Archivo | Cambios | Líneas |
|---------|---------|--------|
| `internal/safeapply/safeapply.go` | scheduleDeadman() y rollback() — rama `os.IsNotExist` | +30 |
| `internal/modules/ssh/ssh.go` | Función detectSSHService() + eliminar `sshService = "ssh"` + 5 usos | +7 -1 |
| `internal/modules/firewall/firewall.go` | resetTable() — `flush` → `delete` + ajustar textos | +5 |

**Checklist C1–C8 ejecución:**

| # | Ítem | Status | Notas |
|---|------|--------|-------|
| C1 | scheduleDeadman() — rama `os.IsNotExist` | ✅ | `nft delete table inet sm` cuando `.bak` no existe |
| C2 | rollback() — rama `os.IsNotExist` | ✅ | Misma lógica; `grep -c "delete table" safeapply.go` → 3 |
| C3 | Agregar `detectSSHService()` | ✅ | Función presente en ssh.go (helpers) |
| C4 | Eliminar `sshService` constante + 5 usos | ✅ | showStatus (2), validate (1), sshdRestart (1), sshdReload (1) reemplazados |
| C5 | Build + vet | ✅ | `go build ./...` OK; `go vet ./...` OK |
| C6 | Verificación rama delete — no `flush` | ✅ | `grep "delete table"` → 3 (safeapply) + 1 (firewall) = 4; `grep "flush table"` → 0 |
| C7 | Commit + TASK_LOG + vault | ✅ | Commit c55438b; TASK_LOG esta entrada; 00-proyecto-sm-ng actualizada |
| C8 | resetTable() — `flush` → `delete` | ✅ | firewall.go:126 cambiado; texto prompt/error actualizado |

**Hallazgo B4 (NO ejecutar):**

Registrado en `.agents/handoffs/security-manager-NG.md` como TASK-B4 (seguimiento):
- `infra.go:135`: ruleset empieza con `flush ruleset` → borra TODAS las tablas nft, incluida fail2ban `f2b-table`
- Impacto: invalida coexistencia con fail2ban documentada
- Fix propuesto: `delete table inet sm` (si existe) + `table inet sm {...}` — acota wipe a tabla propia
- Estado: ⏳ pendiente — Sonnet planificará tarea aparte tras cerrar TASK-FIX-B1B2

**Próxima tarea:** TASK-012 — Deploy script e install.sh (ya validado por Opus, pendiente ejecución)

---

## TASK-B4 — Reemplazo flush ruleset → add+delete table inet sm

| Campo | Valor |
|-------|-------|
| Fecha | 2026-06-16 |
| Estado | ✅ COMPLETADA |
| Commit | e5509cd |
| Archivos | internal/modules/infra/infra.go |

### Fases

| # | Ítem | Status |
|---|------|--------|
| C-B4.1 | Edición infra.go: `flush ruleset` → `add table inet sm` + `delete table inet sm` | ✅ |
| C-B4.2 | Validación sintaxis `nft -c -f` — `SINTAXIS_OK` | ✅ |
| C-B4.3 | `grep "flush ruleset" internal/` → 0 matches | ✅ |
| C-B4.4 | `go build ./...` + `go vet ./...` — sin errores | ✅ |
| C-B4.5 | Coexistencia tabla dummy `inet test_dummy_b4` — `COEXISTENCIA_OK` | ✅ |
| C-B4.6 | Commit e5509cd + TASK_LOG + vault | ✅ |

**Próxima tarea:** TASK-012 — Deploy script e install.sh

## [TASK-012] Deploy script + install.sh

**Inicio:** 2026-06-16
**Agente:** Claude Code (Haiku 4.5 — ejecución; Sonnet/Opus validación previa)
**Branch:** `dev`

| Fase       | Estado      | Timestamp   | Notas |
|------------|-------------|-------------|-------|
| planificación | ✅ completo | 2026-06-16 | Sonnet diseñó checklist E1–E8; Opus validó → APROBADO CON CORRECCIONES (E5 eliminado, E3 nft=warn, E7 doble readLine) |
| desarrollo | ✅ completo | 2026-06-16  | Haiku ejecutó E1–E8: deploy.sh + install.sh + fail2ban.go fix |
| build      | ✅ completo | 2026-06-16  | `go build ./...` OK; `go vet ./...` OK — sin errores |
| validación | ✅ completo | 2026-06-16  | Haiku verificó E1–E8: scripts OK, flags OK, checks OK, permisos OK, E5 skip OK, cleanup OK, readLine collapsed, constantes removed |
| commit     | ✅ completo | 2026-06-16  | Commit efe8cff en branch dev — push a origin/dev |
| cerrado    | ✅          | 2026-06-16  | Validación Haiku E1–E8 all pass — deploy script + install.sh listo para TASK-013 piloto |

**Archivos creados/modificados:**

| Archivo | Descripción |
|---------|-------------|
| `deploy/deploy.sh` | Script de compilación estático (CGO_ENABLED=0 GOOS=linux GOARCH=amd64 -ldflags=-s -w) + rsync a remote |
| `deploy/install.sh` | Instalador cross-distro: checks EUID/sudo/nft-warn, install -m 750, permisos root:root en /usr/local/sbin |
| `internal/modules/fail2ban/fail2ban.go` | Fix: doble readLine colapso (E7) + eliminar f2bDBPath/ipinfoURLTok |

**Checklist E1–E8 ejecución:**

| # | Ítem | Status | Detalle |
|---|------|--------|---------|
| E1 | Crear `deploy/` con deploy.sh + install.sh | ✅ | Directorio + 2 archivos no vacíos (973B + 2.5K) |
| E2 | Flags build estático verificados | ✅ | CGO_ENABLED=0 GOOS=linux GOARCH=amd64 + ldflags -s -w + BINARY name OK |
| E3 | Checks EUID + sudo + nft-warn | ✅ | Verificación previa (no-root-directo, sudo, nft como advertencia, no abort) |
| E4 | Permisos 750 + chown root:root | ✅ | install -m 750 + chown root:root en /usr/local/sbin/security-manager-ng |
| E5 | Eliminado — binario gestiona /etc/security-manager | ✅ | No hay mkdir ni chmod para /etc/security-manager en install.sh |
| E6 | Mensaje post-instalación + limpieza | ✅ | `sudo security-manager-ng` mensajes + `rm -f ~/security-manager-ng ~/install.sh` |
| E7 | Fix doble readLine + constantes muertas | ✅ | listBanned paginación colapso + eliminar f2bDBPath/ipinfoURLTok |
| E8 | Build/vet + commits + TASK_LOG + vault | ✅ | `go build` OK, `go vet` OK, commit efe8cff, TASK_LOG actualizado, vault pendiente |

**Errores encontrados:** Ninguno. Compilación limpia, sin advertencias.

**Hash de commit:** efe8cff

**Próxima tarea:** TASK-013 — Prueba piloto en host Debian (iDRAC de respaldo)

---

## [TASK-GEOIP-REDESIGN] GeoIP BLOCKLIST → ALLOWLIST

**Inicio:** 2026-06-17
**Agente:** Claude Code (Sonnet planificó + Opus validó; Haiku ejecutó C1–C12; Sonnet auditó)
**Branch:** `dev`

| Fase       | Estado      | Timestamp   | Notas |
|------------|-------------|-------------|-------|
| planificación | ✅ completo | 2026-06-17 | Sonnet diseñó C1–C12 |
| desarrollo | ✅ completo | 2026-06-17  | Haiku ejecutó C1–C12 |
| build      | ✅ completo | 2026-06-17  | `go build ./...` OK |
| auditoría  | ✅ completo | 2026-06-17  | Sonnet detectó bug C19 (orden args Sprintf) → corregido en 13f5f08 |
| commit     | ✅ completo | 2026-06-17  | Commit 7338ad4 (Haiku) + 13f5f08 fix (Sonnet) |
| cerrado    | ✅          | 2026-06-17  | Rediseño ALLOWLIST operativo |

**Archivos modificados:**

| Archivo | Descripción |
|---------|-------------|
| `internal/modules/infra/infra.go` | Constantes AllowedCountriesFile/SetGeoAllow4/6; geoipSetsBlock/geoipRulesBlock con lógica ALLOWLIST; port 80 → stage 7a |
| `internal/modules/geoip/geoip.go` | Textos ALLOWLIST, aviso blocked_countries.conf, confirmación fail-open |

**Checklist C1–C12:**

| # | Ítem | Status |
|---|------|--------|
| C1 | Constantes AllowedCountriesFile + SetGeoAllow4/6 en infra.go | ✅ |
| C2 | geoipSetsBlock() — sets unificados por familia | ✅ |
| C3 | geoipRulesBlock() — lógica invertida (saddr != @set drop) | ✅ |
| C4 | GenerateRuleset() — tcp 80 → stage 7a; stage 8 solo 443 | ✅ |
| C5 | geoip.go — comment + Name() → ALLOWLIST | ✅ |
| C6 | Menu() — aviso si blocked_countries.conf detectado | ✅ |
| C7 | addCountry() — prompt PERMITIR | ✅ |
| C8 | loadCountries()/saveCountries() → AllowedCountriesFile | ✅ |
| C9 | listCountries() — mensaje sin países | ✅ |
| C10 | applyGeoIP() — confirmación interactiva fail-open | ✅ |
| C11 | `go build ./...` sin errores | ✅ |
| C12 | Commit 7338ad4 | ✅ |

**Bug detectado en auditoría Sonnet (post-Haiku):**

Orden de args en `fmt.Sprintf` de `GenerateRuleset()` desalineado: `tailscaleRule`
estaba en posición 12 pero el template lo consume en posición 8 (`iif lo accept%s`).
Resultado: `iif lo acceptsm_blacklist4` + sets stages 5/6 mezclados.
**Fix:** commit 13f5f08 — `tailscaleRule` movido antes de SetBlacklist4/6.

---

## [TASK-VPN-DETECT] Auto-detección VPN en GenerateRuleset

**Inicio:** 2026-06-17
**Agente:** Claude Code (Sonnet planificó; Haiku ejecutó C13–C21; Sonnet auditó + fix)
**Branch:** `dev`

| Fase       | Estado      | Timestamp   | Notas |
|------------|-------------|-------------|-------|
| planificación | ✅ completo | 2026-06-17 | Sonnet diseñó C13–C21 |
| desarrollo | ✅ completo | 2026-06-17  | Haiku ejecutó C13–C21 |
| build      | ✅ completo | 2026-06-17  | `go build ./...` OK |
| auditoría  | ✅ completo | 2026-06-17  | Fix integrado en 13f5f08 (compartido con GEOIP-REDESIGN) |
| commit     | ✅ completo | 2026-06-17  | Commit 9abdce4 (Haiku) |
| cerrado    | ✅          | 2026-06-17  | VPN auto-detect operativo post fix 13f5f08 |

**Archivos modificados:**

| Archivo | Descripción |
|---------|-------------|
| `internal/modules/infra/infra.go` | Structs GlobalServices+OVPNRule; DetectGlobalServices(); globalExceptionsBlock(); integración en GenerateRuleset() stages 2 y 7a |

**Checklist C13–C21:**

| # | Ítem | Status |
|---|------|--------|
| C13 | Structs GlobalServices + OVPNRule | ✅ |
| C14 | import "path/filepath" | ✅ |
| C15 | parseWireGuardPort() | ✅ |
| C16 | matchLine() | ✅ |
| C17 | parseOpenVPNServer() | ✅ |
| C18 | DetectGlobalServices() — WireGuard/OpenVPN/Tailscale cross-distro | ✅ |
| C19 | globalExceptionsBlock() + integración GenerateRuleset() | ✅ (bug orden fix 13f5f08) |
| C20 | `go build ./...` sin errores | ✅ |
| C21 | Commit 9abdce4 | ✅ |

**Hash de commits:** 7338ad4 (GeoIP) · 9abdce4 (VPN) · 13f5f08 (fix orden Sonnet)

**Próxima tarea:** TASK-013 — Prueba piloto en host Debian (iDRAC de respaldo)

---

## [FEAT-PORT80-GLOBAL] port80_global configurable — toggle ACME/Let's Encrypt

| Campo      | Valor |
|------------|-------|
| Fecha      | 2026-06-18 |
| Estado     | ✅ COMPLETADA |
| Commit     | b0eef1b |
| Archivos   | infra.go, firewall.go, ruleset_test.go, geoip.go |

**Contexto:** Feature para habilitar/deshabilitar port 80 global (bypass GeoIP ALLOWLIST)
para validación ACME HTTP-01 de Let's Encrypt. Visible solo en hosts con IP pública.

| Fase | Status | Detalle |
|------|--------|---------|
| diseño | ✅ | Sonnet 4.6 — C1–C11 especificados en handoff |
| desarrollo | ✅ | Haiku 4.5 ejecutó C1–C11 |
| auditoría | ✅ | Sonnet 4.6 auditó contra código real (2026-06-18) |
| commit | ✅ | b0eef1b |

**Checklist C1–C11:**

| # | Ítem | Status |
|---|------|--------|
| C1 | import "net" en infra.go | ✅ |
| C2 | constante OptionsFile | ✅ |
| C3 | privateRanges + isPrivateIP() + HasPublicIP() | ✅ |
| C4 | ReadPort80Option() + WritePort80Option() | ✅ |
| C5 | firma GenerateRuleset(…, port80 bool) | ✅ |
| C6 | globalExceptionsBlock recibe port80 bool | ✅ |
| C7 | applyBase() — prompt si IP pública y opción no configurada | ✅ |
| C8 | Menu() opción [4] condicional + togglePort80() | ✅ |
| C9 | ruleset_test.go — TestGenerateRulesetPort80Disabled() nuevo | ✅ |
| C10 | go build + vet + test — 3 passed | ✅ |
| C11 | commit b0eef1b | ✅ |

**Hallazgo incidental (resuelto):** dos llamadas a GenerateRuleset() en geoip.go
(previewRuleset:206, applyGeoIP:248) no contempladas en el checklist. Haiku las
actualizó para pasar port80. Auditoría Sonnet confirmó corrección contra código real.

**Próxima tarea:** reanudar TASK-013 — piloto en PILOT-HOST-REDACTED (FASE A0 pendiente)

---

## [TASK-FIX-SSH-DETECT] GetSSHIP() fallback bajo sudo

| Campo      | Valor |
|------------|-------|
| Fecha      | 2026-06-18 |
| Estado     | ✅ COMPLETADA |
| Commit     | a816549 |
| Archivos   | internal/sys/sys.go |

**Contexto:** Detectado durante TASK-013 piloto. La whitelist no auto-detecta la IP SSH cuando el operador ejecuta `sudo security-manager-ng` (sudo limpia SSH_CLIENT del entorno).

**Causa raíz:** 
1. `SSH_CLIENT` es eliminada por `sudo` — fallback `w -ih` muestra todos los usuarios (ambiguo multi-sesión)
2. No se intentaba `SSH_CONNECTION` (segunda var estándar SSH)

**Fix:** Reemplazar fallback con `who am i` (identifica la sesión actual, funciona bajo sudo, IP entre paréntesis).

### Checklist G1–G6

| # | Ítem | Status | Detalle |
|---|------|--------|---------|
| G1 | Reemplazar GetSSHIP() completa | ✅ | líneas 11-29 → nueva versión con loop env vars + who am i |
| G2 | Sin referencia a "w" | ✅ | `grep '"w"' internal/sys/sys.go` → 0 resultados |
| G3 | "who am i" presente | ✅ | `exec.Command("who", "am", "i")` en línea 25 |
| G4 | SSH_CONNECTION incluido | ✅ | Loop sobre `[]string{"SSH_CLIENT", "SSH_CONNECTION"}` en línea 15 |
| G5 | go build + go vet limpios | ✅ | BUILD_OK + VET_OK |
| G6 | commit + TASK_LOG + vault | ✅ | Hash a816549; entrada aquí; vault actualizado |

**Próxima tarea:** reanudar TASK-013 — piloto en PILOT-HOST-REDACTED (FASE B pendiente)

---

## [FEAT-GEOIP-UX] GeoIP: agregar países en lote + auto-apply + reset

| Campo      | Valor |
|------------|-------|
| Fecha      | 2026-06-19 |
| Estado     | ✅ COMPLETADA |
| Commits    | 43d6f48 (agregar en lote), f2feb4e (reset) |
| Archivos   | internal/modules/geoip/geoip.go |

**Contexto:** Mejora UX solicitada por Freddy durante piloto TASK-013. El flujo anterior requería 3 pasos manuales separados ([1] agregar → [4] descargar → [5] aplicar) con riesgo de olvidar aplicar.

**Cambios implementados:**

1. **[1] Agregar país** — acepta lista separada por comas (ej: `VE, CO, PE, DO`). Después de guardar los países nuevos, ejecuta automáticamente descarga de rangos + aplicación del ruleset.
2. **[6] Resetear GeoIP** — nueva opción: borra `allowed_countries.conf`, elimina todos los zone files, recarga ruleset sin restricción geográfica. Útil para validar el flujo completo desde cero.

| # | Ítem | Status |
|---|------|--------|
| UX-1 | addCountry acepta lista con comas | ✅ |
| UX-2 | Auto-llama updateRanges + applyGeoIP | ✅ |
| UX-3 | resetGeoIP: borra países + zone files + recarga | ✅ |
| UX-4 | go build + vet + test limpios | ✅ |

**Pendiente:** deploy a PILOT-HOST-REDACTED y validación del flujo completo ([6] reset → [1] agregar VE,CO,PE,DO)

---

## [FEAT-GEOIP-APPLY-CORE] Eliminar confirmaciones redundantes en reset y add

| Campo      | Valor |
|------------|-------|
| Fecha      | 2026-06-19 |
| Estado     | ✅ COMPLETADA |
| Commit     | 05c2411 |
| Archivos   | internal/modules/geoip/geoip.go |

**Contexto:** Durante piloto TASK-013, el operador detectó que `[6] resetGeoIP()` y `[1] addCountry()` disparan confirmaciones redundantes por delegar en `applyGeoIP()` que contiene guardas interactivas diseñadas solo para el flujo manual `[5]`.

**Síntoma:** 
- `[6] reset` → 3 prompts (reset confirm + "sin países?" + "¿whitelisteaste IP?") cuando debería ser 1
- `[1] add país` → 2 prompts automáticas innecesarias tras agregar y descargar

**Fix:** Extraer `applyGeoIPCore()` con solo la lógica de escritura/safeapply (sin confirmaciones). Mantener `applyGeoIP()` con guardas interactivas para el flujo manual `[5]`.

### Checklist H1–H6

| # | Ítem | Status | Detalle |
|---|------|--------|---------|
| H1 | Agregar applyGeoIPCore() completa | ✅ | Función privada con mk/write/nft-validate/backup/apply sin confirmaciones |
| H2 | applyGeoIP() delega en applyGeoIPCore() | ✅ | Solo guardas interactivas, al final llama applyGeoIPCore() |
| H3 | resetGeoIP() → applyGeoIPCore() | ✅ | Cambio de llamada; 1 solo prompt (reset confirm) antes de ejecutar |
| H4 | addCountry() → applyGeoIPCore() | ✅ | Cambio de llamada; 0 prompts de GeoIP (solo aviso "asegúrate whitelist") |
| H5 | go build + go vet + go test limpios | ✅ | BUILD_OK + VET_OK + TEST_OK (3 passed en 12 packages) |
| H6 | commit + TASK_LOG + vault | ✅ | Hash 05c2411; entrada aquí; vault actualizado 2026-06-19 |

**Resultado:** Flujo completamente automático sin confirmaciones redundantes:
- `[6] reset` → 1 prompt (confirmar destructivo) → ejecuta
- `[1] add VE,CO,PE,DO` → 0 prompts GeoIP → descarga + apply automático

**Próxima tarea:** redeploy a PILOT-HOST-REDACTED y validación de FASE B de TASK-013

---

## [TASK-UX-BANNER] Mostrar estado inet sm en banner de arranque

| Campo      | Valor |
|------------|-------|
| Fecha      | 2026-06-19 |
| Estado     | ✅ COMPLETADA |
| Commit     | 975bdb8 |
| Archivos   | main.go |

**Contexto:** Agregar una línea de estado al banner principal (`printMenu`) que muestre en cada ciclo del menú: estado de tabla inet sm, puerto SSH, países GeoIP, contadores de whitelist y blacklist.

**Cambios implementados:**

1. **Struct `sysStatus`** — contiene campos: smActive (bool), sshPort (int), geoCountries ([]string), wlCount (int), blCount (int).
2. **Función `collectStatus()`** — consulta estado actual en tiempo real: nft (tabla inet sm), SSH port (DetectSSHPort), GeoIP (LoadGeoIPData), whitelists (ReadACLEntries v4+v6), blacklists (ReadACLEntries v4+v6).
3. **Modificar `printMenu()`** — llama collectStatus() al inicio y renderiza línea de estado: `inet sm: ✓ activa | SSH: :22 | GeoIP: VE CO PE DO | WL: 3 | BL: 0`.

### Checklist H1–H5

| # | Ítem | Status | Detalle |
|---|------|--------|---------|
| H1 | Agregar struct sysStatus + collectStatus() | ✅ | Struct y función presentes, compilación exitosa |
| H2 | Import `infra` agregado | ✅ | Import incluido entre los internos en línea 17 |
| H3 | printMenu() llama collectStatus() y renderiza status | ✅ | Status line mostrada antes de opciones del menú |
| H4 | go build + go vet + go test limpios | ✅ | BUILD_OK, VET_OK, TEST_OK (3 passed) |
| H5 | commit + TASK_LOG + vault | ✅ | Hash 975bdb8; entrada aquí; vault actualizado 2026-06-19 |

**Output esperado:**
```
  inet sm: ✓ activa  |  SSH: :22  |  GeoIP: VE CO PE DO  |  WL: 3  |  BL: 0
```

O si tabla inactiva:
```
  inet sm: ✗ inactiva  |  SSH: :22  |  GeoIP: —  |  WL: 0  |  BL: 0
```

**Validación:** La línea aparece en cada iteración del menú, con valores actualizados en tiempo real.
