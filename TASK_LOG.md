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
