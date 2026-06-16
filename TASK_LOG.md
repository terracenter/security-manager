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

**Inicio:** —
**Agente:** Claude Code (Sonnet 4.6)
**Branch:** `dev`

| Fase       | Estado | Timestamp | Notas |
|------------|--------|-----------|-------|
| desarrollo | ⏳     | —         | Implementar `internal/safeapply/safeapply.go` |
| build      | ⏳     | —         | — |
| validación | ⏳     | —         | Haiku ejecutará checklist funcional |
| commit     | ⏳     | —         | — |
| cerrado    | ⏳     | —         | — |
