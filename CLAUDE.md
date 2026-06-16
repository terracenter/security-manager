# CLAUDE.md — Security-Manager-NG

> [!IMPORTANT] Hereda del Estándar de Desarrollo global
> Reglas generales (git workflow, código Go idiomático, seguridad, operaciones, validación
> pre-deploy, Linux/FHS, idioma) están en **`/home/freddy/Workspace/Desarrollo/AGENTS.md`**.
> Aquí va solo lo específico de este proyecto.
>
> **Planes e informes → vault** `/home/freddy/Workspace/Obsidian/Planes/`

## Naturaleza del proyecto

Sucesor de `Security-Manager-Go` (backend UFW, congelado). Backend **nftables nativo**.
Binario estático Linux, desplegado en hosts vía rsync. Objetivo cross-distro: Debian 12/13,
Ubuntu 20/22/24/26 LTS, AlmaLinux/Rocky 8/9.

## Reglas específicas de este proyecto

- **Backend único: nftables nativo.** iptables crudo queda **descartado** (es el shim
  `iptables-nft` deprecado). Nunca generar reglas iptables.
- **Tabla única `inet sm`** (v4+v6). Un solo ruleset declarativo `/etc/security-manager/sm.nft`
  cargado atómico con `nft -f`. Validar siempre con `nft -c -f` antes de aplicar.
- **Sets nativos** (`flags interval`) reemplazan ipset. Recarga atómica vía regeneración + `nft -f`
  (no se necesita el patrón swap de ipset).
- `os/exec` para comandos del sistema (`nft`, `ip`, `systemctl`). Sin `panic()` en producción.
- Permisos explícitos al escribir archivos: `0600` datos sensibles, `0644` conf.
- **safe-apply obligatorio** para cambios de firewall: deadman vía `systemd-run --on-active`
  con rollback (`nft -f` del backup). Heredado de SM-Go (`internal/safeapply`).
- Persistencia: `nftables.service`. fail2ban con banaction nftables (tabla `f2b-table`, coexiste).

## Documentación

- Arquitectura del pipeline: `docs/arquitectura-pipeline-nftables.md`
- Diagrama editable: `docs/diagramas/sm-ng-pipeline-nftables.drawio` (PNG y `.dot` junto a él)
