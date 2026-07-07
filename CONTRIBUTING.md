# Contribuir a Security-Manager-NG

## Flujo de branches

- Todo el desarrollo ocurre en `dev`. **Nunca** hagas PR directo contra `main`.
- `main` solo recibe merges de `dev` tras aprobación explícita del mantenedor (Freddy Taborda).
- Abre tu rama de trabajo a partir de `dev` (`feature/<nombre>` o `fix/<nombre>`), y tu PR debe
  apuntar de vuelta a `dev`.

## Convenciones de código

Mismas que documenta el README (sección "Convenciones de desarrollo"):

- Cada módulo implementa la interface `modules.Module` (`Order`, `Name`, `Menu`, `Reset`).
- `os/exec` para todos los comandos del sistema (`nft`, `ip`, `systemctl`) — nunca librerías cgo
  que aten el binario a una distro específica.
- Sin `panic()` en paths de producción — retornar error o imprimir y continuar.
- Permisos explícitos al escribir archivos: `0600` datos sensibles, `0644` conf.
- Backend nftables nativo únicamente — nunca reglas `iptables` crudas.

## Antes de abrir un PR

- `go build ./...` y `go vet ./...` deben pasar limpios.
- Si tocas el pipeline de firewall (`internal/modules/firewall/`), valida con
  `sudo nft -c -f /etc/security-manager/sm.nft` en un host de prueba.
- Actualiza `TASK_LOG.md` con una entrada nueva describiendo el cambio.

## Reportar bugs de seguridad

No los reportes como issue público — ver [`SECURITY.md`](SECURITY.md).
