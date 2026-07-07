# Dependencias de terceros

Este proyecto no tiene dependencias de terceros a la fecha de esta versión
(`go list -m all` solo lista el módulo propio, `github.com/terracenter/security-manager-ng`).
Usa exclusivamente la librería estándar de Go.

Las herramientas del sistema operativo invocadas en tiempo de ejecución (`nft`, `fail2ban`,
`sshd`, `systemctl`, `passwd`) son procesos externos ejecutados vía `os/exec` — no se enlazan
ni se distribuyen con este binario. Conservan sus propias licencias:

| Herramienta | Licencia típica |
|-------------|-----------------|
| nftables (`nft`) | GPLv2 |
| fail2ban | GPLv2 |
| OpenSSH (`sshd`) | Licencia BSD-style |
| systemd (`systemctl`) | LGPLv2.1+ |
| shadow-utils (`passwd`) | GPLv2+ / BSD (según distro) |

Si en el futuro se agrega alguna dependencia Go, este archivo debe actualizarse con
`go list -m all` y el detalle de licencia de cada módulo.
