# Política de seguridad

## Alcance

Esta política cubre únicamente el binario **Security-Manager-NG** (código en este repositorio).
No cubre vulnerabilidades en las herramientas del sistema que invoca (`nftables`, `fail2ban`,
`OpenSSH`, `systemd`) — repórtalas directamente a sus proyectos respectivos.

## Cómo reportar una vulnerabilidad

Envía un correo a **terracenter@gmail.com** con el asunto `[SECURITY] Security-Manager-NG`,
describiendo:

- Versión afectada (`security-manager-ng --version` o el tag/commit).
- Distro y versión donde se reprodujo.
- Pasos para reproducir, y el impacto esperado (ej. escalada de privilegios, bypass de firewall).

**No abras un issue público** para vulnerabilidades sin reportar primero por este canal.

## Tiempos de respuesta esperados

- Confirmación de recepción: dentro de 5 días hábiles.
- Diagnóstico inicial: dentro de 15 días hábiles.
- El tiempo de fix depende de la severidad — se coordina directamente con quien reporta.

## Versiones soportadas

Solo la última tag publicada en `main`/Releases recibe parches de seguridad. No se mantienen
versiones anteriores.
