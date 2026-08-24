# Changelog

Formato basado en [Keep a Changelog 1.1.0](https://keepachangelog.com/es-ES/1.1.0/),
versionado según [Semantic Versioning](https://semver.org/lang/es/).

## [Unreleased]

### Fixed
- `internal/i18n`: los catálogos de traducción (`strings_es.json`, `strings_en.json`) se
  embeben en el binario con `go:embed` en vez de leerse del disco por ruta relativa. Antes,
  el binario solo traducía si se ejecutaba desde la raíz del repo o `internal/i18n/`; desde
  cualquier otro directorio de trabajo mostraba las claves de traducción sin resolver.
- `main.go`: `RepoURL` apuntaba a `github.com/terracenter/security-manager-ng` (404). Corregido
  a `github.com/terracenter/security-manager`, el repo real.

### Removed
- `deploy/deploy.sh`: eliminado. Exigía un `deploy/install.sh` que nunca llegó a `main` y
  abortaba siempre. La vía de instalación vigente es
  `curl -fsSL https://raw.githubusercontent.com/terracenter/security-manager/dev/script-dev/install.sh | bash`.

### Docs
- `README.md` / `README_en.md`: eliminadas las referencias a `deploy/install.sh` (inexistente)
  y la afirmación de que toda Release se firma con GPG (falsa hoy — la única Release publicada
  no tiene `.asc`). Se documenta explícitamente que la rama `main` aún no tiene Release estable
  ni instalador firmado, conservando el fingerprint de la llave y sus dos fuentes de descarga.
- `.github/workflows/dev-release.yml` / `script-dev/install.sh`: quitadas las menciones al
  instalador estable de `main` que no existe.
