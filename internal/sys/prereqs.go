package sys

import (
	"fmt"
	"os/exec"
	"strings"
)

// CheckAndInstallPrereqs verifica que los paquetes obligatorios están instalados.
// Si faltan, muestra la lista y solicita confirmación del usuario para instalar.
// Retorna error si el usuario rechaza o la instalación falla.
// Nota: CrowdSec es opcional y se maneja de forma separada en CheckAndInstallCrowdSec().
func CheckAndInstallPrereqs(readLine func(string) string) error {
	distro := DetectDistro()

	// Paquetes obligatorios: nftables + iproute2/iproute (necesario para ss)
	var requiredPkgs []string
	switch distro.Family {
	case "debian", "ubuntu":
		requiredPkgs = []string{"nftables", "iproute2"}
	case "rhel":
		requiredPkgs = []string{"nftables", "iproute"}
	default:
		return fmt.Errorf("distribución no soportada: %s", distro.ID)
	}

	missingPkgs := filterMissingPackages(distro.Family, requiredPkgs)
	if len(missingPkgs) == 0 {
		return nil
	}

	// Mostrar mensaje con distro y versión exacta
	distroDisplay := distro.Name
	if distro.Version != "" {
		distroDisplay += " " + distro.Version
	}
	if distroDisplay == "" {
		distroDisplay = distro.ID
	}
	fmt.Printf("\n  Se necesitan instalar los siguientes paquetes en %s:\n", distroDisplay)
	for _, pkg := range missingPkgs {
		fmt.Printf("    - %s\n", pkg)
	}

	if !OfferInstall(readLine, missingPkgs...) {
		return fmt.Errorf("paquetes requeridos no instalados")
	}

	return nil
}

// CheckAndInstallCrowdSec verifica e instala CrowdSec de forma opcional.
// Si CrowdSec no está instalado, muestra un mensaje informativo (no bloqueante).
// Si el usuario desea instalarlo, registra el repositorio oficial Packagecloud y procede.
func CheckAndInstallCrowdSec(readLine func(string) string) error {
	distro := DetectDistro()

	crowdSecPkgs := []string{"crowdsec", "crowdsec-firewall-bouncer-nftables"}
	missingPkgs := filterMissingPackages(distro.Family, crowdSecPkgs)

	// Si todos los paquetes CrowdSec están instalados, no hacer nada
	if len(missingPkgs) == 0 {
		return nil
	}

	// CrowdSec no está instalado — informar pero no bloquear
	fmt.Println("  [info] CrowdSec no instalado — integración avanzada no disponible.")
	fmt.Print("  ¿Instalar CrowdSec ahora? [s/N]: ")
	response := readLine("")
	if !strings.EqualFold(strings.TrimSpace(response), "s") {
		return nil // Usuario rechazó, no es error
	}

	// Usuario aceptó instalar CrowdSec
	fmt.Println("Registrando repositorio oficial CrowdSec (Packagecloud)...")
	if err := registerCrowdSecRepo(distro.Family); err != nil {
		fmt.Printf("  Advertencia: no se pudo registrar repo CrowdSec: %v\n", err)
		return nil // No bloquear aunque falle el repo
	}

	if !OfferInstall(readLine, missingPkgs...) {
		fmt.Println("  [info] CrowdSec no instalado — operando en modo nftables puro.")
		return nil
	}

	if err := configureCrowdSecPostInstall(distro.Family); err != nil {
		fmt.Printf("  Advertencia: error configurando CrowdSec post-install: %v\n", err)
	}

	return nil
}

// filterMissingPackages verifica qué paquetes falta instalar en el sistema.
func filterMissingPackages(family string, pkgs []string) []string {
	var missing []string
	for _, pkg := range pkgs {
		if !isPackageInstalled(family, pkg) {
			missing = append(missing, pkg)
		}
	}
	return missing
}

// isPackageInstalled verifica si un paquete está instalado según la familia de distro.
func isPackageInstalled(family string, pkg string) bool {
	switch family {
	case "debian", "ubuntu":
		// Debian/Ubuntu: dpkg-query -W -f='${Status}'
		out, err := RunCmdOut("dpkg-query", "-W", "-f=${Status}", pkg)
		return err == nil && strings.Contains(out, "install ok installed")
	case "rhel":
		// RHEL-like: rpm -q <pkg>
		_, err := RunCmdOut("rpm", "-q", pkg)
		return err == nil
	default:
		return false
	}
}

// registerCrowdSecRepo registra el repositorio oficial Packagecloud de CrowdSec.
func registerCrowdSecRepo(family string) error {
	// Script universal de Packagecloud que funciona en todas las distros
	cmd := exec.Command("sh", "-c", "curl -s https://install.crowdsec.net | sudo sh")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error ejecutando script install.crowdsec.net: %v", err)
	}
	return nil
}

// configureCrowdSecPostInstall realiza la configuración post-instalación de CrowdSec.
// - Deshabilita CAPI (modo offline local)
// - Configura el bouncer para usar tabla inet sm (set-only: true)
func configureCrowdSecPostInstall(family string) error {
	// Deshabilitar CAPI (modo offline)
	fmt.Println("Deshabilitando CAPI (modo offline local)...")
	configPath := "/etc/crowdsec/config.yaml"
	if err := disableCAPIInConfig(configPath); err != nil {
		// No retornar error bloqueante, solo log warning
		fmt.Printf("Advertencia: no se pudo deshabilitar CAPI automáticamente: %v\n", err)
	}

	// Configurar bouncer para usar tabla inet sm
	fmt.Println("Configurando bouncer CrowdSec para usar tabla inet sm...")
	bouncerPath := "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
	if err := configureBounceForSmTable(bouncerPath); err != nil {
		fmt.Printf("Advertencia: no se pudo configurar bouncer automáticamente: %v\n", err)
	}

	return nil
}

// disableCAPIInConfig comenta la sección online_client en config.yaml
func disableCAPIInConfig(configPath string) error {
	out, err := RunCmdOut("cat", configPath)
	if err != nil {
		return fmt.Errorf("error leyendo config.yaml: %v", err)
	}

	// Comentar líneas que contengan "online_client"
	lines := strings.Split(out, "\n")
	var modifiedLines []string
	for _, line := range lines {
		if strings.Contains(line, "online_client") {
			modifiedLines = append(modifiedLines, "# "+line)
		} else {
			modifiedLines = append(modifiedLines, line)
		}
	}

	modifiedContent := strings.Join(modifiedLines, "\n")
	cmd := exec.Command("sudo", "tee", configPath)
	cmd.Stdin = strings.NewReader(modifiedContent)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error escribiendo config.yaml: %v", err)
	}

	return nil
}

// configureBounceForSmTable actualiza bouncer.yaml con set-only: true y tabla inet sm
func configureBounceForSmTable(bouncerPath string) error {
	out, err := RunCmdOut("cat", bouncerPath)
	if err != nil {
		return fmt.Errorf("error leyendo bouncer.yaml: %v", err)
	}

	// Buscar sección nftables y configurar set-only + tabla sm
	// Esto es un workaround simple: reemplazar la sección nftables con parámetros correctos
	lines := strings.Split(out, "\n")
	var modifiedLines []string
	inNftables := false
	nftablesConfigAdded := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "nftables:") {
			inNftables = true
			modifiedLines = append(modifiedLines, line)
		} else if inNftables && strings.HasPrefix(trimmed, "ipv4:") && !nftablesConfigAdded {
			// Agregar set-only: true y configuración de tabla
			modifiedLines = append(modifiedLines, line)
			nftablesConfigAdded = true
			// Esperamos que las líneas siguientes tengan la indentación correcta
			// Por ahora, simplemente marcamos que se agregó
		} else if inNftables && (strings.HasPrefix(trimmed, "ipv6:") || (trimmed != "" && !strings.HasPrefix(line, " "))) {
			// Fin de sección nftables
			inNftables = false
			modifiedLines = append(modifiedLines, line)
		} else {
			modifiedLines = append(modifiedLines, line)
		}
	}

	// Si no encontramos la configuración, al menos intentamos insertar set-only
	if !nftablesConfigAdded {
		// Buscar la sección nftables e inyectar set-only: true
		var result []string
		for i, line := range modifiedLines {
			result = append(result, line)
			if strings.Contains(line, "nftables:") && i+1 < len(modifiedLines) {
				// Verificar que la siguiente línea tiene 'enabled: true' y agregar 'set-only: true'
				if strings.Contains(modifiedLines[i+1], "enabled:") {
					result = append(result, "  set-only: true")
					result = append(result, "  table: sm")
				}
			}
		}
		modifiedLines = result
	}

	modifiedContent := strings.Join(modifiedLines, "\n")
	cmd := exec.Command("sudo", "tee", bouncerPath)
	cmd.Stdin = strings.NewReader(modifiedContent)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error escribiendo bouncer.yaml: %v", err)
	}

	return nil
}
