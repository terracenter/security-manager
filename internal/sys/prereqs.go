package sys

import (
	"fmt"
	"strings"
)

// CheckAndInstallPrereqs verifica que los paquetes requeridos están instalados.
// Si faltan, muestra la lista y solicita confirmación del usuario para instalar.
// Retorna error si el usuario rechaza o la instalación falla.
func CheckAndInstallPrereqs(readLine func(string) string) error {
	distro := DetectDistro()

	var requiredPkgs []string
	switch distro.Family {
	case "debian", "ubuntu":
		requiredPkgs = []string{"nftables"}
	case "rhel":
		requiredPkgs = []string{"nftables"}
	default:
		return fmt.Errorf("distribución no soportada: %s", distro.ID)
	}

	missingPkgs := filterMissingPackages(distro.Family, requiredPkgs)
	if len(missingPkgs) == 0 {
		return nil
	}

	if !OfferInstall(readLine, missingPkgs...) {
		return fmt.Errorf("paquetes requeridos no instalados")
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
		// Debian/Ubuntu: dpkg -l <pkg> | grep ^ii
		out, err := RunCmdOut("dpkg", "-l", pkg)
		if err != nil {
			return false
		}
		return strings.HasPrefix(out, "ii")
	case "rhel":
		// RHEL-like: rpm -q <pkg>
		_, err := RunCmdOut("rpm", "-q", pkg)
		return err == nil
	default:
		return false
	}
}
