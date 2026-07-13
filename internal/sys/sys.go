package sys

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// GetSSHIP retorna la IP del cliente SSH activo, o "" si no aplica.
// Funciona incluso bajo sudo (que limpia SSH_CLIENT del entorno).
func GetSSHIP() string {
	// Intentar variables de entorno SSH (pueden estar disponibles si se usa sudo -E).
	for _, env := range []string{"SSH_CLIENT", "SSH_CONNECTION"} {
		if fields := strings.Fields(os.Getenv(env)); len(fields) > 0 {
			if ip := net.ParseIP(fields[0]); ip != nil {
				return ip.String()
			}
		}
	}
	// Fallback: 'who am i' identifica la sesión actual incluso bajo sudo.
	// Lee el TTY de control del proceso desde /var/run/utmp.
	// Formato de salida: "user pts/N date (IP)"
	out, err := exec.Command("who", "am", "i").Output()
	if err != nil {
		return ""
	}
	s := string(out)
	if start := strings.LastIndex(s, "("); start >= 0 {
		if end := strings.LastIndex(s, ")"); end > start {
			candidate := strings.TrimSpace(s[start+1 : end])
			if ip := net.ParseIP(candidate); ip != nil {
				return ip.String()
			}
		}
	}
	return ""
}

// VPNSubnet representa una interfaz VPN y su subred.
type VPNSubnet struct {
	Iface string
	CIDR  string
}

// DetectVPNSubnets detecta wg0 (subred desde routing) y tailscale0 (100.64.0.0/10).
func DetectVPNSubnets() []VPNSubnet {
	var result []VPNSubnet
	ifaces := map[string]string{
		"wg0":        "",
		"tailscale0": "100.64.0.0/10",
	}
	for iface, fixed := range ifaces {
		if err := exec.Command("ip", "link", "show", iface).Run(); err != nil {
			continue
		}
		if fixed != "" {
			result = append(result, VPNSubnet{Iface: iface, CIDR: fixed})
			continue
		}
		out, err := exec.Command("ip", "route", "show", "dev", iface, "scope", "link").Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && strings.Contains(fields[0], "/") {
				result = append(result, VPNSubnet{Iface: iface, CIDR: fields[0]})
				break
			}
		}
	}
	return result
}

// RunCmd ejecuta un comando y retorna true si exitcode == 0.
func RunCmd(name string, args ...string) bool {
	return exec.Command(name, args...).Run() == nil
}

// RunCmdOut ejecuta un comando y retorna su stdout o error.
func RunCmdOut(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return strings.TrimSpace(string(out)), err
}

// CurrentUser retorna SUDO_USER si existe, si no USER, si no "root".
func CurrentUser() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "root"
}

// DetectPkgManager retorna el gestor de paquetes disponible: "apt", "dnf", "yum" o "".
func DetectPkgManager() string {
	for _, pm := range []string{"dnf", "yum", "apt"} {
		if _, err := exec.LookPath(pm); err == nil {
			return pm
		}
	}
	return ""
}

// DistroInfo identifica la distribución Linux activa.
type DistroInfo struct {
	ID      string // "debian", "ubuntu", "almalinux", "rocky", "rhel", "centos", ...
	Family  string // "debian" | "ubuntu" | "rhel" | "unknown"
	Version string // "12", "22.04", "9", etc.
	Name    string // nombre legible del campo NAME en /etc/os-release
}

// DetectDistro lee /etc/os-release y retorna la DistroInfo normalizada.
// ID toma precedencia sobre ID_LIKE para distinguir Ubuntu (ID=ubuntu, ID_LIKE=debian) de Debian puro.
func DetectDistro() DistroInfo {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return DistroInfo{Family: "unknown"}
	}
	var info DistroInfo
	var idLike string
	for _, line := range strings.Split(string(data), "\n") {
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		val = strings.Trim(val, `"`)
		switch key {
		case "ID":
			info.ID = strings.ToLower(val)
		case "VERSION_ID":
			info.Version = val
		case "NAME":
			info.Name = val
		case "ID_LIKE":
			idLike = strings.ToLower(val)
		}
	}
	info.Family = resolveFamily(info.ID)
	if info.Family == "unknown" && idLike != "" {
		info.Family = resolveFamily(idLike)
	}
	return info
}

func resolveFamily(s string) string {
	switch {
	case s == "ubuntu" || strings.Contains(s, "ubuntu"):
		return "ubuntu"
	case s == "debian" || strings.Contains(s, "debian"):
		return "debian"
	case s == "rhel" || s == "almalinux" || s == "rocky" ||
		s == "centos" || s == "fedora" ||
		strings.Contains(s, "rhel") || strings.Contains(s, "fedora"):
		return "rhel"
	default:
		return "unknown"
	}
}

// ConfirmStrong exige que el usuario escriba una palabra exacta para confirmar
// una operación crítica/destructiva. Case-insensitive. Retorna false ante
// cualquier respuesta que no coincida exactamente (fail-safe: no confirmar).
func ConfirmStrong(readLine func(string) string, prompt string, requiredWord string) bool {
	resp := readLine(prompt)
	return strings.EqualFold(strings.TrimSpace(resp), requiredWord)
}

// OfferInstall informa que los paquetes requeridos no están instalados, muestra el
// comando y solicita autorización al usuario vía readLine.
// Retorna true si se instalaron con éxito, false si el usuario rechazó o hubo error.
func OfferInstall(readLine func(string) string, pkgs ...string) bool {
	pm := DetectPkgManager()
	pkgList := strings.Join(pkgs, " ")
	if pm == "" {
		fmt.Printf("  Los paquetes requeridos (%s) no están instalados\n", pkgList)
		fmt.Println("  y no se detectó gestor de paquetes compatible. Instálalos manualmente.")
		return false
	}

	fmt.Printf("\n  Paquetes requeridos : %s\n", pkgList)
	fmt.Printf("  Gestor detectado   : %s\n", pm)
	if pm == "apt" {
		fmt.Printf("  Comando            : apt update && apt install -y %s\n", pkgList)
	} else {
		fmt.Printf("  Comando            : %s install -y %s\n", pm, pkgList)
	}

	resp := readLine("\n  ¿Autorizar instalación? [s/N]: ")
	if strings.ToLower(resp) != "s" {
		fmt.Println("  Instalación cancelada.")
		return false
	}

	installArgs := append([]string{"install", "-y"}, pkgs...)
	var installCmd *exec.Cmd
	if pm == "apt" {
		fmt.Println("\n  Ejecutando apt update...")
		if err := exec.Command("apt", "update").Run(); err != nil {
			fmt.Println("  ERROR en apt update:", err)
			return false
		}
		fmt.Printf("  Ejecutando apt install -y %s...\n", pkgList)
		installCmd = exec.Command("apt", installArgs...)
	} else {
		fmt.Printf("  Ejecutando %s install -y %s...\n", pm, pkgList)
		installCmd = exec.Command(pm, installArgs...)
	}
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	if err := installCmd.Run(); err != nil {
		fmt.Printf("  ERROR instalando %s: %v\n", pkgList, err)
		return false
	}
	fmt.Printf("  Paquetes instalados correctamente: %s\n", pkgList)
	return true
}
