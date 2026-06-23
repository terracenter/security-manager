package crowdsec

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
)

// SyncAllowlist sincroniza IPs IMMUNE de SM-NG al allowlist de CrowdSec.
// Lee los archivos de IPs immune y llama a cscli allowlists add por cada IP/CIDR.
func SyncAllowlist(immuneFiles []string) error {
	if !IsInstalled() {
		return fmt.Errorf("crowdsec no está instalado")
	}

	// Verificar que el allowlist existe, si no, crearlo
	if err := ensureAllowlist(); err != nil {
		return fmt.Errorf("error preparando allowlist CrowdSec: %v", err)
	}

	// Leer todos los archivos immune y agregar IPs/CIDRs
	var allIPs []string
	for _, file := range immuneFiles {
		ips, err := readIPsFromFile(file)
		if err != nil {
			// Continuar si el archivo no existe (puede no estar configurado aún)
			continue
		}
		allIPs = append(allIPs, ips...)
	}

	// Agregar cada IP al allowlist de CrowdSec
	for _, ip := range allIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" || strings.HasPrefix(ip, "#") {
			continue
		}
		if err := addToAllowlist(ip); err != nil {
			return fmt.Errorf("error agregando %s al allowlist: %v", ip, err)
		}
	}

	return nil
}

// IsInstalled verifica si el agent de CrowdSec está instalado.
func IsInstalled() bool {
	cmd := exec.Command("which", "crowdsec")
	err := cmd.Run()
	return err == nil
}

// IsBouncerInstalled verifica si crowdsec-firewall-bouncer-nftables está instalado.
func IsBouncerInstalled() bool {
	cmd := exec.Command("which", "crowdsec-firewall-bouncer-nftables")
	err := cmd.Run()
	return err == nil
}

// Status retorna el estado del servicio crowdsec (systemctl is-active crowdsec).
func Status() (string, error) {
	cmd := exec.Command("systemctl", "is-active", "crowdsec")
	out, err := cmd.CombinedOutput()
	status := strings.TrimSpace(string(out))
	if err != nil {
		return status, fmt.Errorf("error obteniendo status crowdsec: %v", err)
	}
	return status, nil
}

// ensureAllowlist crea el allowlist sm-immune si no existe.
func ensureAllowlist() error {
	// Verificar si el allowlist ya existe
	cmd := exec.Command("sudo", "cscli", "allowlists", "list")
	out, err := cmd.CombinedOutput()
	if err == nil && strings.Contains(string(out), "sm-immune") {
		return nil // Ya existe
	}

	// Crear el allowlist
	cmd = exec.Command("sudo", "cscli", "allowlists", "create", "sm-immune", "--description", "SM-NG Immune Tier IPs")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error creando allowlist sm-immune: %v", err)
	}

	return nil
}

// addToAllowlist agrega una IP/CIDR al allowlist sm-immune.
func addToAllowlist(ip string) error {
	cmd := exec.Command("sudo", "cscli", "allowlists", "add", "sm-immune", ip)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error con cscli allowlists add: %v", err)
	}
	return nil
}

// readIPsFromFile lee un archivo de configuración y retorna las IPs/CIDRs línea por línea.
func readIPsFromFile(filePath string) ([]string, error) {
	cmd := exec.Command("cat", filePath)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error leyendo archivo %s: %v", filePath, err)
	}

	var ips []string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			ips = append(ips, line)
		}
	}

	return ips, nil
}
