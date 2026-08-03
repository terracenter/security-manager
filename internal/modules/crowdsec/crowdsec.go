package crowdsec

import (
	"bufio"
	"fmt"
	"os"
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
// FIX: se usa `cscli allowlists list sm-immune` para chequear (más confiable que parsear
// la lista completa), y se trata el exit code de sudo correctamente.
func ensureAllowlist() error {
	// Chequear si existe pidiendo info específica
	cmd := exec.Command("sudo", "cscli", "allowlists", "inspect", "sm-immune")
	if err := cmd.Run(); err == nil {
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
// FIX: si la IP ya existe en el allowlist, no es error — es idempotente.
func addToAllowlist(ip string) error {
	cmd := exec.Command("sudo", "cscli", "allowlists", "add", "sm-immune", ip)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// cscli retorna exit code != 0 si la IP ya está. Tratar como warning, no error.
		if strings.Contains(string(out), "already") || strings.Contains(string(out), "exists") {
			return nil
		}
		return fmt.Errorf("error con cscli allowlists add: %s: %v", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// RemoveFromAllowlist remueve del allowlist de CrowdSec las IPs que ya NO están
// en los archivos immuneFiles. Útil para evitar acumulación de entradas obsoletas.
// Si crowdsec no está instalado, retorna nil (no-op).
func RemoveFromAllowlist(immuneFiles []string) error {
	if !IsInstalled() {
		return nil
	}

	// 1. Leer IPs actuales de los archivos immune (estado deseado).
	desired := make(map[string]bool)
	for _, file := range immuneFiles {
		ips, err := readIPsFromFile(file)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			desired[strings.TrimSpace(ip)] = true
		}
	}

	// 2. Listar IPs actuales en el allowlist de CrowdSec.
	actual := listAllowlistIPs()

	// 3. Remover las que están en `actual` pero NO en `desired`.
	for ip := range actual {
		if !desired[ip] {
			cmd := exec.Command("sudo", "cscli", "allowlists", "remove", "sm-immune", ip)
			if err := cmd.Run(); err != nil {
				// Log warning, no fatal: si una IP no se puede remover, seguir con las demás.
				fmt.Printf("  [crowdsec] AVISO: no se pudo remover %s del allowlist: %v\n", ip, err)
			}
		}
	}

	return nil
}

// listAllowlistIPs lista las IPs actualmente en el allowlist sm-immune.
// Retorna un set (map[string]bool) para lookup O(1).
func listAllowlistIPs() map[string]bool {
	result := make(map[string]bool)
	cmd := exec.Command("sudo", "cscli", "allowlists", "list", "sm-immune")
	out, err := cmd.Output()
	if err != nil {
		return result
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Formato esperado: una IP/CIDR por línea. Si cscli muestra más columnas,
		// tomar la primera.
		fields := strings.Fields(line)
		if len(fields) > 0 {
			ip := fields[0]
			// Filtrar líneas de header
			if ip != "IP" && !strings.HasPrefix(ip, "#") {
				result[ip] = true
			}
		}
	}
	return result
}

// readIPsFromFile lee un archivo de configuración y retorna las IPs/CIDRs línea por línea.
// FIX: usa os.ReadFile en vez de fork-exec a `cat` (5-10ms menos por llamada).
// FIX: parsea formato ACLEntry pipe-delimited (campo 0 = IP/CIDR).
func readIPsFromFile(filePath string) ([]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var ips []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Formato ACLEntry: "IP | responsable | propósito | fecha | vencimiento"
		// Solo tomamos la primera columna.
		fields := strings.Split(line, "|")
		ip := strings.TrimSpace(fields[0])
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}
