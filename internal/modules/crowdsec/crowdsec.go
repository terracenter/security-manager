package crowdsec

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/terracenter/security-manager-ng/internal/sys"
)

// Crowdsec es el modulo interactivo + CLI que administra la integracion con
// CrowdSec (instalacion, allowlist, status). Logica de negocio sigue viva
// en las funciones de paquete (SyncAllowlist, RemoveFromAllowlist, etc.).
type Crowdsec struct {
	scanner *bufio.Scanner
	logger  *sys.SMLogger
}

// New construye el modulo Crowdsec. Sigue el patron de los otros modulos
// (blacklist/whitelist/etc.): recibe logger, retorna *Crowdsec.
func New(logger *sys.SMLogger) *Crowdsec {
	return &Crowdsec{scanner: bufio.NewScanner(os.Stdin), logger: logger}
}

// Order define la posicion en el menu principal. Posicionado DESPUES de
// los modulos de firewall/conectividad (1-6) y ANTES de los de hardening
// (8-9). Posicion 7 es razonable para "servicios externos".
func (c *Crowdsec) Order() int { return 7 }

// Name es el titulo visible en el menu. NO migra a i18n todavia — eso
// es Subtarea D. Literal hardcoded es aceptable en este punto.
func (c *Crowdsec) Name() string { return "CrowdSec" }

// CscliRunner abstrae la interaccion con la LAPI de CrowdSec via cscli.
// Permite reemplazar la implementacion real (exec.Command sudo+cscli) por
// un fake en memoria, para tests hermeticos sin sudo ni CrowdSec.
//
// Sumario de operaciones:
//   - AllowlistExists: chequea si la allowlist existe en la LAPI.
//   - AllowlistCreate: crea la allowlist con descripcion.
//   - AllowlistAdd: agrega un IP/CIDR. Si ya existe, idempotente (no error).
//   - AllowlistRemove: quita un IP/CIDR.
//   - AllowlistList: retorna set (map[string]bool) de IPs/CIDR actuales.
type CscliRunner interface {
	AllowlistExists(name string) (bool, error)
	AllowlistCreate(name, description string) error
	AllowlistAdd(name, ip string) error
	AllowlistRemove(name, ip string) error
	AllowlistList(name string) (map[string]bool, error)
}

// RealCscliRunner implementa CscliRunner via exec.Command("sudo", "cscli", ...).
// Requiere sudo NOPASSWD para cscli y que CrowdSec este instalado.
type RealCscliRunner struct{}

func (r *RealCscliRunner) AllowlistExists(name string) (bool, error) {
	cmd := exec.Command("sudo", "cscli", "allowlists", "inspect", name)
	return cmd.Run() == nil, nil
}

func (r *RealCscliRunner) AllowlistCreate(name, description string) error {
	cmd := exec.Command("sudo", "cscli", "allowlists", "create", name, "--description", description)
	return cmd.Run()
}

func (r *RealCscliRunner) AllowlistAdd(name, ip string) error {
	cmd := exec.Command("sudo", "cscli", "allowlists", "add", name, ip)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// cscli retorna exit code != 0 si la IP ya esta. Tratar como idempotente.
		if strings.Contains(string(out), "already") || strings.Contains(string(out), "exists") {
			return nil
		}
		return fmt.Errorf("cscli allowlists add: %s: %v", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (r *RealCscliRunner) AllowlistRemove(name, ip string) error {
	cmd := exec.Command("sudo", "cscli", "allowlists", "remove", name, ip)
	return cmd.Run()
}

func (r *RealCscliRunner) AllowlistList(name string) (map[string]bool, error) {
	cmd := exec.Command("sudo", "cscli", "allowlists", "list", name)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	result := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		ip := fields[0]
		if ip != "IP" && !strings.HasPrefix(ip, "#") {
			result[ip] = true
		}
	}
	return result, nil
}

// mockCscliRunner es una implementacion in-memory de CscliRunner para tests.
// NO se usa en produccion. Vive en este archivo para estar cerca de la interface.
type mockCscliRunner struct {
	allowlists map[string]map[string]bool
}

func newMockCscliRunner() *mockCscliRunner {
	return &mockCscliRunner{allowlists: make(map[string]map[string]bool)}
}

func (m *mockCscliRunner) AllowlistExists(name string) (bool, error) {
	_, ok := m.allowlists[name]
	return ok, nil
}

func (m *mockCscliRunner) AllowlistCreate(name, description string) error {
	if _, ok := m.allowlists[name]; !ok {
		m.allowlists[name] = make(map[string]bool)
	}
	return nil
}

func (m *mockCscliRunner) AllowlistAdd(name, ip string) error {
	if _, ok := m.allowlists[name]; !ok {
		m.allowlists[name] = make(map[string]bool)
	}
	m.allowlists[name][ip] = true
	return nil
}

func (m *mockCscliRunner) AllowlistRemove(name, ip string) error {
	if s, ok := m.allowlists[name]; ok {
		delete(s, ip)
	}
	return nil
}

func (m *mockCscliRunner) AllowlistList(name string) (map[string]bool, error) {
	s, ok := m.allowlists[name]
	if !ok {
		return map[string]bool{}, nil
	}
	result := make(map[string]bool, len(s))
	for k, v := range s {
		result[k] = v
	}
	return result, nil
}

// SyncAllowlist sincroniza IPs IMMUNE de SM-NG al allowlist de CrowdSec.
// Usa el RealCscliRunner por defecto. Para tests, usa syncAllowlistWith
// directamente con un mockCscliRunner.
func SyncAllowlist(immuneFiles []string) error {
	return syncAllowlistWith(&RealCscliRunner{}, immuneFiles)
}

// syncAllowlistWith hace el trabajo real usando el CscliRunner inyectado.
func syncAllowlistWith(runner CscliRunner, immuneFiles []string) error {
	if !IsInstalled() {
		return fmt.Errorf("crowdsec no está instalado")
	}

	// Verificar que el allowlist existe, si no, crearlo
	exists, _ := runner.AllowlistExists("sm-immune")
	if !exists {
		if err := runner.AllowlistCreate("sm-immune", "SM-NG Immune Tier IPs"); err != nil {
			return fmt.Errorf("error preparando allowlist CrowdSec: %v", err)
		}
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
		if err := runner.AllowlistAdd("sm-immune", ip); err != nil {
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

// RemoveFromAllowlist remueve del allowlist de CrowdSec las IPs que ya NO están
// en los archivos immuneFiles. Útil para evitar acumulación de entradas obsoletas.
// Si crowdsec no está instalado, retorna nil (no-op).
// Usa el RealCscliRunner por defecto. Para tests, removeFromAllowlistWith.
func RemoveFromAllowlist(immuneFiles []string) error {
	return removeFromAllowlistWith(&RealCscliRunner{}, immuneFiles)
}

// removeFromAllowlistWith hace el trabajo real usando el CscliRunner inyectado.
func removeFromAllowlistWith(runner CscliRunner, immuneFiles []string) error {
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
	actual, err := runner.AllowlistList("sm-immune")
	if err != nil {
		return err
	}

	// 3. Remover las que están en `actual` pero NO en `desired`.
	for ip := range actual {
		if !desired[ip] {
			if err := runner.AllowlistRemove("sm-immune", ip); err != nil {
				// Log warning, no fatal: si una IP no se puede remover, seguir con las demás.
				fmt.Printf("  [crowdsec] AVISO: no se pudo remover %s del allowlist: %v\n", ip, err)
			}
		}
	}

	return nil
}

// listAllowlistIPs lista las IPs actualmente en el allowlist sm-immune.
// Retorna un set (map[string]bool) para lookup O(1).
// Wrapper que usa RealCscliRunner. Errores se ignoran (retorna set vacio).
func listAllowlistIPs() map[string]bool {
	result, _ := (&RealCscliRunner{}).AllowlistList("sm-immune")
	if result == nil {
		result = make(map[string]bool)
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
