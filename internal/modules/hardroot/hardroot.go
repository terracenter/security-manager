package hardroot

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/terracenter/security-manager-ng/internal/sys"
)

const (
	sshdConfig     = "/etc/ssh/sshd_config"
	sudoersDir     = "/etc/sudoers.d"
	sudoersFile    = sudoersDir + "/sm-ng"
	sudoersContent = `# Security-Manager-NG — hardening sudoers
# Generado por sm-ng — no editar manualmente
Defaults timestamp_timeout=5
Defaults requiretty
Defaults logfile="/var/log/sudo.log"
`
)

// HardRoot gestiona el hardening de la cuenta root y sudoers.
type HardRoot struct {
	scanner *bufio.Scanner
	logger  *sys.SMLogger
}

func New(logger *sys.SMLogger) *HardRoot {
	return &HardRoot{scanner: bufio.NewScanner(os.Stdin), logger: logger}
}

func (h *HardRoot) Order() int   { return 5 }
func (h *HardRoot) Name() string { return "HardRoot — hardening root + sudoers" }
func (h *HardRoot) Reset()       {}

func (h *HardRoot) Menu() {
	for {
		fmt.Println("\n  ┌─ HardRoot — Hardening root ────────────┐")
		fmt.Println("  │  [1] Ver estado actual                  │")
		fmt.Println("  │  [2] Endurecer SSH root (sshd_config)   │")
		fmt.Println("  │  [3] Bloquear cuenta root (passwd)      │")
		fmt.Println("  │  [4] Configurar sudoers (/sudoers.d)    │")
		fmt.Println("  │  [0] Volver                             │")
		fmt.Println("  └────────────────────────────────────────┘")
		fmt.Print("  Selección: ")

		if !h.scanner.Scan() {
			return
		}
		switch strings.TrimSpace(h.scanner.Text()) {
		case "1":
			h.showStatus()
		case "2":
			h.hardenSSH()
		case "3":
			h.lockRoot()
		case "4":
			h.configureSudoers()
		case "0":
			return
		default:
			fmt.Println("  Opción inválida.")
		}
	}
}

func (h *HardRoot) showStatus() {
	fmt.Println()
	fmt.Printf("  [SSH] PermitRootLogin      : %s\n", orUnset(sshdOption("PermitRootLogin")))
	fmt.Printf("  [SSH] PermitEmptyPasswords : %s\n", orUnset(sshdOption("PermitEmptyPasswords")))

	out, err := exec.Command("passwd", "-S", "root").Output()
	if err != nil {
		fmt.Println("  [ROOT] Estado passwd       : ERROR al consultar")
	} else {
		fields := strings.Fields(string(out))
		status := "desconocido"
		if len(fields) >= 2 {
			switch fields[1] {
			case "L":
				status = "BLOQUEADA ✓"
			case "P":
				status = "con contraseña (activa)"
			case "NP":
				status = "SIN contraseña ⚠"
			}
		}
		fmt.Printf("  [ROOT] Passwd root         : %s\n", status)
	}

	if _, err := os.Stat(sudoersFile); os.IsNotExist(err) {
		fmt.Printf("  [SUDO] %s : no existe\n", sudoersFile)
	} else {
		fmt.Printf("  [SUDO] %s : presente ✓\n", sudoersFile)
	}
}

func (h *HardRoot) hardenSSH() {
	fmt.Println("\n  Configurará en sshd_config:")
	fmt.Println("    PermitRootLogin no")
	fmt.Println("    PermitEmptyPasswords no")
	if users := sudoCapableUsers(); len(users) == 0 {
		fmt.Println("\n  ⚠  ADVERTENCIA: no se detectó ningún usuario sudo/wheel distinto de root.")
		fmt.Println("     Con PermitRootLogin no podrías perder el acceso SSH a este host.")
	} else {
		fmt.Printf("\n  Usuarios sudo/wheel con acceso alterno: %s\n", strings.Join(users, ", "))
	}
	fmt.Print("  ¿Confirmar? [s/N]: ")
	if !h.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(h.scanner.Text())) != "s" {
		fmt.Println("  Cancelado.")
		return
	}

	if err := setSshdOption("PermitRootLogin", "no"); err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return
	}
	if err := setSshdOption("PermitEmptyPasswords", "no"); err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return
	}
	fmt.Println("  sshd_config actualizado.")

	// Validar sintaxis antes de recargar — evita recargar con una config rota.
	if out, err := exec.Command("sshd", "-t").CombinedOutput(); err != nil {
		fmt.Printf("  ERROR: sshd -t falló tras los cambios:\n%s\n", strings.TrimSpace(string(out)))
		fmt.Println("  Revisa /etc/ssh/sshd_config manualmente. No se recargó sshd.")
		return
	}

	if err := reloadSSHD(); err != nil {
		fmt.Printf("  ADVERTENCIA: no se pudo recargar sshd: %v\n", err)
		fmt.Println("  Ejecuta manualmente: systemctl reload ssh")
	} else {
		fmt.Println("  sshd recargado correctamente.")
	}
}

func (h *HardRoot) lockRoot() {
	out, err := exec.Command("passwd", "-S", "root").Output()
	if err == nil {
		if fields := strings.Fields(string(out)); len(fields) >= 2 && fields[1] == "L" {
			fmt.Println("\n  La cuenta root ya está bloqueada. Sin cambios.")
			return
		}
	}

	if users := sudoCapableUsers(); len(users) == 0 {
		fmt.Println("\n  ⚠  ADVERTENCIA: sin usuario sudo/wheel alterno — bloquear root puede dejarte sin escalada de privilegios.")
	}

	fmt.Print("\n  ¿Bloquear la cuenta root (passwd -l root)? [s/N]: ")
	if !h.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(h.scanner.Text())) != "s" {
		fmt.Println("  Cancelado.")
		return
	}

	out2, err2 := exec.Command("passwd", "-l", "root").CombinedOutput()
	if err2 != nil {
		fmt.Printf("  ERROR: %s\n", strings.TrimSpace(string(out2)))
		return
	}
	fmt.Println("  Cuenta root bloqueada correctamente.")
}

func (h *HardRoot) configureSudoers() {
	prompt := "¿Crear"
	if _, err := os.Stat(sudoersFile); err == nil {
		fmt.Printf("\n  %s ya existe.\n", sudoersFile)
		prompt = "¿Sobreescribir"
	} else {
		fmt.Printf("\n  Creará %s con:\n", sudoersFile)
		fmt.Println("    Defaults timestamp_timeout=5")
		fmt.Println("    Defaults requiretty")
		fmt.Println("    Defaults logfile=\"/var/log/sudo.log\"")
	}
	fmt.Printf("  %s %s? [s/N]: ", prompt, sudoersFile)
	if !h.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(h.scanner.Text())) != "s" {
		fmt.Println("  Cancelado.")
		return
	}

	tmpFile := "/tmp/sm-ng-sudoers"
	if err := os.WriteFile(tmpFile, []byte(sudoersContent), 0o640); err != nil {
		fmt.Printf("  ERROR escribiendo archivo temporal: %v\n", err)
		return
	}
	defer os.Remove(tmpFile)

	out, err := exec.Command("visudo", "-c", "-f", tmpFile).CombinedOutput()
	if err != nil {
		fmt.Printf("  ERROR validación visudo: %s\n", strings.TrimSpace(string(out)))
		return
	}

	if err := os.MkdirAll(sudoersDir, 0o750); err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return
	}
	if err := os.WriteFile(sudoersFile, []byte(sudoersContent), 0o440); err != nil {
		fmt.Printf("  ERROR escribiendo %s: %v\n", sudoersFile, err)
		return
	}
	fmt.Printf("  %s configurado correctamente.\n", sudoersFile)
}

// sshdOption retorna el valor activo (sin comentarios) de una directiva en sshd_config.
func sshdOption(key string) string {
	data, err := os.ReadFile(sshdConfig)
	if err != nil {
		return ""
	}
	lower := strings.ToLower(key)
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if lline := strings.ToLower(trimmed); strings.HasPrefix(lline, lower+" ") || strings.HasPrefix(lline, lower+"\t") {
			if parts := strings.Fields(trimmed); len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}

// setSshdOption establece key=value en sshd_config de forma idempotente.
// Prioriza la directiva activa; si no existe, descomenta la primera comentada; si no, agrega al final.
func setSshdOption(key, value string) error {
	data, err := os.ReadFile(sshdConfig)
	if err != nil {
		return fmt.Errorf("leer %s: %w", sshdConfig, err)
	}
	lines := strings.Split(string(data), "\n")
	lower := strings.ToLower(key)
	target := key + " " + value

	// Buscar directiva activa
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if lline := strings.ToLower(trimmed); strings.HasPrefix(lline, lower+" ") || strings.HasPrefix(lline, lower+"\t") {
			if trimmed == target {
				return nil // ya está correctamente configurado
			}
			lines[i] = target
			return os.WriteFile(sshdConfig, []byte(strings.Join(lines, "\n")), 0o644)
		}
	}

	// Buscar primera directiva comentada y descomentarla
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "#") {
			continue
		}
		effective := strings.TrimSpace(trimmed[1:])
		if lline := strings.ToLower(effective); strings.HasPrefix(lline, lower+" ") || strings.HasPrefix(lline, lower+"\t") {
			lines[i] = target
			return os.WriteFile(sshdConfig, []byte(strings.Join(lines, "\n")), 0o644)
		}
	}

	// No encontrado: agregar al final
	lines = append(lines, target)
	return os.WriteFile(sshdConfig, []byte(strings.Join(lines, "\n")), 0o644)
}

// reloadSSHD recarga el servicio SSH — intenta 'ssh' (Debian/Ubuntu) y luego 'sshd' (RHEL).
func reloadSSHD() error {
	for _, svc := range []string{"ssh", "sshd"} {
		out, err := exec.Command("systemctl", "reload", svc).CombinedOutput()
		if err == nil {
			return nil
		}
		if strings.Contains(string(out), "not found") || strings.Contains(string(out), "no such") {
			continue
		}
		return fmt.Errorf("systemctl reload %s: %s", svc, strings.TrimSpace(string(out)))
	}
	return fmt.Errorf("no se encontró servicio ssh ni sshd")
}

// sudoCapableUsers retorna los usuarios (distintos de root) en los grupos sudo/wheel.
// Se usa como preflight antes de PermitRootLogin no / lockRoot para advertir de lockout.
func sudoCapableUsers() []string {
	out, err := exec.Command("getent", "group", "sudo", "wheel").Output()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var users []string
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 4 || parts[3] == "" {
			continue
		}
		for _, u := range strings.Split(parts[3], ",") {
			u = strings.TrimSpace(u)
			if u != "" && u != "root" && !seen[u] {
				seen[u] = true
				users = append(users, u)
			}
		}
	}
	return users
}

func orUnset(s string) string {
	if s == "" {
		return "(no configurado)"
	}
	return s
}

// RunAction implementa modules.CLIModule para modo no interactivo.
//
//	estado        Ver estado actual
//	harden-ssh    Establecer PermitRootLogin no + PermitEmptyPasswords no
//	lock-root     Bloquear cuenta root (passwd -l root)
//	sudoers       Crear /etc/sudoers.d/sm-ng
func (h *HardRoot) RunAction(action string, args ...string) bool {
	switch strings.ToLower(action) {
	case "estado", "status":
		h.showStatus()
		return true
	case "harden-ssh", "hardenssh":
		users := sudoCapableUsers()
		if len(users) == 0 {
			fmt.Println("  ⚠  ADVERTENCIA: sin usuario sudo/wheel alterno. Verifica antes de continuar.")
		} else {
			fmt.Printf("  Usuarios sudo/wheel alternativos: %s\n", strings.Join(users, ", "))
		}
		fmt.Println("  [cli] Aplicando PermitRootLogin no + PermitEmptyPasswords no...")
		if err := setSshdOption("PermitRootLogin", "no"); err != nil {
			fmt.Printf("  ERROR: %v\n", err)
			return false
		}
		if err := setSshdOption("PermitEmptyPasswords", "no"); err != nil {
			fmt.Printf("  ERROR: %v\n", err)
			return false
		}
		if out, err := exec.Command("sshd", "-t").CombinedOutput(); err != nil {
			fmt.Printf("  ERROR: sshd -t falló:\n%s\n", strings.TrimSpace(string(out)))
			return false
		}
		if err := reloadSSHD(); err != nil {
			fmt.Printf("  ADVERTENCIA: %v\n", err)
		} else {
			fmt.Println("  sshd recargado correctamente.")
		}
		return true
	case "lock-root", "lockroot":
		out, err := exec.Command("passwd", "-S", "root").Output()
		if err == nil {
			if fields := strings.Fields(string(out)); len(fields) >= 2 && fields[1] == "L" {
				fmt.Println("  La cuenta root ya está bloqueada. Sin cambios.")
				return true
			}
		}
		fmt.Println("  [cli] Bloqueando cuenta root...")
		out2, err2 := exec.Command("passwd", "-l", "root").CombinedOutput()
		if err2 != nil {
			fmt.Fprintf(os.Stderr, "  ERROR: %s\n", strings.TrimSpace(string(out2)))
			return false
		}
		fmt.Println("  Cuenta root bloqueada correctamente.")
		return true
	case "sudoers":
		fmt.Println("  [cli] Configurando sudoers...")
		tmpFile := "/tmp/sm-ng-sudoers"
		if err := os.WriteFile(tmpFile, []byte(sudoersContent), 0o640); err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR: %v\n", err)
			return false
		}
		defer os.Remove(tmpFile)
		if out, err := exec.Command("visudo", "-c", "-f", tmpFile).CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR validación visudo: %s\n", strings.TrimSpace(string(out)))
			return false
		}
		if err := os.MkdirAll(sudoersDir, 0o750); err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR: %v\n", err)
			return false
		}
		if err := os.WriteFile(sudoersFile, []byte(sudoersContent), 0o440); err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR escribiendo %s: %v\n", sudoersFile, err)
			return false
		}
		fmt.Printf("  %s configurado correctamente.\n", sudoersFile)
		return true
	default:
		fmt.Fprintf(os.Stderr, "  Acción '%s' no reconocida.\n", action)
		fmt.Fprintln(os.Stderr, "  Acciones: estado, harden-ssh, lock-root, sudoers")
		return false
	}
}

// _ ensures the interface is satisfied at compile time.
var _ interface {
	Order() int
	Name() string
	Menu()
	Reset()
} = (*HardRoot)(nil)
