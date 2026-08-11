package hardroot

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/terracenter/security-manager-ng/internal/i18n"
	"github.com/terracenter/security-manager-ng/internal/sys"
)

const (
	sshdConfig       = "/etc/ssh/sshd_config"
	sshdConfigBackup = "/etc/security-manager/hardroot_sshd_config.bak"
	sudoersDir       = "/etc/sudoers.d"
	sudoersFile      = sudoersDir + "/sm-ng"
	sudoersContent   = `# Security-Manager-NG — hardening sudoers
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

// backupSshdConfig respalda sshd_config antes de la primera modificación, para que
// Reset() pueda restaurarlo verbatim. No sobreescribe un backup ya existente — así
// conserva el estado real previo al hardening a través de corridas repetidas.
func backupSshdConfig() error {
	if _, err := os.Stat(sshdConfigBackup); err == nil {
		return nil
	}
	data, err := os.ReadFile(sshdConfig)
	if err != nil {
		return fmt.Errorf("leer %s: %w", sshdConfig, err)
	}
	return os.WriteFile(sshdConfigBackup, data, 0o600)
}

// Reset revierte todo lo que HardRoot mutó: restaura sshd_config a su estado previo
// al hardening (PermitRootLogin/PermitEmptyPasswords), desbloquea la cuenta root si
// fue bloqueada (passwd -u root — man passwd confirma que revierte exactamente al
// valor previo a passwd -l), y borra el sudoers propio del módulo.
func (h *HardRoot) Reset() {
	if err := os.Remove(sudoersFile); err == nil {
		fmt.Printf(i18n.T("geoip.reset.removed_file")+" %s\n", sudoersFile)
	} else if os.IsNotExist(err) {
		fmt.Println(i18n.T("hardroot.reset.no_sudoers"))
	} else {
		fmt.Printf(i18n.T("geoip.reset.warn_remove")+" %s: %v\n", sudoersFile, err)
	}

	if data, err := os.ReadFile(sshdConfigBackup); err == nil {
		tmpFile := sshdConfigBackup + ".restore-tmp"
		if err := os.WriteFile(tmpFile, data, 0o644); err != nil {
			fmt.Println(i18n.T("hardroot.reset.warn_no_sshd_restore"))
		} else {
			if out, err := exec.Command("sshd", "-t", "-f", tmpFile).CombinedOutput(); err != nil {
				fmt.Printf(i18n.T("hardroot.reset.warn_sshd_backup_invalid")+" %s) — no se restauró.\n",
					strings.TrimSpace(string(out)))
			} else if err := os.WriteFile(sshdConfig, data, 0o644); err != nil {
				fmt.Printf(i18n.T("hardroot.reset.warn_sshd_restore_failed")+" %s: %v\n", sshdConfig, err)
			} else {
				if err := reloadSSHD(); err != nil {
					fmt.Printf(i18n.T("hardroot.reset.warn_sshd_reload_failed")+" %v\n", err)
				} else {
					fmt.Println(i18n.T("hardroot.reset.restored_sshd"))
				}
				_ = os.Remove(sshdConfigBackup)
			}
			os.Remove(tmpFile)
		}
	} else if !os.IsNotExist(err) {
		fmt.Printf(i18n.T("hardroot.reset.warn_no_sshd_backup_read")+" %v\n", err)
	}

	if out, err := exec.Command("passwd", "-u", "root").CombinedOutput(); err != nil {
		fmt.Println(i18n.T("hardroot.reset.info_root_not_unlocked") + " " + strings.TrimSpace(string(out)))
	} else {
		fmt.Println(i18n.T("hardroot.reset.root_unlocked"))
	}
}

func (h *HardRoot) Menu() {
	for {
		fmt.Println(i18n.T("hardroot.menu.header"))
		fmt.Println(i18n.T("hardroot.menu.estado"))
		fmt.Println(i18n.T("hardroot.menu.harden_ssh"))
		fmt.Println(i18n.T("hardroot.menu.lock_root"))
		fmt.Println(i18n.T("hardroot.menu.sudoers"))
		fmt.Println(i18n.T("fw.menu.back"))
		fmt.Println(i18n.T("hardroot.menu.footer"))
		fmt.Print(i18n.T("fw.menu.prompt") + " ")

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
			fmt.Println(i18n.T("fw.invalid.option"))
		}
	}
}

type hardrootStatus struct {
	SudoersExists bool
	SudoersSize   int64
	SudoersDrift  bool   // true si el archivo actual difiere del template generado
	RootPasswd    string // "BLOQUEADA" / "con contraseña" / "SIN contraseña" / "desconocido"
	PermitRoot    string
	PermitEmpty   string
}

// parseSudoersState mira un archivo sudoers del filesystem y determina si
// existe, su tamaño, y si difiere del template generado por SM-NG.
// Funcion pura testeable con t.TempDir().
func parseSudoersState(path, template string) (exists bool, size int64, drift bool) {
	info, err := os.Stat(path)
	if err != nil {
		return false, 0, false
	}
	exists = true
	size = info.Size()
	if cur, err := os.ReadFile(path); err == nil {
		drift = string(cur) != template
	}
	return
}

// parsePasswdStatus interpreta la salida de `passwd -S root` (o `passwd -S USER`).
// Devuelve el estado en formato humano. Funcion pura testeable.
func parsePasswdStatus(rawOutput string) string {
	fields := strings.Fields(rawOutput)
	if len(fields) < 2 {
		return "desconocido"
	}
	switch fields[1] {
	case "L":
		return "BLOQUEADA ✓"
	case "P":
		return "con contraseña (activa)"
	case "NP":
		return "SIN contraseña ⚠"
	default:
		return "desconocido"
	}
}

// collectStatus reune el estado actual de hardroot.
// Llama a las funciones puras con los paths/valores reales del sistema.
func collectStatus() hardrootStatus {
	s := hardrootStatus{
		RootPasswd:  "desconocido",
		PermitRoot:  orUnset(sshdOption("PermitRootLogin")),
		PermitEmpty: orUnset(sshdOption("PermitEmptyPasswords")),
	}

	// Passwd root via `passwd -S root`
	if out, err := exec.Command("passwd", "-S", "root").Output(); err == nil {
		s.RootPasswd = parsePasswdStatus(string(out))
	}

	// Sudoers
	s.SudoersExists, s.SudoersSize, s.SudoersDrift = parseSudoersState(sudoersFile, sudoersContent)

	return s
}

func (h *HardRoot) showStatus() {
	fmt.Println()
	s := collectStatus()

	fmt.Printf(i18n.T("hardroot.status.permit_root")+" %s\n", s.PermitRoot)
	fmt.Printf(i18n.T("hardroot.status.permit_empty")+" %s\n", s.PermitEmpty)
	fmt.Printf(i18n.T("hardroot.status.root_passwd")+" %s\n", s.RootPasswd)

	fmt.Println()
	fmt.Println(i18n.T("hardroot.status.sudoers"))
	if !s.SudoersExists {
		fmt.Printf(i18n.T("hardroot.status.sudoers_missing")+" %s : no existe\n", sudoersFile)
	} else {
		fmt.Printf(i18n.T("hardroot.status.sudoers_ok")+" %s  (%d bytes)\n", sudoersFile, s.SudoersSize)
		if s.SudoersDrift {
			fmt.Println(i18n.T("hardroot.status.sudoers_drift"))
		}
	}

	fmt.Println()
	fmt.Println(i18n.T("fw.status.technical_log"))
}

func (h *HardRoot) hardenSSH() {
	fmt.Println()
	fmt.Println(i18n.T("hardroot.harden_ssh.intro"))
	fmt.Println(i18n.T("hardroot.harden_ssh.perm_root_no"))
	fmt.Println(i18n.T("hardroot.harden_ssh.perm_empty_no"))

	users := sudoCapableUsers()
	if len(users) == 0 {
		fmt.Println()
		fmt.Println(i18n.T("hardroot.harden_ssh.warn_no_sudo"))
		fmt.Println(i18n.T("hardroot.harden_ssh.warn_no_sudo_detail"))
	} else {
		fmt.Printf("\n  "+i18n.T("hardroot.harden_ssh.sudo_users")+" %s\n", strings.Join(users, ", "))
	}
	fmt.Print(i18n.T("hardroot.harden_ssh.confirm") + " ")
	if !h.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(h.scanner.Text())) != "s" {
		fmt.Println(i18n.T("hardroot.cancelled"))
		return
	}

	if err := backupSshdConfig(); err != nil {
		fmt.Printf(i18n.T("hardroot.harden_ssh.warn_backup")+
			"passwd -l root) — "+i18n.T("hardroot.harden_ssh.warn_no_restore")+" %v)\n", err)
	}

	if err := setSshdOption("PermitRootLogin", "no"); err != nil {
		fmt.Printf(i18n.T("hardroot.err.generic")+" %v\n", err)
		return
	}
	if err := setSshdOption("PermitEmptyPasswords", "no"); err != nil {
		fmt.Printf(i18n.T("hardroot.err.generic")+" %v\n", err)
		return
	}
	fmt.Println(i18n.T("hardroot.harden_ssh.success"))

	if out, err := exec.Command("sshd", "-t").CombinedOutput(); err != nil {
		h.logger.Error("La configuración SSH no pasó la validación.", strings.TrimSpace(string(out)))
		fmt.Println(i18n.T("hardroot.harden_ssh.manual_review"))
		return
	}

	if err := reloadSSHD(); err != nil {
		fmt.Printf(i18n.T("hardroot.harden_ssh.warn_reload")+" %v\n", err)
		fmt.Println(i18n.T("hardroot.harden_ssh.manual_reload"))
	} else {
		fmt.Println(i18n.T("hardroot.harden_ssh.reloaded"))
	}
}

func (h *HardRoot) lockRoot() {
	out, err := exec.Command("passwd", "-S", "root").Output()
	if err == nil {
		if fields := strings.Fields(string(out)); len(fields) >= 2 && fields[1] == "L" {
			fmt.Println()
			fmt.Println(i18n.T("hardroot.lock_root.already_locked"))
			return
		}
	}

	if len(sudoCapableUsers()) == 0 {
		fmt.Println()
		fmt.Println(i18n.T("hardroot.lock_root.warn_no_sudo"))
		fmt.Println(i18n.T("hardroot.lock_root.warn_no_sudo_detail"))
	}
	fmt.Print(i18n.T("hardroot.lock_root.confirm") + " ")
	if !h.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(h.scanner.Text())) != "s" {
		fmt.Println(i18n.T("hardroot.cancelled"))
		return
	}

	if out2, err := exec.Command("passwd", "-l", "root").CombinedOutput(); err != nil {
		fmt.Printf(i18n.T("hardroot.err.generic")+" %s\n", strings.TrimSpace(string(out2)))
		return
	}
	fmt.Println(i18n.T("hardroot.lock_root.success"))
}

func (h *HardRoot) configureSudoers() {
	prompt := i18n.T("hardroot.sudoers.prompt_create")
	if _, err := os.Stat(sudoersFile); err == nil {
		fmt.Printf("\n  "+i18n.T("hardroot.sudoers.exists")+" %s\n", sudoersFile)
		prompt = i18n.T("hardroot.sudoers.prompt_overwrite")
	} else {
		fmt.Printf("\n  "+i18n.T("hardroot.sudoers.will_create")+" %s con:\n", sudoersFile)
		fmt.Println(i18n.T("hardroot.sudoers.content_line_1"))
		fmt.Println(i18n.T("hardroot.sudoers.content_line_2"))
		fmt.Println(i18n.T("hardroot.sudoers.content_line_3"))
	}
	fmt.Printf("  "+i18n.T("hardroot.sudoers.confirm")+" %s? [s/N]: ", prompt, sudoersFile)
	if !h.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(h.scanner.Text())) != "s" {
		fmt.Println(i18n.T("hardroot.cancelled"))
		return
	}

	tmpFile := "/tmp/sm-ng-sudoers"
	if err := os.WriteFile(tmpFile, []byte(sudoersContent), 0o640); err != nil {
		fmt.Printf(i18n.T("hardroot.err.generic")+" %v\n", err)
		return
	}
	defer os.Remove(tmpFile)

	out, err := exec.Command("visudo", "-c", "-f", tmpFile).CombinedOutput()
	if err != nil {
		h.logger.Error("El archivo sudoers no pasó la validación.", strings.TrimSpace(string(out)))
		return
	}

	if err := os.MkdirAll(sudoersDir, 0o750); err != nil {
		fmt.Printf(i18n.T("hardroot.err.generic")+" %v\n", err)
		return
	}
	if err := os.WriteFile(sudoersFile, []byte(sudoersContent), 0o440); err != nil {
		fmt.Printf(i18n.T("hardroot.err.generic")+" %v\n", err)
		return
	}
	fmt.Printf(i18n.T("hardroot.sudoers.success")+" %s\n", sudoersFile)
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
			fmt.Println(i18n.T("hardroot.cli.warn_no_sudo"))
		} else {
			fmt.Printf(i18n.T("hardroot.cli.sudo_users_alt")+" %s\n", strings.Join(users, ", "))
		}
		fmt.Println(i18n.T("hardroot.cli.applying"))
		if err := setSshdOption("PermitRootLogin", "no"); err != nil {
			fmt.Printf(i18n.T("hardroot.err.generic")+" %v\n", err)
			return false
		}
		if err := setSshdOption("PermitEmptyPasswords", "no"); err != nil {
			fmt.Printf(i18n.T("hardroot.err.generic")+" %v\n", err)
			return false
		}
		if out, err := exec.Command("sshd", "-t").CombinedOutput(); err != nil {
			fmt.Printf(i18n.T("hardroot.err.sshd_t_failed")+"\n%s\n", strings.TrimSpace(string(out)))
			return false
		}
		if err := reloadSSHD(); err != nil {
			fmt.Printf(i18n.T("hardroot.err.generic")+" %v\n", err)
		} else {
			fmt.Println(i18n.T("hardroot.cli.reloaded_ok"))
		}
		return true
	case "lock-root", "lockroot":
		out, err := exec.Command("passwd", "-S", "root").Output()
		if err == nil {
			if fields := strings.Fields(string(out)); len(fields) >= 2 && fields[1] == "L" {
				fmt.Println(i18n.T("hardroot.lock_root.already_locked"))
				return true
			}
		}
		fmt.Println(i18n.T("hardroot.cli.locking_root"))
		out2, err2 := exec.Command("passwd", "-l", "root").CombinedOutput()
		if err2 != nil {
			fmt.Fprintf(os.Stderr, i18n.T("hardroot.err.generic")+" %s\n", strings.TrimSpace(string(out2)))
			return false
		}
		fmt.Println(i18n.T("hardroot.lock_root.success"))
		return true
	case "sudoers":
		fmt.Println(i18n.T("hardroot.cli.configuring_sudoers"))
		tmpFile := "/tmp/sm-ng-sudoers"
		if err := os.WriteFile(tmpFile, []byte(sudoersContent), 0o640); err != nil {
			fmt.Fprintf(os.Stderr, i18n.T("hardroot.err.generic")+" %v\n", err)
			return false
		}
		defer os.Remove(tmpFile)
		if out, err := exec.Command("visudo", "-c", "-f", tmpFile).CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, i18n.T("hardroot.err.visudo_failed")+" %s\n", strings.TrimSpace(string(out)))
			return false
		}
		if err := os.MkdirAll(sudoersDir, 0o750); err != nil {
			fmt.Fprintf(os.Stderr, i18n.T("hardroot.err.generic")+" %v\n", err)
			return false
		}
		if err := os.WriteFile(sudoersFile, []byte(sudoersContent), 0o440); err != nil {
			fmt.Fprintf(os.Stderr, i18n.T("hardroot.err.generic")+" %v\n", err)
			return false
		}
		fmt.Printf(i18n.T("hardroot.sudoers.success")+" %s\n", sudoersFile)
		return true
	default:
		fmt.Fprintf(os.Stderr, i18n.T("hardroot.cli.unknown_action")+" %s\n", action)
		fmt.Fprintln(os.Stderr, i18n.T("hardroot.cli.available_actions"))
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
