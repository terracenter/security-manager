package ssh

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/terracenter/security-manager-ng/internal/i18n"
)

const (
	configDir = "/etc/ssh/sshd_config.d"
	baseConf  = configDir + "/10-sshd-base.conf"
	issueNet  = "/etc/issue.net"
	issueFile = "/etc/issue"
)

type sshBaseOpts struct {
	AllowGroups  string
	AuthMethods  string
	PasswordAuth string
	PermitTunnel string
}

const baseConfTemplate = `# ============================================================================
# SSH HARDENING - Nivel Infraestructura Crítica
# ============================================================================

# 1. CRIPTOGRAFÍA Y ALGORITMOS
# ----------------------------------------------------------------------------
HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-ed25519

# sntrup761x25519 para resistencia post-cuántica.
# REQUISITO: OpenSSH >= 8.5 (Debian 12 trae 9.2 — OK; Debian 11 trae 8.4 — incompatible).
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256@libssh.org,curve25519-sha256,diffie-hellman-group16-sha512

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# EtM (Encrypt-then-MAC) previene ataques de relleno.
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# 2. AUTENTICACIÓN Y ACCESO
# ----------------------------------------------------------------------------
PermitRootLogin no
PasswordAuthentication %s
PermitEmptyPasswords no

# AuthenticationMethods tiene prioridad absoluta sobre PasswordAuthentication.
# 'publickey'          → solo llave (contraseña rechazada aunque PasswordAuthentication=yes).
# 'publickey password' → llave O contraseña (cualquiera es suficiente).
# 'publickey,password' → llave Y contraseña (MFA — ambas obligatorias).
AuthenticationMethods %s

UsePAM yes
KbdInteractiveAuthentication no

# Lista blanca de grupos (separar por espacios, no comas).
AllowGroups %s

MaxAuthTries 6
MaxSessions 2

# 3. SEGURIDAD OPERATIVA Y RED
# ----------------------------------------------------------------------------
# VERBOSE registra la huella (fingerprint) de la llave usada — esencial para auditoría.
SyslogFacility AUTH
LogLevel VERBOSE

# CountMax 0 = cierra la sesión al primer ping sin respuesta (5 min de inactividad exactos).
ClientAliveInterval 300
ClientAliveCountMax 0

# Vectores de movimiento lateral deshabilitados.
# PermitTunnel: habilitar solo si se requiere túnel SSH explícito (sin VPN activa).
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel %s
PermitUserEnvironment no

# Sin resolución DNS inversa — evita demoras de 5-30s en login.
UseDNS no

# 10:30:60 = hasta 10 pre-auth OK | 10-60 drop 30%% | >60 rechaza todo.
MaxStartups 10:30:60

# Aviso legal antes del prompt de login. Requerido por PCI-DSS, ISO 27001.
Banner /etc/issue.net
`

const issueNetContent = `###################################################################################################################################

  ALERT! You are entering a secured area! Your IP, Login Time, and Username have been noted and
  have been sent to the server administrator!

  This service is restricted to authorized users only. All activities on this system are logged.
  Unauthorized access will be fully investigated and reported to the appropriate law enforcement agencies.


  ¡ALERTA! ¡Está entrando en una zona segura! Su IP, hora de inicio de sesión y nombre de usuario han sido registrados y
  enviados al administrador del servidor.

  Este servicio está restringido únicamente a usuarios autorizados. Todas las actividades de este sistema quedan registradas.
  Los accesos no autorizados serán investigados a fondo y denunciados a las autoridades competentes.

###################################################################################################################################
`

const issueContent = `Este servicio está restringido únicamente a usuarios autorizados. Todas las actividades de este sistema quedan registradas.
Los accesos no autorizados serán investigados a fondo y denunciados a las autoridades competentes.

This service is restricted to authorized users only. All activities on this system are logged.
Unauthorized access will be fully investigated and reported to the appropriate law enforcement agencies.
`

// SSH gestiona el hardening de sshd_config.
type SSH struct {
	scanner *bufio.Scanner
}

func New() *SSH {
	return &SSH{scanner: bufio.NewScanner(os.Stdin)}
}

func (s *SSH) Order() int   { return 6 }
func (s *SSH) Name() string { return "SSH — hardening sshd_config" }

func (s *SSH) Menu() {
	for {
		fmt.Println(i18n.T("ssh.menu.header"))
		fmt.Println(i18n.T("ssh.menu.estado"))
		fmt.Println(i18n.T("ssh.menu.apply"))
		fmt.Println(i18n.T("ssh.menu.banners"))
		fmt.Println(i18n.T("ssh.menu.validar"))
		fmt.Println(i18n.T("fw.menu.back"))
		fmt.Println(i18n.T("ssh.menu.footer"))
		fmt.Print(i18n.T("fw.menu.prompt") + " ")

		if !s.scanner.Scan() {
			return
		}
		switch strings.TrimSpace(s.scanner.Text()) {
		case "1":
			s.showStatus()
		case "2":
			groups := s.askAllowGroups()
			if groups != "" {
				am, pa := s.askAuthMethod()
				tunnel := s.askPermitTunnel()
				s.applyBase(sshBaseOpts{
					AllowGroups:  groups,
					AuthMethods:  am,
					PasswordAuth: pa,
					PermitTunnel: tunnel,
				})
			}
		case "3":
			s.applyBanners()
		case "4":
			s.validate()
		case "0":
			return
		default:
			fmt.Println(i18n.T("fw.invalid.option"))
		}
	}
}

func (s *SSH) Reset() {
	removed := false
	for _, f := range []string{baseConf} {
		if err := os.Remove(f); err == nil {
			fmt.Printf(i18n.T("geoip.reset.removed_file")+" ", f)
			removed = true
		}
	}
	if removed {
		sshdTest()
		sshdRestart()
	} else {
		fmt.Println(i18n.T("ssh.reset.not_applied"))
	}
}

type sshConfigFile struct {
	Path      string
	Size      int64
	ModTime   string // formato YYYY-MM-DD HH:MM:SS
	IsOwn     bool   // true si es el archivo generado por SM-NG
	IsFreeIPA bool   // true si parece override de FreeIPA (nombre contiene "ipa")
	Exists    bool
}

// listConfigFiles lista los archivos en el directorio dado y los clasifica
// contra baseConf (path absoluto esperado del archivo SM-NG) y patron FreeIPA.
// Testeable: recibe el directorio por parametro en vez de leer la constante global.
func listConfigFiles(dir string, ownFile string) []sshConfigFile {
	var result []sshConfigFile
	files, err := os.ReadDir(dir)
	if err != nil {
		return result
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		path := dir + "/" + f.Name()
		info, err := os.Stat(path)
		if err != nil {
			result = append(result, sshConfigFile{
				Path: path, Exists: false,
			})
			continue
		}
		nameLower := strings.ToLower(f.Name())
		result = append(result, sshConfigFile{
			Path:      path,
			Size:      info.Size(),
			ModTime:   info.ModTime().Format("2006-01-02 15:04:05"),
			IsOwn:     path == ownFile,
			IsFreeIPA: strings.Contains(nameLower, "ipa"),
			Exists:    true,
		})
	}
	return result
}

func (s *SSH) showStatus() {
	fmt.Println()

	out, _ := exec.Command("systemctl", "is-active", detectSSHService()).Output()
	activo := strings.TrimSpace(string(out))
	out2, _ := exec.Command("systemctl", "is-enabled", detectSSHService()).Output()
	habilitado := strings.TrimSpace(string(out2))
	fmt.Printf(i18n.T("ssh.status.service_row"), activo, habilitado)

	fmt.Println()
	fmt.Println(i18n.T("ssh.status.config_files"))
	// Listar TODOS los archivos en sshd_config.d (no solo el de SM-NG).
	// Esto permite ver si hay overrides (ej: FreeIPA 99-ipa.conf) sin abrir cada uno.
	cfgs := listConfigFiles(configDir, baseConf)
	if len(cfgs) == 0 {
		fmt.Printf(i18n.T("ssh.status.dir_missing"), configDir)
	}
	for _, c := range cfgs {
		marker := "  "
		note := ""
		if c.IsOwn {
			marker = "✓ "
			note = " (generado por SM-NG)"
		} else if c.IsFreeIPA {
			marker = "⚠ "
			note = " (override FreeIPA detectado)"
		}
		if !c.Exists {
			fmt.Printf(i18n.T("ssh.status.file_missing"), c.Path)
			continue
		}
		fmt.Printf(i18n.T("ssh.status.file_row"),
			marker, c.Path, c.ModTime, c.Size, note)
	}

	out, err := exec.Command("sshd", "-T").Output()
	if err == nil {
		fmt.Println()
		fmt.Println(i18n.T("ssh.status.directives"))
		claves := []string{
			"passwordauthentication", "permitrootlogin", "authenticationmethods",
			"allowgroups", "loglevel", "maxauthtries", "maxsessions", "permittunnel",
		}
		for _, line := range strings.Split(string(out), "\n") {
			l := strings.ToLower(line)
			for _, k := range claves {
				if strings.HasPrefix(l, k+" ") {
					fmt.Printf("    %s\n", line)
					break
				}
			}
		}
	}

	fmt.Println()
	fmt.Println(i18n.T("ssh.status.banners"))
	for _, f := range []string{issueNet, issueFile} {
		if _, err := os.Stat(f); err == nil {
			fmt.Printf(i18n.T("ssh.status.ok")+" ", f)
		} else {
			fmt.Printf(i18n.T("ssh.status.file_missing"), f)
		}
	}

	fmt.Println()
	fmt.Println(i18n.T("ssh.status.listening_port"))
	out, _ = exec.Command("ss", "-lnpt").Output()
	found := false
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, ":22 ") {
			fmt.Printf("    %s\n", line)
			found = true
		}
	}
	if !found {
		fmt.Println(i18n.T("ssh.status.no_listener"))
	}
}

func (s *SSH) preflight(opts sshBaseOpts) bool {
	user := os.Getenv("SUDO_USER")
	if user == "" {
		user = os.Getenv("USER")
	}
	if user == "" {
		user = "root"
	}

	outID, err := exec.Command("id", "-Gn", user).Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, i18n.T("ssh.preflight.warn_groups"), user, err)
		return false
	}
	userGroups := strings.Fields(string(outID))
	inAny := false
	for _, ag := range strings.Fields(opts.AllowGroups) {
		for _, ug := range userGroups {
			if ag == ug {
				inAny = true
				break
			}
		}
		if inAny {
			break
		}
	}
	if !inAny {
		fmt.Fprintf(os.Stderr, i18n.T("ssh.preflight.not_in_groups"), user, opts.AllowGroups)
		fmt.Fprintln(os.Stderr, i18n.T("ssh.preflight.block_warning"))
		return false
	}
	fmt.Printf(i18n.T("ssh.preflight.ok_groups"), user)

	if opts.PasswordAuth == "no" {
		homeDir := ""
		if out, err2 := exec.Command("getent", "passwd", user).Output(); err2 == nil {
			if parts := strings.SplitN(string(out), ":", 7); len(parts) >= 6 {
				homeDir = strings.TrimSpace(parts[5])
			}
		}
		if homeDir == "" {
			homeDir, _ = os.UserHomeDir()
		}
		authKeys := filepath.Join(homeDir, ".ssh", "authorized_keys")
		data, err3 := os.ReadFile(authKeys)
		if err3 != nil || len(strings.TrimSpace(string(data))) == 0 {
			fmt.Fprintf(os.Stderr, i18n.T("ssh.preflight.warn_key"), authKeys)
		} else {
			fmt.Printf(i18n.T("ssh.preflight.ok_key"), authKeys)
		}
	}

	return true
}

func (s *SSH) applyBase(opts sshBaseOpts) {
	authDesc := map[string]string{
		"publickey":          "solo llave pública",
		"publickey password": "llave pública O contraseña",
		"publickey,password": "llave pública Y contraseña (MFA)",
	}[opts.AuthMethods]
	if authDesc == "" {
		authDesc = opts.AuthMethods
	}
	tunnelDesc := "no"
	if opts.PermitTunnel == "yes" {
		tunnelDesc = "sí"
	}

	fmt.Printf(i18n.T("ssh.apply.header"),
		opts.AllowGroups, authDesc, tunnelDesc)

	if err := os.MkdirAll(configDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, i18n.T("ssh.apply.err_create_dir"), configDir, err)
		return
	}

	if existing, err := os.ReadFile(baseConf); err == nil {
		existStr := string(existing)
		if strings.Contains(existStr, "AllowGroups "+opts.AllowGroups+"\n") &&
			strings.Contains(existStr, "AuthenticationMethods "+opts.AuthMethods+"\n") &&
			strings.Contains(existStr, "PermitTunnel "+opts.PermitTunnel+"\n") &&
			strings.Contains(existStr, "PasswordAuthentication "+opts.PasswordAuth+"\n") {
			fmt.Println(i18n.T("ssh.apply.already_applied"))
			return
		}
		fmt.Println(i18n.T("ssh.apply.updating"))
	}

	if !s.preflight(opts) {
		return
	}

	backupFile := baseConf + ".bak"
	if _, err := os.Stat(baseConf); err == nil {
		if err := os.Rename(baseConf, backupFile); err != nil {
			fmt.Fprintf(os.Stderr, i18n.T("ssh.apply.err_backup"), backupFile, err)
			return
		}
		fmt.Printf(i18n.T("ssh.apply.backup"), baseConf, backupFile)
	}

	content := fmt.Sprintf(baseConfTemplate, opts.PasswordAuth, opts.AuthMethods, opts.AllowGroups, opts.PermitTunnel)
	if err := os.WriteFile(baseConf, []byte(content), 0o640); err != nil {
		fmt.Fprintf(os.Stderr, i18n.T("ssh.apply.err_write"), baseConf, err)
		if _, err := os.Stat(backupFile); err == nil {
			os.Rename(backupFile, baseConf)
			fmt.Println(i18n.T("ssh.apply.restored"))
		}
		return
	}
	fmt.Printf(i18n.T("ssh.apply.written"), baseConf)

	if !sshdTest() {
		fmt.Fprint(os.Stderr, i18n.T("ssh.apply.err_sshd_test"))
		if err := os.Remove(baseConf); err == nil {
			if _, err := os.Stat(backupFile); err == nil {
				os.Rename(backupFile, baseConf)
				fmt.Println(i18n.T("ssh.apply.restored"))
			}
		}
		return
	}

	os.Remove(backupFile)

	s.applyBanners()
	sshdReload()
}

func (s *SSH) applyBanners() {
	for _, entry := range []struct{ path, content string }{
		{issueNet, issueNetContent},
		{issueFile, issueContent},
	} {
		if err := os.WriteFile(entry.path, []byte(entry.content), 0644); err != nil {
			fmt.Fprintf(os.Stderr, i18n.T("ssh.banners.err"), err)
		} else {
			fmt.Printf(i18n.T("ssh.apply.written"), entry.path)
		}
	}
}

func (s *SSH) validate() {
	fmt.Println(i18n.T("ssh.validar.title"))

	fmt.Println(i18n.T("ssh.validar.active_config"))
	out, err := exec.Command("sshd", "-T").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, i18n.T("ssh.validar.err_sshd_t"), err)
	} else {
		claves := []string{
			"passwordauthentication", "permitrootlogin", "authenticationmethods",
			"allowgroups", "loglevel", "maxauthtries", "maxsessions",
			"x11forwarding", "allowagentforwarding", "allowtcpforwarding",
			"permittunnel", "usedns", "maxstartups",
		}
		for _, line := range strings.Split(string(out), "\n") {
			l := strings.ToLower(line)
			for _, k := range claves {
				if strings.HasPrefix(l, k+" ") {
					fmt.Printf("    %s\n", line)
					break
				}
			}
		}
	}

	fmt.Println(i18n.T("ssh.validar.port"))
	out, _ = exec.Command("ss", "-lnpt").Output()
	found := false
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, ":22 ") {
			fmt.Printf("    %s\n", line)
			found = true
		}
	}
	if !found {
		fmt.Println(i18n.T("ssh.validar.no_listener"))
	}

	fmt.Println(i18n.T("ssh.validar.last_auth"))
	out, _ = exec.Command("journalctl", "-u", detectSSHService(), "-n", "5", "--no-pager", "--grep", "Accepted").Output()
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		fmt.Println(i18n.T("ssh.validar.no_records"))
	} else {
		for _, l := range lines {
			if strings.TrimSpace(l) != "" {
				fmt.Printf("    %s\n", l)
			}
		}
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// detectSSHService retorna "ssh" (Debian/Ubuntu) o "sshd" (RHEL-family).
func detectSSHService() string {
	if err := exec.Command("systemctl", "cat", "ssh.service").Run(); err == nil {
		return "ssh"
	}
	return "sshd"
}

func sshdTest() bool {
	fmt.Print(i18n.T("ssh.check.syntax"))
	cmd := exec.Command("sshd", "-t")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println(i18n.T("ssh.check.failed"))
		return false
	}
	fmt.Println(i18n.T("ssh.check.ok"))
	return true
}

func sshdRestart() bool {
	fmt.Print(i18n.T("ssh.check.restart"))
	cmd := exec.Command("systemctl", "restart", detectSSHService())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println(i18n.T("ssh.check.failed"))
		return false
	}
	fmt.Println(i18n.T("ssh.check.ok"))
	return true
}

func sshdReload() bool {
	fmt.Print(i18n.T("ssh.check.reload"))
	cmd := exec.Command("systemctl", "reload", detectSSHService())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println(i18n.T("ssh.check.failed"))
		return false
	}
	fmt.Println(i18n.T("ssh.check.ok"))
	return true
}

func (s *SSH) readLine(prompt string) string {
	fmt.Print(prompt)
	if !s.scanner.Scan() {
		return ""
	}
	return strings.TrimSpace(s.scanner.Text())
}

func (s *SSH) askAuthMethod() (string, string) {
	fmt.Println()
	fmt.Println(i18n.T("ssh.wizard.auth_mode"))
	fmt.Println(i18n.T("ssh.wizard.auth1"))
	fmt.Println(i18n.T("ssh.wizard.auth1_detail"))
	fmt.Println(i18n.T("ssh.wizard.auth2"))
	fmt.Println(i18n.T("ssh.wizard.auth2_detail"))
	fmt.Println(i18n.T("ssh.wizard.auth3"))
	fmt.Println(i18n.T("ssh.wizard.auth3_detail"))
	val := s.readLine("  Modo [1]: ")
	switch val {
	case "2":
		return "publickey password", "yes"
	case "3":
		return "publickey,password", "yes"
	default:
		return "publickey", "no"
	}
}

func (s *SSH) askPermitTunnel() string {
	fmt.Println()
	fmt.Println(i18n.T("ssh.wizard.tunnel_desc"))
	fmt.Println(i18n.T("ssh.wizard.tunnel_disable_hint"))
	val := s.readLine("  ¿Habilitar PermitTunnel? [s/N]: ")
	if strings.ToLower(val) == "s" {
		return "yes"
	}
	return "no"
}

func (s *SSH) askAllowGroups() string {
	out, _ := exec.Command("getent", "group").Output()
	var relevantes []string
	relevantNames := []string{"sudo", "wheel", "admin", "adm", "infraestructura"}
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.SplitN(line, ":", 2)[0]
		for _, r := range relevantNames {
			if name == r {
				relevantes = append(relevantes, name)
				break
			}
		}
	}

	fmt.Println()
	if len(relevantes) > 0 {
		fmt.Printf(i18n.T("ssh.wizard.available_groups"), strings.Join(relevantes, ", "))
	}

	user := os.Getenv("SUDO_USER")
	if user == "" {
		user = os.Getenv("USER")
	}
	if user == "" {
		user = "root"
	}
	fmt.Printf(i18n.T("ssh.wizard.current_user"), user)
	fmt.Println(i18n.T("ssh.wizard.allowgroups_warning"))

	val := s.readLine("  AllowGroups [sudo] (q=cancelar, Enter=predeterminado): ")
	if strings.ToLower(val) == "q" {
		fmt.Println(i18n.T("ssh.wizard.cancelled"))
		return ""
	}
	if val == "" {
		return "sudo"
	}
	return val
}

// RunAction implementa modules.CLIModule para modo no interactivo.
//
//	estado                                          Ver estado actual
//	apply [--groups G] [--auth 1|2|3] [--tunnel]   Aplicar hardening SSH
//	banners                                         Escribir /etc/issue.net y /etc/issue
//	validar                                         Validar config activa (sshd -T)
func (s *SSH) RunAction(action string, args ...string) bool {
	switch strings.ToLower(action) {
	case "estado", "status":
		s.showStatus()
		return true
	case "apply", "aplicar":
		return s.cliApply(args)
	case "banners":
		s.applyBanners()
		return true
	case "validar", "validate":
		s.validate()
		return true
	default:
		fmt.Fprintf(os.Stderr, i18n.T("ssh.cli.unknown_action"), action)
		fmt.Fprintln(os.Stderr, i18n.T("ssh.cli.available_actions"))
		return false
	}
}

func (s *SSH) cliApply(args []string) bool {
	fs := flag.NewFlagSet("ssh apply", flag.ContinueOnError)
	groups := fs.String("groups", "sudo", "AllowGroups (default: sudo)")
	auth := fs.Int("auth", 1, "Método de autenticación: 1=solo llave | 2=llave O contraseña | 3=llave Y contraseña (MFA)")
	tunnel := fs.Bool("tunnel", false, "Habilitar PermitTunnel (default: no)")
	if err := fs.Parse(args); err != nil {
		return false
	}
	var authMethods, passwordAuth string
	switch *auth {
	case 2:
		authMethods = "publickey password"
		passwordAuth = "yes"
	case 3:
		authMethods = "publickey,password"
		passwordAuth = "yes"
	default:
		authMethods = "publickey"
		passwordAuth = "no"
	}
	permitTunnel := "no"
	if *tunnel {
		permitTunnel = "yes"
	}
	s.applyBase(sshBaseOpts{
		AllowGroups:  *groups,
		AuthMethods:  authMethods,
		PasswordAuth: passwordAuth,
		PermitTunnel: permitTunnel,
	})
	return true
}

var _ interface {
	Order() int
	Name() string
	Menu()
	Reset()
} = (*SSH)(nil)
