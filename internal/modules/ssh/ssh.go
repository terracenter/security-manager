package ssh

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	configDir  = "/etc/ssh/sshd_config.d"
	baseConf   = configDir + "/10-sshd-base.conf"
	issueNet   = "/etc/issue.net"
	issueFile  = "/etc/issue"
	sshService = "ssh"
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
		fmt.Println("\n  ┌─ SSH — Hardening sshd_config ─────────┐")
		fmt.Println("  │  [1] Ver estado actual                 │")
		fmt.Println("  │  [2] Aplicar configuración base        │")
		fmt.Println("  │  [3] Aplicar banners (/etc/issue.net)  │")
		fmt.Println("  │  [4] Validar configuración activa      │")
		fmt.Println("  │  [0] Volver                            │")
		fmt.Println("  └────────────────────────────────────────┘")
		fmt.Print("  Selección: ")

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
			fmt.Println("  Opción inválida.")
		}
	}
}

func (s *SSH) Reset() {
	removed := false
	for _, f := range []string{baseConf} {
		if err := os.Remove(f); err == nil {
			fmt.Printf("  Eliminado: %s\n", f)
			removed = true
		}
	}
	if removed {
		sshdTest()
		sshdRestart()
	} else {
		fmt.Println("  No hay configuración SSH hardening aplicada.")
	}
}

func (s *SSH) showStatus() {
	fmt.Println()

	out, _ := exec.Command("systemctl", "is-active", sshService).Output()
	activo := strings.TrimSpace(string(out))
	out2, _ := exec.Command("systemctl", "is-enabled", sshService).Output()
	habilitado := strings.TrimSpace(string(out2))
	fmt.Printf("  Servicio SSH:  activo=%-12s habilitado=%s\n", activo, habilitado)

	fmt.Println()
	fmt.Println("  Archivos de configuración:")
	if info, err := os.Stat(baseConf); err == nil {
		fmt.Printf("    ✓ %s  (%s)\n", baseConf, info.ModTime().Format("2006-01-02 15:04:05"))
	} else {
		fmt.Printf("    ✗ %s\n", baseConf)
	}

	out, err := exec.Command("sshd", "-T").Output()
	if err == nil {
		fmt.Println()
		fmt.Println("  Directivas activas:")
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
	fmt.Println("  Banners:")
	for _, f := range []string{issueNet, issueFile} {
		if _, err := os.Stat(f); err == nil {
			fmt.Printf("    ✓ %s\n", f)
		} else {
			fmt.Printf("    ✗ %s\n", f)
		}
	}

	fmt.Println()
	fmt.Println("  Puerto escuchando:")
	out, _ = exec.Command("ss", "-lnpt").Output()
	found := false
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, ":22 ") {
			fmt.Printf("    %s\n", line)
			found = true
		}
	}
	if !found {
		fmt.Println("    (sin listener en :22)")
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
		fmt.Fprintf(os.Stderr, "  ⚠ preflight: no se pudo consultar grupos de '%s': %v\n", user, err)
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
		fmt.Fprintf(os.Stderr, "  ✗ preflight AllowGroups: '%s' no pertenece a ningún grupo en '%s'\n", user, opts.AllowGroups)
		fmt.Fprintln(os.Stderr, "    Aplicar esta configuración bloquearía el acceso SSH.")
		return false
	}
	fmt.Printf("  ✓ preflight AllowGroups: usuario '%s' en grupos permitidos\n", user)

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
			fmt.Fprintf(os.Stderr, "  ⚠ preflight llave: %s ausente o vacío — con AuthMethods 'publickey' podrías perder acceso\n", authKeys)
		} else {
			fmt.Printf("  ✓ preflight llave: %s presente\n", authKeys)
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

	fmt.Printf("\nAplicando 10-sshd-base.conf (AllowGroups: %s | Auth: %s | Tunnel: %s)...\n",
		opts.AllowGroups, authDesc, tunnelDesc)

	if err := os.MkdirAll(configDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "  ERROR creando %s: %v\n", configDir, err)
		return
	}

	if existing, err := os.ReadFile(baseConf); err == nil {
		existStr := string(existing)
		if strings.Contains(existStr, "AllowGroups "+opts.AllowGroups+"\n") &&
			strings.Contains(existStr, "AuthenticationMethods "+opts.AuthMethods+"\n") &&
			strings.Contains(existStr, "PermitTunnel "+opts.PermitTunnel+"\n") &&
			strings.Contains(existStr, "PasswordAuthentication "+opts.PasswordAuth+"\n") {
			fmt.Println("  10-sshd-base.conf ya está aplicado con esa configuración.")
			return
		}
		fmt.Println("  Actualizando 10-sshd-base.conf...")
	}

	if !s.preflight(opts) {
		return
	}

	backupFile := baseConf + ".bak"
	if _, err := os.Stat(baseConf); err == nil {
		if err := os.Rename(baseConf, backupFile); err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR: no se pudo hacer backup en %s: %v\n", backupFile, err)
			return
		}
		fmt.Printf("  Backup: %s → %s\n", baseConf, backupFile)
	}

	content := fmt.Sprintf(baseConfTemplate, opts.PasswordAuth, opts.AuthMethods, opts.AllowGroups, opts.PermitTunnel)
	if err := os.WriteFile(baseConf, []byte(content), 0o640); err != nil {
		fmt.Fprintf(os.Stderr, "  ERROR escribiendo %s: %v\n", baseConf, err)
		if _, err := os.Stat(backupFile); err == nil {
			os.Rename(backupFile, baseConf)
			fmt.Println("  Restaurado backup.")
		}
		return
	}
	fmt.Printf("  Escrito: %s\n", baseConf)

	if !sshdTest() {
		fmt.Fprintf(os.Stderr, "  ERROR: sshd -t falló — revirtiendo cambios\n")
		if err := os.Remove(baseConf); err == nil {
			if _, err := os.Stat(backupFile); err == nil {
				os.Rename(backupFile, baseConf)
				fmt.Println("  Restaurado backup.")
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
			fmt.Fprintf(os.Stderr, "  ERROR: %v\n", err)
		} else {
			fmt.Printf("  Escrito: %s\n", entry.path)
		}
	}
}

func (s *SSH) validate() {
	fmt.Println("\n=== Validación SSH Hardening ===")

	fmt.Println("\n  Configuración activa (sshd -T):")
	out, err := exec.Command("sshd", "-T").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ERROR ejecutando sshd -T: %v\n", err)
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

	fmt.Println("\n  Puerto escuchando:")
	out, _ = exec.Command("ss", "-lnpt").Output()
	found := false
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, ":22 ") {
			fmt.Printf("    %s\n", line)
			found = true
		}
	}
	if !found {
		fmt.Println("    (ningún listener en :22)")
	}

	fmt.Println("\n  Últimas autenticaciones aceptadas:")
	out, _ = exec.Command("journalctl", "-u", sshService, "-n", "5", "--no-pager", "--grep", "Accepted").Output()
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		fmt.Println("    (sin registros recientes)")
	} else {
		for _, l := range lines {
			if strings.TrimSpace(l) != "" {
				fmt.Printf("    %s\n", l)
			}
		}
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func sshdTest() bool {
	fmt.Print("  Verificando sintaxis (sshd -t)... ")
	cmd := exec.Command("sshd", "-t")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println("ERROR")
		return false
	}
	fmt.Println("OK")
	return true
}

func sshdRestart() bool {
	fmt.Print("  Reiniciando sshd... ")
	cmd := exec.Command("systemctl", "restart", sshService)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println("ERROR")
		return false
	}
	fmt.Println("OK")
	return true
}

func sshdReload() bool {
	fmt.Print("  Recargando sshd... ")
	cmd := exec.Command("systemctl", "reload", sshService)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println("ERROR")
		return false
	}
	fmt.Println("OK")
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
	fmt.Println("  Modo de autenticación:")
	fmt.Println("    1. Solo llave pública          (AuthenticationMethods publickey)           [recomendado]")
	fmt.Println("       → contraseña rechazada incluso con PasswordAuthentication=yes.")
	fmt.Println("    2. Llave pública O contraseña  (AuthenticationMethods publickey password)")
	fmt.Println("       → cualquiera es suficiente; para admins sin llave SSH configurada aún.")
	fmt.Println("    3. Llave pública Y contraseña  (AuthenticationMethods publickey,password)  [MFA]")
	fmt.Println("       → ambas obligatorias; para FreeIPA cuando la llave puede fallar por web.")
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
	fmt.Println("  PermitTunnel: permite túneles TUN/TAP via SSH (útil sin VPN activa).")
	fmt.Println("  Deshabilitar en producción salvo necesidad explícita.")
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
		fmt.Printf("  Grupos disponibles relevantes: %s\n", strings.Join(relevantes, ", "))
	}

	user := os.Getenv("SUDO_USER")
	if user == "" {
		user = os.Getenv("USER")
	}
	if user == "" {
		user = "root"
	}
	fmt.Printf("  Usuario actual: %s\n", user)
	fmt.Println("  ADVERTENCIA: solo usuarios en AllowGroups podrán autenticarse.")

	val := s.readLine("  AllowGroups [sudo] (q=cancelar, Enter=predeterminado): ")
	if strings.ToLower(val) == "q" {
		fmt.Println("  Cancelado")
		return ""
	}
	if val == "" {
		return "sudo"
	}
	return val
}

var _ interface {
	Order() int
	Name() string
	Menu()
	Reset()
} = (*SSH)(nil)
