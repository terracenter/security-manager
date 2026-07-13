package firewall

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/terracenter/security-manager-ng/internal/modules/infra"
	"github.com/terracenter/security-manager-ng/internal/safeapply"
	"github.com/terracenter/security-manager-ng/internal/sys"
	"golang.org/x/term"
)

// Firewall gestiona el ruleset nftables declarativo (tabla inet sm).
type Firewall struct {
	scanner *bufio.Scanner
	logger  *sys.SMLogger
}

func New(logger *sys.SMLogger) *Firewall {
	return &Firewall{
		scanner: bufio.NewScanner(os.Stdin),
		logger:  logger,
	}
}

func (f *Firewall) Order() int   { return 1 }
func (f *Firewall) Name() string { return "Firewall (nftables)" }

// Reset elimina la tabla inet sm y toda la configuración persistida del módulo
// (ruleset, backup, opciones, puertos permitidos, e include en /etc/nftables.conf),
// para que el siguiente [1] Aplicar corra el wizard de detección de puertos de nuevo
// en vez de reutilizar silenciosamente la configuración de una corrida anterior.
func (f *Firewall) Reset() {
	if out, err := exec.Command("nft", "delete", "table", "inet", "sm").CombinedOutput(); err != nil {
		fmt.Println("  (info) tabla inet sm ya no existía o no se pudo eliminar: " + strings.TrimSpace(string(out)))
	} else {
		fmt.Println("  Eliminado: tabla inet sm")
	}
	for _, path := range []string{infra.RulesetFile, infra.BackupFile, infra.OptionsFile, infra.AllowedPortsFile} {
		if err := os.Remove(path); err == nil {
			fmt.Printf("  Eliminado: %s\n", path)
		} else if !os.IsNotExist(err) {
			fmt.Printf("  ADVERTENCIA: no se pudo eliminar %s: %v\n", path, err)
		}
	}
	if err := infra.RemoveSmNftPersistence(); err != nil {
		fmt.Printf("  ADVERTENCIA: %v\n", err)
	}
}

func (f *Firewall) Menu() {
	for {
		port80, _ := infra.ReadPort80Option()
		port80Status := "INACTIVO"
		if port80 {
			port80Status = "ACTIVO ✓"
		}

		fmt.Println("\n  ┌─ Firewall (nftables) ────────────────────────────┐")
		fmt.Println("  │  [1] Aplicar / recargar ruleset base              │")
		fmt.Println("  │  [2] Ver estado actual                            │")
		fmt.Println("  │  [3] Resetear tabla inet sm                       │")
		if infra.HasPublicIP() {
			fmt.Printf("  │  [4] Puerto 80 global (ACME/Let's Encrypt): %-8s│\n", port80Status)
		}
		fmt.Println("  │  [0] Volver                                       │")
		fmt.Println("  └───────────────────────────────────────────────────┘")
		fmt.Print("  Selección: ")

		if !f.scanner.Scan() {
			return
		}
		switch strings.TrimSpace(f.scanner.Text()) {
		case "1":
			f.applyBase()
		case "2":
			f.showStatus()
		case "3":
			f.resetTable()
		case "4":
			if infra.HasPublicIP() {
				f.togglePort80()
			} else {
				fmt.Println("  Opción no disponible: este host no tiene IPs públicas.")
			}
		case "0":
			return
		default:
			fmt.Println("  Opción inválida.")
		}
	}
}

func (f *Firewall) togglePort80() {
	current, _ := infra.ReadPort80Option()
	if current {
		fmt.Print("\n  Puerto 80 global está ACTIVO. ¿Desactivar? [s/N]: ")
	} else {
		fmt.Print("\n  Puerto 80 global está INACTIVO. ¿Activar para ACME/Let's Encrypt? [s/N]: ")
	}
	if !f.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(f.scanner.Text())) != "s" {
		fmt.Println("  Cancelado.")
		return
	}
	if err := infra.WritePort80Option(!current); err != nil {
		fmt.Printf("  ERROR guardando opción: %v\n", err)
		return
	}
	if !current {
		fmt.Println("  Puerto 80 global ACTIVADO. Recargando ruleset...")
	} else {
		fmt.Println("  Puerto 80 global DESACTIVADO. Recargando ruleset...")
	}
	f.applyBase()
}

// writeLogrotateConfig escribe /etc/logrotate.d/security-manager-ng si no existe.
// Se llama después de un apply exitoso.
func writeLogrotateConfig() error {
	logrotateFile := "/etc/logrotate.d/security-manager-ng"

	// Idempotencia: si existe, no regenerar
	if _, err := os.Stat(logrotateFile); err == nil {
		return nil
	}

	content := `# Rotación de logs de Security Manager NG
/var/log/security-manager-ng.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
`

	return os.WriteFile(logrotateFile, []byte(content), 0o644)
}

// applyBase genera el ruleset base, valida la sintaxis y lo aplica con safeapply.
func (f *Firewall) applyBase() {
	// FASE 1: Validar prereqs (nftables, etc.)
	if err := sys.CheckAndInstallPrereqs(f.readLine); err != nil {
		f.logger.Error("No se pudieron instalar los paquetes requeridos.", fmt.Sprintf("%v", err))
		return
	}

	// SSH IP Guard: verificar que la IP SSH activa está en la lista blanca/immune
	if sshIP := sys.GetSSHIP(); sshIP != "" {
		if !ipExistsInACL(sshIP) {
			fmt.Printf("\n  ⚠️  Tu IP de conexión SSH (%s) no está en la lista blanca.\n", sshIP)
			fmt.Println("      Si aplicas el firewall sin registrarla, perderás acceso al servidor.")
			fmt.Print("\n  ¿Agregar como IMMUNE (Tier B) ahora? [S/n]: ")
			f.scanner.Scan()
			resp := strings.ToLower(strings.TrimSpace(f.scanner.Text()))
			if resp == "s" {
				entry := infra.ACLEntry{
					Addr:        sshIP,
					Responsable: "auto",
					Proposito:   "IP de sesión SSH — agregada automáticamente por firewall apply",
				}
				if err := infra.AppendACLEntry(infra.Immune4File, entry); err != nil {
					f.logger.Error("No se pudo agregar la IP a la lista immune.", fmt.Sprintf("%v", err))
					return
				}
				fmt.Printf("  ✓ %s agregada como IMMUNE (Tier B).\n", sshIP)
			} else {
				fmt.Printf("\n  ✗ No es posible aplicar el firewall sin registrar tu IP de acceso.\n")
				fmt.Printf("    Agrégala primero:\n")
				fmt.Printf("      security-manager-ng whitelist add %s --tier B\n", sshIP)
				fmt.Printf("    Luego vuelve a ejecutar [1] Aplicar / recargar ruleset base.\n\n")
				return
			}
		}
	}

	// FASE 2: Crear directorio de configuración (necesario para el wizard y el ruleset)
	if err := os.MkdirAll(infra.ConfDir, 0o750); err != nil {
		f.logger.Error("No se pudo crear directorio /etc/security-manager/.", fmt.Sprintf("%v", err))
		return
	}

	// FASE 3: Wizard de servicios en primera instalación
	isFirstInstall := !fileExists(infra.RulesetFile)
	sshEnabled := true // default
	if isFirstInstall {
		var err error
		sshEnabled, err = f.runServiceWizard()
		if err != nil {
			f.logger.Technical(fmt.Sprintf("wizard abortado: %v", err))
			return
		}
	}

	// Si el host tiene IP pública y la opción aún no está configurada → preguntar al usuario.
	if infra.HasPublicIP() {
		if _, found := infra.ReadPort80Option(); !found {
			fmt.Print("\n  Host con IP pública detectado. ¿Habilitar puerto 80 global para ACME/Let's Encrypt?\n  (No aplica si usas certificados auto-firmados) [s/N]: ")
			if f.scanner.Scan() {
				answer := strings.ToLower(strings.TrimSpace(f.scanner.Text()))
				enabled := answer == "s"
				_ = infra.WritePort80Option(enabled)
				if enabled {
					fmt.Println("  Puerto 80 global: ACTIVADO.")
				} else {
					fmt.Println("  Puerto 80 global: INACTIVO.")
				}
			}
		}
	}

	sshPort := infra.DetectSSHPort()
	geoip, _ := infra.LoadGeoIPData()
	port80, _ := infra.ReadPort80Option()
	ruleset := infra.GenerateRuleset(sshPort, sshEnabled, geoip, port80)

	svc := infra.DetectGlobalServices()
	if svc.TailscaleActive {
		fmt.Println("  [info] Tailscale detectado. Si usas subnet routing IPv6, agrega el rango")
		fmt.Println("         fd7a:115c:a1e0::/48 a Tier B: whitelist add fd7a:115c:a1e0::/48 --tier B")
	}

	tmpFile := infra.ConfDir + "/sm.nft.new"
	if err := os.WriteFile(tmpFile, []byte(ruleset), 0o640); err != nil {
		f.logger.Error("No se pudo escribir el ruleset.", fmt.Sprintf("%v", err))
		return
	}
	defer os.Remove(tmpFile)

	fmt.Println("\n  Validando sintaxis (nft -c)...")
	out, err := exec.Command("nft", "-c", "-f", tmpFile).CombinedOutput()
	if err != nil {
		f.logger.Error("Error de sintaxis en el ruleset generado.", strings.TrimSpace(string(out)))
		return
	}
	fmt.Println("  Sintaxis OK.")

	// Backup del ruleset ACTUAL antes de sobreescribir (deadman revertirá a este).
	if cur, err := os.ReadFile(infra.RulesetFile); err == nil {
		_ = os.WriteFile(infra.BackupFile, cur, 0o640)
		f.logger.Info(fmt.Sprintf("[firewall] Backup: %s → %s", infra.RulesetFile, infra.BackupFile))
	}

	if err := os.Rename(tmpFile, infra.RulesetFile); err != nil {
		f.logger.Error("No se pudo preparar el ruleset para aplicación.", fmt.Sprintf("%v", err))
		return
	}

	err = safeapply.Apply(safeapply.Plan{
		BackupFile:     infra.BackupFile,
		RulesetFile:    infra.RulesetFile,
		DeadmanTimeout: 120,
		WhitelistSet:   "",
		SkipBackup:     true,
	})
	if err != nil {
		f.logger.Error("No se pudo aplicar el ruleset.", fmt.Sprintf("%v", err))
		return
	}

	if err := infra.EnsureSmNftPersistence(); err != nil {
		f.logger.Warn(fmt.Sprintf("Persistencia en boot no configurada — agrega manualmente "+
			"'include \"/etc/security-manager/sm.nft\"' en /etc/nftables.conf: %v", err))
	}

	// Escribir config de logrotate (idempotente)
	if err := writeLogrotateConfig(); err != nil {
		f.logger.Warn(fmt.Sprintf("No se pudo escribir logrotate config: %v", err))
	}
}

// showStatus muestra un resumen del estado de la tabla inet sm.
// Si no existe → mensaje amigable.
// Si existe → resumen parseable de cadenas, sets y reglas.
func (f *Firewall) showStatus() {
	fmt.Println()
	out, err := exec.Command("nft", "list", "table", "inet", "sm").CombinedOutput()
	if err != nil {
		errMsg := strings.TrimSpace(string(out))
		// Distinguir si es "tabla no existe" o "nft no disponible"
		if strings.Contains(errMsg, "No such file or directory") || strings.Contains(errMsg, "no such table") {
			fmt.Println("  ✗ Firewall: INACTIVO — Ninguna regla de seguridad está activa en este servidor.")
			fmt.Println("     → Usa [1] Aplicar / recargar ruleset base para activarlo.")
		} else {
			fmt.Println("  ✗ nftables no está instalado — el firewall no puede funcionar.")
			fmt.Println("     → Ejecuta: sudo apt install nftables")
		}
		if f.logger != nil {
			f.logger.Technical(errMsg)
		}
		return
	}

	// Parser mínimo del output de nft
	chains, sets := parseNftStatus(string(out))

	fmt.Println("  ✓ Firewall: ACTIVO")
	fmt.Println()

	if len(chains) > 0 {
		fmt.Println("  Cadenas:")
		for name, info := range chains {
			fmt.Printf("    %-12s policy:%-8s — %d reglas\n", name, info.policy, info.ruleCount)
		}
		fmt.Println()
	}

	if len(sets) > 0 {
		fmt.Println("  Sets:")
		for name, count := range sets {
			if count == 0 {
				fmt.Printf("    %-20s (vacío)\n", name)
			} else {
				fmt.Printf("    %-20s %d entradas\n", name, count)
			}
		}
		fmt.Println()
	}

	fmt.Println("  Detalles técnicos → /var/log/security-manager-ng.log")
	if f.logger != nil {
		f.logger.Technical(string(out))
	}
}

// parseNftStatus extrae información mínima del output de "nft list table inet sm".
// Retorna: map[nombre]chainInfo (cadenas), map[nombre]count (sets).
type chainInfo struct {
	policy    string
	ruleCount int
}

func parseNftStatus(nftOutput string) (map[string]chainInfo, map[string]int) {
	chains := make(map[string]chainInfo)
	sets := make(map[string]int)

	lines := strings.Split(nftOutput, "\n")
	var inChain bool
	var chainName string
	var ruleCount int

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detectar inicio de cadena: "chain input {"
		if strings.HasPrefix(trimmed, "chain ") && strings.HasSuffix(trimmed, "{") {
			inChain = true
			chainName = strings.Fields(trimmed)[1]
			ruleCount = 0

			// Extraer policy: "policy drop" o "policy accept"
			policy := "accept"
			if i+1 < len(lines) {
				nextLine := strings.TrimSpace(lines[i+1])
				if strings.Contains(nextLine, "policy") {
					parts := strings.Fields(nextLine)
					for j, p := range parts {
						if p == "policy" && j+1 < len(parts) {
							policy = strings.TrimSuffix(parts[j+1], ";")
							break
						}
					}
				}
			}
			chains[chainName] = chainInfo{policy: policy, ruleCount: 0}
			continue
		}

		// Contar reglas dentro de cadena (líneas que no sean {, }, type, #)
		if inChain {
			if strings.HasPrefix(trimmed, "}") {
				inChain = false
				info := chains[chainName]
				info.ruleCount = ruleCount
				chains[chainName] = info
				continue
			}
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "type") &&
				!strings.HasPrefix(trimmed, "policy") && trimmed != "{" && trimmed != "}" {
				ruleCount++
			}
		}

		// Detectar sets: "set sm_whitelist4 {"
		if strings.HasPrefix(trimmed, "set ") && strings.HasSuffix(trimmed, "{") {
			setName := strings.Fields(trimmed)[1]
			setCount := 0

			// Contar elementos dentro del set
			for j := i + 1; j < len(lines); j++ {
				nextLine := strings.TrimSpace(lines[j])
				if strings.HasPrefix(nextLine, "}") {
					break
				}
				if strings.HasPrefix(nextLine, "elements = ") || strings.HasPrefix(nextLine, "elements=") {
					// Parseo muy simple: contar comillas, cada elemento dentro está entre comillas
					elementsPart := strings.TrimPrefix(nextLine, "elements = ")
					elementsPart = strings.TrimPrefix(elementsPart, "elements=")
					setCount = strings.Count(elementsPart, `"`) / 2 // cada elemento = 2 comillas
					break
				}
			}
			sets[setName] = setCount
		}
	}

	return chains, sets
}

// resetTable ejecuta delete table inet sm tras confirmación del operador.
func (f *Firewall) resetTable() {
	fmt.Println("\n  ⚠  Esto eliminará: tabla inet sm, " + infra.RulesetFile + ", " +
		infra.BackupFile + ", " + infra.OptionsFile + ", " + infra.AllowedPortsFile +
		" y el include en /etc/nftables.conf.")
	fmt.Println("     El siguiente [1] Aplicar volverá a correr el wizard de detección de puertos.")
	fmt.Print("  ¿Confirmar? [s/N]: ")
	if !f.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(f.scanner.Text())) != "s" {
		fmt.Println("  Cancelado.")
		return
	}
	f.Reset()
}

// RunAction implementa modules.CLIModule para modo no interactivo.
// Uso: security-manager-ng firewall <acción> [flags]
//
//	allow      --port N --proto tcp|udp [--comment C]  Abre puerto globalmente (bypass GeoIP)
//	deny       --port N --proto tcp|udp                Cierra puerto previamente abierto
//	list-ports                                          Lista puertos en allowed_ports.conf
//	estado | status                                     Estado de la tabla inet sm
//	apply                                               Aplica / recarga ruleset base
//	reset                                               Elimina tabla inet sm
//	port80     on|off                                   Activa/desactiva excepción global puerto 80
func (f *Firewall) RunAction(action string, args ...string) bool {
	switch strings.ToLower(action) {
	case "allow":
		return f.cliAllow(args)
	case "deny":
		return f.cliDeny(args)
	case "list-ports", "list-port", "listar-puertos":
		return f.cliListPorts()
	case "estado", "status":
		f.showStatus()
		return true
	case "apply", "aplicar":
		f.applyBase()
		return true
	case "reset":
		fmt.Println("  [firewall] Eliminando tabla inet sm y configuración persistida...")
		f.Reset()
		return true
	case "port80":
		if len(args) == 0 {
			fmt.Println("  Uso: firewall port80 on|off")
			return false
		}
		switch strings.ToLower(args[0]) {
		case "on", "true":
			_ = infra.WritePort80Option(true)
			fmt.Println("  [firewall] Puerto 80 global ACTIVADO. Recargando ruleset...")
			f.applyBase()
		case "off", "false":
			_ = infra.WritePort80Option(false)
			fmt.Println("  [firewall] Puerto 80 global DESACTIVADO. Recargando ruleset...")
			f.applyBase()
		default:
			fmt.Printf("  Valor inválido '%s'. Usa: on | off\n", args[0])
			return false
		}
		return true
	default:
		fmt.Printf("  Acción desconocida: '%s'\n", action)
		fmt.Println("  Acciones disponibles: allow, deny, list-ports, estado, apply, reset, port80")
		return false
	}
}

func (f *Firewall) cliAllow(args []string) bool {
	fs := flag.NewFlagSet("firewall allow", flag.ContinueOnError)
	port := fs.Int("port", 0, "Puerto a abrir (1-65535)")
	proto := fs.String("proto", "tcp", "Protocolo: tcp | udp")
	tier := fs.String("tier", "", "Tier: global | geo (vacío = preguntar interactivamente o default geo)")
	comment := fs.String("comment", "", "Comentario descriptivo")
	if err := fs.Parse(args); err != nil {
		return false
	}
	if *port < 1 || *port > 65535 {
		fmt.Println("  ERROR: --port es obligatorio y debe estar entre 1 y 65535.")
		return false
	}
	p := strings.ToLower(*proto)
	if p != "tcp" && p != "udp" {
		fmt.Printf("  ERROR: --proto debe ser 'tcp' o 'udp', no '%s'.\n", *proto)
		return false
	}

	// Determinar tier: interactivo si stdin es terminal, si no usar flag o default
	tierValue := "GEO" // default seguro
	if *tier != "" {
		tierValue = strings.ToUpper(*tier)
		if tierValue != "GLOBAL" && tierValue != "GEO" {
			fmt.Printf("  ERROR: --tier debe ser 'global' o 'geo', no '%s'.\n", *tier)
			return false
		}
	} else if isTerminal(os.Stdin) {
		// Preguntar interactivamente
		resp := f.readLine("  ¿Acceso GLOBAL (mundo) o GEO-restringido? [G/R]: ")
		if strings.ToLower(resp) == "g" {
			tierValue = "GLOBAL"
		}
	}

	entry := infra.PortEntry{
		Port:    *port,
		Proto:   p,
		Tier:    tierValue,
		Comment: *comment,
		Date:    time.Now().Format("2006-01-02"),
	}
	if err := infra.AddPortEntry(entry); err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return false
	}
	fmt.Printf("  [firewall] Puerto %d/%s (%s) agregado a %s.\n", *port, p, tierValue, infra.AllowedPortsFile)
	if tierValue == "GLOBAL" {
		fmt.Printf("  ✓ Acceso global (bypass GeoIP).\n")
	} else {
		fmt.Printf("  ✓ Acceso GEO-restringido (solo países configurados).\n")
	}
	fmt.Printf("  Cierra con: firewall deny --port %d --proto %s\n", *port, p)
	fmt.Println("  Recargando ruleset...")
	f.applyBase()
	return true
}

func (f *Firewall) cliDeny(args []string) bool {
	fs := flag.NewFlagSet("firewall deny", flag.ContinueOnError)
	port := fs.Int("port", 0, "Puerto a cerrar (1-65535)")
	proto := fs.String("proto", "tcp", "Protocolo: tcp | udp")
	if err := fs.Parse(args); err != nil {
		return false
	}
	if *port < 1 || *port > 65535 {
		fmt.Println("  ERROR: --port es obligatorio y debe estar entre 1 y 65535.")
		return false
	}
	p := strings.ToLower(*proto)
	if p != "tcp" && p != "udp" {
		fmt.Printf("  ERROR: --proto debe ser 'tcp' o 'udp', no '%s'.\n", *proto)
		return false
	}
	if err := infra.RemovePortEntry(*port, p); err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return false
	}
	fmt.Printf("  [firewall] Puerto %d/%s eliminado de %s.\n", *port, p, infra.AllowedPortsFile)
	fmt.Println("  Recargando ruleset...")
	f.applyBase()
	return true
}

func (f *Firewall) cliListPorts() bool {
	entries, err := infra.ReadPortEntries(infra.AllowedPortsFile)
	if err != nil {
		fmt.Printf("  ERROR leyendo %s: %v\n", infra.AllowedPortsFile, err)
		return false
	}
	if len(entries) == 0 {
		fmt.Println("  No hay puertos adicionales abiertos.")
		return true
	}
	fmt.Printf("\n  %-8s %-6s %-30s %s\n", "PUERTO", "PROTO", "COMENTARIO", "FECHA")
	fmt.Println("  " + strings.Repeat("─", 58))
	for _, e := range entries {
		fmt.Printf("  %-8d %-6s %-30s %s\n", e.Port, e.Proto, e.Comment, e.Date)
	}
	fmt.Println()
	return true
}

// readLine lee una línea del scanner y la retorna.
func (f *Firewall) readLine(prompt string) string {
	fmt.Print(prompt)
	if !f.scanner.Scan() {
		return ""
	}
	return strings.TrimSpace(f.scanner.Text())
}

// buildAllowedEntries arma las líneas de allowed_ports.conf a partir de los servicios
// seleccionados y el tier elegido (GLOBAL o GEO). Retorna un slice de strings listo
// para escribir a archivo. Función pura, sin side effects.
func buildAllowedEntries(selected []sys.ServiceInfo, tier string) []string {
	var entries []string
	for _, svc := range selected {
		procName := svc.ProcessName
		if procName == "" {
			procName = "?"
		}
		entry := fmt.Sprintf("%d | %s | %s | auto-detect | %s", svc.Port, svc.Proto, tier, time.Now().Format("2006-01-02"))
		entries = append(entries, entry)
	}
	return entries
}

// runSequentialWizard pregunta puerto por puerto (fallback sin TTY).
// Retorna (sshEnabled, error) para que applyBase() pueda pasar sshEnabled a GenerateRuleset().
func (f *Firewall) runSequentialWizard(services []sys.ServiceInfo) (bool, error) {
	sshEnabled := true // default: SSH abierto

	// Crear archivo allowed_ports.conf
	var entries []string
	for _, svc := range services {
		// Puerto 22 (SSH) → siempre GEO, skip wizard
		if svc.Port == 22 {
			continue
		}
		// Puerto 80 (HTTP) → siempre GLOBAL, skip wizard
		if svc.Port == 80 {
			continue
		}

		procName := svc.ProcessName
		if procName == "" {
			procName = "?"
		}

		// Preguntar si permitir el puerto
		resp := f.readLine(fmt.Sprintf("  Puerto %d (%s) — ¿Permitir? [s/N]: ", svc.Port, procName))
		if strings.ToLower(resp) != "s" {
			continue
		}

		// Preguntar tier
		tierResp := f.readLine("  ¿GLOBAL (mundo) o GEO-restringido? [G/R]: ")
		tier := "GEO"
		if strings.ToLower(tierResp) == "g" {
			tier = "GLOBAL"
		}

		entry := fmt.Sprintf("%d | %s | %s | auto-detect | %s", svc.Port, svc.Proto, tier, time.Now().Format("2006-01-02"))
		entries = append(entries, entry)
	}

	// Escribir en allowed_ports.conf
	if len(entries) > 0 {
		content := strings.Join(entries, "\n") + "\n"
		if err := os.WriteFile(infra.AllowedPortsFile, []byte(content), 0o640); err != nil {
			f.logger.Error(
				fmt.Sprintf("No se pudo guardar la configuración de puertos en %s.", infra.AllowedPortsFile),
				fmt.Sprintf("%v", err),
			)
			fmt.Println("     → Verifica permisos en /etc/security-manager/ o ejecuta con sudo.")
			fmt.Println("     → Detalles técnicos en /var/log/security-manager-ng.log")
			return false, err
		}
		fmt.Printf("  Puertos guardados en %s\n", infra.AllowedPortsFile)
	}

	return sshEnabled, nil
}

// runInteractiveWizard muestra un menú interactivo con checkboxes (survey.MultiSelect).
func (f *Firewall) runInteractiveWizard(services []sys.ServiceInfo) (bool, error) {
	sshEnabled := true // default: SSH abierto

	// Construir opciones para MultiSelect (todos los puertos detectados)
	options := make([]string, 0, len(services))
	serviceMap := make(map[string]sys.ServiceInfo)
	for _, svc := range services {
		procName := svc.ProcessName
		if procName == "" {
			procName = "?"
		}
		label := fmt.Sprintf("%d (%s)", svc.Port, procName)
		// Nota especial para puerto 80
		if svc.Port == 80 {
			label += " — requerido para renovación Let's Encrypt"
		}
		options = append(options, label)
		serviceMap[label] = svc
	}

	// Loop de menú — si el usuario no selecciona nada, reintentar
	var selectedLabels []string
	for {
		selectedLabels = nil
		prompt := &survey.MultiSelect{
			Message: "  ¿Cuáles puertos deseas permitir? (usa SPACE para marcar, ENTER para confirmar)",
			Options: options,
		}
		if err := survey.AskOne(prompt, &selectedLabels); err != nil {
			f.logger.Technical(fmt.Sprintf("survey error: %v", err))
			return false, err
		}
		if len(selectedLabels) > 0 {
			break
		}
		fmt.Println("  (no seleccionaste ningún puerto, reintentar)")
		fmt.Println()
	}

	// Convertir labels a servicios
	var selected []sys.ServiceInfo
	for _, label := range selectedLabels {
		if svc, ok := serviceMap[label]; ok {
			selected = append(selected, svc)
		}
	}

	// Caso especial: si el usuario NO marcó el puerto 22 (SSH), pedir confirmación fuerte
	sshInSelection := false
	for _, svc := range selected {
		if svc.Port == 22 {
			sshInSelection = true
			break
		}
	}
	if !sshInSelection {
		fmt.Println("\n  ⚠️⚠️⚠️  ADVERTENCIA CRÍTICA  ⚠️⚠️⚠️")
		fmt.Println("  Estás a punto de CERRAR el puerto SSH (22) en el firewall.")
		fmt.Println("  Si no tienes otro método de acceso (consola física, IPMI/iDRAC, VPN),")
		fmt.Println("  PERDERÁS EL ACCESO REMOTO A ESTE SERVIDOR.")
		fmt.Println()
		readLine := func(prompt string) string {
			return f.readLine(prompt)
		}
		if !sys.ConfirmStrong(readLine, "  Escribe 'cerrar ssh' para confirmar: ", "cerrar ssh") {
			fmt.Println("  SSH permanece abierto (no se confirmó el cierre).")
			fmt.Println()
			// Forzar SSH en la selección
			selected = append(selected, sys.ServiceInfo{Port: 22, Proto: "tcp", ProcessName: "sshd"})
			sshEnabled = true
		} else {
			sshEnabled = false
		}
	}

	// Preguntar tier una sola vez para el batch completo
	tierPrompt := &survey.Select{
		Message: "  ¿Los puertos SELECCIONADOS serán [G]lobal o [R]egional?",
		Options: []string{"GLOBAL", "GEO (regional)"},
		Default: "GEO (regional)",
	}
	var tierChoice string
	if err := survey.AskOne(tierPrompt, &tierChoice); err != nil {
		f.logger.Technical(fmt.Sprintf("survey tier error: %v", err))
		return false, err
	}
	tier := "GEO"
	if tierChoice == "GLOBAL" {
		tier = "GLOBAL"
	}

	// Construir y escribir entries
	entries := buildAllowedEntries(selected, tier)
	if len(entries) > 0 {
		content := strings.Join(entries, "\n") + "\n"
		if err := os.WriteFile(infra.AllowedPortsFile, []byte(content), 0o640); err != nil {
			f.logger.Error(
				fmt.Sprintf("No se pudo guardar la configuración de puertos en %s.", infra.AllowedPortsFile),
				fmt.Sprintf("%v", err),
			)
			fmt.Println("     → Verifica permisos en /etc/security-manager/ o ejecuta con sudo.")
			fmt.Println("     → Detalles técnicos en /var/log/security-manager-ng.log")
			return false, err
		}
		fmt.Printf("  Puertos guardados en %s\n", infra.AllowedPortsFile)
	}

	return sshEnabled, nil
}

// runServiceWizard dispatcher — selecciona entre menú interactivo o preguntas secuenciales.
func (f *Firewall) runServiceWizard() (bool, error) {
	fmt.Println("\n  Detectando servicios activos...")
	services, err := sys.DetectListeningServices()
	if err != nil {
		f.logger.Error("Error inesperado al detectar servicios.", fmt.Sprintf("%v", err))
		fmt.Println("     → Detalles técnicos en /var/log/security-manager-ng.log")
		return false, err
	}

	if len(services) == 0 {
		fmt.Println("  No se detectaron servicios activos.")
		return true, nil // sin servicios detectados, SSH histórico permanece abierto
	}

	if isTerminal(os.Stdin) {
		return f.runInteractiveWizard(services)
	}
	return f.runSequentialWizard(services)
}

// fileExists verifica si un archivo existe.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// isTerminal verifica si un file descriptor es un terminal.
func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

// ipExistsInACL verifica si la IP está en alguno de los archivos ACL.
// Busca en immune4.conf, immune6.conf, whitelist4.conf, whitelist6.conf.
func ipExistsInACL(ip string) bool {
	files := []string{infra.Immune4File, infra.Immune6File, infra.Whitelist4File, infra.Whitelist6File}
	for _, f := range files {
		entries, err := infra.ReadACLEntries(f)
		if err != nil {
			continue
		}
		for _, addr := range infra.ACLAddresses(entries) {
			if addr == ip {
				return true
			}
		}
	}
	return false
}

// _ ensures the interface is satisfied at compile time.
var _ interface {
	Order() int
	Name() string
	Menu()
	Reset()
} = (*Firewall)(nil)
