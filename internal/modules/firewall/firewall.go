package firewall

import (
	"bufio"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/terracenter/security-manager-ng/internal/i18n"
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
func (f *Firewall) Name() string { return i18n.T("fw.name") }

// Reset elimina la tabla inet sm y toda la configuración persistida del módulo
// (ruleset, backup, opciones, puertos permitidos, e include en /etc/nftables.conf),
// para que el siguiente [1] Aplicar corra el wizard de detección de puertos de nuevo
// en vez de reutilizar silenciosamente la configuración de una corrida anterior.
func (f *Firewall) Reset() {
	if err := safeapply.DeleteAllSmTables(); err != nil {
		fmt.Println("  " + i18n.T("fw.reset.info_not_found") + " " + err.Error())
	} else {
		fmt.Println("  " + i18n.T("fw.reset.removed_table"))
	}
	for _, path := range []string{infra.RulesetFile, infra.BackupFile, infra.OptionsFile, infra.AllowedPortsFile, infra.ForwardDBFile} {
		if err := os.Remove(path); err == nil {
			fmt.Printf("  %s %s\n", i18n.T("fw.reset.removed_file"), path)
		} else if !os.IsNotExist(err) {
			fmt.Printf("  %s %s: %v\n", i18n.T("fw.reset.warn_remove"), path, err)
		}
	}
	if err := infra.RemoveSmNftPersistence(); err != nil {
		fmt.Printf("  %s %v\n", i18n.T("fw.reset.warn_general"), err)
	}
}

func (f *Firewall) Menu() {
	for {
		port80, _ := infra.ReadPort80Option()
		port80Status := i18n.T("fw.port80.inactive")
		if port80 {
			port80Status = i18n.T("fw.port80.active")
		}

		fmt.Println(i18n.T("fw.menu.header"))
		fmt.Println("  │  " + i18n.T("fw.menu.apply") + "             │")
		fmt.Println("  │  " + i18n.T("fw.menu.status") + "                  │")
		fmt.Println("  │  " + i18n.T("fw.menu.reset") + "             │")
		if infra.HasPublicIP() {
			fmt.Printf("  │  [4] %s: %-8s│\n", i18n.T("fw.menu.port80"), port80Status)
		}
		fmt.Println("  │  " + i18n.T("fw.menu.back") + "                                       │")
		fmt.Println(i18n.T("fw.menu.footer"))
		fmt.Print("  " + i18n.T("fw.menu.prompt") + ": ")

		if !f.scanner.Scan() {
			return
		}
		switch strings.TrimSpace(f.scanner.Text()) {
		case "1":
			f.applyBase()
		case "2":
			f.inspectCLI()
		case "3":
			f.resetTable()
		case "4":
			if infra.HasPublicIP() {
				f.togglePort80()
			} else {
				fmt.Println("  " + i18n.T("fw.menu.no_public_ip"))
			}
		case "0":
			return
		default:
			fmt.Println("  " + i18n.T("fw.invalid.option"))
		}
	}
}

func (f *Firewall) togglePort80() {
	current, _ := infra.ReadPort80Option()
	if current {
		fmt.Print(i18n.T("fw.port80.toggle_active") + " ")
	} else {
		fmt.Print(i18n.T("fw.port80.toggle_inactive") + " ")
	}
	if !f.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(f.scanner.Text())) != "s" {
		fmt.Println("  " + i18n.T("fw.port80.cancelled"))
		return
	}
	if err := infra.WritePort80Option(!current); err != nil {
		fmt.Printf("  %s %v\n", i18n.T("fw.port80.error_save"), err)
		return
	}
	if !current {
		fmt.Println("  " + i18n.T("fw.port80.activated_reload"))
	} else {
		fmt.Println("  " + i18n.T("fw.port80.deactivated_reload"))
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
		f.logger.Error(fmt.Sprintf("No se pudieron instalar los paquetes requeridos: %v", err), "")
		return
	}

	// SSH IP Guard: verificar que la IP SSH activa está en la lista blanca/immune
	if sshIP := sys.GetSSHIP(); sshIP != "" {
		if !ipExistsInACL(sshIP) {
			fmt.Printf(i18n.T("fw.apply.ssh_ip_warning"), sshIP)
			fmt.Println(i18n.T("fw.apply.ssh_ip_lose_access"))
			fmt.Print(i18n.T("fw.apply.ssh_ip_prompt") + " ")
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
				fmt.Printf(i18n.T("fw.apply.ssh_ip_added"), sshIP)
			} else {
				fmt.Print(i18n.T("fw.apply.ssh_ip_blocked"))
				fmt.Print(i18n.T("fw.apply.ssh_ip_add_first"))
				fmt.Printf(i18n.T("fw.apply.ssh_ip_use_cmd"), sshIP)
				fmt.Print(i18n.T("fw.apply.ssh_ip_retry"))
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
			fmt.Print(i18n.T("fw.port80.public_ip_prompt") + " ")
			if f.scanner.Scan() {
				answer := strings.ToLower(strings.TrimSpace(f.scanner.Text()))
				enabled := answer == "s"
				_ = infra.WritePort80Option(enabled)
				if enabled {
					fmt.Println("  " + i18n.T("fw.port80.activated_short"))
				} else {
					fmt.Println("  " + i18n.T("fw.port80.deactivated_short"))
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
		fmt.Println(i18n.T("fw.apply.tailscale_detected"))
		fmt.Println(i18n.T("fw.apply.tailscale_hint"))
	}

	tmpFile := infra.ConfDir + "/sm.nft.new"
	if err := os.WriteFile(tmpFile, []byte(ruleset), 0o640); err != nil {
		f.logger.Error("No se pudo escribir el ruleset.", fmt.Sprintf("%v", err))
		return
	}
	defer func() { _ = os.Remove(tmpFile) }()

	fmt.Println(i18n.T("fw.apply.validating"))
	out, err := exec.Command("nft", "-c", "-f", tmpFile).CombinedOutput()
	if err != nil {
		f.logger.Error("Error de sintaxis en el ruleset generado.", strings.TrimSpace(string(out)))
		return
	}
	fmt.Println(i18n.T("fw.apply.syntax_ok"))

	// Backup del ruleset ACTUAL antes de sobreescribir (deadman revertirá a este).
	if cur, err := os.ReadFile(infra.RulesetFile); err == nil {
		_ = os.WriteFile(infra.BackupFile, cur, 0o640)
		f.logger.Info(fmt.Sprintf("[firewall] Backup: %s → %s", infra.RulesetFile, infra.BackupFile))
	}

	// Escribir manifest con timestamp + sha256 del ruleset (para detectar drift manual).
	rulesetHash := sha256.Sum256([]byte(ruleset))
	manifest := fmt.Sprintf("timestamp=%s\nsha256=%x\n", time.Now().UTC().Format(time.RFC3339), rulesetHash)
	_ = os.WriteFile(infra.RulesetFile+".manifest", []byte(manifest), 0o640)

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
			fmt.Println(i18n.T("fw.status.firewall_inactive"))
			fmt.Println(i18n.T("fw.status.firewall_inactive_hint"))
		} else {
			fmt.Println(i18n.T("fw.status.nftables_missing"))
			fmt.Println(i18n.T("fw.status.nftables_install_hint"))
		}
		if f.logger != nil {
			f.logger.Technical(errMsg)
		}
		return
	}

	// Parseo completo: cadenas con sus reglas + sets con sus elementos
	chains, sets := parseNftStatus(string(out))

	fmt.Print(i18n.T("fw.status.active"))

	if len(chains) > 0 {
		fmt.Println(i18n.T("fw.status.chains_header"))
		for name, info := range chains {
			fmt.Printf(i18n.T("fw.status.chain_row"), name, info.policy, info.ruleCount)
		}
		fmt.Println()
	}

	if len(sets) > 0 {
		fmt.Println(i18n.T("fw.status.sets_header"))
		for name, elements := range sets {
			if len(elements) == 0 {
				fmt.Printf(i18n.T("fw.status.set_empty"), name)
			} else {
				fmt.Printf(i18n.T("fw.status.set_with_count"), name, len(elements))
			}
		}
		fmt.Println()
	}

	// Metadata: timestamp + sha256 de la última apply (si existe manifest).
	f.printManifestMetadata()

	fmt.Println(i18n.T("fw.status.technical_log"))
	if f.logger != nil {
		f.logger.Technical(string(out))
	}

	// Sub-menú de drill-down (Fase 1 del checklist: drill-down de firewall)
	f.statusDrilldown(chains, sets)
}

// printManifestMetadata lee /etc/security-manager/sm.nft.manifest y muestra
// timestamp + hash de la última apply. Si el hash del sm.nft actual difiere
// del manifest, avisa drift manual.
func (f *Firewall) printManifestMetadata() {
	manifestPath := infra.RulesetFile + ".manifest"
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		fmt.Println("  " + i18n.T("fw.status.no_manifest"))
		return
	}
	var ts, hash string
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "timestamp="):
			ts = strings.TrimPrefix(line, "timestamp=")
		case strings.HasPrefix(line, "sha256="):
			hash = strings.TrimPrefix(line, "sha256=")
		}
	}
	if ts == "" || hash == "" {
		fmt.Println("  " + i18n.T("fw.status.manifest_corrupt"))
		return
	}
	fmt.Printf(i18n.T("fw.status.last_apply"), ts)
	fmt.Printf(i18n.T("fw.status.hash"), hash)

	// Drift detection: comparar hash del archivo actual vs manifest.
	if cur, err := os.ReadFile(infra.RulesetFile); err == nil {
		curHash := sha256.Sum256(cur)
		curHex := fmt.Sprintf("%x", curHash)
		if curHex != hash {
			fmt.Println("  " + i18n.T("fw.status.drift_warning"))
			fmt.Println("     " + i18n.T("fw.status.drift_hint"))
		}
	}
}

// statusDrilldown ofrece ver el contenido detallado de una cadena o un set.
// Loop interactivo hasta que el usuario elige [0] volver.
func (f *Firewall) statusDrilldown(chains map[string]chainInfo, sets map[string][]string) {
	// Salir si no hay nada que drillar
	if len(chains) == 0 && len(sets) == 0 {
		return
	}
	for {
		fmt.Println(i18n.T("fw.drilldown.header"))
		if len(chains) > 0 {
			fmt.Println("  │  " + i18n.T("fw.drilldown.chain_opt") + "            │")
		}
		if len(sets) > 0 {
			fmt.Println("  │  " + i18n.T("fw.drilldown.set_opt") + "                  │")
		}
		fmt.Println("  │  " + i18n.T("fw.drilldown.back") + "        │")
		fmt.Println(i18n.T("fw.drilldown.footer"))
		fmt.Print("  " + i18n.T("fw.menu.prompt") + ": ")

		if !f.scanner.Scan() {
			return
		}
		switch strings.ToUpper(strings.TrimSpace(f.scanner.Text())) {
		case "C":
			if len(chains) == 0 {
				fmt.Println("  " + i18n.T("fw.drilldown.no_chains"))
				continue
			}
			f.showChainRules(chains)
		case "S":
			if len(sets) == 0 {
				fmt.Println("  " + i18n.T("fw.drilldown.no_sets"))
				continue
			}
			f.showSetElements(sets)
		case "0":
			return
		default:
			fmt.Println("  " + i18n.T("fw.invalid.option"))
		}
	}
}

// showChainRules lista las cadenas y deja elegir una para ver todas sus reglas.
func (f *Firewall) showChainRules(chains map[string]chainInfo) {
	fmt.Println()
	fmt.Println(i18n.T("fw.show.chains_avail"))
	names := make([]string, 0, len(chains))
	for name := range chains {
		names = append(names, name)
	}
	sort.Strings(names)
	for i, name := range names {
		info := chains[name]
		fmt.Printf(i18n.T("fw.show.chains_row"), i+1, name, info.policy, info.ruleCount)
	}
	fmt.Println(i18n.T("fw.show.cancel"))
	fmt.Print(i18n.T("fw.show.chain_prompt") + " ")

	if !f.scanner.Scan() {
		return
	}
	var sel int
	if _, err := fmt.Sscanf(strings.TrimSpace(f.scanner.Text()), "%d", &sel); err != nil {
		fmt.Println("  " + i18n.T("fw.invalid.option"))
		return
	}
	if sel == 0 {
		return
	}
	if sel < 1 || sel > len(names) {
		fmt.Println("  " + i18n.T("fw.invalid.range"))
		return
	}
	chosen := names[sel-1]
	info := chains[chosen]
	fmt.Printf(i18n.T("fw.show.chain_header"), chosen, info.policy)
	if len(info.rules) == 0 {
		fmt.Println("    " + i18n.T("fw.show.chain_empty"))
		return
	}
	for i, rule := range info.rules {
		fmt.Printf(i18n.T("fw.show.rule"), i+1, rule)
	}
}

// showSetElements lista los sets y deja elegir uno para ver sus elementos.
func (f *Firewall) showSetElements(sets map[string][]string) {
	fmt.Println()
	fmt.Println(i18n.T("fw.show.sets_avail"))
	names := make([]string, 0, len(sets))
	for name := range sets {
		names = append(names, name)
	}
	sort.Strings(names)
	for i, name := range names {
		fmt.Printf(i18n.T("fw.show.sets_row"), i+1, name, len(sets[name]))
	}
	fmt.Println(i18n.T("fw.show.cancel"))
	fmt.Print(i18n.T("fw.show.set_prompt") + " ")

	if !f.scanner.Scan() {
		return
	}
	var sel int
	if _, err := fmt.Sscanf(strings.TrimSpace(f.scanner.Text()), "%d", &sel); err != nil {
		fmt.Println("  " + i18n.T("fw.invalid.option"))
		return
	}
	if sel == 0 {
		return
	}
	if sel < 1 || sel > len(names) {
		fmt.Println("  " + i18n.T("fw.invalid.range"))
		return
	}
	chosen := names[sel-1]
	elements := sets[chosen]
	fmt.Printf(i18n.T("fw.show.set_header"), chosen, len(elements))
	if len(elements) == 0 {
		fmt.Println("    " + i18n.T("fw.show.set_empty"))
		return
	}
	for i, elem := range elements {
		fmt.Printf(i18n.T("fw.show.element"), i+1, elem)
	}
}

// parseNftStatus extrae estructura completa del output de "nft list table inet sm".
// Retorna: map[nombre]chainInfo con reglas, map[nombre]elementos (sets).
type chainInfo struct {
	policy    string
	ruleCount int
	rules     []string // texto crudo de cada regla, en orden
}

func parseNftStatus(nftOutput string) (map[string]chainInfo, map[string][]string) {
	chains := make(map[string]chainInfo)
	sets := make(map[string][]string)

	lines := strings.Split(nftOutput, "\n")
	var inChain bool
	var chainName string
	var ruleCount int
	var rules []string

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detectar inicio de cadena: "chain input {"
		if strings.HasPrefix(trimmed, "chain ") && strings.HasSuffix(trimmed, "{") {
			inChain = true
			chainName = strings.Fields(trimmed)[1]
			ruleCount = 0
			rules = nil

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
			chains[chainName] = chainInfo{policy: policy, ruleCount: 0, rules: nil}
			continue
		}

		// Capturar reglas dentro de cadena (líneas que no sean {, }, type, #)
		if inChain {
			if strings.HasPrefix(trimmed, "}") {
				inChain = false
				info := chains[chainName]
				info.ruleCount = ruleCount
				info.rules = rules
				chains[chainName] = info
				continue
			}
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "type") &&
				!strings.HasPrefix(trimmed, "policy") && trimmed != "{" && trimmed != "}" {
				// Limpiar el `;` final para que se vea limpio en el drill-down
				rule := strings.TrimSuffix(strings.TrimSpace(line), ";")
				rules = append(rules, rule)
				ruleCount++
			}
		}

		// Detectar sets: "set sm_whitelist4 {"
		if strings.HasPrefix(trimmed, "set ") && strings.HasSuffix(trimmed, "{") {
			setName := strings.Fields(trimmed)[1]

			// Buscar la línea "elements = { ip1, ip2, ... }"
			for j := i + 1; j < len(lines); j++ {
				nextLine := strings.TrimSpace(lines[j])
				if strings.HasPrefix(nextLine, "}") {
					break
				}
				if strings.HasPrefix(nextLine, "elements = ") || strings.HasPrefix(nextLine, "elements=") {
					elementsPart := strings.TrimPrefix(nextLine, "elements = ")
					elementsPart = strings.TrimPrefix(elementsPart, "elements=")
					elementsPart = strings.TrimSuffix(elementsPart, "}")
					elementsPart = strings.TrimSpace(elementsPart)
					sets[setName] = parseSetElements(elementsPart)
					break
				}
			}
		}
	}

	return chains, sets
}

// parseSetElements extrae cada IP/CIDR de la línea "elements = { ip1, ip2, ... }".
// Cada elemento está entre comillas o separado por coma.
func parseSetElements(elementsLine string) []string {
	var result []string
	if elementsLine == "" {
		return result
	}
	// Quitar comillas envolventes si existen
	elementsLine = strings.Trim(elementsLine, "{}")
	// Separar por coma y limpiar cada elemento
	parts := strings.Split(elementsLine, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"`)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// resetTable ejecuta delete table inet sm tras confirmación del operador.
func (f *Firewall) resetTable() {
	fmt.Println("\n  ⚠ " + i18n.T("fw.reset.eliminating") + " " + infra.RulesetFile + ", " +
		infra.BackupFile + ", " + infra.OptionsFile + ", " + infra.AllowedPortsFile +
		" " + i18n.T("fw.reset.eliminating_files"))
	fmt.Println("     " + i18n.T("fw.reset.will_rerun_wizard"))
	fmt.Print("  " + i18n.T("fw.reset.confirm") + " ")
	if !f.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(f.scanner.Text())) != "s" {
		fmt.Println("  " + i18n.T("fw.reset.cancelled"))
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
		fmt.Println("  " + i18n.T("fw.reset.deleting"))
		f.Reset()
		return true
	case "port80":
		if len(args) == 0 {
			fmt.Println("  " + i18n.T("fw.cli.usage_port80"))
			return false
		}
		switch strings.ToLower(args[0]) {
		case "on", "true":
			_ = infra.WritePort80Option(true)
			fmt.Println("  " + i18n.T("fw.port80.activated_reload"))
			f.applyBase()
		case "off", "false":
			_ = infra.WritePort80Option(false)
			fmt.Println("  " + i18n.T("fw.port80.deactivated_reload"))
			f.applyBase()
		default:
			fmt.Printf(i18n.T("fw.cli.invalid_value"), args[0])
			return false
		}
		return true
	default:
		fmt.Printf(i18n.T("fw.cli.unknown_action"), action)
		fmt.Println(i18n.T("fw.cli.available_actions"))
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
		fmt.Println(i18n.T("fw.cli.err_port_required"))
		return false
	}
	p := strings.ToLower(*proto)
	if p != "tcp" && p != "udp" {
		fmt.Printf(i18n.T("fw.cli.err_proto"), *proto)
		return false
	}

	// Determinar tier: interactivo si stdin es terminal, si no usar flag o default
	tierValue := "GEO" // default seguro
	if *tier != "" {
		tierValue = strings.ToUpper(*tier)
		if tierValue != "GLOBAL" && tierValue != "GEO" {
			fmt.Printf(i18n.T("fw.cli.err_tier"), *tier)
			return false
		}
	} else if isTerminal(os.Stdin) {
		// Preguntar interactivamente
		resp := f.readLine(i18n.T("fw.cli.tier_prompt") + " ")
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
	fmt.Printf(i18n.T("fw.cli.tier_added"), *port, p, tierValue, infra.AllowedPortsFile)
	if tierValue == "GLOBAL" {
		fmt.Print(i18n.T("fw.cli.global_ok"))
	} else {
		fmt.Print(i18n.T("fw.cli.geo_ok"))
	}
	fmt.Printf(i18n.T("fw.cli.deny_hint"), *port, p)
	fmt.Println("  " + i18n.T("fw.cli.reloading"))
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
		fmt.Println(i18n.T("fw.cli.err_port_required"))
		return false
	}
	p := strings.ToLower(*proto)
	if p != "tcp" && p != "udp" {
		fmt.Printf(i18n.T("fw.cli.err_proto"), *proto)
		return false
	}
	if err := infra.RemovePortEntry(*port, p); err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return false
	}
	fmt.Printf(i18n.T("fw.cli.removed"), *port, p, infra.AllowedPortsFile)
	fmt.Println("  " + i18n.T("fw.cli.reloading"))
	f.applyBase()
	return true
}

func (f *Firewall) cliListPorts() bool {
	confPorts, err := infra.ReadPortEntries(infra.AllowedPortsFile)
	if err != nil {
		fmt.Printf(i18n.T("fw.cli.err_read"), infra.AllowedPortsFile, err)
		return false
	}

	result, inspectErr := f.Inspect()
	if inspectErr != nil || !result.TableActive {
		fmt.Print(i18n.T("fw.cli.ports_not_applied"))
		if len(confPorts) == 0 {
			fmt.Println("  " + i18n.T("fw.cli.no_ports"))
			return true
		}
		fmt.Printf(i18n.T("fw.cli.ports_header"), i18n.T("fw.cli.ports_cols"), "PROTO", "TIER", "COMENTARIO", "FECHA")
		fmt.Println(i18n.T("fw.cli.ports_sep") + strings.Repeat("─", 58))
		for _, e := range confPorts {
			fmt.Printf(i18n.T("fw.cli.ports_row_planned"), e.Port, e.Proto, e.Tier, e.Comment, e.Date)
		}
		fmt.Println()
		return true
	}

	ports := parseEffectivePorts(result.Chains["input"].rules, confPorts)
	bypass := parseManagementBypass(result.Chains["input"].rules)

	if len(ports) == 0 {
		fmt.Println("  " + i18n.T("fw.cli.no_ports"))
	} else {
		fmt.Printf(i18n.T("fw.cli.ports_header_full"), i18n.T("fw.cli.ports_cols"), "PROTO", "ORIGEN", "TIER", "COMENTARIO", "FECHA")
		fmt.Println(i18n.T("fw.cli.ports_sep") + strings.Repeat("─", 90))
		for _, p := range ports {
			fmt.Printf(i18n.T("fw.cli.ports_row_full"), p.Port, p.Proto, p.Origen, p.Tier, p.Comment, p.Date)
		}
	}

	if len(bypass) > 0 {
		fmt.Print(i18n.T("fw.cli.ports_mgmt_header"))
		for _, b := range bypass {
			fmt.Printf(i18n.T("fw.cli.ports_mgmt_row"), b.Interfaz, b.Comment)
		}
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
		comment := "auto-detect"
		if procName != "?" {
			comment = "auto-detect:" + procName
		}
		entry := fmt.Sprintf("%d | %s | %s | %s | %s", svc.Port, svc.Proto, tier, comment, time.Now().Format("2006-01-02"))
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
		resp := f.readLine(fmt.Sprintf(i18n.T("fw.wizard.seq_ask_port"), svc.Port, procName))
		if strings.ToLower(resp) != "s" {
			continue
		}

		// Preguntar tier
		tierResp := f.readLine(i18n.T("fw.wizard.seq_ask_tier") + " ")
		tier := "GEO"
		if strings.ToLower(tierResp) == "g" {
			tier = "GLOBAL"
		}

		comment := "auto-detect"
		if procName != "?" {
			comment = "auto-detect:" + procName
		}
		entry := fmt.Sprintf("%d | %s | %s | %s | %s", svc.Port, svc.Proto, tier, comment, time.Now().Format("2006-01-02"))
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
			fmt.Println("     " + i18n.T("fw.wizard.err_save"))
			fmt.Println("     " + i18n.T("fw.wizard.err_log_hint"))
			return false, err
		}
		fmt.Printf(i18n.T("fw.wizard.saved"), infra.AllowedPortsFile)
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
			label += i18n.T("fw.wizard.letsencrypt_hint")
		}
		options = append(options, label)
		serviceMap[label] = svc
	}

	// Loop de menú — si el usuario no selecciona nada, reintentar
	var selectedLabels []string
	for {
		selectedLabels = nil
		prompt := &survey.MultiSelect{
			Message: i18n.T("fw.wizard.prompt"),
			Options: options,
		}
		if err := survey.AskOne(prompt, &selectedLabels); err != nil {
			f.logger.Technical(fmt.Sprintf("survey error: %v", err))
			return false, err
		}
		if len(selectedLabels) > 0 {
			break
		}
		fmt.Println("  " + i18n.T("fw.wizard.no_selection"))
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
		fmt.Println(i18n.T("fw.wizard.ssh_warning"))
		fmt.Println(i18n.T("fw.wizard.ssh_closing"))
		fmt.Println(i18n.T("fw.wizard.ssh_lose_access"))
		fmt.Println(i18n.T("fw.wizard.ssh_perderas"))
		fmt.Println()
		readLine := func(prompt string) string {
			return f.readLine(prompt)
		}
		if !sys.ConfirmStrong(readLine, i18n.T("fw.wizard.ssh_confirm")+" ", "cerrar ssh") {
			fmt.Println("  " + i18n.T("fw.wizard.ssh_kept"))
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
		Message: i18n.T("fw.wizard.tier_question"),
		Options: []string{"GLOBAL", i18n.T("fw.wizard.tier_options")},
		Default: i18n.T("fw.wizard.tier_default"),
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
			fmt.Println("     " + i18n.T("fw.wizard.err_save"))
			fmt.Println("     " + i18n.T("fw.wizard.err_log_hint"))
			return false, err
		}
		fmt.Printf(i18n.T("fw.wizard.saved"), infra.AllowedPortsFile)
	}

	return sshEnabled, nil
}

// runServiceWizard dispatcher — selecciona entre menú interactivo o preguntas secuenciales.
func (f *Firewall) runServiceWizard() (bool, error) {
	fmt.Println(i18n.T("fw.wizard.detecting"))
	services, err := sys.DetectListeningServices()
	if err != nil {
		f.logger.Error("Error inesperado al detectar servicios.", fmt.Sprintf("%v", err))
		fmt.Println("     " + i18n.T("fw.wizard.err_log_hint"))
		return false, err
	}

	if len(services) == 0 {
		fmt.Println("  " + i18n.T("fw.wizard.no_services"))
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
