package geoip

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/terracenter/security-manager-ng/internal/i18n"
	"github.com/terracenter/security-manager-ng/internal/modules/infra"
	"github.com/terracenter/security-manager-ng/internal/safeapply"
	"github.com/terracenter/security-manager-ng/internal/sys"
)

// GeoIP gestiona el acceso por país (ALLOWLIST) usando sets nftables nativos (sm_geoallow4/6).
// Fuente de rangos: ipdeny.com (zone files, un CIDR por línea).
type GeoIP struct {
	scanner *bufio.Scanner
	logger  *sys.SMLogger
}

func New(logger *sys.SMLogger) *GeoIP {
	return &GeoIP{scanner: bufio.NewScanner(os.Stdin), logger: logger}
}

func (g *GeoIP) Order() int   { return 3 }
func (g *GeoIP) Name() string { return "GeoIP — países permitidos" }

// Reset borra la config de países permitidos y los zone files descargados.
// Deliberadamente NO recarga el ruleset en caliente (a diferencia de resetGeoIP()/
// cliReset()): puede ejecutarse dentro de un Reset Global donde Firewall.Reset() ya
// borró el ruleset — forzar un reload aquí regeneraría un ruleset nuevo justo cuando
// el propósito es dejar todo limpio.
func (g *GeoIP) Reset() {
	if err := os.Remove(infra.AllowedCountriesFile); err == nil {
		fmt.Printf(i18n.T("geoip.reset.removed_file"), infra.AllowedCountriesFile)
	} else if os.IsNotExist(err) {
		fmt.Printf(i18n.T("geoip.reset.not_found"), infra.AllowedCountriesFile)
	} else {
		fmt.Printf(i18n.T("geoip.reset.warn_remove"), infra.AllowedCountriesFile, err)
	}

	// os.RemoveAll no distingue "no existía" de "existía y se borró" (ambos
	// retornan nil) — se verifica con Stat antes para no reportar "Eliminado"
	// sobre un directorio que nunca existió.
	_, statErr := os.Stat(infra.GeoIPDir)
	existed := statErr == nil
	if err := os.RemoveAll(infra.GeoIPDir); err != nil {
		fmt.Printf(i18n.T("geoip.reset.warn_remove"), infra.GeoIPDir, err)
	} else if existed {
		fmt.Printf(i18n.T("geoip.reset.removed_file"), infra.GeoIPDir)
	} else {
		fmt.Printf(i18n.T("geoip.reset.not_found"), infra.GeoIPDir)
	}
}

func (g *GeoIP) Menu() {
	if _, err := os.Stat(infra.ConfDir + "/blocked_countries.conf"); err == nil {
		fmt.Println(i18n.T("geoip.legacy.blocklist.header"))
		fmt.Println(i18n.T("geoip.legacy.blocklist.allowlist_note"))
		fmt.Println(i18n.T("geoip.legacy.blocklist.opposite"))
		fmt.Println(i18n.T("geoip.legacy.blocklist.reconfigure"))
	}
	for {
		fmt.Println(i18n.T("geoip.menu.header"))
		fmt.Println(i18n.T("geoip.menu.add"))
		fmt.Println(i18n.T("geoip.menu.del"))
		fmt.Println(i18n.T("geoip.menu.list"))
		fmt.Println(i18n.T("geoip.menu.update"))
		fmt.Println(i18n.T("geoip.menu.apply"))
		fmt.Println(i18n.T("geoip.menu.reset"))
		fmt.Println(i18n.T("geoip.menu.preview"))
		fmt.Println(i18n.T("fw.menu.back"))
		fmt.Println(i18n.T("geoip.menu.footer"))
		fmt.Print(i18n.T("fw.menu.prompt") + " ")

		if !g.scanner.Scan() {
			return
		}
		switch strings.TrimSpace(g.scanner.Text()) {
		case "1":
			g.addCountry()
		case "2":
			g.removeCountry()
		case "3":
			g.listCountries()
		case "4":
			g.updateRanges()
		case "5":
			g.applyGeoIP()
		case "6":
			g.resetGeoIP()
		case "?":
			g.previewRuleset()
		case "0":
			return
		default:
			fmt.Println(i18n.T("fw.invalid.option"))
		}
	}
}

func (g *GeoIP) addCountry() {
	fmt.Print("\n  Código(s) de país ISO 3166-1 alfa-2 a PERMITIR (ej: VE, CO, PE, DO): ")
	if !g.scanner.Scan() {
		return
	}

	var toAdd []string
	for _, raw := range strings.Split(g.scanner.Text(), ",") {
		cc := strings.ToUpper(strings.TrimSpace(raw))
		if cc == "" {
			continue
		}
		if !validCC(cc) {
			fmt.Printf(i18n.T("geoip.err.bad_cc"), cc)
			return
		}
		toAdd = append(toAdd, cc)
	}
	if len(toAdd) == 0 {
		fmt.Println(i18n.T("geoip.err.no_cc"))
		return
	}

	countries, err := loadCountries()
	if err != nil {
		fmt.Printf(i18n.T("geoip.err.read_config"), err)
		return
	}

	existing := make(map[string]bool)
	for _, c := range countries {
		existing[c] = true
	}

	var added []string
	for _, cc := range toAdd {
		if existing[cc] {
			fmt.Printf(i18n.T("geoip.add.already_present"), cc)
			continue
		}
		countries = append(countries, cc)
		existing[cc] = true
		added = append(added, cc)
	}

	if len(added) == 0 {
		fmt.Println(i18n.T("geoip.add.no_changes"))
		return
	}

	if err := saveCountries(countries); err != nil {
		fmt.Printf(i18n.T("geoip.err.save_config"), err)
		return
	}

	fmt.Printf(i18n.T("geoip.add.success"), strings.Join(added, ", "))
	fmt.Println(i18n.T("geoip.add.whitelist_warning"))
	fmt.Println(i18n.T("geoip.update.downloading"))
	g.updateRanges()
	fmt.Println(i18n.T("geoip.update.applying"))
	g.applyGeoIPCore()
}

func (g *GeoIP) removeCountry() {
	fmt.Print("\n  Código de país a eliminar: ")
	if !g.scanner.Scan() {
		return
	}
	cc := strings.ToUpper(strings.TrimSpace(g.scanner.Text()))
	countries, err := loadCountries()
	if err != nil {
		fmt.Printf(i18n.T("geoip.err.read_config"), err)
		return
	}
	var updated []string
	found := false
	for _, c := range countries {
		if c == cc {
			found = true
			continue
		}
		updated = append(updated, c)
	}
	if !found {
		fmt.Printf(i18n.T("geoip.del.not_present"), cc)
		return
	}
	if err := saveCountries(updated); err != nil {
		fmt.Printf(i18n.T("geoip.err.save_config"), err)
		return
	}
	fmt.Printf(i18n.T("geoip.del.success"), cc)
}

func (g *GeoIP) listCountries() {
	countries, err := loadCountries()
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return
	}
	if len(countries) == 0 {
		fmt.Println(i18n.T("geoip.list.empty"))
		fmt.Println(i18n.T("geoip.list.hint"))
		return
	}
	fmt.Println(i18n.T("geoip.list.header"))
	fmt.Println(i18n.T("geoip.list.date_hint"))
	fmt.Println()
	for _, cc := range countries {
		lower := strings.ToLower(cc)
		s4 := zoneStatus(infra.GeoIPDir + "/" + lower + ".zone")
		s6 := zoneStatus(infra.GeoIPDir + "/" + lower + ".zone6")
		fmt.Printf("  %-4s  %s  %s\n", cc, s4, s6)
	}
}

func (g *GeoIP) updateRanges() {
	countries, err := loadCountries()
	if err != nil {
		fmt.Printf(i18n.T("geoip.err.read_config"), err)
		return
	}
	if len(countries) == 0 {
		fmt.Println(i18n.T("geoip.list.empty_hint"))
		return
	}
	if err := os.MkdirAll(infra.GeoIPDir, 0o750); err != nil {
		fmt.Printf(i18n.T("geoip.update.err_create_dir"), infra.GeoIPDir, err)
		return
	}
	for _, cc := range countries {
		lower := strings.ToLower(cc)
		zone4 := infra.GeoIPDir + "/" + lower + ".zone"
		zone6 := infra.GeoIPDir + "/" + lower + ".zone6"

		fmt.Printf(i18n.T("geoip.update.dl_v4"), cc)
		if err := downloadZone("https://www.ipdeny.com/ipblocks/data/countries/"+lower+".zone", zone4); err != nil {
			if _, existErr := os.Stat(zone4); existErr == nil {
				fmt.Printf(i18n.T("geoip.update.warn_v4"), cc, err)
			} else {
				fmt.Printf(i18n.T("geoip.update.err_v4"), cc, err)
			}
		} else {
			lines, _ := infra.ReadLines(zone4)
			fmt.Printf(i18n.T("geoip.update.ok_v4"), cc, len(lines))
		}

		fmt.Printf(i18n.T("geoip.update.dl_v6"), cc)
		if err := downloadZone("https://www.ipdeny.com/ipv6/ipaddresses/blocks/"+lower+".zone", zone6); err != nil {
			if _, existErr := os.Stat(zone6); existErr == nil {
				fmt.Printf(i18n.T("geoip.update.warn_v6"), cc, err)
			} else {
				fmt.Printf(i18n.T("geoip.update.err_v6"), cc, err)
			}
		} else {
			lines, _ := infra.ReadLines(zone6)
			fmt.Printf(i18n.T("geoip.update.ok_v6"), cc, len(lines))
		}
	}
	fmt.Println(i18n.T("geoip.update.complete"))
}

func (g *GeoIP) previewRuleset() {
	geoip, err := infra.LoadGeoIPData()
	if err != nil {
		fmt.Printf(i18n.T("geoip.update.err_load"), err)
		return
	}
	sshPort := infra.DetectSSHPort()
	port80, _ := infra.ReadPort80Option()
	ruleset := infra.GenerateRuleset(sshPort, true, geoip, port80)

	fmt.Println(i18n.T("geoip.preview.header"))
	fmt.Println(i18n.T("fw.cli.ports_sep") + strings.Repeat("─", 42))
	for _, line := range strings.Split(ruleset, "\n") {
		fmt.Printf("  %s\n", line)
	}
	fmt.Println(i18n.T("fw.cli.ports_sep") + strings.Repeat("─", 42))
	fmt.Println()
}

// applyGeoIPCore genera, valida sintaxis y aplica el ruleset GeoIP sin confirmaciones interactivas.
// Llamar desde flujos automáticos (resetGeoIP, addCountry). Para uso manual usar applyGeoIP().
func (g *GeoIP) applyGeoIPCore() {
	geoip, err := infra.LoadGeoIPData()
	if err != nil {
		fmt.Printf(i18n.T("geoip.update.err_load"), err)
		return
	}
	sshPort := infra.DetectSSHPort()
	port80, _ := infra.ReadPort80Option()
	ruleset := infra.GenerateRuleset(sshPort, true, geoip, port80)

	if err := os.MkdirAll(infra.ConfDir, 0o750); err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return
	}

	tmpFile := infra.ConfDir + "/sm.nft.new"
	if err := os.WriteFile(tmpFile, []byte(ruleset), 0o640); err != nil {
		fmt.Printf("  ERROR escribiendo ruleset: %v\n", err)
		return
	}
	defer os.Remove(tmpFile)

	fmt.Println("  Validando sintaxis (nft -c)...")
	out, err := exec.Command("nft", "-c", "-f", tmpFile).CombinedOutput()
	if err != nil {
		g.logger.Error("Error de sintaxis en el ruleset GeoIP generado.", strings.TrimSpace(string(out)))
		return
	}
	fmt.Println("  Sintaxis OK.")

	if cur, readErr := os.ReadFile(infra.RulesetFile); readErr == nil {
		_ = os.WriteFile(infra.BackupFile, cur, 0o640)
		fmt.Printf("  [geoip] Backup: %s → %s\n", infra.RulesetFile, infra.BackupFile)
	}

	if err := os.Rename(tmpFile, infra.RulesetFile); err != nil {
		fmt.Printf("  ERROR moviendo ruleset: %v\n", err)
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
		fmt.Printf("\n  [geoip] %v\n", err)
	}
}

func (g *GeoIP) applyGeoIP() {
	geoip, err := infra.LoadGeoIPData()
	if err != nil {
		fmt.Printf(i18n.T("geoip.update.err_load"), err)
		return
	}
	if len(geoip.Countries) == 0 {
		fmt.Println("\n  ⚠  AVISO: No hay países en la lista de permitidos.")
		fmt.Println("     El ruleset se aplicará sin restricción geográfica (todo el tráfico pasa el stage 7).")
		fmt.Println("     Usa [1] para agregar países y [4] para descargar sus rangos.")
		fmt.Print("\n  ¿Continuar de todas formas? [s/N]: ")
		if !g.scanner.Scan() {
			return
		}
		if strings.ToLower(strings.TrimSpace(g.scanner.Text())) != "s" {
			fmt.Println("  Cancelado.")
			return
		}
	}

	fmt.Println("\n  ⚠️  IMPORTANTE: ¿Whitelisteaste tu IP/red antes de aplicar GeoIP?")
	fmt.Println("     Si tu país no está en la lista de permitidos, GeoIP puede bloquear tu SSH.")
	fmt.Print("  ¿Continuar? [s/N]: ")
	if !g.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(g.scanner.Text())) != "s" {
		fmt.Println("  Cancelado.")
		return
	}

	g.applyGeoIPCore()
}

func (g *GeoIP) resetGeoIP() {
	fmt.Println("\n  ⚠  RESET GeoIP: borra lista de países, zone files y recarga ruleset sin restricción geográfica.")
	fmt.Print("  ¿Confirmar reset? [s/N]: ")
	if !g.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(g.scanner.Text())) != "s" {
		fmt.Println("  Cancelado.")
		return
	}

	// Borrar lista de países
	if err := os.Remove(infra.AllowedCountriesFile); err != nil && !os.IsNotExist(err) {
		fmt.Printf("  ERROR borrando lista de países: %v\n", err)
		return
	}
	fmt.Println("  Lista de países borrada.")

	// Borrar zone files
	entries, err := os.ReadDir(infra.GeoIPDir)
	if err != nil && !os.IsNotExist(err) {
		fmt.Printf("  ERROR leyendo directorio GeoIP: %v\n", err)
		return
	}
	removed := 0
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".zone") || strings.HasSuffix(name, ".zone6") {
			_ = os.Remove(infra.GeoIPDir + "/" + name)
			removed++
		}
	}
	fmt.Printf("  Zone files eliminados: %d\n", removed)

	// Recargar ruleset sin GeoIP (stage 7 sin restricción)
	fmt.Println("  Recargando ruleset sin restricción geográfica...")
	g.applyGeoIPCore()
}

func validCC(cc string) bool {
	if len(cc) != 2 {
		return false
	}
	for _, r := range cc {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

func loadCountries() ([]string, error) {
	f, err := os.Open(infra.AllowedCountriesFile)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var countries []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			countries = append(countries, line)
		}
	}
	return countries, sc.Err()
}

func saveCountries(countries []string) error {
	var sb strings.Builder
	sb.WriteString("# Países PERMITIDOS — Security-Manager-NG GeoIP (ALLOWLIST)\n")
	sb.WriteString("# Un código ISO 3166-1 alfa-2 por línea\n")
	for _, cc := range countries {
		sb.WriteString(cc + "\n")
	}
	return os.WriteFile(infra.AllowedCountriesFile, []byte(sb.String()), 0o640)
}

func downloadZone(url, dest string) error {
	tmp := dest + ".tmp"
	defer os.Remove(tmp)

	out, err := exec.Command(
		"curl", "-fsSL", "--retry", "2", "--max-time", "30", "-o", tmp, url,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("curl: %s", strings.TrimSpace(string(out)))
	}
	if err := validateZoneFile(tmp); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}

func validateZoneFile(path string) error {
	lines, err := infra.ReadLines(path)
	if err != nil {
		return fmt.Errorf("no se pudo leer el archivo descargado: %w", err)
	}
	if len(lines) == 0 {
		return fmt.Errorf("descarga vacía (0 entradas)")
	}
	for _, line := range lines {
		if _, _, err := net.ParseCIDR(line); err == nil {
			return nil
		}
	}
	return fmt.Errorf("descarga sin CIDRs válidos (%d líneas)", len(lines))
}

// zoneStatus devuelve un string con count de rangos + fecha de modificacion
// del zone file. Si el archivo no existe, devuelve "sin datos".
func zoneStatus(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "⚠ sin datos"
	}
	lines, err := infra.ReadLines(path)
	if err != nil {
		return fmt.Sprintf("⚠ error leyendo (%v)", err)
	}
	date := info.ModTime().Format("2006-01-02")
	if strings.HasSuffix(path, ".zone6") {
		return fmt.Sprintf("✓ IPv6 (%d rangos, %s)", len(lines), date)
	}
	return fmt.Sprintf("✓ IPv4 (%d rangos, %s)", len(lines), date)
}

// RunAction implementa modules.CLIModule para modo no interactivo.
//
//	add <CC...>    Agregar países a la lista de permitidos (ej: VE CO PE)
//	del <CC>       Eliminar país de la lista
//	list           Ver países configurados
//	update         Descargar rangos desde ipdeny.com
//	apply          Aplicar / recargar ruleset GeoIP
//	reset          Resetear GeoIP (borra lista y zone files)
//	preview        Ver vista previa del ruleset generado
func (g *GeoIP) RunAction(action string, args ...string) bool {
	switch strings.ToLower(action) {
	case "add", "agregar":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "  Uso: geoip add <CC...>  (ej: geoip add VE CO PE)")
			return false
		}
		return g.cliAdd(args)
	case "del", "delete", "eliminar":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "  Uso: geoip del <CC>")
			return false
		}
		return g.cliDel(args[0])
	case "list", "listar":
		g.listCountries()
		return true
	case "update", "actualizar":
		g.updateRanges()
		return true
	case "apply", "aplicar":
		fmt.Println("  [cli] Aplicando ruleset GeoIP sin confirmación interactiva...")
		g.applyGeoIPCore()
		return true
	case "reset", "resetear":
		fmt.Println("  [cli] Reseteando GeoIP sin confirmación interactiva...")
		return g.cliReset()
	case "preview", "vista-previa":
		g.previewRuleset()
		return true
	default:
		fmt.Fprintf(os.Stderr, "  Acción '%s' no reconocida.\n", action)
		fmt.Fprintln(os.Stderr, "  Acciones: add <CC...>, del <CC>, list, update, apply, reset, preview")
		return false
	}
}

func (g *GeoIP) cliAdd(codes []string) bool {
	countries, err := loadCountries()
	if err != nil {
		fmt.Fprintf(os.Stderr, i18n.T("geoip.err.read_config"), err)
		return false
	}
	existing := make(map[string]bool)
	for _, c := range countries {
		existing[c] = true
	}
	var added []string
	for _, raw := range codes {
		cc := strings.ToUpper(strings.TrimSpace(raw))
		if !validCC(cc) {
			fmt.Fprintf(os.Stderr, i18n.T("geoip.err.bad_cc"), cc)
			return false
		}
		if existing[cc] {
			fmt.Printf(i18n.T("geoip.add.already_present"), cc)
			continue
		}
		countries = append(countries, cc)
		existing[cc] = true
		added = append(added, cc)
	}
	if len(added) == 0 {
		fmt.Println("  Sin cambios.")
		return true
	}
	if err := saveCountries(countries); err != nil {
		fmt.Fprintf(os.Stderr, i18n.T("geoip.err.save_config"), err)
		return false
	}
	fmt.Printf("  Agregado(s): %s\n", strings.Join(added, ", "))
	fmt.Println("  Descargando rangos...")
	g.updateRanges()
	fmt.Println("  Aplicando ruleset...")
	g.applyGeoIPCore()
	return true
}

func (g *GeoIP) cliDel(cc string) bool {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	countries, err := loadCountries()
	if err != nil {
		fmt.Fprintf(os.Stderr, i18n.T("geoip.err.read_config"), err)
		return false
	}
	var updated []string
	found := false
	for _, c := range countries {
		if c == cc {
			found = true
			continue
		}
		updated = append(updated, c)
	}
	if !found {
		fmt.Fprintf(os.Stderr, i18n.T("geoip.del.not_present"), cc)
		return false
	}
	if err := saveCountries(updated); err != nil {
		fmt.Fprintf(os.Stderr, i18n.T("geoip.err.save_config"), err)
		return false
	}
	fmt.Printf("  %s eliminado. Aplicando ruleset...\n", cc)
	g.applyGeoIPCore()
	return true
}

func (g *GeoIP) cliReset() bool {
	if err := os.Remove(infra.AllowedCountriesFile); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "  ERROR borrando lista de países: %v\n", err)
		return false
	}
	entries, err := os.ReadDir(infra.GeoIPDir)
	if err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "  ERROR leyendo directorio GeoIP: %v\n", err)
		return false
	}
	removed := 0
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".zone") || strings.HasSuffix(name, ".zone6") {
			_ = os.Remove(infra.GeoIPDir + "/" + name)
			removed++
		}
	}
	fmt.Printf("  Zone files eliminados: %d\n", removed)
	fmt.Println("  Recargando ruleset sin restricción geográfica...")
	g.applyGeoIPCore()
	return true
}

// _ ensures the interface is satisfied at compile time.
var _ interface {
	Order() int
	Name() string
	Menu()
	Reset()
} = (*GeoIP)(nil)
