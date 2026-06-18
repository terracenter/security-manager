package geoip

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/terracenter/security-manager-ng/internal/modules/infra"
	"github.com/terracenter/security-manager-ng/internal/safeapply"
)

// GeoIP gestiona el acceso por país (ALLOWLIST) usando sets nftables nativos (sm_geoallow4/6).
// Fuente de rangos: ipdeny.com (zone files, un CIDR por línea).
type GeoIP struct {
	scanner *bufio.Scanner
}

func New() *GeoIP {
	return &GeoIP{scanner: bufio.NewScanner(os.Stdin)}
}

func (g *GeoIP) Order() int   { return 3 }
func (g *GeoIP) Name() string { return "GeoIP — países permitidos" }
func (g *GeoIP) Reset()       {}

func (g *GeoIP) Menu() {
	if _, err := os.Stat(infra.ConfDir + "/blocked_countries.conf"); err == nil {
		fmt.Println("\n  ⚠  AVISO: Se detectó blocked_countries.conf (formato GeoIP anterior — BLOCKLIST).")
		fmt.Println("     El módulo GeoIP ahora opera en modo ALLOWLIST (allowed_countries.conf).")
		fmt.Println("     Los países del archivo anterior eran BLOQUEADOS — contenido semánticamente opuesto.")
		fmt.Println("     Configura los países PERMITIDOS desde cero con [1].")
	}
	for {
		fmt.Println("\n  ┌─ GeoIP — Países permitidos ─────────────┐")
		fmt.Println("  │  [1] Agregar país a la lista             │")
		fmt.Println("  │  [2] Eliminar país de la lista           │")
		fmt.Println("  │  [3] Ver países permitidos               │")
		fmt.Println("  │  [4] Actualizar rangos (ipdeny.com)      │")
		fmt.Println("  │  [5] Aplicar / recargar ruleset          │")
		fmt.Println("  │  [?] Vista previa del ruleset            │")
		fmt.Println("  │  [0] Volver                              │")
		fmt.Println("  └─────────────────────────────────────────┘")
		fmt.Print("  Selección: ")

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
		case "?":
			g.previewRuleset()
		case "0":
			return
		default:
			fmt.Println("  Opción inválida.")
		}
	}
}

func (g *GeoIP) addCountry() {
	fmt.Print("\n  Código de país ISO 3166-1 alfa-2 a PERMITIR (ej: VE, CO, US): ")
	if !g.scanner.Scan() {
		return
	}
	cc := strings.ToUpper(strings.TrimSpace(g.scanner.Text()))
	if !validCC(cc) {
		fmt.Println("  ERROR: código inválido — usa 2 letras (ej: CN, RU).")
		return
	}
	countries, err := loadCountries()
	if err != nil {
		fmt.Printf("  ERROR leyendo config: %v\n", err)
		return
	}
	for _, c := range countries {
		if c == cc {
			fmt.Printf("  %s ya está en la lista.\n", cc)
			return
		}
	}
	countries = append(countries, cc)
	if err := saveCountries(countries); err != nil {
		fmt.Printf("  ERROR guardando config: %v\n", err)
		return
	}
	fmt.Printf("  %s agregado. Usa [4] para descargar rangos y [5] para aplicar.\n", cc)
}

func (g *GeoIP) removeCountry() {
	fmt.Print("\n  Código de país a eliminar: ")
	if !g.scanner.Scan() {
		return
	}
	cc := strings.ToUpper(strings.TrimSpace(g.scanner.Text()))
	countries, err := loadCountries()
	if err != nil {
		fmt.Printf("  ERROR leyendo config: %v\n", err)
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
		fmt.Printf("  %s no está en la lista.\n", cc)
		return
	}
	if err := saveCountries(updated); err != nil {
		fmt.Printf("  ERROR guardando config: %v\n", err)
		return
	}
	fmt.Printf("  %s eliminado. Usa [5] para recargar el ruleset.\n", cc)
}

func (g *GeoIP) listCountries() {
	countries, err := loadCountries()
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return
	}
	if len(countries) == 0 {
		fmt.Println("\n  Sin países en la lista de permitidos.")
		fmt.Println("  Usa [1] para agregar países y [4]+[5] para descargar rangos y aplicar.")
		return
	}
	fmt.Println("\n  Países PERMITIDOS (solo estos alcanzan SSH/443/ICMP):")
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
		fmt.Printf("  ERROR leyendo config: %v\n", err)
		return
	}
	if len(countries) == 0 {
		fmt.Println("  Sin países configurados. Agrega países con [1] primero.")
		return
	}
	if err := os.MkdirAll(infra.GeoIPDir, 0o750); err != nil {
		fmt.Printf("  ERROR creando %s: %v\n", infra.GeoIPDir, err)
		return
	}
	for _, cc := range countries {
		lower := strings.ToLower(cc)
		zone4 := infra.GeoIPDir + "/" + lower + ".zone"
		zone6 := infra.GeoIPDir + "/" + lower + ".zone6"

		fmt.Printf("  [%s] descargando IPv4...\n", cc)
		if err := downloadZone("https://www.ipdeny.com/ipblocks/data/countries/"+lower+".zone", zone4); err != nil {
			if _, existErr := os.Stat(zone4); existErr == nil {
				fmt.Printf("  [%s] IPv4 ⚠ %v — usando datos previos\n", cc, err)
			} else {
				fmt.Printf("  [%s] IPv4 ERROR: %v\n", cc, err)
			}
		} else {
			lines, _ := infra.ReadLines(zone4)
			fmt.Printf("  [%s] IPv4 OK (%d rangos)\n", cc, len(lines))
		}

		fmt.Printf("  [%s] descargando IPv6...\n", cc)
		if err := downloadZone("https://www.ipdeny.com/ipv6/ipaddresses/blocks/"+lower+".zone", zone6); err != nil {
			if _, existErr := os.Stat(zone6); existErr == nil {
				fmt.Printf("  [%s] IPv6 ⚠ %v — usando datos previos\n", cc, err)
			} else {
				fmt.Printf("  [%s] IPv6 ERROR: %v\n", cc, err)
			}
		} else {
			lines, _ := infra.ReadLines(zone6)
			fmt.Printf("  [%s] IPv6 OK (%d rangos)\n", cc, len(lines))
		}
	}
	fmt.Println("\n  Actualización completada. Usa [5] para aplicar el ruleset.")
}

func (g *GeoIP) previewRuleset() {
	geoip, err := infra.LoadGeoIPData()
	if err != nil {
		fmt.Printf("  ERROR cargando datos GeoIP: %v\n", err)
		return
	}
	sshPort := infra.DetectSSHPort()
	ruleset := infra.GenerateRuleset(sshPort, geoip)

	fmt.Println("\n  ┌─ Vista previa del ruleset (sm.nft) ─────┐")
	fmt.Println("  " + strings.Repeat("─", 42))
	for i, line := range strings.Split(ruleset, "\n") {
		if i < 50 {
			fmt.Printf("  %s\n", line)
		} else if i == 50 {
			fmt.Println("  ... (truncado para brevedad)")
			break
		}
	}
	fmt.Println("  " + strings.Repeat("─", 42))
	fmt.Println()
}

func (g *GeoIP) applyGeoIP() {
	geoip, err := infra.LoadGeoIPData()
	if err != nil {
		fmt.Printf("  ERROR cargando datos GeoIP: %v\n", err)
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
	sshPort := infra.DetectSSHPort()
	ruleset := infra.GenerateRuleset(sshPort, geoip)

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

	fmt.Println("\n  Validando sintaxis (nft -c)...")
	out, err := exec.Command("nft", "-c", "-f", tmpFile).CombinedOutput()
	if err != nil {
		fmt.Printf("  ERROR de sintaxis:\n%s\n", strings.TrimSpace(string(out)))
		return
	}
	fmt.Println("  Sintaxis OK.")

	// Backup del ruleset ACTUAL antes de sobreescribir.
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

func zoneStatus(path string) string {
	lines, err := infra.ReadLines(path)
	if err != nil {
		return "⚠ sin datos"
	}
	if strings.HasSuffix(path, ".zone6") {
		return fmt.Sprintf("✓ IPv6 (%d rangos)", len(lines))
	}
	return fmt.Sprintf("✓ IPv4 (%d rangos)", len(lines))
}

// _ ensures the interface is satisfied at compile time.
var _ interface {
	Order() int
	Name() string
	Menu()
	Reset()
} = (*GeoIP)(nil)
