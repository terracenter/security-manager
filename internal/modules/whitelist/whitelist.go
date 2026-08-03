package whitelist

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/terracenter/security-manager-ng/internal/modules/crowdsec"
	"github.com/terracenter/security-manager-ng/internal/modules/infra"
	"github.com/terracenter/security-manager-ng/internal/sys"
)

type Whitelist struct {
	scanner *bufio.Scanner
}

func New() *Whitelist {
	return &Whitelist{scanner: bufio.NewScanner(os.Stdin)}
}

func (w *Whitelist) Order() int   { return 2 }
func (w *Whitelist) Name() string { return "Whitelist / SSoT (Confiables / Intocables)" }

// Reset borra la whitelist/immune (Tier A/B) y el jail.d de fail2ban derivado de ella.
func (w *Whitelist) Reset() {
	for _, path := range []string{infra.Whitelist4File, infra.Whitelist6File, infra.Immune4File, infra.Immune6File} {
		if err := os.Remove(path); err == nil {
			fmt.Printf("  Eliminado: %s\n", path)
		} else if os.IsNotExist(err) {
			fmt.Printf("  No había %s.\n", path)
		} else {
			fmt.Printf("  ADVERTENCIA: no se pudo eliminar %s: %v\n", path, err)
		}
	}
	if err := os.Remove(fail2banIgnoreipFile); err == nil {
		fmt.Printf("  Eliminado: %s\n", fail2banIgnoreipFile)
		if out, err := exec.Command("fail2ban-client", "reload").CombinedOutput(); err != nil {
			fmt.Printf("  ADVERTENCIA: fail2ban-client reload falló: %s\n", strings.TrimSpace(string(out)))
		} else {
			fmt.Println("  fail2ban recargado.")
		}
	} else if os.IsNotExist(err) {
		fmt.Printf("  No había %s.\n", fail2banIgnoreipFile)
	} else {
		fmt.Printf("  ADVERTENCIA: no se pudo eliminar %s: %v\n", fail2banIgnoreipFile, err)
	}
}

// tier parametriza cada nivel de confianza para reusar add/list/delete.
type tier struct {
	label  string
	set4   string
	set6   string
	file4  string
	file6  string
	immune bool // Tier B → se sincroniza a fail2ban ignoreip
}

func tierA() tier {
	return tier{
		label:  "Confiables (Tier A — vigiladas por fail2ban)",
		set4:   infra.SetWhitelist4, set6: infra.SetWhitelist6,
		file4: infra.Whitelist4File, file6: infra.Whitelist6File,
		immune: false,
	}
}

func tierB() tier {
	return tier{
		label:  "Intocables (Tier B — fail2ban ignoreip)",
		set4:   infra.SetImmune4, set6: infra.SetImmune6,
		file4: infra.Immune4File, file6: infra.Immune6File,
		immune: true,
	}
}

func (w *Whitelist) Menu() {
	for {
		fmt.Println("\n  ┌─ Whitelist / SSoT ─────────────────────────────┐")
		fmt.Println("  │  [1] Confiables (Tier A) — fail2ban SÍ vigila   │")
		fmt.Println("  │  [2] Intocables (Tier B) — fail2ban JAMÁS banea │")
		fmt.Println("  │  [3] Sincronizar fail2ban (Tier B → ignoreip)   │")
		fmt.Println("  │  [0] Volver                                     │")
		fmt.Println("  └─────────────────────────────────────────────────┘")
		fmt.Print("  Selección: ")

		if !w.scanner.Scan() {
			return
		}
		switch strings.TrimSpace(w.scanner.Text()) {
		case "1":
			w.tierMenu(tierA())
		case "2":
			w.tierMenu(tierB())
		case "3":
			SyncImmuneTier()
		case "0":
			return
		default:
			fmt.Println("  Opción inválida.")
		}
	}
}

func (w *Whitelist) tierMenu(t tier) {
	for {
		fmt.Printf("\n  ┌─ %s\n", t.label)
		fmt.Println("  │  [1] Agregar IP/CIDR")
		fmt.Println("  │  [2] Agregar mi IP (sesión SSH activa)")
		fmt.Println("  │  [3] Listar")
		fmt.Println("  │  [4] Eliminar")
		fmt.Println("  │  [0] Volver")
		fmt.Print("  Selección: ")

		if !w.scanner.Scan() {
			return
		}
		switch strings.TrimSpace(w.scanner.Text()) {
		case "1":
			w.addIP(t)
		case "2":
			w.addSelf(t)
		case "3":
			w.listIPs(t)
		case "4":
			w.deleteIP(t)
		case "0":
			return
		default:
			fmt.Println("  Opción inválida.")
		}
	}
}

// prompt lee una línea de entrada con un mensaje.
func (w *Whitelist) prompt(msg string) string {
	fmt.Print(msg)
	if !w.scanner.Scan() {
		return ""
	}
	return strings.TrimSpace(w.scanner.Text())
}

// promptMetadata captura los metadatos de auditoría de la entrada.
func (w *Whitelist) promptMetadata() (responsable, proposito, vencimiento string) {
	responsable = w.prompt("  Responsable: ")
	proposito = w.prompt("  Propósito: ")
	vencimiento = w.prompt("  Vencimiento (YYYY-MM-DD, vacío = permanente): ")
	return
}

func (w *Whitelist) addIP(t tier) {
	entry := w.prompt("\n  IP o CIDR a agregar (ej: 192.168.1.0/24 o 2001:db8::1): ")
	if entry == "" {
		fmt.Println("  Entrada vacía. Cancelado.")
		return
	}
	w.persist(t, entry)
}

func (w *Whitelist) addSelf(t tier) {
	ip := sys.GetSSHIP()
	if ip == "" {
		fmt.Println("\n  No se detectó sesión SSH activa (SSH_CLIENT vacío y 'w' sin resultados).")
		fmt.Println("  Usa [1] para agregar tu IP manualmente.")
		return
	}
	entry := ip
	// Sugerir CIDR de red si es una IPv4 individual.
	if cidr := suggestCIDR(ip); cidr != "" {
		fmt.Printf("\n  IP detectada: %s\n", ip)
		fmt.Printf("  [1] Solo esta IP (%s/32)\n", ip)
		fmt.Printf("  [2] Toda la red (%s)\n", cidr)
		switch w.prompt("  Selección [1]: ") {
		case "2":
			entry = cidr
		default:
			// dejar la IP individual tal cual
		}
	} else {
		fmt.Printf("\n  IP detectada: %s\n", ip)
	}
	w.persist(t, entry)
}

// persist valida la entrada, captura metadatos, la agrega al set nft y al archivo,
// y sincroniza fail2ban si el tier es intocable.
func (w *Whitelist) persist(t tier, addr string) {
	setName, confFile, err := t.resolve(addr)
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return
	}
	resp, prop, venc := w.promptMetadata()
	e := infra.ACLEntry{
		Addr:        addr,
		Responsable: resp,
		Proposito:   prop,
		FechaAlta:   time.Now().Format("2006-01-02"),
		Vencimiento: venc,
	}
	if err := nftAddElement(setName, addr); err != nil {
		fmt.Printf("  ERROR al agregar al set nft: %v\n", err)
		fmt.Println("  (¿Aplicaste el ruleset base con el set actualizado? Firewall [1])")
		return
	}
	if err := appendEntry(confFile, e); err != nil {
		fmt.Printf("  ADVERTENCIA: no se pudo persistir en %s: %v\n", confFile, err)
	}
	fmt.Printf("  Agregado %s → %s\n", addr, setName)
	if t.immune {
		SyncImmuneTier()
	}
}

func (w *Whitelist) listIPs(t tier) {
	fmt.Printf("\n  %s\n", t.label)
	total := 0
	for _, f := range []string{t.file4, t.file6} {
		entries, _ := infra.ReadACLEntries(f)
		for _, e := range entries {
			if total == 0 {
				fmt.Printf("\n  %-22s %-18s %-24s %-12s %s\n",
					"IP/CIDR", "Responsable", "Propósito", "Alta", "Vence")
				fmt.Println("  " + strings.Repeat("─", 88))
			}
			venc := e.Vencimiento
			if venc == "" {
				venc = "permanente"
			}
			fmt.Printf("  %-22s %-18s %-24s %-12s %s\n",
				e.Addr, e.Responsable, e.Proposito, e.FechaAlta, venc)
			total++
		}
	}
	if total == 0 {
		fmt.Println("\n  Sin entradas.")
	}
}

func (w *Whitelist) deleteIP(t tier) {
	addr := w.prompt("\n  IP o CIDR a eliminar: ")
	if addr == "" {
		fmt.Println("  Entrada vacía. Cancelado.")
		return
	}
	setName, confFile, err := t.resolve(addr)
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return
	}
	if strings.ToLower(w.prompt(fmt.Sprintf("  Eliminar %s de %s. ¿Confirmar? [s/N]: ", addr, setName))) != "s" {
		fmt.Println("  Cancelado.")
		return
	}
	if err := nftDeleteElement(setName, addr); err != nil {
		fmt.Printf("  ERROR al eliminar del set nft: %v\n", err)
		return
	}
	if err := removeByAddr(confFile, addr); err != nil {
		fmt.Printf("  ADVERTENCIA: no se pudo actualizar %s: %v\n", confFile, err)
	}
	fmt.Printf("  Eliminado %s de %s\n", addr, setName)
	if t.immune {
		SyncImmuneTier()
	}
}

// resolve clasifica addr como IPv4 o IPv6 y retorna el set nftables y el archivo del tier.
func (t tier) resolve(addr string) (setName, confFile string, err error) {
	v4, err := isV4(addr)
	if err != nil {
		return "", "", err
	}
	if v4 {
		return t.set4, t.file4, nil
	}
	return t.set6, t.file6, nil
}

// isV4 valida addr (IP o CIDR) y reporta si es IPv4.
func isV4(addr string) (bool, error) {
	if strings.Contains(addr, "/") {
		ip, _, parseErr := net.ParseCIDR(addr)
		if parseErr != nil {
			return false, fmt.Errorf("CIDR inválido %q: %w", addr, parseErr)
		}
		return ip.To4() != nil, nil
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return false, fmt.Errorf("dirección IP inválida: %q", addr)
	}
	return ip.To4() != nil, nil
}

// suggestCIDR devuelve la red /24 de una IPv4 individual, o "" si no aplica.
func suggestCIDR(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	return ""
}

func nftAddElement(setName, entry string) error {
	out, err := exec.Command(
		"nft", "add", "element", "inet", "sm", setName,
		fmt.Sprintf("{ %s }", entry),
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft add element %s { %s }: %s", setName, entry, strings.TrimSpace(string(out)))
	}
	return nil
}

func nftDeleteElement(setName, entry string) error {
	out, err := exec.Command(
		"nft", "delete", "element", "inet", "sm", setName,
		fmt.Sprintf("{ %s }", entry),
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft delete element %s { %s }: %s", setName, entry, strings.TrimSpace(string(out)))
	}
	return nil
}

// appendEntry agrega la entrada (con metadatos) si su dirección no existe ya.
func appendEntry(path string, e infra.ACLEntry) error {
	existing, _ := infra.ReadACLEntries(path)
	for _, ex := range existing {
		if ex.Addr == e.Addr {
			return nil
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, e.String())
	return err
}

// removeByAddr elimina del archivo la entrada cuya dirección coincide.
func removeByAddr(path, addr string) error {
	entries, err := infra.ReadACLEntries(path)
	if err != nil {
		return err
	}
	var updated []string
	for _, e := range entries {
		if e.Addr != addr {
			updated = append(updated, e.String())
		}
	}
	if len(updated) == 0 {
		return os.WriteFile(path, []byte(""), 0o640)
	}
	return os.WriteFile(path, []byte(strings.Join(updated, "\n")+"\n"), 0o640)
}

const fail2banIgnoreipFile = "/etc/fail2ban/jail.d/sm-ng-whitelist.conf"

// syncFail2banIgnoreipLegacy escribe SOLO las IPs intocables (Tier B) en fail2ban ignoreip
// y recarga. El Tier A (confiables/vigiladas) NO va a ignoreip — fail2ban puede banearlas.
// Fallo no es fatal. Esta función es el fallback cuando CrowdSec no está instalado.
func syncFail2banIgnoreipLegacy() {
	im4 := infra.ACLAddresses(mustEntries(infra.Immune4File))
	im6 := infra.ACLAddresses(mustEntries(infra.Immune6File))
	all := append(im4, im6...)

	if len(all) == 0 {
		os.Remove(fail2banIgnoreipFile)
		exec.Command("fail2ban-client", "reload").Run()
		fmt.Println("  ✓  fail2ban ignoreip vaciado (sin intocables Tier B).")
		return
	}

	content := fmt.Sprintf(
		"# Generado por Security-Manager-NG — Intocables (Tier B). NO editar manualmente.\n"+
			"[DEFAULT]\nignoreip = %s\n", strings.Join(all, " "))
	if err := os.WriteFile(fail2banIgnoreipFile, []byte(content), 0o640); err != nil {
		fmt.Printf("  ⚠  fail2ban ignoreip: no se pudo escribir %s: %v\n", fail2banIgnoreipFile, err)
		return
	}
	exec.Command("fail2ban-client", "reload").Run()
	fmt.Printf("  ✓  fail2ban ignoreip sincronizado (%d intocables Tier B).\n", len(all))
}

// SyncImmuneTier sincroniza el tier IMMUNE (intocables) a CrowdSec o fail2ban según disponibilidad.
// - Si CrowdSec está instalado: sincroniza vía CrowdSec allowlist
// - Si fail2ban está instalado (sin CrowdSec): sincroniza vía fail2ban ignoreip
// - Si ninguno está disponible: retorna error no-bloqueante (log warning)
func SyncImmuneTier() error {
	immuneFiles := []string{infra.Immune4File, infra.Immune6File}

	if crowdsec.IsInstalled() {
		fmt.Println("  Sincronizando IMMUNE tier a CrowdSec...")
		if err := crowdsec.SyncAllowlist(immuneFiles); err != nil {
			fmt.Printf("  ⚠  Error sincronizando CrowdSec: %v\n", err)
			// No retornar error bloqueante
		} else {
			fmt.Println("  ✓  IMMUNE tier sincronizado a CrowdSec.")
		}
		// FIX P2.1: limpiar IPs obsoletas del allowlist de CrowdSec.
		// Sin esto, el allowlist acumula entradas para siempre.
		if err := crowdsec.RemoveFromAllowlist(immuneFiles); err != nil {
			fmt.Printf("  ⚠  Error limpiando allowlist CrowdSec: %v\n", err)
		}
		return nil
	}

	// Fallback a fail2ban si CrowdSec no está disponible
	if isFail2banInstalled() {
		syncFail2banIgnoreipLegacy()
		return nil
	}

	// Si ninguno está disponible, retornar error no-bloqueante
	fmt.Println("  ⚠  Advertencia: ni CrowdSec ni fail2ban están instalados. IMMUNE tier no sincronizado.")
	return nil
}

// isFail2banInstalled verifica si fail2ban está disponible en el sistema.
func isFail2banInstalled() bool {
	cmd := exec.Command("which", "fail2ban-client")
	err := cmd.Run()
	return err == nil
}

func mustEntries(path string) []infra.ACLEntry {
	e, _ := infra.ReadACLEntries(path)
	return e
}

// RunAction implementa modules.CLIModule para modo no interactivo.
//
//	add <ip> --tier A|B [--responsable R] [--proposito P] [--vencimiento YYYY-MM-DD]
//	add-self --tier A|B
//	list [--tier A|B]
//	del <ip> --tier A|B
//	sync
func (w *Whitelist) RunAction(action string, args ...string) bool {
	switch strings.ToLower(action) {
	case "add", "agregar":
		return w.cliAdd(args)
	case "add-self", "add-auto":
		return w.cliAddSelf(args)
	case "list", "listar":
		return w.cliList(args)
	case "del", "delete", "eliminar":
		return w.cliDel(args)
	case "sync", "sincronizar":
		SyncImmuneTier()
		return true
	default:
		fmt.Fprintf(os.Stderr, "  Acción '%s' no reconocida.\n", action)
		fmt.Fprintln(os.Stderr, "  Acciones: add <ip> --tier A|B [...], add-self --tier A|B, list [--tier A|B], del <ip> --tier A|B, sync")
		return false
	}
}

func (w *Whitelist) cliAdd(args []string) bool {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "  Uso: whitelist add <ip> --tier A|B [--responsable R] [--proposito P] [--vencimiento YYYY-MM-DD]")
		return false
	}
	addr := args[0]
	fs := flag.NewFlagSet("whitelist add", flag.ContinueOnError)
	tierFlag := fs.String("tier", "", "Tier: A (confiable, fail2ban vigila) | B (intocable, fail2ban ignora)")
	responsable := fs.String("responsable", "", "Responsable de la entrada")
	proposito := fs.String("proposito", "", "Propósito / descripción")
	vencimiento := fs.String("vencimiento", "", "Fecha de vencimiento YYYY-MM-DD (vacío = permanente)")
	if err := fs.Parse(args[1:]); err != nil {
		return false
	}
	t, ok := w.parseTier(*tierFlag)
	if !ok {
		return false
	}
	setName, confFile, err := t.resolve(addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ERROR: %v\n", err)
		return false
	}
	e := infra.ACLEntry{
		Addr:        addr,
		Responsable: *responsable,
		Proposito:   *proposito,
		FechaAlta:   time.Now().Format("2006-01-02"),
		Vencimiento: *vencimiento,
	}
	if err := nftAddElement(setName, addr); err != nil {
		fmt.Fprintf(os.Stderr, "  ERROR al agregar al set nft: %v\n", err)
		return false
	}
	if err := appendEntry(confFile, e); err != nil {
		fmt.Printf("  ADVERTENCIA: no se pudo persistir en %s: %v\n", confFile, err)
	}
	fmt.Printf("  Agregado %s → %s\n", addr, setName)
	if t.immune {
		SyncImmuneTier()
	}
	return true
}

func (w *Whitelist) cliAddSelf(args []string) bool {
	fs := flag.NewFlagSet("whitelist add-self", flag.ContinueOnError)
	tierFlag := fs.String("tier", "", "Tier: A | B")
	if err := fs.Parse(args); err != nil {
		return false
	}
	if _, ok := w.parseTier(*tierFlag); !ok {
		return false
	}
	ip := sys.GetSSHIP()
	if ip == "" {
		fmt.Fprintln(os.Stderr, "  No se detectó sesión SSH activa. Usa 'add <ip> --tier ...' manualmente.")
		return false
	}
	fmt.Printf("  IP detectada: %s\n", ip)
	return w.cliAdd(append([]string{ip}, "--tier", *tierFlag))
}

func (w *Whitelist) cliList(args []string) bool {
	fs := flag.NewFlagSet("whitelist list", flag.ContinueOnError)
	tierFlag := fs.String("tier", "", "Tier: A | B (omitir = ambos)")
	if err := fs.Parse(args); err != nil {
		return false
	}
	switch strings.ToUpper(*tierFlag) {
	case "A":
		w.listIPs(tierA())
	case "B":
		w.listIPs(tierB())
	case "":
		w.listIPs(tierA())
		w.listIPs(tierB())
	default:
		fmt.Fprintf(os.Stderr, "  ERROR: --tier debe ser A o B, no '%s'.\n", *tierFlag)
		return false
	}
	return true
}

func (w *Whitelist) cliDel(args []string) bool {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "  Uso: whitelist del <ip> --tier A|B")
		return false
	}
	addr := args[0]
	fs := flag.NewFlagSet("whitelist del", flag.ContinueOnError)
	tierFlag := fs.String("tier", "", "Tier: A | B")
	if err := fs.Parse(args[1:]); err != nil {
		return false
	}
	t, ok := w.parseTier(*tierFlag)
	if !ok {
		return false
	}
	setName, confFile, err := t.resolve(addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ERROR: %v\n", err)
		return false
	}
	if err := nftDeleteElement(setName, addr); err != nil {
		fmt.Fprintf(os.Stderr, "  ERROR al eliminar del set nft: %v\n", err)
		return false
	}
	if err := removeByAddr(confFile, addr); err != nil {
		fmt.Printf("  ADVERTENCIA: no se pudo actualizar %s: %v\n", confFile, err)
	}
	fmt.Printf("  Eliminado %s de %s\n", addr, setName)
	if t.immune {
		SyncImmuneTier()
	}
	return true
}

func (w *Whitelist) parseTier(s string) (tier, bool) {
	switch strings.ToUpper(s) {
	case "A":
		return tierA(), true
	case "B":
		return tierB(), true
	default:
		fmt.Fprintln(os.Stderr, "  ERROR: --tier es obligatorio y debe ser A o B.")
		return tier{}, false
	}
}

// _ ensures the interface is satisfied at compile time.
var _ interface {
	Order() int
	Name() string
	Menu()
	Reset()
} = (*Whitelist)(nil)
