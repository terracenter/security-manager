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

	"github.com/terracenter/security-manager-ng/internal/i18n"
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

// Reset borra la whitelist/immune (Tier A/B). El jail.d de fail2ban ya
// no existe (Tarea 12: fail2ban fue removido en favor de crowdsec).
func (w *Whitelist) Reset() {
	for _, path := range []string{infra.Whitelist4File, infra.Whitelist6File, infra.Immune4File, infra.Immune6File} {
		if err := os.Remove(path); err == nil {
			fmt.Printf(i18n.T("geoip.reset.removed_file")+" %s\n", path)
		} else if !os.IsNotExist(err) {
			fmt.Printf(i18n.T("geoip.reset.warn_remove")+" %s: %v\n", path, err)
		}
	}
	// Tarea 12: ya no escribimos a /etc/fail2ban/jail.d/ ni recargamos fail2ban-client.
	// Si crowdsec NO esta instalado, el operador no tiene baneador automatico.
	// Documentado en ROADMAP (Decision 3: fail2ban → crowdsec, pendiente E2E).
}

// tier parametriza cada nivel de confianza para reusar add/list/delete.
type tier struct {
	label  string
	set4   string
	set6   string
	file4  string
	file6  string
	immune bool // Tier B → se sincroniza al allowlist de crowdsec
}

func tierA() tier {
	return tier{
		label: "Confiables (Tier A — vigiladas por crowdsec)",
		set4:  infra.SetWhitelist4, set6: infra.SetWhitelist6,
		file4: infra.Whitelist4File, file6: infra.Whitelist6File,
		immune: false,
	}
}

func tierB() tier {
	return tier{
		label: "Intocables (Tier B — crowdsec never-bans)",
		set4:  infra.SetImmune4, set6: infra.SetImmune6,
		file4: infra.Immune4File, file6: infra.Immune6File,
		immune: true,
	}
}

func (w *Whitelist) Menu() {
	for {
		fmt.Println(i18n.T("whitelist.menu.header"))
		fmt.Println(i18n.T("whitelist.menu.tier_a"))
		fmt.Println(i18n.T("whitelist.menu.tier_b"))
		fmt.Println(i18n.T("whitelist.menu.sync"))
		fmt.Println(i18n.T("fw.menu.back"))
		fmt.Println(i18n.T("whitelist.menu.footer"))
		fmt.Print(i18n.T("fw.menu.prompt") + " ")

		if !w.scanner.Scan() {
			return
		}
		switch strings.TrimSpace(w.scanner.Text()) {
		case "1":
			w.tierMenu(tierA())
		case "2":
			w.tierMenu(tierB())
		case "3":
			_ = SyncImmuneTier()
		case "0":
			return
		default:
			fmt.Println(i18n.T("fw.invalid.option"))
		}
	}
}

func (w *Whitelist) tierMenu(t tier) {
	for {
		fmt.Printf(i18n.T("whitelist.tier_menu.header_fmt")+" %s\n", t.label)
		fmt.Println(i18n.T("whitelist.tier_menu.add"))
		fmt.Println(i18n.T("whitelist.tier_menu.add_self"))
		fmt.Println(i18n.T("whitelist.tier_menu.list"))
		fmt.Println(i18n.T("whitelist.tier_menu.del"))
		fmt.Println(i18n.T("fw.menu.back"))
		fmt.Println(i18n.T("whitelist.tier_menu.footer"))
		fmt.Print(i18n.T("fw.menu.prompt") + " ")

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
			fmt.Println(i18n.T("fw.invalid.option"))
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
	responsable = w.prompt(i18n.T("whitelist.add.prompt_responsable") + " ")
	proposito = w.prompt(i18n.T("whitelist.add.prompt_proposito") + " ")
	vencimiento = w.prompt(i18n.T("whitelist.add.prompt_vencimiento") + " ")
	return
}

func (w *Whitelist) addIP(t tier) {
	entry := w.prompt(i18n.T("whitelist.add.prompt_addr") + " ")
	if entry == "" {
		fmt.Println(i18n.T("whitelist.add.empty_cancelled"))
		return
	}
	w.persist(t, entry)
}

func (w *Whitelist) addSelf(t tier) {
	ip := sys.GetSSHIP()
	if ip == "" {
		fmt.Println(i18n.T("whitelist.addself.no_ssh"))
		fmt.Println(i18n.T("whitelist.addself.use_manual"))
		return
	}
	entry := ip
	// Sugerir CIDR de red si es una IPv4 individual.
	if cidr := suggestCIDR(ip); cidr != "" {
		fmt.Printf("\n  "+i18n.T("whitelist.addself.detected")+" %s\n", ip)
		fmt.Printf("  [1] "+i18n.T("whitelist.addself.option_single")+" (%s/32)\n", ip)
		fmt.Printf("  [2] "+i18n.T("whitelist.addself.option_network")+" (%s)\n", cidr)
		switch w.prompt(i18n.T("whitelist.addself.select") + " ") {
		case "2":
			entry = cidr
		default:
			// dejar la IP individual tal cual
		}
	} else {
		fmt.Printf("\n  "+i18n.T("whitelist.addself.detected")+" %s\n", ip)
	}
	w.persist(t, entry)
}

// persist valida la entrada, captura metadatos, la agrega al set nft y al archivo,
// y sincroniza crowdsec si el tier es intocable.
func (w *Whitelist) persist(t tier, addr string) {
	setName, confFile, err := t.resolve(addr)
	if err != nil {
		fmt.Printf(i18n.T("hardroot.err.generic")+" %v\n", err)
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
		fmt.Printf(i18n.T("whitelist.persist.err_nft_add")+" %v\n", err)
		fmt.Println(i18n.T("whitelist.persist.err_nft_hint"))
		return
	}
	if err := appendEntry(confFile, e); err != nil {
		fmt.Printf(i18n.T("whitelist.persist.warn_persist")+" %s: %v\n", confFile, err)
	}
	fmt.Printf(i18n.T("whitelist.persist.added")+" %s → %s\n", addr, setName)
	if t.immune {
		_ = SyncImmuneTier()
	}
}

func (w *Whitelist) listIPs(t tier) {
	fmt.Printf(i18n.T("whitelist.list.tier_label")+" %s\n", t.label)
	total := 0
	now := time.Now()
	for _, f := range []string{t.file4, t.file6} {
		entries, _ := infra.ReadACLEntries(f)
		for _, e := range entries {
			if total == 0 {
				fmt.Printf("\n  %-22s %-18s %-24s %-12s %-12s %s\n",
					i18n.T("whitelist.list.col_ip"),
					i18n.T("whitelist.list.col_responsable"),
					i18n.T("whitelist.list.col_proposito"),
					i18n.T("whitelist.list.col_alta"),
					i18n.T("whitelist.list.col_vence"),
					i18n.T("whitelist.list.col_estado"))
				fmt.Println(i18n.T("whitelist.list.separator"))
			}
			venc := e.Vencimiento
			estado := vencimientoStatus(e.Vencimiento, now)
			if venc == "" {
				venc = i18n.T("whitelist.list.permanente")
			}
			fmt.Printf("  %-22s %-18s %-24s %-12s %-12s %s\n",
				e.Addr, e.Responsable, e.Proposito, e.FechaAlta, venc, estado)
			total++
		}
	}
	if total == 0 {
		fmt.Println(i18n.T("whitelist.list.empty"))
	}
}

// vencimientoStatus clasifica una fecha de vencimiento contra `now`.
// Retorna un marcador humano para la vista de estado:
//   - "" (vacio)               -> "permanente"
//   - fecha invalida           -> "fecha inválida"
//   - fecha < now              -> "� VENCIDO"
//   - diferencia <= 7 dias     -> "⚠ vence pronto"
//   - diferencia > 7 dias      -> "OK"
//   - diferencia > 30 dias     -> "OK (>30d)"
//
// Funcion pura testeable (recibe now por parametro).
func vencimientoStatus(vencimiento string, now time.Time) string {
	if vencimiento == "" {
		return "permanente"
	}
	t, err := time.Parse("2006-01-02", vencimiento)
	if err != nil {
		return "fecha inválida"
	}
	diff := t.Sub(now)
	switch {
	case diff < 0:
		return "⚠ VENCIDO"
	case diff <= 7*24*time.Hour:
		return "⚠ vence pronto"
	case diff <= 30*24*time.Hour:
		return "OK"
	default:
		return "OK (>30d)"
	}
}

func (w *Whitelist) deleteIP(t tier) {
	addr := w.prompt(i18n.T("whitelist.del.prompt_addr") + " ")
	if addr == "" {
		fmt.Println(i18n.T("whitelist.del.empty_cancelled"))
		return
	}
	setName, confFile, err := t.resolve(addr)
	if err != nil {
		fmt.Printf(i18n.T("hardroot.err.generic")+" %v\n", err)
		return
	}
	if strings.ToLower(w.prompt(fmt.Sprintf(i18n.T("whitelist.del.confirm")+" ", addr, setName))) != "s" {
		fmt.Println(i18n.T("whitelist.del.cancelled"))
		return
	}
	if err := nftDeleteElement(setName, addr); err != nil {
		fmt.Printf(i18n.T("whitelist.del.err_nft")+" %v\n", err)
		return
	}
	if err := removeByAddr(confFile, addr); err != nil {
		fmt.Printf(i18n.T("whitelist.del.warn_persist")+" %s: %v\n", confFile, err)
	}
	fmt.Printf(i18n.T("whitelist.del.removed")+" %s de %s\n", addr, setName)
	if t.immune {
		_ = SyncImmuneTier()
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
	defer func() { _ = f.Close() }()
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

const crowdsecAllowlistFile = "/etc/crowdsec/allowlists/sm-ng.yaml"

// syncFail2banIgnoreipLegacy ELIMINADO en Tarea 12.
// Antes escribia IPs intocables a /etc/fail2ban/jail.d/sm-ng-whitelist.conf
// y recargaba fail2ban-client. Reemplazado por crowdsec.SyncAllowlist en
// SyncImmuneTier() (commit 2953ca3 + 9b2b141). Ver Decision 3 del
// checkpoint 2026-07-27 y ROADMAP.md.

// SyncImmuneTier sincroniza el tier IMMUNE (intocables) a CrowdSec.
// Tarea 12: el fallback a fail2ban fue eliminado. Si CrowdSec NO esta
// instalado, el operador no tiene baneador automatico y la operacion es
// no-bloqueante (solo warning).
func SyncImmuneTier() error {
	immuneFiles := []string{infra.Immune4File, infra.Immune6File}

	if crowdsec.IsInstalled() {
		fmt.Println(i18n.T("whitelist.sync.syncing"))
		if err := crowdsec.SyncAllowlist(immuneFiles); err != nil {
			fmt.Printf(i18n.T("whitelist.sync.err_sync")+" %v\n", err)
			// No retornar error bloqueante
		} else {
			fmt.Println(i18n.T("whitelist.sync.success"))
		}
		// FIX P2.1: limpiar IPs obsoletas del allowlist de CrowdSec.
		// Sin esto, el allowlist acumula entradas para siempre.
		if err := crowdsec.RemoveFromAllowlist(immuneFiles); err != nil {
			fmt.Printf(i18n.T("whitelist.sync.err_clean")+" %v\n", err)
		}
		return nil
	}

	// Si CrowdSec no esta instalado, log de advertencia. No bloqueante.
	fmt.Println(i18n.T("whitelist.sync.crowdsec_missing"))
	fmt.Println(i18n.T("whitelist.sync.crowdsec_hint"))
	return nil
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
		_ = SyncImmuneTier()
		return true
	default:
		fmt.Fprintf(os.Stderr, i18n.T("whitelist.cli.unknown_action")+" %s\n", action)
		fmt.Fprintln(os.Stderr, i18n.T("whitelist.cli.available_actions"))
		return false
	}
}

func (w *Whitelist) cliAdd(args []string) bool {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, i18n.T("whitelist.cli.usage_add"))
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
		fmt.Fprintf(os.Stderr, i18n.T("hardroot.err.generic")+" %v\n", err)
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
		fmt.Fprintf(os.Stderr, i18n.T("whitelist.persist.err_nft_add")+" %v\n", err)
		return false
	}
	if err := appendEntry(confFile, e); err != nil {
		fmt.Printf(i18n.T("whitelist.persist.warn_persist")+" %s: %v\n", confFile, err)
	}
	fmt.Printf(i18n.T("whitelist.persist.added")+" %s → %s\n", addr, setName)
	if t.immune {
		_ = SyncImmuneTier()
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
		fmt.Fprintln(os.Stderr, i18n.T("whitelist.cli.no_ssh"))
		return false
	}
	fmt.Printf(i18n.T("whitelist.addself.detected")+" %s\n", ip)
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
		fmt.Fprintf(os.Stderr, i18n.T("whitelist.cli.err_tier")+" %s\n", *tierFlag)
		return false
	}
	return true
}

func (w *Whitelist) cliDel(args []string) bool {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, i18n.T("whitelist.cli.usage_del"))
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
		fmt.Fprintf(os.Stderr, i18n.T("hardroot.err.generic")+" %v\n", err)
		return false
	}
	if err := nftDeleteElement(setName, addr); err != nil {
		fmt.Fprintf(os.Stderr, i18n.T("whitelist.del.err_nft")+" %v\n", err)
		return false
	}
	if err := removeByAddr(confFile, addr); err != nil {
		fmt.Printf(i18n.T("whitelist.del.warn_persist")+" %s: %v\n", confFile, err)
	}
	fmt.Printf(i18n.T("whitelist.del.removed")+" %s de %s\n", addr, setName)
	if t.immune {
		_ = SyncImmuneTier()
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
		fmt.Fprintln(os.Stderr, i18n.T("whitelist.cli.err_tier_required"))
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
