package blacklist

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/terracenter/security-manager-ng/internal/i18n"
	"github.com/terracenter/security-manager-ng/internal/modules/infra"
	"github.com/terracenter/security-manager-ng/internal/sys"
)

// Blacklist gestiona bans manuales en sm_blacklist4/sm_blacklist6.
// Operaciones atómicas nft add/delete element — no requiere safeapply.
type Blacklist struct {
	scanner *bufio.Scanner
	logger  *sys.SMLogger
}

func New(logger *sys.SMLogger) *Blacklist {
	return &Blacklist{scanner: bufio.NewScanner(os.Stdin), logger: logger}
}

func (b *Blacklist) Order() int   { return 5 }
func (b *Blacklist) Name() string { return i18n.T("blacklist.name") }

// Reset borra la blacklist persistida (bans manuales).
func (b *Blacklist) Reset() {
	for _, path := range []string{infra.Blacklist4File, infra.Blacklist6File} {
		if err := os.Remove(path); err == nil {
			fmt.Printf(i18n.T("blacklist.reset.removed_file_fmt"), path)
		} else if os.IsNotExist(err) {
			fmt.Printf(i18n.T("blacklist.reset.not_found_fmt"), path)
		} else {
			fmt.Printf(i18n.T("blacklist.reset.warn_remove_fmt"), path, err)
		}
	}
}

func (b *Blacklist) Menu() {
	for {
		fmt.Println(i18n.T("blacklist.menu.header"))
		fmt.Println(i18n.T("blacklist.menu.add"))
		fmt.Println(i18n.T("blacklist.menu.list"))
		fmt.Println(i18n.T("blacklist.menu.del"))
		fmt.Println(i18n.T("blacklist.menu.flush"))
		fmt.Println(i18n.T("fw.menu.back"))
		fmt.Println(i18n.T("fw.menu.footer"))
		fmt.Print(i18n.T("fw.menu.prompt") + " ")

		if !b.scanner.Scan() {
			return
		}
		switch strings.TrimSpace(b.scanner.Text()) {
		case "1":
			b.addIP()
		case "2":
			b.listIPs()
		case "3":
			b.deleteIP()
		case "4":
			b.flushAll()
		case "0":
			return
		default:
			fmt.Println(i18n.T("fw.invalid.option"))
		}
	}
}

func (b *Blacklist) addIP() {
	fmt.Print(i18n.T("blacklist.add.prompt"))
	if !b.scanner.Scan() {
		return
	}
	entry := strings.TrimSpace(b.scanner.Text())
	if entry == "" {
		fmt.Println(i18n.T("blacklist.add.empty_cancelled"))
		return
	}
	setName, confFile, err := resolveSet(entry)
	if err != nil {
		fmt.Printf(i18n.T("blacklist.cli.err_generic_fmt"), err)
		return
	}
	if err := nftAddElement(setName, entry); err != nil {
		fmt.Printf(i18n.T("blacklist.cli.err_nft_ban_fmt"), err)
		return
	}
	if err := appendToFile(confFile, entry); err != nil {
		fmt.Printf(i18n.T("blacklist.cli.warn_persist_fmt"), confFile, err)
	}
	fmt.Printf(i18n.T("blacklist.add.banned_fmt"), entry, setName)
}

// parseSetElementsFromNft extrae cada IP/CIDR del output de `nft list set`.
// Formatos aceptados:
//   - "elements = { ip1, ip2, ... }"   (en una sola linea)
//   - "elements = " seguido de "{ ip1, ip2 }" en la siguiente linea
//   - "elements={ip1,ip2}"            (sin espacios)
//
// Reuso la logica de firewall/parseSetElements via copia pequena (este
// paquete no debe depender de firewall para evitar ciclo).
func parseSetElementsFromNft(rawOutput string) []string {
	var result []string
	lines := strings.Split(rawOutput, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "elements") {
			continue
		}
		// Si la linea actual tiene { y }, parsear aca mismo.
		open := strings.Index(trimmed, "{")
		close := strings.LastIndex(trimmed, "}")
		if open >= 0 && close > open {
			// Caso en una linea: "elements = { ip1, ip2 }"
			result = append(result, splitSetBody(trimmed[open+1:close])...)
			continue
		}
		// Caso multilinea: "elements" en una linea y "{ ip1, ip2 }" en la siguiente.
		if i+1 < len(lines) {
			next := strings.TrimSpace(lines[i+1])
			open2 := strings.Index(next, "{")
			close2 := strings.LastIndex(next, "}")
			if open2 >= 0 && close2 > open2 {
				result = append(result, splitSetBody(next[open2+1:close2])...)
			}
		}
	}
	return result
}

// splitSetBody divide el cuerpo "{ ip1, ip2, ip3 }" en sus elementos,
// limpiando comillas y espacios.
func splitSetBody(body string) []string {
	var result []string
	for _, p := range strings.Split(body, ",") {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"`)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// lookupCountry consulta ipinfo.io (sin API key, solo el endpoint /country)
// para resolver el pais de una IP. Best-effort: si falla, retorna "" y NO
// rompe el listado (red caida, IP privada, rate-limit, etc).
func lookupCountry(ip string) string {
	// IPs privadas (RFC1918) y loopback: skip rapido.
	if ip == "" {
		return ""
	}
	// Heuristica simple para no pegarle a ipinfo con CIDR.
	if strings.Contains(ip, "/") {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"https://ipinfo.io/"+ip+"/country", nil)
	req.Header.Set("User-Agent", "security-manager-ng/0.8")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return ""
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

func (b *Blacklist) listIPs() {
	fmt.Println()
	for _, setName := range []string{infra.SetBlacklist4, infra.SetBlacklist6} {
		out, err := exec.Command("nft", "list", "set", "inet", "sm", setName).CombinedOutput()
		if err != nil {
			fmt.Printf(i18n.T("blacklist.list.unavailable_fmt"), setName, strings.TrimSpace(string(out)))
			continue
		}
		elements := parseSetElementsFromNft(string(out))
		if len(elements) == 0 {
			fmt.Printf("  [%-20s] %s\n", setName, i18n.T("blacklist.list.empty"))
			continue
		}
		fmt.Printf(i18n.T("blacklist.list.header_fmt"), setName, len(elements))
		fmt.Printf("  %-22s %s\n", i18n.T("blacklist.list.col_ip"), i18n.T("blacklist.list.col_country"))
		fmt.Println(i18n.T("blacklist.list.separator"))
		for _, ip := range elements {
			pais := lookupCountry(ip)
			if pais == "" {
				pais = i18n.T("blacklist.list.country_unknown")
			}
			fmt.Printf(i18n.T("blacklist.list.row_fmt"), ip, pais)
		}
		b.logger.Technical(strings.TrimSpace(string(out)))
	}
}

func (b *Blacklist) deleteIP() {
	fmt.Print(i18n.T("blacklist.del.prompt"))
	if !b.scanner.Scan() {
		return
	}
	entry := strings.TrimSpace(b.scanner.Text())
	if entry == "" {
		fmt.Println(i18n.T("blacklist.add.empty_cancelled"))
		return
	}
	setName, confFile, err := resolveSet(entry)
	if err != nil {
		fmt.Printf(i18n.T("blacklist.cli.err_generic_fmt"), err)
		return
	}
	fmt.Printf(i18n.T("blacklist.del.confirm_fmt"), entry, setName)
	if !b.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(b.scanner.Text())) != "s" {
		fmt.Println(i18n.T("blacklist.del.cancelled"))
		return
	}
	if err := nftDeleteElement(setName, entry); err != nil {
		fmt.Printf(i18n.T("blacklist.cli.err_nft_del_fmt"), err)
		return
	}
	if err := removeFromFile(confFile, entry); err != nil {
		fmt.Printf(i18n.T("blacklist.cli.warn_persist_update_fmt"), confFile, err)
	}
	fmt.Printf(i18n.T("blacklist.del.removed_fmt"), entry, setName)
}

func (b *Blacklist) flushAll() {
	fmt.Print(i18n.T("blacklist.flush.confirm"))
	if !b.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(b.scanner.Text())) != "s" {
		fmt.Println(i18n.T("blacklist.flush.cancelled"))
		return
	}
	errored := false
	for _, setName := range []string{infra.SetBlacklist4, infra.SetBlacklist6} {
		out, err := exec.Command("nft", "flush", "set", "inet", "sm", setName).CombinedOutput()
		if err != nil {
			fmt.Printf(i18n.T("blacklist.cli.err_flush_fmt"), setName, strings.TrimSpace(string(out)))
			errored = true
		}
	}
	if errored {
		return
	}
	for _, path := range []string{infra.Blacklist4File, infra.Blacklist6File} {
		if err := os.WriteFile(path, []byte{}, 0o640); err != nil {
			fmt.Printf(i18n.T("blacklist.cli.warn_truncate_fmt"), path, err)
		}
	}
	fmt.Println(i18n.T("blacklist.flush.done"))
}

// resolveSet clasifica entry como IPv4 o IPv6 y retorna el set y archivo de blacklist correspondiente.
func resolveSet(entry string) (setName, confFile string, err error) {
	if strings.Contains(entry, "/") {
		ip, _, parseErr := net.ParseCIDR(entry)
		if parseErr != nil {
			return "", "", fmt.Errorf("CIDR inválido %q: %w", entry, parseErr)
		}
		if ip.To4() != nil {
			return infra.SetBlacklist4, infra.Blacklist4File, nil
		}
		return infra.SetBlacklist6, infra.Blacklist6File, nil
	}
	ip := net.ParseIP(entry)
	if ip == nil {
		return "", "", fmt.Errorf("dirección IP inválida: %q", entry)
	}
	if ip.To4() != nil {
		return infra.SetBlacklist4, infra.Blacklist4File, nil
	}
	return infra.SetBlacklist6, infra.Blacklist6File, nil
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

func appendToFile(path, entry string) error {
	existing, _ := infra.ReadLines(path)
	for _, line := range existing {
		if line == entry {
			return nil
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = fmt.Fprintln(f, entry)
	return err
}

func removeFromFile(path, entry string) error {
	lines, err := infra.ReadLines(path)
	if err != nil {
		return err
	}
	var updated []string
	for _, l := range lines {
		if l != entry {
			updated = append(updated, l)
		}
	}
	return os.WriteFile(path, []byte(strings.Join(updated, "\n")+"\n"), 0o640)
}

// RunAction implementa modules.CLIModule para modo no interactivo.
//
//	add <ip>    Banear IP o CIDR
//	list        Listar IPs baneadas
//	del <ip>    Eliminar IP o CIDR del ban
//	flush       Vaciar blacklist completa
func (b *Blacklist) RunAction(action string, args ...string) bool {
	switch strings.ToLower(action) {
	case "add", "agregar":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, i18n.T("blacklist.cli.usage_add"))
			return false
		}
		entry := args[0]
		setName, confFile, err := resolveSet(entry)
		if err != nil {
			fmt.Fprintf(os.Stderr, i18n.T("blacklist.cli.err_generic_fmt"), err)
			return false
		}
		if err := nftAddElement(setName, entry); err != nil {
			fmt.Fprintf(os.Stderr, i18n.T("blacklist.cli.err_nft_ban_fmt"), err)
			return false
		}
		if err := appendToFile(confFile, entry); err != nil {
			fmt.Printf(i18n.T("blacklist.cli.warn_persist_fmt"), confFile, err)
		}
		fmt.Printf(i18n.T("blacklist.add.banned_fmt"), entry, setName)
		return true

	case "list", "listar":
		b.listIPs()
		return true

	case "del", "delete", "eliminar":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, i18n.T("blacklist.cli.usage_del"))
			return false
		}
		entry := args[0]
		setName, confFile, err := resolveSet(entry)
		if err != nil {
			fmt.Fprintf(os.Stderr, i18n.T("blacklist.cli.err_generic_fmt"), err)
			return false
		}
		if err := nftDeleteElement(setName, entry); err != nil {
			fmt.Fprintf(os.Stderr, i18n.T("blacklist.cli.err_nft_del_fmt"), err)
			return false
		}
		if err := removeFromFile(confFile, entry); err != nil {
			fmt.Printf(i18n.T("blacklist.cli.warn_persist_update_fmt"), confFile, err)
		}
		fmt.Printf(i18n.T("blacklist.del.removed_fmt"), entry, setName)
		return true

	case "flush", "vaciar":
		for _, setName := range []string{infra.SetBlacklist4, infra.SetBlacklist6} {
			out, err := exec.Command("nft", "flush", "set", "inet", "sm", setName).CombinedOutput()
			if err != nil {
				fmt.Fprintf(os.Stderr, i18n.T("blacklist.cli.err_flush_fmt"), setName, strings.TrimSpace(string(out)))
				return false
			}
		}
		for _, path := range []string{infra.Blacklist4File, infra.Blacklist6File} {
			if err := os.WriteFile(path, []byte{}, 0o640); err != nil {
				fmt.Printf(i18n.T("blacklist.cli.warn_truncate_fmt"), path, err)
			}
		}
		fmt.Println(i18n.T("blacklist.cli.flush_done"))
		return true

	default:
		fmt.Fprintf(os.Stderr, i18n.T("blacklist.cli.unknown_action_fmt"), action)
		fmt.Fprintln(os.Stderr, i18n.T("blacklist.cli.available_actions"))
		return false
	}
}

// _ ensures the interface is satisfied at compile time.
var _ interface {
	Order() int
	Name() string
	Menu()
	Reset()
} = (*Blacklist)(nil)
