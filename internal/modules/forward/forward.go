// Package forward implementa el motor de reglas forward estilo MikroTik
// (T-4.10): reglas (src, dst, port, proto) -> accept/drop evaluadas en
// orden (primera coincidencia gana), aplicadas a la chain `forward` de
// `sm_forward` (internal/modules/infra). El estado vive en SQLite
// (internal/store) porque, a diferencia de whitelist/immune/blacklist, el
// ORDEN es semánticamente crítico — ver justificación en el plan T-4.10.
//
// v1 no aplica en vivo: `add`/`del`/`move` solo escriben en la base. El
// operador corre `firewall apply` para materializar (mismo precedente que
// el wizard de puertos) — razón completa en el plan T-4.10, Paso 6.
package forward

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/terracenter/security-manager-ng/internal/i18n"
	"github.com/terracenter/security-manager-ng/internal/modules/infra"
	"github.com/terracenter/security-manager-ng/internal/store"
)

type Forward struct {
	scanner *bufio.Scanner
}

func New() *Forward {
	return &Forward{scanner: bufio.NewScanner(os.Stdin)}
}

func (f *Forward) Order() int   { return 4 }
func (f *Forward) Name() string { return i18n.T("forward.name") }

// Reset borra la base del motor forward. Nota: `firewall reset` (módulo
// firewall) también la borra, porque las reglas forward afectan
// directamente al ruleset que ese comando regenera — ver T-4.10 Paso 7.
// Este Reset() cubre el reset global ("R" del menú principal), que itera
// cada módulo por separado.
func (f *Forward) Reset() {
	if err := os.Remove(infra.ForwardDBFile); err == nil {
		fmt.Printf("  %s %s\n", i18n.T("forward.reset.removed_file"), infra.ForwardDBFile)
	} else if !os.IsNotExist(err) {
		fmt.Printf("  %s %s: %v\n", i18n.T("forward.reset.warn_remove"), infra.ForwardDBFile, err)
	}
}

func openStore() (*store.DB, error) {
	return store.Open(infra.ForwardDBFile)
}

// validateRule aplica las invariantes del motor ANTES de persistir — este es
// el único punto de escritura hacia internal/store, por eso el renderer
// (internal/modules/infra) puede confiar en los datos sin revalidar.
func validateRule(r store.ForwardRule) error {
	action := strings.ToLower(r.Action)
	if action != "accept" && action != "drop" {
		return fmt.Errorf("acción inválida %q (debe ser accept|drop)", r.Action)
	}
	if r.PortRange != "" {
		if r.Proto == "" {
			return fmt.Errorf("--port requiere --proto (tcp|udp) — nftables no permite dport sin protocolo")
		}
		if err := validatePortRange(r.PortRange); err != nil {
			return err
		}
	}
	if r.Proto != "" && r.Proto != "tcp" && r.Proto != "udp" {
		return fmt.Errorf("proto inválido %q (debe ser tcp|udp)", r.Proto)
	}
	srcFam, err := addrFamily(r.Src)
	if err != nil {
		return fmt.Errorf("src inválido (%q): %w", r.Src, err)
	}
	dstFam, err := addrFamily(r.Dst)
	if err != nil {
		return fmt.Errorf("dst inválido (%q): %w", r.Dst, err)
	}
	if srcFam != "" && dstFam != "" && srcFam != dstFam {
		return fmt.Errorf("src (%s) y dst (%s) deben ser de la misma familia (IPv4 o IPv6)", r.Src, r.Dst)
	}
	return nil
}

// addrFamily retorna "v4"/"v6" para addr no vacío, "" si addr == "" (any).
func addrFamily(addr string) (string, error) {
	if addr == "" {
		return "", nil
	}
	ipPart := addr
	if idx := strings.Index(addr, "/"); idx >= 0 {
		ipPart = addr[:idx]
	}
	ip := net.ParseIP(ipPart)
	if ip == nil {
		return "", fmt.Errorf("no es una dirección IP ni CIDR válida")
	}
	if ip.To4() != nil {
		return "v4", nil
	}
	return "v6", nil
}

// validatePortRange acepta "N" o "N-M" (1-65535, N<=M).
func validatePortRange(pr string) error {
	parts := strings.SplitN(pr, "-", 2)
	nums := make([]int, 0, 2)
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("puerto/rango inválido %q (1-65535, o N-M)", pr)
		}
		nums = append(nums, n)
	}
	if len(nums) == 2 && nums[0] > nums[1] {
		return fmt.Errorf("rango de puerto inválido %q (el primero debe ser menor o igual al segundo)", pr)
	}
	return nil
}

func (f *Forward) Menu() {
	for {
		fmt.Println(i18n.T("forward.menu.header"))
		f.printList("")
		fmt.Println(i18n.T("forward.menu.add"))
		fmt.Println(i18n.T("forward.menu.del"))
		fmt.Println(i18n.T("forward.menu.move"))
		fmt.Println(i18n.T("fw.menu.back"))
		fmt.Println(i18n.T("fw.menu.footer"))
		fmt.Print(i18n.T("fw.menu.prompt") + " ")

		if !f.scanner.Scan() {
			return
		}
		switch strings.TrimSpace(f.scanner.Text()) {
		case "a", "A":
			f.menuAdd()
		case "b", "B":
			f.menuDel()
		case "m", "M":
			f.menuMove()
		case "0":
			return
		default:
			fmt.Println(i18n.T("fw.invalid.option"))
		}
	}
}

func (f *Forward) readLine(prompt string) string {
	fmt.Print(prompt)
	if !f.scanner.Scan() {
		return ""
	}
	return strings.TrimSpace(f.scanner.Text())
}

func (f *Forward) menuAdd() {
	r := store.ForwardRule{
		Src:       f.readLine(i18n.T("forward.prompt.src")),
		Dst:       f.readLine(i18n.T("forward.prompt.dst")),
		PortRange: f.readLine(i18n.T("forward.prompt.port")),
		Proto:     strings.ToLower(f.readLine(i18n.T("forward.prompt.proto"))),
		Action:    strings.ToLower(f.readLine(i18n.T("forward.prompt.action"))),
		Comment:   f.readLine(i18n.T("forward.prompt.comment")),
	}
	f.addAndReport(r, f.readLine(i18n.T("forward.prompt.tag")))
}

func (f *Forward) menuDel() {
	idStr := f.readLine(i18n.T("forward.prompt.id_del"))
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		fmt.Printf(i18n.T("forward.err.invalid_id")+"\n", idStr)
		return
	}
	f.delAndReport(id)
}

func (f *Forward) menuMove() {
	idStr := f.readLine(i18n.T("forward.prompt.id_move"))
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		fmt.Printf(i18n.T("forward.err.invalid_id")+"\n", idStr)
		return
	}
	posStr := f.readLine(i18n.T("forward.prompt.newpos"))
	pos, err := strconv.ParseInt(posStr, 10, 64)
	if err != nil {
		fmt.Printf(i18n.T("forward.err.invalid_position")+"\n", posStr)
		return
	}
	f.moveAndReport(id, pos)
}

func (f *Forward) addAndReport(r store.ForwardRule, tag string) {
	if err := validateRule(r); err != nil {
		fmt.Printf("  %s %v\n", i18n.T("forward.err.prefix"), err)
		return
	}
	db, err := openStore()
	if err != nil {
		fmt.Printf("  %s %v\n", i18n.T("forward.err.db"), err)
		return
	}
	defer func() { _ = db.Close() }()

	id, err := db.AddForwardRule(r)
	if err != nil {
		fmt.Printf("  %s %v\n", i18n.T("forward.err.db"), err)
		return
	}
	if tag != "" {
		for _, t := range strings.Split(tag, ",") {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			if err := db.AddTag("forward_rule", id, t); err != nil {
				fmt.Printf("  %s %v\n", i18n.T("forward.err.tag"), err)
			}
		}
	}
	fmt.Printf(i18n.T("forward.add.done_fmt")+"\n", id)
	fmt.Println("  " + i18n.T("forward.hint.apply"))
}

func (f *Forward) delAndReport(id int64) {
	db, err := openStore()
	if err != nil {
		fmt.Printf("  %s %v\n", i18n.T("forward.err.db"), err)
		return
	}
	defer func() { _ = db.Close() }()

	if err := db.DeleteForwardRule(id); err != nil {
		fmt.Printf("  %s %v\n", i18n.T("forward.err.db"), err)
		return
	}
	fmt.Printf(i18n.T("forward.del.done_fmt")+"\n", id)
	fmt.Println("  " + i18n.T("forward.hint.apply"))
}

func (f *Forward) moveAndReport(id, pos int64) {
	db, err := openStore()
	if err != nil {
		fmt.Printf("  %s %v\n", i18n.T("forward.err.db"), err)
		return
	}
	defer func() { _ = db.Close() }()

	if err := db.MoveForwardRule(id, pos); err != nil {
		fmt.Printf("  %s %v\n", i18n.T("forward.err.db"), err)
		return
	}
	fmt.Printf(i18n.T("forward.move.done_fmt")+"\n", id, pos)
	fmt.Println("  " + i18n.T("forward.hint.apply"))
}

func (f *Forward) printList(tag string) {
	db, err := openStore()
	if err != nil {
		fmt.Printf("  %s %v\n", i18n.T("forward.err.db"), err)
		return
	}
	defer func() { _ = db.Close() }()

	rules, err := db.ListForwardRules(tag)
	if err != nil {
		fmt.Printf("  %s %v\n", i18n.T("forward.err.db"), err)
		return
	}
	if len(rules) == 0 {
		fmt.Println("  " + i18n.T("forward.list.empty"))
		return
	}
	fmt.Printf("  %-4s %-4s %-20s %-20s %-12s %-6s %-7s %s\n",
		"ID", "POS", "SRC", "DST", "PORT", "PROTO", "ACTION", "COMMENT")
	for _, r := range rules {
		src, dst, port, proto := r.Src, r.Dst, r.PortRange, r.Proto
		if src == "" {
			src = "any"
		}
		if dst == "" {
			dst = "any"
		}
		if port == "" {
			port = "any"
		}
		if proto == "" {
			proto = "any"
		}
		fmt.Printf("  %-4d %-4d %-20s %-20s %-12s %-6s %-7s %s\n",
			r.ID, r.Position, src, dst, port, proto, r.Action, r.Comment)
	}
}

// RunAction implementa modules.CLIModule para modo no interactivo.
//
//	add --src CIDR --dst CIDR --port N|N-M --proto tcp|udp --action accept|drop [--comment C] [--tag T]
//	list [--tag T]
//	del <id>
//	move <id> <newpos>
func (f *Forward) RunAction(action string, args ...string) bool {
	switch strings.ToLower(action) {
	case "add", "agregar":
		fs := flag.NewFlagSet("forward add", flag.ContinueOnError)
		src := fs.String("src", "", "CIDR/IP origen (vacío = any)")
		dst := fs.String("dst", "", "CIDR/IP destino (vacío = any)")
		port := fs.String("port", "", "Puerto exacto o rango N-M (vacío = any)")
		proto := fs.String("proto", "", "tcp | udp (obligatorio si --port está seteado)")
		act := fs.String("action", "", "accept | drop (obligatorio)")
		comment := fs.String("comment", "", "Comentario libre")
		tag := fs.String("tag", "", "Tag(s) separados por coma")
		if err := fs.Parse(args); err != nil {
			return false
		}
		r := store.ForwardRule{
			Src: *src, Dst: *dst, PortRange: *port,
			Proto: strings.ToLower(*proto), Action: strings.ToLower(*act), Comment: *comment,
		}
		if err := validateRule(r); err != nil {
			fmt.Fprintf(os.Stderr, "  %s %v\n", i18n.T("forward.err.prefix"), err)
			return false
		}
		db, err := openStore()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s %v\n", i18n.T("forward.err.db"), err)
			return false
		}
		defer func() { _ = db.Close() }()
		id, err := db.AddForwardRule(r)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s %v\n", i18n.T("forward.err.db"), err)
			return false
		}
		for _, t := range strings.Split(*tag, ",") {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			if err := db.AddTag("forward_rule", id, t); err != nil {
				fmt.Fprintf(os.Stderr, "  %s %v\n", i18n.T("forward.err.tag"), err)
			}
		}
		fmt.Printf(i18n.T("forward.add.done_fmt")+"\n", id)
		fmt.Println("  " + i18n.T("forward.hint.apply"))
		return true

	case "list", "listar":
		fs := flag.NewFlagSet("forward list", flag.ContinueOnError)
		tag := fs.String("tag", "", "Filtrar por tag")
		if err := fs.Parse(args); err != nil {
			return false
		}
		f.printList(*tag)
		return true

	case "del", "delete", "eliminar":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, i18n.T("forward.cli.usage_del"))
			return false
		}
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, i18n.T("forward.err.invalid_id")+"\n", args[0])
			return false
		}
		db, err := openStore()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s %v\n", i18n.T("forward.err.db"), err)
			return false
		}
		defer func() { _ = db.Close() }()
		if err := db.DeleteForwardRule(id); err != nil {
			fmt.Fprintf(os.Stderr, "  %s %v\n", i18n.T("forward.err.db"), err)
			return false
		}
		fmt.Printf(i18n.T("forward.del.done_fmt")+"\n", id)
		fmt.Println("  " + i18n.T("forward.hint.apply"))
		return true

	case "move", "mover":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, i18n.T("forward.cli.usage_move"))
			return false
		}
		id, err1 := strconv.ParseInt(args[0], 10, 64)
		pos, err2 := strconv.ParseInt(args[1], 10, 64)
		if err1 != nil || err2 != nil {
			fmt.Fprintln(os.Stderr, i18n.T("forward.cli.usage_move"))
			return false
		}
		db, err := openStore()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s %v\n", i18n.T("forward.err.db"), err)
			return false
		}
		defer func() { _ = db.Close() }()
		if err := db.MoveForwardRule(id, pos); err != nil {
			fmt.Fprintf(os.Stderr, "  %s %v\n", i18n.T("forward.err.db"), err)
			return false
		}
		fmt.Printf(i18n.T("forward.move.done_fmt")+"\n", id, pos)
		fmt.Println("  " + i18n.T("forward.hint.apply"))
		return true

	default:
		fmt.Fprintf(os.Stderr, i18n.T("forward.cli.unknown_action_fmt"), action)
		fmt.Fprintln(os.Stderr, i18n.T("forward.cli.available_actions"))
		return false
	}
}

// _ ensures the interface is satisfied at compile time.
var _ interface {
	Order() int
	Name() string
	Menu()
	Reset()
	RunAction(action string, args ...string) bool
} = (*Forward)(nil)
