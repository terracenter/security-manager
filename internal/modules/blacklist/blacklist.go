package blacklist

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

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

func (b *Blacklist) Order() int   { return 4 }
func (b *Blacklist) Name() string { return "Blacklist — Bans manuales" }

// Reset borra la blacklist persistida (bans manuales).
func (b *Blacklist) Reset() {
	for _, path := range []string{infra.Blacklist4File, infra.Blacklist6File} {
		if err := os.Remove(path); err == nil {
			fmt.Printf("  Eliminado: %s\n", path)
		} else if os.IsNotExist(err) {
			fmt.Printf("  No había %s.\n", path)
		} else {
			fmt.Printf("  ADVERTENCIA: no se pudo eliminar %s: %v\n", path, err)
		}
	}
}

func (b *Blacklist) Menu() {
	for {
		fmt.Println("\n  ┌─ Blacklist — Bans manuales ────────────┐")
		fmt.Println("  │  [1] Agregar IP/CIDR al ban            │")
		fmt.Println("  │  [2] Listar IPs baneadas               │")
		fmt.Println("  │  [3] Eliminar IP/CIDR del ban          │")
		fmt.Println("  │  [4] Vaciar blacklist completa          │")
		fmt.Println("  │  [0] Volver                             │")
		fmt.Println("  └────────────────────────────────────────┘")
		fmt.Print("  Selección: ")

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
			fmt.Println("  Opción inválida.")
		}
	}
}

func (b *Blacklist) addIP() {
	fmt.Print("\n  IP o CIDR a banear (ej: 1.2.3.4 o 10.0.0.0/8): ")
	if !b.scanner.Scan() {
		return
	}
	entry := strings.TrimSpace(b.scanner.Text())
	if entry == "" {
		fmt.Println("  Entrada vacía. Cancelado.")
		return
	}
	setName, confFile, err := resolveSet(entry)
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return
	}
	if err := nftAddElement(setName, entry); err != nil {
		fmt.Printf("  ERROR al banear: %v\n", err)
		return
	}
	if err := appendToFile(confFile, entry); err != nil {
		fmt.Printf("  ADVERTENCIA: no se pudo persistir en %s: %v\n", confFile, err)
	}
	fmt.Printf("  Baneado %s → %s\n", entry, setName)
}

func (b *Blacklist) listIPs() {
	fmt.Println()
	for _, setName := range []string{infra.SetBlacklist4, infra.SetBlacklist6} {
		out, err := exec.Command("nft", "list", "set", "inet", "sm", setName).CombinedOutput()
		if err != nil {
			fmt.Printf("  [%s] No disponible (¿tabla inet sm cargada?): %s\n",
				setName, strings.TrimSpace(string(out)))
			continue
		}
		count := strings.Count(strings.TrimSpace(string(out)), "\n") + 1
		if strings.TrimSpace(string(out)) == "" {
			count = 0
		}
		b.logger.Screen(fmt.Sprintf("  %-20s %d entradas", setName, count))
		b.logger.Technical(strings.TrimSpace(string(out)))
	}
}

func (b *Blacklist) deleteIP() {
	fmt.Print("\n  IP o CIDR a eliminar del ban: ")
	if !b.scanner.Scan() {
		return
	}
	entry := strings.TrimSpace(b.scanner.Text())
	if entry == "" {
		fmt.Println("  Entrada vacía. Cancelado.")
		return
	}
	setName, confFile, err := resolveSet(entry)
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return
	}
	fmt.Printf("  Eliminar %s de %s. ¿Confirmar? [s/N]: ", entry, setName)
	if !b.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(b.scanner.Text())) != "s" {
		fmt.Println("  Cancelado.")
		return
	}
	if err := nftDeleteElement(setName, entry); err != nil {
		fmt.Printf("  ERROR al eliminar: %v\n", err)
		return
	}
	if err := removeFromFile(confFile, entry); err != nil {
		fmt.Printf("  ADVERTENCIA: no se pudo actualizar %s: %v\n", confFile, err)
	}
	fmt.Printf("  Eliminado %s de %s\n", entry, setName)
}

func (b *Blacklist) flushAll() {
	fmt.Print("\n  ¿Vaciar TODA la blacklist (sm_blacklist4 y sm_blacklist6)? [s/N]: ")
	if !b.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(b.scanner.Text())) != "s" {
		fmt.Println("  Cancelado.")
		return
	}
	errored := false
	for _, setName := range []string{infra.SetBlacklist4, infra.SetBlacklist6} {
		out, err := exec.Command("nft", "flush", "set", "inet", "sm", setName).CombinedOutput()
		if err != nil {
			fmt.Printf("  ERROR flush %s: %s\n", setName, strings.TrimSpace(string(out)))
			errored = true
		}
	}
	if errored {
		return
	}
	for _, path := range []string{infra.Blacklist4File, infra.Blacklist6File} {
		if err := os.WriteFile(path, []byte{}, 0o640); err != nil {
			fmt.Printf("  ADVERTENCIA: no se pudo truncar %s: %v\n", path, err)
		}
	}
	fmt.Println("  Blacklist vaciada (sets nftables + archivos de config).")
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
	defer f.Close()
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
			fmt.Fprintln(os.Stderr, "  Uso: blacklist add <ip|CIDR>")
			return false
		}
		entry := args[0]
		setName, confFile, err := resolveSet(entry)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR: %v\n", err)
			return false
		}
		if err := nftAddElement(setName, entry); err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR al banear: %v\n", err)
			return false
		}
		if err := appendToFile(confFile, entry); err != nil {
			fmt.Printf("  ADVERTENCIA: no se pudo persistir en %s: %v\n", confFile, err)
		}
		fmt.Printf("  Baneado %s → %s\n", entry, setName)
		return true

	case "list", "listar":
		b.listIPs()
		return true

	case "del", "delete", "eliminar":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "  Uso: blacklist del <ip|CIDR>")
			return false
		}
		entry := args[0]
		setName, confFile, err := resolveSet(entry)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR: %v\n", err)
			return false
		}
		if err := nftDeleteElement(setName, entry); err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR al eliminar: %v\n", err)
			return false
		}
		if err := removeFromFile(confFile, entry); err != nil {
			fmt.Printf("  ADVERTENCIA: no se pudo actualizar %s: %v\n", confFile, err)
		}
		fmt.Printf("  Eliminado %s de %s\n", entry, setName)
		return true

	case "flush", "vaciar":
		for _, setName := range []string{infra.SetBlacklist4, infra.SetBlacklist6} {
			out, err := exec.Command("nft", "flush", "set", "inet", "sm", setName).CombinedOutput()
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ERROR flush %s: %s\n", setName, strings.TrimSpace(string(out)))
				return false
			}
		}
		for _, path := range []string{infra.Blacklist4File, infra.Blacklist6File} {
			if err := os.WriteFile(path, []byte{}, 0o640); err != nil {
				fmt.Printf("  ADVERTENCIA: no se pudo truncar %s: %v\n", path, err)
			}
		}
		fmt.Println("  Blacklist vaciada.")
		return true

	default:
		fmt.Fprintf(os.Stderr, "  Acción '%s' no reconocida.\n", action)
		fmt.Fprintln(os.Stderr, "  Acciones: add <ip>, list, del <ip>, flush")
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
