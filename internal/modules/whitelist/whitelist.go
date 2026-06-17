package whitelist

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

type Whitelist struct {
	scanner *bufio.Scanner
}

func New() *Whitelist {
	return &Whitelist{scanner: bufio.NewScanner(os.Stdin)}
}

func (w *Whitelist) Order() int   { return 2 }
func (w *Whitelist) Name() string { return "Whitelist / SSoT" }
func (w *Whitelist) Reset()       {}

func (w *Whitelist) Menu() {
	for {
		fmt.Println("\n  ┌─ Whitelist / SSoT ─────────────────────┐")
		fmt.Println("  │  [1] Agregar IP/CIDR                    │")
		fmt.Println("  │  [2] Agregar mi IP (sesión SSH activa)  │")
		fmt.Println("  │  [3] Listar whitelist actual            │")
		fmt.Println("  │  [4] Eliminar IP/CIDR                   │")
		fmt.Println("  │  [5] Sincronizar con fail2ban           │")
		fmt.Println("  │  [0] Volver                             │")
		fmt.Println("  └────────────────────────────────────────┘")
		fmt.Print("  Selección: ")

		if !w.scanner.Scan() {
			return
		}
		switch strings.TrimSpace(w.scanner.Text()) {
		case "1":
			w.addIP()
		case "2":
			w.addSelf()
		case "3":
			w.listIPs()
		case "4":
			w.deleteIP()
		case "5":
			syncFail2banIgnoreip()
		case "0":
			return
		default:
			fmt.Println("  Opción inválida.")
		}
	}
}

func (w *Whitelist) addIP() {
	fmt.Print("\n  IP o CIDR a agregar (ej: 192.168.1.0/24 o 2001:db8::1): ")
	if !w.scanner.Scan() {
		return
	}
	entry := strings.TrimSpace(w.scanner.Text())
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
		fmt.Printf("  ERROR al agregar: %v\n", err)
		return
	}
	if err := appendToFile(confFile, entry); err != nil {
		fmt.Printf("  ADVERTENCIA: no se pudo persistir en %s: %v\n", confFile, err)
	}
	fmt.Printf("  Agregado %s → %s\n", entry, setName)
	syncFail2banIgnoreip()
}

func (w *Whitelist) addSelf() {
	ip := sys.GetSSHIP()
	if ip == "" {
		fmt.Println("\n  No se detectó sesión SSH activa (SSH_CLIENT vacío y 'w' sin resultados).")
		fmt.Println("  Usa [1] para agregar tu IP manualmente.")
		return
	}
	setName, confFile, err := resolveSet(ip)
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return
	}
	fmt.Printf("\n  IP detectada: %s → %s\n", ip, setName)
	fmt.Print("  ¿Confirmar agregar al whitelist? [s/N]: ")
	if !w.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(w.scanner.Text())) != "s" {
		fmt.Println("  Cancelado.")
		return
	}
	if err := nftAddElement(setName, ip); err != nil {
		fmt.Printf("  ERROR al agregar: %v\n", err)
		return
	}
	if err := appendToFile(confFile, ip); err != nil {
		fmt.Printf("  ADVERTENCIA: no se pudo persistir en %s: %v\n", confFile, err)
	}
	fmt.Printf("  Agregado %s → %s\n", ip, setName)
	syncFail2banIgnoreip()
}

func (w *Whitelist) listIPs() {
	fmt.Println()
	for _, setName := range []string{infra.SetWhitelist4, infra.SetWhitelist6} {
		out, err := exec.Command("nft", "list", "set", "inet", "sm", setName).CombinedOutput()
		if err != nil {
			fmt.Printf("  [%s] No disponible (¿tabla inet sm cargada?): %s\n",
				setName, strings.TrimSpace(string(out)))
			continue
		}
		fmt.Printf("--- %s ---\n%s\n", setName, strings.TrimSpace(string(out)))
	}
}

func (w *Whitelist) deleteIP() {
	fmt.Print("\n  IP o CIDR a eliminar: ")
	if !w.scanner.Scan() {
		return
	}
	entry := strings.TrimSpace(w.scanner.Text())
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
	if !w.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(w.scanner.Text())) != "s" {
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
	syncFail2banIgnoreip()
}

// resolveSet clasifica entry como IPv4 o IPv6 y retorna el set nftables y el archivo de config.
func resolveSet(entry string) (setName, confFile string, err error) {
	if strings.Contains(entry, "/") {
		ip, _, parseErr := net.ParseCIDR(entry)
		if parseErr != nil {
			return "", "", fmt.Errorf("CIDR inválido %q: %w", entry, parseErr)
		}
		if ip.To4() != nil {
			return infra.SetWhitelist4, infra.Whitelist4File, nil
		}
		return infra.SetWhitelist6, infra.Whitelist6File, nil
	}
	ip := net.ParseIP(entry)
	if ip == nil {
		return "", "", fmt.Errorf("dirección IP inválida: %q", entry)
	}
	if ip.To4() != nil {
		return infra.SetWhitelist4, infra.Whitelist4File, nil
	}
	return infra.SetWhitelist6, infra.Whitelist6File, nil
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

// appendToFile agrega entry al archivo de config si no existe ya.
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

// removeFromFile elimina entry del archivo de config.
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

const fail2banIgnoreipFile = "/etc/fail2ban/jail.d/sm-ng-whitelist.conf"

// syncFail2banIgnoreip escribe las IPs del whitelist en fail2ban jail.d y recarga.
// Se llama automáticamente al agregar/eliminar entradas. Fallo no es fatal.
func syncFail2banIgnoreip() {
	wl4, _ := infra.ReadLines(infra.Whitelist4File)
	wl6, _ := infra.ReadLines(infra.Whitelist6File)
	all := append(wl4, wl6...)

	if len(all) == 0 {
		os.Remove(fail2banIgnoreipFile)
		exec.Command("fail2ban-client", "reload").Run()
		return
	}

	content := fmt.Sprintf("[DEFAULT]\nignoreip = %s\n", strings.Join(all, " "))
	if err := os.WriteFile(fail2banIgnoreipFile, []byte(content), 0o640); err != nil {
		fmt.Printf("  ⚠  fail2ban ignoreip: no se pudo escribir %s: %v\n", fail2banIgnoreipFile, err)
		return
	}
	exec.Command("fail2ban-client", "reload").Run()
	fmt.Println("  ✓  fail2ban ignoreip sincronizado.")
}

// _ ensures the interface is satisfied at compile time.
var _ interface {
	Order() int
	Name() string
	Menu()
	Reset()
} = (*Whitelist)(nil)
