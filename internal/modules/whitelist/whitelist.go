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

// Whitelist gestiona los sets sm_whitelist4/6 (SSoT de infra confiable).
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
		case "0":
			return
		default:
			fmt.Println("  Opción inválida.")
		}
	}
}

// addIP solicita una IP/CIDR al operador y la agrega al set correspondiente.
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
	setName, err := resolveSet(entry)
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return
	}
	if err := nftAddElement(setName, entry); err != nil {
		fmt.Printf("  ERROR al agregar: %v\n", err)
		return
	}
	fmt.Printf("  Agregado %s → %s\n", entry, setName)
}

// addSelf detecta la IP de la sesión SSH activa y la agrega al whitelist.
func (w *Whitelist) addSelf() {
	ip := sys.GetSSHIP()
	if ip == "" {
		fmt.Println("\n  No se detectó sesión SSH activa (SSH_CLIENT vacío y 'w' sin resultados).")
		fmt.Println("  Usa [1] para agregar tu IP manualmente.")
		return
	}
	setName, err := resolveSet(ip)
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
	fmt.Printf("  Agregado %s → %s\n", ip, setName)
}

// listIPs muestra el contenido de ambos sets del whitelist.
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

// deleteIP solicita una IP/CIDR y la elimina del set correspondiente tras confirmación.
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
	setName, err := resolveSet(entry)
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
	fmt.Printf("  Eliminado %s de %s\n", entry, setName)
}

// resolveSet determina el set nftables (sm_whitelist4 o sm_whitelist6) para una entrada.
// Acepta IPs sueltas y notación CIDR. Retorna error si el formato no es válido.
func resolveSet(entry string) (string, error) {
	// Intentar CIDR primero
	if strings.Contains(entry, "/") {
		ip, _, err := net.ParseCIDR(entry)
		if err != nil {
			return "", fmt.Errorf("CIDR inválido %q: %w", entry, err)
		}
		if ip.To4() != nil {
			return infra.SetWhitelist4, nil
		}
		return infra.SetWhitelist6, nil
	}
	// IP suelta
	ip := net.ParseIP(entry)
	if ip == nil {
		return "", fmt.Errorf("dirección IP inválida: %q", entry)
	}
	if ip.To4() != nil {
		return infra.SetWhitelist4, nil
	}
	return infra.SetWhitelist6, nil
}

// nftAddElement agrega una entrada al set indicado usando nft add element.
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

// nftDeleteElement elimina una entrada del set indicado usando nft delete element.
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

// _ ensures the interface is satisfied at compile time.
var _ interface {
	Order() int
	Name() string
	Menu()
	Reset()
} = (*Whitelist)(nil)
