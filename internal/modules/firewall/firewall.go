package firewall

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/terracenter/security-manager-ng/internal/modules/infra"
	"github.com/terracenter/security-manager-ng/internal/safeapply"
)

// Firewall gestiona el ruleset nftables declarativo (tabla inet sm).
type Firewall struct {
	scanner *bufio.Scanner
}

func New() *Firewall {
	return &Firewall{scanner: bufio.NewScanner(os.Stdin)}
}

func (f *Firewall) Order() int   { return 1 }
func (f *Firewall) Name() string { return "Firewall (nftables)" }
func (f *Firewall) Reset()       {}

func (f *Firewall) Menu() {
	for {
		port80, _ := infra.ReadPort80Option()
		port80Status := "INACTIVO"
		if port80 {
			port80Status = "ACTIVO ✓"
		}

		fmt.Println("\n  ┌─ Firewall (nftables) ────────────────────────────┐")
		fmt.Println("  │  [1] Aplicar / recargar ruleset base              │")
		fmt.Println("  │  [2] Ver estado actual                            │")
		fmt.Println("  │  [3] Resetear tabla inet sm                       │")
		if infra.HasPublicIP() {
			fmt.Printf("  │  [4] Puerto 80 global (ACME/Let's Encrypt): %-8s│\n", port80Status)
		}
		fmt.Println("  │  [0] Volver                                       │")
		fmt.Println("  └───────────────────────────────────────────────────┘")
		fmt.Print("  Selección: ")

		if !f.scanner.Scan() {
			return
		}
		switch strings.TrimSpace(f.scanner.Text()) {
		case "1":
			f.applyBase()
		case "2":
			f.showStatus()
		case "3":
			f.resetTable()
		case "4":
			if infra.HasPublicIP() {
				f.togglePort80()
			} else {
				fmt.Println("  Opción no disponible: este host no tiene IPs públicas.")
			}
		case "0":
			return
		default:
			fmt.Println("  Opción inválida.")
		}
	}
}

func (f *Firewall) togglePort80() {
	current, _ := infra.ReadPort80Option()
	if current {
		fmt.Print("\n  Puerto 80 global está ACTIVO. ¿Desactivar? [s/N]: ")
	} else {
		fmt.Print("\n  Puerto 80 global está INACTIVO. ¿Activar para ACME/Let's Encrypt? [s/N]: ")
	}
	if !f.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(f.scanner.Text())) != "s" {
		fmt.Println("  Cancelado.")
		return
	}
	if err := infra.WritePort80Option(!current); err != nil {
		fmt.Printf("  ERROR guardando opción: %v\n", err)
		return
	}
	if !current {
		fmt.Println("  Puerto 80 global ACTIVADO. Recargando ruleset...")
	} else {
		fmt.Println("  Puerto 80 global DESACTIVADO. Recargando ruleset...")
	}
	f.applyBase()
}

// applyBase genera el ruleset base, valida la sintaxis y lo aplica con safeapply.
func (f *Firewall) applyBase() {
	// Si el host tiene IP pública y la opción aún no está configurada → preguntar al usuario.
	if infra.HasPublicIP() {
		if _, found := infra.ReadPort80Option(); !found {
			fmt.Print("\n  Host con IP pública detectado. ¿Habilitar puerto 80 global para ACME/Let's Encrypt?\n  (No aplica si usas certificados auto-firmados) [s/N]: ")
			if f.scanner.Scan() {
				answer := strings.ToLower(strings.TrimSpace(f.scanner.Text()))
				enabled := answer == "s"
				_ = infra.WritePort80Option(enabled)
				if enabled {
					fmt.Println("  Puerto 80 global: ACTIVADO.")
				} else {
					fmt.Println("  Puerto 80 global: INACTIVO.")
				}
			}
		}
	}

	sshPort := infra.DetectSSHPort()
	geoip, _ := infra.LoadGeoIPData()
	port80, _ := infra.ReadPort80Option()
	ruleset := infra.GenerateRuleset(sshPort, geoip, port80)

	if err := os.MkdirAll(infra.ConfDir, 0o750); err != nil {
		fmt.Printf("\n  ERROR: %v\n", err)
		return
	}

	tmpFile := infra.ConfDir + "/sm.nft.new"
	if err := os.WriteFile(tmpFile, []byte(ruleset), 0o640); err != nil {
		fmt.Printf("\n  ERROR escribiendo ruleset: %v\n", err)
		return
	}
	defer os.Remove(tmpFile)

	fmt.Println("\n  Validando sintaxis (nft -c)...")
	out, err := exec.Command("nft", "-c", "-f", tmpFile).CombinedOutput()
	if err != nil {
		fmt.Printf("  ERROR de sintaxis nftables:\n%s\n", strings.TrimSpace(string(out)))
		return
	}
	fmt.Println("  Sintaxis OK.")

	// Backup del ruleset ACTUAL antes de sobreescribir (deadman revertirá a este).
	if cur, err := os.ReadFile(infra.RulesetFile); err == nil {
		_ = os.WriteFile(infra.BackupFile, cur, 0o640)
		fmt.Printf("  [firewall] Backup: %s → %s\n", infra.RulesetFile, infra.BackupFile)
	}

	if err := os.Rename(tmpFile, infra.RulesetFile); err != nil {
		fmt.Printf("\n  ERROR moviendo ruleset: %v\n", err)
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
		fmt.Printf("\n  [firewall] %v\n", err)
		return
	}

	infra.EnsureSmNftPersistence()
}

// showStatus muestra el estado de la tabla inet sm.
func (f *Firewall) showStatus() {
	fmt.Println()
	out, err := exec.Command("nft", "list", "table", "inet", "sm").CombinedOutput()
	if err != nil {
		fmt.Printf("  La tabla inet sm no existe o nft no está disponible:\n  %s\n",
			strings.TrimSpace(string(out)))
		return
	}
	fmt.Println(string(out))
}

// resetTable ejecuta delete table inet sm tras confirmación del operador.
func (f *Firewall) resetTable() {
	fmt.Print("\n  ¿Confirmar reset (delete) de la tabla inet sm? [s/N]: ")
	if !f.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(f.scanner.Text())) != "s" {
		fmt.Println("  Cancelado.")
		return
	}
	out, err := exec.Command("nft", "delete", "table", "inet", "sm").CombinedOutput()
	if err != nil {
		fmt.Printf("  ERROR en delete: %s\n", strings.TrimSpace(string(out)))
		return
	}
	fmt.Println("  Tabla inet sm eliminada.")
}

// _ ensures the interface is satisfied at compile time.
var _ interface {
	Order() int
	Name() string
	Menu()
	Reset()
} = (*Firewall)(nil)
