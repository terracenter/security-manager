package firewall

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

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

	svc := infra.DetectGlobalServices()
	if svc.TailscaleActive {
		fmt.Println("  [info] Tailscale detectado. Si usas subnet routing IPv6, agrega el rango")
		fmt.Println("         fd7a:115c:a1e0::/48 a Tier B: whitelist add fd7a:115c:a1e0::/48 --tier B")
	}

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

// RunAction implementa modules.CLIModule para modo no interactivo.
// Uso: security-manager-ng firewall <acción> [flags]
//
//	allow      --port N --proto tcp|udp [--comment C]  Abre puerto globalmente (bypass GeoIP)
//	deny       --port N --proto tcp|udp                Cierra puerto previamente abierto
//	list-ports                                          Lista puertos en allowed_ports.conf
//	estado | status                                     Estado de la tabla inet sm
//	apply                                               Aplica / recarga ruleset base
//	reset                                               Elimina tabla inet sm
//	port80     on|off                                   Activa/desactiva excepción global puerto 80
func (f *Firewall) RunAction(action string, args ...string) bool {
	switch strings.ToLower(action) {
	case "allow":
		return f.cliAllow(args)
	case "deny":
		return f.cliDeny(args)
	case "list-ports", "list-port", "listar-puertos":
		return f.cliListPorts()
	case "estado", "status":
		f.showStatus()
		return true
	case "apply", "aplicar":
		f.applyBase()
		return true
	case "reset":
		fmt.Println("  [firewall] Eliminando tabla inet sm...")
		out, err := exec.Command("nft", "delete", "table", "inet", "sm").CombinedOutput()
		if err != nil {
			fmt.Printf("  ERROR: %s\n", strings.TrimSpace(string(out)))
			return false
		}
		fmt.Println("  [firewall] OK — tabla inet sm eliminada.")
		return true
	case "port80":
		if len(args) == 0 {
			fmt.Println("  Uso: firewall port80 on|off")
			return false
		}
		switch strings.ToLower(args[0]) {
		case "on", "true":
			_ = infra.WritePort80Option(true)
			fmt.Println("  [firewall] Puerto 80 global ACTIVADO. Recargando ruleset...")
			f.applyBase()
		case "off", "false":
			_ = infra.WritePort80Option(false)
			fmt.Println("  [firewall] Puerto 80 global DESACTIVADO. Recargando ruleset...")
			f.applyBase()
		default:
			fmt.Printf("  Valor inválido '%s'. Usa: on | off\n", args[0])
			return false
		}
		return true
	default:
		fmt.Printf("  Acción desconocida: '%s'\n", action)
		fmt.Println("  Acciones disponibles: allow, deny, list-ports, estado, apply, reset, port80")
		return false
	}
}

func (f *Firewall) cliAllow(args []string) bool {
	fs := flag.NewFlagSet("firewall allow", flag.ContinueOnError)
	port := fs.Int("port", 0, "Puerto a abrir (1-65535)")
	proto := fs.String("proto", "tcp", "Protocolo: tcp | udp")
	comment := fs.String("comment", "", "Comentario descriptivo")
	if err := fs.Parse(args); err != nil {
		return false
	}
	if *port < 1 || *port > 65535 {
		fmt.Println("  ERROR: --port es obligatorio y debe estar entre 1 y 65535.")
		return false
	}
	p := strings.ToLower(*proto)
	if p != "tcp" && p != "udp" {
		fmt.Printf("  ERROR: --proto debe ser 'tcp' o 'udp', no '%s'.\n", *proto)
		return false
	}
	entry := infra.PortEntry{
		Port:    *port,
		Proto:   p,
		Comment: *comment,
		Date:    time.Now().Format("2006-01-02"),
	}
	if err := infra.AddPortEntry(entry); err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return false
	}
	fmt.Printf("  [firewall] Puerto %d/%s agregado a %s.\n", *port, p, infra.AllowedPortsFile)
	fmt.Printf("  ⚠  Acceso global (bypass GeoIP). Cierra con: firewall deny --port %d --proto %s\n", *port, p)
	fmt.Println("  Recargando ruleset...")
	f.applyBase()
	return true
}

func (f *Firewall) cliDeny(args []string) bool {
	fs := flag.NewFlagSet("firewall deny", flag.ContinueOnError)
	port := fs.Int("port", 0, "Puerto a cerrar (1-65535)")
	proto := fs.String("proto", "tcp", "Protocolo: tcp | udp")
	if err := fs.Parse(args); err != nil {
		return false
	}
	if *port < 1 || *port > 65535 {
		fmt.Println("  ERROR: --port es obligatorio y debe estar entre 1 y 65535.")
		return false
	}
	p := strings.ToLower(*proto)
	if p != "tcp" && p != "udp" {
		fmt.Printf("  ERROR: --proto debe ser 'tcp' o 'udp', no '%s'.\n", *proto)
		return false
	}
	if err := infra.RemovePortEntry(*port, p); err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return false
	}
	fmt.Printf("  [firewall] Puerto %d/%s eliminado de %s.\n", *port, p, infra.AllowedPortsFile)
	fmt.Println("  Recargando ruleset...")
	f.applyBase()
	return true
}

func (f *Firewall) cliListPorts() bool {
	entries, err := infra.ReadPortEntries(infra.AllowedPortsFile)
	if err != nil {
		fmt.Printf("  ERROR leyendo %s: %v\n", infra.AllowedPortsFile, err)
		return false
	}
	if len(entries) == 0 {
		fmt.Println("  No hay puertos adicionales abiertos.")
		return true
	}
	fmt.Printf("\n  %-8s %-6s %-30s %s\n", "PUERTO", "PROTO", "COMENTARIO", "FECHA")
	fmt.Println("  " + strings.Repeat("─", 58))
	for _, e := range entries {
		fmt.Printf("  %-8d %-6s %-30s %s\n", e.Port, e.Proto, e.Comment, e.Date)
	}
	fmt.Println()
	return true
}

// _ ensures the interface is satisfied at compile time.
var _ interface {
	Order() int
	Name() string
	Menu()
	Reset()
} = (*Firewall)(nil)
