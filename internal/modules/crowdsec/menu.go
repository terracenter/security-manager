package crowdsec

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Paths de los archivos immune de SM-NG. Replicados aqui para evitar
// import cycle (internal/modules/infra ya importa este paquete).
// Mantener en sync con infra.Immune4File / infra.Immune6File.
const (
	immune4File = "/etc/security-manager/immune4.conf"
	immune6File = "/etc/security-manager/immune6.conf"
)

// Menu muestra el menu interactivo de CrowdSec. Las acciones se implementan
// en commits subsiguientes (Tarea A4..A7). Esta version es un shell que
// enruta las opciones a los stubs correspondientes.
//
// Codigo UI: usa literales hardcoded en espanol. Migracion a i18n es
// Subtarea D (un commit aparte) para mantener este PR chiquito.
func (c *Crowdsec) Menu() {
	for {
		c.printMenuHeader()

		if !c.scanner.Scan() {
			return
		}
		switch strings.TrimSpace(c.scanner.Text()) {
		case "1":
			c.statusScreen()
		case "2":
			c.allowlistScreen()
		case "3":
			c.syncScreen()
		case "4":
			c.resetScreen()
		case "0":
			return
		default:
			fmt.Println("  Opcion invalida.")
		}
	}
}

func (c *Crowdsec) printMenuHeader() {
	fmt.Println("\n  ┌─ CrowdSec ─────────────────────────────┐")
	fmt.Println("  │  [1] Ver estado                        │")
	fmt.Println("  │  [2] Ver allowlist actual              │")
	fmt.Println("  │  [3] Sincronizar allowlist manual       │")
	fmt.Println("  │  [4] Reset allowlist                   │")
	fmt.Println("  │  [0] Volver                            │")
	fmt.Println("  └────────────────────────────────────────┘")
	fmt.Print("  Seleccion: ")
}

func (c *Crowdsec) statusScreen() {
	fmt.Println("\n  === CrowdSec — Estado ===")
	if !IsInstalled() {
		fmt.Println("  crowdsec: NO INSTALADO")
		fmt.Println("  bouncer:  --")
		fmt.Println("  servicio: --")
		fmt.Println("\n  Para instalar, use el menu de prereqs del modulo sys.")
		return
	}
	fmt.Println("  crowdsec: INSTALADO")
	if IsBouncerInstalled() {
		fmt.Println("  bouncer:  INSTALADO (nftables)")
	} else {
		fmt.Println("  bouncer:  NO INSTALADO")
	}
	status, err := Status()
	if err != nil {
		fmt.Printf("  servicio: ERROR (%v)\n", err)
	} else {
		fmt.Printf("  servicio: %s\n", status)
	}
}

func (c *Crowdsec) allowlistScreen() {
	fmt.Println("\n  === CrowdSec — Allowlist sm-immune ===")
	if !IsInstalled() {
		fmt.Println("  crowdsec no esta instalado.")
		return
	}
	ips := listAllowlistIPs()
	if len(ips) == 0 {
		fmt.Println("  (vacio)")
		return
	}
	fmt.Printf("  %d entradas:\n", len(ips))
	for ip := range ips {
		fmt.Printf("    %s\n", ip)
	}
}
func (c *Crowdsec) syncScreen() {
	fmt.Println("\n  Sincronizando allowlist desde whitelist Tier B...")
	immuneFiles := []string{immune4File, immune6File}
	if err := SyncAllowlist(immuneFiles); err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return
	}
	fmt.Println("  OK.")
}

func (c *Crowdsec) resetScreen() {
	fmt.Println("\n  AVISO: Borrar la allowlist sm-immune permite que CrowdSec banee IPs immune.")
	fmt.Print("  Confirmar? [s/N]: ")
	if !c.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(c.scanner.Text())) != "s" {
		fmt.Println("  Cancelado.")
		return
	}
	if err := ResetAllowlist(); err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return
	}
	fmt.Println("  OK.")
}

// ResetAllowlist borra la allowlist sm-immune en CrowdSec via cscli.
// Si crowdsec no esta instalado, retorna nil (no-op).
func ResetAllowlist() error {
	if !IsInstalled() {
		return nil
	}
	cmd := exec.Command("sudo", "cscli", "allowlists", "delete", "sm-immune")
	return cmd.Run()
}

// Reset es el metodo de la interface modules.Module. Lo llama resetGlobal
// en main.go cuando se hace un reset completo de SM-NG.
func (c *Crowdsec) Reset() {
	if err := ResetAllowlist(); err != nil {
		fmt.Printf("  [crowdsec] advertencia: %v\n", err)
	}
}

// RunAction implementa modules.CLIModule. Verbos NO traducibles (son contrato CLI).
//
//	status                   Muestra estado (instalado/bouncer/servicio).
//	allowlist, list          Lista IPs/CIDR de sm-immune.
//	sync                     Sincroniza allowlist desde whitelist Tier B.
//	reset                    Borra allowlist sm-immune (sin confirmacion en CLI).
func (c *Crowdsec) RunAction(action string, args ...string) bool {
	switch strings.ToLower(action) {
	case "status":
		c.statusScreen()
		return true
	case "allowlist", "list":
		c.allowlistScreen()
		return true
	case "sync":
		c.syncScreen()
		return true
	case "reset":
		// CLI no-interactive: skip confirmation. Asume que quien lo corre
		// sabe lo que hace.
		if err := ResetAllowlist(); err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR: %v\n", err)
			return false
		}
		fmt.Println("  OK.")
		return true
	default:
		fmt.Fprintf(os.Stderr, "  Accion '%s' no reconocida.\n", action)
		fmt.Fprintln(os.Stderr, "  Acciones: status, allowlist, sync, reset")
		return false
	}
}
