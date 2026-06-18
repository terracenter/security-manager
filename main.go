package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/terracenter/security-manager-ng/internal/modules"
	"github.com/terracenter/security-manager-ng/internal/modules/blacklist"
	"github.com/terracenter/security-manager-ng/internal/modules/fail2ban"
	"github.com/terracenter/security-manager-ng/internal/modules/firewall"
	"github.com/terracenter/security-manager-ng/internal/modules/geoip"
	"github.com/terracenter/security-manager-ng/internal/modules/hardroot"
	"github.com/terracenter/security-manager-ng/internal/modules/ssh"
	"github.com/terracenter/security-manager-ng/internal/modules/whitelist"
	"github.com/terracenter/security-manager-ng/internal/sys"
)

var Version = "dev"

func initModules() []modules.Module {
	mods := []modules.Module{
		firewall.New(),
		whitelist.New(),
		geoip.New(),
		blacklist.New(),
		hardroot.New(),
		ssh.New(),
		fail2ban.New(),
	}
	sort.Slice(mods, func(i, j int) bool {
		return mods[i].Order() < mods[j].Order()
	})
	return mods
}

func printMenu(mods []modules.Module) {
	fmt.Println("\n╔══════════════════════════════════════╗")
	fmt.Println("║       Security Manager NG            ║")
	fmt.Println("╚══════════════════════════════════════╝")
	fmt.Printf("  Versión: %s\n", Version)
	fmt.Printf("  Usuario activo: %s\n\n", sys.CurrentUser())
	for i, m := range mods {
		fmt.Printf("  [%d] %s\n", i+1, m.Name())
	}
	fmt.Println("  [R] Reset Global — eliminar tabla inet sm")
	fmt.Println("  [0] Salir")
	fmt.Print("\n  Selección: ")
}

func ensureNftablesEnabled() {
	if _, err := exec.Command("systemctl", "is-enabled", "nftables").Output(); err == nil {
		if _, err := exec.Command("systemctl", "is-active", "nftables").Output(); err == nil {
			return
		}
	}

	fmt.Println("  [init] nftables no activo — habilitando y iniciando...")
	if _, err := exec.Command("sudo", "systemctl", "enable", "nftables").CombinedOutput(); err != nil {
		fmt.Printf("  WARN: systemctl enable nftables — %v\n", err)
	}
	if _, err := exec.Command("sudo", "systemctl", "start", "nftables").CombinedOutput(); err != nil {
		fmt.Printf("  WARN: systemctl start nftables — %v\n", err)
	}
}

func resetGlobal(scanner *bufio.Scanner) {
	fmt.Println("\n  ⚠️  ADVERTENCIA: Reset Global eliminará la tabla nftables inet sm de este host.")
	fmt.Print("  ¿Continuar? (s/n): ")
	scanner.Scan()
	if !strings.EqualFold(strings.TrimSpace(scanner.Text()), "s") {
		fmt.Println("  Operación cancelada.")
		return
	}

	fmt.Println("\n  Confirmación final (esta es tu última oportunidad).")
	fmt.Print("  Escribe 'reset' para confirmar: ")
	scanner.Scan()
	if !strings.EqualFold(strings.TrimSpace(scanner.Text()), "reset") {
		fmt.Println("  Operación cancelada.")
		return
	}

	fmt.Println("\n  [reset] Ejecutando nft delete table inet sm...")
	if _, err := exec.Command("sudo", "nft", "delete", "table", "inet", "sm").CombinedOutput(); err != nil {
		fmt.Printf("  ERROR: nft delete table inet sm — %v\n", err)
	} else {
		fmt.Println("  [reset] OK — tabla inet sm eliminada.")
	}

	fmt.Println("  [reset] Borrando /etc/fail2ban/jail.d/sm-ng-whitelist.conf...")
	if _, err := exec.Command("sudo", "rm", "-f", "/etc/fail2ban/jail.d/sm-ng-whitelist.conf").CombinedOutput(); err != nil {
		fmt.Printf("  ERROR: rm sm-ng-whitelist.conf — %v\n", err)
	} else {
		fmt.Println("  [reset] OK — archivo de ignoreip eliminado.")
	}

	fmt.Println("  [reset] Recargando fail2ban...")
	if _, err := exec.Command("sudo", "fail2ban-client", "reload").CombinedOutput(); err != nil {
		fmt.Printf("  WARN: fail2ban reload — %v\n", err)
	} else {
		fmt.Println("  [reset] OK — fail2ban recargado.")
	}

	fmt.Print("\n  ¿Purgar también /etc/security-manager/* (todas las configs)? (s/n): ")
	scanner.Scan()
	if strings.EqualFold(strings.TrimSpace(scanner.Text()), "s") {
		fmt.Println("  [reset] Purgando /etc/security-manager/...")
		if _, err := exec.Command("sudo", "rm", "-rf", "/etc/security-manager").CombinedOutput(); err != nil {
			fmt.Printf("  ERROR: rm /etc/security-manager — %v\n", err)
		} else {
			fmt.Println("  [reset] OK — configuraciones purgadas.")
		}
	}

	fmt.Println("\n  ✓ Reset Global completado. El host está limpio de Security Manager NG.")
}

func main() {
	ensureNftablesEnabled()
	mods := initModules()
	scanner := bufio.NewScanner(os.Stdin)
	for {
		printMenu(mods)
		if !scanner.Scan() {
			break
		}
		input := strings.TrimSpace(scanner.Text())

		if input == "0" {
			fmt.Println("\n  Saliendo. Hasta luego.")
			break
		}

		if strings.EqualFold(input, "r") {
			resetGlobal(scanner)
			continue
		}

		var sel int
		if _, err := fmt.Sscanf(input, "%d", &sel); err != nil {
			fmt.Println("  Opción inválida.")
			continue
		}
		if sel < 1 || sel > len(mods) {
			fmt.Println("  Opción fuera de rango.")
			continue
		}
		mods[sel-1].Menu()
	}
}
