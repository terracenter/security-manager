package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"

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
	fmt.Printf("  Usuario activo: %s\n\n", sys.CurrentUser())
	for i, m := range mods {
		fmt.Printf("  [%d] %s\n", i+1, m.Name())
	}
	fmt.Println("  [0] Salir")
	fmt.Print("\n  Selección: ")
}

func main() {
	mods := initModules()
	scanner := bufio.NewScanner(os.Stdin)
	for {
		printMenu(mods)
		if !scanner.Scan() {
			break
		}
		var sel int
		if _, err := fmt.Sscanf(scanner.Text(), "%d", &sel); err != nil {
			fmt.Println("  Opción inválida.")
			continue
		}
		if sel == 0 {
			fmt.Println("\n  Saliendo. Hasta luego.")
			break
		}
		if sel < 1 || sel > len(mods) {
			fmt.Println("  Opción fuera de rango.")
			continue
		}
		mods[sel-1].Menu()
	}
}
