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
	"github.com/terracenter/security-manager-ng/internal/modules/infra"
	"github.com/terracenter/security-manager-ng/internal/modules/ssh"
	"github.com/terracenter/security-manager-ng/internal/modules/whitelist"
	"github.com/terracenter/security-manager-ng/internal/sys"
)

var Version = "dev"

type sysStatus struct {
	smActive     bool
	sshPort      int
	geoCountries []string
	wlCount      int
	blCount      int
}

func collectStatus() sysStatus {
	s := sysStatus{}
	s.smActive = exec.Command("nft", "list", "table", "inet", "sm").Run() == nil
	s.sshPort = infra.DetectSSHPort()
	if gd, err := infra.LoadGeoIPData(); err == nil {
		for _, cs := range gd.Countries {
			s.geoCountries = append(s.geoCountries, cs.CC)
		}
	}
	if wl4, err := infra.ReadACLEntries(infra.Whitelist4File); err == nil {
		s.wlCount += len(wl4)
	}
	if wl6, err := infra.ReadACLEntries(infra.Whitelist6File); err == nil {
		s.wlCount += len(wl6)
	}
	if bl4, err := infra.ReadACLEntries(infra.Blacklist4File); err == nil {
		s.blCount += len(bl4)
	}
	if bl6, err := infra.ReadACLEntries(infra.Blacklist6File); err == nil {
		s.blCount += len(bl6)
	}
	return s
}

func initModules(logger *sys.SMLogger) []modules.Module {
	mods := []modules.Module{
		firewall.New(logger),
		whitelist.New(),
		geoip.New(logger),
		blacklist.New(logger),
		hardroot.New(logger),
		ssh.New(),
		fail2ban.New(),
	}
	sort.Slice(mods, func(i, j int) bool {
		return mods[i].Order() < mods[j].Order()
	})
	return mods
}

func printMenu(mods []modules.Module) {
	st := collectStatus()
	fmt.Println("\n╔══════════════════════════════════════╗")
	fmt.Println("║       Security Manager NG            ║")
	fmt.Println("╚══════════════════════════════════════╝")
	fmt.Printf("  Versión: %s\n", Version)
	fmt.Printf("  Usuario activo: %s\n", sys.CurrentUser())

	smStr := "✗ inactiva"
	if st.smActive {
		smStr = "✓ activa"
	}
	geoStr := "—"
	if len(st.geoCountries) > 0 {
		geoStr = strings.Join(st.geoCountries, " ")
	}
	fmt.Printf("  inet sm: %s  |  SSH: :%d  |  GeoIP: %s  |  WL: %d  |  BL: %d\n\n",
		smStr, st.sshPort, geoStr, st.wlCount, st.blCount)

	for i, m := range mods {
		fmt.Printf("  [%d] %s\n", i+1, m.Name())
	}
	fmt.Println("  [R] Reset Global — eliminar tabla inet sm")
	fmt.Println("  [0] Salir")
	fmt.Print("\n  Selección: ")
}

func ensureNftablesEnabled() {
	// Solo habilitar para boot — NO iniciar (start recarga /etc/nftables.conf y borra inet sm).
	// nftables.service es oneshot en Ubuntu/Debian: queda inactive(dead) después de cargar su config.
	// SM-NG gestiona su propia tabla inet sm — no depender del estado del servicio.
	out, _ := exec.Command("systemctl", "is-enabled", "nftables").Output()
	if strings.TrimSpace(string(out)) == "enabled" {
		return
	}
	fmt.Println("  [init] Habilitando nftables.service para arranque automático...")
	if out, err := exec.Command("systemctl", "enable", "nftables").CombinedOutput(); err != nil {
		fmt.Printf("  WARN: systemctl enable nftables — %v: %s\n", err, strings.TrimSpace(string(out)))
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
	if _, err := exec.Command("nft", "delete", "table", "inet", "sm").CombinedOutput(); err != nil {
		fmt.Printf("  ERROR: nft delete table inet sm — %v\n", err)
	} else {
		fmt.Println("  [reset] OK — tabla inet sm eliminada.")
	}

	fmt.Println("  [reset] Borrando /etc/fail2ban/jail.d/sm-ng-whitelist.conf...")
	if _, err := exec.Command("rm", "-f", "/etc/fail2ban/jail.d/sm-ng-whitelist.conf").CombinedOutput(); err != nil {
		fmt.Printf("  ERROR: rm sm-ng-whitelist.conf — %v\n", err)
	} else {
		fmt.Println("  [reset] OK — archivo de ignoreip eliminado.")
	}

	fmt.Println("  [reset] Recargando fail2ban...")
	if _, err := exec.Command("fail2ban-client", "reload").CombinedOutput(); err != nil {
		fmt.Printf("  WARN: fail2ban reload — %v\n", err)
	} else {
		fmt.Println("  [reset] OK — fail2ban recargado.")
	}

	fmt.Print("\n  ¿Purgar también /etc/security-manager/* (todas las configs)? (s/n): ")
	scanner.Scan()
	if strings.EqualFold(strings.TrimSpace(scanner.Text()), "s") {
		fmt.Println("  [reset] Purgando /etc/security-manager/...")
		if _, err := exec.Command("rm", "-rf", "/etc/security-manager").CombinedOutput(); err != nil {
			fmt.Printf("  ERROR: rm /etc/security-manager — %v\n", err)
		} else {
			fmt.Println("  [reset] OK — configuraciones purgadas.")
		}

		// Limpiar include en /etc/nftables.conf para evitar fallo de nftables.service en boot.
		fmt.Println("  [reset] Limpiando include de /etc/nftables.conf...")
		const nftConf = "/etc/nftables.conf"
		if data, err := os.ReadFile(nftConf); err == nil {
			var kept []string
			for _, line := range strings.Split(string(data), "\n") {
				if !strings.Contains(line, `include "/etc/security-manager/sm.nft"`) &&
					!strings.Contains(line, "# Security Manager NG") {
					kept = append(kept, line)
				}
			}
			cleaned := strings.TrimRight(strings.Join(kept, "\n"), "\n") + "\n"
			if err := os.WriteFile(nftConf, []byte(cleaned), 0o644); err != nil {
				fmt.Printf("  WARN: no se pudo limpiar %s: %v\n", nftConf, err)
			} else {
				fmt.Println("  [reset] OK — include sm.nft eliminado de nftables.conf.")
			}
		} else {
			fmt.Printf("  WARN: no se pudo leer %s: %v\n", nftConf, err)
		}
	}

	fmt.Println("\n  ✓ Reset Global completado. El host está limpio de Security Manager NG.")
}

// handleCLI enruta argumentos CLI al módulo correspondiente.
// Retorna 0 en éxito, 1 en error.
func handleCLI(args []string, logger *sys.SMLogger) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printCLIHelp()
		return 0
	}
	mods := initModules(logger)
	modName := strings.ToLower(args[0])

	// Matching flexible: exacto, luego prefijo, luego substring (igual que SM-Go).
	var matched modules.Module
	for _, m := range mods {
		name := strings.ToLower(m.Name())
		// Normalizar nombre del módulo para matching (quitar paréntesis y descripción).
		// "Firewall (nftables)" → "firewall"
		if idx := strings.Index(name, " "); idx > 0 {
			name = name[:idx]
		}
		if name == modName {
			matched = m
			break
		}
	}
	if matched == nil {
		for _, m := range mods {
			name := strings.ToLower(m.Name())
			if strings.HasPrefix(name, modName) {
				matched = m
				break
			}
		}
	}
	if matched == nil {
		for _, m := range mods {
			name := strings.ToLower(m.Name())
			if strings.Contains(name, modName) {
				matched = m
				break
			}
		}
	}

	if matched == nil {
		fmt.Fprintf(os.Stderr, "  Módulo '%s' no encontrado.\n", args[0])
		fmt.Fprintf(os.Stderr, "  Módulos disponibles: firewall, whitelist, geoip, blacklist, hardroot, ssh, fail2ban\n")
		return 1
	}

	cli, ok := matched.(modules.CLIModule)
	if !ok {
		fmt.Fprintf(os.Stderr, "  El módulo '%s' no soporta CLI aún. Usa el menú interactivo.\n", matched.Name())
		return 1
	}

	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "  Falta acción. Uso: security-manager-ng %s <acción> [flags]\n", args[0])
		return 1
	}

	if ok := cli.RunAction(args[1], args[2:]...); !ok {
		return 1
	}
	return 0
}

func printCLIHelp() {
	fmt.Println("Security Manager NG — CLI")
	fmt.Println()
	fmt.Println("Uso: security-manager-ng <módulo> <acción> [flags]")
	fmt.Println()
	fmt.Println("  firewall")
	fmt.Println("    allow      --port N --proto tcp|udp [--comment C]   Abre puerto globalmente (bypass GeoIP)")
	fmt.Println("    deny       --port N --proto tcp|udp                  Cierra puerto previamente abierto")
	fmt.Println("    list-ports                                            Lista puertos en allowed_ports.conf")
	fmt.Println("    estado                                                Estado de la tabla inet sm")
	fmt.Println("    apply                                                 Aplica / recarga ruleset base")
	fmt.Println("    reset                                                 Elimina tabla inet sm")
	fmt.Println("    port80     on|off                                     Puerto 80 global (ACME/Let's Encrypt)")
	fmt.Println()
	fmt.Println("  fail2ban")
	fmt.Println("    buscar <ip>                                           Diagnóstico completo: fail2ban + nftables")
	fmt.Println("    baneadas [--jail J]                                   IPs baneadas (todos los jails o uno)")
	fmt.Println("    estado                                                Estado del servicio y jails activos")
	fmt.Println("    geo <ip>                                              Geolocalización vía ipinfo.io")
	fmt.Println()
	fmt.Println("  whitelist")
	fmt.Println("    add <ip> --tier A|B [--responsable R] [--proposito P] [--vencimiento YYYY-MM-DD]")
	fmt.Println("    add-self  --tier A|B                                  Agregar IP de sesión SSH activa")
	fmt.Println("    list      [--tier A|B]                                Listar entradas (A=confiables, B=intocables)")
	fmt.Println("    del  <ip> --tier A|B                                  Eliminar entrada")
	fmt.Println("    sync                                                  Sincronizar Tier B → fail2ban ignoreip")
	fmt.Println()
	fmt.Println("  geoip")
	fmt.Println("    add <CC...>                                           Agregar países permitidos (ej: VE CO PE)")
	fmt.Println("    del <CC>                                              Eliminar país de la lista")
	fmt.Println("    list                                                  Ver países configurados")
	fmt.Println("    update                                                Descargar rangos desde ipdeny.com")
	fmt.Println("    apply                                                 Aplicar / recargar ruleset GeoIP")
	fmt.Println("    reset                                                 Borrar lista de países y zone files")
	fmt.Println("    preview                                               Vista previa del ruleset sm.nft")
	fmt.Println()
	fmt.Println("  blacklist")
	fmt.Println("    add <ip|CIDR>                                         Banear IP o red")
	fmt.Println("    list                                                  Listar IPs baneadas")
	fmt.Println("    del <ip|CIDR>                                         Eliminar del ban")
	fmt.Println("    flush                                                 Vaciar blacklist completa")
	fmt.Println()
	fmt.Println("  hardroot")
	fmt.Println("    estado                                                Ver estado root/SSH/sudoers")
	fmt.Println("    harden-ssh                                            PermitRootLogin no + PermitEmptyPasswords no")
	fmt.Println("    lock-root                                             Bloquear cuenta root (passwd -l)")
	fmt.Println("    sudoers                                               Crear /etc/sudoers.d/sm-ng")
	fmt.Println()
	fmt.Println("  ssh")
	fmt.Println("    estado                                                Ver estado SSH hardening")
	fmt.Println("    apply  [--groups G] [--auth 1|2|3] [--tunnel]        Aplicar 10-sshd-base.conf")
	fmt.Println("             --auth 1 = solo llave pública (recomendado)")
	fmt.Println("             --auth 2 = llave O contraseña")
	fmt.Println("             --auth 3 = llave Y contraseña (MFA)")
	fmt.Println("    banners                                               Escribir /etc/issue.net y /etc/issue")
	fmt.Println("    validar                                               Validar config activa (sshd -T)")
	fmt.Println()
	fmt.Println("Sin argumentos: inicia el menú interactivo.")
}

func main() {
	logger := sys.NewLogger()
	defer logger.Close()

	if len(os.Args) > 1 {
		os.Exit(handleCLI(os.Args[1:], logger))
	}
	ensureNftablesEnabled()
	mods := initModules(logger)
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
