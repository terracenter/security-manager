package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/terracenter/security-manager-ng/internal/i18n"
	"github.com/terracenter/security-manager-ng/internal/modules"
	"github.com/terracenter/security-manager-ng/internal/modules/blacklist"
	"github.com/terracenter/security-manager-ng/internal/modules/firewall"
	"github.com/terracenter/security-manager-ng/internal/modules/geoip"
	"github.com/terracenter/security-manager-ng/internal/modules/hardroot"
	"github.com/terracenter/security-manager-ng/internal/modules/infra"
	"github.com/terracenter/security-manager-ng/internal/modules/ssh"
	"github.com/terracenter/security-manager-ng/internal/modules/whitelist"
	"github.com/terracenter/security-manager-ng/internal/sys"
)

var Version = "dev"
var RepoURL = "https://github.com/terracenter/security-manager-ng"

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
		// Tarea 12: fail2ban fue removido en favor de crowdsec.
		// crowdsec ya tiene su modulo (`internal/modules/crowdsec`).
	}
	sort.Slice(mods, func(i, j int) bool {
		return mods[i].Order() < mods[j].Order()
	})
	return mods
}

func printMenu(mods []modules.Module) {
	st := collectStatus()
	fmt.Println("\n╔══════════════════════════════════════╗")
	fmt.Println("║       " + i18n.T("menu.title") + "            ║")
	fmt.Println("╚══════════════════════════════════════╝")
	fmt.Printf("  "+i18n.T("menu.version")+": %s\n", Version)
	fmt.Printf("  "+i18n.T("menu.repo")+": %s\n", RepoURL)
	fmt.Printf("  "+i18n.T("menu.user")+": %s\n", sys.CurrentUser())

	smStr := "✗ " + i18n.T("menu.status.firewall.inactive")
	if st.smActive {
		smStr = "✓ " + i18n.T("menu.status.firewall.active")
	}
	geoStr := "—"
	if len(st.geoCountries) > 0 {
		geoStr = strings.Join(st.geoCountries, " ")
	}
	fmt.Printf("  "+i18n.T("menu.status.firewall.label")+": %s  |  "+i18n.T("menu.status.ssh")+": :%d  |  "+i18n.T("menu.status.geoip")+": %s  |  "+i18n.T("menu.status.wl")+": %d  |  "+i18n.T("menu.status.bl")+": %d\n\n",
		smStr, st.sshPort, geoStr, st.wlCount, st.blCount)

	for i, m := range mods {
		fmt.Printf("  [%d] %s\n", i+1, m.Name())
	}
	fmt.Println("  [R] " + i18n.T("menu.option.reset"))
	fmt.Println("  [0] " + i18n.T("menu.option.exit"))
	fmt.Print("\n  " + i18n.T("menu.prompt.select") + ": ")
}

func ensureNftablesEnabled(logger *sys.SMLogger) {
	// Solo habilitar para boot — NO iniciar (start recarga /etc/nftables.conf y borra inet sm).
	// nftables.service es oneshot en Ubuntu/Debian: queda inactive(dead) después de cargar su config.
	// SM-NG gestiona su propia tabla inet sm — no depender del estado del servicio.
	out, _ := exec.Command("systemctl", "is-enabled", "nftables").Output()
	if strings.TrimSpace(string(out)) == "enabled" {
		return
	}
	fmt.Println("  [init] " + i18n.T("init.nftables.enabling") + "...")
	if out, err := exec.Command("systemctl", "enable", "nftables").CombinedOutput(); err != nil {
		logger.Warn(fmt.Sprintf("%s: %v", i18n.T("init.nftables.warn"), err))
		logger.Technical(strings.TrimSpace(string(out)))
	}
}

// resetGlobal ejecuta un reset completo de un solo nivel: no hay reset parcial que
// deje configuración huérfana. Delega en Reset() de cada módulo (mismo orden que el
// menú, por Order()) en vez de duplicar lógica de borrado de archivos aquí.
func resetGlobal(scanner *bufio.Scanner, mods []modules.Module) {
	fmt.Println("\n  ⚠️  " + i18n.T("reset.banner") + ":")
	fmt.Println("      • " + i18n.T("reset.item.ruleset") + " (" + infra.ConfDir + ")")
	fmt.Println("      • " + i18n.T("reset.item.wl"))
	fmt.Println("      • " + i18n.T("reset.item.geoip"))
	fmt.Println("      • " + i18n.T("reset.item.bl"))
	fmt.Println("      • " + i18n.T("reset.item.sudoers"))
	fmt.Println("      • " + i18n.T("reset.item.ssh"))
	fmt.Println("\n  " + i18n.T("reset.warning.single_level"))
	readLine := func(prompt string) string {
		fmt.Print(prompt)
		if !scanner.Scan() {
			return ""
		}
		return scanner.Text()
	}
	if !sys.ConfirmStrong(readLine, "\n  "+i18n.T("reset.confirm.prompt")+": ", "reset") {
		fmt.Println("  " + i18n.T("reset.confirm.cancelled"))
		return
	}

	for _, m := range mods {
		fmt.Printf("\n  [%s] %s...\n", i18n.T("reset.module.prefix"), m.Name())
		m.Reset()
	}

	fmt.Println("\n  ✓ " + i18n.T("reset.done"))
}

// handleCLI enruta argumentos CLI al módulo correspondiente.
// Retorna 0 en éxito, 1 en error.
func handleCLI(args []string, logger *sys.SMLogger) int {
	if len(args) > 0 && (args[0] == "--version" || args[0] == "-v") {
		fmt.Printf("%s %s\n%s\n", i18n.T("cli.version.line"), Version, RepoURL)
		return 0
	}
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
		fmt.Fprintf(os.Stderr, "  %s '%s'.\n", i18n.T("cli.module.not_found"), args[0])
		fmt.Fprintf(os.Stderr, "  %s: firewall, whitelist, geoip, blacklist, hardroot, ssh, crowdsec\n", i18n.T("cli.module.available"))
		return 1
	}

	cli, ok := matched.(modules.CLIModule)
	if !ok {
		fmt.Fprintf(os.Stderr, "  %s '%s'.\n", i18n.T("cli.module.no_cli"), matched.Name())
		return 1
	}

	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "  %s: security-manager-ng %s <acción> [flags]\n", i18n.T("cli.missing.action"), args[0])
		return 1
	}

	if ok := cli.RunAction(args[1], args[2:]...); !ok {
		return 1
	}
	return 0
}

func printCLIHelp() {
	fmt.Println(i18n.T("cli.version.line") + " — CLI")
	fmt.Println()
	fmt.Println(i18n.T("cli.usage") + ": security-manager-ng <módulo> <acción> [flags]")
	fmt.Println()
	fmt.Println("  " + i18n.T("cli.cmd.firewall"))
	fmt.Println("    allow      --port N --proto tcp|udp [--comment C]   " + i18n.T("cli.cmd.firewall.allow"))
	fmt.Println("    deny       --port N --proto tcp|udp                  " + i18n.T("cli.cmd.firewall.deny"))
	fmt.Println("    list-ports                                            " + i18n.T("cli.cmd.firewall.list_ports"))
	fmt.Println("    estado                                                " + i18n.T("cli.cmd.firewall.status"))
	fmt.Println("    apply                                                 " + i18n.T("cli.cmd.firewall.apply"))
	fmt.Println("    reset                                                 " + i18n.T("cli.cmd.firewall.reset"))
	fmt.Println("    port80     on|off                                     " + i18n.T("cli.cmd.firewall.port80"))
	fmt.Println()
	fmt.Println("  " + i18n.T("cli.cmd.whitelist"))
	fmt.Println("    add <ip> --tier A|B [--responsable R] [--proposito P] [--vencimiento YYYY-MM-DD]   " + i18n.T("cli.cmd.whitelist.add"))
	fmt.Println("    add-self  --tier A|B                                  " + i18n.T("cli.cmd.whitelist.add_self"))
	fmt.Println("    list      [--tier A|B]                                " + i18n.T("cli.cmd.whitelist.list"))
	fmt.Println("    del  <ip> --tier A|B                                  " + i18n.T("cli.cmd.whitelist.del"))
	fmt.Println("    sync                                                  " + i18n.T("cli.cmd.whitelist.sync"))
	fmt.Println()
	fmt.Println("  " + i18n.T("cli.cmd.geoip"))
	fmt.Println("    add <CC...>                                           " + i18n.T("cli.cmd.geoip.add"))
	fmt.Println("    del <CC>                                              " + i18n.T("cli.cmd.geoip.del"))
	fmt.Println("    list                                                  " + i18n.T("cli.cmd.geoip.list"))
	fmt.Println("    update                                                " + i18n.T("cli.cmd.geoip.update"))
	fmt.Println("    apply                                                 " + i18n.T("cli.cmd.geoip.apply"))
	fmt.Println("    reset                                                 " + i18n.T("cli.cmd.geoip.reset"))
	fmt.Println("    preview                                               " + i18n.T("cli.cmd.geoip.preview"))
	fmt.Println()
	fmt.Println("  " + i18n.T("cli.cmd.blacklist"))
	fmt.Println("    add <ip|CIDR>                                         " + i18n.T("cli.cmd.blacklist.add"))
	fmt.Println("    list                                                  " + i18n.T("cli.cmd.blacklist.list"))
	fmt.Println("    del <ip|CIDR>                                         " + i18n.T("cli.cmd.blacklist.del"))
	fmt.Println("    flush                                                 " + i18n.T("cli.cmd.blacklist.flush"))
	fmt.Println()
	fmt.Println("  " + i18n.T("cli.cmd.hardroot"))
	fmt.Println("    estado                                                " + i18n.T("cli.cmd.hardroot.status"))
	fmt.Println("    harden-ssh                                            " + i18n.T("cli.cmd.hardroot.harden_ssh"))
	fmt.Println("    lock-root                                             " + i18n.T("cli.cmd.hardroot.lock_root"))
	fmt.Println("    sudoers                                               " + i18n.T("cli.cmd.hardroot.sudoers"))
	fmt.Println()
	fmt.Println("  " + i18n.T("cli.cmd.ssh"))
	fmt.Println("    estado                                                " + i18n.T("cli.cmd.ssh.status"))
	fmt.Println("    apply  [--groups G] [--auth 1|2|3] [--tunnel]        " + i18n.T("cli.cmd.ssh.apply"))
	fmt.Println("             --auth 1 = " + i18n.T("cli.cmd.ssh.apply.auth1"))
	fmt.Println("             --auth 2 = " + i18n.T("cli.cmd.ssh.apply.auth2"))
	fmt.Println("             --auth 3 = " + i18n.T("cli.cmd.ssh.apply.auth3"))
	fmt.Println("    banners                                               " + i18n.T("cli.cmd.ssh.banners"))
	fmt.Println("    validar                                               " + i18n.T("cli.cmd.ssh.validate"))
	fmt.Println()
	fmt.Println(i18n.T("cli.no_args.help"))
}

func main() {
	if err := i18n.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "i18n load failed: %v\n", err)
		os.Exit(1)
	}

	logger := sys.NewLogger()
	defer logger.Close()

	if len(os.Args) > 1 {
		os.Exit(handleCLI(os.Args[1:], logger))
	}
	ensureNftablesEnabled(logger)
	mods := initModules(logger)
	scanner := bufio.NewScanner(os.Stdin)
	for {
		printMenu(mods)
		if !scanner.Scan() {
			break
		}
		input := strings.TrimSpace(scanner.Text())

		if input == "0" {
			fmt.Println("\n  " + i18n.T("menu.exit.goodbye"))
			break
		}

		if strings.EqualFold(input, "r") {
			resetGlobal(scanner, mods)
			continue
		}

		var sel int
		if _, err := fmt.Sscanf(input, "%d", &sel); err != nil {
			fmt.Println("  " + i18n.T("menu.invalid.option"))
			continue
		}
		if sel < 1 || sel > len(mods) {
			fmt.Println("  " + i18n.T("menu.invalid.range"))
			continue
		}
		mods[sel-1].Menu()
	}
}
