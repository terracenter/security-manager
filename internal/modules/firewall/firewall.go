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
		fmt.Println("\n  ┌─ Firewall (nftables) ──────────────────┐")
		fmt.Println("  │  [1] Aplicar / recargar ruleset base    │")
		fmt.Println("  │  [2] Ver estado actual                  │")
		fmt.Println("  │  [3] Resetear tabla inet sm             │")
		fmt.Println("  │  [0] Volver                             │")
		fmt.Println("  └────────────────────────────────────────┘")
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
		case "0":
			return
		default:
			fmt.Println("  Opción inválida.")
		}
	}
}

// applyBase genera el ruleset base, valida la sintaxis y lo aplica con safeapply.
func (f *Firewall) applyBase() {
	sshPort := detectSSHPort()
	ruleset := generateRuleset(sshPort)

	if err := ensureConfDir(); err != nil {
		fmt.Printf("\n  ERROR: %v\n", err)
		return
	}

	tmpFile := infra.ConfDir + "/sm.nft.new"
	if err := os.WriteFile(tmpFile, []byte(ruleset), 0o640); err != nil {
		fmt.Printf("\n  ERROR escribiendo ruleset temporal: %v\n", err)
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

	if err := os.Rename(tmpFile, infra.RulesetFile); err != nil {
		fmt.Printf("\n  ERROR moviendo ruleset: %v\n", err)
		return
	}

	backupFile := infra.ConfDir + "/sm.nft.bak"
	err = safeapply.Apply(safeapply.Plan{
		BackupFile:     backupFile,
		RulesetFile:    infra.RulesetFile,
		DeadmanTimeout: 120,
		WhitelistSet:   "",
	})
	if err != nil {
		fmt.Printf("\n  [firewall] %v\n", err)
	}
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

// resetTable ejecuta flush table inet sm tras confirmación del operador.
func (f *Firewall) resetTable() {
	fmt.Print("\n  ¿Confirmar reset (flush) de la tabla inet sm? [s/N]: ")
	if !f.scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(f.scanner.Text())) != "s" {
		fmt.Println("  Cancelado.")
		return
	}
	out, err := exec.Command("nft", "flush", "table", "inet", "sm").CombinedOutput()
	if err != nil {
		fmt.Printf("  ERROR en flush: %s\n", strings.TrimSpace(string(out)))
		return
	}
	fmt.Println("  Tabla inet sm reseteada.")
}

// ensureConfDir crea /etc/security-manager si no existe.
func ensureConfDir() error {
	if err := os.MkdirAll(infra.ConfDir, 0o750); err != nil {
		return fmt.Errorf("crear %s: %w", infra.ConfDir, err)
	}
	return nil
}

// detectSSHPort intenta detectar el puerto SSH activo leyendo sshd_config.
// Retorna 22 si no puede determinarlo.
func detectSSHPort() int {
	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return 22
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(strings.ToLower(line), "port ") {
			continue
		}
		var port int
		if _, err := fmt.Sscanf(line[5:], "%d", &port); err == nil && port > 0 {
			return port
		}
	}
	return 22
}

// generateRuleset produce el ruleset nftables completo como string.
// sshPort: puerto SSH a permitir en la etapa de servicios (default 22).
func generateRuleset(sshPort int) string {
	sshComment := ""
	if sshPort != 22 {
		sshComment = fmt.Sprintf(" # puerto personalizado (sshd_config)")
	}

	return fmt.Sprintf(`#!/usr/sbin/nft -f
# Security-Manager-NG — ruleset base
# Generado por el módulo firewall. NO editar manualmente.
# Tabla: inet sm — pipeline de 9 etapas (declarativo, atómico)
#
# ORDEN CRÍTICO:
#   5-Blacklist ANTES de 6-Whitelist
#   6-Whitelist ANTES de 7-GeoIP
#
# Para recargar: nft -f %s
# Para validar:  nft -c -f %s

flush ruleset

table inet sm {

    #
    # Sets — reemplaza ipset; flags interval para CIDR/rangos
    #

    set %s {
        type ipv4_addr
        flags interval
        comment "Infra confiable IPv4 — bypass total (SSoT)"
    }

    set %s {
        type ipv6_addr
        flags interval
        comment "Infra confiable IPv6 — bypass total (SSoT)"
    }

    set %s {
        type ipv4_addr
        flags interval
        comment "Bans manuales IPv4"
    }

    set %s {
        type ipv6_addr
        flags interval
        comment "Bans manuales IPv6"
    }

    #
    # Chain principal — pipeline de filtrado de entrada
    #

    chain input {
        type filter hook input priority filter; policy drop;

        # 1 · Conntrack fast-path: tráfico ya conocido
        ct state established,related accept

        # 2 · Loopback
        iif lo accept

        # 3 · Conntrack inválido
        ct state invalid drop

        # 4 · Antirecon — XMAS, NULL, FIN+SYN, SYN+RST
        tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn|rst|psh|ack|urg \
            limit rate 5/minute log prefix "SM-ANTIRECON XMAS " drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 \
            limit rate 5/minute log prefix "SM-ANTIRECON NULL " drop
        tcp flags & (fin|syn) == fin|syn \
            limit rate 5/minute log prefix "SM-ANTIRECON FIN+SYN " drop
        tcp flags & (syn|rst) == syn|rst \
            limit rate 5/minute log prefix "SM-ANTIRECON SYN+RST " drop

        # 5 · Blacklist (antes que whitelist)
        ip  saddr @%s drop
        ip6 saddr @%s drop

        # 6 · Whitelist / SSoT — bypass total, infra confiable
        ip  saddr @%s accept
        ip6 saddr @%s accept

        # 7 · GeoIP (placeholder — activado por módulo geoip)
        # ip saddr @geoip_<cc>4 drop  ← módulo geoip escribe esta sección

        # 8 · Servicios permitidos
        tcp dport %d accept%s
        tcp dport { 80, 443 } accept
        icmp   type echo-request limit rate 10/second accept
        icmpv6 type echo-request limit rate 10/second accept

        # 9 · Default DROP con log
        log prefix "SM-DROP-DEFAULT " drop
    }

    #
    # NAT — postrouting para WireGuard (si aplica)
    #

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        # WireGuard NAT: oifname "eth0" masquerade
        # (activado por módulo ssh/vpn si se detecta wg0)
    }
}
`,
		infra.RulesetFile, infra.RulesetFile,
		infra.SetWhitelist4, infra.SetWhitelist6,
		infra.SetBlacklist4, infra.SetBlacklist6,
		infra.SetBlacklist4, infra.SetBlacklist6,
		infra.SetWhitelist4, infra.SetWhitelist6,
		sshPort, sshComment,
	)
}

// _ ensures the interface is satisfied at compile time.
var _ interface {
	Order() int
	Name() string
	Menu()
	Reset()
} = (*Firewall)(nil)
