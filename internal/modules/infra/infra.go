package infra

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Rutas y constantes compartidas entre módulos (SSoT).
const (
	ConfDir     = "/etc/security-manager"
	RulesetFile = ConfDir + "/sm.nft"
	BackupFile  = ConfDir + "/sm.nft.bak"

	// Sets nftables — whitelist / blacklist
	SetWhitelist4 = "sm_whitelist4"
	SetWhitelist6 = "sm_whitelist6"
	SetBlacklist4 = "sm_blacklist4"
	SetBlacklist6 = "sm_blacklist6"

	Table = "inet sm"

	// Config persistente de whitelist y blacklist (un CIDR/IP por línea)
	Whitelist4File = ConfDir + "/whitelist4.conf"
	Whitelist6File = ConfDir + "/whitelist6.conf"
	Blacklist4File = ConfDir + "/blacklist4.conf"
	Blacklist6File = ConfDir + "/blacklist6.conf"

	// GeoIP
	GeoIPDir             = ConfDir + "/geoip"
	BlockedCountriesFile = ConfDir + "/blocked_countries.conf"
)

// GeoIPData contiene los rangos por país a incrustar en el ruleset.
type GeoIPData struct {
	Countries []CountrySet
}

// CountrySet agrupa los rangos IPv4/IPv6 de un país.
type CountrySet struct {
	CC      string
	Ranges4 []string
	Ranges6 []string
}

// LoadGeoIPData lee blocked_countries.conf y los archivos zone de GeoIPDir.
// Retorna GeoIPData vacía si el archivo de config no existe.
func LoadGeoIPData() (GeoIPData, error) {
	f, err := os.Open(BlockedCountriesFile)
	if os.IsNotExist(err) {
		return GeoIPData{}, nil
	}
	if err != nil {
		return GeoIPData{}, fmt.Errorf("leer %s: %w", BlockedCountriesFile, err)
	}
	defer f.Close()

	var countries []CountrySet
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		cc := strings.TrimSpace(sc.Text())
		if cc == "" || strings.HasPrefix(cc, "#") {
			continue
		}
		lower := strings.ToLower(cc)
		cs := CountrySet{CC: strings.ToUpper(cc)}
		cs.Ranges4, _ = ReadLines(GeoIPDir + "/" + lower + ".zone")
		cs.Ranges6, _ = ReadLines(GeoIPDir + "/" + lower + ".zone6")
		if len(cs.Ranges4) > 0 || len(cs.Ranges6) > 0 {
			countries = append(countries, cs)
		}
	}
	return GeoIPData{Countries: countries}, sc.Err()
}

// ReadLines lee un archivo de texto y retorna las líneas no vacías sin comentarios.
func ReadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

// DetectSSHPort lee /etc/ssh/sshd_config y retorna el puerto SSH (default 22).
func DetectSSHPort() int {
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

// GenerateRuleset produce el contenido completo de sm.nft.
// Lee whitelist/blacklist desde los archivos de config para preservar entradas entre recargas.
func GenerateRuleset(sshPort int, geoip GeoIPData) string {
	sshComment := ""
	if sshPort != 22 {
		sshComment = " # puerto personalizado (sshd_config)"
	}

	wl4, _ := ReadLines(Whitelist4File)
	wl6, _ := ReadLines(Whitelist6File)
	bl4, _ := ReadLines(Blacklist4File)
	bl6, _ := ReadLines(Blacklist6File)

	return fmt.Sprintf(`#!/usr/sbin/nft -f
# Security-Manager-NG — ruleset base
# Generado automáticamente. NO editar manualmente.
# Tabla: inet sm — pipeline de 9 etapas (declarativo, atómico)
#
# Para recargar: nft -f %s
# Para validar:  nft -c -f %s

flush ruleset

table inet sm {

    # ── Sets whitelist / blacklist ────────────────────────────────────
%s%s%s%s
    # ── Sets GeoIP (por país) ────────────────────────────────────────
%s
    # ── Chain principal ──────────────────────────────────────────────

    chain input {
        type filter hook input priority filter; policy drop;

        # 1 · Conntrack fast-path
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

        # 6 · Whitelist / SSoT — bypass total
        ip  saddr @%s accept
        ip6 saddr @%s accept

        # 7 · GeoIP
%s
        # 8 · Servicios permitidos
        tcp dport %d accept%s
        tcp dport { 80, 443 } accept
        icmp   type echo-request limit rate 10/second accept
        icmpv6 type echo-request limit rate 10/second accept

        # 9 · Default DROP
        log prefix "SM-DROP-DEFAULT " drop
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
    }
}
`,
		RulesetFile, RulesetFile,
		formatSet(SetWhitelist4, "ipv4_addr", `Infra confiable IPv4 — bypass total (SSoT)`, wl4),
		formatSet(SetWhitelist6, "ipv6_addr", `Infra confiable IPv6 — bypass total (SSoT)`, wl6),
		formatSet(SetBlacklist4, "ipv4_addr", `Bans manuales IPv4`, bl4),
		formatSet(SetBlacklist6, "ipv6_addr", `Bans manuales IPv6`, bl6),
		geoipSetsBlock(geoip),
		SetBlacklist4, SetBlacklist6,
		SetWhitelist4, SetWhitelist6,
		geoipRulesBlock(geoip),
		sshPort, sshComment,
	)
}

func formatSet(name, addrType, comment string, elements []string) string {
	s := fmt.Sprintf("\n    set %s {\n        type %s\n        flags interval\n        comment %q\n",
		name, addrType, comment)
	if len(elements) > 0 {
		s += fmt.Sprintf("        elements = { %s }\n", strings.Join(elements, ", "))
	}
	s += "    }\n"
	return s
}

func geoipSetsBlock(geoip GeoIPData) string {
	if len(geoip.Countries) == 0 {
		return "    # (sin países bloqueados)\n"
	}
	var sb strings.Builder
	for _, cs := range geoip.Countries {
		lower := strings.ToLower(cs.CC)
		if len(cs.Ranges4) > 0 {
			sb.WriteString(fmt.Sprintf("\n    set geoip_%s4 {\n        type ipv4_addr\n        flags interval\n        comment \"GeoIP block %s IPv4\"\n        elements = { %s }\n    }\n",
				lower, cs.CC, strings.Join(cs.Ranges4, ", ")))
		}
		if len(cs.Ranges6) > 0 {
			sb.WriteString(fmt.Sprintf("\n    set geoip_%s6 {\n        type ipv6_addr\n        flags interval\n        comment \"GeoIP block %s IPv6\"\n        elements = { %s }\n    }\n",
				lower, cs.CC, strings.Join(cs.Ranges6, ", ")))
		}
	}
	return sb.String()
}

func geoipRulesBlock(geoip GeoIPData) string {
	if len(geoip.Countries) == 0 {
		return "        # (sin países bloqueados configurados)"
	}
	var sb strings.Builder
	for _, cs := range geoip.Countries {
		lower := strings.ToLower(cs.CC)
		if len(cs.Ranges4) > 0 {
			sb.WriteString(fmt.Sprintf("        ip  saddr @geoip_%s4 drop\n", lower))
		}
		if len(cs.Ranges6) > 0 {
			sb.WriteString(fmt.Sprintf("        ip6 saddr @geoip_%s6 drop\n", lower))
		}
	}
	return strings.TrimRight(sb.String(), "\n")
}
