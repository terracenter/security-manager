package infra

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Rutas y constantes compartidas entre módulos (SSoT).
const (
	ConfDir     = "/etc/security-manager"
	RulesetFile = ConfDir + "/sm.nft"
	BackupFile  = ConfDir + "/sm.nft.bak"

	// Sets nftables — whitelist (Tier A) / immune (Tier B) / blacklist
	SetWhitelist4 = "sm_whitelist4"
	SetWhitelist6 = "sm_whitelist6"
	SetImmune4    = "sm_immune4"
	SetImmune6    = "sm_immune6"
	SetBlacklist4 = "sm_blacklist4"
	SetBlacklist6 = "sm_blacklist6"

	Table = "inet sm"

	// Config persistente. whitelist/immune usan formato con metadatos (ver ReadACLEntries);
	// blacklist sigue siendo un CIDR/IP por línea.
	// Tier A (Confiables/vigiladas): pasan el firewall, fail2ban SÍ puede banearlas.
	Whitelist4File = ConfDir + "/whitelist4.conf"
	Whitelist6File = ConfDir + "/whitelist6.conf"
	// Tier B (Intocables): pasan el firewall y van a fail2ban ignoreip (jamás baneadas).
	Immune4File    = ConfDir + "/immune4.conf"
	Immune6File    = ConfDir + "/immune6.conf"
	Blacklist4File = ConfDir + "/blacklist4.conf"
	Blacklist6File = ConfDir + "/blacklist6.conf"

	// Opciones generales del ruleset
	OptionsFile = ConfDir + "/options.conf"

	// GeoIP
	GeoIPDir             = ConfDir + "/geoip"
	AllowedCountriesFile = ConfDir + "/allowed_countries.conf"
	SetGeoAllow4         = "sm_geoallow4"
	SetGeoAllow6         = "sm_geoallow6"
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

// GlobalServices contiene los servicios VPN detectados en el host.
type GlobalServices struct {
	WireGuardPorts  []int
	OpenVPNRules    []OVPNRule
	TailscaleActive bool
}

// OVPNRule representa un servidor OpenVPN detectado.
type OVPNRule struct {
	Port  int
	Proto string // "tcp" | "udp"
}

// LoadGeoIPData lee allowed_countries.conf y los archivos zone de GeoIPDir.
// Retorna GeoIPData vacía si el archivo de config no existe.
func LoadGeoIPData() (GeoIPData, error) {
	f, err := os.Open(AllowedCountriesFile)
	if os.IsNotExist(err) {
		return GeoIPData{}, nil
	}
	if err != nil {
		return GeoIPData{}, fmt.Errorf("leer %s: %w", AllowedCountriesFile, err)
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

// ACLEntry es una entrada de whitelist/immune con metadatos de auditoría.
// Formato persistido (pipe-delimited, una entrada por línea):
//
//	IP/CIDR | responsable | propósito | fecha_alta | vencimiento(opcional)
//
// Una línea sin pipes (solo la dirección) se acepta por compatibilidad.
type ACLEntry struct {
	Addr        string // CIDR o IP — único campo obligatorio
	Responsable string
	Proposito   string
	FechaAlta   string
	Vencimiento string // vacío = permanente
}

// String serializa la entrada al formato pipe-delimited persistido.
func (e ACLEntry) String() string {
	return fmt.Sprintf("%s | %s | %s | %s | %s",
		e.Addr, e.Responsable, e.Proposito, e.FechaAlta, e.Vencimiento)
}

// ReadACLEntries lee un archivo de whitelist/immune con metadatos.
// Tolera líneas planas (solo dirección) para compatibilidad con configs previos.
func ReadACLEntries(path string) ([]ACLEntry, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []ACLEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "|")
		e := ACLEntry{Addr: strings.TrimSpace(fields[0])}
		if e.Addr == "" {
			continue
		}
		if len(fields) > 1 {
			e.Responsable = strings.TrimSpace(fields[1])
		}
		if len(fields) > 2 {
			e.Proposito = strings.TrimSpace(fields[2])
		}
		if len(fields) > 3 {
			e.FechaAlta = strings.TrimSpace(fields[3])
		}
		if len(fields) > 4 {
			e.Vencimiento = strings.TrimSpace(fields[4])
		}
		entries = append(entries, e)
	}
	return entries, sc.Err()
}

// ACLAddresses extrae solo las direcciones (CIDR/IP) de una lista de entradas,
// para incrustarlas en los sets nftables.
func ACLAddresses(entries []ACLEntry) []string {
	addrs := make([]string, 0, len(entries))
	for _, e := range entries {
		addrs = append(addrs, e.Addr)
	}
	return addrs
}

// privateRanges cubre RFC 1918, CGNAT (RFC 6598), loopback, link-local y ULA IPv6 (RFC 4193).
var privateRanges = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"169.254.0.0/16",
		"::1/128",
		"fe80::/10",
		"fc00::/7",
	} {
		_, n, _ := net.ParseCIDR(cidr)
		nets = append(nets, n)
	}
	return nets
}()

func isPrivateIP(ip net.IP) bool {
	for _, r := range privateRanges {
		if r != nil && r.Contains(ip) {
			return true
		}
	}
	return false
}

// HasPublicIP devuelve true si al menos una interfaz del host tiene una IP pública (no RFC privada/especial).
// Itera todas las interfaces y todas sus IPs — un host puede tener IPs privadas y públicas simultáneamente.
func HasPublicIP() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && !isPrivateIP(ip) {
				return true
			}
		}
	}
	return false
}

// ReadPort80Option lee la clave port80_global de OptionsFile.
// Retorna (enabled, found). found=false si el archivo o la clave no existen.
func ReadPort80Option() (bool, bool) {
	f, err := os.Open(OptionsFile)
	if err != nil {
		return false, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "port80_global=") {
			val := strings.TrimPrefix(line, "port80_global=")
			return val == "true", true
		}
	}
	return false, false
}

// WritePort80Option escribe o actualiza port80_global en OptionsFile.
// Preserva el resto de claves que pudiera contener el archivo.
func WritePort80Option(enabled bool) error {
	val := "false"
	if enabled {
		val = "true"
	}
	var lines []string
	f, err := os.Open(OptionsFile)
	if err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if l != "" && !strings.HasPrefix(l, "port80_global=") {
				lines = append(lines, l)
			}
		}
		f.Close()
	}
	lines = append(lines, "port80_global="+val)
	return os.WriteFile(OptionsFile, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
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

// parseWireGuardPort extrae el puerto de escucha de un archivo de configuración WireGuard.
func parseWireGuardPort(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "listenport") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				var port int
				fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &port)
				return port
			}
		}
	}
	return 0
}

// matchLine verifica si el contenido contiene una línea que comienza con el prefijo.
func matchLine(content, prefix string) bool {
	cleanPrefix := strings.TrimPrefix(prefix, "^")
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), cleanPrefix) {
			return true
		}
	}
	return false
}

// parseOpenVPNServer verifica si un archivo es una configuración de servidor OpenVPN válida
// y extrae puerto y protocolo.
func parseOpenVPNServer(path string) (OVPNRule, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return OVPNRule{}, false
	}
	content := string(data)
	// Descartar configs cliente
	if matchLine(content, "^client") || matchLine(content, "^remote ") {
		return OVPNRule{}, false
	}
	// Verificar que es servidor
	if !matchLine(content, "mode server") && !matchLine(content, "^server ") {
		return OVPNRule{}, false
	}
	port := 1194
	proto := "udp"
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "port ") {
			fmt.Sscanf(line[5:], "%d", &port)
		}
		if strings.HasPrefix(line, "proto ") {
			// Normalizar a tcp/udp: OpenVPN admite udp6, tcp4, tcp-server, tcp4-server, etc.
			// Sin esto, un "proto tcp-server" generaría una regla nftables inválida.
			p := strings.ToLower(strings.TrimSpace(line[6:]))
			switch {
			case strings.HasPrefix(p, "tcp"):
				proto = "tcp"
			case strings.HasPrefix(p, "udp"):
				proto = "udp"
			}
		}
	}
	return OVPNRule{Port: port, Proto: proto}, true
}

// DetectGlobalServices detecta servicios VPN instalados en el host.
// Se llama en cada GenerateRuleset() para generar excepciones mundiales en stage 7a.
func DetectGlobalServices() GlobalServices {
	var svc GlobalServices

	// WireGuard — path idéntico en todas las distros
	wgFiles, _ := filepath.Glob("/etc/wireguard/*.conf")
	seenWG := map[int]bool{}
	for _, f := range wgFiles {
		port := parseWireGuardPort(f)
		if port > 0 && !seenWG[port] {
			svc.WireGuardPorts = append(svc.WireGuardPorts, port)
			seenWG[port] = true
		}
	}

	// OpenVPN servidor — paths Debian/Ubuntu + RHEL/AlmaLinux/Rocky
	ovpnPatterns := []string{
		"/etc/openvpn/server/*.conf",
		"/etc/openvpn/*.conf",
	}
	seenOVPN := map[string]bool{}
	for _, pattern := range ovpnPatterns {
		files, _ := filepath.Glob(pattern)
		for _, f := range files {
			rule, ok := parseOpenVPNServer(f)
			if !ok {
				continue
			}
			key := fmt.Sprintf("%s/%d", rule.Proto, rule.Port)
			if !seenOVPN[key] {
				svc.OpenVPNRules = append(svc.OpenVPNRules, rule)
				seenOVPN[key] = true
			}
		}
	}

	// Tailscale — interfaz kernel, cross-distro
	if _, err := os.Stat("/sys/class/net/tailscale0"); err == nil {
		svc.TailscaleActive = true
	}

	return svc
}

// globalExceptionsBlock genera las reglas de excepción de puertos para servicios VPN.
func globalExceptionsBlock(svc GlobalServices, port80 bool) string {
	var sb strings.Builder
	if port80 {
		sb.WriteString("        tcp dport 80 accept   # Let's Encrypt HTTP-01 (global — ACME valida desde cualquier país)\n")
	}
	for _, port := range svc.WireGuardPorts {
		sb.WriteString(fmt.Sprintf("        udp dport %d accept   # WireGuard (auto-detectado)\n", port))
	}
	for _, rule := range svc.OpenVPNRules {
		sb.WriteString(fmt.Sprintf("        %s dport %d accept   # OpenVPN (auto-detectado)\n", rule.Proto, rule.Port))
	}
	return strings.TrimRight(sb.String(), "\n")
}

// GenerateRuleset produce el contenido completo de sm.nft.
// Lee whitelist/blacklist desde los archivos de config para preservar entradas entre recargas.
func GenerateRuleset(sshPort int, geoip GeoIPData, port80 bool) string {
	svc := DetectGlobalServices()

	sshComment := ""
	if sshPort != 22 {
		sshComment = " # puerto personalizado (sshd_config)"
	}

	tailscaleRule := ""
	if svc.TailscaleActive {
		tailscaleRule = "\n        iif \"tailscale0\" accept   # Tailscale (red de gestión — auto-detectado)"
	}

	wlEntries4, _ := ReadACLEntries(Whitelist4File)
	wlEntries6, _ := ReadACLEntries(Whitelist6File)
	imEntries4, _ := ReadACLEntries(Immune4File)
	imEntries6, _ := ReadACLEntries(Immune6File)
	wl4 := ACLAddresses(wlEntries4)
	wl6 := ACLAddresses(wlEntries6)
	im4 := ACLAddresses(imEntries4)
	im6 := ACLAddresses(imEntries6)
	bl4, _ := ReadLines(Blacklist4File)
	bl6, _ := ReadLines(Blacklist6File)

	return fmt.Sprintf(`#!/usr/sbin/nft -f
# Security-Manager-NG — ruleset base
# Generado automáticamente. NO editar manualmente.
# Tabla: inet sm — pipeline de 9 etapas (declarativo, atómico)
#
# Para recargar: nft -f %s
# Para validar:  nft -c -f %s

add table inet sm
delete table inet sm

table inet sm {

    # ── Sets confiables (Tier A) / intocables (Tier B) / blacklist ────
%s%s%s%s%s%s
    # ── Sets GeoIP (por país) ────────────────────────────────────────
%s
    # ── Chain principal ──────────────────────────────────────────────

    chain input {
        type filter hook input priority filter; policy drop;

        # 1 · Conntrack fast-path
        ct state established,related accept

        # 2 · Loopback (+ interfaces de gestión auto-detectadas)
        iif lo accept%s

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

        # 6 · Confiables (Tier A) + Intocables (Tier B) — bypass de GeoIP/puertos
        #     Tier A: fail2ban SÍ puede banearlas (no van a ignoreip).
        #     Tier B: fail2ban JAMÁS las banea (sincronizadas a ignoreip).
        #     La distinción Tier A/B vive en fail2ban, no en este accept.
        ip  saddr @%s accept
        ip6 saddr @%s accept
        ip  saddr @%s accept
        ip6 saddr @%s accept

        # 7 · GeoIP ALLOWLIST + excepciones mundiales (VPN auto-detectada)
%s
%s
        # 8 · Servicios permitidos — country-restricted POR DISEÑO.
        #     Solo IPs de países permitidos (stage 7) alcanzan estos puertos.
        #     Para acceso GLOBAL a SSH/443 (LAN, IP fija, proveedor), agregar la IP
        #     a Confiables/Intocables (stage 6) — NO abrir estos puertos al mundo.
        #     (El puerto 80 está en stage 7a, global, solo para Let's Encrypt HTTP-01.)
        tcp dport %d accept%s
        tcp dport 443 accept   # HTTPS country-restricted; whitelist la IP para acceso global
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
		formatSet(SetWhitelist4, "ipv4_addr", `Confiables IPv4 (Tier A) — bypass GeoIP, fail2ban vigila`, wl4),
		formatSet(SetWhitelist6, "ipv6_addr", `Confiables IPv6 (Tier A) — bypass GeoIP, fail2ban vigila`, wl6),
		formatSet(SetImmune4, "ipv4_addr", `Intocables IPv4 (Tier B) — bypass GeoIP + fail2ban ignoreip`, im4),
		formatSet(SetImmune6, "ipv6_addr", `Intocables IPv6 (Tier B) — bypass GeoIP + fail2ban ignoreip`, im6),
		formatSet(SetBlacklist4, "ipv4_addr", `Bans manuales IPv4`, bl4),
		formatSet(SetBlacklist6, "ipv6_addr", `Bans manuales IPv6`, bl6),
		geoipSetsBlock(geoip),
		tailscaleRule,
		SetBlacklist4, SetBlacklist6,
		SetWhitelist4, SetWhitelist6,
		SetImmune4, SetImmune6,
		globalExceptionsBlock(svc, port80),
		geoipRulesBlock(geoip),
		sshPort, sshComment,
	)
}

func formatSet(name, addrType, _ string, elements []string) string {
	s := fmt.Sprintf("\n    set %s {\n        type %s\n        flags interval\n",
		name, addrType)
	if len(elements) > 0 {
		s += fmt.Sprintf("        elements = { %s }\n", strings.Join(elements, ", "))
	}
	s += "    }\n"
	return s
}

func geoipSetsBlock(geoip GeoIPData) string {
	if len(geoip.Countries) == 0 {
		return fmt.Sprintf(
			"\n    set %s {\n        type ipv4_addr\n        flags interval\n    }\n"+
				"\n    set %s {\n        type ipv6_addr\n        flags interval\n    }\n",
			SetGeoAllow4, SetGeoAllow6)
	}
	var all4, all6 []string
	for _, cs := range geoip.Countries {
		all4 = append(all4, cs.Ranges4...)
		all6 = append(all6, cs.Ranges6...)
	}
	s4 := fmt.Sprintf("\n    set %s {\n        type ipv4_addr\n        flags interval\n", SetGeoAllow4)
	if len(all4) > 0 {
		s4 += fmt.Sprintf("        elements = { %s }\n", strings.Join(all4, ", "))
	}
	s4 += "    }\n"
	s6 := fmt.Sprintf("\n    set %s {\n        type ipv6_addr\n        flags interval\n", SetGeoAllow6)
	if len(all6) > 0 {
		s6 += fmt.Sprintf("        elements = { %s }\n", strings.Join(all6, ", "))
	}
	s6 += "    }\n"
	return s4 + s6
}

func geoipRulesBlock(geoip GeoIPData) string {
	if len(geoip.Countries) == 0 {
		return "        # 7 · GeoIP ALLOWLIST — sin países configurados (todo el tráfico pasa)\n" +
			"        # AVISO: Configura países permitidos con el módulo geoip [1]"
	}
	return fmt.Sprintf(
		"        ip  saddr != @%s drop\n"+
			"        ip6 saddr != @%s drop",
		SetGeoAllow4, SetGeoAllow6)
}
