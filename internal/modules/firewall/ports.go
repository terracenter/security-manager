package firewall

import (
	"regexp"
	"strconv"

	"github.com/terracenter/security-manager-ng/internal/modules/infra"
)

// EffectivePort es una vía de acceso real detectada en el ruleset ya aplicado
// (nft list table inet sm), sin importar si el operador la registró vía CLI,
// wizard, o si es una regla builtin/auto-detectada del propio SM-NG.
type EffectivePort struct {
	Port    int
	Proto   string
	Origen  string // "builtin" | "auto-letsencrypt" | "auto-wireguard" | "auto-openvpn" | "auto-ssh" | "cli/wizard" | "cli/wizard (sin registro en config)"
	Tier    string // "GLOBAL" | "GEO" | "" (vacio = no aplica: builtin/auto-ssh son pais-restringidas, no tienen tier configurable)
	Comment string
	Date    string
}

// ManagementBypass es una interfaz con bypass total (ej. Tailscale) — no es un
// puerto, no entra en la tabla de EffectivePort.
type ManagementBypass struct {
	Interfaz string
	Comment  string
}

var dportRuleRe = regexp.MustCompile(`(tcp|udp)\s+dport\s+(\d+)\s+accept\s+comment\s+"([^"]+)"`)
var iifBypassRe = regexp.MustCompile(`iif\s+"([^"]+)"\s+accept\s+comment\s+"([^"]+)"`)

// parseEffectivePorts clasifica cada regla dport/accept de `rules` (texto crudo
// de chainInfo.rules para la chain "input", ver inspect.go/parseNftStatus) por
// su comment nft. confPorts viene de infra.ReadPortEntries(infra.AllowedPortsFile)
// y se usa SOLO para recuperar Tier/Comment/Date originales de las vias CLI/wizard
// (que no tienen un tag fijo — su comment es el que puso el operador).
func parseEffectivePorts(rules []string, confPorts []infra.PortEntry) []EffectivePort {
	var out []EffectivePort
	for _, line := range rules {
		m := dportRuleRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		proto, portStr, comment := m[1], m[2], m[3]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		ep := EffectivePort{Port: port, Proto: proto, Comment: comment}
		switch comment {
		case "sm-https-global":
			ep.Origen = "builtin"
			ep.Comment = "443 - pais-restringido (stage 8), salvo IP en Confiables/Intocables"
		case "LetsEncrypt-HTTP01":
			ep.Origen = "auto-letsencrypt"
			ep.Tier = "GLOBAL"
		case "WireGuard-auto":
			ep.Origen = "auto-wireguard"
			ep.Tier = "GLOBAL"
		case "OpenVPN-auto":
			ep.Origen = "auto-openvpn"
			ep.Tier = "GLOBAL"
		case "sm-ssh":
			ep.Origen = "auto-ssh"
			ep.Comment = "pais-restringido salvo Confiables/Intocables"
		default:
			ep.Origen = "cli/wizard (sin registro en config)"
			for _, pe := range confPorts {
				if pe.Port == port && pe.Proto == proto {
					ep.Origen = "cli/wizard"
					ep.Tier = pe.Tier
					ep.Comment = pe.Comment
					ep.Date = pe.Date
					break
				}
			}
		}
		out = append(out, ep)
	}
	return out
}

// parseManagementBypass detecta reglas iif <interfaz> accept (ej. Tailscale) —
// bypass total de una interfaz completa, no un puerto especifico.
func parseManagementBypass(rules []string) []ManagementBypass {
	var out []ManagementBypass
	for _, line := range rules {
		m := iifBypassRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out = append(out, ManagementBypass{Interfaz: m[1], Comment: m[2]})
	}
	return out
}
