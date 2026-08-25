package firewall

import (
	"reflect"
	"testing"

	"github.com/terracenter/security-manager-ng/internal/modules/infra"
)

func TestParseEffectivePorts(t *testing.T) {
	confPorts := []infra.PortEntry{
		{Port: 8081, Proto: "tcp", Tier: "GLOBAL", Comment: "permitir docker", Date: "2026-08-25"},
	}

	tests := []struct {
		name      string
		rules     []string
		confPorts []infra.PortEntry
		expected  []EffectivePort
	}{
		{
			name:      "1. sm-https-global -> builtin",
			rules:     []string{`tcp dport 443 accept comment "sm-https-global"`},
			confPorts: confPorts,
			expected: []EffectivePort{
				{
					Port:    443,
					Proto:   "tcp",
					Origen:  "builtin",
					Tier:    "",
					Comment: "443 - pais-restringido (stage 8), salvo IP en Confiables/Intocables",
					Date:    "",
				},
			},
		},
		{
			name:      "2. LetsEncrypt-HTTP01 -> auto-letsencrypt",
			rules:     []string{`tcp dport 80 accept comment "LetsEncrypt-HTTP01"`},
			confPorts: confPorts,
			expected: []EffectivePort{
				{
					Port:    80,
					Proto:   "tcp",
					Origen:  "auto-letsencrypt",
					Tier:    "GLOBAL",
					Comment: "LetsEncrypt-HTTP01",
					Date:    "",
				},
			},
		},
		{
			name:      "3. WireGuard-auto -> auto-wireguard",
			rules:     []string{`udp dport 51820 accept comment "WireGuard-auto"`},
			confPorts: confPorts,
			expected: []EffectivePort{
				{
					Port:    51820,
					Proto:   "udp",
					Origen:  "auto-wireguard",
					Tier:    "GLOBAL",
					Comment: "WireGuard-auto",
					Date:    "",
				},
			},
		},
		{
			name:      "4. OpenVPN-auto -> auto-openvpn",
			rules:     []string{`udp dport 1194 accept comment "OpenVPN-auto"`},
			confPorts: confPorts,
			expected: []EffectivePort{
				{
					Port:    1194,
					Proto:   "udp",
					Origen:  "auto-openvpn",
					Tier:    "GLOBAL",
					Comment: "OpenVPN-auto",
					Date:    "",
				},
			},
		},
		{
			name:      "5. sm-ssh -> auto-ssh",
			rules:     []string{`tcp dport 22 accept comment "sm-ssh"`},
			confPorts: confPorts,
			expected: []EffectivePort{
				{
					Port:    22,
					Proto:   "tcp",
					Origen:  "auto-ssh",
					Tier:    "",
					Comment: "pais-restringido salvo Confiables/Intocables",
					Date:    "",
				},
			},
		},
		{
			name:      "6. cli/wizard con match en confPorts",
			rules:     []string{`tcp dport 8081 accept comment "permitir-docker"`},
			confPorts: confPorts,
			expected: []EffectivePort{
				{
					Port:    8081,
					Proto:   "tcp",
					Origen:  "cli/wizard",
					Tier:    "GLOBAL",
					Comment: "permitir docker",
					Date:    "2026-08-25",
				},
			},
		},
		{
			name:      "7. cli/wizard sin match en confPorts",
			rules:     []string{`tcp dport 9999 accept comment "algo"`},
			confPorts: confPorts,
			expected: []EffectivePort{
				{
					Port:    9999,
					Proto:   "tcp",
					Origen:  "cli/wizard (sin registro en config)",
					Tier:    "",
					Comment: "algo",
					Date:    "",
				},
			},
		},
		{
			name:      "8. Tailscale rule (iif) -> no aparece en ports",
			rules:     []string{`iif "tailscale0" accept comment "Tailscale-mgmt"`},
			confPorts: confPorts,
			expected:  nil,
		},
		{
			name:      "9. rules vacio",
			rules:     []string{},
			confPorts: confPorts,
			expected:  nil,
		},
		{
			name:      "10. rule sin match",
			rules:     []string{`ct state established,related accept comment "sm-fastpath"`},
			confPorts: confPorts,
			expected:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseEffectivePorts(tt.rules, tt.confPorts)
			if len(got) == 0 && len(tt.expected) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("parseEffectivePorts() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestParseManagementBypass(t *testing.T) {
	tests := []struct {
		name     string
		rules    []string
		expected []ManagementBypass
	}{
		{
			name:     "1. iif match",
			rules:    []string{`iif "tailscale0" accept comment "Tailscale-mgmt"`},
			expected: []ManagementBypass{{Interfaz: "tailscale0", Comment: "Tailscale-mgmt"}},
		},
		{
			name:     "2. dport accept -> no aparece en bypass",
			rules:    []string{`tcp dport 22 accept comment "sm-ssh"`},
			expected: nil,
		},
		{
			name:     "3. rules vacio",
			rules:    []string{},
			expected: nil,
		},
		{
			name:     "4. rule sin match",
			rules:    []string{`ct state established,related accept comment "sm-fastpath"`},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseManagementBypass(tt.rules)
			if len(got) == 0 && len(tt.expected) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("parseManagementBypass() = %v, expected %v", got, tt.expected)
			}
		})
	}
}
