package infra

import (
	"os"
	"strings"
	"testing"
)

func TestGenerateRulesetTwoTiers(t *testing.T) {
	geoip := GeoIPData{Countries: []CountrySet{
		{CC: "VE", Ranges4: []string{"190.0.0.0/8"}},
	}}
	rs := GenerateRuleset(22, true, geoip, true)

	mustContain := []string{
		"set sm_whitelist4", "set sm_whitelist6",
		"set sm_immune4", "set sm_immune6",
		"ip  saddr @sm_whitelist4 accept",
		"ip  saddr @sm_immune4 accept",
		"tcp dport 80 accept",
		"tcp dport 443 accept",
	}
	for _, want := range mustContain {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset no contiene %q", want)
		}
	}

	geoDrop := strings.Index(rs, "saddr != @sm_geoallow4 drop")
	pos443 := strings.Index(rs, "tcp dport 443 accept")
	pos80 := strings.Index(rs, "tcp dport 80 accept")
	if geoDrop < 0 {
		t.Fatal("no se encontró el geoallow drop (stage 7)")
	}
	if !(pos80 < geoDrop) {
		t.Errorf("puerto 80 debe ir ANTES del geoallow (global Let's Encrypt): 80=%d geo=%d", pos80, geoDrop)
	}
	if !(pos443 > geoDrop) {
		t.Errorf("puerto 443 debe ir DESPUÉS del geoallow (country-restricted): 443=%d geo=%d", pos443, geoDrop)
	}
	wlAccept := strings.Index(rs, "ip  saddr @sm_whitelist4 accept")
	if !(wlAccept < geoDrop) {
		t.Errorf("whitelist accept (stage 6) debe ir antes del geoallow (stage 7)")
	}
}

func TestGenerateRulesetPort80Disabled(t *testing.T) {
	geoip := GeoIPData{Countries: []CountrySet{
		{CC: "VE", Ranges4: []string{"190.0.0.0/8"}},
	}}
	rs := GenerateRuleset(22, true, geoip, false)

	if strings.Contains(rs, "tcp dport 80 accept") {
		t.Error("ruleset no debe contener tcp dport 80 cuando port80=false")
	}
	if !strings.Contains(rs, "tcp dport 443 accept") {
		t.Error("tcp dport 443 debe estar presente independientemente de port80")
	}
}

func TestGenerateRulesetSSHDisabled(t *testing.T) {
	geoip := GeoIPData{Countries: []CountrySet{
		{CC: "VE", Ranges4: []string{"190.0.0.0/8"}},
	}}

	// Con sshEnabled=true (default)
	rsEnabled := GenerateRuleset(22, true, geoip, true)
	if !strings.Contains(rsEnabled, "tcp dport 22 accept") {
		t.Error("ruleset con sshEnabled=true debe contener tcp dport 22 accept")
	}

	// Con sshEnabled=false
	rsDisabled := GenerateRuleset(22, false, geoip, true)
	if strings.Contains(rsDisabled, "tcp dport 22 accept") {
		t.Error("ruleset con sshEnabled=false no debe contener tcp dport 22 accept")
	}

	// Verificar que otros puertos (443, 80) siguen presentes
	if !strings.Contains(rsDisabled, "tcp dport 443 accept") {
		t.Error("tcp dport 443 debe estar presente independientemente de sshEnabled")
	}
	if !strings.Contains(rsDisabled, "tcp dport 80 accept") {
		t.Error("tcp dport 80 debe estar presente cuando port80=true")
	}
}

func TestGenerateRulesetSSHAndHTTPSSeparateLines(t *testing.T) {
	geoip := GeoIPData{Countries: []CountrySet{
		{CC: "VE", Ranges4: []string{"190.0.0.0/8"}},
	}}
	rs := GenerateRuleset(22, true, geoip, true)
	for _, line := range strings.Split(rs, "\n") {
		if strings.Contains(line, "tcp dport 22 accept") && strings.Contains(line, "tcp dport 443") {
			t.Fatalf("tcp dport 22 y 443 están fusionados en la misma línea (sintaxis inválida para nft): %q", line)
		}
	}
}

func TestReadACLEntries(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/wl.conf"
	content := "# comentario\n" +
		"172.16.11.0/24 | Freddy | Admin LAN | 2026-06-18 | 2027-06-18\n" +
		"10.0.0.5\n" +
		"\n"
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	entries, err := ReadACLEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("esperado 2 entradas, obtenido %d", len(entries))
	}
	if entries[0].Addr != "172.16.11.0/24" || entries[0].Responsable != "Freddy" ||
		entries[0].Vencimiento != "2027-06-18" {
		t.Errorf("metadatos mal parseados: %+v", entries[0])
	}
	if entries[1].Addr != "10.0.0.5" || entries[1].Responsable != "" {
		t.Errorf("línea plana mal tolerada: %+v", entries[1])
	}
	addrs := ACLAddresses(entries)
	if len(addrs) != 2 || addrs[0] != "172.16.11.0/24" {
		t.Errorf("ACLAddresses incorrecto: %v", addrs)
	}
}

// FIX P3: verifica que GenerateRuleset emite la keyword `comment` de nft
// en las reglas de excepciones globales (LetsEncrypt, WireGuard, OpenVPN,
// Tailscale).
func TestGenerateRulesetNftComments(t *testing.T) {
	geoip := GeoIPData{Countries: []CountrySet{
		{CC: "VE", Ranges4: []string{"190.0.0.0/8"}},
	}}
	rs := GenerateRuleset(22, true, geoip, true)

	mustContainComment := []string{
		`comment "LetsEncrypt-HTTP01"`,
		`comment "Tailscale-mgmt"`,
	}
	for _, want := range mustContainComment {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset no contiene %q (comment keyword)", want)
		}
	}
}
