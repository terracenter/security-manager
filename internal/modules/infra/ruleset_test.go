package infra

import (
	"os"
	"strings"
	"testing"
)

// TestGenerateRulesetTwoTiers verifica las invariantes del rediseño two-tier
// y la corrección del orden de stages (443 country-restricted POR DISEÑO).
func TestGenerateRulesetTwoTiers(t *testing.T) {
	geoip := GeoIPData{Countries: []CountrySet{
		{CC: "VE", Ranges4: []string{"190.0.0.0/8"}},
	}}
	rs := GenerateRuleset(22, geoip)

	mustContain := []string{
		"set sm_whitelist4", "set sm_whitelist6",
		"set sm_immune4", "set sm_immune6",
		"ip  saddr @sm_whitelist4 accept",
		"ip  saddr @sm_immune4 accept",
		"tcp dport 80 accept",  // global, Let's Encrypt
		"tcp dport 443 accept", // country-restricted
	}
	for _, want := range mustContain {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset no contiene %q", want)
		}
	}

	// INVARIANTE CRÍTICA: 443 debe ir DESPUÉS del geoallow drop (country-restricted).
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
		t.Errorf("puerto 443 debe ir DESPUÉS del geoallow (country-restricted por diseño): 443=%d geo=%d", pos443, geoDrop)
	}

	// El whitelist accept (stage 6) debe ir antes del geoallow (stage 7).
	wlAccept := strings.Index(rs, "ip  saddr @sm_whitelist4 accept")
	if !(wlAccept < geoDrop) {
		t.Errorf("whitelist accept (stage 6) debe ir antes del geoallow (stage 7)")
	}
}

// TestReadACLEntries valida el parser de metadatos y la tolerancia a líneas planas.
func TestReadACLEntries(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/wl.conf"
	content := "# comentario\n" +
		"172.16.11.0/24 | Freddy | Admin LAN | 2026-06-18 | 2027-06-18\n" +
		"10.0.0.5\n" + // línea plana (compat)
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
