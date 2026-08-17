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
//
// FIX determinismo CI: este test usa GenerateRulesetWith con un GlobalServices
// explícito (TailscaleActive=true) para NO depender de si la interfaz
// tailscale0 existe en el host donde corren los tests. Antes el test llamaba
// GenerateRuleset() que internamente hacía os.Stat("/sys/class/net/tailscale0"),
// entonces pasaba en máquinas con Tailscale y fallaba en CI runners limpios.
// Ver TestGenerateRulesetNftComments_NoTailscale para el camino opuesto.
func TestGenerateRulesetNftComments(t *testing.T) {
	geoip := GeoIPData{Countries: []CountrySet{
		{CC: "VE", Ranges4: []string{"190.0.0.0/8"}},
	}}
	svc := GlobalServices{TailscaleActive: true}
	rs := GenerateRulesetWith(svc, 22, true, geoip, true)

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

// FIX P14 (Tarea 14): verifica que el ruleset base (9 stages del template
// principal) tiene `comment "sm-..."` en CADA regla, no solo en las
// excepciones globales. Esto es lo que documenta cada regla en `nft list`
// para auditoria y para el modulo inspect().
func TestGenerateRulesetBaseRulesHaveComment(t *testing.T) {
	geoip := GeoIPData{Countries: []CountrySet{
		{CC: "VE", Ranges4: []string{"190.0.0.0/8"}},
	}}
	rs := GenerateRuleset(22, true, geoip, true)

	// Stages 1-9 del template principal. Cada regla tiene un slug "sm-*".
	mustHaveComment := []string{
		`comment "sm-fastpath"`,       // Stage 1: conntrack
		`comment "sm-invalid-drop"`,   // Stage 3: conntrack invalid
		`comment "sm-antirecon-xmas"`, // Stage 4: antirecon
		`comment "sm-antirecon-null"`,
		`comment "sm-antirecon-finsyn"`,
		`comment "sm-antirecon-synrst"`,
		`comment "sm-blacklist4"`, // Stage 5: blacklist
		`comment "sm-whitelist4"`, // Stage 6: whitelist/immune
		`comment "sm-whitelist6"`,
		`comment "sm-immune4"`,
		`comment "sm-immune6"`,
		`comment "sm-https-global"`, // Stage 8: HTTPS
		`comment "sm-default-drop"`, // Stage 9: default DROP
	}
	for _, want := range mustHaveComment {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset base NO contiene comment %q (Tarea 14)", want)
		}
	}
}

// FIX P13 (Tarea 13): verifica que GenerateRuleset ahora incluye la
// tabla sm_nat al final del ruleset, y que NO incluye chain forward
// todavia (ese queda para sesion dedicada).
func TestGenerateRulesetIncludesSmNatTable(t *testing.T) {
	geoip := GeoIPData{Countries: []CountrySet{
		{CC: "VE", Ranges4: []string{"190.0.0.0/8"}},
	}}
	rs := GenerateRuleset(22, true, geoip, true)

	mustContain := []string{
		"table inet sm_nat {",
		"chain prerouting {",
		"type nat hook prerouting priority dstnat",
		"chain postrouting {",
		"type nat hook postrouting priority srcnat",
	}
	for _, want := range mustContain {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset NO contiene %q (Tarea 13: tabla sm_nat)", want)
		}
	}

	posSM := strings.Index(rs, "table inet sm {")
	posSMNat := strings.Index(rs, "table inet sm_nat {")
	if posSM < 0 || posSMNat < 0 {
		t.Fatal("no se encontro tabla inet sm o inet sm_nat")
	}
	if !(posSM < posSMNat) {
		t.Errorf("tabla inet sm debe ir ANTES de sm_nat: sm=%d sm_nat=%d", posSM, posSMNat)
	}
}

// FIX P13 (Tarea 13, parte 2/3): verifica que GenerateRuleset ahora incluye
// la tabla sm_forward con chain forward stateful (clase 044 del curso Udemy
// + diseno MikroTik-style: una tabla por dominio funcional).
//
// La chain forward filtra trafico EN TRANSITO entre interfaces (no destinado
// al host). Es complementaria a `input` (tabla inet sm, trafico al host) y
// a `sm_nat` (tabla inet sm_nat, NAT). Default policy drop (clase 028).
func TestGenerateRuleset_IncludesForwardChain(t *testing.T) {
	geoip := GeoIPData{Countries: []CountrySet{
		{CC: "VE", Ranges4: []string{"190.0.0.0/8"}},
	}}
	rs := GenerateRuleset(22, true, geoip, true)

	mustContain := []string{
		"table inet sm_forward {",
		"chain forward {",
		"type filter hook forward priority filter; policy drop;",
		`ct state established,related accept comment "sm-fwd-fastpath"`,
		`ct state invalid drop comment "sm-fwd-invalid-drop"`,
		`comment "sm-fwd-antirecon-xmas"`,
		`comment "sm-fwd-antirecon-null"`,
		`comment "sm-fwd-antirecon-finsyn"`,
		`comment "sm-fwd-antirecon-synrst"`,
		`comment "sm-fwd-whitelist4"`,
		`comment "sm-fwd-immune4"`,
		`comment "sm-fwd-blacklist4"`,
		`comment "sm-fwd-geoallow4"`,
		`comment "sm-fwd-default-drop"`,
	}
	for _, want := range mustContain {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset NO contiene %q (chain forward)", want)
		}
	}

	// Orden: tabla sm_forward debe ir DESPUES de sm_nat (sm_nat ya estaba
	// antes que sm_forward en el orden de concatenacion).
	posSM := strings.Index(rs, "table inet sm {")
	posSMNat := strings.Index(rs, "table inet sm_nat {")
	posSMFwd := strings.Index(rs, "table inet sm_forward {")
	if posSM < 0 || posSMNat < 0 || posSMFwd < 0 {
		t.Fatal("no se encontro alguna de las 3 tablas esperadas")
	}
	if !(posSM < posSMNat) {
		t.Errorf("tabla inet sm debe ir ANTES de sm_nat: sm=%d sm_nat=%d", posSM, posSMNat)
	}
	if !(posSMNat < posSMFwd) {
		t.Errorf("tabla inet sm_nat debe ir ANTES de sm_forward: sm_nat=%d sm_forward=%d", posSMNat, posSMFwd)
	}
}

// TestGenerateRulesetForwardChain_NoServices verifica que chain forward NO
// contiene reglas de servicios destinados al host (SSH/80/443). Esos
// servicios son para `input`, no para trafico en transito entre interfaces.
// El operador agrega reglas de forward especificas via `nft add rule` o
// wizard futuro.
func TestGenerateRulesetForwardChain_NoServices(t *testing.T) {
	geoip := GeoIPData{Countries: []CountrySet{
		{CC: "VE", Ranges4: []string{"190.0.0.0/8"}},
	}}
	rs := GenerateRuleset(22, true, geoip, true)

	// Extraer el bloque de chain forward para inspeccionarlo aislado.
	fwdStart := strings.Index(rs, "chain forward {")
	fwdEnd := strings.Index(rs[fwdStart:], "\n}")
	if fwdStart < 0 || fwdEnd < 0 {
		t.Fatal("no se encontro chain forward { o su cierre")
	}
	fwdBlock := rs[fwdStart : fwdStart+fwdEnd]

	mustNotContain := []string{
		"tcp dport 22",  // SSH — servicio del host, no de transito
		"tcp dport 80",  // HTTP — idem
		"tcp dport 443", // HTTPS — idem
	}
	for _, bad := range mustNotContain {
		if strings.Contains(fwdBlock, bad) {
			t.Errorf("chain forward contiene %q (no debe: forward es para transito, no para servicios del host)", bad)
		}
	}
}

// FIX determinismo CI: gemelo de TestGenerateRulesetNftComments pero con
// TailscaleActive=false. Verifica que cuando Tailscale NO está activo el
// ruleset NO contiene el comment keyword "Tailscale-mgmt". Usa la variante
// testeable GenerateRulesetWith para no depender del host.
func TestGenerateRulesetNftComments_NoTailscale(t *testing.T) {
	geoip := GeoIPData{Countries: []CountrySet{
		{CC: "VE", Ranges4: []string{"190.0.0.0/8"}},
	}}
	svc := GlobalServices{TailscaleActive: false}
	rs := GenerateRulesetWith(svc, 22, true, geoip, true)

	if strings.Contains(rs, `comment "Tailscale-mgmt"`) {
		t.Error(`ruleset contiene "comment \"Tailscale-mgmt\"" pero TailscaleActive=false (no deberia incluirlo)`)
	}
	// LetsEncrypt SI debe estar presente (no depende de Tailscale)
	if !strings.Contains(rs, `comment "LetsEncrypt-HTTP01"`) {
		t.Error(`ruleset no contiene "comment \"LetsEncrypt-HTTP01\"" (LetsEncrypt SI debe estar aunque Tailscale no)`)
	}
}
