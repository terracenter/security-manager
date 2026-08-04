package firewall

import (
	"testing"
)

// runDetector crea un patternDetector con el input dado y corre detect().
// Retorna los patrones detectados. Sirve para tests unitarios de los 12
// detectores SIN necesidad de nft real (todo in-memory).
func runDetector(t *testing.T, raw string) []PatternDetected {
	t.Helper()
	d := newPatternDetector(raw)
	d.detect()
	return d.patterns
}

func hasPattern(patterns []PatternDetected, name string) bool {
	for _, p := range patterns {
		if p.Name == name {
			return true
		}
	}
	return false
}

// 1. detectChainForward -> router-borde
func TestDetectChainForward_Stateless(t *testing.T) {
	raw := `
table inet sm {
    chain forward {
        type filter hook forward priority filter; policy drop;
        tcp dport 22 accept
    }
}`
	got := runDetector(t, raw)
	if !hasPattern(got, "router-borde") {
		t.Errorf("esperaba patron router-borde, obtuvo: %+v", got)
	}
}

func TestDetectChainForward_Stateful(t *testing.T) {
	raw := `
table inet sm {
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
    }
}`
	got := runDetector(t, raw)
	if !hasPattern(got, "router-borde") {
		t.Errorf("esperaba patron router-borde, obtuvo: %+v", got)
	}
	// El estado stateful aumenta confianza a 90.
	var conf int
	for _, p := range got {
		if p.Name == "router-borde" {
			conf = p.Confidence
		}
	}
	if conf != 90 {
		t.Errorf("confianza esperada 90 (stateful), obtuvo %d", conf)
	}
}

func TestDetectChainForward_Ausente(t *testing.T) {
	raw := `
table inet sm {
    chain input {
        type filter hook input priority filter; policy drop;
    }
}`
	got := runDetector(t, raw)
	if hasPattern(got, "router-borde") {
		t.Errorf("NO esperaba router-borde sin chain forward, obtuvo: %+v", got)
	}
}

// 2. detectChainPostrouting -> nat-out (snat)
func TestDetectChainPostrouting_snat(t *testing.T) {
	// El detector itera lineas (split por \n), por eso el input debe tener \n.
	raw := `
table inet sm {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "eth0" snat to 1.2.3.4
    }
}
`
	got := runDetector(t, raw)
	if !hasPattern(got, "nat-out") {
		t.Errorf("esperaba patron nat-out, obtuvo: %+v", got)
	}
}

func TestDetectChainPostrouting_masquerade(t *testing.T) {
	raw := `
table inet sm {
    chain postrouting {
        type nat hook postrouting priority srcnat;
        oifname "eth0" masquerade
    }
}
`
	got := runDetector(t, raw)
	if !hasPattern(got, "nat-out") {
		t.Errorf("esperaba nat-out por masquerade, obtuvo: %+v", got)
	}
}

func TestDetectChainPostrouting_Vacio(t *testing.T) {
	raw := `
table inet sm {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
    }
}
`
	got := runDetector(t, raw)
	if hasPattern(got, "nat-out") {
		t.Errorf("postrouting vacio NO debe generar nat-out, obtuvo: %+v", got)
	}
}

// 3. detectChainPrerouting -> nat-in (dnat)
func TestDetectChainPrerouting_dnat(t *testing.T) {
	raw := `
table inet sm {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        tcp dport 80 dnat to 192.168.1.10
    }
}
`
	got := runDetector(t, raw)
	if !hasPattern(got, "nat-in") {
		t.Errorf("esperaba patron nat-in, obtuvo: %+v", got)
	}
}

func TestDetectChainPrerouting_SinDNAT(t *testing.T) {
	raw := `
table inet sm {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        tcp dport 80 accept
    }
}`
	got := runDetector(t, raw)
	if hasPattern(got, "nat-in") {
		t.Errorf("pregunting sin dnat NO debe generar nat-in, obtuvo: %+v", got)
	}
}

// 4. detectStateful -> stateful
func TestDetectStateful_Presente(t *testing.T) {
	raw := `
chain input {
    type filter hook input priority filter; policy drop;
    ct state established,related accept
}`
	got := runDetector(t, raw)
	if !hasPattern(got, "stateful") {
		t.Errorf("esperaba patron stateful, obtuvo: %+v", got)
	}
}

func TestDetectStateful_Ausente(t *testing.T) {
	raw := `
chain input {
    type filter hook input priority filter; policy drop;
    tcp dport 22 accept
}`
	got := runDetector(t, raw)
	if hasPattern(got, "stateful") {
		t.Errorf("sin ct state NO debe generar stateful, obtuvo: %+v", got)
	}
}

// 5. detectPolicyDrop -> default-policy-drop
func TestDetectPolicyDrop_Presente(t *testing.T) {
	raw := `
chain input {
    type filter hook input priority filter; policy drop;
}`
	got := runDetector(t, raw)
	if !hasPattern(got, "default-policy-drop") {
		t.Errorf("esperaba default-policy-drop, obtuvo: %+v", got)
	}
}

func TestDetectPolicyDrop_Ausente(t *testing.T) {
	raw := `
chain input {
    type filter hook input priority filter; policy accept;
}`
	got := runDetector(t, raw)
	if hasPattern(got, "default-policy-drop") {
		t.Errorf("policy accept NO debe generar default-policy-drop, obtuvo: %+v", got)
	}
}

// 6. detectGeoIPRules -> geoip-allowlist
func TestDetectGeoIPRules_Presente(t *testing.T) {
	raw := `
chain input {
    ip saddr != @sm_geoallow4 drop
}`
	got := runDetector(t, raw)
	if !hasPattern(got, "geoip-allowlist") {
		t.Errorf("esperaba geoip-allowlist, obtuvo: %+v", got)
	}
}

func TestDetectGeoIPRules_Ausente(t *testing.T) {
	raw := `
chain input {
    tcp dport 22 accept
}`
	got := runDetector(t, raw)
	if hasPattern(got, "geoip-allowlist") {
		t.Errorf("sin @sm_geoallow NO debe generar geoip-allowlist, obtuvo: %+v", got)
	}
}

// 7. detectTierAWhitelist -> tier-a-whitelist
func TestDetectTierAWhitelist_ConElementos(t *testing.T) {
	raw := `
table inet sm {
    set sm_whitelist4 {
        type ipv4_addr
        flags interval
        elements = { 10.0.0.1, 192.168.1.0/24 }
    }
}`
	got := runDetector(t, raw)
	if !hasPattern(got, "tier-a-whitelist") {
		t.Errorf("esperaba tier-a-whitelist con elementos, obtuvo: %+v", got)
	}
}

func TestDetectTierAWhitelist_Vacio(t *testing.T) {
	raw := `
table inet sm {
    set sm_whitelist4 {
        type ipv4_addr
        flags interval
        elements = {  }
    }
}`
	got := runDetector(t, raw)
	if hasPattern(got, "tier-a-whitelist") {
		t.Errorf("set vacio NO debe generar tier-a-whitelist, obtuvo: %+v", got)
	}
}

// 8. detectTierBImmune -> tier-b-immune
func TestDetectTierBImmune_ConElementos(t *testing.T) {
	raw := `
table inet sm {
    set sm_immune4 {
        type ipv4_addr
        flags interval
        elements = { 172.16.0.5 }
    }
}`
	got := runDetector(t, raw)
	if !hasPattern(got, "tier-b-immune") {
		t.Errorf("esperaba tier-b-immune, obtuvo: %+v", got)
	}
}

// 9. detectBlacklistActive -> blacklist-active
func TestDetectBlacklistActive_ConElementos(t *testing.T) {
	raw := `
table inet sm {
    set sm_blacklist4 {
        type ipv4_addr
        flags interval
        elements = { 5.6.7.8 }
    }
}`
	got := runDetector(t, raw)
	if !hasPattern(got, "blacklist-active") {
		t.Errorf("esperaba blacklist-active, obtuvo: %+v", got)
	}
}

// 10. detectCrowdsecDrops -> crowdsec-integration
func TestDetectCrowdsecDrops_Presente(t *testing.T) {
	raw := `
chain input {
    ip saddr @crowdsec-blacklists drop
}`
	got := runDetector(t, raw)
	if !hasPattern(got, "crowdsec-integration") {
		t.Errorf("esperaba crowdsec-integration, obtuvo: %+v", got)
	}
}

func TestDetectCrowdsecDrops_Ausente(t *testing.T) {
	raw := `
chain input {
    tcp dport 22 accept
}`
	got := runDetector(t, raw)
	if hasPattern(got, "crowdsec-integration") {
		t.Errorf("sin @crowdsec-blacklists NO debe generar crowdsec-integration, obtuvo: %+v", got)
	}
}

// 11. detectAntirecon -> antirecon
// El detector (post-fix Tarea 14) soporta tanto el caso single-line como
// multi-linea con backslash-continuacion (output normal de nft list).
func TestDetectAntirecon_SingleLine(t *testing.T) {
	raw := `
chain input {
    tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn|rst|psh|ack|urg limit rate 5/minute log prefix "SM-ANTIRECON XMAS " drop
}
`
	got := runDetector(t, raw)
	if !hasPattern(got, "antirecon") {
		t.Errorf("esperaba antirecon (single-line), obtuvo: %+v", got)
	}
}

// Caso real: nft list imprime la regla en 2 lineas con "\\" de continuacion.
func TestDetectAntirecon_MultiLine(t *testing.T) {
	raw := `
chain input {
    tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn|rst|psh|ack|urg \
        limit rate 5/minute log prefix "SM-ANTIRECON XMAS " drop
}
`
	got := runDetector(t, raw)
	if !hasPattern(got, "antirecon") {
		t.Errorf("esperaba antirecon (multi-line), obtuvo: %+v", got)
	}
}

// 12. detectDefaultDropLog -> default-drop-logged
func TestDetectDefaultDropLog_Presente(t *testing.T) {
	raw := `
chain input {
    log prefix "SM-DROP-DEFAULT " drop
}`
	got := runDetector(t, raw)
	if !hasPattern(got, "default-drop-logged") {
		t.Errorf("esperaba default-drop-logged, obtuvo: %+v", got)
	}
}

// Test de smoke: input que simula el ruleset base de SM-NG (con patron
// stateful + default-policy-drop + antirecon + default-drop-logged).
// Verifica que los 4 patrones se detectan en simultaneo.
// (Para una validacion completa contra el output real de GenerateRuleset,
// correr el test de integracion en el paquete infra.)
func TestDetect_RulesetBaseSimulado(t *testing.T) {
	// antirecon debe estar en una sola linea porque el detector busca
	// "tcp flags" Y "limit rate" en la MISMA linea (ver TestDetectAntirecon_Presente).
	raw := `
table inet sm {
    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        iif lo accept
        ct state invalid drop
        tcp flags & (fin|syn) == fin|syn limit rate 5/minute log prefix "SM-ANTIRECON FIN+SYN " drop
        log prefix "SM-DROP-DEFAULT " drop
    }
}
`
	got := runDetector(t, raw)

	expected := []string{
		"stateful",
		"default-policy-drop",
		"antirecon",
		"default-drop-logged",
	}
	for _, name := range expected {
		if !hasPattern(got, name) {
			t.Errorf("patron %q deberia detectarse, no se detecto", name)
		}
	}
}
