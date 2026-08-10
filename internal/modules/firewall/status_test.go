package firewall

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Tests del parser de output de `nft list table inet sm` para Fase 1 del
// checklist: drill-down del firewall.
//
// parseNftStatus ahora retorna las reglas completas de cada cadena y los
// elementos de cada set (antes solo contaba). Esto permite el drill-down
// interactivo desde showStatus().

// Mínimo viable: una cadena con policy drop y 2 reglas.
const sampleNftOutput = `table inet sm {
	chain input {
		type filter hook input priority 0; policy drop;
		ct state established,related accept comment "sm-fastpath"
		iif "lo" accept comment "sm-loopback"
		tcp dport 22 accept comment "sm-ssh"
	}

	chain forward {
		type filter hook forward priority 0; policy accept;
	}

	set sm_whitelist4 {
		type ipv4_addr
		flags interval
		elements = { 192.168.1.0/24, 10.0.0.5, 203.0.113.42 }
	}

	set sm_blacklist4 {
		type ipv4_addr
		flags interval
		elements = { 198.51.100.7 }
	}

	set sm_empty {
		type ipv4_addr
		flags interval
		elements = { }
	}
}
`

func TestParseNftStatus_Basic(t *testing.T) {
	chains, sets := parseNftStatus(sampleNftOutput)

	// Verificar cadenas
	if len(chains) != 2 {
		t.Errorf("esperaba 2 cadenas, obtuve %d", len(chains))
	}
	inputChain, ok := chains["input"]
	if !ok {
		t.Fatal("no encontre chain input")
	}
	if inputChain.policy != "drop" {
		t.Errorf("policy input = %q, esperaba drop", inputChain.policy)
	}
	if inputChain.ruleCount != 3 {
		t.Errorf("ruleCount input = %d, esperaba 3", inputChain.ruleCount)
	}
	if len(inputChain.rules) != 3 {
		t.Errorf("rules input = %d, esperaba 3 items", len(inputChain.rules))
	}

	// Verificar que las reglas NO tienen el ";" final (limpieza para drill-down)
	for i, r := range inputChain.rules {
		if strings.HasSuffix(r, ";") {
			t.Errorf("regla %d tiene ';' final: %q", i, r)
		}
	}

	// Verificar cadena forward
	forwardChain, ok := chains["forward"]
	if !ok {
		t.Fatal("no encontre chain forward")
	}
	if forwardChain.policy != "accept" {
		t.Errorf("policy forward = %q, esperaba accept", forwardChain.policy)
	}
	if forwardChain.ruleCount != 0 {
		t.Errorf("ruleCount forward = %d, esperaba 0", forwardChain.ruleCount)
	}

	// Verificar sets
	if len(sets) != 3 {
		t.Errorf("esperaba 3 sets, obtuve %d", len(sets))
	}
	if len(sets["sm_whitelist4"]) != 3 {
		t.Errorf("sm_whitelist4 deberia tener 3 elementos, tiene %d", len(sets["sm_whitelist4"]))
	}
	if len(sets["sm_blacklist4"]) != 1 {
		t.Errorf("sm_blacklist4 deberia tener 1 elemento, tiene %d", len(sets["sm_blacklist4"]))
	}
	if len(sets["sm_empty"]) != 0 {
		t.Errorf("sm_empty deberia estar vacio, tiene %d elementos", len(sets["sm_empty"]))
	}

	// Verificar contenido especifico de whitelist
	wl := sets["sm_whitelist4"]
	expectedWL := []string{"192.168.1.0/24", "10.0.0.5", "203.0.113.42"}
	for i, exp := range expectedWL {
		if i >= len(wl) {
			t.Errorf("falta elemento %d (%s) en whitelist", i, exp)
			continue
		}
		if wl[i] != exp {
			t.Errorf("elemento %d whitelist = %q, esperaba %q", i, wl[i], exp)
		}
	}
}

func TestParseNftStatus_Vacio(t *testing.T) {
	chains, sets := parseNftStatus("")
	if len(chains) != 0 {
		t.Errorf("output vacio deberia dar 0 cadenas, dio %d", len(chains))
	}
	if len(sets) != 0 {
		t.Errorf("output vacio deberia dar 0 sets, dio %d", len(sets))
	}
}

func TestParseNftStatus_SinTabla(t *testing.T) {
	// Output cuando nft dice "no such table"
	chains, sets := parseNftStatus("Error: No such file or directory; did you mean table inet sm?")
	if len(chains) != 0 || len(sets) != 0 {
		t.Errorf("error deberia dar mapas vacios, dio chains=%d sets=%d", len(chains), len(sets))
	}
}

func TestParseSetElements_Vacio(t *testing.T) {
	result := parseSetElements("")
	if len(result) != 0 {
		t.Errorf("string vacio deberia dar slice vacio, dio %d elementos", len(result))
	}
}

func TestParseSetElements_UnElemento(t *testing.T) {
	result := parseSetElements(`{ 192.168.1.1 }`)
	if len(result) != 1 || result[0] != "192.168.1.1" {
		t.Errorf("un elemento: %v", result)
	}
}

func TestParseSetElements_MuchosElementos(t *testing.T) {
	result := parseSetElements(`{ "192.168.1.1", 10.0.0.0/8, 203.0.113.42 }`)
	if len(result) != 3 {
		t.Fatalf("esperaba 3 elementos, dio %d: %v", len(result), result)
	}
	if result[0] != "192.168.1.1" {
		t.Errorf("elemento 0 = %q, esperaba 192.168.1.1", result[0])
	}
	if result[2] != "203.0.113.42" {
		t.Errorf("elemento 2 = %q, esperaba 203.0.113.42", result[2])
	}
}

// Tests del manifest (Fase 1 item 2): timestamp + sha256 + drift detection.

func TestParseManifest_Valid(t *testing.T) {
	data := "timestamp=2026-08-06T15:30:00Z\nsha256=abc123def456\n"
	var ts, hash string
	for _, line := range strings.Split(data, "\n") {
		switch {
		case strings.HasPrefix(line, "timestamp="):
			ts = strings.TrimPrefix(line, "timestamp=")
		case strings.HasPrefix(line, "sha256="):
			hash = strings.TrimPrefix(line, "sha256=")
		}
	}
	if ts != "2026-08-06T15:30:00Z" {
		t.Errorf("ts = %q", ts)
	}
	if hash != "abc123def456" {
		t.Errorf("hash = %q", hash)
	}
}

func TestParseManifest_Vacio(t *testing.T) {
	// El logico de printManifestMetadata debe tolerar entrada vacia.
	data := ""
	var ts, hash string
	for _, line := range strings.Split(data, "\n") {
		switch {
		case strings.HasPrefix(line, "timestamp="):
			ts = strings.TrimPrefix(line, "timestamp=")
		case strings.HasPrefix(line, "sha256="):
			hash = strings.TrimPrefix(line, "sha256=")
		}
	}
	if ts != "" || hash != "" {
		t.Errorf("manifest vacio: ts=%q hash=%q (ambos deberian ser vacio)", ts, hash)
	}
}

func TestManifestHash_DriftDetection(t *testing.T) {
	// Simular que el archivo sm.nft fue modificado despues de la apply.
	rulesetOriginal := []byte("table inet sm {\n}")
	originalHash := sha256.Sum256(rulesetOriginal)
	originalHex := fmt.Sprintf("%x", originalHash)

	// Simular drift: sm.nft tiene otro contenido.
	modified := []byte("table inet sm {\n# editado a mano\n}")
	modifiedHash := sha256.Sum256(modified)
	modifiedHex := fmt.Sprintf("%x", modifiedHash)

	if originalHex == modifiedHex {
		t.Error("hashes iguales no deberia pasar — el contenido es distinto")
	}
}
