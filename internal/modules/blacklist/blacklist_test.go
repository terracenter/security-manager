package blacklist

import (
	"strings"
	"testing"
)

// Tests del status de blacklist (Fase 1 item 6): parseo de elementos de nft
// y lookup de pais best-effort (sin red, solo validamos el path de error).

func TestParseSetElementsFromNft_Vacio(t *testing.T) {
	result := parseSetElementsFromNft("")
	if len(result) != 0 {
		t.Errorf("input vacio deberia dar 0 elementos, dio %d", len(result))
	}
}

func TestParseSetElementsFromNft_SetVacio(t *testing.T) {
	out := `table inet sm {
	set sm_blacklist4 {
		type ipv4_addr
		flags interval
		elements = { }
	}`
	result := parseSetElementsFromNft(out)
	if len(result) != 0 {
		t.Errorf("set vacio deberia dar 0 elementos, dio %d: %v", len(result), result)
	}
}

func TestParseSetElementsFromNft_UnElemento(t *testing.T) {
	out := `elements = { 192.168.1.1 }`
	result := parseSetElementsFromNft(out)
	if len(result) != 1 || result[0] != "192.168.1.1" {
		t.Errorf("un elemento: %v", result)
	}
}

func TestParseSetElementsFromNft_MuchosElementos(t *testing.T) {
	out := `elements = { 192.168.1.1, 10.0.0.0/8, 203.0.113.42 }`
	result := parseSetElementsFromNft(out)
	if len(result) != 3 {
		t.Fatalf("esperaba 3 elementos, dio %d: %v", len(result), result)
	}
	if result[0] != "192.168.1.1" || result[2] != "203.0.113.42" {
		t.Errorf("orden incorrecto: %v", result)
	}
}

func TestParseSetElementsFromNft_ConComillas(t *testing.T) {
	out := `elements = { "192.168.1.1", "10.0.0.0/8" }`
	result := parseSetElementsFromNft(out)
	if len(result) != 2 {
		t.Fatalf("esperaba 2, dio %d: %v", len(result), result)
	}
	if result[0] != "192.168.1.1" {
		t.Errorf("comilla no removida: %v", result)
	}
}

func TestParseSetElementsFromNft_FormatoSinEspacios(t *testing.T) {
	out := `elements={192.168.1.1,10.0.0.0/8}`
	result := parseSetElementsFromNft(out)
	if len(result) != 2 {
		t.Fatalf("sin espacios: esperaba 2, dio %d: %v", len(result), result)
	}
}

func TestParseSetElementsFromNft_MultiplesLineas(t *testing.T) {
	// Algunos outputs de nft tienen "elements =" en su propia linea.
	out := `table inet sm {
	set sm_blacklist4 {
		type ipv4_addr
		elements
		= { 1.2.3.4, 5.6.7.8 }
	}`
	result := parseSetElementsFromNft(out)
	if len(result) != 2 {
		t.Fatalf("multiples lineas: esperaba 2, dio %d: %v", len(result), result)
	}
}

func TestLookupCountry_Vacio(t *testing.T) {
	got := lookupCountry("")
	if got != "" {
		t.Errorf("input vacio deberia dar vacio, dio %q", got)
	}
}

func TestLookupCountry_CIDR(t *testing.T) {
	// CIDR no debe pegarle a ipinfo (solo IPs puntuales).
	got := lookupCountry("192.168.1.0/24")
	if got != "" {
		t.Errorf("CIDR deberia dar vacio sin pegarle a la red, dio %q", got)
	}
}

// TestLookupCountry_Offline valida que el comportamiento best-effort no rompe
// el flujo cuando no hay red (este test corre sin internet probablemente).
// Si ipinfo responde, retorna el codigo de pais; si falla, retorna vacio.
// Cualquier resultado es valido — el test solo verifica que NO hace panic.
func TestLookupCountry_Offline(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("lookupCountry hizo panic en modo offline: %v", r)
		}
	}()
	// IP publica conocida — si no hay red, retorna "" sin panic.
	got := lookupCountry("8.8.8.8")
	if got != "" && len(got) != 2 {
		t.Errorf("lookupCountry retorno algo inesperado: %q (deberia ser codigo ISO-2 o vacio)", got)
	}
	// Acepta solo letras mayusculas o vacio.
	if got != "" && strings.ToUpper(got) != got {
		t.Errorf("codigo de pais deberia ser mayusculas o vacio, dio %q", got)
	}
}
