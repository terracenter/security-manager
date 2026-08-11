package infra

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// =============================================================================
// Property-Based Testing (PBT) para GenerateRulesetWith
// =============================================================================
//
// Estas propiedades son invariantes que deben cumplirse PARA TODO input
// válido de la función. La librería rapid genera inputs aleatorios y los
// reduce (shrink) si encuentra un contraejemplo.
//
// Patrón: cada propiedad es una función `test...(t *rapid.T)` registrada
// desde un `Test...(t *testing.T)` via `rapid.Check(t, test...)`. rapid
// detecta automáticamente las funciones y corre 100 iteraciones default.
//
// Justificación PBT (ver 06_Desarrollo/tipos-test-backend-go.md §2.4):
// GenerateRulesetWith es una función pura* con 5 entradas. Los tests
// existentes cubren casos representativos, pero no exploran el espacio
// combinatorial (~2^5 * 65535^1 * N_countries combinaciones). PBT cubre
// ese espacio con 100 iteraciones aleatorias por propiedad.
//
// (* Pura = excepto por las lecturas a /etc/security-manager/* que fallan
// silenciosamente cuando los archivos no existen, como en este host de
// desarrollo. Eso es exactamente lo que queremos para PBT: comportamiento
// determinista independiente del estado del filesystem).
//
// =============================================================================

// validCountryCC: paises reales (codigos ISO-3166-1 alpha-2). Usamos un set
// acotado en vez de strings aleatorios para que las CIDR generadas abajo
// sean realistas.
var validCountryCC = []string{
	"VE", "US", "AR", "CO", "BR", "MX", "CL", "PE", "EC", "UY",
	"ES", "FR", "DE", "IT", "GB", "PT", "NL", "CA", "JP", "CN",
}

// makeCIDRv4 genera un CIDR IPv4 /8 a /24 aleatorio usando t.
// Helper NO es un Generator — solo produce el valor dentro de un callback.
func makeCIDRv4(t *rapid.T) string {
	first := rapid.IntRange(1, 223).Draw(t, "first_octet") // evitar 0, 127, 224+
	prefix := rapid.IntRange(8, 24).Draw(t, "prefix_v4")
	return strconv.Itoa(first) + ".0.0.0/" + strconv.Itoa(prefix)
}

// makeCIDRv6 genera un CIDR IPv6 /12 a /48 aleatorio.
func makeCIDRv6(t *rapid.T) string {
	prefix := rapid.IntRange(12, 48).Draw(t, "prefix_v6")
	return "2001:db8::/" + strconv.Itoa(prefix)
}

// countrySetGen genera un CountrySet con 1-3 CIDR IPv4 y 0-2 CIDR IPv6.
func countrySetGen() *rapid.Generator[CountrySet] {
	return rapid.Custom(func(t *rapid.T) CountrySet {
		n4 := rapid.IntRange(1, 3).Draw(t, "n4")
		n6 := rapid.IntRange(0, 2).Draw(t, "n6")
		ranges4 := make([]string, n4)
		for i := range ranges4 {
			ranges4[i] = makeCIDRv4(t)
		}
		ranges6 := make([]string, n6)
		for i := range ranges6 {
			ranges6[i] = makeCIDRv6(t)
		}
		return CountrySet{
			CC:      rapid.SampledFrom(validCountryCC).Draw(t, "cc"),
			Ranges4: ranges4,
			Ranges6: ranges6,
		}
	})
}

// geoipGen genera un GeoIPData con 0-3 paises.
func geoipGen() *rapid.Generator[GeoIPData] {
	return rapid.Custom(func(t *rapid.T) GeoIPData {
		n := rapid.IntRange(0, 3).Draw(t, "n_countries")
		countries := make([]CountrySet, n)
		for i := range countries {
			countries[i] = countrySetGen().Draw(t, "country")
		}
		return GeoIPData{Countries: countries}
	})
}

// svcGen genera un GlobalServices. WireGuardPorts y OpenVPNRules se dejan
// vacios porque dependen de archivos en /etc/wireguard/* que no existen en
// este host (ReadPortEntries/ReadACLEntries fallan silenciosamente).
func svcGen() *rapid.Generator[GlobalServices] {
	return rapid.Custom(func(t *rapid.T) GlobalServices {
		return GlobalServices{
			WireGuardPorts:  nil,
			OpenVPNRules:    nil,
			TailscaleActive: rapid.Bool().Draw(t, "tailscale"),
		}
	})
}

// pbtInput agrupa los 5 parámetros de GenerateRulesetWith para tests PBT.
type pbtInput struct {
	svc        GlobalServices
	sshPort    int
	geo        GeoIPData
	port80     bool
	sshEnabled bool
}

func inputGen() *rapid.Generator[pbtInput] {
	return rapid.Custom(func(t *rapid.T) pbtInput {
		return pbtInput{
			svc:        svcGen().Draw(t, "svc"),
			sshPort:    rapid.IntRange(1, 65535).Draw(t, "sshPort"),
			geo:        geoipGen().Draw(t, "geo"),
			port80:     rapid.Bool().Draw(t, "port80"),
			sshEnabled: rapid.Bool().Draw(t, "sshEnabled"),
		}
	})
}

// =============================================================================
// PROPIEDADES
// =============================================================================

// Propiedad 1: Output nunca vacio + siempre empieza con shebang.
func testProperty_OutputShape(t *rapid.T) {
	in := inputGen().Draw(t, "input")
	rs := GenerateRulesetWith(in.svc, in.sshPort, in.sshEnabled, in.geo, in.port80)

	if rs == "" {
		t.Fatalf("output vacio para input=%+v", in)
	}
	if !strings.HasPrefix(rs, "#!/usr/sbin/nft -f\n") {
		head := rs
		if len(head) > 80 {
			head = head[:80]
		}
		t.Fatalf("output no empieza con shebang: %q", head)
	}
}

// Propiedad 2: Output contiene siempre las 3 tablas en orden.
// inet sm < inet sm_nat < inet sm_forward (MikroTik-style + clase 044).
func testProperty_TablesOrder(t *rapid.T) {
	in := inputGen().Draw(t, "input")
	rs := GenerateRulesetWith(in.svc, in.sshPort, in.sshEnabled, in.geo, in.port80)

	posSM := strings.Index(rs, "table inet sm {")
	posSMNat := strings.Index(rs, "table inet sm_nat {")
	posSMFwd := strings.Index(rs, "table inet sm_forward {")

	if posSM < 0 {
		t.Fatal("no se encontro 'table inet sm {'")
	}
	if posSMNat < 0 {
		t.Fatal("no se encontro 'table inet sm_nat {'")
	}
	if posSMFwd < 0 {
		t.Fatal("no se encontro 'table inet sm_forward {'")
	}
	if !(posSM < posSMNat) {
		t.Fatalf("orden incorrecto: sm(%d) >= sm_nat(%d)", posSM, posSMNat)
	}
	if !(posSMNat < posSMFwd) {
		t.Fatalf("orden incorrecto: sm_nat(%d) >= sm_forward(%d)", posSMNat, posSMFwd)
	}
}

// Propiedad 3: sshEnabled=true => contiene linea SSH con el puerto.
// sshEnabled=false => NO contiene linea SSH dentro de chain input.
func testProperty_SSHToggle(t *rapid.T) {
	in := inputGen().Draw(t, "input")
	rs := GenerateRulesetWith(in.svc, in.sshPort, in.sshEnabled, in.geo, in.port80)

	expected := "tcp dport " + strconv.Itoa(in.sshPort) + " accept"
	if in.sshEnabled {
		if !strings.Contains(rs, expected) {
			t.Fatalf("sshEnabled=true pero output no contiene %q", expected)
		}
	} else {
		inputStart := strings.Index(rs, "chain input {")
		inputEnd := strings.Index(rs[inputStart:], "\n    }")
		if inputStart < 0 || inputEnd < 0 {
			t.Fatal("no se encontro chain input { delimitada")
		}
		inputBlock := rs[inputStart : inputStart+inputEnd]
		if strings.Contains(inputBlock, expected) {
			t.Fatalf("sshEnabled=false pero chain input contiene linea SSH (port=%d)", in.sshPort)
		}
	}
}

// Propiedad 4: port80=true => contiene 'tcp dport 80 accept'.
// port80=false => NO contiene esa linea dentro de chain input.
func testProperty_Port80Toggle(t *rapid.T) {
	in := inputGen().Draw(t, "input")
	rs := GenerateRulesetWith(in.svc, in.sshPort, in.sshEnabled, in.geo, in.port80)

	if in.port80 {
		if !strings.Contains(rs, "tcp dport 80 accept") {
			t.Fatal("port80=true pero output no contiene 'tcp dport 80 accept'")
		}
	} else {
		inputStart := strings.Index(rs, "chain input {")
		inputEnd := strings.Index(rs[inputStart:], "\n    }")
		if inputStart < 0 || inputEnd < 0 {
			t.Fatal("no se encontro chain input { delimitada")
		}
		inputBlock := rs[inputStart : inputStart+inputEnd]
		if strings.Contains(inputBlock, "tcp dport 80 accept") {
			t.Fatal("port80=false pero chain input contiene 'tcp dport 80 accept'")
		}
	}
}

// Propiedad 5: sshPort=22 => NO contiene comentario 'puerto personalizado'.
// sshPort!=22 => SI contiene ese comentario.
// sshEnabled forzado a true para que la linea SSH siempre exista.
func testProperty_SSHPortCustom(t *rapid.T) {
	svc := svcGen().Draw(t, "svc")
	port := rapid.IntRange(1, 65535).Draw(t, "sshPort")
	geo := geoipGen().Draw(t, "geo")
	port80 := rapid.Bool().Draw(t, "port80")

	rs := GenerateRulesetWith(svc, port, true, geo, port80)

	hasComment := strings.Contains(rs, "puerto personalizado (sshd_config)")
	if port == 22 {
		if hasComment {
			t.Fatalf("sshPort=22 pero output contiene comentario 'puerto personalizado': %d", port)
		}
	} else {
		if !hasComment {
			t.Fatalf("sshPort=%d (no es 22) pero output NO contiene comentario 'puerto personalizado'", port)
		}
	}
}

// Propiedad 6: TailscaleActive=true => contiene regla tailscale0.
// TailscaleActive=false => NO contiene esa regla.
func testProperty_TailscaleToggle(t *rapid.T) {
	port := rapid.IntRange(1, 65535).Draw(t, "sshPort")
	geo := geoipGen().Draw(t, "geo")
	port80 := rapid.Bool().Draw(t, "port80")
	sshEnabled := rapid.Bool().Draw(t, "sshEnabled")
	tailscale := rapid.Bool().Draw(t, "tailscale")
	svc := GlobalServices{TailscaleActive: tailscale}

	rs := GenerateRulesetWith(svc, port, sshEnabled, geo, port80)

	if tailscale {
		if !strings.Contains(rs, `iif "tailscale0" accept comment "Tailscale-mgmt"`) {
			t.Fatal("TailscaleActive=true pero output no contiene regla tailscale0")
		}
	} else {
		if strings.Contains(rs, "Tailscale-mgmt") {
			t.Fatal("TailscaleActive=false pero output contiene 'Tailscale-mgmt'")
		}
	}
}

// Propiedad 7: GeoIP con N paises => todos los CIDR aparecen en el output.
// (Propiedad "round-trip": el output refleja literalmente los rangos del
// input. Si alguien rompe el formateo de ranges4/ranges6, rapid lo
// encuentra con 100 iteraciones.)
func testProperty_GeoIPRangesAppear(t *rapid.T) {
	in := inputGen().Draw(t, "input")
	rs := GenerateRulesetWith(in.svc, in.sshPort, in.sshEnabled, in.geo, in.port80)

	for _, cs := range in.geo.Countries {
		for _, cidr := range cs.Ranges4 {
			if !strings.Contains(rs, cidr) {
				t.Fatalf("CIDR IPv4 %q del pais %q no aparece en output (geo=%+v)", cidr, cs.CC, in.geo)
			}
		}
		for _, cidr := range cs.Ranges6 {
			if !strings.Contains(rs, cidr) {
				t.Fatalf("CIDR IPv6 %q del pais %q no aparece en output (geo=%+v)", cidr, cs.CC, in.geo)
			}
		}
	}
}

// Propiedad 8: Chain forward NO contiene servicios del host (SSH/HTTP/HTTPS).
// Garantiza que forward es para trafico en transito, no para servicios
// locales (MikroTik-style: una tabla por dominio funcional).
func testProperty_ForwardNoServices(t *rapid.T) {
	in := inputGen().Draw(t, "input")
	rs := GenerateRulesetWith(in.svc, in.sshPort, in.sshEnabled, in.geo, in.port80)

	fwdStart := strings.Index(rs, "chain forward {")
	fwdEnd := strings.Index(rs[fwdStart:], "\n    }")
	if fwdStart < 0 || fwdEnd < 0 {
		t.Fatal("no se encontro chain forward { delimitada")
	}
	fwdBlock := rs[fwdStart : fwdStart+fwdEnd]

	bads := []string{"tcp dport 22", "tcp dport 80", "tcp dport 443"}
	for _, bad := range bads {
		if strings.Contains(fwdBlock, bad) {
			t.Fatalf("chain forward contiene %q (debe ser solo para transito)", bad)
		}
	}
}

// Propiedad 9: Output siempre contiene al menos 2 'policy drop;'
// (uno en chain input, otro en chain forward — defensa en profundidad).
func testProperty_PolicyDropCount(t *rapid.T) {
	in := inputGen().Draw(t, "input")
	rs := GenerateRulesetWith(in.svc, in.sshPort, in.sshEnabled, in.geo, in.port80)

	allDrops := regexp.MustCompile(`policy drop;`).FindAllString(rs, -1)
	if len(allDrops) < 2 {
		t.Fatalf("esperaba >=2 'policy drop;' (input + forward), got %d", len(allDrops))
	}
}

// =============================================================================
// TESTS GO QUE REGISTRAN LAS PROPIEDADES CON RAPID
// =============================================================================
//
// rapid.Check envuelve cada propiedad con un *testing.T real. Por default
// corre 100 iteraciones, shrink automatico, y reporta el contraejemplo si
// lo encuentra.

func TestProperty_GenerateRuleset(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testProperty_OutputShape)
	rapid.Check(t, testProperty_TablesOrder)
	rapid.Check(t, testProperty_SSHToggle)
	rapid.Check(t, testProperty_Port80Toggle)
	rapid.Check(t, testProperty_SSHPortCustom)
	rapid.Check(t, testProperty_TailscaleToggle)
	rapid.Check(t, testProperty_GeoIPRangesAppear)
	rapid.Check(t, testProperty_ForwardNoServices)
	rapid.Check(t, testProperty_PolicyDropCount)
}
