package infra

import (
	"strings"
	"testing"
)

// Tests para parseWireGuardPortContent y parseOpenVPNServerContent (variantes
// testeables de parseWireGuardPort y parseOpenVPNServer introducidas para
// permitir fuzz tests sin depender del filesystem).
//
// Esto cubre Grupo B del estandar de testing:
// - Fuzz tests para parsers (item 4)
// - Property-based testing (item 5) implementado con tabla-driven para no
//   agregar dependencia nueva (rapid); si se quiere rapid real va en otra pasada.

// =====================================================================
// parseWireGuardPortContent
// =====================================================================

func TestParseWireGuardPortContent_Basics(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"empty", "", 0},
		{"no listenport", "[Interface]\nPrivateKey = x\n", 0},
		{"basic listenport", "[Interface]\nListenPort = 51820\nPrivateKey = x\n", 51820},
		{"lowercase listenport", "[Interface]\nlistenport = 443\n", 443},
		{"with spaces around =", "ListenPort  =  1234 ", 1234},
		{"multiple interfaces", "[Interface]\nListenPort = 1111\n[Peer]\n# ListenPort = 9999 (ignored in peers)\n", 1111},
		{"zero port", "ListenPort = 0", 0},
		{"negative port", "ListenPort = -1", -1},
		{"huge port", "ListenPort = 65535", 65535},
		{"ListenPort mid-line garbage", "[Interface]\n# ListenPort = 999\nListenPort = 22222\n", 22222},
		{"non-numeric ignored, returns 0", "ListenPort = abc", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseWireGuardPortContent(tt.content)
			if got != tt.want {
				t.Errorf("parseWireGuardPortContent() = %d, want %d", got, tt.want)
			}
		})
	}
}

// Fuzz test: parseWireGuardPortContent no debe panic ni colgarse con
// cualquier input binario aleatorio. La propiedad es: la función SIEMPRE
// retorna un int (no error) y termina.
func FuzzParseWireGuardPortContent(f *testing.F) {
	seeds := []string{
		"",
		"[Interface]\nListenPort = 51820\n",
		"listenport=443\n",
		strings.Repeat("ListenPort = 1\n", 1000),
		"ListenPort = \x00\x01\x02\xff",
		"🔒 ListenPort = 1234 🚀",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, content string) {
		// Invariante 1: nunca panic.
		got := parseWireGuardPortContent(content)
		// Invariante 2: si hay un ListenPort válido en el contenido, el
		// resultado debe estar en rango razonable (-2^31 .. 2^31-1).
		if got < -2147483648 || got > 2147483647 {
			t.Errorf("port fuera de rango int32: %d", got)
		}
		// Invariante 3: resultado determinista — la misma entrada produce
		// la misma salida.
		got2 := parseWireGuardPortContent(content)
		if got != got2 {
			t.Errorf("no determinista: %d != %d", got, got2)
		}
	})
}

// =====================================================================
// parseOpenVPNServerContent
// =====================================================================

func TestParseOpenVPNServerContent_Basics(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantOK    bool
		wantPort  int
		wantProto string
	}{
		{"empty", "", false, 0, ""},
		{"client config rejected", "client\nremote vpn.example.com\n", false, 0, ""},
		{"server mode default", "mode server\n", true, 1194, "udp"},
		{"server line", "server 10.8.0.0 255.255.255.0\n", true, 1194, "udp"},
		{"custom port tcp", "mode server\nport 443\nproto tcp\n", true, 443, "tcp"},
		{"custom port udp", "mode server\nport 1195\nproto udp\n", true, 1195, "udp"},
		{"proto tcp-server normaliza a tcp", "mode server\nproto tcp-server\n", true, 1194, "tcp"},
		{"proto udp6 normaliza a udp", "mode server\nproto udp6\n", true, 1194, "udp"},
		{"proto raro no reconocido queda udp", "mode server\nproto sctp\n", true, 1194, "udp"},
		{"case-insensitive port not detected, default port", "mode server\nPORT 8080\n", true, 1194, "udp"}, // parser es case-sensitive: "PORT" != "port"
		{"port negative", "mode server\nport -1\n", true, -1, "udp"},
		{"port huge", "mode server\nport 99999\n", true, 99999, "udp"},
		{"comments y lineas vacias", "mode server\n\n# comentario\nport 1234\n\n", true, 1234, "udp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseOpenVPNServerContent(tt.content)
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
				return
			}
			if !ok {
				return
			}
			if got.Port != tt.wantPort {
				t.Errorf("Port = %d, want %d", got.Port, tt.wantPort)
			}
			if got.Proto != tt.wantProto {
				t.Errorf("Proto = %q, want %q", got.Proto, tt.wantProto)
			}
		})
	}
}

// Fuzz test: parseOpenVPNServerContent no debe panic con input arbitrario.
// La propiedad es: si la función acepta la entrada como servidor, el
// protocolo retornado SIEMPRE es "tcp" o "udp" (no otro valor).
func FuzzParseOpenVPNServerContent(f *testing.F) {
	seeds := []string{
		"",
		"mode server\n",
		"mode server\nport 443\nproto tcp\n",
		"client\nremote x\n",
		"mode server\nproto tcp-server\n",
		strings.Repeat("port 1\n", 500),
		"\x00\x01\x02 mode server\xff",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, content string) {
		got, ok := parseOpenVPNServerContent(content)
		if !ok {
			// Rechazo es OK; el proto vacio es el estado valido.
			if got.Proto != "" {
				t.Errorf("rechazo pero Proto no vacio: %q", got.Proto)
			}
			return
		}
		// Aceptado: proto DEBE ser tcp o udp, NUNCA algo mas.
		if got.Proto != "tcp" && got.Proto != "udp" {
			t.Errorf("proto no normalizado: %q (debe ser tcp o udp)", got.Proto)
		}
		// Determinismo.
		got2, _ := parseOpenVPNServerContent(content)
		if got != got2 {
			t.Errorf("no determinista: %+v != %+v", got, got2)
		}
	})
}
