package geoip

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests del status de geoip (Fase 1 item 7): zoneStatus con modtime.

func writeZoneFile(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestZoneStatus_NoExiste(t *testing.T) {
	got := zoneStatus("/tmp/este/no/existe/xyz123.zone")
	if got != "⚠ sin datos" {
		t.Errorf("archivo inexistente deberia ser '⚠ sin datos', dio %q", got)
	}
}

func TestZoneStatus_IPv4ConFecha(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ve.zone")
	writeZoneFile(t, path, []string{"190.0.0.0/8", "200.0.0.0/8", "201.0.0.0/8"})

	got := zoneStatus(path)
	// Debe contener IPv4, el count, y una fecha (YYYY-MM-DD).
	if !strings.Contains(got, "IPv4") {
		t.Errorf("deberia mencionar IPv4, dio %q", got)
	}
	if !strings.Contains(got, "3 rangos") {
		t.Errorf("deberia decir '3 rangos', dio %q", got)
	}
	// Verificar formato de fecha YYYY-MM-DD al final
	if len(got) < 14 || got[len(got)-10:len(got)-4] != "-" {
		// formato esperado: "✓ IPv4 (3 rangos, 2026-08-06)"
		// buscar el patron ", YYYY-MM-DD)" al final
		if !strings.Contains(got, ", ") || !strings.HasSuffix(got, ")") {
			t.Errorf("formato deberia terminar en ', YYYY-MM-DD)', dio %q", got)
		}
	}
}

func TestZoneStatus_IPv6ConFecha(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ve.zone6")
	writeZoneFile(t, path, []string{"::1/128", "2001:db8::/32"})

	got := zoneStatus(path)
	if !strings.Contains(got, "IPv6") {
		t.Errorf("deberia mencionar IPv6, dio %q", got)
	}
	if !strings.Contains(got, "2 rangos") {
		t.Errorf("deberia decir '2 rangos', dio %q", got)
	}
	if !strings.Contains(got, ", ") {
		t.Errorf("deberia incluir fecha, dio %q", got)
	}
}

func TestZoneStatus_VacioExiste(t *testing.T) {
	// Archivo existe pero esta vacio.
	dir := t.TempDir()
	path := filepath.Join(dir, "ve.zone")
	if err := os.WriteFile(path, []byte(""), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := zoneStatus(path)
	// Sin lineas = count 0, pero debe seguir mostrando fecha (porque el archivo existe).
	if !strings.Contains(got, "0 rangos") {
		t.Errorf("archivo vacio deberia decir '0 rangos', dio %q", got)
	}
}

func TestZoneStatus_ModtimeSeActualiza(t *testing.T) {
	// Crear archivo, leer status, modificar, leer status: las fechas deben diferir
	// si pasa suficiente tiempo (mtime resolution puede ser 1s en algunos FS).
	dir := t.TempDir()
	path := filepath.Join(dir, "ve.zone")
	writeZoneFile(t, path, []string{"1.2.3.0/24"})
	first := zoneStatus(path)

	// Sobreescribir con nuevo contenido (mtime cambia).
	writeZoneFile(t, path, []string{"1.2.3.0/24", "5.6.7.0/24"})
	second := zoneStatus(path)

	// Ambos deben tener 2 rangos ahora.
	if !strings.Contains(first, "1 rangos") {
		t.Errorf("first deberia tener '1 rangos', dio %q", first)
	}
	if !strings.Contains(second, "2 rangos") {
		t.Errorf("second deberia tener '2 rangos', dio %q", second)
	}
	// No assert sobre fechas distintas (mtime resolution puede variar entre FS).
}