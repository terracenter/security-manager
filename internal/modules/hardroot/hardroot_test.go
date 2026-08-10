package hardroot

import (
	"os"
	"path/filepath"
	"testing"
)

// Tests del status de hardroot (Fase 1 item 4): drift detection de sudoers
// y parseo del passwd status.

func TestParseSudoersState_NoExiste(t *testing.T) {
	exists, size, drift := parseSudoersState("/tmp/este/no/existe/xyz123", "template")
	if exists || size != 0 || drift {
		t.Errorf("archivo inexistente: deberia ser (false, 0, false), dio (%v, %d, %v)", exists, size, drift)
	}
}

func TestParseSudoersState_SinDrift(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sm-ng")
	content := "# test template\nDefaults timestamp_timeout=5\n"
	if err := os.WriteFile(path, []byte(content), 0o440); err != nil {
		t.Fatalf("write: %v", err)
	}
	exists, size, drift := parseSudoersState(path, content)
	if !exists {
		t.Error("deberia existir")
	}
	if size != int64(len(content)) {
		t.Errorf("size = %d, esperaba %d", size, len(content))
	}
	if drift {
		t.Error("contenido identico al template, drift deberia ser false")
	}
}

func TestParseSudoersState_ConDrift(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sm-ng")
	if err := os.WriteFile(path, []byte("# template original\n"), 0o440); err != nil {
		t.Fatalf("write: %v", err)
	}
	// pasamos un template distinto al contenido real -> debe detectar drift
	exists, _, drift := parseSudoersState(path, "# template diferente\n")
	if !exists {
		t.Error("deberia existir")
	}
	if !drift {
		t.Error("contenido distinto al template, drift deberia ser true")
	}
}

func TestParsePasswdStatus_Bloqueada(t *testing.T) {
	// Formato real: "root L 08/15/2024 0 99999 7 -1"
	got := parsePasswdStatus("root L 08/15/2024 0 99999 7 -1")
	if got != "BLOQUEADA ✓" {
		t.Errorf("esperaba BLOQUEADA, dio %q", got)
	}
}

func TestParsePasswdStatus_ConContrasena(t *testing.T) {
	got := parsePasswdStatus("root P 08/15/2024 0 99999 7 -1")
	if got != "con contraseña (activa)" {
		t.Errorf("esperaba 'con contraseña', dio %q", got)
	}
}

func TestParsePasswdStatus_SinContrasena(t *testing.T) {
	got := parsePasswdStatus("root NP 01/01/2024 -1 -1 -1 -1")
	if got != "SIN contraseña ⚠" {
		t.Errorf("esperaba SIN contraseña, dio %q", got)
	}
}

func TestParsePasswdStatus_Vacio(t *testing.T) {
	got := parsePasswdStatus("")
	if got != "desconocido" {
		t.Errorf("string vacio deberia ser desconocido, dio %q", got)
	}
}

func TestParsePasswdStatus_Malformado(t *testing.T) {
	got := parsePasswdStatus("solo una linea")
	if got != "desconocido" {
		t.Errorf("input malformado deberia ser desconocido, dio %q", got)
	}
}

func TestParsePasswdStatus_StatusDesconocido(t *testing.T) {
	// passwd -S usa letras L/P/NP; cualquier otra cosa es desconocida
	got := parsePasswdStatus("root X 01/01/2024 0 99999 7 -1")
	if got != "desconocido" {
		t.Errorf("status X deberia ser desconocido, dio %q", got)
	}
}
