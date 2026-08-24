package crowdsec

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRemoveFromAllowlist_NoCscli_NoOp valida el comportamiento contractual:
// cuando CrowdSec NO está instalado, RemoveFromAllowlist retorna nil
// sin tocar nada (no-op seguro). Esto cubre la rama "no instalado" del
// flujo de whitelist.go:420 sin requerir dependencias externas.
func TestRemoveFromAllowlist_NoCscli_NoOp(t *testing.T) {
	if IsInstalled() {
		t.Skip("crowdsec instalado en este entorno — caso 'no instalado' no aplica")
	}

	tmpDir := t.TempDir()
	immuneFile := filepath.Join(tmpDir, "immune.txt")
	if err := os.WriteFile(immuneFile, []byte("10.0.0.1\n10.0.0.2\n"), 0644); err != nil {
		t.Fatalf("error escribiendo archivo immune: %v", err)
	}

	if err := RemoveFromAllowlist([]string{immuneFile}); err != nil {
		t.Fatalf("RemoveFromAllowlist con crowdsec no instalado debe retornar nil, got: %v", err)
	}
}

// TestRunAction_UnknownAction retorna false y muestra usage en stderr.
func TestRunAction_UnknownAction(t *testing.T) {
	c := &Crowdsec{scanner: bufio.NewScanner(strings.NewReader(""))}
	if c.RunAction("foo") {
		t.Error(`RunAction("foo") debe retornar false`)
	}
}

// TestRemoveFromAllowlist_MockCscli_Reconciliation valida que la logica
// de reconciliacion (remover IPs obsoletas del allowlist CrowdSec) funciona
// con mockCscliRunner, sin sudo ni CrowdSec instalado.
//
// Limitacion documentada: skip si crowdsec no esta instalado, porque
// IsInstalled() no es inyectable. La rama no-op esta cubierta por
// TestRemoveFromAllowlist_NoCscli_NoOp. La logica de reconciliacion
// propiamente dicha requiere que la funcion llegue hasta runner.AllowlistList,
// lo que requiere IsInstalled() == true.
//
// TODO futuro: inyectar IsInstalled como dependencia para test 100% hermetico.
func TestRemoveFromAllowlist_MockCscli_Reconciliation(t *testing.T) {
	if !IsInstalled() {
		t.Skip("crowdsec no instalado — no se puede ejercitar reconciliacion. Ver TODO en header.")
	}

	// Setup: archivo immune con 2 IPs.
	tmpDir := t.TempDir()
	immuneFile := filepath.Join(tmpDir, "immune.txt")
	if err := os.WriteFile(immuneFile, []byte("10.0.0.1\n10.0.0.2\n"), 0644); err != nil {
		t.Fatalf("error escribiendo archivo immune: %v", err)
	}

	// Mock runner: allowlist tiene 3 IPs (10.0.0.1, 10.0.0.2, 10.0.0.99).
	// La 0.99 debe removerse porque ya no esta en desired.
	mock := newMockCscliRunner()
	if err := mock.AllowlistCreate("sm-immune", "test"); err != nil {
		t.Fatalf("AllowlistCreate: %v", err)
	}
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.99"} {
		if err := mock.AllowlistAdd("sm-immune", ip); err != nil {
			t.Fatalf("AllowlistAdd(%s): %v", ip, err)
		}
	}

	// Ejecutar removeFromAllowlistWith con mock.
	if err := removeFromAllowlistWith(mock, []string{immuneFile}); err != nil {
		t.Fatalf("removeFromAllowlistWith: %v", err)
	}

	// Verificar que 10.0.0.99 se removio y las otras siguen.
	actual, err := mock.AllowlistList("sm-immune")
	if err != nil {
		t.Fatalf("AllowlistList post: %v", err)
	}
	if len(actual) != 2 {
		t.Errorf("esperaba 2 IPs en allowlist, got %d: %v", len(actual), actual)
	}
	if !actual["10.0.0.1"] || !actual["10.0.0.2"] {
		t.Errorf("IPs esperadas faltantes: %v", actual)
	}
	if actual["10.0.0.99"] {
		t.Error("10.0.0.99 deberia haberse removido")
	}
}

// TestSyncAllowlist_WithMockCscli valida syncAllowlistWith con mock:
// - Crea allowlist si no existe.
// - Agrega IPs (some already present, must be idempotent).
func TestSyncAllowlist_WithMockCscli(t *testing.T) {
	if !IsInstalled() {
		t.Skip("crowdsec no instalado — no se puede ejercitar sync. Ver TODO en TestRemoveFromAllowlist_MockCscli_Reconciliation.")
	}

	tmpDir := t.TempDir()
	immuneFile := filepath.Join(tmpDir, "immune.txt")
	content := "# header\n10.0.0.1\n10.0.0.2\n\n# comentario\n10.0.0.3\n"
	if err := os.WriteFile(immuneFile, []byte(content), 0644); err != nil {
		t.Fatalf("escritura: %v", err)
	}

	mock := newMockCscliRunner()
	_ = mock.AllowlistAdd("sm-immune", "10.0.0.1") // pre-existente (idempotente)

	if err := syncAllowlistWith(mock, []string{immuneFile}); err != nil {
		t.Fatalf("syncAllowlistWith: %v", err)
	}

	actual, _ := mock.AllowlistList("sm-immune")
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if !actual[ip] {
			t.Errorf("IP %s esperada en allowlist, no encontrada. actual=%v", ip, actual)
		}
	}
	if len(actual) != 3 {
		t.Errorf("esperaba 3 IPs, got %d: %v", len(actual), actual)
	}
}

// TestReadIPsFromFile_ACLEntryFormat valida el parser de archivos immune.
// Formato pipe-delimited (ACLEntry): "IP | responsable | propósito | fecha | vencimiento"
// Solo el campo 0 (IP) es relevante para RemoveFromAllowlist.
func TestReadIPsFromFile_ACLEntryFormat(t *testing.T) {
	tmpDir := t.TempDir()
	immuneFile := filepath.Join(tmpDir, "immune.txt")

	content := `# Header comment — debe ignorarse
10.0.0.1 | admin | ssh bastion | 2026-01-01 | 2027-01-01
10.0.0.2 | vpn-acme | wireguard | 2026-02-01 | 2027-02-01

192.168.1.0/24 | datacenter | nat exemption | 2026-03-01 | permanente
# Otro comentario

`
	if err := os.WriteFile(immuneFile, []byte(content), 0644); err != nil {
		t.Fatalf("error escribiendo archivo immune: %v", err)
	}

	ips, err := readIPsFromFile(immuneFile)
	if err != nil {
		t.Fatalf("readIPsFromFile error: %v", err)
	}

	want := []string{"10.0.0.1", "10.0.0.2", "192.168.1.0/24"}
	if len(ips) != len(want) {
		t.Fatalf("esperaba %d IPs, got %d: %v", len(want), len(ips), ips)
	}
	for i, w := range want {
		if !strings.EqualFold(ips[i], w) {
			t.Errorf("IP[%d]: esperaba %q, got %q", i, w, ips[i])
		}
	}
}
