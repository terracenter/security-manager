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
