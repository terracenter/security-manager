package ssh

import (
	"os"
	"path/filepath"
	"testing"
)

// Tests del listado de archivos en /etc/ssh/sshd_config.d/ (Fase 1 item 3):
// drill-down del modulo SSH, deteccion de override FreeIPA.

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestListConfigFiles_Vacio(t *testing.T) {
	dir := t.TempDir()
	cfgs := listConfigFiles(dir, "/nope/own.conf")
	if len(cfgs) != 0 {
		t.Errorf("directorio vacio deberia dar 0 archivos, dio %d", len(cfgs))
	}
}

func TestListConfigFiles_DirectorioInexistente(t *testing.T) {
	cfgs := listConfigFiles("/tmp/este/path/no/existe/xyz123", "/nope")
	if len(cfgs) != 0 {
		t.Errorf("directorio inexistente deberia dar 0 archivos, dio %d", len(cfgs))
	}
}

func TestListConfigFiles_SoloPropio(t *testing.T) {
	dir := t.TempDir()
	ownPath := filepath.Join(dir, "10-sshd-base.conf")
	writeFile(t, ownPath, "# SM-NG base config\nPermitRootLogin no\n")

	cfgs := listConfigFiles(dir, ownPath)
	if len(cfgs) != 1 {
		t.Fatalf("esperaba 1 archivo, dio %d", len(cfgs))
	}
	if !cfgs[0].IsOwn {
		t.Error("el archivo propio deberia tener IsOwn=true")
	}
	if cfgs[0].IsFreeIPA {
		t.Error("10-sshd-base.conf NO es FreeIPA")
	}
	if cfgs[0].Size <= 0 {
		t.Errorf("size deberia ser > 0, dio %d", cfgs[0].Size)
	}
	if !cfgs[0].Exists {
		t.Error("Exists deberia ser true")
	}
}

func TestListConfigFiles_ConFreeIPA(t *testing.T) {
	dir := t.TempDir()
	ownPath := filepath.Join(dir, "10-sshd-base.conf")
	ipaPath := filepath.Join(dir, "99-ipa.conf")
	writeFile(t, ownPath, "# SM-NG\n")
	writeFile(t, ipaPath, "# FreeIPA override\n")

	cfgs := listConfigFiles(dir, ownPath)
	if len(cfgs) != 2 {
		t.Fatalf("esperaba 2 archivos, dio %d", len(cfgs))
	}

	var own, ipa *sshConfigFile
	for i := range cfgs {
		switch cfgs[i].Path {
		case ownPath:
			own = &cfgs[i]
		case ipaPath:
			ipa = &cfgs[i]
		}
	}
	if own == nil {
		t.Fatal("no encontre 10-sshd-base.conf")
	}
	if !own.IsOwn {
		t.Error("10-sshd-base.conf deberia ser IsOwn")
	}
	if own.IsFreeIPA {
		t.Error("10-sshd-base.conf NO es FreeIPA")
	}
	if ipa == nil {
		t.Fatal("no encontre 99-ipa.conf")
	}
	if ipa.IsOwn {
		t.Error("99-ipa.conf NO es IsOwn")
	}
	if !ipa.IsFreeIPA {
		t.Error("99-ipa.conf deberia ser IsFreeIPA=true")
	}
}

func TestListConfigFiles_CaseInsensitiveFreeIPA(t *testing.T) {
	dir := t.TempDir()
	// Variantes del nombre que deberian detectarse como FreeIPA
	for _, name := range []string{"99-IPA.conf", "00-FreeIPA.conf", "zzz_ipa-master.conf"} {
		writeFile(t, filepath.Join(dir, name), "x")
	}
	cfgs := listConfigFiles(dir, "")
	for _, c := range cfgs {
		if !c.IsFreeIPA {
			t.Errorf("%s deberia detectarse como FreeIPA", filepath.Base(c.Path))
		}
	}
}

func TestListConfigFiles_SinArchivosPropios(t *testing.T) {
	// Caso real: el operador borra 10-sshd-base.conf o nunca lo aplico.
	// El listado debe seguir funcionando.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "99-ipa.conf"), "x")
	cfgs := listConfigFiles(dir, filepath.Join(dir, "10-sshd-base.conf"))
	if len(cfgs) != 1 {
		t.Fatalf("esperaba 1, dio %d", len(cfgs))
	}
	if cfgs[0].IsOwn {
		t.Error("sin archivo propio, IsOwn deberia ser false")
	}
	if !cfgs[0].IsFreeIPA {
		t.Error("99-ipa.conf deberia ser FreeIPA")
	}
}
