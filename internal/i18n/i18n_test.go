package i18n

import (
	"os"
	"sort"
	"testing"
)

// helper para reset entre tests.
func resetState(t *testing.T) {
	t.Helper()
	Reset()
	t.Cleanup(func() { Reset() })
}

// helper para limpiar env var entre tests.
func cleanEnv(t *testing.T) {
	t.Helper()
	oldEnv := os.Getenv("SM_NG_LANG")
	os.Unsetenv("SM_NG_LANG")
	t.Cleanup(func() {
		if oldEnv != "" {
			os.Setenv("SM_NG_LANG", oldEnv)
		} else {
			os.Unsetenv("SM_NG_LANG")
		}
	})
}

func TestLoad_DefaultLang(t *testing.T) {
	resetState(t)
	cleanEnv(t)

	if err := Load(); err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if got := GetLang(); got != "es" {
		t.Errorf("default lang = %q, want %q", got, "es")
	}
}

func TestLoad_FromEnv(t *testing.T) {
	resetState(t)
	cleanEnv(t)
	os.Setenv("SM_NG_LANG", "EN") // mayusculas para verificar lowercase

	if err := Load(); err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if got := GetLang(); got != "en" {
		t.Errorf("lang from env = %q, want %q", got, "en")
	}
}

func TestT_BasicLookup(t *testing.T) {
	resetState(t)
	cleanEnv(t)
	if err := Load(); err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	got := T("menu.title")
	if got == "" || got == "menu.title" {
		t.Errorf("T(menu.title) = %q, want non-empty translated string", got)
	}
}

func TestT_FallbackToDefault(t *testing.T) {
	resetState(t)
	cleanEnv(t)
	if err := Load(); err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	// SetLang a un idioma que existe pero que NO tiene todas las keys
	// (imposible en este test porque ambos JSON tienen las mismas keys,
	// asi que forzamos el escenario eliminando una key del cache).
	mu.Lock()
	delete(cache["en"], "menu.title")
	mu.Unlock()
	SetLang("en")

	got := T("menu.title")
	want := T("es.menu.title")
	if got == "" || got == "menu.title" {
		t.Errorf("fallback failed: got %q, want %q", got, want)
	}
}

func TestT_MissingKey_ReturnsKey(t *testing.T) {
	resetState(t)
	cleanEnv(t)
	if err := Load(); err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	got := T("nonexistent.key.that.does.not.exist")
	if got != "nonexistent.key.that.does.not.exist" {
		t.Errorf("missing key = %q, want the key itself", got)
	}
}

func TestSetLang_InvalidLang_NoChange(t *testing.T) {
	resetState(t)
	cleanEnv(t)
	if err := Load(); err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	original := GetLang()
	if err := SetLang("klingon"); err == nil {
		t.Fatal("SetLang(klingon) deberia retornar error")
	}
	if GetLang() != original {
		t.Errorf("SetLang invalido cambio el lang: got %q, want %q", GetLang(), original)
	}
}

func TestSetLang_Valid(t *testing.T) {
	resetState(t)
	cleanEnv(t)
	if err := Load(); err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if err := SetLang("en"); err != nil {
		t.Fatalf("SetLang(en) error: %v", err)
	}
	if got := GetLang(); got != "en" {
		t.Errorf("after SetLang(en) = %q, want %q", got, "en")
	}
}

func TestAvailableLangs(t *testing.T) {
	resetState(t)
	cleanEnv(t)
	if err := Load(); err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	langs := AvailableLangs()
	if len(langs) < 2 {
		t.Errorf("AvailableLangs() = %v, want >= 2 entries", langs)
	}
	// Verificar que 'es' y 'en' estan presentes (orden no garantizado).
	sort.Strings(langs)
	if langs[0] != "en" || langs[1] != "es" {
		t.Errorf("AvailableLangs() = %v, want [en es] (sorted)", langs)
	}
}

func TestT_BothLangsHaveSameKeys(t *testing.T) {
	// Garantia: los dos JSON tienen exactamente las mismas keys. Esto
	// evita drift silencioso entre idiomas.
	resetState(t)
	cleanEnv(t)
	if err := Load(); err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	mu.RLock()
	defer mu.RUnlock()

	esKeys := keysOf(cache["es"])
	enKeys := keysOf(cache["en"])

	if len(esKeys) != len(enKeys) {
		t.Fatalf("es tiene %d keys, en tiene %d — drift entre idiomas", len(esKeys), len(enKeys))
	}

	missing := diff(esKeys, enKeys)
	if len(missing) > 0 {
		t.Errorf("keys en 'es' que faltan en 'en': %v", missing)
	}
	extra := diff(enKeys, esKeys)
	if len(extra) > 0 {
		t.Errorf("keys en 'en' que faltan en 'es': %v", extra)
	}
}

func keysOf(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func diff(a, b []string) []string {
	setB := make(map[string]bool, len(b))
	for _, v := range b {
		setB[v] = true
	}
	var out []string
	for _, v := range a {
		if !setB[v] {
			out = append(out, v)
		}
	}
	return out
}
