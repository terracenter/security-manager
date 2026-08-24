// Package i18n provee un sistema minimo de internacionalizacion para
// Security Manager NG.
//
// Filosofia: SIMPLE. No usar gettext/po, no dependencias externas. Solo
// JSON embebido + un lookup con fallback.
//
// Como se usa:
//
//	i18n.SetLang("en")                              // cambiar idioma
//	fmt.Println(i18n.T("menu.title"))               // imprime el string
//	lang := i18n.GetLang()                           // idioma actual
//
// Como se selecciona el idioma (en orden de prioridad):
//
//  1. Variable de entorno SM_NG_LANG (ej: "en", "es")
//  2. Default: "es"
//
// Como agregar un idioma nuevo:
//
//  1. Crear internal/i18n/strings_<lang>.json con la misma estructura
//     que strings_es.json.
//  2. Agregar el filename a la directiva //go:embed y al slice `assets` abajo.
//  3. Listo.
//
// Limitaciones conocidas:
//   - Sin pluralizacion. Si se necesita (ej: "1 entrada" vs "N entradas"),
//     el caller debe ramificar fuera de i18n.
//   - Sin interpolacion. Strings con variables se arman con fmt.Sprintf
//     en el caller, ej: fmt.Sprintf(i18n.T("msg.count"), n).
//   - Sin contexto por seccion. Cada key es global.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

//go:embed strings_es.json strings_en.json
var catalogFS embed.FS

// assets lista los archivos JSON embebidos. El primer elemento es el
// default (espanol). El resto se carga bajo demanda segun el idioma
// seleccionado. Si un idioma falta, se cae al default.
//
// Para agregar un idioma: crear strings_<lang>.json, agregarlo a //go:embed
// y al slice assets aqui.
var assets = []string{
	"strings_es.json",
	"strings_en.json",
}

// catalog es el dict cargado en memoria: lang -> key -> string.
type catalog map[string]map[string]string

var (
	mu          sync.RWMutex
	cache       catalog
	defaultLang = "es"
	currentLang = defaultLang
)

// Load carga todos los archivos de assets. Idempotente. Si falla, retorna
// error pero los tests pueden skipear.
func Load() error {
	mu.Lock()
	defer mu.Unlock()

	if cache != nil {
		return nil
	}

	// Detectar idioma desde env ANTES de cargar.
	if env := os.Getenv("SM_NG_LANG"); env != "" {
		currentLang = strings.ToLower(strings.TrimSpace(env))
	} else {
		currentLang = defaultLang
	}

	cache = make(catalog)
	for _, path := range assets {
		data, err := readAsset(path)
		if err != nil {
			// Si un idioma falla al cargar, lo salteamos pero seguimos
			// con los demas. El fallback al default cubre el resto.
			continue
		}
		var langDict map[string]string
		if err := json.Unmarshal(data, &langDict); err != nil {
			return fmt.Errorf("i18n: parse %s: %w", path, err)
		}
		// El nombre del archivo determina el lang: "strings_es.json" -> "es".
		lang := langFromFilename(path)
		if cache[lang] == nil {
			cache[lang] = make(map[string]string)
		}
		for k, v := range langDict {
			cache[lang][k] = v
		}
	}
	return nil
}

// readAsset lee un archivo del filesystem embebido catalogFS.
func readAsset(path string) ([]byte, error) {
	return catalogFS.ReadFile(path)
}

func langFromFilename(path string) string {
	// "strings_es.json" -> "es"
	base := path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		base = path[idx+1:]
	}
	// base = "strings_es.json"
	if !strings.HasPrefix(base, "strings_") || !strings.HasSuffix(base, ".json") {
		return ""
	}
	return base[len("strings_") : len(base)-len(".json")]
}

// T retorna el string traducido para key en el idioma actual. Si la key
// no existe en el idioma actual, cae al default (es). Si tampoco existe
// en el default, retorna la key misma (para detectar strings faltantes).
func T(key string) string {
	mu.RLock()
	lang := currentLang
	cat := cache
	mu.RUnlock()

	if cat == nil {
		// Load no se llamo (caso patologico). Retornamos la key para
		// que el caller vea el problema. Load() deberia llamarse en
		// init() de cada binario o en los tests.
		return key
	}

	if m, ok := cat[lang]; ok {
		if s, ok := m[key]; ok {
			return s
		}
	}
	if m, ok := cat[defaultLang]; ok {
		if s, ok := m[key]; ok {
			return s
		}
	}
	return key
}

// SetLang cambia el idioma activo. Si el idioma no esta disponible,
// retorna error pero el idioma actual NO cambia (defensa: nunca
// terminamos en un estado sin strings).
func SetLang(lang string) error {
	mu.Lock()
	defer mu.Unlock()

	if cache == nil {
		// Load no se llamo aun. Llamarlo ahora.
		if err := loadLocked(); err != nil {
			return err
		}
	}

	lang = strings.ToLower(strings.TrimSpace(lang))
	if _, ok := cache[lang]; !ok {
		return fmt.Errorf("i18n: idioma %q no disponible", lang)
	}
	currentLang = lang
	return nil
}

// GetLang retorna el idioma actual.
func GetLang() string {
	mu.RLock()
	defer mu.RUnlock()
	return currentLang
}

// AvailableLangs retorna la lista de idiomas cargados. Util para
// validar desde CLI o desde el wizard.
func AvailableLangs() []string {
	mu.RLock()
	defer mu.RUnlock()
	if cache == nil {
		return nil
	}
	langs := make([]string, 0, len(cache))
	for lang := range cache {
		langs = append(langs, lang)
	}
	return langs
}

// loadLocked es Load() pero ya con el lock tomado. Usado por SetLang
// cuando Load() no se llamo aun.
func loadLocked() error {
	cache = make(catalog)
	for _, path := range assets {
		data, err := readAsset(path)
		if err != nil {
			continue
		}
		var langDict map[string]string
		if err := json.Unmarshal(data, &langDict); err != nil {
			return fmt.Errorf("i18n: parse %s: %w", path, err)
		}
		lang := langFromFilename(path)
		if cache[lang] == nil {
			cache[lang] = make(map[string]string)
		}
		for k, v := range langDict {
			cache[lang][k] = v
		}
	}
	return nil
}

// Reset resetea el cache. Usado SOLO en tests. No llamar en produccion.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	cache = nil
	currentLang = defaultLang
}
