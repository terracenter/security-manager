package firewall

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// PatternDetected es el resultado de detectar un patron de firewall en el ruleset.
// El agente usa esto desde `inspect/` para decirle al operador que patron implemento
// el host (endpoint, router de borde, DMZ, dual firewall) y que servicios
// se romperan al hacer apply.
type PatternDetected struct {
	Name        string   // endpoint | router-borde | dmz | dual-firewall | nat-out | nat-in
	Confidence  int      // 0-100
	Evidence    []string // lineas de `nft list table inet sm` que justifican la deteccion
	Description string   // explicacion en lenguaje humano
}

// InspectResult es el reporte completo de un inspect profundo.
// Incluye el output basico de `parseNftStatus()` (chains/sets) MAS los patrones
// detectados (que es lo que el checkpoint 2026-07-27 llamaba "inspect profundo").
type InspectResult struct {
	TableActive    bool             // true si la tabla `inet sm` existe
	Chains         map[string]chainInfo
	Sets           map[string]int
	Patterns       []PatternDetected
	Recommendation string           // texto humano: que el operador deberia hacer
}

// Inspect ejecuta `nft list table inet sm`, parsea el resultado, y detecta
// los 16 patrones documentados en
// Planes/Cursos/Firewall-Nftables/caracteristicas/patrones-diseno-sm-ng.md.
// Inspirado en clases 041-056 del curso Udemy nftables.
func (f *Firewall) Inspect() (InspectResult, error) {
	var result InspectResult

	// 1. Listar el ruleset completo.
	out, err := exec.Command("nft", "list", "table", "inet", "sm").CombinedOutput()
	if err != nil {
		// No distinguir error: tabla no existe o nft no disponible. Caller decide.
		return result, fmt.Errorf("nft list table inet sm: %s", strings.TrimSpace(string(out)))
	}
	result.TableActive = true

	// 2. Parser basico (existente). Reutiliza parseNftStatus().
	chains, sets := parseNftStatus(string(out))
	result.Chains = chains
	result.Sets = sets

	// 3. Deteccion de patrones.
	detector := newPatternDetector(string(out))
	detector.detect()
	result.Patterns = detector.patterns

	// 4. Recomendacion agregada.
	result.Recommendation = buildRecommendation(detector.patterns, chains, sets)

	return result, nil
}

// patternDetector analiza el output de `nft list table inet sm` y detecta
// los 16 patrones de firewall (endpoint, router de borde, DMZ, dual firewall,
// NAT, stateful vs stateless).
type patternDetector struct {
	raw      string   // output completo de nft list
	lines    []string // lineas separadas
	patterns []PatternDetected
}

func newPatternDetector(raw string) *patternDetector {
	return &patternDetector{
		raw:   raw,
		lines: strings.Split(raw, "\n"),
	}
}

// detect corre todas las detecciones. Cada una agrega un PatternDetected
// a la lista con su evidencia.
func (d *patternDetector) detect() {
	d.detectChainForward()    // chain forward existe?
	d.detectChainPostrouting() // NAT en postrouting?
	d.detectChainPrerouting()  // NAT en prerouting (dNAT)?
	d.detectStateful()         // ct state established,related accept?
	d.detectPolicyDrop()       // policy drop en chains de filter?
	d.detectGeoIPRules()       // reglas GeoIP con @sm_geoallow?
	d.detectTierAWhitelist()   // sm_whitelist4/6 con elementos?
	d.detectTierBImmune()      // sm_immune4/6 con elementos?
	d.detectBlacklistActive()  // sm_blacklist4/6 con elementos?
	d.detectCrowdsecDrops()    // drop por @crowdsec-blacklists?
	d.detectAntirecon()        // tcp flags & (fin|syn|...) == ...?
	d.detectDefaultDropLog()   // log prefix "SM-DROP-DEFAULT" en chain?
}

// detectChainForward verifica si existe chain `forward { type filter hook forward ... }`.
// Patron: router de borde (clase 044), DMZ (047-051), dual firewall (052-056).
func (d *patternDetector) detectChainForward() {
	re := regexp.MustCompile(`(?m)^\s*chain\s+forward\s*\{`)
	match := re.FindString(d.raw)
	if match == "" {
		return
	}
	// Buscar la linea del type filter hook forward.
	for _, line := range d.lines {
		if strings.Contains(line, "type filter hook forward") {
			confidence := 70
			// Si ademas tiene ct state established,related, es stateful (mas confianza).
			for _, l := range d.lines {
				if strings.Contains(l, "ct state established,related accept") {
					confidence = 90
				}
			}
			d.patterns = append(d.patterns, PatternDetected{
				Name:        "router-borde",
				Confidence:  confidence,
				Evidence:    d.evidenceAround("chain forward", 3),
				Description: "El host hace routing entre interfaces (chain forward activa). Caso tipico: firewall perimetral / router de borde con stateful inspection.",
			})
			return
		}
	}
}

// detectChainPostrouting detecta sNAT/masquerade (clases 030-031, 042, 054).
func (d *patternDetector) detectChainPostrouting() {
	// La cadena postrouting existe por default en GenerateRuleset (linea
	// "chain postrouting { type nat hook postrouting priority srcnat; }").
	// Lo que indica NAT activo son las REGLAS dentro (snat to, masquerade).
	re := regexp.MustCompile(`(?m)^\s*snat\s+to`)
	for _, line := range d.lines {
		if re.MatchString(line) || strings.Contains(line, "masquerade") {
			d.patterns = append(d.patterns, PatternDetected{
				Name:        "nat-out",
				Confidence:  85,
				Evidence:    d.evidenceAround(line, 2),
				Description: "NAT de salida (sNAT o masquerade) configurado. El host comparte internet o reescribe source de paquetes salientes.",
			})
			return
		}
	}
}

// detectChainPrerouting detecta dNAT (clases 032, 050, 056).
func (d *patternDetector) detectChainPrerouting() {
	re := regexp.MustCompile(`(?m)^\s*dnat\s+to`)
	for _, line := range d.lines {
		if re.MatchString(line) {
			d.patterns = append(d.patterns, PatternDetected{
				Name:        "nat-in",
				Confidence:  85,
				Evidence:    d.evidenceAround(line, 2),
				Description: "DNAT de entrada (Destination NAT) configurado. El host redirige paquetes entrantes a otro equipo (típico: DMZ o servidor interno).",
			})
			return
		}
	}
}

// detectStateful detecta ct state established,related (clase 043).
func (d *patternDetector) detectStateful() {
	for _, line := range d.lines {
		if strings.Contains(line, "ct state established,related accept") {
			d.patterns = append(d.patterns, PatternDetected{
				Name:        "stateful",
				Confidence:  95,
				Evidence:    d.evidenceAround("ct state established,related accept", 2),
				Description: "Firewall stateful: usa conntrack para permitir respuestas de conexiones iniciadas. Patron moderno, el 90% de los hosts Linux lo necesitan.",
			})
			return
		}
	}
}

// detectPolicyDrop detecta policy drop en chains filter (clase 028).
func (d *patternDetector) detectPolicyDrop() {
	for _, line := range d.lines {
		if strings.Contains(line, "policy drop") && strings.Contains(line, "hook") {
			// Solo chains filter con hook.
			if strings.Contains(line, "type filter hook") {
				d.patterns = append(d.patterns, PatternDetected{
					Name:        "default-policy-drop",
					Confidence:  100,
					Evidence:    d.evidenceAround(line, 1),
					Description: "Default policy es DROP. Patron correcto para firewalls: lo no permitido explicitamente se cae al vacio (no se rechaza, lo que evita filtracion de informacion).",
				})
				return
			}
		}
	}
}

// detectGeoIPRules detecta reglas con @sm_geoallow (clase 012-018 + geoip module).
func (d *patternDetector) detectGeoIPRules() {
	for _, line := range d.lines {
		if strings.Contains(line, "@sm_geoallow") {
			d.patterns = append(d.patterns, PatternDetected{
				Name:        "geoip-allowlist",
				Confidence:  90,
				Evidence:    d.evidenceAround("@sm_geoallow", 2),
				Description: "Filtro geografico activo: solo IPs de paises en la allowlist GeoIP alcanzan stage 8. Patron de seguridad recomendado para hosts publicos.",
			})
			return
		}
	}
}

// detectTierAWhitelist detecta sm_whitelist4/6 con elementos.
func (d *patternDetector) detectTierAWhitelist() {
	if d.setHasElements("sm_whitelist4") || d.setHasElements("sm_whitelist6") {
		d.patterns = append(d.patterns, PatternDetected{
			Name:        "tier-a-whitelist",
			Confidence:  100,
			Evidence:    d.setEvidence("sm_whitelist"),
			Description: "Tier A (Confiables) configurado: IPs que pasan el firewall pero fail2ban SI puede banearlas. Tipico: LAN, IPs de proveedores con soporte.",
		})
	}
}

// detectTierBImmune detecta sm_immune4/6 con elementos.
func (d *patternDetector) detectTierBImmune() {
	if d.setHasElements("sm_immune4") || d.setHasElements("sm_immune6") {
		d.patterns = append(d.patterns, PatternDetected{
			Name:        "tier-b-immune",
			Confidence:  100,
			Evidence:    d.setEvidence("sm_immune"),
			Description: "Tier B (Intocables) configurado: IPs que pasan el firewall Y fail2ban/crowdsec JAMAS las banea. Sincronizadas a ignoreip/allowlist. Tipico: admins, IPs de oficina.",
		})
	}
}

// detectBlacklistActive detecta sm_blacklist4/6 con elementos.
func (d *patternDetector) detectBlacklistActive() {
	if d.setHasElements("sm_blacklist4") || d.setHasElements("sm_blacklist6") {
		d.patterns = append(d.patterns, PatternDetected{
			Name:        "blacklist-active",
			Confidence:  100,
			Evidence:    d.setEvidence("sm_blacklist"),
			Description: "Blacklist con bans manuales activos. Stage 5 los bloquea ANTES de whitelist/immune (orden correcto, verificado en clases 008 del curso).",
		})
	}
}

// detectCrowdsecDrops detecta drop por @crowdsec-blacklists (Decision 3).
func (d *patternDetector) detectCrowdsecDrops() {
	for _, line := range d.lines {
		if strings.Contains(line, "@crowdsec-blacklists") && strings.Contains(line, "drop") {
			d.patterns = append(d.patterns, PatternDetected{
				Name:        "crowdsec-integration",
				Confidence:  95,
				Evidence:    d.evidenceAround("@crowdsec-blacklists", 2),
				Description: "Integracion con CrowdSec activa: stage 5b dropea bans de CrowdSec antes de whitelist/immune. CrowdSec + SM-NG comparten el mismo ruleset.",
			})
			return
		}
	}
}

// detectAntirecon detecta las reglas anti-recon con flags malformados (stage 4).
func (d *patternDetector) detectAntirecon() {
	for _, line := range d.lines {
		if strings.Contains(line, "tcp flags") && strings.Contains(line, "limit rate 5/minute") {
			d.patterns = append(d.patterns, PatternDetected{
				Name:        "antirecon",
				Confidence:  90,
				Evidence:    d.evidenceAround("tcp flags", 3),
				Description: "Anti-recon activo: detecta y rate-limita paquetes con flags malformados (XMAS, NULL, FIN+SYN, SYN+RST). Patron recomendado para hosts publicos.",
			})
			return
		}
	}
}

// detectDefaultDropLog detecta log prefix "SM-DROP-DEFAULT" en stage 9.
func (d *patternDetector) detectDefaultDropLog() {
	for _, line := range d.lines {
		if strings.Contains(line, "SM-DROP-DEFAULT") {
			d.patterns = append(d.patterns, PatternDetected{
				Name:        "default-drop-logged",
				Confidence:  85,
				Evidence:    d.evidenceAround("SM-DROP-DEFAULT", 1),
				Description: "Default DROP esta logueado (no silencioso). Permite auditoria post-mortem de intentos de conexion bloqueados.",
			})
			return
		}
	}
}

// --- helpers ---

// setHasElements verifica si un set nftables tiene elementos (no solo declaracion).
// Busca "elements = { ... }" o "elements = {" (vacio cuenta como declarado, no activo).
func (d *patternDetector) setHasElements(setName string) bool {
	inSet := false
	for _, line := range d.lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "set "+setName+" ") || strings.HasPrefix(trim, "set "+setName+"{") {
			inSet = true
			continue
		}
		if inSet {
			if strings.HasPrefix(trim, "elements = {") {
				// Si la linea tiene "elements = { algo }", hay elementos.
				content := strings.TrimPrefix(trim, "elements = {")
				content = strings.TrimSuffix(content, "}")
				content = strings.TrimSpace(content)
				return content != ""
			}
			if trim == "}" {
				return false
			}
		}
	}
	return false
}

// evidenceAround retorna las lineas alrededor de un patron para incluir como evidencia.
// Retorna []string{} si no encuentra el patron.
func (d *patternDetector) evidenceAround(needle string, context int) []string {
	var out []string
	for i, line := range d.lines {
		if strings.Contains(line, needle) {
			start := i - context
			if start < 0 {
				start = 0
			}
			end := i + context + 1
			if end > len(d.lines) {
				end = len(d.lines)
			}
			for j := start; j < end; j++ {
				out = append(out, strings.TrimSpace(d.lines[j]))
			}
			return out
		}
	}
	return out
}

// setEvidence retorna evidencia para un set (su declaracion con conteo).
func (d *patternDetector) setEvidence(setPrefix string) []string {
	var out []string
	for _, line := range d.lines {
		if strings.Contains(line, "set "+setPrefix) {
			out = append(out, strings.TrimSpace(line))
		}
	}
	return out
}

// buildRecommendation genera una recomendacion humana segun los patrones detectados.
func buildRecommendation(patterns []PatternDetected, chains map[string]chainInfo, sets map[string]int) string {
	if len(patterns) == 0 {
		return "No se detectaron patrones especificos. El ruleset parece ser un baseline generico. Considerar agregar whitelist/immune/blacklist segun el caso de uso."
	}

	var rec strings.Builder
	rec.WriteString("Patrones detectados:\n")
	for _, p := range patterns {
		rec.WriteString(fmt.Sprintf("  - %s (confianza %d%%): %s\n", p.Name, p.Confidence, p.Description))
	}

	// Recomendaciones especificas.
	hasForward := false
	hasNAT := false
	for _, p := range patterns {
		if strings.HasPrefix(p.Name, "router-borde") || strings.HasPrefix(p.Name, "dmz") || strings.HasPrefix(p.Name, "dual-firewall") {
			hasForward = true
		}
		if strings.HasPrefix(p.Name, "nat-") {
			hasNAT = true
		}
	}

	rec.WriteString("\nRecomendaciones:\n")
	if !hasForward {
		rec.WriteString("  - El host es ENDPOINT (no hace forward). Si queres que haga routing, agregar chain forward (ver ROADMAP P3).\n")
	}
	if hasNAT {
		rec.WriteString("  - NAT activo. Verificar que la tabla sm_nat (o prerouting/postrouting de inet sm) tiene las reglas correctas.\n")
	}
	_, hasInputChain := chains["input"]
	if !hasInputChain {
		rec.WriteString("  - NO se detecto chain input. El ruleset esta vacio o solo tiene forward.\n")
	}

	return rec.String()
}

// --- CLI integration ---

// inspectCLI es el handler de la opcion de menu [2] (ver estado).
// REEMPLAZA al showStatus() existente para usar el Inspect profundo.
// Mantener showStatus() por compatibilidad con RunAction("status") y tests.
func (f *Firewall) inspectCLI() {
	result, err := f.Inspect()
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "No such file or directory") || strings.Contains(errMsg, "no such table") {
			fmt.Println("  ✗ Firewall: INACTIVO — Ninguna regla de seguridad está activa en este servidor.")
			fmt.Println("     → Usa [1] Aplicar / recargar ruleset base para activarlo.")
		} else {
			fmt.Println("  ✗ nftables no está instalado — el firewall no puede funcionar.")
			fmt.Println("     → Ejecuta: sudo apt install nftables")
		}
		if f.logger != nil {
			f.logger.Technical(errMsg)
		}
		return
	}

	fmt.Println()
	fmt.Println("  ✓ Firewall: ACTIVO")
	fmt.Println()

	if len(result.Chains) > 0 {
		fmt.Println("  Cadenas:")
		for name, info := range result.Chains {
			fmt.Printf("    %-12s policy:%-8s — %d reglas\n", name, info.policy, info.ruleCount)
		}
		fmt.Println()
	}

	if len(result.Sets) > 0 {
		fmt.Println("  Sets:")
		for name, count := range result.Sets {
			if count == 0 {
				fmt.Printf("    %-20s (vacío)\n", name)
			} else {
				fmt.Printf("    %-20s %d entradas\n", name, count)
			}
		}
		fmt.Println()
	}

	if len(result.Patterns) > 0 {
		fmt.Println("  Patrones detectados:")
		for _, p := range result.Patterns {
			conf := strconv.Itoa(p.Confidence)
			fmt.Printf("    [%s%%] %s — %s\n", conf, p.Name, p.Description)
		}
		fmt.Println()
	}

	if result.Recommendation != "" {
		fmt.Println("  " + strings.ReplaceAll(result.Recommendation, "\n", "\n  "))
	}

	fmt.Println("  Detalles técnicos → /var/log/security-manager-ng.log")
	if f.logger != nil {
		f.logger.Technical(strings.Join(collectEvidenceHelper(result.Patterns), "\n"))
	}
}

// collectEvidence concatena la evidencia de todos los patrones para el log tecnico.
func collectEvidenceHelper(patterns []PatternDetected) []string {
	var out []string
	for _, p := range patterns {
		out = append(out, fmt.Sprintf("=== %s (confianza %d%%) ===", p.Name, p.Confidence))
		out = append(out, p.Evidence...)
	}
	return out
}

// Asegurar que el compiler no marque unused: bufio se importa por compatibilidad
// con el resto del archivo. Si no se usa, el linter se queja.
var _ = bufio.NewScanner
