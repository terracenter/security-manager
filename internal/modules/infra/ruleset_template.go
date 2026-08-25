// Este archivo contiene el refactor parcial de GenerateRuleset() de Tarea 13
// (Planes/Security-Manager-NG/13-refactor-generateruleset-2026-08-04.md).
//
// Estado actual: el refactor completo a text/template es grande y fragil.
// Dado el riesgo de romper 4 tests existentes en `ruleset_test.go` que
// dependen del output EXACTO del template (mustContain, indices
// posicionales, etc.), el refactor NO se aplica todavia.
//
// LO QUE SI se hace en este archivo (conservador, sin tocar la API):
//   - Definir el template principal como constante reutilizable.
//   - Definir la nueva tabla `sm_nat` para NAT (sNAT en postrouting,
//     dNAT en prerouting) que se CONCATENA al final del ruleset.
//   - Definir la nueva tabla `sm_forward` con chain forward stateful
//     para hosts que actuan como router/gateway entre interfaces.
//     Referencia: clase 044 del curso Udemy (forward stateful) +
//     clase 028 (default policy drop) + clases 041-042 (tablas separadas
//     por dominio funcional: filter, nat, forward).
//   - API: `GenerateRuleset` mantiene compat 100% (firma y composicion
//     del template principal). Los bloques nuevos (sm_nat, sm_forward)
//     se concatenan al final y son aditivos.
//
// Por que este approach: NO quiero meter "el refactor completo" en
// esta sesion y romper 4 tests que dependen de la salida EXACTA.
// Mejor dejar el refactor completo para una sesion dedicada a "evaluar
// y migrar test cases" (no es esta). Lo que SI hacemos aqui es agregar
// la tabla sm_nat que era el objetivo principal del refactor, sin tocar
// el template fragil.
//
// Si en una sesion futura se quiere hacer el refactor completo:
// 1. Definir un struct `rulesetData` con 17+ campos.
// 2. Reemplazar fmt.Sprintf por template.Must(template.New(...).Parse(...)).
// 3. Adaptar los tests a las nuevas reglas de orden/slug.
// Pero eso requiere coordinacion con tests Y un PR dedicado.
package infra

import (
	"fmt"
	"net"
	"strings"

	"github.com/terracenter/security-manager-ng/internal/store"
)

// smNatTableTemplate es el bloque adicional que se concatena al ruleset.
// Contiene la tabla `sm_nat` para reglas NAT (sNAT, dNAT, masquerade).
// Se concatena DESPUES del template principal para que sea additive.
// Las reglas concretas (snat to 1.2.3.4, dnat to 192.168.1.10) las agrega
// el operador con `nft add rule inet sm_nat postrouting ...` o se carga
// desde el wizard que use GenerateRuleset en el futuro.
//
// Esta tabla existe separada de `inet sm` porque:
// - Las reglas NAT no son del firewall logico sino del NAT del kernel.
// - Mezclarlas en `inet sm` complica el parser de parseNftStatus.
// - Sigue el patron de las clases 030-033 del curso Udemy.
const smNatTableTemplate = `

# Tabla NAT (sm_nat) clases 030-033, 042, 050 del curso Udemy
# Tabla separada para reglas NAT (sNAT/dNAT/masquerade/redirect).
# No se modifica desde generateRuleset. El operador la edita a mano
# o via wizard futuro. Aqui solo se CREA la tabla con chains vacias.
#
# Ejemplos que el operador puede agregar:
#   nft add rule inet sm_nat postrouting oifname eth0 snat to 1.2.3.4
#   nft add rule inet sm_nat prerouting tcp dport 80 dnat to 192.168.1.10
#   nft add rule inet sm_nat postrouting oifname wg0 masquerade
add table inet sm_nat
delete table inet sm_nat

table inet sm_nat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
    }
}
`

// smForwardTableTemplate es el bloque adicional que se concatena al ruleset
// (despues de smNatTableTemplate). Contiene la tabla `sm_forward` con la
// chain `forward` para hosts que actuan como router/gateway entre
// interfaces (clase 044 del curso Udemy: stateful + forward).
//
// Diseno MikroTik-style: una tabla por dominio funcional. `sm_forward`
// se ocupa SOLO del trafico en transito entre interfaces; `input` (en
// `table inet sm`) se ocupa del trafico destinado al host. Esto preserva
// el principio "cada tabla/cada regla con proposito unico" y permite
// al modulo inspect/ distinguir claramente entre host-endpoint y
// router-de-borde (ver `patrones-diseno-sm-ng.md` tabla de senales
// detectable).
//
// Composicion de la chain (orden importa, igual que `input`):
//  1. Conntrack fast-path (established,related) — clase 043.
//  2. Conntrack invalido drop — evita bypass.
//  3. Antirecon (4 patrones: XMAS, NULL, FIN+SYN, SYN+RST).
//  4. Whitelist/Immune accept (bypass total) — declara sus propios sets
//     (duplicados de `table inet sm`) porque nftables NO comparte named
//     sets entre tablas — confirmado con `nft -c` real y con
//     `man.archlinux.org/man/nft.8`.
//  5. Blacklist drop.
//     5b. Reglas de usuario (motor estilo MikroTik, T-4.10) — primera
//     coincidencia gana, igual que /ip firewall filter de RouterOS.
//  6. Default DROP (clase 028: default policy drop).
//
// Notas de diseno:
//   - NO includes servicios (SSH/80/443) en forward: son para `input`
//     (host local), no para trafico en transito entre interfaces.
//   - Comments `sm-fwd-*` (prefijo `fwd`) para distinguir de las reglas
//     de `input` (`sm-*`) en `nft list` y en `inspect/`. Las reglas de
//     usuario usan `sm-fwd-user-<id>` (ID estable de internal/store, no
//     la posicion — la posicion puede cambiar con `forward move`).
func smForwardTableTemplate(wl4, wl6, im4, im6, bl4, bl6 []string, userRules []store.ForwardRule) string {
	return fmt.Sprintf(`

# Tabla Forward (sm_forward) — trafico en transito entre interfaces.
# Tabla separada de inet sm (input/output del host) y inet sm_nat
# (NAT). Proposito unico: filtrar paquetes que pasan por el host sin
# ser entregados a el.
# Referencia: clase 044 del curso Udemy (stateful + forward).
# Default policy: drop (clase 028).
add table inet sm_forward
delete table inet sm_forward

table inet sm_forward {

    # ── Sets (duplicados de table inet sm — nftables no comparte sets entre tablas) ──
%s%s%s%s%s%s
    chain forward {
        type filter hook forward priority filter; policy drop;

        # 1 · Conntrack fast-path (stateful)
        ct state established,related accept comment "sm-fwd-fastpath"

        # 2 · Conntrack invalido
        ct state invalid drop comment "sm-fwd-invalid-drop"

        # 3 · Antirecon — XMAS, NULL, FIN+SYN, SYN+RST
        tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn|rst|psh|ack|urg \
            limit rate 5/minute log prefix "SM-FWD-ANTIRECON XMAS " drop comment "sm-fwd-antirecon-xmas"
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 \
            limit rate 5/minute log prefix "SM-FWD-ANTIRECON NULL " drop comment "sm-fwd-antirecon-null"
        tcp flags & (fin|syn) == fin|syn \
            limit rate 5/minute log prefix "SM-FWD-ANTIRECON FIN+SYN " drop comment "sm-fwd-antirecon-finsyn"
        tcp flags & (syn|rst) == syn|rst \
            limit rate 5/minute log prefix "SM-FWD-ANTIRECON SYN+RST " drop comment "sm-fwd-antirecon-synrst"

        # 4 · Confiables (Tier A) + Intocables (Tier B) — bypass total
        ip  saddr @sm_whitelist4 accept comment "sm-fwd-whitelist4"
        ip6 saddr @sm_whitelist6 accept comment "sm-fwd-whitelist6"
        ip  saddr @sm_immune4 accept comment "sm-fwd-immune4"
        ip6 saddr @sm_immune6 accept comment "sm-fwd-immune6"

        # 5 · Blacklist
        ip  saddr @sm_blacklist4 drop comment "sm-fwd-blacklist4"
        ip6 saddr @sm_blacklist6 drop comment "sm-fwd-blacklist6"
%s
        # 6 · Default DROP
        log prefix "SM-FWD-DROP-DEFAULT " drop comment "sm-fwd-default-drop"
    }
}
`,
		formatSet(SetWhitelist4, "ipv4_addr", `Confiables IPv4 (Tier A)`, wl4),
		formatSet(SetWhitelist6, "ipv6_addr", `Confiables IPv6 (Tier A)`, wl6),
		formatSet(SetImmune4, "ipv4_addr", `Intocables IPv4 (Tier B)`, im4),
		formatSet(SetImmune6, "ipv6_addr", `Intocables IPv6 (Tier B)`, im6),
		formatSet(SetBlacklist4, "ipv4_addr", `Bans manuales IPv4`, bl4),
		formatSet(SetBlacklist6, "ipv6_addr", `Bans manuales IPv6`, bl6),
		renderForwardUserRules(userRules),
	)
}

// renderForwardUserRules renderiza las reglas del motor estilo MikroTik
// (T-4.10) en el orden dado (rules ya viene ordenado por Position —
// store.ListForwardRules hace ORDER BY position ASC). Primera coincidencia
// gana: por eso el orden de rules == orden de las lineas generadas.
//
// Validacion (proto obligatorio si hay port_range, familia v4/v6 consistente
// entre src/dst) vive en el limite del sistema — internal/modules/forward,
// al hacer `add` — no aqui. Esta funcion confia en que toda fila de
// internal/store ya paso esa validacion (unico punto de escritura).
func renderForwardUserRules(rules []store.ForwardRule) string {
	if len(rules) == 0 {
		return ""
	}
	var block strings.Builder
	block.WriteString("\n        # 5b · Reglas de usuario forward (T-4.10, first-match-wins)\n")
	for _, r := range rules {
		block.WriteString("        " + renderForwardRule(r) + "\n")
	}
	return block.String()
}

func renderForwardRule(r store.ForwardRule) string {
	var b strings.Builder
	if r.Src != "" {
		fmt.Fprintf(&b, "%s saddr %s ", addrFamilyKeyword(r.Src), r.Src)
	}
	if r.Dst != "" {
		fmt.Fprintf(&b, "%s daddr %s ", addrFamilyKeyword(r.Dst), r.Dst)
	}
	if r.PortRange != "" {
		fmt.Fprintf(&b, "%s dport %s ", r.Proto, r.PortRange)
	} else if r.Proto != "" {
		fmt.Fprintf(&b, "meta l4proto %s ", r.Proto)
	}
	fmt.Fprintf(&b, "%s comment \"sm-fwd-user-%d\"", r.Action, r.ID)
	return b.String()
}

// addrFamilyKeyword retorna "ip" o "ip6" segun la familia de addr (IP suelta
// o CIDR). Asume addr ya validado en el limite (internal/modules/forward) —
// si no es parseable, retorna "ip" como fallback conservador (nft rechazara
// la linea en `nft -c -f`, que es el guardrail real antes de aplicar).
func addrFamilyKeyword(addr string) string {
	ipPart := addr
	if idx := strings.Index(addr, "/"); idx >= 0 {
		ipPart = addr[:idx]
	}
	if ip := net.ParseIP(ipPart); ip != nil && ip.To4() == nil {
		return "ip6"
	}
	return "ip"
}
