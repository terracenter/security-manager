package sys

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ServiceInfo describe un servicio activo detectado en el host.
type ServiceInfo struct {
	Port        int
	Proto       string
	ProcessName string
}

// DetectListeningServices detecta servicios activos escaneando puertos con ss.
// Excluye loopback (127.x.x.x, ::1).
// Retorna lista ordenada por puerto.
func DetectListeningServices() ([]ServiceInfo, error) {
	var services []ServiceInfo

	flagMap := map[string]string{"tcp": "t", "udp": "u"}
	for _, proto := range []string{"tcp", "udp"} {
		cmd := "ss"
		flag := "-" + flagMap[proto] + "lnp"
		out, err := RunCmdOut(cmd, flag)
		if err != nil {
			return nil, fmt.Errorf("error ejecutando ss -%s: %v", proto, err)
		}

		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "State") {
				continue
			}

			info, ok := parseSsLine(line, proto)
			if !ok {
				continue
			}

			services = append(services, info)
		}
	}

	// Eliminar duplicados (puerto puede aparecer en IPv4 e IPv6)
	services = deduplicateServices(services)

	// Ordenar por puerto
	sort.Slice(services, func(i, j int) bool {
		return services[i].Port < services[j].Port
	})

	return services, nil
}

// isLoopbackAddr verifica si una dirección local es loopback (127.x.x.x o ::1).
func isLoopbackAddr(localAddr string) bool {
	host, _, err := net.SplitHostPort(localAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// parseSsLine parsea una línea de salida de `ss -tlnp` o `ss -ulnp`.
// Formato esperado:
//
//	LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=1234,fd=6))
//
// Filtra automáticamente direcciones loopback.
// Retorna ServiceInfo con Proto temporalmente usado para IP origen (ignorar).
func parseSsLine(line string, proto string) (ServiceInfo, bool) {
	parts := strings.Fields(line)
	if len(parts) < 4 {
		return ServiceInfo{}, false
	}

	// Parsear dirección local (campo 3): "0.0.0.0:443" o "[::1]:443"
	localAddr := parts[3]

	// Filtrar loopback: solo procesar si la IP no es loopback
	if isLoopbackAddr(localAddr) {
		return ServiceInfo{}, false
	}

	port, processName := extractPortAndProcess(localAddr, line)
	if port == 0 {
		return ServiceInfo{}, false
	}

	return ServiceInfo{
		Port:        port,
		Proto:       strings.ToLower(proto),
		ProcessName: processName,
	}, true
}

// extractPortAndProcess extrae el puerto y nombre de proceso de una línea ss.
func extractPortAndProcess(localAddr string, fullLine string) (int, string) {
	// Extraer puerto de "0.0.0.0:443" o "[::1]:443"
	var port int
	if strings.Contains(localAddr, ":") {
		parts := strings.Split(localAddr, ":")
		if len(parts) > 0 {
			portStr := parts[len(parts)-1]
			portStr = strings.TrimPrefix(portStr, "]")
			if p, err := strconv.Atoi(portStr); err == nil {
				port = p
			}
		}
	}

	if port == 0 {
		return 0, ""
	}

	// Extraer nombre de proceso de "users:(("nginx",pid=1234,fd=6))"
	re := regexp.MustCompile(`users:\(\("([^"]+)"`)
	matches := re.FindStringSubmatch(fullLine)
	if len(matches) > 1 {
		return port, matches[1]
	}

	return port, ""
}

// deduplicateServices elimina servicios duplicados (mismo puerto, protocolo).
func deduplicateServices(services []ServiceInfo) []ServiceInfo {
	seen := make(map[string]bool)
	var result []ServiceInfo
	for _, s := range services {
		key := fmt.Sprintf("%d/%s", s.Port, s.Proto)
		if !seen[key] {
			seen[key] = true
			result = append(result, s)
		}
	}
	return result
}
