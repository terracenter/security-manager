package fail2ban

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// D1 — Constantes SSoT
const (
	ipinfoURL = "https://ipinfo.io/%s"
)

var httpClient = &http.Client{Timeout: 5 * time.Second}

// D2 — Struct + New()
type Fail2ban struct {
	scanner *bufio.Scanner
}

func New() *Fail2ban {
	return &Fail2ban{scanner: bufio.NewScanner(os.Stdin)}
}

// D3 — Interface Module (Order/Name/Reset)
func (f *Fail2ban) Order() int   { return 7 }
func (f *Fail2ban) Name() string { return "Fail2ban — monitoreo" }

func (f *Fail2ban) Reset() {
	fmt.Println("  Fail2ban: módulo de solo monitoreo — no hay configuración que resetear.")
	fmt.Println("  Para gestionar fail2ban usa: fail2ban-client, systemctl.")
}

// D4 — Menu() — 5 opciones
func (f *Fail2ban) Menu() {
	for {
		fmt.Println("\n┌─ Fail2ban — Monitoreo ─────────────────────────┐")
		fmt.Println("│  [1] Estado del servicio y jails               │")
		fmt.Println("│  [2] IPs baneadas por jail                     │")
		fmt.Println("│  [3] Buscar IP en todos los jails              │")
		fmt.Println("│  [4] Geolocalización de IP (ipinfo.io)         │")
		fmt.Println("│  [0] Volver                                    │")
		fmt.Println("└─────────────────────────────────────────────────┘")

		opt := f.readLine("\nOpción: ")
		switch strings.TrimSpace(opt) {
		case "1":
			f.showStatus()
		case "2":
			f.listBannedMenu()
		case "3":
			ip := f.readLine("IP a buscar: ")
			if ip = strings.TrimSpace(ip); ip != "" {
				f.searchIP(ip)
			}
		case "4":
			ip := f.readLine("IP a geolocalizar: ")
			if ip = strings.TrimSpace(ip); ip != "" {
				f.geoInfo(ip)
			}
		case "0", "":
			return
		default:
			fmt.Println("  Opción inválida")
		}
	}
}

// D5 — showStatus()
func (f *Fail2ban) showStatus() {
	// Verificar systemctl
	out, _ := exec.Command("systemctl", "is-active", "fail2ban").Output()
	active := strings.TrimSpace(string(out))
	out, _ = exec.Command("systemctl", "is-enabled", "fail2ban").Output()
	enabled := strings.TrimSpace(string(out))

	fmt.Printf("\n  Servicio: activo=%s  habilitado=%s\n", active, enabled)

	// Obtener lista de jails
	jails := f.activeJails()
	if len(jails) == 0 {
		fmt.Println("  No hay jails activos.")
		return
	}

	fmt.Println("\n  Jaula                   Baneados   Total histórico")
	fmt.Println("  ─────────────────────────────────────────────────")

	for _, jail := range jails {
		// fail2ban-client status <jail>
		out, err := exec.Command("fail2ban-client", "status", jail).Output()
		if err != nil {
			continue
		}

		// Parsear "Currently banned:" y "Total banned:"
		lines := strings.Split(string(out), "\n")
		var currently, total string
		for _, line := range lines {
			if strings.Contains(line, "Currently banned") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					currently = strings.TrimSpace(parts[len(parts)-1])
				}
			}
			if strings.Contains(line, "Total banned") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					total = strings.TrimSpace(parts[len(parts)-1])
				}
			}
		}

		if currently == "" {
			currently = "0"
		}
		if total == "" {
			total = "0"
		}

		fmt.Printf("  %-23s %-10s %s\n", jail, currently, total)
	}
}

// D6 — listBanned()
func (f *Fail2ban) listBanned(jail string) {
	out, err := exec.Command("fail2ban-client", "status", jail).Output()
	if err != nil {
		fmt.Printf("  Error consultando jail %s\n", jail)
		return
	}

	ips := f.parseBannedIPs(string(out))
	if len(ips) == 0 {
		fmt.Printf("  [%s] — 0 IPs baneadas\n", jail)
		return
	}

	fmt.Printf("\n  [%s] — %d IPs baneadas\n\n", jail, len(ips))
	fmt.Println("  IP                    País  Ciudad          Org")
	fmt.Println("  ──────────────────────────────────────────────────────")

	pageSize := 15
	for i := 0; i < len(ips); i += pageSize {
		end := i + pageSize
		if end > len(ips) {
			end = len(ips)
		}

		for _, ip := range ips[i:end] {
			info := f.geoInfoQuiet(ip)
			país := info.Country
			if país == "" {
				país = "—"
			}
			ciudad := info.City
			if ciudad == "" {
				ciudad = "—"
			}
			org := info.Org
			if org == "" {
				org = "—"
			}
			if len(org) > 20 {
				org = org[:20]
			}

			fmt.Printf("  %-21s %-5s %-15s %s\n", ip, país, ciudad, org)
		}

		if end < len(ips) {
			if strings.HasPrefix(f.readLine("\n  Enter=más IPs | q=salir: "), "q") {
				return
			}
		}
	}
}

func (f *Fail2ban) listBannedMenu() {
	jails := f.activeJails()
	if len(jails) == 0 {
		fmt.Println("  No hay jails activos.")
		return
	}

	for i, jail := range jails {
		fmt.Printf("  [%d] %s\n", i+1, jail)
	}

	opt := f.readLine("\nJail a consultar (número): ")
	opt = strings.TrimSpace(opt)
	for i, jail := range jails {
		if fmt.Sprintf("%d", i+1) == opt {
			f.listBanned(jail)
			return
		}
	}
	fmt.Println("  Opción inválida")
}

// D7 — searchIP()
func (f *Fail2ban) searchIP(ip string) {
	jails := f.activeJails()
	if len(jails) == 0 {
		fmt.Println("  No hay jails activos.")
		return
	}

	found := false
	fmt.Printf("\n  Buscando IP %s en todos los jails...\n", ip)

	for _, jail := range jails {
		out, err := exec.Command("fail2ban-client", "status", jail).Output()
		if err != nil {
			continue
		}

		ips := f.parseBannedIPs(string(out))
		for _, bannedIP := range ips {
			if bannedIP == ip {
				fmt.Printf("  ✓ Encontrada en jail: %s\n", jail)
				found = true
			}
		}
	}

	if !found {
		fmt.Printf("  ✗ IP %s no encontrada en ningún jail.\n", ip)
		return
	}

	// Mostrar geo de la IP
	fmt.Println()
	f.geoInfo(ip)
}

// D8 — geoInfo() — consulta directa a ipinfo.io
func (f *Fail2ban) geoInfo(ip string) {
	info := f.fetchGeo(ip)
	if info.Country == "" {
		fmt.Printf("  Geolocalización no disponible para %s\n", ip)
		return
	}

	fmt.Printf("  País:     %s — %s, %s\n", info.Country, info.City, info.Region)
	fmt.Printf("  Org:      %s\n", info.Org)
	fmt.Printf("  Timezone: %s\n", info.Timezone)
	fmt.Printf("  Loc:      %s\n", info.Loc)
}

// geoInfoQuiet retorna GeoInfo sin imprimir (para tablas)
func (f *Fail2ban) geoInfoQuiet(ip string) GeoInfo {
	return f.fetchGeo(ip)
}

// GeoInfo contiene resultado de ipinfo.io
type GeoInfo struct {
	Country  string `json:"country"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Loc      string `json:"loc"`
	Org      string `json:"org"`
	Hostname string `json:"hostname"`
	Postal   string `json:"postal"`
	Timezone string `json:"timezone"`
}

// fetchGeo llama directamente a ipinfo.io
func (f *Fail2ban) fetchGeo(ip string) GeoInfo {
	apiURL := fmt.Sprintf(ipinfoURL, ip)
	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return GeoInfo{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return GeoInfo{}
	}

	var info GeoInfo
	json.NewDecoder(resp.Body).Decode(&info)
	return info
}

// D9 — Helpers
func (f *Fail2ban) activeJails() []string {
	out, err := exec.Command("fail2ban-client", "status").Output()
	if err != nil {
		return nil
	}

	var jails []string
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Jail list:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				jailsStr := strings.TrimSpace(parts[1])
				jails = strings.Fields(jailsStr)
			}
			break
		}
	}
	return jails
}

func (f *Fail2ban) parseBannedIPs(output string) []string {
	var ips []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Banned IP list:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				ipsStr := strings.TrimSpace(parts[1])
				if ipsStr != "" {
					ips = strings.Fields(ipsStr)
				}
			}
			break
		}
	}
	return ips
}

func (f *Fail2ban) readLine(prompt string) string {
	fmt.Print(prompt)
	if f.scanner.Scan() {
		return f.scanner.Text()
	}
	return ""
}

// Compile-time assertion
var _ interface {
	Order() int
	Name() string
	Menu()
	Reset()
} = (*Fail2ban)(nil)
