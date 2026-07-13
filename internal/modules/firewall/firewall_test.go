package firewall

import (
	"strings"
	"testing"
	"time"

	"github.com/terracenter/security-manager-ng/internal/sys"
)

func TestBuildAllowedEntries(t *testing.T) {
	tests := []struct {
		name     string
		selected []sys.ServiceInfo
		tier     string
		wantLen  int
		wantPort string
	}{
		{
			name:     "empty selection",
			selected: []sys.ServiceInfo{},
			tier:     "GLOBAL",
			wantLen:  0,
		},
		{
			name: "single port GLOBAL",
			selected: []sys.ServiceInfo{
				{Port: 443, Proto: "tcp", ProcessName: "nginx"},
			},
			tier:     "GLOBAL",
			wantLen:  1,
			wantPort: "443 | tcp | GLOBAL",
		},
		{
			name: "multiple ports GEO",
			selected: []sys.ServiceInfo{
				{Port: 443, Proto: "tcp", ProcessName: "nginx"},
				{Port: 3128, Proto: "tcp", ProcessName: "squid"},
			},
			tier:     "GEO",
			wantLen:  2,
			wantPort: "3128 | tcp | GEO",
		},
		{
			name: "port with unknown process",
			selected: []sys.ServiceInfo{
				{Port: 5000, Proto: "tcp", ProcessName: ""},
			},
			tier:     "GLOBAL",
			wantLen:  1,
			wantPort: "5000 | tcp | GLOBAL | auto-detect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := buildAllowedEntries(tt.selected, tt.tier)
			if len(entries) != tt.wantLen {
				t.Errorf("expected %d entries, got %d", tt.wantLen, len(entries))
			}
			if tt.wantLen > 0 && tt.wantPort != "" {
				// Buscar el wantPort en cualquiera de las entradas
				found := false
				for _, entry := range entries {
					if strings.Contains(entry, tt.wantPort) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("entries do not contain %q: %v", tt.wantPort, entries)
				}
			}
			// Verifica que todas las entradas contienen la fecha de hoy
			today := time.Now().Format("2006-01-02")
			for _, entry := range entries {
				if !strings.Contains(entry, today) {
					t.Errorf("entry missing today's date (%s): %s", today, entry)
				}
			}
		})
	}
}
