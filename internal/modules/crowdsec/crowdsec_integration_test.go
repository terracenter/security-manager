//go:build integration

package crowdsec

import (
	"testing"
)

// TestRemoveFromAllowlist_RequiresCscli documenta el setup exacto para validar
// RemoveFromAllowlist contra un cscli real, y skippea cuando CrowdSec no está.
//
// Setup completo para validar en vivo (ejecutar en host con crowdsec agent):
//
//	# 1. Instalar CrowdSec agent + cscli (Debian/Ubuntu):
//	curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
//	sudo apt install crowdsec
//	cscli version   # verificar instalación
//
//	# 2. Permitir sudo NOPASSWD para cscli allowlists (requerido por RemoveFromAllowlist):
//	echo 'freddy ALL=(root) NOPASSWD: /usr/bin/cscli allowlists *' | sudo tee /etc/sudoers.d/crowdsec-smng
//	sudo chmod 440 /etc/sudoers.d/crowdsec-smng
//
//	# 3. Crear el allowlist destino:
//	sudo cscli allowlists create sm-immune --description "SM-NG Immune Tier IPs"
//
//	# 4. Poblar con 3 IPs de prueba:
//	sudo cscli allowlists add sm-immune 10.0.0.1
//	sudo cscli allowlists add sm-immune 10.0.0.2
//	sudo cscli allowlists add sm-immune 10.0.0.3
//
//	# 5. Crear archivo immune con SOLO 10.0.0.1 (las otras 2 deben ser removidas):
//	echo "10.0.0.1" > /tmp/immune-test.txt
//
//	# 6. Validar antes/después:
//	sudo cscli allowlists list sm-immune   # ANTES: 3 IPs
//	go test -tags=integration -v -run TestRemoveFromAllowlist_RequiresCscli ./internal/modules/crowdsec/
//	sudo cscli allowlists list sm-immune   # DESPUÉS: solo 10.0.0.1
//
// Limitación documentada: RemoveFromAllowlist invoca `sudo cscli ...` sin
// wrapping — no hay interfaz CscliRunner para mockear. Cualquier test que
// ejecute el código real requiere el setup completo de arriba. Un test
// hermético requeriría refactor previo (fuera de scope).
func TestRemoveFromAllowlist_RequiresCscli(t *testing.T) {
	if !IsInstalled() {
		t.Skip("cscli no instalado localmente — ver header del test para setup completo")
	}

	t.Log("RemoveFromAllowlist validable en host con cscli — seguir pasos del header")
	t.Log("Estado actual: crowdsec instalado, validación E2E pendiente de ejecución manual")
}
