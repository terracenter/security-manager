// Package safeapply implementa el modelo backup → preflight → deadman → confirm/rollback
// para cambios de firewall nftables. El deadman usa systemd-run --on-active para revertir
// automáticamente si el operador no confirma dentro del timeout.
package safeapply

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Plan describe un ciclo completo de safe-apply sobre el ruleset nftables.
type Plan struct {
	// BackupFile es la ruta donde se guarda el backup de sm.nft antes de aplicar.
	BackupFile string
	// RulesetFile es la ruta del ruleset activo (/etc/security-manager/sm.nft).
	RulesetFile string
	// DeadmanTimeout es el tiempo en segundos antes del rollback automático (default 120).
	DeadmanTimeout int
	// WhitelistSet es el nombre del set nftables que debe existir antes de aplicar (preflight).
	WhitelistSet string
	// Stdin permite inyectar un reader alternativo para tests (nil → os.Stdin).
	Stdin io.Reader
	// SkipBackup indica que el llamador ya hizo el backup antes de escribir RulesetFile.
	// Usar cuando el backup debe capturar el ruleset ANTERIOR al rename (flujo correcto).
	SkipBackup bool
}

// Apply ejecuta el ciclo completo: backup → preflight → apply → deadman → confirm/rollback.
// Retorna nil si el operador confirmó en tiempo; error en cualquier falla o rollback.
func Apply(p Plan) error {
	if p.DeadmanTimeout <= 0 {
		p.DeadmanTimeout = 120
	}
	if p.Stdin == nil {
		p.Stdin = os.Stdin
	}

	if !p.SkipBackup {
		if err := backup(p); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
	}
	if err := preflight(p); err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	if err := applyRuleset(p); err != nil {
		// El ruleset no se aplicó; el backup sigue siendo el activo.
		return fmt.Errorf("apply: %w", err)
	}

	unit, err := scheduleDeadman(p)
	if err != nil {
		// No se pudo armar el deadman — revertir de inmediato por seguridad.
		_ = rollback(p)
		return fmt.Errorf("deadman: %w", err)
	}

	confirmed := askConfirm(p, unit)
	if confirmed {
		cancelDeadman(unit)
		fmt.Println("\n  [safeapply] Reglas confirmadas. Deadman cancelado.")
		return nil
	}

	// El operador no confirmó — revertir manualmente (el deadman hubiera actuado igualmente).
	cancelDeadman(unit)
	if err := rollback(p); err != nil {
		return fmt.Errorf("rollback manual: %w", err)
	}
	fmt.Println("\n  [safeapply] Rollback completado. Reglas anteriores restauradas.")
	return fmt.Errorf("operador no confirmó — se aplicó rollback")
}

// backup copia RulesetFile → BackupFile.
func backup(p Plan) error {
	src, err := os.ReadFile(p.RulesetFile)
	if err != nil {
		return fmt.Errorf("leer %s: %w", p.RulesetFile, err)
	}
	if err := os.WriteFile(p.BackupFile, src, 0o640); err != nil {
		return fmt.Errorf("escribir %s: %w", p.BackupFile, err)
	}
	fmt.Printf("  [safeapply] Backup: %s → %s\n", p.RulesetFile, p.BackupFile)
	return nil
}

// preflight verifica que el set WhitelistSet exista en nftables.
func preflight(p Plan) error {
	if p.WhitelistSet == "" {
		// Verificar que el backup (si existe) tiene sintaxis nft válida.
		// Si el deadman se dispara y el backup está corrupto, el rollback falla.
		if _, err := os.Stat(p.BackupFile); err == nil {
			out, err := exec.Command("nft", "-c", "-f", p.BackupFile).CombinedOutput()
			if err != nil {
				return fmt.Errorf("backup inválido — rollback no sería posible: %s",
					strings.TrimSpace(string(out)))
			}
			fmt.Printf("  [safeapply] Preflight OK — backup válido: %s\n", p.BackupFile)
		}
		return nil
	}
	out, err := exec.Command("nft", "list", "set", "inet", "sm", p.WhitelistSet).CombinedOutput()
	if err != nil {
		return fmt.Errorf("set '%s' no existe en nftables (preflight): %s", p.WhitelistSet, strings.TrimSpace(string(out)))
	}
	fmt.Printf("  [safeapply] Preflight OK — set '%s' presente\n", p.WhitelistSet)
	return nil
}

// applyRuleset recarga el ruleset con nft -f (operación atómica).
func applyRuleset(p Plan) error {
	out, err := exec.Command("nft", "-f", p.RulesetFile).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft -f %s: %s", p.RulesetFile, strings.TrimSpace(string(out)))
	}
	fmt.Printf("  [safeapply] Ruleset aplicado: %s\n", p.RulesetFile)
	return nil
}

// scheduleDeadman programa un rollback automático con systemd-run --on-active.
// Retorna el nombre de la unit transient para cancelarla si el operador confirma.
func scheduleDeadman(p Plan) (string, error) {
	unitName := fmt.Sprintf("sm-ng-deadman-%d.service", time.Now().Unix())

	var deadmanArgs []string
	if _, err := os.Stat(p.BackupFile); os.IsNotExist(err) {
		deadmanArgs = []string{"nft", "delete", "table", "inet", "sm"}
		fmt.Println("  [safeapply] Primera instalación — deadman: nft delete table inet sm")
	} else {
		deadmanArgs = []string{"nft", "-f", p.BackupFile}
	}

	cmd := exec.Command(
		"systemd-run",
		"--collect",
		"--unit="+unitName,
		fmt.Sprintf("--on-active=%ds", p.DeadmanTimeout),
	)
	cmd.Args = append(cmd.Args, deadmanArgs...)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("systemd-run: %s", strings.TrimSpace(string(out)))
	}
	fmt.Printf("  [safeapply] Deadman activo — rollback automático en %ds si no confirmas\n", p.DeadmanTimeout)
	fmt.Printf("  [safeapply] Unit: %s\n", unitName)
	return unitName, nil
}

// cancelDeadman detiene el timer del deadman.
func cancelDeadman(unit string) {
	_ = exec.Command("systemctl", "stop", unit).Run()
}

// rollback restaura el backup aplicando nft -f BackupFile.
// En primera instalación (sin BackupFile), usa nft delete table inet sm.
func rollback(p Plan) error {
	if _, err := os.Stat(p.BackupFile); os.IsNotExist(err) {
		out, err := exec.Command("nft", "delete", "table", "inet", "sm").CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft delete table inet sm (rollback primera-vez): %s", strings.TrimSpace(string(out)))
		}
		return nil
	}
	out, err := exec.Command("nft", "-f", p.BackupFile).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft -f %s (rollback): %s", p.BackupFile, strings.TrimSpace(string(out)))
	}
	return nil
}

// askConfirm presenta el prompt al operador y retorna true si confirma dentro del timeout.
func askConfirm(p Plan, _ string) bool {
	deadline := time.Now().Add(time.Duration(p.DeadmanTimeout) * time.Second)
	remaining := int(time.Until(deadline).Seconds())

	fmt.Printf("\n  [safeapply] Tienes %d segundos para confirmar las nuevas reglas.\n", remaining)
	fmt.Print("  ¿Confirmar reglas? [s/N]: ")

	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		scanner := bufio.NewScanner(p.Stdin)
		if scanner.Scan() {
			ch <- result{line: scanner.Text()}
		} else {
			ch <- result{err: io.EOF}
		}
	}()

	select {
	case r := <-ch:
		return r.err == nil && strings.ToLower(strings.TrimSpace(r.line)) == "s"
	case <-time.After(time.Until(deadline)):
		fmt.Println("\n  [safeapply] Timeout — el deadman ejecutará rollback automático.")
		return false
	}
}
