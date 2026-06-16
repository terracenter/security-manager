// Package safeapply implementa el modelo backup → preflight → deadman → confirm/rollback
// para cambios de firewall nftables. El deadman usa systemd-run --on-active para revertir
// automáticamente si el operador no confirma dentro del timeout.
// Port de Security-Manager-Go/internal/safeapply — adaptado a nftables (nft -f en lugar de ufw reload).
package safeapply

// Plan describe un ciclo completo de safe-apply sobre el ruleset nftables.
type Plan struct {
	// BackupFile es la ruta donde se guarda el backup de sm.nft antes de aplicar.
	BackupFile string
	// RulesetFile es la ruta del ruleset activo (/etc/security-manager/sm.nft).
	RulesetFile string
	// DeadmanTimeout es el tiempo en segundos antes del rollback automático (default 120).
	DeadmanTimeout int
	// WhitelistSet es el nombre del set nftables que debe existir antes de aplicar.
	WhitelistSet string
}

// Apply ejecuta el ciclo completo: backup → preflight → deadman → Apply → confirm/rollback.
// Implementación pendiente — TASK-004.
func Apply(p Plan) error {
	panic("safeapply.Apply: no implementado — ver TASK-004")
}
