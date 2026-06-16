package infra

// SSoT compartido entre módulos — rutas de archivos y constantes del sistema.
const (
	ConfDir    = "/etc/security-manager"
	RulesetFile = ConfDir + "/sm.nft"

	// Sets nftables
	SetWhitelist4 = "sm_whitelist4"
	SetWhitelist6 = "sm_whitelist6"
	SetBlacklist4 = "sm_blacklist4"
	SetBlacklist6 = "sm_blacklist6"

	// Tabla nftables dueña del ruleset
	Table = "inet sm"
)
