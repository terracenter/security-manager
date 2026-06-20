package modules

// Module es la interfaz que cada módulo debe implementar.
type Module interface {
	Order() int
	Name() string
	Menu()
	Reset()
}

// CLIModule es una extensión opcional de Module para modo no interactivo.
// Solo los módulos que soportan CLI la implementan; no se requiere stub en los demás.
type CLIModule interface {
	Module
	RunAction(action string, args ...string) bool
}
