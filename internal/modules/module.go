package modules

// Module es la interfaz que cada módulo debe implementar.
type Module interface {
	Order() int
	Name() string
	Menu()
	Reset()
}
