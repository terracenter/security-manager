package whitelist

import "fmt"

// Whitelist gestiona el SSoT (sm_whitelist4/6) — subredes de infra confiable.
type Whitelist struct{}

func New() *Whitelist { return &Whitelist{} }

func (w *Whitelist) Order() int   { return 2 }
func (w *Whitelist) Name() string { return "Whitelist / SSoT" }
func (w *Whitelist) Menu()        { fmt.Println("  [Whitelist] — en desarrollo") }
func (w *Whitelist) Reset()       {}
