package firewall

import "fmt"

// Firewall gestiona el ruleset nftables declarativo (tabla inet sm).
type Firewall struct{}

func New() *Firewall { return &Firewall{} }

func (f *Firewall) Order() int   { return 1 }
func (f *Firewall) Name() string { return "Firewall (nftables)" }
func (f *Firewall) Menu()        { fmt.Println("  [Firewall] — en desarrollo") }
func (f *Firewall) Reset()       {}
