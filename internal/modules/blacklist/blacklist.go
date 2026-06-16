package blacklist

import "fmt"

// Blacklist gestiona bans manuales (sm_blacklist4/6).
type Blacklist struct{}

func New() *Blacklist { return &Blacklist{} }

func (b *Blacklist) Order() int   { return 4 }
func (b *Blacklist) Name() string { return "Blacklist" }
func (b *Blacklist) Menu()        { fmt.Println("  [Blacklist] — en desarrollo") }
func (b *Blacklist) Reset()       {}
