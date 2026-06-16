package fail2ban

import "fmt"

// Fail2ban provee monitoreo de fail2ban (solo lectura — no gestión admin).
type Fail2ban struct{}

func New() *Fail2ban { return &Fail2ban{} }

func (f *Fail2ban) Order() int   { return 7 }
func (f *Fail2ban) Name() string { return "Fail2ban (monitoreo)" }
func (f *Fail2ban) Menu()        { fmt.Println("  [Fail2ban] — en desarrollo") }
func (f *Fail2ban) Reset()       {}
