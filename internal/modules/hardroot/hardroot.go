package hardroot

import "fmt"

// HardRoot gestiona el hardening de root y sudoers.
type HardRoot struct{}

func New() *HardRoot { return &HardRoot{} }

func (h *HardRoot) Order() int   { return 5 }
func (h *HardRoot) Name() string { return "HardRoot (sudoers)" }
func (h *HardRoot) Menu()        { fmt.Println("  [HardRoot] — en desarrollo") }
func (h *HardRoot) Reset()       {}
