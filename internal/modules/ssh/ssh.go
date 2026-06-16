package ssh

import "fmt"

// SSH gestiona el hardening de sshd_config.
type SSH struct{}

func New() *SSH { return &SSH{} }

func (s *SSH) Order() int   { return 6 }
func (s *SSH) Name() string { return "SSH (sshd_config)" }
func (s *SSH) Menu()        { fmt.Println("  [SSH] — en desarrollo") }
func (s *SSH) Reset()       {}
