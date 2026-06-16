package geoip

import "fmt"

// GeoIP gestiona los sets nftables de rangos por país (geoip_<cc>4/6).
type GeoIP struct{}

func New() *GeoIP { return &GeoIP{} }

func (g *GeoIP) Order() int   { return 3 }
func (g *GeoIP) Name() string { return "GeoIP" }
func (g *GeoIP) Menu()        { fmt.Println("  [GeoIP] — en desarrollo") }
func (g *GeoIP) Reset()       {}
