package whitelist

import (
	"testing"
	"time"
)

// Tests del status de whitelist (Fase 1 item 5): clasificacion de
// vencimiento para alerta visual en listIPs.

func TestVencimientoStatus_VacioEsPermanente(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	got := vencimientoStatus("", now)
	if got != "permanente" {
		t.Errorf("vencimiento vacio deberia ser 'permanente', dio %q", got)
	}
}

func TestVencimientoStatus_FechaInvalida(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	for _, invalido := range []string{"ayer", "2026/08/06", "06-08-2026", "no-fecha", "2026-13-45"} {
		got := vencimientoStatus(invalido, now)
		if got != "fecha inválida" {
			t.Errorf("input invalido %q deberia ser 'fecha inválida', dio %q", invalido, got)
		}
	}
}

func TestVencimientoStatus_Vencido(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	// Un dia antes
	got := vencimientoStatus("2026-08-05", now)
	if got != "⚠ VENCIDO" {
		t.Errorf("ayer deberia ser '⚠ VENCIDO', dio %q", got)
	}
	// Mucho antes
	got = vencimientoStatus("2025-01-01", now)
	if got != "⚠ VENCIDO" {
		t.Errorf("fecha muy antigua deberia ser '⚠ VENCIDO', dio %q", got)
	}
}

func TestVencimientoStatus_VencePronto(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	// 7 dias exactos
	got := vencimientoStatus("2026-08-13", now)
	if got != "⚠ vence pronto" {
		t.Errorf("7 dias deberia ser '⚠ vence pronto', dio %q", got)
	}
	// 1 dia
	got = vencimientoStatus("2026-08-07", now)
	if got != "⚠ vence pronto" {
		t.Errorf("manana deberia ser '⚠ vence pronto', dio %q", got)
	}
	// 3 dias
	got = vencimientoStatus("2026-08-09", now)
	if got != "⚠ vence pronto" {
		t.Errorf("3 dias deberia ser '⚠ vence pronto', dio %q", got)
	}
}

func TestVencimientoStatus_OK(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	// 8 dias (justo despues del umbral de 7)
	got := vencimientoStatus("2026-08-14", now)
	if got != "OK" {
		t.Errorf("8 dias deberia ser 'OK', dio %q", got)
	}
	// 30 dias exactos
	got = vencimientoStatus("2026-09-05", now)
	if got != "OK" {
		t.Errorf("30 dias deberia ser 'OK', dio %q", got)
	}
}

func TestVencimientoStatus_OKLargoPlazo(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	// 31 dias
	got := vencimientoStatus("2026-09-06", now)
	if got != "OK (>30d)" {
		t.Errorf("31 dias deberia ser 'OK (>30d)', dio %q", got)
	}
	// 1 año
	got = vencimientoStatus("2027-08-06", now)
	if got != "OK (>30d)" {
		t.Errorf("1 año deberia ser 'OK (>30d)', dio %q", got)
	}
}
