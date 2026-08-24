package sys

import (
	"testing"
)

func TestResolveFamily(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"ubuntu", "ubuntu"},
		{"debian", "debian"},
		{"rhel", "rhel"},
		{"almalinux", "rhel"},
		{"rocky", "rhel"},
		{"fedora", "rhel"},
		{"arch", "arch"},
		{"desconocida", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := resolveFamily(tt.id)
			if got != tt.want {
				t.Errorf("resolveFamily(%q) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

func TestConfirmStrong(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		requiredWord string
		want         bool
	}{
		{
			name:         "exact match",
			input:        "reset",
			requiredWord: "reset",
			want:         true,
		},
		{
			name:         "case-insensitive match",
			input:        "RESET",
			requiredWord: "reset",
			want:         true,
		},
		{
			name:         "case-insensitive match uppercase required",
			input:        "reset",
			requiredWord: "RESET",
			want:         true,
		},
		{
			name:         "partial match should fail",
			input:        "reset partial",
			requiredWord: "reset",
			want:         false,
		},
		{
			name:         "no match",
			input:        "wrong",
			requiredWord: "reset",
			want:         false,
		},
		{
			name:         "empty input",
			input:        "",
			requiredWord: "reset",
			want:         false,
		},
		{
			name:         "whitespace trimming",
			input:        "  reset  ",
			requiredWord: "reset",
			want:         true,
		},
		{
			name:         "ssh close confirmation exact",
			input:        "cerrar ssh",
			requiredWord: "cerrar ssh",
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readLine := func(prompt string) string {
				return tt.input
			}
			got := ConfirmStrong(readLine, "test prompt: ", tt.requiredWord)
			if got != tt.want {
				t.Errorf("ConfirmStrong(%q, %q) = %v, want %v", tt.input, tt.requiredWord, got, tt.want)
			}
		})
	}
}
