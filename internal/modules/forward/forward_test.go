package forward

import (
	"testing"

	"github.com/terracenter/security-manager-ng/internal/store"
)

func TestValidateRule_PortWithoutProto_Rejected(t *testing.T) {
	r := store.ForwardRule{Src: "172.17.0.0/16", PortRange: "22", Action: "drop"}
	if err := validateRule(r); err == nil {
		t.Error("esperaba rechazo: --port sin --proto")
	}
}

func TestValidateRule_PortWithProto_Accepted(t *testing.T) {
	r := store.ForwardRule{Src: "172.17.0.0/16", PortRange: "22", Proto: "tcp", Action: "drop"}
	if err := validateRule(r); err != nil {
		t.Errorf("esperaba aceptar puerto+proto válidos, obtuve: %v", err)
	}
}

func TestValidateRule_MixedFamily_Rejected(t *testing.T) {
	r := store.ForwardRule{Src: "10.0.0.0/8", Dst: "2001:db8::/32", Action: "accept"}
	if err := validateRule(r); err == nil {
		t.Error("esperaba rechazo: src v4 + dst v6 (familia mixta)")
	}
}

func TestValidateRule_SameFamily_Accepted(t *testing.T) {
	r := store.ForwardRule{Src: "10.0.0.0/8", Dst: "8.8.8.8/32", Action: "accept"}
	if err := validateRule(r); err != nil {
		t.Errorf("esperaba aceptar misma familia (v4/v4), obtuve: %v", err)
	}
}

func TestValidateRule_InvalidAction_Rejected(t *testing.T) {
	r := store.ForwardRule{Action: "maybe"}
	if err := validateRule(r); err == nil {
		t.Error("esperaba rechazo: action inválida")
	}
}

func TestValidateRule_InvalidProto_Rejected(t *testing.T) {
	r := store.ForwardRule{Action: "accept", PortRange: "80", Proto: "icmp"}
	if err := validateRule(r); err == nil {
		t.Error("esperaba rechazo: proto inválido (solo tcp|udp)")
	}
}

func TestValidatePortRange(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"22", false},
		{"8000-9000", false},
		{"0", true},
		{"70000", true},
		{"9000-8000", true},
		{"abc", true},
	}
	for _, c := range cases {
		err := validatePortRange(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("validatePortRange(%q): err=%v, wantErr=%v", c.in, err, c.wantErr)
		}
	}
}
