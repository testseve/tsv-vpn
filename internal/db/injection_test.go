package db

import "testing"

func TestValidateConnectionRejectsInjection(t *testing.T) {
	base := Connection{
		Name:          "vpn1",
		GatewayHost:   "gw.example.com",
		PPPUsername:   "user",
		RemoteSubnets: []string{"10.0.0.0/24"},
	}
	cases := map[string]Connection{
		"newline in username": func() Connection { c := base; c.PPPUsername = "user\ninit \"/bin/sh\""; return c }(),
		"quote in username":   func() Connection { c := base; c.PPPUsername = "us\"er"; return c }(),
		"space in username":   func() Connection { c := base; c.PPPUsername = "us er"; return c }(),
		"newline in host":     func() Connection { c := base; c.GatewayHost = "gw\nremote_addrs = evil"; return c }(),
		"space in host":       func() Connection { c := base; c.GatewayHost = "gw evil"; return c }(),
	}
	for name, conn := range cases {
		if err := validateConnection(conn); err == nil {
			t.Errorf("%s: expected rejection, got nil", name)
		}
	}
	if err := validateConnection(base); err != nil {
		t.Errorf("valid connection rejected: %v", err)
	}
}

func TestValidateSecretsRejectsInjection(t *testing.T) {
	if err := ValidateSecrets(Secrets{PSK: "good\nsecret = evil", PPPPassword: "p"}); err == nil {
		t.Error("newline in psk not rejected")
	}
	if err := ValidateSecrets(Secrets{PSK: "s", PPPPassword: "pass\nother\t*\tevil"}); err == nil {
		t.Error("newline in ppp password not rejected")
	}
	if err := ValidateSecrets(Secrets{PSK: "pa ss phrase!", PPPPassword: "p@ssw0rd-with_symbols"}); err != nil {
		t.Errorf("legitimate secrets rejected: %v", err)
	}
}
