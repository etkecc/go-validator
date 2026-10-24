package validator

import (
	"strings"
	"testing"
)

func TestDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		enforce bool
		want    bool
	}{
		{name: "empty enforced", enforce: true},
		{name: "empty lax", want: true},
		{name: "valid", domain: "example.com", want: true},
		{name: "subdomain", domain: "sub.example.com", want: true},
		{name: "uppercase", domain: "Example.COM", want: true},
		{name: "single label", domain: "localhost"},
		{name: "too short", domain: "a.b"},
		{name: "shortest valid", domain: "a.co", want: true},
		{name: "max length", domain: strings.Repeat("a", 63) + "." + strings.Repeat("b", 13), want: true},
		{name: "too long", domain: strings.Repeat("a", 63) + "." + strings.Repeat("b", 14)},
		{name: "label too long", domain: strings.Repeat("a", 64) + ".com"},
		{name: "leading hyphen", domain: "-example.com"},
		{name: "trailing hyphen", domain: "example-.com"},
		{name: "underscore", domain: "exa_mple.com"},
		{name: "two dots", domain: "example..com"},
		{name: "trailing dot", domain: "example.com."},
		{name: "garbage", domain: "that's invalid!"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newEnv(t)
			env.v.cfg.Domain.Enforce = tt.enforce
			if got := env.v.Domain(tt.domain); got != tt.want {
				t.Errorf("Domain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestDomainWithError(t *testing.T) {
	env := newEnv(t)
	if err := env.v.DomainWithError("example.com"); err != nil {
		t.Errorf("DomainWithError(example.com) = %v, want nil", err)
	}
	if err := env.v.DomainWithError("nope"); err == nil {
		t.Error("DomainWithError(nope) = nil, want error")
	}
	env.v.cfg.Domain.Enforce = true
	if err := env.v.DomainWithError(""); err == nil {
		t.Error("DomainWithError(\"\") = nil with Enforce, want error")
	}
}

func TestDomainString(t *testing.T) {
	env := newEnv(t)
	if env.v.DomainString("") {
		t.Error("DomainString(\"\") = true, want false")
	}
	if !env.v.DomainString("example.com") {
		t.Error("DomainString(example.com) = false, want true")
	}
}

func TestGetBase(t *testing.T) {
	tests := map[string]string{
		"example.com":                "example.com",
		"sub.example.com":            "example.com",
		"sub.sub.sub.example.com":    "example.com",
		"example.etke.host":          "example.etke.host",
		"sub.example.etke.host":      "example.etke.host",
		"deep.sub.example.etke.host": "example.etke.host",
		"notetke.host":               "notetke.host",
		"example.co.uk":              "example.co.uk",
		"sub.example.co.uk":          "example.co.uk",
		"example.gov.la":             "example.gov.la",
		"sub.example.gov.la":         "example.gov.la",
		"example.com.sg":             "example.com.sg",
		"sub.example.com.sg":         "example.com.sg",
		"localhost":                  "localhost",
		"com":                        "com",
	}
	for domain, expected := range tests {
		t.Run(domain, func(t *testing.T) {
			env := newEnv(t)
			if got := env.v.GetBase(domain); got != expected {
				t.Errorf("GetBase(%q) = %q, want %q", domain, got, expected)
			}
		})
	}
}

func TestHasSuffix(t *testing.T) {
	tests := map[string]bool{
		"example.etke.host":     true,
		"sub.example.etke.host": true,
		"notetke.host":          false,
		"example.co.uk":         true,
		"example.com":           false,
		"example.unknown":       false,
		"localhost":             false,
	}
	env := newEnv(t)
	for domain, expected := range tests {
		t.Run(domain, func(t *testing.T) {
			if got := env.v.hasSuffix(domain); got != expected {
				t.Errorf("hasSuffix(%q) = %v, want %v", domain, got, expected)
			}
		})
	}
}
