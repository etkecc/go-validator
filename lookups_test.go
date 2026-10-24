package validator

import (
	"errors"
	"net"
	"slices"
	"testing"
)

func TestA(t *testing.T) {
	tests := []struct {
		name string
		host string
		res  []net.IP
		err  error
		want bool
	}{
		{name: "empty host"},
		{name: "record", host: "example.com", res: []net.IP{net.IPv4(192, 0, 2, 1)}, want: true},
		{name: "no records", host: "example.com"},
		{name: "lookup error", host: "example.com", err: errors.New("dns is down")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newEnv(t)
			env.dns.lookupIP = func(host string) ([]net.IP, error) {
				if host != tt.host {
					t.Errorf("LookupIP(%q), want %q", host, tt.host)
				}
				return tt.res, tt.err
			}
			if got := env.v.A(tt.host); got != tt.want {
				t.Errorf("A(%q) = %v, want %v", tt.host, got, tt.want)
			}
			checkCalls(t, env.dns.calls(), tt.host)
		})
	}
}

func TestCNAME(t *testing.T) {
	tests := []struct {
		name string
		host string
		res  string
		err  error
		want bool
	}{
		{name: "empty host"},
		{name: "record", host: "example.com", res: "example.com.", want: true},
		{name: "empty answer", host: "example.com"},
		{name: "lookup error", host: "example.com", err: errors.New("dns is down")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newEnv(t)
			env.dns.lookupCNAME = func(host string) (string, error) {
				if host != tt.host {
					t.Errorf("LookupCNAME(%q), want %q", host, tt.host)
				}
				return tt.res, tt.err
			}
			if got := env.v.CNAME(tt.host); got != tt.want {
				t.Errorf("CNAME(%q) = %v, want %v", tt.host, got, tt.want)
			}
			checkCalls(t, env.dns.calls(), tt.host)
		})
	}
}

func TestMX(t *testing.T) {
	tests := []struct {
		name string
		host string
		res  []*net.MX
		err  error
		want bool
	}{
		{name: "empty host"},
		{name: "record", host: "example.com", res: []*net.MX{{Host: "mx.example.com.", Pref: 10}}, want: true},
		{name: "no records", host: "example.com"},
		{name: "lookup error", host: "example.com", err: errors.New("dns is down")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newEnv(t)
			env.dns.lookupMX = func(host string) ([]*net.MX, error) {
				if host != tt.host {
					t.Errorf("LookupMX(%q), want %q", host, tt.host)
				}
				return tt.res, tt.err
			}
			if got := env.v.MX(tt.host); got != tt.want {
				t.Errorf("MX(%q) = %v, want %v", tt.host, got, tt.want)
			}
			checkCalls(t, env.dns.calls(), tt.host)
		})
	}
}

func TestNS(t *testing.T) {
	tests := []struct {
		name string
		host string
		res  []*net.NS
		err  error
		want bool
	}{
		{name: "empty host"},
		{name: "records", host: "example.com", res: []*net.NS{{Host: "ns1.example.com."}}, want: true},
		{name: "no records", host: "example.com"},
		{name: "lookup error", host: "example.com", err: errors.New("dns is down")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newEnv(t)
			env.dns.lookupNS = func(host string) ([]*net.NS, error) {
				if host != tt.host {
					t.Errorf("LookupNS(%q), want %q", host, tt.host)
				}
				return tt.res, tt.err
			}
			if got := env.v.NS(tt.host); got != tt.want {
				t.Errorf("NS(%q) = %v, want %v", tt.host, got, tt.want)
			}
			checkCalls(t, env.dns.calls(), tt.host)
		})
	}
}

func TestNSContains(t *testing.T) {
	records := []*net.NS{{Host: "ns1.other.net."}, {Host: "ns1.cloudflare.com."}}
	tests := []struct {
		name     string
		contains []string
		res      []*net.NS
		err      error
		want     bool
	}{
		{name: "no filter", res: records, want: true},
		{name: "match", contains: []string{"cloudflare.com"}, res: records, want: true},
		{name: "match second filter", contains: []string{"nope", "cloudflare.com"}, res: records, want: true},
		{name: "no match", contains: []string{"nope"}, res: records},
		{name: "no records", contains: []string{"cloudflare.com"}},
		{name: "lookup error", contains: []string{"cloudflare.com"}, err: errors.New("dns is down")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newEnv(t)
			env.dns.lookupNS = func(string) ([]*net.NS, error) {
				return tt.res, tt.err
			}
			if got := env.v.NS("example.com", tt.contains...); got != tt.want {
				t.Errorf("NS(example.com, %v) = %v, want %v", tt.contains, got, tt.want)
			}
		})
	}
}

func checkCalls(t *testing.T, calls []string, host string) {
	t.Helper()
	if host == "" {
		if len(calls) != 0 {
			t.Errorf("empty host triggered lookups: %v", calls)
		}
		return
	}
	if !slices.Equal(calls, []string{host}) {
		t.Errorf("resolver calls = %v, want [%q]", calls, host)
	}
}
