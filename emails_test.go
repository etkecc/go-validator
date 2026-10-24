package validator

import (
	"errors"
	"net"
	"slices"
	"sync"
	"testing"
)

func TestEmail(t *testing.T) {
	env := newEnv(t)
	if !env.v.Email("user@example.com", "") {
		t.Error("valid email rejected")
	}
	if env.v.Email("not an email", "") {
		t.Error("invalid email accepted")
	}
}

func TestEmailWithError(t *testing.T) {
	tests := []struct {
		name       string
		email      string
		returnPath string
		enforce    bool
		wantErr    bool
	}{
		{name: "empty enforced", enforce: true, wantErr: true},
		{name: "empty lax"},
		{name: "missing domain", email: "example.com", wantErr: true},
		{name: "garbage", email: "not an email", wantErr: true},
		{name: "single label domain", email: "a@e"},
		{name: "display name", email: "John Doe <john@example.com>"},
		{name: "invalid return path ignored", email: "john@example.com", returnPath: "not an email"},
		{name: "display name return path", email: "john@example.com", returnPath: "Bounces <b@example.com>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newEnv(t)
			env.v.cfg.Email.Enforce = tt.enforce
			err := env.v.EmailWithError(tt.email, tt.returnPath)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EmailWithError(%q, %q) = %v, wantErr %v", tt.email, tt.returnPath, err, tt.wantErr)
			}
		})
	}
}

func TestEmailNormalizesAddress(t *testing.T) {
	env := newEnv(t)
	env.v.cfg.Email.MX = true
	env.dns.lookupMX = func(host string) ([]*net.MX, error) {
		if host != "example.com" {
			t.Errorf("MX lookup for %q, want example.com", host)
		}
		return []*net.MX{{Host: "mx.example.com.", Pref: 10}}, nil
	}
	if err := env.v.EmailWithError("John Doe <john@example.com>", ""); err != nil {
		t.Fatalf("EmailWithError = %v, want nil", err)
	}
}

func TestEmailSpamlist(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{name: "wildcard domain", email: "evil@spam.host", wantErr: true},
		{name: "wildcard local part", email: "spam@example.com", wantErr: true},
		{name: "exact match", email: "spam@email.host", wantErr: true},
		{name: "display name", email: "Evil <evil@spam.host>", wantErr: true},
		{name: "clean address", email: "hello@example.com"},
		{name: "similar domain", email: "evil@notspam.host"},
		{name: "similar local part", email: "notspam@example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newEnv(t)
			err := env.v.EmailWithError(tt.email, "")
			if tt.wantErr && !errors.Is(err, ErrSpamlist) {
				t.Fatalf("EmailWithError(%q) = %v, want ErrSpamlist", tt.email, err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("EmailWithError(%q) = %v, want nil", tt.email, err)
			}
		})
	}
}

func TestEmailMX(t *testing.T) {
	records := []*net.MX{{Host: "mx.example.com.", Pref: 10}}
	tests := []struct {
		name     string
		email    string
		enabled  bool
		res      []*net.MX
		err      error
		wantHost string
		wantErr  error
	}{
		{name: "disabled", email: "user@example.com"},
		{name: "record found", email: "user@example.com", enabled: true, res: records, wantHost: "example.com"},
		{name: "no record", email: "user@example.com", enabled: true, wantHost: "example.com", wantErr: ErrNoMX},
		{
			name:     "lookup failure",
			email:    "user@example.com",
			enabled:  true,
			err:      errors.New("dns is down"),
			wantHost: "example.com",
			wantErr:  ErrNoMX,
		},
		{name: "subdomain queried as is", email: "user@mail.example.com", enabled: true, res: records, wantHost: "mail.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newEnv(t)
			env.v.cfg.Email.MX = tt.enabled
			env.dns.lookupMX = func(string) ([]*net.MX, error) {
				return tt.res, tt.err
			}
			err := env.v.EmailWithError(tt.email, "")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("EmailWithError(%q) = %v, want %v", tt.email, err, tt.wantErr)
			}
			calls := env.dns.calls()
			if !tt.enabled {
				if len(calls) != 0 {
					t.Errorf("disabled MX check queried %v", calls)
				}
				return
			}
			if !slices.Equal(calls, []string{tt.wantHost}) {
				t.Errorf("MX lookups = %v, want [%q]", calls, tt.wantHost)
			}
		})
	}
}

func TestEmailSMTP(t *testing.T) {
	tests := []struct {
		name       string
		enabled    bool
		dialErr    error
		withClient bool
		wantErr    error
		wantCalls  int
		wantClosed int
	}{
		{name: "disabled"},
		{name: "accepted", enabled: true, wantCalls: 1, wantClosed: 1},
		{name: "greylisted", enabled: true, dialErr: errors.New("451 4.7.1 try again later"), wantCalls: 1},
		{
			name:       "greylisted with client",
			enabled:    true,
			dialErr:    errors.New("451 4.7.1 try again later"),
			withClient: true,
			wantCalls:  1,
			wantClosed: 1,
		},
		{name: "rejected", enabled: true, dialErr: errors.New("550 5.1.1 user unknown"), wantErr: ErrSMTP, wantCalls: 1},
		{
			name:       "non-fatal error with client accepted",
			enabled:    true,
			dialErr:    errors.New("dial tcp: connection refused"),
			withClient: true,
			wantCalls:  1,
			wantClosed: 1,
		},
		{name: "transient prefix", enabled: true, dialErr: errors.New("45 busy"), wantCalls: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newEnv(t)
			env.v.cfg.Email.SMTP = tt.enabled
			env.smtp.err = tt.dialErr
			env.smtp.errWithClient = tt.withClient
			err := env.v.EmailWithError("user@example.com", "")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("EmailWithError = %v, want %v", err, tt.wantErr)
			}
			calls, closed := env.smtp.snapshot()
			if len(calls) != tt.wantCalls {
				t.Fatalf("SMTP dials = %d, want %d", len(calls), tt.wantCalls)
			}
			if closed != tt.wantClosed {
				t.Errorf("SMTP closes = %d, want %d", closed, tt.wantClosed)
			}
			if len(calls) == 1 {
				want := dialCall{from: "check@example.net", to: "user@example.com"}
				if calls[0] != want {
					t.Errorf("SMTP dial = %+v, want %+v", calls[0], want)
				}
			}
		})
	}
}

func TestEmailConcurrentSMTPChecks(t *testing.T) {
	env := newEnv(t)
	env.v.cfg.Email.SMTP = true

	const workers = 8
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			errs <- env.v.EmailWithError("user@example.com", "")
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent EmailWithError = %v, want nil", err)
		}
	}
}
