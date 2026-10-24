package validator

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"blitiri.com.ar/go/spf"
)

func TestEmailSPF(t *testing.T) {
	senderIP := net.IPv4(192, 0, 2, 1)
	tests := []struct {
		name        string
		enabled     bool
		email       string
		returnPath  string
		results     map[string]spf.Result
		wantErr     error
		wantSenders []string
	}{
		{name: "disabled", email: "user@example.com"},
		{name: "pass", enabled: true, email: "user@example.com", wantSenders: []string{"user@example.com"}},
		{
			name:        "fail without return path",
			enabled:     true,
			email:       "user@example.com",
			results:     map[string]spf.Result{"user@example.com": spf.Fail},
			wantErr:     ErrSPF,
			wantSenders: []string{"user@example.com"},
		},
		{
			name:        "fail other domain return path",
			enabled:     true,
			email:       "user@example.com",
			returnPath:  "bounce@other.org",
			results:     map[string]spf.Result{"user@example.com": spf.Fail},
			wantErr:     ErrSPF,
			wantSenders: []string{"user@example.com"},
		},
		{
			name:       "fail same base return path fails",
			enabled:    true,
			email:      "user@example.com",
			returnPath: "bounce@mail.example.com",
			results: map[string]spf.Result{
				"user@example.com":        spf.Fail,
				"bounce@mail.example.com": spf.Fail,
			},
			wantErr:     ErrSPF,
			wantSenders: []string{"user@example.com", "bounce@mail.example.com"},
		},
		{
			name:        "fail sender passing return path accepted",
			enabled:     true,
			email:       "user@example.com",
			returnPath:  "bounce@mail.example.com",
			results:     map[string]spf.Result{"user@example.com": spf.Fail},
			wantSenders: []string{"user@example.com", "bounce@mail.example.com"},
		},
		{
			name:       "fail sender softfail return path rejected",
			enabled:    true,
			email:      "user@example.com",
			returnPath: "bounce@mail.example.com",
			results: map[string]spf.Result{
				"user@example.com":        spf.Fail,
				"bounce@mail.example.com": spf.SoftFail,
			},
			wantErr:     ErrSPF,
			wantSenders: []string{"user@example.com", "bounce@mail.example.com"},
		},
		{
			name:       "fail sender none return path rejected",
			enabled:    true,
			email:      "user@example.com",
			returnPath: "bounce@mail.example.com",
			results: map[string]spf.Result{
				"user@example.com":        spf.Fail,
				"bounce@mail.example.com": spf.None,
			},
			wantErr:     ErrSPF,
			wantSenders: []string{"user@example.com", "bounce@mail.example.com"},
		},
		{
			name:       "pass sender skips return path",
			enabled:    true,
			email:      "user@example.com",
			returnPath: "bounce@mail.example.com",
			results: map[string]spf.Result{
				"user@example.com":        spf.Pass,
				"bounce@mail.example.com": spf.Fail,
			},
			wantSenders: []string{"user@example.com"},
		},
		{
			name:        "fail identical return path",
			enabled:     true,
			email:       "user@example.com",
			returnPath:  "user@example.com",
			results:     map[string]spf.Result{"user@example.com": spf.Fail},
			wantErr:     ErrSPF,
			wantSenders: []string{"user@example.com"},
		},
		{
			name:        "display name return path accepted",
			enabled:     true,
			email:       "user@example.com",
			returnPath:  "Bounces <b@example.com>",
			results:     map[string]spf.Result{"user@example.com": spf.Fail},
			wantSenders: []string{"user@example.com", "b@example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newEnv(t)
			env.v.cfg.Email.SPF = tt.enabled
			env.spf.results = tt.results
			err := env.v.EmailWithError(tt.email, tt.returnPath, senderIP)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("EmailWithError = %v, want %v", err, tt.wantErr)
			}
			if got := env.spf.senders(); !slices.Equal(got, tt.wantSenders) {
				t.Fatalf("SPF senders = %v, want %v", got, tt.wantSenders)
			}
			for _, call := range env.spf.snapshot() {
				if !call.ip.Equal(senderIP) {
					t.Errorf("SPF check IP = %v, want %v", call.ip, senderIP)
				}
			}
		})
	}
}

func TestEmailPanicIsLoggedNotRejected(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*testEnv)
		wantLog   string
	}{
		{
			name: "mx lookup",
			configure: func(env *testEnv) {
				env.v.cfg.Email.MX = true
				env.dns.lookupMX = func(string) ([]*net.MX, error) {
					panic("dns exploded")
				}
			},
			wantLog: "panic in MX check: dns exploded",
		},
		{
			name: "smtp dial",
			configure: func(env *testEnv) {
				env.v.cfg.Email.SMTP = true
				env.smtp.panics = true
			},
			wantLog: "panic in SMTP check: smtp exploded",
		},
		{
			name: "spf check",
			configure: func(env *testEnv) {
				env.v.cfg.Email.SPF = true
				env.spf.panics = map[string]bool{"user@example.com": true}
			},
			wantLog: "panic in SPF check: spf exploded",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newEnv(t)
			tt.configure(env)
			if err := env.v.EmailWithError("user@example.com", ""); err != nil {
				t.Fatalf("EmailWithError = %v, panicking check must not reject", err)
			}
			if !env.logs.contains(tt.wantLog) {
				t.Errorf("log does not contain %q", tt.wantLog)
			}
		})
	}
}

func TestEmailPanicDoesNotSuppressOtherFailures(t *testing.T) {
	env := newEnv(t)
	panicStarted := make(chan struct{})
	env.v.cfg.Email.MX = true
	env.v.cfg.Email.SMTP = true
	env.dns.lookupMX = func(string) ([]*net.MX, error) {
		close(panicStarted)
		panic("dns exploded")
	}
	env.smtp.gate = panicStarted
	env.smtp.err = errors.New("550 5.1.1 user unknown")

	if err := env.v.EmailWithError("user@example.com", ""); !errors.Is(err, ErrSMTP) {
		t.Fatalf("EmailWithError = %v, want ErrSMTP", err)
	}
}

func TestEmailRunsEachCheckOnce(t *testing.T) {
	env := newEnv(t)
	env.v.cfg.Email.MX = true
	env.v.cfg.Email.SMTP = true
	env.v.cfg.Email.SPF = true
	env.dns.lookupMX = func(string) ([]*net.MX, error) {
		return []*net.MX{{Host: "mx.example.com."}}, nil
	}

	if err := env.v.EmailWithError("user@example.com", ""); err != nil {
		t.Fatalf("EmailWithError = %v, want nil", err)
	}
	if env.logs.contains("panic") {
		t.Error("passing checks logged a panic")
	}
	if calls := env.dns.calls(); !slices.Equal(calls, []string{"example.com"}) {
		t.Errorf("MX lookups = %v, want [example.com]", calls)
	}
	if calls, closed := env.smtp.snapshot(); len(calls) != 1 || closed != 1 {
		t.Errorf("SMTP dials = %d, closes = %d, want 1 and 1", len(calls), closed)
	}
	if senders := env.spf.senders(); !slices.Equal(senders, []string{"user@example.com"}) {
		t.Errorf("SPF senders = %v, want [user@example.com]", senders)
	}
}

func TestEmailChecksDoNotSwallowErrors(t *testing.T) {
	env := newEnv(t)
	env.v.cfg.Email.MX = true
	env.dns.lookupMX = func(string) ([]*net.MX, error) {
		return nil, errors.New("dns is down")
	}

	for range 50 {
		if err := env.v.EmailWithError("user@example.com", ""); !errors.Is(err, ErrNoMX) {
			t.Fatalf("EmailWithError = %v, want ErrNoMX", err)
		}
	}
}

func TestShouldValidateReturnPath(t *testing.T) {
	tests := []struct {
		name       string
		email      string
		returnPath string
		want       bool
	}{
		{name: "empty return path", email: "user@example.com"},
		{name: "identical", email: "user@example.com", returnPath: "user@example.com"},
		{name: "same base", email: "user@example.com", returnPath: "bounce@example.com", want: true},
		{name: "return path subdomain", email: "user@example.com", returnPath: "bounce@mail.example.com", want: true},
		{name: "sender subdomain", email: "user@mail.example.com", returnPath: "bounce@example.com", want: true},
		{name: "different domains", email: "user@example.com", returnPath: "bounce@other.org"},
		{name: "different subdomains", email: "user@mail.example.com", returnPath: "bounce@mail.other.org"},
		{name: "invalid sender", email: "user", returnPath: "bounce@example.com"},
		{name: "invalid return path", email: "user@example.com", returnPath: "bounce"},
		{
			name:       "private suffix shared",
			email:      "user@example.etke.host",
			returnPath: "bounce@mail.example.etke.host",
			want:       true,
		},
		{name: "private suffix different", email: "user@example.etke.host", returnPath: "bounce@other.etke.host"},
		{name: "public suffix shared", email: "user@mail.example.co.uk", returnPath: "bounce@example.co.uk", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newEnv(t)
			if got := env.v.shouldValidateReturnPath(tt.email, tt.returnPath); got != tt.want {
				t.Errorf("shouldValidateReturnPath(%q, %q) = %v, want %v", tt.email, tt.returnPath, got, tt.want)
			}
		})
	}
}

func TestRunCheck(t *testing.T) {
	env := newEnv(t)
	called := false
	err := env.v.runCheck(t.Context(), "probe", func() error {
		called = true
		return ErrSPF
	})
	if !called || !errors.Is(err, ErrSPF) {
		t.Errorf("runCheck = %v (called %v), want ErrSPF (called true)", err, called)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	called = false
	if err := env.v.runCheck(ctx, "probe", func() error {
		called = true
		return ErrSPF
	}); err != nil || called {
		t.Errorf("canceled runCheck = %v (called %v), want nil (called false)", err, called)
	}
}

func TestEmailTimeout(t *testing.T) {
	env := newEnv(t)
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })
	env.v.cfg.Email.SMTP = true
	env.v.checkTimeout = 100 * time.Millisecond
	env.smtp.gate = gate

	if err := env.v.EmailWithError("user@example.com", ""); !errors.Is(err, ErrTimeout) {
		t.Fatalf("EmailWithError = %v, want ErrTimeout", err)
	}
	if calls, _ := env.smtp.snapshot(); len(calls) != 1 {
		t.Fatalf("SMTP dials = %d, want 1; the deadline must interrupt an in-flight dial", len(calls))
	}
	if !env.logs.contains("aborted") {
		t.Error("timeout was not logged")
	}
}

func TestEmailContextCanceled(t *testing.T) {
	env := newEnv(t)
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })
	env.v.cfg.Email.SMTP = true
	env.smtp.gate = gate

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- env.v.EmailWithContext(ctx, "user@example.com", "") }()
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("EmailWithContext = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("EmailWithContext ignored cancellation")
	}
}

func TestCanceledContextNeverPasses(t *testing.T) {
	env := newEnv(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	for range 500 {
		if err := env.v.EmailWithContext(ctx, "spam@example.com", ""); !errors.Is(err, context.Canceled) {
			t.Fatalf("EmailWithContext = %v, want context.Canceled", err)
		}
	}
}
