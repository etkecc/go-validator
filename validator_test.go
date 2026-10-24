package validator

import (
	"errors"
	"net/smtp"
	"testing"
)

func TestNew(t *testing.T) {
	cfg := &Config{}
	v := New(cfg)

	if v == nil {
		t.Fatal("New returned nil")
	}
	if cfg.Log == nil {
		t.Error("New did not install a default logger")
	}
	if v.resolver == nil || v.spfCheck == nil || v.smtpDial == nil {
		t.Error("New did not install default dependencies")
	}
}

func TestNewParsesSpamlist(t *testing.T) {
	cfg := &Config{
		Log:   func(string, ...any) {},
		Email: Email{Spamlist: []string{"spam@*"}},
	}
	v := New(cfg)

	err := v.EmailWithError("spam@example.com", "")
	if !errors.Is(err, ErrSpamlist) {
		t.Fatalf("EmailWithError = %v, want ErrSpamlist", err)
	}
}

func TestWrapSMTPClient(t *testing.T) {
	errBoom := errors.New("boom")
	if client, err := wrapSMTPClient(nil, errBoom); client != nil || !errors.Is(err, errBoom) {
		t.Errorf("wrapSMTPClient(nil, boom) = %v, %v; want nil closer and boom", client, err)
	}

	if client, err := wrapSMTPClient(&smtp.Client{}, errBoom); client == nil || !errors.Is(err, errBoom) {
		t.Errorf("wrapSMTPClient(client, boom) = %v, %v; want closer and boom", client, err)
	}
}

func TestParsePattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		match   []string
		noMatch []string
	}{
		{
			name:    "domain wildcard",
			pattern: "*@spam.host",
			match:   []string{"x@spam.host", "a.b@spam.host"},
			noMatch: []string{"x@spam.host.evil", "x@notspam.host", "x@spamXhost"},
		},
		{
			name:    "local part wildcard",
			pattern: "spam@*",
			match:   []string{"spam@example.com", "spam@sub.example.com"},
			noMatch: []string{"notspam@example.com", "spam"},
		},
		{
			name:    "literal dot",
			pattern: "a.b@example.com",
			match:   []string{"a.b@example.com"},
			noMatch: []string{"axb@example.com", "a.b@exampleXcom"},
		},
		{
			name:    "quoted metacharacters",
			pattern: "a+b@example.com",
			match:   []string{"a+b@example.com"},
			noMatch: []string{"aab@example.com", "aaab@example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regexes, err := parseSpamlist([]string{tt.pattern})
			if err != nil {
				t.Fatalf("parseSpamlist(%q): %v", tt.pattern, err)
			}
			if len(regexes) != 1 {
				t.Fatalf("parseSpamlist(%q) returned %d regexes, want 1", tt.pattern, len(regexes))
			}
			for _, value := range tt.match {
				if !regexes[0].MatchString(value) {
					t.Errorf("pattern %q does not match %q", tt.pattern, value)
				}
			}
			for _, value := range tt.noMatch {
				if regexes[0].MatchString(value) {
					t.Errorf("pattern %q unexpectedly matches %q", tt.pattern, value)
				}
			}
		})
	}
}
