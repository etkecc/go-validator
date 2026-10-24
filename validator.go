package validator

import (
	"fmt"
	"io"
	"net"
	"net/smtp"
	"regexp"
	"strings"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/etkecc/go-trysmtp"
)

// emailCheckTimeout bounds the whole email check pipeline.
const emailCheckTimeout = 30 * time.Second

var defaultLogfunc = func(msg string, args ...any) {
	fmt.Printf(msg+"\n", args...)
}

type (
	// V is a validator implementation
	V struct {
		cfg          *Config
		resolver     dnsResolver
		spfCheck     spfChecker
		smtpDial     smtpDialer
		checkTimeout time.Duration
	}

	// dnsResolver is the DNS surface used by lookups and MX email checks.
	dnsResolver interface {
		LookupIP(host string) ([]net.IP, error)
		LookupCNAME(host string) (string, error)
		LookupMX(host string) ([]*net.MX, error)
		LookupNS(host string) ([]*net.NS, error)
	}

	// spfChecker evaluates SPF records for a sender.
	spfChecker func(ip net.IP, helo, sender string, opts ...spf.Option) (spf.Result, error)

	// smtpDialer opens an SMTP connection used to verify a recipient.
	smtpDialer func(from, to string) (io.Closer, error)

	// netResolver performs lookups through the system resolver.
	netResolver struct{}
)

// New validator
func New(cfg *Config) *V {
	if cfg.Log == nil {
		cfg.Log = defaultLogfunc
	}
	cfg.Email.spamlist = parseSpamlist(cfg.Email.Spamlist)
	return &V{
		cfg:          cfg,
		resolver:     netResolver{},
		spfCheck:     spf.CheckHostWithSender,
		smtpDial:     dialSMTP,
		checkTimeout: emailCheckTimeout,
	}
}

// dialSMTP opens a real connection to the recipient's mail server.
func dialSMTP(from, to string) (io.Closer, error) {
	return wrapSMTPClient(trysmtp.Connect(from, to))
}

// wrapSMTPClient keeps a nil client from becoming a non-nil io.Closer.
func wrapSMTPClient(client *smtp.Client, err error) (io.Closer, error) {
	if client == nil {
		return nil, err
	}
	return client, err
}

func (netResolver) LookupIP(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

func (netResolver) LookupCNAME(host string) (string, error) {
	return net.LookupCNAME(host)
}

func (netResolver) LookupMX(host string) ([]*net.MX, error) {
	return net.LookupMX(host)
}

func (netResolver) LookupNS(host string) ([]*net.NS, error) {
	return net.LookupNS(host)
}

// parseSpamlist compiles glob patterns into anchored regexes, skipping a pattern too large for the regexp engine.
func parseSpamlist(patterns []string) []*regexp.Regexp {
	regexes := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		rule, err := regexp.Compile("^" + parsePattern(pattern) + "$")
		if err != nil {
			continue
		}
		regexes = append(regexes, rule)
	}

	return regexes
}

func parsePattern(pattern string) string {
	var regexpattern strings.Builder
	for _, runeItem := range pattern {
		if runeItem == '*' {
			regexpattern.WriteString("(.*)")
			continue
		}
		regexpattern.WriteString(regexp.QuoteMeta(string(runeItem)))
	}

	return regexpattern.String()
}
