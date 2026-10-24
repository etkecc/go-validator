package validator

import (
	"fmt"
	"io"
	"net"
	"net/smtp"
	"regexp"
	"strings"

	"blitiri.com.ar/go/spf"
	"github.com/etkecc/go-trysmtp"
)

var defaultLogfunc = func(msg string, args ...any) {
	fmt.Printf(msg+"\n", args...)
}

type (
	// V is a validator implementation
	V struct {
		cfg      *Config
		resolver dnsResolver
		spfCheck spfChecker
		smtpDial smtpDialer
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
	spamregexes, err := parseSpamlist(cfg.Email.Spamlist)
	if err != nil {
		cfg.Log("cannot parse spamlist: %v", err)
	}
	cfg.Email.spamlist = spamregexes
	return &V{
		cfg:      cfg,
		resolver: netResolver{},
		spfCheck: spf.CheckHostWithSender,
		smtpDial: dialSMTP,
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

func parseSpamlist(patterns []string) ([]*regexp.Regexp, error) {
	regexes := []*regexp.Regexp{}
	for _, pattern := range patterns {
		rule, err := regexp.Compile("^" + parsePattern(pattern) + "$")
		if err != nil {
			return regexes, err
		}

		regexes = append(regexes, rule)
	}

	return regexes, nil
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
