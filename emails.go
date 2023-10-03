package validator

import (
	"fmt"
	"net"
	"net/mail"
	"strings"
	"time"

	"blitiri.com.ar/go/spf"
	"gitlab.com/etke.cc/go/trysmtp"
	"golang.org/x/net/context"
)

var (
	ErrSpamlist = fmt.Errorf("spamlist")
	ErrNoMX     = fmt.Errorf("no MX")
	ErrSMTP     = fmt.Errorf("SMTP")
	ErrSPF      = fmt.Errorf("SPF")
)

// Email checks if email is valid
func (v *V) Email(email string, optionalSenderIP ...net.IP) bool {
	// edge case: email may be optional
	if email == "" {
		return !v.cfg.Email.Enforce
	}

	address, err := mail.ParseAddress(email)
	if err != nil {
		v.cfg.Log("email %s invalid, reason: %v", email, err)
		return false
	}
	email = address.Address
	return v.emailChecks(email, optionalSenderIP...)
}

func (v *V) emailChecks(email string, optionalSenderIP ...net.IP) bool {
	maxChecks := 4
	var senderIP net.IP
	if len(optionalSenderIP) > 0 {
		senderIP = optionalSenderIP[0]
	}
	errchan := make(chan error, maxChecks)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	go v.emailSpamlist(ctx, email, errchan)
	go v.emailNoMX(ctx, email, errchan)
	go v.emailNoSPF(ctx, email, senderIP, errchan)
	go v.emailNoSMTP(ctx, email, errchan)

	var checks int
	for {
		checks++
		err := <-errchan
		if err != nil {
			v.cfg.Log("email %q is invalid, reason: %v", email, err)
			return false
		}
		if checks >= maxChecks {
			return true
		}
	}
}

func (v *V) emailSpamlist(ctx context.Context, email string, errchan chan error) {
	select {
	case <-ctx.Done():
		return
	default:
		emailb := []byte(email)
		for _, spamregex := range v.cfg.Email.spamlist {
			if spamregex.Match(emailb) {
				errchan <- ErrSpamlist
				return
			}
		}
		errchan <- nil
	}
}

func (v *V) emailNoMX(ctx context.Context, email string, errchan chan error) {
	select {
	case <-ctx.Done():
		return
	default:
		if !v.cfg.Email.MX {
			errchan <- nil
			return
		}

		at := strings.LastIndex(email, "@")
		domain := email[at+1:]
		if !v.MX(domain) {
			v.cfg.Log("email %s domain %s invalid, reason: no MX", email, domain)
			errchan <- ErrNoMX
			return
		}
		errchan <- nil
	}
}

func (v *V) emailNoSMTP(ctx context.Context, email string, errchan chan error) {
	select {
	case <-ctx.Done():
		return
	default:
		if !v.cfg.Email.SMTP {
			errchan <- nil
			return
		}

		client, err := trysmtp.Connect(v.cfg.Email.From, email)
		if err != nil {
			if strings.HasPrefix(err.Error(), "45") {
				v.cfg.Log("email %s may be invalid, reason: SMTP check (%v)", email, err)
				errchan <- nil
				return
			}

			v.cfg.Log("email %s invalid, reason: SMTP check (%v)", email, err)
			errchan <- ErrSMTP
			return
		}
		client.Close()
		errchan <- nil
	}
}

func (v *V) emailNoSPF(ctx context.Context, email string, senderIP net.IP, errchan chan error) {
	select {
	case <-ctx.Done():
		return
	default:
		if !v.cfg.Email.SPF {
			errchan <- nil
			return
		}

		result, _ := spf.CheckHostWithSender(senderIP, "", email, spf.WithTraceFunc(v.cfg.Log)) //nolint:errcheck // not a error
		if result == spf.Fail {
			errchan <- ErrSPF
			return
		}
		errchan <- nil
	}
}
