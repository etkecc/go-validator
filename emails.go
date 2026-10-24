package validator

import (
	"context"
	"errors"
	"net"
	"net/mail"
	"strings"
	"sync"

	"blitiri.com.ar/go/spf"
	"github.com/etkecc/go-trysmtp"
)

var (
	ErrSpamlist = errors.New("spamlist")
	ErrNoMX     = errors.New("no MX")
	ErrSMTP     = errors.New("SMTP")
	ErrSPF      = errors.New("SPF")
	ErrTimeout  = errors.New("timeout")
)

// setSMTPAddrs restricts recipient checks to port 25, once per process.
var setSMTPAddrs = sync.OnceFunc(func() {
	trysmtp.SMTPAddrs = []string{":25"}
})

// Email checks if email is valid; returnPath and optionalSenderIP are optional fields.
func (v *V) Email(email, returnPath string, optionalSenderIP ...net.IP) bool {
	return v.EmailWithError(email, returnPath, optionalSenderIP...) == nil
}

// EmailWithError checks if email is valid and returns an error if not
func (v *V) EmailWithError(email, returnPath string, optionalSenderIP ...net.IP) error {
	return v.EmailWithContext(context.Background(), email, returnPath, optionalSenderIP...)
}

// EmailWithContext checks if email is valid, stopping when ctx is done.
func (v *V) EmailWithContext(ctx context.Context, email, returnPath string, optionalSenderIP ...net.IP) error {
	// edge case: email may be optional
	if email == "" {
		if v.cfg.Email.Enforce {
			return errors.New("email is required")
		}
		return nil
	}

	address, err := mail.ParseAddress(email)
	if err != nil {
		v.cfg.Log("email %s invalid, reason: %v", email, err)
		return err
	}
	if returnPath != "" {
		rpAddress, err := mail.ParseAddress(returnPath)
		if err != nil {
			v.cfg.Log("return path %s invalid, reason: %v", returnPath, err)
		}
		if rpAddress != nil {
			returnPath = rpAddress.Address
		}
	}

	email = address.Address
	return v.emailChecks(ctx, email, returnPath, optionalSenderIP...)
}

func (v *V) emailChecks(ctx context.Context, email, returnPath string, optionalSenderIP ...net.IP) error {
	maxChecks := 4
	var senderIP net.IP
	if len(optionalSenderIP) > 0 {
		senderIP = optionalSenderIP[0]
	}
	errchan := make(chan error, maxChecks)
	ctx, cancel := context.WithTimeout(ctx, v.checkTimeout)
	defer cancel()

	go v.emailSpamlist(ctx, email, errchan)
	go v.emailNoMX(ctx, email, errchan)
	go v.emailNoSPF(ctx, email, returnPath, senderIP, errchan)
	go v.emailNoSMTP(ctx, email, errchan)

	var checks int
	for {
		checks++
		select {
		case err := <-errchan:
			if err != nil {
				v.cfg.Log("email %q is invalid, reason: %v", email, err)
				return err
			}
			if checks >= maxChecks {
				// runCheck counts a skipped check as nil, so a done ctx is never a pass.
				if ctx.Err() != nil {
					return v.abortError(ctx, email)
				}
				return nil
			}
		case <-ctx.Done():
			return v.abortError(ctx, email)
		}
	}
}

// abortError maps a done context to its verdict: our deadline is ErrTimeout, a cancel is ctx.Err().
func (v *V) abortError(ctx context.Context, email string) error {
	v.cfg.Log("email %q checks aborted: %v", email, ctx.Err())
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrTimeout
	}
	return ctx.Err()
}

// runCheck runs one email check; a panic is logged and the check passes.
func (v *V) runCheck(ctx context.Context, name string, check func() error) error {
	defer func() {
		if r := recover(); r != nil {
			v.cfg.Log("panic in %s check: %v", name, r)
		}
	}()
	if ctx.Err() != nil {
		return nil
	}
	return check()
}

func (v *V) emailSpamlist(ctx context.Context, email string, errchan chan error) {
	errchan <- v.runCheck(ctx, "spamlist", func() error {
		emailb := []byte(email)
		for _, spamregex := range v.cfg.Email.spamlist {
			if spamregex.Match(emailb) {
				return ErrSpamlist
			}
		}
		return nil
	})
}

func (v *V) emailNoMX(ctx context.Context, email string, errchan chan error) {
	errchan <- v.runCheck(ctx, "MX", func() error {
		if !v.cfg.Email.MX {
			return nil
		}

		at := strings.LastIndex(email, "@")
		domain := email[at+1:]
		if !v.MX(domain) {
			v.cfg.Log("email %s domain %s invalid, reason: no MX", email, domain)
			return ErrNoMX
		}
		return nil
	})
}

func (v *V) emailNoSMTP(ctx context.Context, email string, errchan chan error) {
	errchan <- v.runCheck(ctx, "SMTP", func() error {
		if !v.cfg.Email.SMTP {
			return nil
		}

		setSMTPAddrs()
		client, err := v.smtpDial(v.cfg.Email.From, email)
		if client != nil {
			// A live client means MAIL and RCPT succeeded; err only carries earlier failures.
			defer client.Close()
			return nil
		}
		if err != nil {
			if strings.HasPrefix(err.Error(), "45") {
				v.cfg.Log("email %s may be invalid, reason: SMTP check (%v)", email, err)
				return nil
			}

			v.cfg.Log("email %s invalid, reason: SMTP check (%v)", email, err)
			return ErrSMTP
		}
		return nil
	})
}

// shouldValidateReturnPath checks if returnPath should be validated in SPF check
func (v *V) shouldValidateReturnPath(email, returnPath string) bool {
	if returnPath == "" {
		return false
	}
	if email == returnPath {
		return false
	}

	var emailDomain, returnPathDomain string
	emailParts := strings.Split(email, "@")
	if len(emailParts) < 2 {
		return false
	}
	emailDomain = v.GetBase(emailParts[1])

	if returnPath != "" {
		returnPathParts := strings.Split(returnPath, "@")
		if len(returnPathParts) < 2 {
			return false
		}
		returnPathDomain = v.GetBase(returnPathParts[1])
	}
	return emailDomain == returnPathDomain
}

func (v *V) emailNoSPF(ctx context.Context, email, returnPath string, senderIP net.IP, errchan chan error) {
	errchan <- v.runCheck(ctx, "SPF", func() error {
		if !v.cfg.Email.SPF {
			return nil
		}

		opts := []spf.Option{
			spf.WithContext(ctx),
			spf.WithTraceFunc(v.cfg.Log),
		}

		resultEmail, _ := v.spfCheck(senderIP, "", email, opts...) //nolint:errcheck // not a error
		if resultEmail != spf.Fail {
			return nil
		}
		if v.shouldValidateReturnPath(email, returnPath) {
			resultReturnPath, _ := v.spfCheck(senderIP, "", returnPath, opts...) //nolint:errcheck // not a error
			if resultReturnPath == spf.Pass {
				return nil
			}
		}
		return ErrSPF
	})
}
